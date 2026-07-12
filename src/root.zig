//! z-oci: Pure Zig OCI/Docker Registry API v2 toolkit.
//!
//! Current scope:
//! - offline OCI/Docker reference parsing and normalization
//! - OCI manifest, index, and descriptor types with JSON round-trip support
//! - auth engine: manifest HEAD/GET challenge handling, token exchange, credential providers
//! - public manifest resolution for single-arch and supported multi-arch flows
//! - registry `/v2/` ping (`pingRegistry`); not used by resolve
//!
//! Ownership conventions:
//! - Functions taking an allocator produce owned storage that the caller must
//!   free (pattern B): `Reference.parse(gpa, "img")` → caller calls `ref.deinit(gpa)`.
//! - Functions returning `std.json.Parsed(T)` own an arena (pattern A): the caller
//!   calls `parsed.deinit()` to free everything.
//! - `AuthEngine` wraps persistent cache storage with its own `deinit()`.
//! - Successful `authenticate()` responses borrow the cached access token when
//!   `owns_access_token == false`. The borrow ends when `AuthEngine.deinit()` runs,
//!   the entry is evicted, or another auth call replaces the same
//!   `realm + service + scope` slot. Copy the token before retaining it.
//!   Call `TokenResponse.deinit(allocator)` to release any owned refresh token.
//! - Batch workloads should reuse one `std.http.Client` and one `AuthEngine` across
//!   multiple manifest operations so per-scope token cache entries stay warm.
//!   Public `resolve`/`validate`/`getManifest` create a fresh engine per call; use
//!   `testing.resolveWithEngine` (or the same pattern in application code) when
//!   measuring or implementing session reuse.
//! - Per-operation transient arena (`resolveWithEngine`, `getManifestWithEngine`, and
//!   the GET fallback inside `validateWithEngine`): one bump arena wraps the caller
//!   allocator for manifest fetch work, including multi-arch child fetches where
//!   applicable. Transient work (canonical error references, HTTP request URLs,
//!   redirect targets, response metadata clones, interim digest buffers, platform
//!   clones during multi-arch selection) uses the arena. Success returns
//!   caller-owned results; `getManifest` promotes `std.json.Parsed(Manifest)` via
//!   `ResolvedManifestSuccess.detachManifestForPromotion` before arena teardown;
//!   `resolve` uses `detachForResolvePromotion` so digest buffers are not freed
//!   while `Digest.hex` still aliases them. Failure promotes `ResolveError.reference`
//!   to the caller allocator before arena teardown. `AuthEngine`, the input
//!   `Reference`, and persistent token cache storage stay on the caller allocator.
//! - `validateWithEngine` is asymmetric: the initial manifest `HEAD` phase allocates
//!   `HeadRequestOutcome` metadata on the caller allocator (same as the public
//!   `validate` contract). Only the optional GET fallback opens a transient arena,
//!   matching `resolve`/`getManifest` fetch semantics for that phase.
//! - `ResolveManyResult` owns every item it returns. Deinit the batch result once
//!   to release every successful `ResolveResult`, every failed `ResolveError`, and
//!   the item array. Batch item failures own both `registry` and `reference`; never
//!   use `deinitResolveFailure` on them (that helper is single-resolve only).
//! - `resolveMany` borrows input `Reference` values. It deep-clones each item before
//!   calling the existing single-resolve path so callers keep uniform ownership of
//!   the input slice on success and failure. Progress callbacks see borrowed
//!   reference views valid only for the callback. An in-call session cache reuses
//!   successful tag / implicit `latest` pins within that one call; digest-addressed
//!   refs bypass the cache.
//! - Types that never allocate: `Digest` (borrowed view), `MediaType` (enum),
//!   `Platform` (struct of slices), `AuthChallenge`/`BearerChallenge` (borrowed views).
//!   These need no deinit.
//!
//! Error surfaces at the public boundary:
//! - `PublicApiError` (`Config.ApplyError`): pre-flight config/TLS setup only (`applyToClient`).
//!   Returned as the API error union, not inside `ResolveOutcome.failure`.
//! - `Reference.ParseError` / `Digest.ParseError`: caller parses before invoking resolve APIs.
//! - `ResolveError`: registry operation failures inside `ResolveOutcome.failure`,
//!   `ValidateOutcome.failure`, or `ManifestOutcome.failure`.
//! - `RegistryPingResult`: `/v2/` probe outcomes. Independent of resolve; resolve never calls ping.
//!
const std = @import("std");
const resolver = @import("resolver.zig");
const resilience = @import("resilience.zig");
const registry_ping = @import("registry_ping.zig");
pub const test_matrix = @import("test_matrix.zig");

pub const Digest = @import("Digest.zig");
pub const MediaType = @import("MediaType.zig").MediaType;
pub const Platform = @import("Platform.zig");
pub const Descriptor = @import("Descriptor.zig");
pub const Manifest = @import("Manifest.zig");
pub const Index = @import("Index.zig");
pub const OciImageIndex = Index.OciImageIndex;
pub const DockerManifestList = Index.DockerManifestList;
pub const MultiArchManifest = Index.MultiArchManifest;
pub const Reference = @import("Reference.zig");
pub const auth = @import("auth.zig");
pub const json = @import("json.zig");
pub const AuthEngine = auth.AuthEngine;
pub const AuthChallenge = auth.AuthChallenge;
pub const AuthReferenceView = auth.AuthReferenceView;
pub const BearerChallenge = auth.BearerChallenge;
pub const AuthenticateRequest = auth.AuthenticateRequest;
pub const ProbeResult = auth.ProbeResult;
pub const ProbeHttpResponse = auth.ProbeHttpResponse;
pub const referenceView = auth.referenceView;
pub const Token = auth.Token;
pub const TokenResponse = auth.TokenResponse;
pub const ResolveError = @import("ResolveError.zig").ResolveError;
pub const ResolveResult = @import("ResolveResult.zig");
pub const Config = @import("Config.zig").Config;
pub const CredentialProvider = @import("Config.zig").CredentialProvider;
pub const Credential = @import("Config.zig").Credential;
pub const CredentialHandle = @import("Config.zig").CredentialHandle;
pub const PublicApiError = Config.ApplyError;
pub const RegistryPingStatus = registry_ping.RegistryPingStatus;
pub const RegistryPingFailure = registry_ping.RegistryPingFailure;
pub const RegistryPingFailureKind = registry_ping.RegistryPingFailureKind;
pub const RegistryPingResult = registry_ping.RegistryPingResult;
pub const testing = struct {
    pub const FailureScenario = test_matrix.Scenario;
    pub const refuseTokenExchange = test_matrix.refuseTokenExchange;
    pub const TokenHttpExchanger = auth.TokenHttpExchanger;
    pub const ManifestHttpExchanger = resolver.ManifestHttpExchanger;
    pub const ManifestHttpRequest = resolver.ManifestHttpRequest;
    pub const ManifestHttpResponse = resolver.ManifestHttpResponse;
    pub const ManifestExchangeError = resolver.ManifestExchangeError;
    pub const PingHttpExchanger = registry_ping.PingHttpExchanger;
    pub const PingHttpRequest = registry_ping.PingHttpRequest;
    pub const PingHttpResponse = registry_ping.PingHttpResponse;
    pub const PingExchangeError = registry_ping.PingExchangeError;

    pub fn pingRegistryWithExchanger(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        registry: []const u8,
        exchanger: PingHttpExchanger,
    ) PublicApiError!RegistryPingResult {
        return root.pingRegistryWithExchanger(allocator, client, config, registry, exchanger);
    }

    pub fn resolveWithExchangers(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        ref: Reference,
        platform: ?Platform,
        token_exchanger: TokenHttpExchanger,
        manifest_exchanger: ManifestHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) PublicApiError!ResolveOutcome {
        return root.resolveWithExchangers(
            allocator,
            client,
            config,
            ref,
            platform,
            token_exchanger,
            manifest_exchanger,
            transport_hooks,
        );
    }

    pub fn resolveWithEngine(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        engine: *auth.AuthEngine,
        ref: Reference,
        platform: ?Platform,
        token_exchanger: TokenHttpExchanger,
        manifest_exchanger: ManifestHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) PublicApiError!ResolveOutcome {
        return root.resolveWithEngine(
            allocator,
            client,
            config,
            engine,
            ref,
            platform,
            token_exchanger,
            manifest_exchanger,
            transport_hooks,
        );
    }

    pub fn validateWithExchangers(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        ref: Reference,
        platform: ?Platform,
        token_exchanger: TokenHttpExchanger,
        manifest_exchanger: ManifestHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) PublicApiError!ValidateOutcome {
        return root.validateWithExchangers(
            allocator,
            client,
            config,
            ref,
            platform,
            token_exchanger,
            manifest_exchanger,
            transport_hooks,
        );
    }

    pub fn validateWithEngine(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        engine: *auth.AuthEngine,
        ref: Reference,
        platform: ?Platform,
        token_exchanger: TokenHttpExchanger,
        manifest_exchanger: ManifestHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) PublicApiError!ValidateOutcome {
        return root.validateWithEngine(
            allocator,
            client,
            config,
            engine,
            ref,
            platform,
            token_exchanger,
            manifest_exchanger,
            transport_hooks,
        );
    }

    pub fn getManifestWithEngine(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        engine: *auth.AuthEngine,
        ref: Reference,
        platform: ?Platform,
        token_exchanger: TokenHttpExchanger,
        manifest_exchanger: ManifestHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) PublicApiError!ManifestOutcome {
        return root.getManifestWithEngine(
            allocator,
            client,
            config,
            engine,
            ref,
            platform,
            token_exchanger,
            manifest_exchanger,
            transport_hooks,
        );
    }

    pub fn getManifestWithExchangers(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        ref: Reference,
        platform: ?Platform,
        token_exchanger: TokenHttpExchanger,
        manifest_exchanger: ManifestHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) PublicApiError!ManifestOutcome {
        return root.getManifestWithExchangers(
            allocator,
            client,
            config,
            ref,
            platform,
            token_exchanger,
            manifest_exchanger,
            transport_hooks,
        );
    }

    pub fn resolveManyWithExchangers(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        refs: []const Reference,
        options: ResolveManyOptions,
        token_exchanger: TokenHttpExchanger,
        manifest_exchanger: ManifestHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) PublicApiError!ResolveManyResult {
        return root.resolveManyWithExchangers(
            allocator,
            client,
            config,
            refs,
            options,
            token_exchanger,
            manifest_exchanger,
            transport_hooks,
        );
    }

    pub fn deinitResolveError(failure: ResolveError, allocator: std.mem.Allocator) void {
        root.deinitResolveFailure(failure, allocator);
    }
};
pub const ResolveOutcome = union(enum) {
    success: ResolveResult,
    failure: ResolveError,
};
pub const ValidateOutcome = union(enum) {
    valid,
    not_found,
    failure: ResolveError,
};
/// `.success` owns a JSON arena (`parsed.deinit()`).
pub const ManifestOutcome = union(enum) {
    success: std.json.Parsed(Manifest),
    failure: ResolveError,
};
/// One batch outcome. Failures own both `registry` and `reference`; never use `deinitResolveFailure`.
pub const ResolveManyItem = union(enum) {
    success: ResolveResult,
    /// Unlike single-resolve failures, owns `registry` as well as `reference`.
    failure: ResolveError,

    pub fn deinit(self: *ResolveManyItem, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |*result| result.deinit(allocator),
            .failure => |failure| deinitResolveManyFailure(failure, allocator),
        }
    }
};
/// Owns the item slice and every item. Call `deinit` once (second call is a no-op).
pub const ResolveManyResult = struct {
    items: []ResolveManyItem,

    pub fn deinit(self: *ResolveManyResult, allocator: std.mem.Allocator) void {
        for (self.items) |*item| item.deinit(allocator);
        if (self.items.len != 0) allocator.free(self.items);
        self.items = &.{};
    }
};
/// Borrowed input slices for progress callbacks; valid only for the callback duration.
pub const ResolveManyReferenceView = struct {
    registry: []const u8,
    repository: []const u8,
    ref_string: []const u8,
};
/// Progress event for `resolveMany`. `reference` borrows for this callback only; do not retain.
/// Callbacks are `void` and cannot fail or abort the batch.
pub const ResolveManyProgress = struct {
    event: Event,
    index: usize,
    total: usize,
    reference: ResolveManyReferenceView,

    pub const Event = enum {
        item_started,
        /// In-call tag / implicit `latest` session cache hit; digest refs never hit.
        cache_hit,
        item_succeeded,
        item_failed,
    };
};
pub const ResolveManyOptions = struct {
    /// Batch-wide; per-item platforms need separate batches.
    platform: ?Platform = null,
    /// Optional observer; must not retain `event.reference` past return.
    progress_fn: ?*const fn (event: ResolveManyProgress, user_data: ?*anyopaque) void = null,
    progress_user_data: ?*anyopaque = null,
};
/// Single-resolve only: frees owned `reference` from `.failure` on `resolve` /
/// `validate` / `getManifest`. `registry` still borrows the input `Reference`.
///
/// Do **not** call this on `ResolveManyItem.failure`: batch failures own both
/// `registry` and `reference`. Use `ResolveManyResult.deinit` or
/// `ResolveManyItem.deinit`, or you will leak `registry`.
pub fn deinitResolveFailure(failure: ResolveError, allocator: std.mem.Allocator) void {
    failure.deinitOwned(allocator);
}
// --- Public resolve API ---

/// Ownership: success moves `ref` identity fields into the result (do not `ref.deinit`).
/// Call `result.deinit(allocator)` unless the allocator is an arena.
pub fn resolve(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
    platform: ?Platform,
) PublicApiError!ResolveOutcome {
    return resolveWithExchangers(
        allocator,
        client,
        config,
        ref,
        platform,
        auth.liveTokenHttpExchanger,
        resolver.liveManifestHttpExchanger,
        resilience.liveTransportHooks(),
    );
}
/// Ownership: `refs` borrowed; result owns every item. One item failure does not abort.
/// Sequential (one `Client` + `AuthEngine`). In-call tag / implicit `latest` session
/// cache only; digest-addressed refs bypass it. Progress views borrow for the callback only.
pub fn resolveMany(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    refs: []const Reference,
    options: ResolveManyOptions,
) PublicApiError!ResolveManyResult {
    return resolveManyWithExchangers(
        allocator,
        client,
        config,
        refs,
        options,
        auth.liveTokenHttpExchanger,
        resolver.liveManifestHttpExchanger,
        resilience.liveTransportHooks(),
    );
}
/// Ownership: no success payload. HEAD uses the caller allocator; GET fallback uses a
/// transient arena and promotes `ResolveError.reference` on failure. `.not_found` is terminal;
/// multi-arch without `platform` → `platform_required`.
pub fn validate(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
    platform: ?Platform,
) PublicApiError!ValidateOutcome {
    return validateWithExchangers(
        allocator,
        client,
        config,
        ref,
        platform,
        auth.liveTokenHttpExchanger,
        resolver.liveManifestHttpExchanger,
        resilience.liveTransportHooks(),
    );
}
/// Ownership: `.success` is a JSON arena (`parsed.deinit()`). Multi-arch without `platform` → `platform_required`.
pub fn getManifest(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
    platform: ?Platform,
) PublicApiError!ManifestOutcome {
    return getManifestWithExchangers(
        allocator,
        client,
        config,
        ref,
        platform,
        auth.liveTokenHttpExchanger,
        resolver.liveManifestHttpExchanger,
        resilience.liveTransportHooks(),
    );
}

/// Probe `https://{registry}/v2/`. Does not fetch manifests and is not used by resolve.
pub fn pingRegistry(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    registry: []const u8,
) PublicApiError!RegistryPingResult {
    return pingRegistryWithExchanger(
        allocator,
        client,
        config,
        registry,
        registry_ping.livePingHttpExchanger,
    );
}

// --- Private helpers ---

const root = @This();
const MAX_CHILD_MANIFEST_DEPTH: usize = 4;
const MANIFEST_ACCEPT_VALUES = [_][]const u8{
    MediaType.oci_manifest_v1.toString(),
    MediaType.docker_manifest_v2.toString(),
    MediaType.oci_index_v1.toString(),
    MediaType.docker_manifest_list_v2.toString(),
};
const ResolvedManifestSuccess = struct {
    // New fields must be torn down in `deinit` and handled in both detach helpers.
    resolved_digest: Digest,
    resolved_digest_raw: []u8,
    document: resolver.ParsedManifestDocument,
    platform: ?Platform,
    backing_body: ?[]u8 = null,

    fn clearDigestAlias(self: *ResolvedManifestSuccess) void {
        self.resolved_digest_raw = "";
        self.resolved_digest = .{ .algorithm = .sha256, .hex = "" };
    }

    fn releaseDigestRaw(self: *ResolvedManifestSuccess, allocator: std.mem.Allocator) void {
        if (self.resolved_digest_raw.len != 0) {
            allocator.free(self.resolved_digest_raw);
            self.clearDigestAlias();
        }
    }

    fn releaseDocument(self: *ResolvedManifestSuccess) void {
        const media_type = switch (self.document) {
            .manifest => |parsed| parsed.value.media_type,
            .manifest_media_type => |value| value,
            else => MediaType.docker_manifest_v2,
        };
        self.document.deinit();
        self.document = .{ .manifest_media_type = media_type };
    }

    fn releaseBackingBody(self: *ResolvedManifestSuccess, allocator: std.mem.Allocator) void {
        if (self.backing_body) |body| {
            allocator.free(body);
            self.backing_body = null;
        }
    }

    fn releasePlatform(self: *ResolvedManifestSuccess, allocator: std.mem.Allocator) void {
        if (self.platform) |platform| {
            deinitOwnedPlatform(platform, allocator);
            self.platform = null;
        }
    }

    fn deinit(self: *ResolvedManifestSuccess, allocator: std.mem.Allocator) void {
        self.releaseDigestRaw(allocator);
        self.releaseDocument();
        self.releaseBackingBody(allocator);
        self.releasePlatform(allocator);
    }

    // Move `Parsed(Manifest)` to `caller_allocator` and leave a `deinit`-safe shell.
    // On error the manifest document is restored; on success digest fields are
    // cleared so `deinit` cannot free `resolved_digest_raw` while `digest.hex`
    // still aliases it.
    fn detachManifestForPromotion(
        self: *ResolvedManifestSuccess,
        caller_allocator: std.mem.Allocator,
    ) !std.json.Parsed(Manifest) {
        const parsed = switch (self.document) {
            .manifest => |parsed| parsed,
            else => unreachable,
        };
        const media_type = parsed.value.media_type;
        self.document = .{ .manifest_media_type = media_type };
        errdefer self.document = .{ .manifest = parsed };

        const promoted = try json.promoteParsed(Manifest, caller_allocator, parsed);
        self.clearDigestAlias();
        return promoted;
    }

    const ResolvePromotionDetach = struct {
        resolved_digest_raw: []u8,
        media_type: MediaType,
        platform: ?Platform,
    };

    // Move caller-promoted resolve fields out and clear digest/document/platform
    // so `deinit` cannot free `resolved_digest_raw` while `resolved_digest.hex`
    // still aliases it.
    fn detachForResolvePromotion(self: *ResolvedManifestSuccess) ResolvePromotionDetach {
        const media_type = switch (self.document) {
            .manifest => |parsed| parsed.value.media_type,
            .manifest_media_type => |value| value,
            else => unreachable,
        };
        const resolved_digest_raw = self.resolved_digest_raw;
        self.clearDigestAlias();
        self.document = .{ .manifest_media_type = media_type };

        const platform = self.platform;
        self.platform = null;

        return .{
            .resolved_digest_raw = resolved_digest_raw,
            .media_type = media_type,
            .platform = platform,
        };
    }
};
const ResolvedManifestOutcome = union(enum) {
    success: ResolvedManifestSuccess,
    failure: ResolveError,
};
const ResolveManySessionCache = struct {
    /// Stack buffer for hit-path key formatting. Oversized keys fall back to heap.
    const cache_key_stack_max = 1024;

    map: std.StringHashMapUnmanaged(ResolveResult) = .empty,

    fn deinit(self: *ResolveManySessionCache, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.map.deinit(allocator);
    }

    fn cloneHit(
        self: *ResolveManySessionCache,
        allocator: std.mem.Allocator,
        ref: Reference,
    ) error{OutOfMemory}!?ResolveResult {
        const key_len = cacheKeyByteLen(ref) orelse return null;

        var stack: [cache_key_stack_max]u8 = undefined;
        var heap_key: ?[]u8 = null;
        defer if (heap_key) |owned| allocator.free(owned);

        const key: []const u8 = if (key_len <= stack.len) blk: {
            break :blk formatCacheKey(stack[0..key_len], ref);
        } else blk: {
            const owned = try allocator.alloc(u8, key_len);
            heap_key = owned;
            break :blk formatCacheKey(owned, ref);
        };

        const cached = self.map.get(key) orelse return null;
        return try cached.clone(allocator);
    }

    fn storeSuccess(
        self: *ResolveManySessionCache,
        allocator: std.mem.Allocator,
        ref: Reference,
        result: ResolveResult,
    ) error{OutOfMemory}!void {
        const key = try cacheKeyAlloc(allocator, ref) orelse return;
        errdefer allocator.free(key);

        std.debug.assert(self.map.get(key) == null);

        var cached = try result.clone(allocator);
        errdefer cached.deinit(allocator);

        try self.map.put(allocator, key, cached);
    }

    fn cacheKeyByteLen(ref: Reference) ?usize {
        if (ref.digest != null) return null;
        return ref.registry.len + 1 + ref.repository.len + 1 + ref.refString().len;
    }

    fn formatCacheKey(buf: []u8, ref: Reference) []u8 {
        const tag = ref.refString();
        std.debug.assert(buf.len == ref.registry.len + 1 + ref.repository.len + 1 + tag.len);
        @memcpy(buf[0..ref.registry.len], ref.registry);
        buf[ref.registry.len] = '/';
        const repo_start = ref.registry.len + 1;
        @memcpy(buf[repo_start..][0..ref.repository.len], ref.repository);
        buf[repo_start + ref.repository.len] = ':';
        @memcpy(buf[repo_start + ref.repository.len + 1 ..][0..tag.len], tag);
        return buf;
    }

    /// Owns a single exact-size key allocation. Digest-addressed refs return null.
    fn cacheKeyAlloc(
        allocator: std.mem.Allocator,
        ref: Reference,
    ) error{OutOfMemory}!?[]u8 {
        const key_len = cacheKeyByteLen(ref) orelse return null;
        const key = try allocator.alloc(u8, key_len);
        return formatCacheKey(key, ref);
    }
};
const ResolveManySession = struct {
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    engine: auth.AuthEngine,
    token_exchanger: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    transport_hooks: resilience.TransportHooks,
    cache: ResolveManySessionCache = .{},

    fn init(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        token_exchanger: auth.TokenHttpExchanger,
        manifest_exchanger: resolver.ManifestHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) PublicApiError!ResolveManySession {
        try ensureClientConfigured(config, client);

        return .{
            .allocator = allocator,
            .client = client,
            .config = config,
            .engine = auth.AuthEngine.initWithTokenHttpExchangerAndHooks(
                allocator,
                config,
                token_exchanger,
                transport_hooks,
            ),
            .token_exchanger = token_exchanger,
            .manifest_exchanger = manifest_exchanger,
            .transport_hooks = transport_hooks,
        };
    }

    fn deinit(self: *ResolveManySession) void {
        self.cache.deinit(self.allocator);
        self.engine.deinit();
    }
};
fn ensureClientConfigured(config: Config, client: *std.http.Client) PublicApiError!void {
    return config.applyToClient(client);
}
fn pingRegistryWithExchanger(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    registry: []const u8,
    exchanger: registry_ping.PingHttpExchanger,
) PublicApiError!RegistryPingResult {
    try ensureClientConfigured(config, client);
    return registry_ping.pingRegistryWithExchanger(allocator, client, registry, exchanger);
}
fn resolveWithExchangers(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
    platform: ?Platform,
    token_exchanger: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    transport_hooks: resilience.TransportHooks,
) PublicApiError!ResolveOutcome {
    try ensureClientConfigured(config, client);

    var engine = auth.AuthEngine.initWithTokenHttpExchangerAndHooks(allocator, config, token_exchanger, transport_hooks);
    defer engine.deinit();

    return resolveWithEngine(
        allocator,
        client,
        config,
        &engine,
        ref,
        platform,
        token_exchanger,
        manifest_exchanger,
        transport_hooks,
    );
}
fn resolveManyWithExchangers(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    refs: []const Reference,
    options: ResolveManyOptions,
    token_exchanger: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    transport_hooks: resilience.TransportHooks,
) PublicApiError!ResolveManyResult {
    var session = try ResolveManySession.init(
        allocator,
        client,
        config,
        token_exchanger,
        manifest_exchanger,
        transport_hooks,
    );
    defer session.deinit();

    return resolveManyWithSession(&session, refs, options);
}
fn resolveManyWithSession(
    session: *ResolveManySession,
    refs: []const Reference,
    options: ResolveManyOptions,
) PublicApiError!ResolveManyResult {
    if (refs.len == 0) return .{ .items = &.{} };

    const allocator = session.allocator;
    // Upper bound on unique tag-cache entries (digest refs bypass; duplicates share).
    const cache_cap: u32 = @intCast(@min(refs.len, std.math.maxInt(u32)));
    try session.cache.map.ensureTotalCapacity(allocator, cache_cap);

    var items = try allocator.alloc(ResolveManyItem, refs.len);
    var initialized_items: usize = 0;
    errdefer {
        for (items[0..initialized_items]) |*item| item.deinit(allocator);
        allocator.free(items);
    }

    for (refs, 0..) |input_ref, index| {
        emitResolveManyProgress(options, .item_started, index, refs.len, input_ref);

        if (try session.cache.cloneHit(allocator, input_ref)) |cached_success| {
            items[index] = .{ .success = cached_success };
            initialized_items += 1;
            emitResolveManyProgress(options, .cache_hit, index, refs.len, input_ref);
            emitResolveManyProgress(
                options,
                .item_succeeded,
                index,
                refs.len,
                input_ref,
            );
            continue;
        }

        var item_ref = try cloneReferenceAlloc(allocator, input_ref);

        const outcome = resolveWithEngine(
            allocator,
            session.client,
            session.config,
            &session.engine,
            item_ref,
            options.platform,
            session.token_exchanger,
            session.manifest_exchanger,
            session.transport_hooks,
        ) catch |err| {
            item_ref.deinit(allocator);
            return err;
        };

        switch (outcome) {
            .success => |success| {
                items[index] = .{ .success = success };
                initialized_items += 1;
                try session.cache.storeSuccess(allocator, input_ref, items[index].success);
                emitResolveManyProgress(
                    options,
                    .item_succeeded,
                    index,
                    refs.len,
                    input_ref,
                );
            },
            .failure => |failure| {
                const batch_failure = cloneResolveErrorRegistryAlloc(allocator, failure) catch |err| {
                    deinitResolveFailure(failure, allocator);
                    item_ref.deinit(allocator);
                    return err;
                };
                item_ref.deinit(allocator);
                items[index] = .{ .failure = batch_failure };
                initialized_items += 1;
                emitResolveManyProgress(options, .item_failed, index, refs.len, input_ref);
            },
        }
    }

    return .{ .items = items };
}
fn resolveWithEngine(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    engine: *auth.AuthEngine,
    ref: Reference,
    platform: ?Platform,
    _: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    transport_hooks: resilience.TransportHooks,
) PublicApiError!ResolveOutcome {
    var resolve_arena = std.heap.ArenaAllocator.init(allocator);
    defer resolve_arena.deinit();
    const transient = resolve_arena.allocator();

    var manifest_throttle: resilience.ManifestThrottle = .{};
    var outcome = try fetchResolvedManifestWithExchangers(
        transient,
        client,
        config,
        engine,
        referenceView(ref),
        platform,
        manifest_exchanger,
        .resolve,
        0,
        transport_hooks,
        &manifest_throttle,
    );
    switch (outcome) {
        .success => |*success| {
            const detached = success.detachForResolvePromotion();
            defer success.deinit(transient);
            errdefer if (detached.platform) |value| deinitOwnedPlatform(value, transient);

            const caller_digest_raw = try allocator.dupe(u8, detached.resolved_digest_raw);
            errdefer allocator.free(caller_digest_raw);

            const caller_platform: ?Platform = if (platform) |requested|
                try clonePlatformAlloc(allocator, requested)
            else
                null;
            errdefer if (caller_platform) |value| deinitOwnedPlatform(value, allocator);

            return .{ .success = try buildResolveResultAlloc(
                allocator,
                ref,
                caller_digest_raw,
                detached.media_type,
                caller_platform,
            ) };
        },
        .failure => {
            return .{ .failure = try promoteResolvedManifestFailure(allocator, transient, &outcome) };
        },
    }
}
fn validateWithExchangers(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
    platform: ?Platform,
    token_exchanger: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    transport_hooks: resilience.TransportHooks,
) PublicApiError!ValidateOutcome {
    var engine = auth.AuthEngine.initWithTokenHttpExchangerAndHooks(allocator, config, token_exchanger, transport_hooks);
    defer engine.deinit();
    return validateWithEngine(
        allocator,
        client,
        config,
        &engine,
        ref,
        platform,
        token_exchanger,
        manifest_exchanger,
        transport_hooks,
    );
}
fn validateWithEngine(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    engine: *auth.AuthEngine,
    ref: Reference,
    platform: ?Platform,
    _: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    transport_hooks: resilience.TransportHooks,
) PublicApiError!ValidateOutcome {
    // HEAD uses `allocator` (see `validate` doc). GET fallback below uses a transient arena.
    try ensureClientConfigured(config, client);

    const ref_view = referenceView(ref);
    var manifest_throttle: resilience.ManifestThrottle = .{};
    const ctx = resolver.ResolverParams.initWithTransportHooks(
        allocator,
        client,
        config,
        ref_view,
        platform,
        .validate,
        transport_hooks,
    ).withManifestThrottle(&manifest_throttle);

    const head_outcome = try resolver.performManifestHead(ctx, engine, manifest_exchanger, manifestAcceptValues());
    var owned_head_outcome = head_outcome;
    defer owned_head_outcome.deinit(allocator);

    const head_decision = try resolver.classifyValidateManifestHead(allocator, ref_view, &owned_head_outcome);
    switch (head_decision) {
        .valid => return .valid,
        .not_found => return .not_found,
        .owned_failure => |failure| return .{ .failure = failure },
        .inspect_multi_arch_head => {
            const metadata = switch (owned_head_outcome) {
                .success => |value| value,
                else => unreachable,
            };
            if (try validateOutcomeFromHeadMetadata(allocator, ref_view, platform, metadata)) |outcome| {
                return outcome;
            }
        },
        .proceed_with_get => {},
    }

    var validate_arena = std.heap.ArenaAllocator.init(allocator);
    defer validate_arena.deinit();
    const transient = validate_arena.allocator(); // GET fallback only; HEAD used `allocator` above.

    var outcome = try fetchResolvedManifestWithExchangers(
        transient,
        client,
        config,
        engine,
        ref_view,
        platform,
        manifest_exchanger,
        .validate,
        0,
        transport_hooks,
        &manifest_throttle,
    );
    return try validateOutcomeFromResolvedManifestOutcome(allocator, transient, &outcome);
}
fn promoteResolvedManifestFailure(
    caller_allocator: std.mem.Allocator,
    outcome_allocator: std.mem.Allocator,
    outcome: *ResolvedManifestOutcome,
) !ResolveError {
    const promoted = try promoteResolveErrorAlloc(caller_allocator, outcome.failure);
    outcome.failure.releaseOwnedReference(outcome_allocator);
    return promoted;
}
fn validateOutcomeFromResolvedManifestOutcome(
    caller_allocator: std.mem.Allocator,
    outcome_allocator: std.mem.Allocator,
    outcome: *ResolvedManifestOutcome,
) PublicApiError!ValidateOutcome {
    switch (outcome.*) {
        .success => |*success| {
            defer success.deinit(outcome_allocator);
            return switch (success.document) {
                .manifest, .manifest_media_type => .valid,
                else => unreachable,
            };
        },
        .failure => |*failure| switch (failure.*) {
            .not_found => {
                failure.releaseOwnedReference(outcome_allocator);
                return .not_found;
            },
            else => {
                const promoted = try promoteResolveErrorAlloc(caller_allocator, failure.*);
                failure.releaseOwnedReference(outcome_allocator);
                return .{ .failure = promoted };
            },
        },
    }
}
fn validateOutcomeFromHeadMetadata(
    allocator: std.mem.Allocator,
    ref_view: AuthReferenceView,
    platform: ?Platform,
    metadata: resolver.ManifestResponseMetadata,
) error{OutOfMemory}!?ValidateOutcome {
    const content_type = metadata.content_type orelse return null;
    const media_type = manifestResponseMediaType(content_type) orelse return null;

    if (!media_type.isMultiArch()) return .valid;
    if (platform == null) {
        return .{ .failure = try platformRequiredErrorAlloc(allocator, ref_view) };
    }

    return null;
}
fn manifestResponseMediaType(content_type: []const u8) ?MediaType {
    const without_parameters = content_type[0..(std.mem.indexOfScalar(u8, content_type, ';') orelse content_type.len)];
    return MediaType.fromString(std.mem.trim(u8, without_parameters, " \t\r\n"));
}
fn getManifestWithExchangers(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
    platform: ?Platform,
    token_exchanger: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    transport_hooks: resilience.TransportHooks,
) PublicApiError!ManifestOutcome {
    var engine = auth.AuthEngine.initWithTokenHttpExchangerAndHooks(allocator, config, token_exchanger, transport_hooks);
    defer engine.deinit();
    return getManifestWithEngine(
        allocator,
        client,
        config,
        &engine,
        ref,
        platform,
        token_exchanger,
        manifest_exchanger,
        transport_hooks,
    );
}
fn getManifestWithEngine(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    engine: *auth.AuthEngine,
    ref: Reference,
    platform: ?Platform,
    _: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    transport_hooks: resilience.TransportHooks,
) PublicApiError!ManifestOutcome {
    try ensureClientConfigured(config, client);

    var get_arena = std.heap.ArenaAllocator.init(allocator);
    defer get_arena.deinit();
    const transient = get_arena.allocator();

    var manifest_throttle: resilience.ManifestThrottle = .{};
    var outcome = try fetchResolvedManifestWithExchangers(
        transient,
        client,
        config,
        engine,
        referenceView(ref),
        platform,
        manifest_exchanger,
        .get_manifest,
        0,
        transport_hooks,
        &manifest_throttle,
    );
    switch (outcome) {
        .success => |*success| {
            const parsed_manifest = success.detachManifestForPromotion(allocator) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    defer success.deinit(transient);
                    return .{ .failure = try manifestParseErrorAlloc(allocator, referenceView(ref)) };
                },
            };
            defer success.deinit(transient);
            return .{ .success = parsed_manifest };
        },
        .failure => {
            return .{ .failure = try promoteResolvedManifestFailure(allocator, transient, &outcome) };
        },
    }
}
fn validateResolvedManifestFromChildHead(
    allocator: std.mem.Allocator,
    ref_view: AuthReferenceView,
    head_outcome: resolver.HeadRequestOutcome,
) PublicApiError!ResolvedManifestOutcome {
    var owned_head = head_outcome;
    defer owned_head.deinit(allocator);
    const mapped = try resolver.mapChildValidateHeadOutcome(allocator, ref_view, &owned_head);
    return switch (mapped) {
        .success_manifest_media_type => |media_type| blk: {
            const resolved_digest = Digest.parse(ref_view.ref_string) catch {
                break :blk .{ .failure = try digestMismatchErrorAlloc(allocator, ref_view) };
            };
            const resolved_digest_raw = try allocator.dupe(u8, ref_view.ref_string);
            errdefer allocator.free(resolved_digest_raw);

            break :blk .{ .success = .{
                .resolved_digest = resolved_digest,
                .resolved_digest_raw = resolved_digest_raw,
                .document = .{ .manifest_media_type = media_type },
                .platform = null,
            } };
        },
        .not_found => .{ .failure = try notFoundErrorAlloc(allocator, ref_view) },
        .owned_failure => |failure| .{ .failure = failure },
    };
}
fn digestMismatchErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .digest_mismatch, null, false);
}
fn contentTypeMismatchErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .content_type_mismatch, null, false);
}
fn manifestParseErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .manifest_parse_error, null, false);
}
fn fetchResolvedManifestWithExchangers(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    engine: *auth.AuthEngine,
    ref_view: AuthReferenceView,
    platform: ?Platform,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    operation: resolver.ResolverOperation,
    depth: usize,
    transport_hooks: resilience.TransportHooks,
    manifest_throttle: *resilience.ManifestThrottle,
) PublicApiError!ResolvedManifestOutcome {
    if (depth > MAX_CHILD_MANIFEST_DEPTH) {
        return .{ .failure = try depthLimitExceededErrorAlloc(allocator, ref_view) };
    }

    const ctx = resolver.ResolverParams.initWithTransportHooks(
        allocator,
        client,
        config,
        ref_view,
        platform,
        if (depth == 0) operation else switch (operation) {
            .get_manifest, .validate => operation,
            else => .resolve_child_manifest,
        },
        transport_hooks,
    ).withManifestThrottle(manifest_throttle);

    if (operation == .validate and depth > 0) {
        const head_outcome = try resolver.performManifestHead(ctx, engine, manifest_exchanger, manifestAcceptValues());
        return try validateResolvedManifestFromChildHead(allocator, ref_view, head_outcome);
    }

    var outcome = try resolver.performManifestGet(ctx, engine, manifest_exchanger, manifestAcceptValues());
    switch (outcome) {
        .success => |*success| {
            const document = success.document;
            const resolved_digest = success.resolved_digest;
            const resolved_digest_raw = success.resolved_digest_raw;
            const backing_body = success.backing_body;
            success.backing_body = null;

            switch (document) {
                .manifest, .manifest_media_type => {
                    return .{ .success = .{
                        .resolved_digest = resolved_digest,
                        .resolved_digest_raw = resolved_digest_raw,
                        .document = document,
                        .platform = null,
                        .backing_body = backing_body,
                    } };
                },
                .oci_index => |parsed| {
                    return recurseIntoMultiArchDocument(
                        allocator,
                        client,
                        config,
                        engine,
                        ref_view,
                        platform,
                        manifest_exchanger,
                        operation,
                        depth,
                        resolved_digest_raw,
                        document,
                        backing_body,
                        transport_hooks,
                        manifest_throttle,
                        .{ .oci = parsed.value },
                    );
                },
                .docker_manifest_list => |parsed| {
                    return recurseIntoMultiArchDocument(
                        allocator,
                        client,
                        config,
                        engine,
                        ref_view,
                        platform,
                        manifest_exchanger,
                        operation,
                        depth,
                        resolved_digest_raw,
                        document,
                        backing_body,
                        transport_hooks,
                        manifest_throttle,
                        .{ .docker = parsed.value },
                    );
                },
            }
        },
        .not_found => return .{ .failure = try notFoundErrorAlloc(allocator, ref_view) },
        .redirect => |metadata| {
            defer metadata.deinitOwned(allocator);
            return .{ .failure = try networkErrorAlloc(allocator, ref_view, metadata.httpStatus()) };
        },
        .failure => |failure| return .{ .failure = failure },
    }
}
fn recurseIntoMultiArchDocument(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    engine: *auth.AuthEngine,
    ref_view: AuthReferenceView,
    platform: ?Platform,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    operation: resolver.ResolverOperation,
    depth: usize,
    parent_digest_raw: []u8,
    parent_document: resolver.ParsedManifestDocument,
    parent_backing_body: ?[]u8,
    transport_hooks: resilience.TransportHooks,
    manifest_throttle: *resilience.ManifestThrottle,
    multi_arch: MultiArchManifest,
) PublicApiError!ResolvedManifestOutcome {
    defer allocator.free(parent_digest_raw);
    defer if (parent_backing_body) |body| allocator.free(body);

    var owned_parent_document = parent_document;
    var parent_document_live = true;
    defer if (parent_document_live) owned_parent_document.deinit();

    const requested_platform = platform orelse {
        return .{ .failure = try platformRequiredErrorAlloc(allocator, ref_view) };
    };
    const child_descriptor = multi_arch.selectChildDescriptorByPlatform(requested_platform) orelse {
        return .{ .failure = try platformNotFoundErrorAlloc(allocator, ref_view) };
    };

    var child_ref_string_buffer: [128]u8 = undefined;
    const child_ref_string = std.fmt.bufPrint(
        &child_ref_string_buffer,
        "{s}:{s}",
        .{ @tagName(child_descriptor.digest.algorithm), child_descriptor.digest.hex },
    ) catch unreachable;

    owned_parent_document.deinit();
    parent_document_live = false;

    const child_outcome = try fetchResolvedManifestWithExchangers(
        allocator,
        client,
        config,
        engine,
        .{
            .registry = ref_view.registry,
            .repository_path = ref_view.repository_path,
            .ref_string = child_ref_string,
        },
        platform,
        manifest_exchanger,
        operation,
        depth + 1,
        transport_hooks,
        manifest_throttle,
    );

    return child_outcome;
}
fn manifestAcceptValues() []const []const u8 {
    return &MANIFEST_ACCEPT_VALUES;
}
fn buildResolveResultAlloc(
    allocator: std.mem.Allocator,
    ref: Reference,
    resolved_digest_raw: []u8,
    media_type: MediaType,
    platform: ?Platform,
) error{OutOfMemory}!ResolveResult {
    var resolved_reference = buildResolvedReferenceAlloc(allocator, ref, resolved_digest_raw);
    errdefer resolved_reference.deinit(allocator);

    return .{
        .digest = resolved_reference.digest.?,
        .media_type = media_type,
        .platform = platform,
        .reference = resolved_reference,
    };
}
fn buildResolvedReferenceAlloc(
    allocator: std.mem.Allocator,
    ref: Reference,
    resolved_digest_raw: []u8,
) Reference {
    var resolved = ref;
    if (resolved.digest_raw) |old_raw| allocator.free(old_raw);

    resolved.digest_raw = resolved_digest_raw;
    resolved.digest = Digest.parse(resolved_digest_raw) catch unreachable;
    return resolved;
}
fn notFoundErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .not_found, null, false);
}
fn networkErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView, http_status: ?u16) !ResolveError {
    return allocatedResolveError(allocator, ref, .network_error, http_status, false);
}
fn platformNotFoundErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .platform_not_found, null, false);
}
fn platformRequiredErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .platform_required, null, false);
}
fn depthLimitExceededErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .depth_limit_exceeded, null, false);
}
fn allocatedResolveError(
    allocator: std.mem.Allocator,
    ref: AuthReferenceView,
    comptime tag: std.meta.Tag(ResolveError),
    http_status: ?u16,
    transport_retries_exhausted: bool,
) !ResolveError {
    return resolver.ownedResolveErrorAlloc(allocator, ref, tag, http_status, transport_retries_exhausted);
}
fn clonePlatformAlloc(allocator: std.mem.Allocator, platform: Platform) !Platform {
    const os = try allocator.dupe(u8, platform.os);
    errdefer allocator.free(os);

    const architecture = try allocator.dupe(u8, platform.architecture);
    errdefer allocator.free(architecture);

    const variant = if (platform.variant) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (variant) |value| allocator.free(value);

    const os_version = if (platform.os_version) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (os_version) |value| allocator.free(value);

    const os_features = if (platform.os_features) |features|
        try clonePlatformFeaturesAlloc(allocator, features)
    else
        null;
    errdefer if (os_features) |features| freePlatformFeatures(features, allocator);

    return .{
        .os = os,
        .architecture = architecture,
        .variant = variant,
        .os_version = os_version,
        .os_features = os_features,
    };
}
fn clonePlatformFeaturesAlloc(allocator: std.mem.Allocator, features: []const []const u8) ![]const []const u8 {
    const owned = try allocator.alloc([]const u8, features.len);
    errdefer allocator.free(owned);

    var cloned_count: usize = 0;
    errdefer {
        for (owned[0..cloned_count]) |feature| allocator.free(feature);
    }

    for (features, 0..) |feature, index| {
        owned[index] = try allocator.dupe(u8, feature);
        cloned_count += 1;
    }
    return owned;
}
fn freePlatformFeatures(features: []const []const u8, allocator: std.mem.Allocator) void {
    for (features) |feature| allocator.free(feature);
    allocator.free(features);
}
fn deinitOwnedPlatform(platform: Platform, allocator: std.mem.Allocator) void {
    allocator.free(platform.os);
    allocator.free(platform.architecture);
    if (platform.variant) |variant| allocator.free(variant);
    if (platform.os_version) |os_version| allocator.free(os_version);
    if (platform.os_features) |features| freePlatformFeatures(features, allocator);
}
fn cloneReferenceAlloc(allocator: std.mem.Allocator, ref: Reference) !Reference {
    const registry = try allocator.dupe(u8, ref.registry);
    errdefer allocator.free(registry);

    const repository = try allocator.dupe(u8, ref.repository);
    errdefer allocator.free(repository);

    const tag = if (ref.tag) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (tag) |value| allocator.free(value);

    const digest_raw = if (ref.digest_raw) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (digest_raw) |value| allocator.free(value);

    const digest = if (digest_raw) |value|
        Digest.parse(value) catch unreachable
    else
        null;

    return .{
        .registry = registry,
        .repository = repository,
        .tag = tag,
        .digest = digest,
        .digest_raw = digest_raw,
    };
}
fn resolveManyReferenceView(ref: Reference) ResolveManyReferenceView {
    return .{
        .registry = ref.registry,
        .repository = ref.repository,
        .ref_string = ref.refString(),
    };
}
fn emitResolveManyProgress(
    options: ResolveManyOptions,
    event: ResolveManyProgress.Event,
    index: usize,
    total: usize,
    ref: Reference,
) void {
    if (options.progress_fn) |progress_fn| {
        progress_fn(.{
            .event = event,
            .index = index,
            .total = total,
            .reference = resolveManyReferenceView(ref),
        }, options.progress_user_data);
    }
}
fn deinitOwnedResolveError(failure: ResolveError, allocator: std.mem.Allocator) void {
    deinitResolveFailure(failure, allocator);
}
fn deinitResolveManyFailure(failure: ResolveError, allocator: std.mem.Allocator) void {
    switch (failure) {
        inline else => |value| {
            allocator.free(value.registry);
            allocator.free(value.reference);
        },
    }
}
fn promoteResolveErrorAlloc(allocator: std.mem.Allocator, failure: ResolveError) !ResolveError {
    const owned_reference = try allocator.dupe(u8, switch (failure) {
        inline else => |value| value.reference,
    });
    errdefer allocator.free(owned_reference);
    return failure.withOwnedReference(owned_reference);
}
fn cloneResolveErrorRegistryAlloc(allocator: std.mem.Allocator, failure: ResolveError) !ResolveError {
    const owned_registry = try allocator.dupe(u8, switch (failure) {
        inline else => |value| value.registry,
    });
    errdefer allocator.free(owned_registry);

    return switch (failure) {
        .auth_failed => |value| .{ .auth_failed = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .not_found => |value| .{ .not_found = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .rate_limited => |value| .{ .rate_limited = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
            .transport_retries_exhausted = value.transport_retries_exhausted,
        } },
        .digest_mismatch => |value| .{ .digest_mismatch = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .platform_not_found => |value| .{ .platform_not_found = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .platform_required => |value| .{ .platform_required = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .manifest_parse_error => |value| .{ .manifest_parse_error = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .network_error => |value| .{ .network_error = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
            .transport_retries_exhausted = value.transport_retries_exhausted,
        } },
        .unsupported_algorithm => |value| .{ .unsupported_algorithm = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .content_type_mismatch => |value| .{ .content_type_mismatch = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .timeout => |value| .{ .timeout = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
            .transport_retries_exhausted = value.transport_retries_exhausted,
        } },
        .depth_limit_exceeded => |value| .{ .depth_limit_exceeded = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
        .response_too_large => |value| .{ .response_too_large = .{
            .registry = owned_registry,
            .reference = value.reference,
            .http_status = value.http_status,
        } },
    };
}
const expectResolveFailure = test_matrix.expectResolveFailure;
const readFixtureAlloc = test_matrix.readFixtureAlloc;
const sha256DigestStringAlloc = test_matrix.sha256DigestStringAlloc;
const buildIndexBodyAlloc = test_matrix.buildIndexBodyAlloc;

const busybox_fixture = "fixtures/manifests/busybox-amd64-live-oci-manifest.json";
const busybox_literal_ref = Reference{
    .registry = "registry-1.docker.io",
    .repository = "library/busybox",
    .tag = "latest",
    .digest = null,
    .digest_raw = null,
};

fn skipUnlessTls() !void {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;
}

fn refuseToken(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: auth.TokenHttpRequest,
) auth.AuthError!auth.TokenExchangeResponse {
    return test_matrix.refuseTokenExchange(allocator, client, request);
}

fn busyboxManifestExchange(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    request: resolver.ManifestHttpRequest,
) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
    defer request.deinit(allocator);

    const body = readFixtureAlloc(allocator, busybox_fixture, 16 * 1024) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.TransportFailed,
    };
    defer allocator.free(body);

    const digest = try sha256DigestStringAlloc(allocator, body);
    defer allocator.free(digest);

    return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
        .status = .ok,
        .content_type = MediaType.oci_manifest_v1.toString(),
        .docker_content_digest = digest,
    }, body);
}

fn expectPlatformRequiredFailure(failure: ResolveError) !void {
    try expectResolveFailure(
        failure,
        "platform_required",
        "registry-1.docker.io",
        "registry-1.docker.io/library/busybox:latest",
        null,
        null,
    );
}

// Pulling every sub-module into the test build.
// zig test only includes tests from the root file unless sub-modules are
// referenced here. Each @import forces the compiler to compile that file in
// test mode, which makes its test blocks visible to the test runner.

// --- Tests ---

test {
    _ = @import("Digest.zig");
    _ = @import("MediaType.zig");
    _ = @import("Platform.zig");
    _ = @import("Reference.zig");
    _ = @import("Descriptor.zig");
    _ = @import("Manifest.zig");
    _ = @import("Index.zig");
    _ = @import("auth.zig");
    _ = @import("json.zig");
    _ = @import("ResolveError.zig");
    _ = @import("ResolveResult.zig");
    _ = @import("Config.zig");
    _ = @import("resolver.zig");
    _ = @import("resilience.zig");
    _ = @import("test_support.zig");
    _ = @import("test_matrix.zig");
}

fn testingResolveResultAlloc(
    allocator: std.mem.Allocator,
    tag: []const u8,
    digest_byte: u8,
) !ResolveResult {
    const digest_hex = try allocator.alloc(u8, 64);
    errdefer allocator.free(digest_hex);
    @memset(digest_hex, digest_byte);

    const registry = try allocator.dupe(u8, "registry.example.test");
    errdefer allocator.free(registry);

    const repository = try allocator.dupe(u8, "owner/repo");
    errdefer allocator.free(repository);

    const tag_owned = try allocator.dupe(u8, tag);
    errdefer allocator.free(tag_owned);

    return .{
        .digest = .{ .algorithm = .sha256, .hex = digest_hex },
        .media_type = .oci_manifest_v1,
        .platform = null,
        .reference = .{
            .registry = registry,
            .repository = repository,
            .tag = tag_owned,
            .digest = null,
            .digest_raw = null,
        },
    };
}

fn testingResolveFailureAlloc(
    allocator: std.mem.Allocator,
    reference: []const u8,
) !ResolveError {
    const registry_owned = try allocator.dupe(u8, "registry.example.test");
    errdefer allocator.free(registry_owned);

    const reference_owned = try allocator.dupe(u8, reference);
    errdefer allocator.free(reference_owned);

    return .{ .not_found = .{
        .registry = registry_owned,
        .reference = reference_owned,
        .http_status = 404,
    } };
}

test "ResolveManyResult.deinit: empty result is safe" {
    var result = ResolveManyResult{ .items = &.{} };

    result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "ResolveManyResult.deinit: second call is a no-op" {
    const allocator = std.testing.allocator;
    var items = try allocator.alloc(ResolveManyItem, 1);
    items[0] = .{ .success = try testingResolveResultAlloc(allocator, "v1", 'a') };

    var result = ResolveManyResult{ .items = items };
    result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), result.items.len);

    result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "ResolveManyResult.deinit: releases single success item" {
    const allocator = std.testing.allocator;
    var items = try allocator.alloc(ResolveManyItem, 1);
    errdefer if (items.len != 0) allocator.free(items);
    items[0] = .{ .success = try testingResolveResultAlloc(allocator, "v1", 'a') };

    var result = ResolveManyResult{ .items = items };
    result.deinit(allocator);
    items = &.{};

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "ResolveManyResult.deinit: releases single failure item" {
    const allocator = std.testing.allocator;
    var items = try allocator.alloc(ResolveManyItem, 1);
    errdefer if (items.len != 0) allocator.free(items);
    items[0] = .{ .failure = try testingResolveFailureAlloc(
        allocator,
        "registry.example.test/owner/repo:missing",
    ) };

    var result = ResolveManyResult{ .items = items };
    result.deinit(allocator);
    items = &.{};

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "ResolveManyResult.deinit: releases multiple success items" {
    const allocator = std.testing.allocator;
    var items = try allocator.alloc(ResolveManyItem, 2);
    var initialized_items: usize = 0;
    errdefer {
        for (items[0..initialized_items]) |*item| item.deinit(allocator);
        if (items.len != 0) allocator.free(items);
    }

    items[0] = .{ .success = try testingResolveResultAlloc(allocator, "latest", 'b') };
    initialized_items += 1;

    items[1] = .{ .success = try testingResolveResultAlloc(allocator, "latest", 'b') };
    initialized_items += 1;

    var result = ResolveManyResult{ .items = items };
    result.deinit(allocator);
    initialized_items = 0;
    items = &.{};

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "cloneReferenceAlloc: digest input owns independent digest alias" {
    const allocator = std.testing.allocator;
    var original = try Reference.parse(
        allocator,
        "registry.example.test/owner/repo:tag@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
    );
    defer original.deinit(allocator);

    var cloned = try cloneReferenceAlloc(allocator, original);
    defer cloned.deinit(allocator);

    try std.testing.expectEqualStrings(original.registry, cloned.registry);
    try std.testing.expectEqualStrings(original.repository, cloned.repository);
    try std.testing.expectEqualStrings(original.tag.?, cloned.tag.?);
    try std.testing.expectEqualStrings(original.digest_raw.?, cloned.digest_raw.?);
    try std.testing.expectEqualStrings(original.digest.?.hex, cloned.digest.?.hex);
    try std.testing.expect(original.registry.ptr != cloned.registry.ptr);
    try std.testing.expect(original.repository.ptr != cloned.repository.ptr);
    try std.testing.expect(original.tag.?.ptr != cloned.tag.?.ptr);
    try std.testing.expect(original.digest_raw.?.ptr != cloned.digest_raw.?.ptr);
    try std.testing.expect(@intFromPtr(cloned.digest.?.hex.ptr) >= @intFromPtr(cloned.digest_raw.?.ptr));
    try std.testing.expect(
        @intFromPtr(cloned.digest.?.hex.ptr) + cloned.digest.?.hex.len <=
            @intFromPtr(cloned.digest_raw.?.ptr) + cloned.digest_raw.?.len,
    );
}

test "cloneReferenceAlloc: allocation failures do not leak partially cloned reference" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const original = try Reference.parse(
        arena_allocator,
        "registry.example.test/owner/repo:tag@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
    );

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, ref: Reference) !void {
            var cloned = try cloneReferenceAlloc(allocator, ref);
            defer cloned.deinit(allocator);

            try std.testing.expectEqualStrings(ref.registry, cloned.registry);
            try std.testing.expectEqualStrings(ref.digest_raw.?, cloned.digest_raw.?);
            try std.testing.expectEqualStrings(ref.digest.?.hex, cloned.digest.?.hex);
        }
    }.run, .{original});
}

test "resolveManyWithExchangers: empty batch returns empty result" {
    var client: std.http.Client = undefined;

    var result = try testing.resolveManyWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        &.{},
        .{},
        refuseToken,
        busyboxManifestExchange,
        .{},
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "resolveManyWithExchangers: empty batch emits no progress events" {
    const MockHarness = struct {
        var event_count: usize = 0;

        fn progress(_: ResolveManyProgress, _: ?*anyopaque) void {
            event_count += 1;
        }
    };
    defer MockHarness.event_count = 0;

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        &.{},
        .{ .progress_fn = MockHarness.progress },
        refuseToken,
        busyboxManifestExchange,
        .{},
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), MockHarness.event_count);
}

test "resolveManyWithExchangers: empty batch applies config before returning" {
    try skipUnlessTls();

    const MockHarness = struct {
        var token_calls: usize = 0;
        var manifest_calls: usize = 0;

        fn tokenExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: auth.TokenHttpRequest,
        ) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(allocator);
            token_calls += 1;
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            request.deinit(allocator);
            manifest_calls += 1;
            return error.TransportFailed;
        }
    };
    defer {
        MockHarness.token_calls = 0;
        MockHarness.manifest_calls = 0;
    }

    var client = std.http.Client{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer client.deinit();

    const result = testing.resolveManyWithExchangers(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" },
        &.{},
        .{},
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    try std.testing.expectError(error.CaBundleFileNotFound, result);
    try std.testing.expectEqual(@as(usize, 0), MockHarness.token_calls);
    try std.testing.expectEqual(@as(usize, 0), MockHarness.manifest_calls);
}

test "pingRegistryWithExchanger: anonymous and auth-required outcomes" {
    const MockHarness = struct {
        var status: std.http.Status = .ok;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: registry_ping.PingHttpRequest) registry_ping.PingExchangeError!registry_ping.PingHttpResponse {
            defer request.deinit(allocator);
            if (!std.mem.eql(u8, request.url, "https://registry.example.test/v2/")) return error.TransportFailed;
            return .{ .status = status };
        }
    };

    var client: std.http.Client = undefined;

    MockHarness.status = .ok;
    try std.testing.expectEqual(
        RegistryPingStatus.reachable_anonymous,
        (try testing.pingRegistryWithExchanger(
            std.testing.allocator,
            &client,
            Config{},
            "registry.example.test",
            MockHarness.exchange,
        )).ok,
    );

    MockHarness.status = .unauthorized;
    try std.testing.expectEqual(
        RegistryPingStatus.reachable_auth_required,
        (try testing.pingRegistryWithExchanger(
            std.testing.allocator,
            &client,
            Config{},
            "registry.example.test",
            MockHarness.exchange,
        )).ok,
    );
}

test "pingRegistryWithExchanger: unexpected status and network failure" {
    const MockHarness = struct {
        var mode: enum { unexpected, network } = .unexpected;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: registry_ping.PingHttpRequest) registry_ping.PingExchangeError!registry_ping.PingHttpResponse {
            defer request.deinit(allocator);
            return switch (mode) {
                .unexpected => .{ .status = .internal_server_error },
                .network => error.ConnectionRefused,
            };
        }
    };

    var client: std.http.Client = undefined;

    MockHarness.mode = .unexpected;
    const unexpected = try testing.pingRegistryWithExchanger(
        std.testing.allocator,
        &client,
        Config{},
        "registry.example.test",
        MockHarness.exchange,
    );
    try std.testing.expectEqual(RegistryPingFailureKind.unexpected_status, unexpected.failure.kind);
    try std.testing.expectEqual(@as(?u16, 500), unexpected.failure.http_status);

    MockHarness.mode = .network;
    try std.testing.expectEqual(
        RegistryPingFailureKind.network,
        (try testing.pingRegistryWithExchanger(
            std.testing.allocator,
            &client,
            Config{},
            "registry.example.test",
            MockHarness.exchange,
        )).failure.kind,
    );
}

test "pingRegistryWithExchanger: missing ca bundle maps to PublicApiError" {
    const MockHarness = struct {
        var calls: usize = 0;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: registry_ping.PingHttpRequest) registry_ping.PingExchangeError!registry_ping.PingHttpResponse {
            defer request.deinit(allocator);
            calls += 1;
            return .{ .status = .ok };
        }
    };
    defer MockHarness.calls = 0;

    var client = std.http.Client{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer client.deinit();

    const result = testing.pingRegistryWithExchanger(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" },
        "registry.example.test",
        MockHarness.exchange,
    );
    try std.testing.expectError(error.CaBundleFileNotFound, result);
    try std.testing.expectEqual(@as(usize, 0), MockHarness.calls);
}

test "resolveManyWithExchangers: single-item success owns output and preserves input" {
    const allocator = std.testing.allocator;
    var ref = try Reference.parse(allocator, "registry.example.test/owner/repo:single");
    defer ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        &.{ref},
        .{},
        refuseToken,
        busyboxManifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), result.items.len);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqualStrings("single", result.items[0].success.reference.tag.?);
    try std.testing.expectEqualStrings("single", ref.tag.?);
    try std.testing.expect(ref.registry.ptr != result.items[0].success.reference.registry.ptr);
    try std.testing.expect(ref.repository.ptr != result.items[0].success.reference.repository.ptr);
    try std.testing.expect(ref.tag.?.ptr != result.items[0].success.reference.tag.?.ptr);
}

test "resolveManyWithExchangers: all-success batch preserves order and input ownership" {
    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:first"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:second"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        busyboxManifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expectEqualStrings("first", result.items[0].success.reference.tag.?);
    try std.testing.expectEqualStrings("second", result.items[1].success.reference.tag.?);
    try std.testing.expectEqualStrings("first", refs[0].tag.?);
    try std.testing.expectEqualStrings("second", refs[1].tag.?);
    try std.testing.expect(refs[0].registry.ptr != result.items[0].success.reference.registry.ptr);
    try std.testing.expect(refs[1].repository.ptr != result.items[1].success.reference.repository.ptr);
}

test "resolveManyWithExchangers: unique tags resolve independently without cache hit" {
    const MockHarness = struct {
        var manifest_attempts: usize = 0;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            client: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            manifest_attempts += 1;
            return busyboxManifestExchange(allocator, client, request);
        }
    };
    defer MockHarness.manifest_attempts = 0;

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:first"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:second"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_attempts);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expectEqualStrings("first", result.items[0].success.reference.tag.?);
    try std.testing.expectEqualStrings("second", result.items[1].success.reference.tag.?);
}

test "resolveManyWithExchangers: 50 unique tags stay leak-free with pre-sized cache" {
    const MockHarness = struct {
        var manifest_attempts: usize = 0;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            client: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            manifest_attempts += 1;
            return busyboxManifestExchange(allocator, client, request);
        }
    };
    defer MockHarness.manifest_attempts = 0;

    const allocator = std.testing.allocator;
    const unique_count: usize = 50;
    var refs: [unique_count]Reference = undefined;
    var initialized: usize = 0;
    errdefer for (refs[0..initialized]) |*ref| ref.deinit(allocator);
    for (&refs, 0..) |*ref, i| {
        var tag_buf: [16]u8 = undefined;
        const tag = try std.fmt.bufPrint(&tag_buf, "u{d}", .{i});
        var image_buf: [64]u8 = undefined;
        const image = try std.fmt.bufPrint(&image_buf, "registry.example.test/owner/repo:{s}", .{tag});
        ref.* = try Reference.parse(allocator, image);
        initialized += 1;
    }
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(unique_count, result.items.len);
    try std.testing.expectEqual(unique_count, MockHarness.manifest_attempts);
    for (result.items) |item| {
        try std.testing.expectEqual(.success, std.meta.activeTag(item));
    }
}

test "resolveManyWithExchangers: duplicate tag uses session cache and clones independent results" {
    const MockHarness = struct {
        var manifest_attempts: usize = 0;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            client: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            manifest_attempts += 1;
            return busyboxManifestExchange(allocator, client, request);
        }
    };
    defer MockHarness.manifest_attempts = 0;

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:repeat"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:repeat"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(@as(usize, 1), MockHarness.manifest_attempts);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expectEqualStrings(result.items[0].success.digest.hex, result.items[1].success.digest.hex);
    try std.testing.expect(result.items[0].success.digest.hex.ptr != result.items[1].success.digest.hex.ptr);
    try std.testing.expect(result.items[0].success.reference.registry.ptr != result.items[1].success.reference.registry.ptr);
    try std.testing.expect(result.items[0].success.reference.repository.ptr != result.items[1].success.reference.repository.ptr);
    try std.testing.expect(result.items[0].success.reference.tag.?.ptr != result.items[1].success.reference.tag.?.ptr);
}

test "resolveManyWithExchangers: duplicate implicit latest uses session cache" {
    const MockHarness = struct {
        var manifest_attempts: usize = 0;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            client: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            manifest_attempts += 1;
            return busyboxManifestExchange(allocator, client, request);
        }
    };
    defer MockHarness.manifest_attempts = 0;

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo"),
        try Reference.parse(allocator, "registry.example.test/owner/repo"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(@as(usize, 1), MockHarness.manifest_attempts);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expect(refs[0].tag == null);
    try std.testing.expectEqualStrings("latest", refs[0].refString());
    try std.testing.expectEqualStrings(result.items[0].success.digest.hex, result.items[1].success.digest.hex);
    try std.testing.expect(result.items[0].success.digest.hex.ptr != result.items[1].success.digest.hex.ptr);
}

test "resolveManyWithExchangers: digest-addressed references bypass tag cache" {
    const MockHarness = struct {
        var manifest_attempts: usize = 0;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            client: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            manifest_attempts += 1;
            return busyboxManifestExchange(allocator, client, request);
        }
    };
    defer MockHarness.manifest_attempts = 0;

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(
            allocator,
            "registry.example.test/owner/repo@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        ),
        try Reference.parse(
            allocator,
            "registry.example.test/owner/repo@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        ),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_attempts);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expectEqualStrings(
        "b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        result.items[0].success.digest.hex,
    );
    try std.testing.expectEqualStrings(
        result.items[0].success.digest.hex,
        result.items[1].success.digest.hex,
    );
    try std.testing.expect(result.items[0].success.digest.hex.ptr != result.items[1].success.digest.hex.ptr);
    try std.testing.expect(result.items[0].success.reference.registry.ptr != result.items[1].success.reference.registry.ptr);
    try std.testing.expect(result.items[0].success.reference.repository.ptr != result.items[1].success.reference.repository.ptr);
    try std.testing.expect(result.items[0].success.reference.digest_raw.?.ptr != result.items[1].success.reference.digest_raw.?.ptr);
    try std.testing.expect(result.items[0].success.reference.digest.?.hex.ptr != result.items[1].success.reference.digest.?.hex.ptr);
}

test "resolveManyWithExchangers: batch-wide platform selects child manifest for every item" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (std.mem.endsWith(u8, request.url, "/manifests/latest") or
                std.mem.endsWith(u8, request.url, "/manifests/stable"))
            {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_index_v1.toString(),
                    .docker_content_digest = index_digest,
                }, index_body);
            }

            if (std.mem.endsWith(u8, request.url, child_digest)) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_manifest_v1.toString(),
                    .docker_content_digest = child_digest,
                }, child_body);
            }

            return error.TransportFailed;
        }
    };

    const allocator = std.testing.allocator;
    MockHarness.child_body = try allocator.dupe(
        u8,
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "size": 123
        \\  },
        \\  "layers": []
        \\}
        ,
    );
    defer allocator.free(MockHarness.child_body);

    MockHarness.child_digest = try sha256DigestStringAlloc(allocator, MockHarness.child_body);
    defer allocator.free(MockHarness.child_digest);

    MockHarness.index_body = try buildIndexBodyAlloc(
        allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        MockHarness.child_digest,
        "linux",
        "arm64",
    );
    defer allocator.free(MockHarness.index_body);

    MockHarness.index_digest = try sha256DigestStringAlloc(allocator, MockHarness.index_body);
    defer allocator.free(MockHarness.index_digest);

    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:latest"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:stable"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{ .platform = .{ .os = "linux", .architecture = "arm64" } },
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    for (result.items, 0..) |item, index| {
        try std.testing.expectEqual(.success, std.meta.activeTag(item));
        try std.testing.expectEqual(MediaType.oci_manifest_v1, item.success.media_type);
        try std.testing.expectEqualStrings(MockHarness.child_digest[("sha256:").len..], item.success.digest.hex);
        try std.testing.expect(item.success.platform != null);
        try std.testing.expectEqualStrings("linux", item.success.platform.?.os);
        try std.testing.expectEqualStrings("arm64", item.success.platform.?.architecture);
        try std.testing.expectEqualStrings(refs[index].tag.?, item.success.reference.tag.?);
    }
}

test "resolveManyWithExchangers: mixed batch continues after per-item failure" {
    const MockHarness = struct {
        var manifest_attempts: usize = 0;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            client: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            manifest_attempts += 1;
            if (std.mem.endsWith(u8, request.url, "/missing")) {
                defer request.deinit(allocator);
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .not_found,
                }, null);
            }
            return busyboxManifestExchange(allocator, client, request);
        }
    };
    defer MockHarness.manifest_attempts = 0;

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:first"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:missing"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:second"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), result.items.len);
    try std.testing.expectEqual(@as(usize, 3), MockHarness.manifest_attempts);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[1]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[2]));
    try std.testing.expectEqualStrings("first", result.items[0].success.reference.tag.?);
    try std.testing.expectEqualStrings("second", result.items[2].success.reference.tag.?);
    try expectResolveFailure(
        result.items[1].failure,
        "not_found",
        "registry.example.test",
        "registry.example.test/owner/repo:missing",
        null,
        null,
    );
    try std.testing.expectEqualStrings("first", refs[0].tag.?);
    try std.testing.expectEqualStrings("missing", refs[1].tag.?);
    try std.testing.expectEqualStrings("second", refs[2].tag.?);
    try std.testing.expect(refs[0].tag.?.ptr != result.items[0].success.reference.tag.?.ptr);
    try std.testing.expect(refs[2].tag.?.ptr != result.items[2].success.reference.tag.?.ptr);
}

test "resolveManyWithExchangers: allocation failures clean up mixed batch state" {
    const MockHarness = struct {
        var manifest_body: []const u8 = undefined;
        var manifest_digest: []const u8 = undefined;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (std.mem.endsWith(u8, request.url, "/missing")) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .not_found,
                }, null);
            }

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = manifest_digest,
            }, manifest_body);
        }

        fn run(allocator: std.mem.Allocator, refs: []const Reference) !void {
            var client: std.http.Client = undefined;
            var result = try testing.resolveManyWithExchangers(
                allocator,
                &client,
                Config{},
                refs,
                .{},
                refuseToken,
                manifestExchange,
                .{},
            );
            defer result.deinit(allocator);

            try std.testing.expectEqual(@as(usize, 4), result.items.len);
            try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
            try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
            try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[2]));
            try std.testing.expectEqual(.success, std.meta.activeTag(result.items[3]));
            try std.testing.expect(result.items[0].success.digest.hex.ptr != result.items[1].success.digest.hex.ptr);
            try expectResolveFailure(
                result.items[2].failure,
                "not_found",
                "registry.example.test",
                "registry.example.test/owner/repo:missing",
                null,
                null,
            );
        }
    };

    const manifest_body =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "size": 123
        \\  },
        \\  "layers": []
        \\}
    ;

    MockHarness.manifest_body = manifest_body;
    MockHarness.manifest_digest = try sha256DigestStringAlloc(std.testing.allocator, manifest_body);
    defer std.testing.allocator.free(MockHarness.manifest_digest);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const refs = try arena_allocator.alloc(Reference, 4);
    refs[0] = try Reference.parse(arena_allocator, "registry.example.test/owner/repo:first");
    refs[1] = try Reference.parse(arena_allocator, "registry.example.test/owner/repo:first");
    refs[2] = try Reference.parse(arena_allocator, "registry.example.test/owner/repo:missing");
    refs[3] = try Reference.parse(arena_allocator, "registry.example.test/owner/repo:second");

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        MockHarness.run,
        .{refs},
    );
}

test "resolveManyWithExchangers: targeted allocation failures clean up batch setup paths" {
    const refs = [_]Reference{busybox_literal_ref};

    const Case = enum {
        session_cache_ensure,
        result_array,
        input_reference_clone,
        cache_key,
        cache_result_clone,
    };
    const cases = [_]Case{
        .session_cache_ensure,
        .result_array,
        .input_reference_clone,
        .cache_key,
        .cache_result_clone,
    };

    for (cases) |case| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
            .fail_index = switch (case) {
                // resolveManyWithSession: ensureTotalCapacity, then items array, then cloneReference.
                .session_cache_ensure => 0,
                .result_array => 1,
                .input_reference_clone => 2,
                // Isolated helpers (not the batch loop):
                .cache_key => 0,
                .cache_result_clone => 1,
            },
        });
        const allocator = failing.allocator();

        switch (case) {
            .session_cache_ensure, .result_array, .input_reference_clone => {
                var client: std.http.Client = undefined;
                const result = testing.resolveManyWithExchangers(
                    allocator,
                    &client,
                    Config{},
                    refs[0..],
                    .{},
                    refuseToken,
                    busyboxManifestExchange,
                    .{},
                );

                try std.testing.expectError(error.OutOfMemory, result);
            },
            .cache_key => {
                const result = ResolveManySessionCache.cacheKeyAlloc(allocator, busybox_literal_ref);

                try std.testing.expectError(error.OutOfMemory, result);
            },
            .cache_result_clone => {
                var cache: ResolveManySessionCache = .{};
                var result = try testingResolveResultAlloc(std.testing.allocator, "latest", 'c');
                defer result.deinit(std.testing.allocator);

                try std.testing.expectError(
                    error.OutOfMemory,
                    cache.storeSuccess(allocator, busybox_literal_ref, result),
                );
            },
        }

        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

test "ResolveManySessionCache: allocation failures clean up store and hit paths" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var source = try testingResolveResultAlloc(std.testing.allocator, "latest", 'd');
            defer source.deinit(std.testing.allocator);

            var cache: ResolveManySessionCache = .{};
            defer cache.deinit(allocator);

            try cache.storeSuccess(allocator, busybox_literal_ref, source);

            var hit = try cache.cloneHit(allocator, busybox_literal_ref) orelse
                return error.TestUnexpectedResult;
            defer hit.deinit(allocator);

            try std.testing.expectEqualStrings(source.digest.hex, hit.digest.hex);
            try std.testing.expect(source.digest.hex.ptr != hit.digest.hex.ptr);
            try std.testing.expect(source.reference.registry.ptr != hit.reference.registry.ptr);
            try std.testing.expect(source.reference.repository.ptr != hit.reference.repository.ptr);
            try std.testing.expect(source.reference.tag.?.ptr != hit.reference.tag.?.ptr);
        }
    }.run, .{});
}

test "ResolveManySessionCache: allocation shape for key, clone, store, hit, and map growth" {
    const Counting = struct {
        parent: std.mem.Allocator,
        allocations: usize = 0,
        bytes: usize = 0,

        fn allocator(self: *@This()) std.mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        fn reset(self: *@This()) void {
            self.allocations = 0;
            self.bytes = 0;
        }

        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const ptr = self.parent.rawAlloc(len, alignment, ret_addr) orelse return null;
            self.allocations += 1;
            self.bytes += len;
            return ptr;
        }

        fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (!self.parent.rawResize(buf, alignment, new_len, ret_addr)) return false;
            if (new_len > buf.len) self.bytes += new_len - buf.len;
            return true;
        }

        fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.parent.rawRemap(buf, alignment, new_len, ret_addr);
        }

        fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.parent.rawFree(buf, alignment, ret_addr);
        }
    };

    var counting: Counting = .{ .parent = std.testing.allocator };
    const alloc = counting.allocator();

    var source = try testingResolveResultAlloc(std.testing.allocator, "latest", 'e');
    defer source.deinit(std.testing.allocator);

    // cacheKeyAlloc: one exact-size allocation (no allocPrint growth).
    counting.reset();
    const key = try ResolveManySessionCache.cacheKeyAlloc(alloc, busybox_literal_ref) orelse
        return error.TestUnexpectedResult;
    defer alloc.free(key);
    const key_allocs = counting.allocations;
    const key_bytes = counting.bytes;
    try std.testing.expectEqualStrings("registry-1.docker.io/library/busybox:latest", key);
    try std.testing.expectEqual(@as(usize, 1), key_allocs);
    try std.testing.expectEqual(key.len, key_bytes);

    // ResolveResult.clone for tag-only / null-platform: 4 dupes.
    counting.reset();
    var cloned = try source.clone(alloc);
    defer cloned.deinit(alloc);
    const clone_allocs = counting.allocations;
    try std.testing.expectEqual(@as(usize, 4), clone_allocs);

    // storeSuccess on empty map: key + clone + at least one map growth.
    var cache: ResolveManySessionCache = .{};
    defer cache.deinit(alloc);
    counting.reset();
    try cache.storeSuccess(alloc, busybox_literal_ref, source);
    const store_allocs = counting.allocations;
    try std.testing.expectEqual(key_allocs + clone_allocs + 1, store_allocs);
    try std.testing.expectEqual(@as(usize, 1), cache.map.count());

    // cloneHit: stack key for typical refs, so only the result clone allocates.
    counting.reset();
    var hit = try cache.cloneHit(alloc, busybox_literal_ref) orelse
        return error.TestUnexpectedResult;
    defer hit.deinit(alloc);
    const hit_allocs = counting.allocations;
    try std.testing.expectEqual(clone_allocs, hit_allocs);

    // Oversized key still hits correctly via heap fallback on lookup.
    {
        const long_repo = "r" ** (ResolveManySessionCache.cache_key_stack_max);
        const long_ref = Reference{
            .registry = "r.io",
            .repository = long_repo,
            .tag = "t",
            .digest = null,
            .digest_raw = null,
        };
        try cache.storeSuccess(alloc, long_ref, source);
        counting.reset();
        var long_hit = try cache.cloneHit(alloc, long_ref) orelse
            return error.TestUnexpectedResult;
        defer long_hit.deinit(alloc);
        // Heap key for lookup + clone.
        try std.testing.expectEqual(key_allocs + clone_allocs, counting.allocations);
        try std.testing.expectEqualStrings(source.digest.hex, long_hit.digest.hex);
    }

    // Result array is one contiguous allocation of ResolveManyItem.
    counting.reset();
    const items = try alloc.alloc(ResolveManyItem, 4);
    defer alloc.free(items);
    try std.testing.expectEqual(@as(usize, 1), counting.allocations);
    try std.testing.expectEqual(@sizeOf(ResolveManyItem) * 4, counting.bytes);

    // Map growth without pre-size vs ensureTotalCapacity for a 50-key Zencelot-sized pin.
    const unique_count: usize = 50;
    var growth_cache: ResolveManySessionCache = .{};
    defer growth_cache.deinit(alloc);
    counting.reset();
    for (0..unique_count) |i| {
        var tag_buf: [16]u8 = undefined;
        const tag = try std.fmt.bufPrint(&tag_buf, "t{d}", .{i});
        const ref = Reference{
            .registry = "registry.example.test",
            .repository = "owner/repo",
            .tag = tag,
            .digest = null,
            .digest_raw = null,
        };
        try growth_cache.storeSuccess(alloc, ref, source);
    }
    const growth_without = counting.allocations;

    var sized_cache: ResolveManySessionCache = .{};
    defer sized_cache.deinit(alloc);
    counting.reset();
    try sized_cache.map.ensureTotalCapacity(alloc, unique_count);
    const ensure_allocs = counting.allocations;
    counting.reset();
    for (0..unique_count) |i| {
        var tag_buf: [16]u8 = undefined;
        const tag = try std.fmt.bufPrint(&tag_buf, "t{d}", .{i});
        const ref = Reference{
            .registry = "registry.example.test",
            .repository = "owner/repo",
            .tag = tag,
            .digest = null,
            .digest_raw = null,
        };
        try sized_cache.storeSuccess(alloc, ref, source);
    }
    const growth_with_inserts = counting.allocations;

    // Pre-sizing removes insert-loop map reallocs. Key+clone still dominate.
    try std.testing.expect(ensure_allocs >= 1);
    try std.testing.expect(growth_with_inserts < growth_without);
    // Claimed STYLE win: about 4 map growth allocs saved on a 50-key pin.
    const map_growth_saved = growth_without - growth_with_inserts;
    try std.testing.expect(map_growth_saved >= 4);
    try std.testing.expectEqual(unique_count, growth_cache.map.count());
    try std.testing.expectEqual(unique_count, sized_cache.map.count());
    // Lock the measured delta so regressions in HashMap growth are visible.
    try std.testing.expectEqual(@as(usize, 4), map_growth_saved);
    try std.testing.expectEqual(@as(usize, 1), ensure_allocs);

    // Structural locks after exact-size key formatting (no allocPrint growth).
    try std.testing.expectEqual(@as(usize, 1), key_allocs);
    try std.testing.expectEqual(key.len, key_bytes);
    try std.testing.expectEqual(@as(usize, 6), store_allocs);
    try std.testing.expectEqual(@as(usize, 4), hit_allocs);
    try std.testing.expect(ensure_allocs >= 1);
    try std.testing.expect(growth_without - growth_with_inserts >= 1);
}

test "resolveManyWithExchangers: all-failure batch stores every failure" {
    const MockHarness = struct {
        var manifest_attempts: usize = 0;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_attempts += 1;
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .not_found,
            }, null);
        }
    };
    defer MockHarness.manifest_attempts = 0;

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:first"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:second"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_attempts);
    try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[1]));
    try expectResolveFailure(
        result.items[0].failure,
        "not_found",
        "registry.example.test",
        "registry.example.test/owner/repo:first",
        null,
        null,
    );
    try expectResolveFailure(
        result.items[1].failure,
        "not_found",
        "registry.example.test",
        "registry.example.test/owner/repo:second",
        null,
        null,
    );
}

test "resolveManyWithExchangers: duplicate failures are not cached" {
    const MockHarness = struct {
        var manifest_attempts: usize = 0;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_attempts += 1;
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .not_found,
            }, null);
        }
    };
    defer MockHarness.manifest_attempts = 0;

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:missing"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:missing"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_attempts);
    try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[1]));
    try expectResolveFailure(
        result.items[0].failure,
        "not_found",
        "registry.example.test",
        "registry.example.test/owner/repo:missing",
        null,
        null,
    );
    try expectResolveFailure(
        result.items[1].failure,
        "not_found",
        "registry.example.test",
        "registry.example.test/owner/repo:missing",
        null,
        null,
    );
    try std.testing.expect(result.items[0].failure.not_found.reference.ptr != result.items[1].failure.not_found.reference.ptr);
    try std.testing.expect(result.items[0].failure.not_found.registry.ptr != result.items[1].failure.not_found.registry.ptr);
}

test "resolveManyWithExchangers: failure matrix preserves stored context" {
    const MockHarness = struct {
        var scenario: test_matrix.Scenario = .network_error;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            return test_matrix.manifestExchange(scenario, allocator, request);
        }
    };
    defer test_matrix.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;

    for (test_matrix.resolve_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try test_matrix.prepareScenario(scenario, std.testing.allocator);

        var result = try testing.resolveManyWithExchangers(
            std.testing.allocator,
            &client,
            test_matrix.scenarioConfig(scenario),
            &.{busybox_literal_ref},
            .{ .platform = test_matrix.scenarioPlatform(scenario) },
            refuseToken,
            MockHarness.manifestExchange,
            .{},
        );
        defer result.deinit(std.testing.allocator);

        try std.testing.expectEqual(@as(usize, 1), result.items.len);
        try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[0]));
        try expectResolveFailure(
            result.items[0].failure,
            @tagName(scenario),
            "registry-1.docker.io",
            test_matrix.expectedReference(scenario),
            test_matrix.expectedHttpStatus(scenario),
            switch (scenario) {
                .rate_limited => false,
                .timeout => true,
                else => null,
            },
        );
    }
}

test "resolveManyWithExchangers: progress callback preserves ordered events and user data" {
    const MockHarness = struct {
        const RecordedEvent = struct {
            event: ResolveManyProgress.Event,
            index: usize,
            total: usize,
            ref_string: []const u8,
        };

        const Recorder = struct {
            events: [7]RecordedEvent = undefined,
            event_count: usize = 0,
        };

        fn progress(event: ResolveManyProgress, user_data: ?*anyopaque) void {
            const recorder: *Recorder = @ptrCast(@alignCast(user_data.?));
            std.debug.assert(recorder.event_count < recorder.events.len);
            recorder.events[recorder.event_count] = .{
                .event = event.event,
                .index = event.index,
                .total = event.total,
                // Borrowed for this callback only; compared before input refs are freed.
                .ref_string = event.reference.ref_string,
            };
            recorder.event_count += 1;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            client: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            if (std.mem.endsWith(u8, request.url, "/missing")) {
                defer request.deinit(allocator);
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .not_found,
                }, null);
            }
            return busyboxManifestExchange(allocator, client, request);
        }
    };

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:ok"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:ok"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:missing"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var recorder: MockHarness.Recorder = .{};
    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{
            .progress_fn = MockHarness.progress,
            .progress_user_data = @ptrCast(&recorder),
        },
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    const expected = [_]MockHarness.RecordedEvent{
        .{ .event = .item_started, .index = 0, .total = 3, .ref_string = "ok" },
        .{ .event = .item_succeeded, .index = 0, .total = 3, .ref_string = "ok" },
        .{ .event = .item_started, .index = 1, .total = 3, .ref_string = "ok" },
        .{ .event = .cache_hit, .index = 1, .total = 3, .ref_string = "ok" },
        .{ .event = .item_succeeded, .index = 1, .total = 3, .ref_string = "ok" },
        .{ .event = .item_started, .index = 2, .total = 3, .ref_string = "missing" },
        .{ .event = .item_failed, .index = 2, .total = 3, .ref_string = "missing" },
    };

    try std.testing.expectEqual(@as(usize, expected.len), recorder.event_count);
    for (expected, recorder.events[0..recorder.event_count]) |want, got| {
        try std.testing.expectEqual(want.event, got.event);
        try std.testing.expectEqual(want.index, got.index);
        try std.testing.expectEqual(want.total, got.total);
        try std.testing.expectEqualStrings(want.ref_string, got.ref_string);
    }
}

test "resolveManyWithExchangers: progress views must be copied to outlive the callback" {
    const MockHarness = struct {
        const CopiedEvent = struct {
            event: ResolveManyProgress.Event = .item_started,
            registry: [64]u8 = undefined,
            registry_len: usize = 0,
            repository: [64]u8 = undefined,
            repository_len: usize = 0,
            ref_string: [32]u8 = undefined,
            ref_string_len: usize = 0,
        };

        const Recorder = struct {
            events: [2]CopiedEvent = .{ .{}, .{} },
            event_count: usize = 0,
        };

        fn copyInto(dest: []u8, src: []const u8) usize {
            std.debug.assert(src.len <= dest.len);
            @memcpy(dest[0..src.len], src);
            return src.len;
        }

        fn progress(event: ResolveManyProgress, user_data: ?*anyopaque) void {
            const recorder: *Recorder = @ptrCast(@alignCast(user_data.?));
            std.debug.assert(recorder.event_count < recorder.events.len);
            var slot = &recorder.events[recorder.event_count];
            slot.event = event.event;
            slot.registry_len = copyInto(&slot.registry, event.reference.registry);
            slot.repository_len = copyInto(&slot.repository, event.reference.repository);
            slot.ref_string_len = copyInto(&slot.ref_string, event.reference.ref_string);
            recorder.event_count += 1;
        }
    };

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:ok"),
    };

    var recorder: MockHarness.Recorder = .{};
    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{
            .progress_fn = MockHarness.progress,
            .progress_user_data = @ptrCast(&recorder),
        },
        refuseToken,
        busyboxManifestExchange,
        .{},
    );
    result.deinit(allocator);
    for (&refs) |*ref| ref.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), recorder.event_count);
    try std.testing.expectEqual(.item_started, recorder.events[0].event);
    try std.testing.expectEqual(.item_succeeded, recorder.events[1].event);
    for (recorder.events[0..2]) |event| {
        try std.testing.expectEqualStrings(
            "registry.example.test",
            event.registry[0..event.registry_len],
        );
        try std.testing.expectEqualStrings(
            "owner/repo",
            event.repository[0..event.repository_len],
        );
        try std.testing.expectEqualStrings("ok", event.ref_string[0..event.ref_string_len]);
    }
}

test "ResolveManySessionCache: storeSuccess OOM after prior success leaves cache intact" {
    const allocator = std.testing.allocator;
    var first = try testingResolveResultAlloc(allocator, "first", 'e');
    defer first.deinit(allocator);
    var second = try testingResolveResultAlloc(allocator, "second", 'f');
    defer second.deinit(allocator);

    var cache: ResolveManySessionCache = .{};
    defer cache.deinit(allocator);

    var first_ref = try Reference.parse(allocator, "registry.example.test/owner/repo:first");
    defer first_ref.deinit(allocator);
    var second_ref = try Reference.parse(allocator, "registry.example.test/owner/repo:second");
    defer second_ref.deinit(allocator);

    try cache.storeSuccess(allocator, first_ref, first);

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.OutOfMemory,
        cache.storeSuccess(failing.allocator(), second_ref, second),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);

    var hit = try cache.cloneHit(allocator, first_ref) orelse return error.TestUnexpectedResult;
    defer hit.deinit(allocator);
    try std.testing.expectEqualStrings(first.digest.hex, hit.digest.hex);
    try std.testing.expect((try cache.cloneHit(allocator, second_ref)) == null);
}

test "resolveManyWithExchangers: mid-batch storeSuccess OOM after prior success does not leak" {
    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:first"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:second"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var saw_oom = false;
    var fail_index: usize = 0;
    while (fail_index < 128) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var client: std.http.Client = undefined;
        const outcome = testing.resolveManyWithExchangers(
            failing.allocator(),
            &client,
            Config{},
            refs[0..],
            .{},
            refuseToken,
            busyboxManifestExchange,
            .{},
        );

        if (outcome) |result| {
            var owned = result;
            owned.deinit(failing.allocator());
            try std.testing.expect(failing.allocated_bytes == failing.freed_bytes);
            break;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            saw_oom = true;
        }
    }

    try std.testing.expect(saw_oom);
}

test "resolveManyWithExchangers: shared AuthEngine reuses cached token across items" {
    const MockHarness = struct {
        var token_exchanges: usize = 0;
        var manifest_calls: usize = 0;
        const token_body = "{\"access_token\":\"batch-token\",\"expires_in\":3600}";

        fn tokenExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: auth.TokenHttpRequest,
        ) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            token_exchanges += 1;
            return .{ .status = .ok, .body = token_body };
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_calls += 1;

            if (request.authorization == null) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/repo:pull\"",
                    },
                }, null);
            }

            if (!std.mem.eql(u8, request.authorization.?, "Bearer batch-token")) {
                return error.TransportFailed;
            }

            const body = readFixtureAlloc(allocator, busybox_fixture, 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = digest,
            }, body);
        }
    };
    defer {
        MockHarness.token_exchanges = 0;
        MockHarness.manifest_calls = 0;
    }

    const allocator = std.testing.allocator;
    var refs = [_]Reference{
        try Reference.parse(allocator, "registry.example.test/owner/repo:first"),
        try Reference.parse(allocator, "registry.example.test/owner/repo:second"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try testing.resolveManyWithExchangers(
        allocator,
        &client,
        Config{},
        refs[0..],
        .{},
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(@as(usize, 1), MockHarness.token_exchanges);
    try std.testing.expectEqual(@as(usize, 4), MockHarness.manifest_calls);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expectEqualStrings("first", result.items[0].success.reference.tag.?);
    try std.testing.expectEqualStrings("second", result.items[1].success.reference.tag.?);
}

test "resolveWithExchangers: single-arch success pins digest and preserves parsed reference pointers" {
    const Case = enum { literal_ref, parsed_ref_moves };
    const cases = [_]Case{ .literal_ref, .parsed_ref_moves };

    for (cases) |case| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = if (case == .literal_ref) arena.allocator() else std.testing.allocator;

        var ref: Reference = undefined;
        var registry_ptr: ?[*]const u8 = null;
        var repository_ptr: ?[*]const u8 = null;
        var tag_ptr: ?[*]const u8 = null;

        switch (case) {
            .literal_ref => ref = busybox_literal_ref,
            .parsed_ref_moves => {
                ref = try Reference.parse(alloc, "registry-1.docker.io/library/busybox:latest");
                registry_ptr = ref.registry.ptr;
                repository_ptr = ref.repository.ptr;
                tag_ptr = ref.tag.?.ptr;
            },
        }

        var client: std.http.Client = undefined;
        const outcome = try resolveWithExchangers(alloc, &client, Config{}, ref, null, refuseToken, busyboxManifestExchange, .{});

        switch (outcome) {
            .success => |result| {
                try std.testing.expectEqual(MediaType.oci_manifest_v1, result.media_type);
                try std.testing.expect(result.platform == null);
                try std.testing.expectEqualSlices(u8, "registry-1.docker.io", result.reference.registry);
                try std.testing.expectEqualSlices(u8, "library/busybox", result.reference.repository);
                try std.testing.expectEqualSlices(u8, "latest", result.reference.tag.?);
                try std.testing.expect(result.reference.digest != null);
                try std.testing.expect(result.reference.digest_raw != null);
                try std.testing.expectEqualSlices(u8, result.digest.hex, result.reference.digest.?.hex);
                try std.testing.expectEqualSlices(u8, result.reference.digest_raw.?[("sha256:").len..], result.digest.hex);
                if (case == .parsed_ref_moves) {
                    try std.testing.expect(result.reference.registry.ptr == registry_ptr.?);
                    try std.testing.expect(result.reference.repository.ptr == repository_ptr.?);
                    try std.testing.expect(result.reference.tag.?.ptr == tag_ptr.?);
                    var owned = result;
                    owned.deinit(alloc);
                }
            },
            .failure => return error.TestUnexpectedResult,
        }
    }
}

test "resolveWithExchangers: authenticates on challenge then resolves manifest" {
    const MockHarness = struct {
        var manifest_calls: usize = 0;
        const token_body = "{\"access_token\":\"resolve-token\",\"expires_in\":3600}";

        fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            return .{ .status = .ok, .body = token_body };
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_calls += 1;

            if (manifest_calls == 1) {
                if (request.authorization != null) return error.TransportFailed;
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:library/busybox:pull\"",
                    },
                }, null);
            }

            if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Bearer resolve-token")) {
                return error.TransportFailed;
            }

            const body = readFixtureAlloc(allocator, busybox_fixture, 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = digest,
            }, body);
        }
    };

    defer MockHarness.manifest_calls = 0;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var client: std.http.Client = undefined;
    const outcome = try resolveWithExchangers(
        arena.allocator(),
        &client,
        Config{},
        busybox_literal_ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |result| {
            try std.testing.expectEqual(MediaType.oci_manifest_v1, result.media_type);
            try std.testing.expect(result.platform == null);
            try std.testing.expectEqualSlices(u8, "latest", result.reference.tag.?);
            try std.testing.expect(result.reference.digest != null);
            try std.testing.expectEqualSlices(u8, result.digest.hex, result.reference.digest.?.hex);
            try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_calls);
        },
        .failure => return error.TestUnexpectedResult,
    }
}

test "resolveWithExchangers: maps exhausted token transport timeout to timeout" {
    const MockHarness = struct {
        var token_attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            token_attempts += 1;
            return error.Timeout;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .unauthorized,
                .www_authenticate_headers = &.{
                    "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:library/busybox:pull\"",
                },
            }, null);
        }
    };

    defer MockHarness.token_attempts = 0;

    var client: std.http.Client = undefined;
    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 1 },
        busybox_literal_ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .failure => |failure| {
            try expectResolveFailure(
                failure,
                "timeout",
                "registry-1.docker.io",
                "registry-1.docker.io/library/busybox:latest",
                401,
                true,
            );
            try std.testing.expectEqual(@as(usize, 2), MockHarness.token_attempts);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "resolveWithExchangers: applies fixture ca_bundle_path without breaking mock resolve" {
    try skipUnlessTls();

    const rel_path = "fixtures/tls/enterprise-test-ca.pem";
    const abs_path = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, rel_path, std.testing.allocator);
    defer std.testing.allocator.free(abs_path);

    var client = std.http.Client{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer client.deinit();

    const ref = try Reference.parse(std.testing.allocator, "registry-1.docker.io/library/busybox:latest");
    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = abs_path },
        ref,
        null,
        refuseToken,
        busyboxManifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .success => |result| {
            var owned = result;
            defer owned.deinit(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }

    try client.ca_bundle_lock.lockShared(std.testing.io);
    defer client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expect(client.ca_bundle.bytes.items.len > 0);
}

test "resolveWithExchangers: multi-arch success selects child platform and digest" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (std.mem.endsWith(u8, request.url, "/manifests/latest")) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_index_v1.toString(),
                    .docker_content_digest = index_digest,
                }, index_body);
            }

            if (std.mem.endsWith(u8, request.url, child_digest)) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_manifest_v1.toString(),
                    .docker_content_digest = child_digest,
                }, child_body);
            }

            return error.TransportFailed;
        }
    };

    MockHarness.child_body = try std.testing.allocator.dupe(
        u8,
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "size": 123
        \\  },
        \\  "layers": []
        \\}
        ,
    );
    defer std.testing.allocator.free(MockHarness.child_body);

    MockHarness.child_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.child_body);
    defer std.testing.allocator.free(MockHarness.child_digest);

    MockHarness.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        MockHarness.child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(MockHarness.index_body);

    MockHarness.index_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.index_body);
    defer std.testing.allocator.free(MockHarness.index_digest);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var client: std.http.Client = undefined;
    const outcome = try resolveWithExchangers(
        arena.allocator(),
        &client,
        Config{},
        busybox_literal_ref,
        .{ .os = "linux", .architecture = "arm64" },
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |result| {
            try std.testing.expectEqual(MediaType.oci_manifest_v1, result.media_type);
            try std.testing.expect(result.platform != null);
            try std.testing.expectEqualSlices(u8, "linux", result.platform.?.os);
            try std.testing.expectEqualSlices(u8, "arm64", result.platform.?.architecture);
            try std.testing.expectEqualSlices(u8, MockHarness.child_digest[("sha256:").len..], result.digest.hex);
        },
        .failure => return error.TestUnexpectedResult,
    }
}

test "resolveWithExchangers: failure scenarios map to ResolveError with full context" {
    const MockHarness = struct {
        var scenario: test_matrix.Scenario = .network_error;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            return test_matrix.manifestExchange(scenario, allocator, request);
        }
    };

    defer test_matrix.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;

    for (test_matrix.resolve_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try test_matrix.prepareScenario(scenario, std.testing.allocator);

        const outcome = try resolveWithExchangers(
            std.testing.allocator,
            &client,
            test_matrix.scenarioConfig(scenario),
            busybox_literal_ref,
            test_matrix.scenarioPlatform(scenario),
            refuseToken,
            MockHarness.manifestExchange,
            .{},
        );
        defer switch (outcome) {
            .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
            else => {},
        };

        switch (outcome) {
            .success => return error.TestUnexpectedResult,
            .failure => |failure| try expectResolveFailure(
                failure,
                @tagName(scenario),
                "registry-1.docker.io",
                test_matrix.expectedReference(scenario),
                test_matrix.expectedHttpStatus(scenario),
                if (scenario == .rate_limited) false else null,
            ),
        }
    }
}

test "resolveWithExchangers: depth_limit_exceeded for nested indexes beyond limit" {
    const depth = MAX_CHILD_MANIFEST_DEPTH + 1;
    const MockHarness = struct {
        var bodies: [depth][]u8 = undefined;
        var digests: [depth][]u8 = undefined;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (std.mem.endsWith(u8, request.url, "/manifests/latest")) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_index_v1.toString(),
                    .docker_content_digest = digests[0],
                }, bodies[0]);
            }

            for (1..depth) |index| {
                if (std.mem.endsWith(u8, request.url, digests[index])) {
                    return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                        .status = .ok,
                        .content_type = MediaType.oci_index_v1.toString(),
                        .docker_content_digest = digests[index],
                    }, bodies[index]);
                }
            }

            return error.TransportFailed;
        }
    };

    var next_digest: []const u8 = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    var reverse_index: usize = depth;
    while (reverse_index > 0) {
        reverse_index -= 1;
        MockHarness.bodies[reverse_index] = try buildIndexBodyAlloc(
            std.testing.allocator,
            MediaType.oci_index_v1.toString(),
            MediaType.oci_index_v1.toString(),
            next_digest,
            "linux",
            "arm64",
        );
        MockHarness.digests[reverse_index] = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.bodies[reverse_index]);
        next_digest = MockHarness.digests[reverse_index];
    }
    defer for (MockHarness.bodies) |body| std.testing.allocator.free(body);
    defer for (MockHarness.digests) |digest| std.testing.allocator.free(digest);

    var client: std.http.Client = undefined;
    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        busybox_literal_ref,
        .{ .os = "linux", .architecture = "arm64" },
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .success => return error.TestUnexpectedResult,
        .failure => |failure| try std.testing.expectEqual(@as(std.meta.Tag(ResolveError), .depth_limit_exceeded), std.meta.activeTag(failure)),
    }
}

test "validateWithExchangers: single-arch HEAD validation and HEAD-to-GET fallback" {
    const Scenario = enum { head_ok, head_fallback_get };
    const cases = [_]Scenario{ .head_ok, .head_fallback_get };

    const MockHarness = struct {
        var active: Scenario = .head_ok;
        var saw_get = false;

        fn manifestExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (request.method == .head) {
                return switch (active) {
                    .head_ok => resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                        .status = .ok,
                        .content_type = MediaType.oci_manifest_v1.toString(),
                        .docker_content_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    }, null),
                    .head_fallback_get => resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{ .status = .ok }, null),
                };
            }

            saw_get = true;
            return busyboxManifestExchange(allocator, client, request);
        }
    };

    for (cases) |scenario| {
        MockHarness.active = scenario;
        MockHarness.saw_get = false;

        var client: std.http.Client = undefined;
        const platform: ?Platform = if (scenario == .head_fallback_get)
            .{ .os = "linux", .architecture = "amd64" }
        else
            null;

        const outcome = try validateWithExchangers(
            std.testing.allocator,
            &client,
            Config{},
            busybox_literal_ref,
            platform,
            refuseToken,
            MockHarness.manifestExchange,
            .{},
        );

        switch (scenario) {
            .head_ok => try std.testing.expectEqual(ValidateOutcome.valid, outcome),
            .head_fallback_get => {
                try std.testing.expect(MockHarness.saw_get);
                try std.testing.expectEqual(ValidateOutcome.valid, outcome);
            },
        }
    }
}

test "validateWithExchangers: multi-arch child HEAD returns valid without GET" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;
        var child_head_calls: usize = 0;
        var child_get_calls: usize = 0;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (std.mem.endsWith(u8, request.url, "/manifests/latest")) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_index_v1.toString(),
                    .docker_content_digest = index_digest,
                }, index_body);
            }

            if (std.mem.endsWith(u8, request.url, child_digest)) {
                switch (request.method) {
                    .head => child_head_calls += 1,
                    .get => child_get_calls += 1,
                }
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_manifest_v1.toString(),
                    .docker_content_digest = child_digest,
                }, child_body);
            }

            return error.TransportFailed;
        }
    };

    MockHarness.child_body = try std.testing.allocator.dupe(
        u8,
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        \\    "size": 321
        \\  },
        \\  "layers": []
        \\}
        ,
    );
    defer std.testing.allocator.free(MockHarness.child_body);

    MockHarness.child_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.child_body);
    defer std.testing.allocator.free(MockHarness.child_digest);

    MockHarness.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        MockHarness.child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(MockHarness.index_body);

    MockHarness.index_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.index_body);
    defer std.testing.allocator.free(MockHarness.index_digest);

    MockHarness.child_head_calls = 0;
    MockHarness.child_get_calls = 0;

    var client: std.http.Client = undefined;
    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        busybox_literal_ref,
        .{ .os = "linux", .architecture = "arm64" },
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );

    try std.testing.expectEqual(ValidateOutcome.valid, outcome);
    try std.testing.expectEqual(@as(usize, 1), MockHarness.child_head_calls);
    try std.testing.expectEqual(@as(usize, 0), MockHarness.child_get_calls);
}

test "validateWithExchangers: failure scenarios map to outcome or ResolveError with full context" {
    const MockHarness = struct {
        var scenario: test_matrix.Scenario = .not_found;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            return test_matrix.manifestExchange(scenario, allocator, request);
        }
    };

    defer test_matrix.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;

    for (test_matrix.validate_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try test_matrix.prepareScenario(scenario, std.testing.allocator);

        const outcome = try validateWithExchangers(
            std.testing.allocator,
            &client,
            test_matrix.scenarioConfig(scenario),
            busybox_literal_ref,
            test_matrix.scenarioPlatform(scenario),
            refuseToken,
            MockHarness.manifestExchange,
            .{},
        );
        defer switch (outcome) {
            .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
            else => {},
        };

        switch (scenario) {
            .not_found => try std.testing.expectEqual(ValidateOutcome.not_found, outcome),
            else => switch (outcome) {
                .valid, .not_found => return error.TestUnexpectedResult,
                .failure => |failure| try expectResolveFailure(
                    failure,
                    @tagName(scenario),
                    "registry-1.docker.io",
                    test_matrix.expectedReference(scenario),
                    test_matrix.expectedHttpStatus(scenario),
                    switch (scenario) {
                        .rate_limited => false,
                        .timeout => true,
                        else => null,
                    },
                ),
            },
        }
    }
}

test "validateWithExchangers: digest_mismatch when digest-pinned HEAD disagrees with Docker-Content-Digest" {
    const MockHarness = struct {
        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            return test_matrix.manifestExchange(.digest_mismatch, allocator, request);
        }
    };

    const digest_raw = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const pinned = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = null,
        .digest = try Digest.parse(digest_raw),
        .digest_raw = digest_raw,
    };

    var client: std.http.Client = undefined;
    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        pinned,
        null,
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .valid, .not_found => return error.TestUnexpectedResult,
        .failure => |failure| try expectResolveFailure(
            failure,
            "digest_mismatch",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            200,
            null,
        ),
    }
}

test "validateWithExchangers: platform_required when multi-arch HEAD omits platform" {
    const child_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const MockHarness = struct {
        var index_digest: []u8 = undefined;
        var head_calls: usize = 0;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            if (request.method != .head) return error.TransportFailed;
            if (!std.mem.endsWith(u8, request.url, "/manifests/latest")) return error.TransportFailed;
            head_calls += 1;
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_index_v1.toString(),
                .docker_content_digest = index_digest,
            }, null);
        }
    };

    const index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(index_body);
    MockHarness.index_digest = try sha256DigestStringAlloc(std.testing.allocator, index_body);
    defer std.testing.allocator.free(MockHarness.index_digest);
    MockHarness.head_calls = 0;

    var client: std.http.Client = undefined;
    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        busybox_literal_ref,
        null,
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    try std.testing.expectEqual(@as(usize, 1), MockHarness.head_calls);
    switch (outcome) {
        .valid, .not_found => return error.TestUnexpectedResult,
        .failure => |failure| try expectPlatformRequiredFailure(failure),
    }
}

test "validateWithExchangers: platform_required when multi-arch index GET omits platform" {
    const child_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            if (!std.mem.endsWith(u8, request.url, "/manifests/latest")) return error.TransportFailed;
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_index_v1.toString(),
                .docker_content_digest = index_digest,
            }, index_body);
        }
    };

    MockHarness.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(MockHarness.index_body);
    MockHarness.index_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.index_body);
    defer std.testing.allocator.free(MockHarness.index_digest);

    var client: std.http.Client = undefined;
    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        busybox_literal_ref,
        null,
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .valid, .not_found => return error.TestUnexpectedResult,
        .failure => |failure| try expectPlatformRequiredFailure(failure),
    }
}

test "getManifestWithExchangers: platform_required when multi-arch omits platform" {
    const child_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            if (!std.mem.endsWith(u8, request.url, "/manifests/latest")) return error.TransportFailed;
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_index_v1.toString(),
                .docker_content_digest = index_digest,
            }, index_body);
        }
    };

    MockHarness.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(MockHarness.index_body);
    MockHarness.index_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.index_body);
    defer std.testing.allocator.free(MockHarness.index_digest);

    var client: std.http.Client = undefined;
    const outcome = try getManifestWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        busybox_literal_ref,
        null,
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        .success => |parsed| parsed.deinit(),
    };

    switch (outcome) {
        .success => return error.TestUnexpectedResult,
        .failure => |failure| try expectPlatformRequiredFailure(failure),
    }
}

test "getManifestWithExchangers: single-arch success matches direct busybox fixture parse" {
    const fixture_bytes = try readFixtureAlloc(std.testing.allocator, busybox_fixture, 16 * 1024);
    defer std.testing.allocator.free(fixture_bytes);

    const direct = try json.parse(Manifest, std.testing.allocator, fixture_bytes);
    defer direct.deinit();

    var client: std.http.Client = undefined;
    const outcome = try getManifestWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        busybox_literal_ref,
        null,
        refuseToken,
        busyboxManifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |parsed| {
            defer parsed.deinit();
            try std.testing.expectEqual(direct.value.schema_version, parsed.value.schema_version);
            try std.testing.expectEqual(direct.value.media_type, parsed.value.media_type);
            try std.testing.expectEqualSlices(u8, direct.value.config.digest.hex, parsed.value.config.digest.hex);
            try std.testing.expectEqual(direct.value.layers.len, parsed.value.layers.len);
            try std.testing.expectEqualSlices(u8, direct.value.layers[0].digest.hex, parsed.value.layers[0].digest.hex);
            try std.testing.expect(parsed.value.annotations != null);
            try std.testing.expectEqualStrings(
                direct.value.annotations.?.object.get("org.opencontainers.image.version").?.string,
                parsed.value.annotations.?.object.get("org.opencontainers.image.version").?.string,
            );
        },
        .failure => return error.TestUnexpectedResult,
    }
}

test "getManifestWithExchangers: single-arch success stays leak-free under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;
    const outcome = try getManifestWithExchangers(
        allocator,
        &client,
        Config{},
        busybox_literal_ref,
        null,
        refuseToken,
        busyboxManifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |parsed| parsed.deinit(),
        .failure => return error.TestUnexpectedResult,
    }
}

test "getManifestWithExchangers: failure scenarios map to ResolveError with full context" {
    const MockHarness = struct {
        var scenario: test_matrix.Scenario = .not_found;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            return test_matrix.manifestExchange(scenario, allocator, request);
        }
    };

    defer test_matrix.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;

    for (test_matrix.get_manifest_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try test_matrix.prepareScenario(scenario, std.testing.allocator);

        const outcome = try getManifestWithExchangers(
            std.testing.allocator,
            &client,
            test_matrix.scenarioConfig(scenario),
            busybox_literal_ref,
            test_matrix.scenarioPlatform(scenario),
            refuseToken,
            MockHarness.manifestExchange,
            .{},
        );
        defer switch (outcome) {
            .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
            .success => |parsed| parsed.deinit(),
        };

        switch (outcome) {
            .success => return error.TestUnexpectedResult,
            .failure => |failure| try expectResolveFailure(
                failure,
                @tagName(scenario),
                "registry-1.docker.io",
                test_matrix.expectedReference(scenario),
                test_matrix.expectedHttpStatus(scenario),
                switch (scenario) {
                    .rate_limited => false,
                    .timeout => true,
                    else => null,
                },
            ),
        }
    }
}

test "getManifestWithExchangers: nested index resolves to leaf manifest" {
    const MockHarness = struct {
        var outer_body: []u8 = undefined;
        var outer_digest: []u8 = undefined;
        var inner_body: []u8 = undefined;
        var inner_digest: []u8 = undefined;
        var leaf_body: []u8 = undefined;
        var leaf_digest: []u8 = undefined;

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (std.mem.endsWith(u8, request.url, "/manifests/latest")) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_index_v1.toString(),
                    .docker_content_digest = outer_digest,
                }, outer_body);
            }
            if (std.mem.endsWith(u8, request.url, inner_digest)) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_index_v1.toString(),
                    .docker_content_digest = inner_digest,
                }, inner_body);
            }
            if (std.mem.endsWith(u8, request.url, leaf_digest)) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_manifest_v1.toString(),
                    .docker_content_digest = leaf_digest,
                }, leaf_body);
            }
            return error.TransportFailed;
        }
    };

    MockHarness.leaf_body = try std.testing.allocator.dupe(
        u8,
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\    "size": 456
        \\  },
        \\  "layers": []
        \\}
        ,
    );
    defer std.testing.allocator.free(MockHarness.leaf_body);

    MockHarness.leaf_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.leaf_body);
    defer std.testing.allocator.free(MockHarness.leaf_digest);

    MockHarness.inner_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        MockHarness.leaf_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(MockHarness.inner_body);

    MockHarness.inner_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.inner_body);
    defer std.testing.allocator.free(MockHarness.inner_digest);

    MockHarness.outer_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_index_v1.toString(),
        MockHarness.inner_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(MockHarness.outer_body);

    MockHarness.outer_digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.outer_body);
    defer std.testing.allocator.free(MockHarness.outer_digest);

    var client: std.http.Client = undefined;
    const outcome = try getManifestWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        busybox_literal_ref,
        .{ .os = "linux", .architecture = "arm64" },
        refuseToken,
        MockHarness.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |parsed| {
            defer parsed.deinit();
            try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
        },
        .failure => |failure| {
            deinitOwnedResolveError(failure, std.testing.allocator);
            return error.TestUnexpectedResult;
        },
    }
}

test "WithEngine: platform_required failures are leak-free across resolve, validate, and get_manifest" {
    const Api = enum { resolve, validate, get_manifest };
    const cases = [_]Api{ .resolve, .validate, .get_manifest };

    const MockHarness = struct {
        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            const body = readFixtureAlloc(allocator, "fixtures/indexes/busybox-latest-live-oci-index.json", 32 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_index_v1.toString(),
                .docker_content_digest = digest,
            }, body);
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(allocator, .{}, refuseToken);
    defer engine.deinit();

    for (cases) |api| {
        var ref = try Reference.parse(allocator, "registry-1.docker.io/library/busybox:latest");
        defer ref.deinit(allocator);

        switch (api) {
            .resolve => {
                const outcome = try resolveWithEngine(allocator, &client, Config{}, &engine, ref, null, refuseToken, MockHarness.manifestExchange, .{});
                switch (outcome) {
                    .success => return error.TestUnexpectedResult,
                    .failure => |failure| {
                        defer deinitOwnedResolveError(failure, allocator);
                        try expectPlatformRequiredFailure(failure);
                    },
                }
            },
            .validate => {
                const outcome = try validateWithEngine(allocator, &client, Config{}, &engine, ref, null, refuseToken, MockHarness.manifestExchange, .{});
                switch (outcome) {
                    .valid, .not_found => return error.TestUnexpectedResult,
                    .failure => |failure| {
                        defer deinitOwnedResolveError(failure, allocator);
                        try expectPlatformRequiredFailure(failure);
                    },
                }
            },
            .get_manifest => {
                const outcome = try getManifestWithEngine(allocator, &client, Config{}, &engine, ref, null, refuseToken, MockHarness.manifestExchange, .{});
                switch (outcome) {
                    .success => |parsed| parsed.deinit(),
                    .failure => |failure| {
                        defer deinitOwnedResolveError(failure, allocator);
                        try expectPlatformRequiredFailure(failure);
                    },
                }
            },
        }
    }
}

test "ResolvedManifestSuccess.detachForResolvePromotion: clears resolved_digest fields on source" {
    const hex = "a" ** 64;
    const raw = try std.fmt.allocPrint(std.testing.allocator, "sha256:{s}", .{hex});

    var success = ResolvedManifestSuccess{
        .resolved_digest = try Digest.parse(raw),
        .resolved_digest_raw = raw,
        .document = .{ .manifest_media_type = .docker_manifest_v2 },
        .platform = null,
    };

    const detached = success.detachForResolvePromotion();
    defer std.testing.allocator.free(detached.resolved_digest_raw);

    try std.testing.expect(success.resolved_digest_raw.len == 0);
    try std.testing.expect(success.resolved_digest.hex.len == 0);
    success.deinit(std.testing.allocator);
}

test "ResolvedManifestSuccess.deinit: frees owned fields and clears digest aliases" {
    const minimal_manifest_json =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\    "size": 1
        \\  },
        \\  "layers": []
        \\}
    ;
    const parsed = try std.json.parseFromSlice(Manifest, std.testing.allocator, minimal_manifest_json, .{});
    const hex = "b" ** 64;
    const raw = try std.fmt.allocPrint(std.testing.allocator, "sha256:{s}", .{hex});
    const platform = Platform{
        .os = try std.testing.allocator.dupe(u8, "linux"),
        .architecture = try std.testing.allocator.dupe(u8, "amd64"),
    };

    var success = ResolvedManifestSuccess{
        .resolved_digest = try Digest.parse(raw),
        .resolved_digest_raw = raw,
        .document = .{ .manifest = parsed },
        .platform = platform,
        .backing_body = try std.testing.allocator.dupe(u8, minimal_manifest_json),
    };

    success.deinit(std.testing.allocator);

    try std.testing.expect(success.resolved_digest_raw.len == 0);
    try std.testing.expect(success.resolved_digest.hex.len == 0);
    try std.testing.expect(success.backing_body == null);
    try std.testing.expect(success.platform == null);
    try std.testing.expectEqual(.manifest_media_type, std.meta.activeTag(success.document));
}

test "ResolvedManifestSuccess.detachManifestForPromotion: allocation failures do not leak" {
    const minimal_manifest_json =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\    "size": 1
        \\  },
        \\  "layers": []
        \\}
    ;

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(caller_allocator: std.mem.Allocator, bytes: []const u8) !void {
            var transient_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer transient_arena.deinit();
            const transient = transient_arena.allocator();

            const parsed_local = try json.parse(Manifest, transient, bytes);
            var success_local = ResolvedManifestSuccess{
                .resolved_digest = try Digest.parse("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
                .resolved_digest_raw = try transient.dupe(u8, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
                .document = .{ .manifest = parsed_local },
                .platform = null,
            };
            errdefer success_local.deinit(transient);

            const promoted = try success_local.detachManifestForPromotion(caller_allocator);
            promoted.deinit();
            success_local.deinit(transient);
        }
    }.run, .{minimal_manifest_json});
}

test "ResolvedManifestSuccess.detachManifestForPromotion: clears digest fields on source after success" {
    const minimal_manifest_json =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\    "size": 1
        \\  },
        \\  "layers": []
        \\}
    ;
    var transient_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer transient_arena.deinit();
    const transient = transient_arena.allocator();

    const parsed_local = try json.parse(Manifest, transient, minimal_manifest_json);
    var success_local = ResolvedManifestSuccess{
        .resolved_digest = try Digest.parse("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        .resolved_digest_raw = try transient.dupe(u8, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        .document = .{ .manifest = parsed_local },
        .platform = null,
    };
    defer success_local.deinit(transient);

    const promoted = try success_local.detachManifestForPromotion(std.testing.allocator);
    defer promoted.deinit();

    try std.testing.expect(success_local.resolved_digest_raw.len == 0);
    try std.testing.expect(success_local.resolved_digest.hex.len == 0);
    try std.testing.expectEqual(.manifest_media_type, std.meta.activeTag(success_local.document));
}

test "validateOutcomeFromResolvedManifestOutcome: failure release clears stored reference" {
    const owned_reference = try std.testing.allocator.dupe(u8, "registry.example.test/library/busybox:latest");
    var outcome = ResolvedManifestOutcome{ .failure = .{ .platform_required = .{
        .registry = "registry.example.test",
        .reference = owned_reference,
        .http_status = null,
    } } };

    const result = try validateOutcomeFromResolvedManifestOutcome(
        std.testing.allocator,
        std.testing.allocator,
        &outcome,
    );
    switch (result) {
        .failure => |failure| {
            defer failure.deinitOwned(std.testing.allocator);
            try std.testing.expectEqualStrings("platform_required", @tagName(std.meta.activeTag(failure)));
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(outcome.failure.platform_required.reference.len == 0);
}
