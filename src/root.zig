//! z-oci: Pure Zig OCI/Docker Registry API v2 toolkit.
//!
//! Current scope:
//! - offline OCI/Docker reference parsing and normalization
//! - OCI manifest, index, and descriptor types with JSON round-trip support
//! - auth engine: manifest HEAD/GET challenge handling, token exchange, credential providers
//! - public manifest resolution for single-arch and supported multi-arch flows
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
//!
const std = @import("std");
const resolver = @import("resolver.zig");
const resilience = @import("resilience.zig");
pub const test_matrix = @import("test_matrix.zig");

/// Content digest view and parser. See `Digest.zig` for ownership (`hex` may borrow).
pub const Digest = @import("Digest.zig");
/// OCI/Docker manifest media type enum. See `MediaType.zig`.
pub const MediaType = @import("MediaType.zig").MediaType;
/// Platform selector (OS/arch/variant slices). See `Platform.zig` for borrow rules.
pub const Platform = @import("Platform.zig");
/// OCI content descriptor. See `Descriptor.zig`.
pub const Descriptor = @import("Descriptor.zig");
/// Single-arch image manifest type and JSON helpers. See `Manifest.zig`.
pub const Manifest = @import("Manifest.zig");
/// Multi-arch index types and selection helpers. See `Index.zig`.
pub const Index = @import("Index.zig");
/// OCI image index (`application/vnd.oci.image.index.v1+json`). See `Index.zig`.
pub const OciImageIndex = Index.OciImageIndex;
/// Docker manifest list (`application/vnd.docker.distribution.manifest.list.v2+json`). See `Index.zig`.
pub const DockerManifestList = Index.DockerManifestList;
/// Union of supported multi-arch index/list document shapes. See `Index.zig`.
pub const MultiArchManifest = Index.MultiArchManifest;
/// Docker/OCI image reference parser and normalizer. See `Reference.zig`.
pub const Reference = @import("Reference.zig");
/// Full auth module for integrators and mock exchanger authors (`z_oci.auth.*`).
pub const auth = @import("auth.zig");
/// Shared JSON parse/serialize helpers for OCI types. See `json.zig`.
pub const json = @import("json.zig");
/// Token cache and manifest auth orchestration. See `auth.AuthEngine`.
pub const AuthEngine = auth.AuthEngine;
/// Parsed WWW-Authenticate challenge view. See `auth.AuthChallenge`.
pub const AuthChallenge = auth.AuthChallenge;
/// Borrowed registry/repository/ref view for auth and resolver paths. See `auth.AuthReferenceView`.
pub const AuthReferenceView = auth.AuthReferenceView;
/// Parsed Bearer challenge fields. See `auth.BearerChallenge`.
pub const BearerChallenge = auth.BearerChallenge;
/// Inputs for a single authenticate call. See `auth.AuthenticateRequest`.
pub const AuthenticateRequest = auth.AuthenticateRequest;
/// Outcome of classifying a manifest probe response. See `auth.ProbeResult`.
pub const ProbeResult = auth.ProbeResult;
/// Minimal HTTP response shape for auth probe classification. See `auth.ProbeHttpResponse`.
pub const ProbeHttpResponse = auth.ProbeHttpResponse;
/// Build a borrowed auth reference view from a parsed `Reference`. See `auth.referenceView`.
pub const referenceView = auth.referenceView;
/// Parsed bearer token metadata. See `auth.Token`.
pub const Token = auth.Token;
/// Token exchange response with optional refresh token ownership. See `auth.TokenResponse`.
pub const TokenResponse = auth.TokenResponse;
/// Structured registry failure at the public outcome boundary. See `ResolveError.zig`.
pub const ResolveError = @import("ResolveError.zig").ResolveError;
/// Successful resolve payload (digest, media type, platform). See `ResolveResult.zig`.
pub const ResolveResult = @import("ResolveResult.zig");
/// Transport, retry, TLS, and credential configuration. See `Config.zig`.
pub const Config = @import("Config.zig").Config;
/// Credential lookup strategy for token exchange. See `Config.zig`.
pub const CredentialProvider = @import("Config.zig").CredentialProvider;
/// Username/password pair for basic or token auth. See `Config.zig`.
pub const Credential = @import("Config.zig").Credential;
/// Opaque credential slot returned by a provider. See `Config.zig`.
pub const CredentialHandle = @import("Config.zig").CredentialHandle;
/// Errors returned directly from public entry points before an outcome is produced.
///
/// Covers `Config.applyToClient` failures and `OutOfMemory` during outcome promotion.
/// Structured resolve failures use `ResolveError` inside outcome `.failure` arms; release
/// those with `deinitResolveFailure`.
pub const PublicApiError = Config.ApplyError;
/// Narrow testing seam for repository smoke tests.
///
/// This keeps workflow-level coverage on the same public resolver logic while
/// still allowing injected transports instead of real network access.
pub const testing = struct {
    /// Shared offline failure-matrix fixtures for T2/T3 tests. See `test_matrix.zig`.
    pub const FailureScenario = test_matrix.Scenario;
    pub const refuseTokenExchange = test_matrix.refuseTokenExchange;
    /// Injectable token HTTP exchanger for offline auth tests. See `auth.TokenHttpExchanger`.
    pub const TokenHttpExchanger = auth.TokenHttpExchanger;
    /// Injectable manifest HTTP exchanger for offline resolver tests. See `resolver.ManifestHttpExchanger`.
    pub const ManifestHttpExchanger = resolver.ManifestHttpExchanger;
    /// Concrete manifest request shape passed to mock exchangers. See `resolver.ManifestHttpRequest`.
    pub const ManifestHttpRequest = resolver.ManifestHttpRequest;
    /// Concrete manifest response shape returned by mock exchangers. See `resolver.ManifestHttpResponse`.
    pub const ManifestHttpResponse = resolver.ManifestHttpResponse;
    /// Transport errors mock manifest exchangers may return. See `resolver.ManifestExchangeError`.
    pub const ManifestExchangeError = resolver.ManifestExchangeError;

    /// Resolve with injected token and manifest exchangers (fresh `AuthEngine` per call).
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

    /// Same as `resolveWithExchangers`, but reuses an existing `AuthEngine` for token cache warmth.
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

    /// Validate existence with injected exchangers (fresh `AuthEngine` per call).
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

    /// Validate existence while reusing an existing `AuthEngine` for token cache warmth.
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

    /// Fetch parsed manifest while reusing an existing `AuthEngine` for token cache warmth.
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

    /// Fetch parsed manifest with injected exchangers (fresh `AuthEngine` per call).
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

    /// Release owned fields inside a `ResolveError` (alias of `deinitResolveFailure`).
    pub fn deinitResolveError(failure: ResolveError, allocator: std.mem.Allocator) void {
        root.deinitResolveFailure(failure, allocator);
    }
};
/// Outcome of `resolve`: owned success payload or owned failure context.
///
/// On `.failure`, call `deinitResolveFailure(failure, allocator)`.
pub const ResolveOutcome = union(enum) {
    success: ResolveResult,
    failure: ResolveError,
};
/// Outcome of `validate`: terminal status or owned failure context.
///
/// On `.failure`, call `deinitResolveFailure(failure, allocator)`.
pub const ValidateOutcome = union(enum) {
    valid,
    not_found,
    failure: ResolveError,
};
/// Outcome of `getManifest`: arena-owned parsed manifest or owned failure context.
///
/// On `.success`, call `parsed.deinit()`. On `.failure`, call `deinitResolveFailure`.
pub const ManifestOutcome = union(enum) {
    success: std.json.Parsed(Manifest),
    failure: ResolveError,
};
/// Release caller-owned storage inside a `ResolveError` from a public outcome `.failure` arm.
pub fn deinitResolveFailure(failure: ResolveError, allocator: std.mem.Allocator) void {
    failure.deinitOwned(allocator);
}
// --- Public resolve API ---

/// Resolve an image reference to a pinned manifest digest.
///
/// Ownership contract:
/// - The returned ResolveResult is owned through the caller-provided allocator.
/// - On success, `registry`, `repository`, and `tag` from the input `ref` are moved into
///   `result.reference`; do not call `ref.deinit()` after a successful resolve.
/// - Call `result.deinit(allocator)` when using a non-arena allocator.
/// - If the allocator is an arena, tearing the arena down is also sufficient.
/// - `ResolveResult.clone()` is only needed when moving the result into a different allocator.
///
/// Auth: manifest `HEAD`/`GET` drives registry probes; `401` bearer challenges, token
/// exchange, and cached-401 retry are handled inside `resolver` + `auth` (see module filedocs).
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
/// Validate that a manifest reference still exists and is fetchable.
///
/// Ownership contract:
/// - No owned success payload is returned from this API.
/// - The caller owns `allocator` for the HEAD phase: `performManifestHead` stores
///   response metadata and structured failures on that allocator until the call
///   returns. Failures promoted from HEAD use `promoteResolveErrorAlloc`.
/// - When HEAD requires a GET fallback (405, missing digest header, etc.), the
///   fallback fetch uses an internal transient arena like `resolve`/`getManifest`;
///   only `ResolveError.reference` on failure is promoted back to the caller
///   allocator before the arena is torn down.
/// - HEAD failures extracted by `classifyValidateManifestHead` (`.owned_failure`)
///   already own `reference` on the caller allocator; return them directly.
///
/// Auth: same manifest/auth pipeline as `resolve` (internal to resolver/auth).
/// Validation treats `.not_found` as terminal. Multi-arch without `platform` returns
/// `ResolveError.platform_required`.
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
/// Fetch and parse a manifest payload.
///
/// Ownership contract:
/// - The returned std.json.Parsed(Manifest) owns an arena.
/// - Call parsed.deinit() when finished.
/// - Do not free the allocator backing that arena while the parsed value is still in use.
///
/// Auth: same manifest/auth pipeline as `resolve` (internal to resolver/auth).
/// Multi-arch without `platform` returns `ResolveError.platform_required`.
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
fn ensureClientConfigured(config: Config, client: *std.http.Client) PublicApiError!void {
    return config.applyToClient(client);
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
            errdefer allocator.free(detached.resolved_digest_raw);
            errdefer if (detached.platform) |value| deinitOwnedPlatform(value, transient);

            const caller_digest_raw = try allocator.dupe(u8, detached.resolved_digest_raw);
            errdefer allocator.free(caller_digest_raw);

            const caller_platform: ?Platform = if (detached.platform) |value|
                try clonePlatformAlloc(allocator, value)
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

    var selected_child_platform: ?Platform = null;
    if (child_descriptor.platform) |child_platform| {
        selected_child_platform = try clonePlatformAlloc(allocator, child_platform);
        errdefer if (selected_child_platform) |owned_platform| deinitOwnedPlatform(owned_platform, allocator);
    }

    var child_ref_string_buffer: [128]u8 = undefined;
    const child_ref_string = std.fmt.bufPrint(
        &child_ref_string_buffer,
        "{s}:{s}",
        .{ @tagName(child_descriptor.digest.algorithm), child_descriptor.digest.hex },
    ) catch unreachable;

    owned_parent_document.deinit();
    parent_document_live = false;

    var child_outcome = try fetchResolvedManifestWithExchangers(
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

    switch (child_outcome) {
        .success => |*child_success| {
            if (child_success.platform == null) {
                if (selected_child_platform) |child_platform| {
                    child_success.platform = child_platform;
                    selected_child_platform = null;
                }
            } else if (selected_child_platform) |child_platform| {
                deinitOwnedPlatform(child_platform, allocator);
                selected_child_platform = null;
            }
        },
        .failure => {
            if (selected_child_platform) |child_platform| {
                deinitOwnedPlatform(child_platform, allocator);
                selected_child_platform = null;
            }
        },
    }

    if (selected_child_platform) |child_platform| {
        deinitOwnedPlatform(child_platform, allocator);
    }

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
fn deinitOwnedResolveError(failure: ResolveError, allocator: std.mem.Allocator) void {
    deinitResolveFailure(failure, allocator);
}
fn promoteResolveErrorAlloc(allocator: std.mem.Allocator, failure: ResolveError) !ResolveError {
    const owned_reference = try allocator.dupe(u8, switch (failure) {
        inline else => |value| value.reference,
    });
    errdefer allocator.free(owned_reference);
    return failure.withOwnedReference(owned_reference);
}
const expectResolveFailure = test_matrix.expectResolveFailure;
const readFixtureAlloc = test_matrix.readFixtureAlloc;
const sha256DigestStringAlloc = test_matrix.sha256DigestStringAlloc;
const buildIndexBodyAlloc = test_matrix.buildIndexBodyAlloc;

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
test "resolveWithExchangers returns pinned single-arch result for tag reference" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            const body = readFixtureAlloc(allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = digest,
            }, body);
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try resolveWithExchangers(
        arena_allocator,
        &client,
        Config{},
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

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
        },
        .failure => return error.TestUnexpectedResult,
    }
}
test "resolveWithExchangers moves input reference strings into result without re-duping" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            const body = readFixtureAlloc(allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
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

    const allocator = std.testing.allocator;
    const ref = try Reference.parse(allocator, "registry-1.docker.io/library/busybox:latest");
    const registry_ptr = ref.registry.ptr;
    const repository_ptr = ref.repository.ptr;
    const tag_ptr = ref.tag.?.ptr;

    var client: std.http.Client = undefined;
    const outcome = try resolveWithExchangers(
        allocator,
        &client,
        Config{},
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |result| {
            try std.testing.expect(result.reference.registry.ptr == registry_ptr);
            try std.testing.expect(result.reference.repository.ptr == repository_ptr);
            try std.testing.expect(result.reference.tag.?.ptr == tag_ptr);
            try std.testing.expect(result.reference.digest != null);
            try std.testing.expect(result.reference.digest_raw != null);
            try std.testing.expectEqualSlices(u8, result.digest.hex, result.reference.digest.?.hex);

            var owned = result;
            owned.deinit(allocator);
        },
        .failure => return error.TestUnexpectedResult,
    }
}
test "resolveWithExchangers repeated single-arch runs leave no residual allocations under DebugAllocator" {
    const MockHarness = struct {
        var body: []u8 = undefined;
        var digest: []u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = digest,
            }, body);
        }
    };

    MockHarness.body = try readFixtureAlloc(std.testing.allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024);
    defer std.testing.allocator.free(MockHarness.body);

    MockHarness.digest = try sha256DigestStringAlloc(std.testing.allocator, MockHarness.body);
    defer std.testing.allocator.free(MockHarness.digest);

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;

    for (0..32) |_| {
        const ref = try Reference.parse(allocator, "registry-1.docker.io/library/busybox:latest");
        const outcome = try resolveWithExchangers(
            allocator,
            &client,
            Config{},
            ref,
            null,
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );

        switch (outcome) {
            .success => |result| {
                var owned = result;
                owned.deinit(allocator);
            },
            .failure => return error.TestUnexpectedResult,
        }
    }
}
test "getManifestWithExchangers returns parsed single-arch manifest" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            const body = readFixtureAlloc(allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = digest,
            }, body);
        }
    };

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try getManifestWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |parsed| {
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u32, 2), parsed.value.schema_version);
            try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
            try std.testing.expect(parsed.value.config.digest.hex.len == 64);
            try std.testing.expect(parsed.value.layers.len > 0);
            try std.testing.expectEqualSlices(u8, "925ff61909aebae4bcc9bc04bb96a8bd15cd2271f13159fe95ce4338824531dd", parsed.value.config.digest.hex);
        },
        .failure => return error.TestUnexpectedResult,
    }
}
test "getManifestWithExchangers per-resolve arena promotes manifest without leaking" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            const body = readFixtureAlloc(allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = digest,
            }, body);
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    for (0..32) |_| {
        const outcome = try getManifestWithExchangers(
            allocator,
            &client,
            Config{},
            ref,
            null,
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );

        switch (outcome) {
            .success => |parsed| parsed.deinit(),
            .failure => return error.TestUnexpectedResult,
        }
    }
}
test "ResolvedManifestSuccess: detachForResolvePromotion clears digest alias before deinit" {
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
test "ResolvedManifestSuccess: deinit clears every owned field" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "size": 1,
        \\    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\  },
        \\  "layers": []
        \\}
    ;

    const parsed = try std.json.parseFromSlice(
        Manifest,
        std.testing.allocator,
        json_bytes,
        .{},
    );
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
        .backing_body = try std.testing.allocator.dupe(u8, json_bytes),
    };

    success.deinit(std.testing.allocator);

    try std.testing.expect(success.resolved_digest_raw.len == 0);
    try std.testing.expect(success.resolved_digest.hex.len == 0);
    try std.testing.expect(success.backing_body == null);
    try std.testing.expect(success.platform == null);
    switch (success.document) {
        .manifest_media_type => |media_type| try std.testing.expectEqual(MediaType.oci_manifest_v1, media_type),
        else => return error.TestUnexpectedResult,
    }
}
test "ResolvedManifestSuccess: detachManifestForPromotion OOM leaves shell deinit-safe" {
    const json_bytes =
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

    const MockHarness = struct {
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
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, MockHarness.run, .{json_bytes});
}
test "ResolvedManifestSuccess: detachManifestForPromotion clears digest fields on success" {
    const json_bytes =
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

    const parsed_local = try json.parse(Manifest, transient, json_bytes);
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
test "getManifestWithExchangers matches direct parse of live busybox fixture" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            const body = readFixtureAlloc(allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = digest,
            }, body);
        }
    };

    const fixture_bytes = try readFixtureAlloc(std.testing.allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024);
    defer std.testing.allocator.free(fixture_bytes);

    const direct = try json.parse(Manifest, std.testing.allocator, fixture_bytes);
    defer direct.deinit();

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try getManifestWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |parsed| {
            defer parsed.deinit();
            try std.testing.expectEqual(direct.value.schema_version, parsed.value.schema_version);
            try std.testing.expectEqual(direct.value.media_type, parsed.value.media_type);
            try std.testing.expectEqual(direct.value.config.size, parsed.value.config.size);
            try std.testing.expectEqualSlices(u8, direct.value.config.digest.hex, parsed.value.config.digest.hex);
            try std.testing.expectEqual(direct.value.layers.len, parsed.value.layers.len);
            try std.testing.expectEqual(direct.value.layers[0].size, parsed.value.layers[0].size);
            try std.testing.expectEqualSlices(u8, direct.value.layers[0].digest.hex, parsed.value.layers[0].digest.hex);
            try std.testing.expect(direct.value.annotations != null);
            try std.testing.expect(parsed.value.annotations != null);
            try std.testing.expectEqualStrings(
                direct.value.annotations.?.object.get("org.opencontainers.image.version").?.string,
                parsed.value.annotations.?.object.get("org.opencontainers.image.version").?.string,
            );
        },
        .failure => return error.TestUnexpectedResult,
    }
}
test "getManifestWithExchangers failure promotes caller-owned reference" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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

    const child_digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999";
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
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try getManifestWithExchangers(std.testing.allocator, &client, Config{}, ref, null, MockHarness.tokenExchange, MockHarness.manifestExchange, .{});
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .success => return error.TestUnexpectedResult,
        .failure => |failure| try expectResolveFailure(
            failure,
            "platform_required",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            null,
            null,
        ),
    }
}
test "validateWithExchangers returns not_found for missing manifest" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .not_found,
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/alpine",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    try std.testing.expectEqual(ValidateOutcome.not_found, outcome);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/alpine", ref.repository);
    try std.testing.expectEqualSlices(u8, "latest", ref.tag.?);
}
test "validateWithExchangers returns valid from HEAD for single-arch manifest" {
    const MockHarness = struct {
        var saw_head = false;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (request.method != .head) return error.TransportFailed;
            saw_head = true;

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/alpine",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    try std.testing.expect(MockHarness.saw_head);
    try std.testing.expectEqual(ValidateOutcome.valid, outcome);
}
test "validateWithExchangers single-arch HEAD avoids metadata clone allocations" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            if (request.method != .head) return error.TransportFailed;
            return .{ .metadata = .{
                .status = .ok,
                .content_type = MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            } };
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/alpine",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    for (0..32) |_| {
        const outcome = try validateWithExchangers(
            allocator,
            &client,
            Config{},
            ref,
            null,
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );
        try std.testing.expectEqual(ValidateOutcome.valid, outcome);
    }
}
test "validateWithExchangers HEAD to GET fallback stays leak-free under DebugAllocator" {
    const MockHarness = struct {
        var saw_get = false;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (request.method == .head) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                }, null);
            }

            saw_get = true;
            const body = readFixtureAlloc(allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
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

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    for (0..16) |_| {
        MockHarness.saw_get = false;
        const outcome = try validateWithExchangers(
            allocator,
            &client,
            Config{},
            ref,
            .{ .os = "linux", .architecture = "amd64" },
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );
        try std.testing.expect(MockHarness.saw_get);
        try std.testing.expectEqual(ValidateOutcome.valid, outcome);
    }
}
test "validateWithExchangers returns platform_required from HEAD for multi-arch request without platform" {
    const MockHarness = struct {
        var calls: usize = 0;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            calls += 1;
            if (request.method != .head) return error.TransportFailed;

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_index_v1.toString(),
                .docker_content_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    try std.testing.expectEqual(@as(usize, 1), MockHarness.calls);
    switch (outcome) {
        .failure => |failure| try expectResolveFailure(
            failure,
            "platform_required",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            null,
            null,
        ),
        else => return error.TestUnexpectedResult,
    }
}
test "resolveWithExchangers propagates resolver failure matrix with full context" {
    const MockHarness = struct {
        var scenario: test_matrix.Scenario = .network_error;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            return test_matrix.manifestExchange(scenario, allocator, request);
        }
    };

    defer test_matrix.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    for (test_matrix.resolve_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try test_matrix.prepareScenario(scenario, std.testing.allocator);

        const outcome = try resolveWithExchangers(
            std.testing.allocator,
            &client,
            test_matrix.scenarioConfig(scenario),
            ref,
            test_matrix.scenarioPlatform(scenario),
            MockHarness.tokenExchange,
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
test "validateWithExchangers propagates representative failure matrix with full context" {
    const MockHarness = struct {
        var scenario: test_matrix.Scenario = .not_found;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            return test_matrix.manifestExchange(scenario, allocator, request);
        }
    };

    defer test_matrix.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    for (test_matrix.validate_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try test_matrix.prepareScenario(scenario, std.testing.allocator);

        const outcome = try validateWithExchangers(
            std.testing.allocator,
            &client,
            test_matrix.scenarioConfig(scenario),
            ref,
            test_matrix.scenarioPlatform(scenario),
            MockHarness.tokenExchange,
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
                    null,
                ),
            },
        }
    }
}
test "getManifestWithExchangers propagates representative failure matrix with full context" {
    const MockHarness = struct {
        var scenario: test_matrix.Scenario = .not_found;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            return test_matrix.manifestExchange(scenario, allocator, request);
        }
    };

    defer test_matrix.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    for (test_matrix.get_manifest_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try test_matrix.prepareScenario(scenario, std.testing.allocator);

        const outcome = try getManifestWithExchangers(
            std.testing.allocator,
            &client,
            test_matrix.scenarioConfig(scenario),
            ref,
            test_matrix.scenarioPlatform(scenario),
            MockHarness.tokenExchange,
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
                null,
            ),
        }
    }
}
test "resolveWithExchangers authenticates on challenge and resolves manifest" {
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

            if (request.authorization == null) return error.TransportFailed;
            if (!std.mem.eql(u8, request.authorization.?, "Bearer resolve-token")) return error.TransportFailed;

            const body = readFixtureAlloc(allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
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
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try resolveWithExchangers(
        arena.allocator(),
        &client,
        Config{},
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |result| {
            try std.testing.expectEqual(MediaType.oci_manifest_v1, result.media_type);
            try std.testing.expect(result.platform == null);
            try std.testing.expectEqualSlices(u8, "registry-1.docker.io", result.reference.registry);
            try std.testing.expectEqualSlices(u8, "library/busybox", result.reference.repository);
            try std.testing.expectEqualSlices(u8, "latest", result.reference.tag.?);
            try std.testing.expect(result.reference.digest != null);
            try std.testing.expectEqualSlices(u8, result.digest.hex, result.reference.digest.?.hex);
            try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_calls);
        },
        .failure => return error.TestUnexpectedResult,
    }
}
test "resolveWithExchangers maps exhausted token transport timeout to timeout" {
    const MockHarness = struct {
        var token_attempts: usize = 0;
        var manifest_calls: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            token_attempts += 1;
            return error.Timeout;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: resolver.ManifestHttpRequest,
        ) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_calls += 1;
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .unauthorized,
                .www_authenticate_headers = &.{
                    "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:library/busybox:pull\"",
                },
            }, null);
        }
    };

    defer {
        MockHarness.token_attempts = 0;
        MockHarness.manifest_calls = 0;
    }

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 1 },
        ref,
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
test "resolveWithExchangers applies fixture ca_bundle_path without breaking mock resolve" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const rel_path = "fixtures/tls/enterprise-test-ca.pem";
    const abs_path = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, rel_path, std.testing.allocator);
    defer std.testing.allocator.free(abs_path);

    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            const body = readFixtureAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = digest,
            }, body);
        }
    };

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const ref = try Reference.parse(std.testing.allocator, "registry-1.docker.io/library/busybox:latest");

    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = abs_path },
        ref,
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
test "resolveWithEngine per-resolve arena promotes failures without leaking" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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
                .content_type = "application/vnd.oci.image.index.v1+json",
                .docker_content_digest = digest,
            }, body);
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(allocator, .{}, MockHarness.tokenExchange);
    defer engine.deinit();

    for (0..32) |_| {
        var ref = try Reference.parse(allocator, "registry-1.docker.io/library/busybox:latest");
        defer ref.deinit(allocator);

        const outcome = try resolveWithEngine(
            allocator,
            &client,
            Config{},
            &engine,
            ref,
            null,
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );

        switch (outcome) {
            .success => return error.TestUnexpectedResult,
            .failure => |failure| {
                defer deinitOwnedResolveError(failure, allocator);
                try expectResolveFailure(
                    failure,
                    "platform_required",
                    "registry-1.docker.io",
                    "registry-1.docker.io/library/busybox:latest",
                    null,
                    null,
                );
            },
        }
    }
}
test "validateWithEngine per-resolve arena promotes failures without leaking" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(allocator, .{}, MockHarness.tokenExchange);
    defer engine.deinit();

    for (0..32) |_| {
        var ref = try Reference.parse(allocator, "registry-1.docker.io/library/busybox:latest");
        defer ref.deinit(allocator);

        const outcome = try validateWithEngine(
            allocator,
            &client,
            Config{},
            &engine,
            ref,
            null,
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );

        switch (outcome) {
            .valid, .not_found => return error.TestUnexpectedResult,
            .failure => |failure| {
                defer deinitOwnedResolveError(failure, allocator);
                try expectResolveFailure(
                    failure,
                    "platform_required",
                    "registry-1.docker.io",
                    "registry-1.docker.io/library/busybox:latest",
                    null,
                    null,
                );
            },
        }
    }
}
test "getManifestWithEngine per-resolve arena promotes failures without leaking" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(allocator, .{}, MockHarness.tokenExchange);
    defer engine.deinit();

    for (0..32) |_| {
        var ref = try Reference.parse(allocator, "registry-1.docker.io/library/busybox:latest");
        defer ref.deinit(allocator);

        const outcome = try getManifestWithEngine(
            allocator,
            &client,
            Config{},
            &engine,
            ref,
            null,
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );

        switch (outcome) {
            .success => |parsed| parsed.deinit(),
            .failure => |failure| {
                defer deinitOwnedResolveError(failure, allocator);
                try expectResolveFailure(
                    failure,
                    "platform_required",
                    "registry-1.docker.io",
                    "registry-1.docker.io/library/busybox:latest",
                    null,
                    null,
                );
            },
        }
    }
}
test "validateWithExchangers returns valid for selected multi-arch child manifest" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;
        var child_head_calls: usize = 0;
        var child_get_calls: usize = 0;
        var index_calls: usize = 0;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (std.mem.endsWith(u8, request.url, "/manifests/latest")) {
                index_calls += 1;
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
    MockHarness.index_calls = 0;

    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        .{ .os = "linux", .architecture = "arm64" },
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    try std.testing.expectEqual(ValidateOutcome.valid, outcome);
    try std.testing.expect(MockHarness.index_calls >= 1);
    try std.testing.expectEqual(@as(usize, 1), MockHarness.child_head_calls);
    try std.testing.expectEqual(@as(usize, 0), MockHarness.child_get_calls);
}
test "validateWithExchangers returns platform_required when multi-arch request omits platform" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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

    const child_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
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
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try validateWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
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
        .valid, .not_found => return error.TestUnexpectedResult,
        .failure => |failure| try expectResolveFailure(
            failure,
            "platform_required",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            null,
            null,
        ),
    }
}
test "getManifestWithExchangers returns platform_required when multi-arch request omits platform" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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

    const child_digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999";
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
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try getManifestWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
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
        .success => |parsed| {
            parsed.deinit();
            return error.TestUnexpectedResult;
        },
        .failure => |failure| try expectResolveFailure(
            failure,
            "platform_required",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            null,
            null,
        ),
    }
}
test "resolveWithExchangers resolves multi-arch index to selected child manifest" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try resolveWithExchangers(
        arena.allocator(),
        &client,
        Config{},
        ref,
        .{ .os = "linux", .architecture = "arm64" },
        MockHarness.tokenExchange,
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
test "resolveWithExchangers repeated multi-arch runs leave no residual allocations under DebugAllocator" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;

    for (0..32) |_| {
        const ref = try Reference.parse(allocator, "registry-1.docker.io/library/busybox:latest");
        const outcome = try resolveWithExchangers(
            allocator,
            &client,
            Config{},
            ref,
            .{ .os = "linux", .architecture = "arm64" },
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );

        switch (outcome) {
            .success => |result| {
                var owned = result;
                owned.deinit(allocator);
            },
            .failure => return error.TestUnexpectedResult,
        }
    }
}
test "resolveWithExchangers returns platform_not_found when multi-arch platform is missing" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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

    const child_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
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
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        .{ .os = "windows", .architecture = "amd64" },
        MockHarness.tokenExchange,
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
            "platform_not_found",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            null,
            null,
        ),
    }
}
test "getManifestWithExchangers resolves nested index to leaf manifest" {
    const MockHarness = struct {
        var outer_body: []u8 = undefined;
        var outer_digest: []u8 = undefined;
        var inner_body: []u8 = undefined;
        var inner_digest: []u8 = undefined;
        var leaf_body: []u8 = undefined;
        var leaf_digest: []u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try getManifestWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        .{ .os = "linux", .architecture = "arm64" },
        MockHarness.tokenExchange,
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
test "resolveWithExchangers returns depth_limit_exceeded for nested indexes beyond limit" {
    const depth = MAX_CHILD_MANIFEST_DEPTH + 1;
    const MockHarness = struct {
        var bodies: [depth][]u8 = undefined;
        var digests: [depth][]u8 = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

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
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        Config{},
        ref,
        .{ .os = "linux", .architecture = "arm64" },
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .success => return error.TestUnexpectedResult,
        .failure => |failure| switch (failure) {
            .depth_limit_exceeded => {},
            else => return error.TestUnexpectedResult,
        },
    }
}
