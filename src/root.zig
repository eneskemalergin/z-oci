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
//!   Engine-created tokens (`TokenResponse`) are caller-owned → `.deinit(allocator)`.
//! - Types that never allocate: `Digest` (borrowed view), `MediaType` (enum),
//!   `Platform` (struct of slices), `AuthChallenge`/`BearerChallenge` (borrowed views).
//!   These need no deinit.
//!
const std = @import("std");
const resolver = @import("resolver.zig");
const resilience = @import("resilience.zig");

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
pub const AuthError = auth.AuthError;
pub const AuthChallenge = auth.AuthChallenge;
pub const AuthReferenceView = auth.AuthReferenceView;
pub const BearerChallenge = auth.BearerChallenge;
pub const AuthenticateRequest = auth.AuthenticateRequest;
pub const ProbeResult = auth.ProbeResult;
pub const ProbeHttpResponse = auth.ProbeHttpResponse;
pub const referenceView = auth.referenceView;
pub const Token = auth.Token;
pub const TokenResponse = auth.TokenResponse;
pub const TokenCacheKey = auth.TokenCacheKey;
pub const CachedToken = auth.CachedToken;
pub const ResolveError = @import("ResolveError.zig").ResolveError;
pub const ResolveResult = @import("ResolveResult.zig");
pub const Config = @import("Config.zig").Config;
pub const CredentialProvider = @import("Config.zig").CredentialProvider;
pub const Credential = @import("Config.zig").Credential;
pub const CredentialHandle = @import("Config.zig").CredentialHandle;

pub const PublicApiError = Config.ApplyError;
const root = @This();

/// Narrow testing seam for repository smoke tests.
///
/// This keeps workflow-level coverage on the same public resolver logic while
/// still allowing injected transports instead of real network access.
pub const testing = struct {
    pub const TokenHttpExchanger = auth.TokenHttpExchanger;
    pub const ManifestHttpExchanger = resolver.ManifestHttpExchanger;
    pub const ManifestHttpRequest = resolver.ManifestHttpRequest;
    pub const ManifestHttpResponse = resolver.ManifestHttpResponse;
    pub const ManifestExchangeError = resolver.ManifestExchangeError;

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

    pub fn deinitResolveError(failure: ResolveError, allocator: std.mem.Allocator) void {
        root.deinitOwnedResolveError(failure, allocator);
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

pub const ManifestOutcome = union(enum) {
    success: std.json.Parsed(Manifest),
    failure: ResolveError,
};

const max_child_manifest_depth: usize = 4;

const manifest_accept_values = [_][]const u8{
    MediaType.oci_manifest_v1.toString(),
    MediaType.docker_manifest_v2.toString(),
    MediaType.oci_index_v1.toString(),
    MediaType.docker_manifest_list_v2.toString(),
};

const ResolvedManifestSuccess = struct {
    resolved_digest: Digest,
    resolved_digest_raw: []u8,
    document: resolver.ParsedManifestDocument,
    platform: ?Platform,

    fn deinit(self: *ResolvedManifestSuccess, allocator: std.mem.Allocator) void {
        if (self.resolved_digest_raw.len != 0) allocator.free(self.resolved_digest_raw);
        self.document.deinit();
        if (self.platform) |platform| deinitOwnedPlatform(platform, allocator);
    }
};

const ResolvedManifestOutcome = union(enum) {
    success: ResolvedManifestSuccess,
    failure: ResolveError,
};

/// Resolve an image reference to a pinned manifest digest.
///
/// Ownership contract:
/// - The returned ResolveResult is owned through the caller-provided allocator.
/// - Call `result.deinit(allocator)` when using a non-arena allocator.
/// - If the allocator is an arena, tearing the arena down is also sufficient.
/// - `ResolveResult.clone()` is only needed when moving the result into a different allocator.
///
/// Auth handoff contract:
/// - derive `AuthReferenceView` from the normalized `Reference` with `referenceView(ref)`
/// - manifest HEAD/GET is the live probe path today; a `401` with `WWW-Authenticate`
///   triggers auth via `ProbeHttpResponse.classify()` on response metadata
/// - turn that bearer challenge into `AuthenticateRequest.init(view.registry, challenge)` and call
///   `AuthEngine.authenticate(...)`
/// - attach the returned bearer token to the retried HEAD/GET request; if that retry comes back
///   `401`, call `AuthEngine.retryAuthenticateAfterCachedUnauthorized(...)` once for the same
///   request and surface failure after that single retry
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
/// - No owned data is returned from this API.
/// - The caller still owns `allocator`; the resolver uses it for transient request shaping,
///   parsing, and any structured failure context that must outlive internal temporaries.
///
/// Auth handoff contract:
/// - validation follows the same manifest HEAD/GET -> classify -> authenticate -> retry-once flow as `resolve`
/// - validation must treat `.not_found` as terminal and must not attempt auth in that case
/// - multi-arch validation follows the selected child manifest when `platform` is provided
/// - multi-arch validation returns `ResolveError.platform_required` instead of guessing a child when
///   `platform` is null
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
/// Auth handoff contract:
/// - manifest GET uses the same `AuthReferenceView` and `AuthenticateRequest` boundary as `resolve`
/// - auth owns token exchange and cache invalidation; manifest fetch owns Accept negotiation,
///   response status handling, and JSON parsing
/// - multi-arch GET returns `ResolveError.platform_required` instead of guessing a child when
///   `platform` is null
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

    var outcome = try fetchResolvedManifestWithExchangers(
        allocator,
        client,
        config,
        &engine,
        referenceView(ref),
        platform,
        token_exchanger,
        manifest_exchanger,
        .resolve,
        0,
        transport_hooks,
    );
    switch (outcome) {
        .success => |*success| {
            defer success.deinit(allocator);
            const manifest = switch (success.document) {
                .manifest => |parsed| parsed.value,
                else => unreachable,
            };
            const selected_platform = success.platform;
            success.platform = null;
            const resolved_digest_raw = success.resolved_digest_raw;
            success.resolved_digest_raw = "";

            return .{ .success = try buildResolveResultAlloc(
                allocator,
                ref,
                resolved_digest_raw,
                manifest.media_type,
                selected_platform,
            ) };
        },
        .failure => |failure| {
            return .{ .failure = failure };
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
    try ensureClientConfigured(config, client);

    var engine = auth.AuthEngine.initWithTokenHttpExchangerAndHooks(allocator, config, token_exchanger, transport_hooks);
    defer engine.deinit();

    const ref_view = referenceView(ref);
    const ctx = resolver.ResolverContext.initWithTransportHooks(
        allocator,
        client,
        config,
        ref_view,
        platform,
        .validate,
        transport_hooks,
    );

    const head_outcome = try resolver.performManifestHead(ctx, &engine, manifest_exchanger, manifestAcceptValues());
    switch (head_outcome) {
        .success => |metadata| {
            defer metadata.deinitOwned(allocator);

            if (try validateOutcomeFromHeadMetadata(allocator, ref_view, platform, metadata)) |outcome| {
                return outcome;
            }
        },
        .use_get_fallback => |metadata| metadata.deinitOwned(allocator),
        .not_found => return .not_found,
        .redirect => |metadata| {
            defer metadata.deinitOwned(allocator);
            return .{ .failure = try networkErrorAlloc(allocator, ref_view, metadata.httpStatus()) };
        },
        .failure => |failure| return .{ .failure = failure },
    }

    var outcome = try fetchResolvedManifestWithExchangers(
        allocator,
        client,
        config,
        &engine,
        ref_view,
        platform,
        token_exchanger,
        manifest_exchanger,
        .validate,
        0,
        transport_hooks,
    );
    return validateOutcomeFromResolvedManifestOutcome(allocator, &outcome);
}

fn validateOutcomeFromResolvedManifestOutcome(
    allocator: std.mem.Allocator,
    outcome: *ResolvedManifestOutcome,
) ValidateOutcome {
    switch (outcome.*) {
        .success => |*success| {
            defer success.deinit(allocator);
            return switch (success.document) {
                .manifest => .valid,
                else => unreachable,
            };
        },
        .failure => |failure| return switch (failure) {
            .not_found => {
                deinitOwnedResolveError(failure, allocator);
                return .not_found;
            },
            else => .{ .failure = failure },
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
    try ensureClientConfigured(config, client);

    var engine = auth.AuthEngine.initWithTokenHttpExchangerAndHooks(allocator, config, token_exchanger, transport_hooks);
    defer engine.deinit();

    var outcome = try fetchResolvedManifestWithExchangers(
        allocator,
        client,
        config,
        &engine,
        referenceView(ref),
        platform,
        token_exchanger,
        manifest_exchanger,
        .get_manifest,
        0,
        transport_hooks,
    );
    switch (outcome) {
        .success => |*success| {
            const parsed_manifest = switch (success.document) {
                .manifest => |parsed| parsed,
                else => unreachable,
            };

            if (success.platform) |selected_platform| deinitOwnedPlatform(selected_platform, allocator);
            allocator.free(success.resolved_digest_raw);
            return .{ .success = parsed_manifest };
        },
        .failure => |failure| return .{ .failure = failure },
    }
}

fn fetchResolvedManifestWithExchangers(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    engine: *auth.AuthEngine,
    ref_view: AuthReferenceView,
    platform: ?Platform,
    _: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
    operation: resolver.ResolverOperation,
    depth: usize,
    transport_hooks: resilience.TransportHooks,
) PublicApiError!ResolvedManifestOutcome {
    if (depth > max_child_manifest_depth) {
        return .{ .failure = try depthLimitExceededErrorAlloc(allocator, ref_view) };
    }

    const ctx = resolver.ResolverContext.initWithTransportHooks(
        allocator,
        client,
        config,
        ref_view,
        platform,
        if (depth == 0) operation else .resolve_child_manifest,
        transport_hooks,
    );

    var outcome = try resolver.performManifestGet(ctx, engine, manifest_exchanger, manifestAcceptValues());
    switch (outcome) {
        .success => |*success| {
            success.metadata.deinitOwned(allocator);

            const document = success.document;
            const resolved_digest = success.resolved_digest;
            const resolved_digest_raw = success.resolved_digest_raw;

            switch (document) {
                .manifest => {
                    return .{ .success = .{
                        .resolved_digest = resolved_digest,
                        .resolved_digest_raw = resolved_digest_raw,
                        .document = document,
                        .platform = null,
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
                        depth,
                        resolved_digest_raw,
                        document,
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
                        depth,
                        resolved_digest_raw,
                        document,
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
    depth: usize,
    parent_digest_raw: []u8,
    parent_document: resolver.ParsedManifestDocument,
    multi_arch: MultiArchManifest,
) PublicApiError!ResolvedManifestOutcome {
    defer allocator.free(parent_digest_raw);
    defer {
        var owned_document = parent_document;
        owned_document.deinit();
    }

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
        auth.liveTokenHttpExchanger,
        manifest_exchanger,
        .resolve_child_manifest,
        depth + 1,
        engine.transport_hooks,
    );

    switch (child_outcome) {
        .success => |*child_success| {
            if (child_success.platform == null) {
                if (child_descriptor.platform) |child_platform| {
                    child_success.platform = try clonePlatformAlloc(allocator, child_platform);
                }
            }
        },
        .failure => {},
    }

    return child_outcome;
}

fn manifestAcceptValues() []const []const u8 {
    return &manifest_accept_values;
}

fn buildResolveResultAlloc(
    allocator: std.mem.Allocator,
    ref: Reference,
    resolved_digest_raw: []u8,
    media_type: MediaType,
    platform: ?Platform,
) error{OutOfMemory}!ResolveResult {
    var resolved_reference = try buildResolvedReferenceAlloc(allocator, ref, resolved_digest_raw);
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
) error{OutOfMemory}!Reference {
    const registry = try allocator.dupe(u8, ref.registry);
    errdefer allocator.free(registry);

    const repository = try allocator.dupe(u8, ref.repository);
    errdefer allocator.free(repository);

    const tag = if (ref.tag) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (tag) |value| allocator.free(value);

    errdefer allocator.free(resolved_digest_raw);

    const digest = Digest.parse(resolved_digest_raw) catch unreachable;
    return .{
        .registry = registry,
        .repository = repository,
        .tag = tag,
        .digest = digest,
        .digest_raw = resolved_digest_raw,
    };
}

fn notFoundErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .not_found, null);
}

fn networkErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView, http_status: ?u16) !ResolveError {
    return allocatedResolveError(allocator, ref, .network_error, http_status);
}

fn platformNotFoundErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .platform_not_found, null);
}

fn platformRequiredErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .platform_required, null);
}

fn depthLimitExceededErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    return allocatedResolveError(allocator, ref, .depth_limit_exceeded, null);
}

fn allocatedResolveError(
    allocator: std.mem.Allocator,
    ref: AuthReferenceView,
    comptime tag: std.meta.Tag(ResolveError),
    http_status: ?u16,
) !ResolveError {
    const reference = try resolver.canonicalReferenceAlloc(allocator, ref);
    return @unionInit(ResolveError, @tagName(tag), .{
        .registry = ref.registry,
        .reference = reference,
        .http_status = http_status,
    });
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
    failure.deinitOwned(allocator);
}

fn expectResolveFailure(
    failure: ResolveError,
    expected_tag_name: []const u8,
    expected_registry: []const u8,
    expected_reference: []const u8,
    expected_http_status: ?u16,
) !void {
    try std.testing.expectEqualStrings(expected_tag_name, @tagName(std.meta.activeTag(failure)));
    switch (failure) {
        inline else => |value| {
            try std.testing.expectEqualSlices(u8, expected_registry, value.registry);
            try std.testing.expectEqualSlices(u8, expected_reference, value.reference);
            try std.testing.expectEqual(expected_http_status, value.http_status);
        },
    }
}

fn readFixtureAlloc(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(max_bytes),
    );
}

fn sha256DigestStringAlloc(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var digest_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest_bytes, .{});
    const digest_hex = std.fmt.bytesToHex(digest_bytes, .lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{digest_hex[0..]});
}

fn buildIndexBodyAlloc(
    allocator: std.mem.Allocator,
    index_media_type: []const u8,
    child_media_type: []const u8,
    child_digest: []const u8,
    os: []const u8,
    architecture: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "schemaVersion": 2,
        \\  "mediaType": "{s}",
        \\  "manifests": [
        \\    {{
        \\      "mediaType": "{s}",
        \\      "digest": "{s}",
        \\      "size": 610,
        \\      "platform": {{
        \\        "os": "{s}",
        \\        "architecture": "{s}"
        \\      }}
        \\    }}
        \\  ]
        \\}}
    ,
        .{ index_media_type, child_media_type, child_digest, os, architecture },
    );
}

// Pulling every sub-module into the test build.
// zig test only includes tests from the root file unless sub-modules are
// referenced here. Each @import forces the compiler to compile that file in
// test mode, which makes its test blocks visible to the test runner.
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
}

test "resolveWithExchangers returns pinned single-arch result for tag reference" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
        State.tokenExchange,
        State.manifestExchange,
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

test "resolveWithExchangers repeated single-arch runs leave no residual allocations under DebugAllocator" {
    const State = struct {
        var body: []u8 = undefined;
        var digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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

    State.body = try readFixtureAlloc(std.testing.allocator, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 16 * 1024);
    defer std.testing.allocator.free(State.body);

    State.digest = try sha256DigestStringAlloc(std.testing.allocator, State.body);
    defer std.testing.allocator.free(State.digest);

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
        const outcome = try resolveWithExchangers(
            allocator,
            &client,
            Config{},
            ref,
            null,
            State.tokenExchange,
            State.manifestExchange,
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
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |parsed| {
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u32, 2), parsed.value.schema_version);
            try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
        },
        .failure => return error.TestUnexpectedResult,
    }
}

test "validateWithExchangers returns not_found for missing manifest" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );

    try std.testing.expectEqual(ValidateOutcome.not_found, outcome);
}

test "validateWithExchangers returns valid from HEAD for single-arch manifest" {
    const State = struct {
        var saw_head = false;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );

    try std.testing.expect(State.saw_head);
    try std.testing.expectEqual(ValidateOutcome.valid, outcome);
}

test "validateWithExchangers returns platform_required from HEAD for multi-arch request without platform" {
    const State = struct {
        var calls: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    try std.testing.expectEqual(@as(usize, 1), State.calls);
    switch (outcome) {
        .failure => |failure| switch (failure) {
            .platform_required => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "resolveWithExchangers propagates resolver failure matrix with full context" {
    const Matrix = struct {
        const Scenario = enum {
            network_error,
            auth_failed,
            content_type_mismatch,
            manifest_parse_error,
            digest_mismatch,
            unsupported_algorithm,
        };

        const BodyKind = enum {
            none,
            malformed_manifest_fixture,
            manifest_fixture,
        };

        const ResponsePlan = struct {
            status: std.http.Status,
            content_type: ?[]const u8 = null,
            docker_content_digest: ?[]const u8 = null,
            body_kind: BodyKind = .none,
            malformed_auth_header: bool = false,
        };

        const scenarios = [_]Scenario{
            .network_error,
            .auth_failed,
            .content_type_mismatch,
            .manifest_parse_error,
            .digest_mismatch,
            .unsupported_algorithm,
        };

        fn responsePlan(scenario: Scenario) ResponsePlan {
            return switch (scenario) {
                .network_error => .{
                    .status = .temporary_redirect,
                },
                .auth_failed => .{
                    .status = .unauthorized,
                    .malformed_auth_header = true,
                },
                .content_type_mismatch => .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.config.v1+json",
                    .body_kind = .manifest_fixture,
                },
                .manifest_parse_error => .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                    .body_kind = .malformed_manifest_fixture,
                },
                .digest_mismatch => .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                    .docker_content_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    .body_kind = .manifest_fixture,
                },
                .unsupported_algorithm => .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                    .docker_content_digest = "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    .body_kind = .manifest_fixture,
                },
            };
        }

        fn expectedTagName(scenario: Scenario) []const u8 {
            return @tagName(scenario);
        }

        fn expectedHttpStatus(scenario: Scenario) ?u16 {
            return @intCast(@intFromEnum(responsePlan(scenario).status));
        }
    };

    const State = struct {
        var scenario: Matrix.Scenario = .network_error;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);

            const plan = Matrix.responsePlan(scenario);
            const headers: []const []const u8 = if (plan.malformed_auth_header)
                &.{"Bearer realm=\"https://auth.example.test/token"}
            else
                &.{};

            const metadata = resolver.ManifestResponseMetadata{
                .status = plan.status,
                .content_type = plan.content_type,
                .docker_content_digest = plan.docker_content_digest,
                .www_authenticate_headers = headers,
            };

            return switch (plan.body_kind) {
                .none => resolver.ManifestHttpResponse.initOwnedAlloc(allocator, metadata, null),
                .malformed_manifest_fixture => blk: {
                    const body = readFixtureAlloc(allocator, "fixtures/manifests/invalid-truncated-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.TransportFailed,
                    };
                    defer allocator.free(body);

                    break :blk resolver.ManifestHttpResponse.initOwnedAlloc(allocator, metadata, body);
                },
                .manifest_fixture => blk: {
                    const body = readFixtureAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.TransportFailed,
                    };
                    defer allocator.free(body);

                    break :blk resolver.ManifestHttpResponse.initOwnedAlloc(allocator, metadata, body);
                },
            };
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

    for (Matrix.scenarios) |scenario| {
        State.scenario = scenario;

        const outcome = try resolveWithExchangers(
            std.testing.allocator,
            &client,
            Config{},
            ref,
            null,
            State.tokenExchange,
            State.manifestExchange,
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
                Matrix.expectedTagName(scenario),
                "registry-1.docker.io",
                "registry-1.docker.io/library/busybox:latest",
                Matrix.expectedHttpStatus(scenario),
            ),
        }
    }
}

test "resolveWithExchangers maps exhausted manifest 429 to rate_limited" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .too_many_requests,
                .resilience_headers = &.{
                    .{ .name = "Retry-After", .value = "1" },
                },
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

    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 0 },
        ref,
        null,
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .failure => |failure| try expectResolveFailure(
            failure,
            "rate_limited",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            429,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "resolveWithExchangers maps exhausted transport timeout to timeout" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
            defer request.deinit(allocator);
            return error.Timeout;
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

    const outcome = try resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 0 },
        ref,
        null,
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .failure => |failure| try expectResolveFailure(
            failure,
            "timeout",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            null,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "resolveWithExchangers returns CaBundleFileNotFound when ca_bundle_path is missing" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" },
        ref,
        null,
        struct {
            fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
                return error.TokenExchangeFailed;
            }
        }.tokenExchange,
        struct {
            fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
                defer request.deinit(allocator);
                unreachable;
            }
        }.manifestExchange,
        .{},
    );

    try std.testing.expectError(error.CaBundleFileNotFound, outcome);
}

test "resolveWithExchangers applies fixture ca_bundle_path without breaking mock resolve" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const rel_path = "fixtures/tls/enterprise-test-ca.pem";
    const abs_path = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, rel_path, std.testing.allocator);
    defer std.testing.allocator.free(abs_path);

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
        .{ .ca_bundle_path = abs_path },
        ref,
        null,
        State.tokenExchange,
        State.manifestExchange,
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

test "validateWithExchangers returns CaBundleFileNotFound when ca_bundle_path is missing" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = validateWithExchangers(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" },
        ref,
        null,
        struct {
            fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
                return error.TokenExchangeFailed;
            }
        }.tokenExchange,
        struct {
            fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
                defer request.deinit(allocator);
                unreachable;
            }
        }.manifestExchange,
        .{},
    );

    try std.testing.expectError(error.CaBundleFileNotFound, outcome);
}

test "getManifestWithExchangers returns CaBundleFileNotFound when ca_bundle_path is missing" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = getManifestWithExchangers(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" },
        ref,
        null,
        struct {
            fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
                return error.TokenExchangeFailed;
            }
        }.tokenExchange,
        struct {
            fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: resolver.ManifestHttpRequest) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
                defer request.deinit(allocator);
                unreachable;
            }
        }.manifestExchange,
        .{},
    );

    try std.testing.expectError(error.CaBundleFileNotFound, outcome);
}

test "resolveWithExchangers returns platform_required when multi-arch request omits platform" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
        null,
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .success => return error.TestUnexpectedResult,
        .failure => |failure| switch (failure) {
            .platform_required => {},
            else => return error.TestUnexpectedResult,
        },
    }
}

test "validateWithExchangers returns valid for selected multi-arch child manifest" {
    const State = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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

    State.child_body = try std.testing.allocator.dupe(
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
    defer std.testing.allocator.free(State.child_body);

    State.child_digest = try sha256DigestStringAlloc(std.testing.allocator, State.child_body);
    defer std.testing.allocator.free(State.child_digest);

    State.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        State.child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.index_body);

    State.index_digest = try sha256DigestStringAlloc(std.testing.allocator, State.index_body);
    defer std.testing.allocator.free(State.index_digest);

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
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );

    try std.testing.expectEqual(ValidateOutcome.valid, outcome);
}

test "validateWithExchangers returns platform_required when multi-arch request omits platform" {
    const State = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
    State.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.index_body);

    State.index_digest = try sha256DigestStringAlloc(std.testing.allocator, State.index_body);
    defer std.testing.allocator.free(State.index_digest);

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
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .valid, .not_found => return error.TestUnexpectedResult,
        .failure => |failure| switch (failure) {
            .platform_required => {},
            else => return error.TestUnexpectedResult,
        },
    }
}

test "getManifestWithExchangers returns platform_required when multi-arch request omits platform" {
    const State = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
    State.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.index_body);

    State.index_digest = try sha256DigestStringAlloc(std.testing.allocator, State.index_body);
    defer std.testing.allocator.free(State.index_digest);

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
        State.tokenExchange,
        State.manifestExchange,
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
        .failure => |failure| switch (failure) {
            .platform_required => {},
            else => return error.TestUnexpectedResult,
        },
    }
}

test "resolveWithExchangers resolves multi-arch index to selected child manifest" {
    const State = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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

    State.child_body = try std.testing.allocator.dupe(
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
    defer std.testing.allocator.free(State.child_body);

    State.child_digest = try sha256DigestStringAlloc(std.testing.allocator, State.child_body);
    defer std.testing.allocator.free(State.child_digest);

    State.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        State.child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.index_body);

    State.index_digest = try sha256DigestStringAlloc(std.testing.allocator, State.index_body);
    defer std.testing.allocator.free(State.index_digest);

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
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |result| {
            try std.testing.expectEqual(MediaType.oci_manifest_v1, result.media_type);
            try std.testing.expect(result.platform != null);
            try std.testing.expectEqualSlices(u8, "linux", result.platform.?.os);
            try std.testing.expectEqualSlices(u8, "arm64", result.platform.?.architecture);
            try std.testing.expectEqualSlices(u8, State.child_digest[("sha256:").len..], result.digest.hex);
        },
        .failure => return error.TestUnexpectedResult,
    }
}

test "resolveWithExchangers repeated multi-arch runs leave no residual allocations under DebugAllocator" {
    const State = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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

    State.child_body = try std.testing.allocator.dupe(
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
    defer std.testing.allocator.free(State.child_body);

    State.child_digest = try sha256DigestStringAlloc(std.testing.allocator, State.child_body);
    defer std.testing.allocator.free(State.child_digest);

    State.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        State.child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.index_body);

    State.index_digest = try sha256DigestStringAlloc(std.testing.allocator, State.index_body);
    defer std.testing.allocator.free(State.index_digest);

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
        const outcome = try resolveWithExchangers(
            allocator,
            &client,
            Config{},
            ref,
            .{ .os = "linux", .architecture = "arm64" },
            State.tokenExchange,
            State.manifestExchange,
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
    const State = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
    State.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.index_body);

    State.index_digest = try sha256DigestStringAlloc(std.testing.allocator, State.index_body);
    defer std.testing.allocator.free(State.index_digest);

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
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| deinitOwnedResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .success => return error.TestUnexpectedResult,
        .failure => |failure| try std.testing.expectEqualStrings("PlatformNotFound", switch (failure) {
            .platform_not_found => "PlatformNotFound",
            else => return error.TestUnexpectedResult,
        }),
    }
}

test "getManifestWithExchangers resolves nested index to leaf manifest" {
    const State = struct {
        var outer_body: []u8 = undefined;
        var outer_digest: []u8 = undefined;
        var inner_body: []u8 = undefined;
        var inner_digest: []u8 = undefined;
        var leaf_body: []u8 = undefined;
        var leaf_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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

    State.leaf_body = try std.testing.allocator.dupe(
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
    defer std.testing.allocator.free(State.leaf_body);

    State.leaf_digest = try sha256DigestStringAlloc(std.testing.allocator, State.leaf_body);
    defer std.testing.allocator.free(State.leaf_digest);

    State.inner_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        State.leaf_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.inner_body);

    State.inner_digest = try sha256DigestStringAlloc(std.testing.allocator, State.inner_body);
    defer std.testing.allocator.free(State.inner_digest);

    State.outer_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_index_v1.toString(),
        State.inner_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.outer_body);

    State.outer_digest = try sha256DigestStringAlloc(std.testing.allocator, State.outer_body);
    defer std.testing.allocator.free(State.outer_digest);

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
        State.tokenExchange,
        State.manifestExchange,
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
    const depth = max_child_manifest_depth + 1;
    const State = struct {
        var bodies: [depth][]u8 = undefined;
        var digests: [depth][]u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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
        State.bodies[reverse_index] = try buildIndexBodyAlloc(
            std.testing.allocator,
            MediaType.oci_index_v1.toString(),
            MediaType.oci_index_v1.toString(),
            next_digest,
            "linux",
            "arm64",
        );
        State.digests[reverse_index] = try sha256DigestStringAlloc(std.testing.allocator, State.bodies[reverse_index]);
        next_digest = State.digests[reverse_index];
    }
    defer for (State.bodies) |body| std.testing.allocator.free(body);
    defer for (State.digests) |digest| std.testing.allocator.free(digest);

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
        State.tokenExchange,
        State.manifestExchange,
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
