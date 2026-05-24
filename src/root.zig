//! z-oci: Pure Zig OCI/Docker Registry API v2 toolkit.
//!
//! Current scope:
//! - offline OCI/Docker reference parsing and normalization
//! - OCI manifest, index, and descriptor types with JSON round-trip support
//! - auth engine: /v2/ probe, challenge parsing, token exchange, credential providers
//! - single-arch public manifest resolution on top of the internal Phase 3 GET path
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
//! Not yet implemented:
//! - multi-arch public resolution and child-manifest selection
//! - final public API semantic cleanup across every Phase 3-supported path

const std = @import("std");
const resolver = @import("resolver.zig");

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

/// Placeholder error returned by stub APIs until the network transport layer lands in Phase 3.
pub const ImplementationError = error{NotYetImplemented};
pub const PublicApiError = error{ OutOfMemory, NotYetImplemented };

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

const ResolvedManifestSuccess = struct {
    resolved_digest: Digest,
    resolved_digest_raw: []u8,
    document: resolver.ParsedManifestDocument,
    platform: ?Platform,

    fn deinit(self: *ResolvedManifestSuccess, allocator: std.mem.Allocator) void {
        allocator.free(self.resolved_digest_raw);
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
/// - The caller owns `allocator` and decides whether it is an arena, GPA, or something else.
/// - In the intended Phase 2 flow, all borrowed slices in the returned ResolveResult live for
///   as long as `allocator` keeps that memory alive.
/// - For single-shot calls, an arena allocator is the intended pattern: use the result, copy what
///   you need, then tear the arena down.
/// - For batch operations that keep results longer, clone the ResolveResult into caller-owned
///   memory before freeing the per-call arena.
///
/// Phase 3 auth handoff contract:
/// - derive `AuthReferenceView` from the normalized `Reference` with `referenceView(ref)`
/// - probe `view.probeUriAlloc(...)` first; only enter auth when `ProbeHttpResponse.classify()`
///   returns `.auth_required`
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
    );
}

/// Validate that a manifest reference still exists and is fetchable.
///
/// Ownership contract:
/// - No owned data is returned from this API.
/// - The caller still owns `allocator`; later implementations may use it for transient parsing and
///   response handling even though this stub returns immediately.
///
/// Phase 3 auth handoff contract:
/// - validation follows the same probe -> classify -> authenticate -> retry-once flow as `resolve`
/// - validation must treat `.not_found` as terminal and must not attempt auth in that case
pub fn validate(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
) PublicApiError!ValidateOutcome {
    return validateWithExchangers(
        allocator,
        client,
        config,
        ref,
        auth.liveTokenHttpExchanger,
        resolver.liveManifestHttpExchanger,
    );
}

/// Fetch and parse a manifest payload.
///
/// Ownership contract:
/// - The returned std.json.Parsed(Manifest) owns an arena.
/// - Call parsed.deinit() when finished.
/// - Do not free the allocator backing that arena while the parsed value is still in use.
///
/// Phase 3 auth handoff contract:
/// - manifest GET uses the same `AuthReferenceView` and `AuthenticateRequest` boundary as `resolve`
/// - auth owns token exchange and cache invalidation; manifest fetch owns Accept negotiation,
///   response status handling, and JSON parsing
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
    );
}

fn resolveWithExchangers(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
    platform: ?Platform,
    token_exchanger: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
) PublicApiError!ResolveOutcome {
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(allocator, config, token_exchanger);
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

            return .{ .success = try buildResolveResultAlloc(
                allocator,
                ref,
                success.resolved_digest_raw,
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
    token_exchanger: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
) PublicApiError!ValidateOutcome {
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(allocator, config, token_exchanger);
    defer engine.deinit();

    var outcome = try fetchResolvedManifestWithExchangers(
        allocator,
        client,
        config,
        &engine,
        referenceView(ref),
        null,
        token_exchanger,
        manifest_exchanger,
        .validate,
        0,
    );
    switch (outcome) {
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

fn getManifestWithExchangers(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    ref: Reference,
    platform: ?Platform,
    token_exchanger: auth.TokenHttpExchanger,
    manifest_exchanger: resolver.ManifestHttpExchanger,
) PublicApiError!ManifestOutcome {
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(allocator, config, token_exchanger);
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
) PublicApiError!ResolvedManifestOutcome {
    if (depth > max_child_manifest_depth) {
        return .{ .failure = try depthLimitExceededErrorAlloc(allocator, ref_view) };
    }

    const ctx = resolver.ResolverContext.init(
        allocator,
        client,
        config,
        ref_view,
        platform,
        if (depth == 0) operation else .resolve_child_manifest,
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
            return .{ .failure = try transportFailureAlloc(allocator, ref_view, metadata.httpStatus()) };
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

    const requested_platform = platform orelse return error.NotYetImplemented;
    const child_descriptor = multi_arch.selectChildDescriptorByPlatform(requested_platform) orelse {
        return .{ .failure = try platformNotFoundErrorAlloc(allocator, ref_view) };
    };

    const selected_platform = if (child_descriptor.platform) |child_platform|
        try clonePlatformAlloc(allocator, child_platform)
    else
        null;
    errdefer if (selected_platform) |owned_platform| deinitOwnedPlatform(owned_platform, allocator);

    const child_ref_string = try std.fmt.allocPrint(
        allocator,
        "{s}:{s}",
        .{ @tagName(child_descriptor.digest.algorithm), child_descriptor.digest.hex },
    );
    defer allocator.free(child_ref_string);

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
    );

    switch (child_outcome) {
        .success => |*child_success| {
            if (child_success.platform == null) {
                child_success.platform = selected_platform;
            } else if (selected_platform) |owned_platform| {
                deinitOwnedPlatform(owned_platform, allocator);
            }
        },
        .failure => {
            if (selected_platform) |owned_platform| deinitOwnedPlatform(owned_platform, allocator);
        },
    }

    return child_outcome;
}

fn manifestAcceptValues() []const []const u8 {
    return &.{
        MediaType.oci_manifest_v1.toString(),
        MediaType.docker_manifest_v2.toString(),
        MediaType.oci_index_v1.toString(),
        MediaType.docker_manifest_list_v2.toString(),
    };
}

fn buildResolveResultAlloc(
    allocator: std.mem.Allocator,
    ref: Reference,
    resolved_digest_raw: []const u8,
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
    resolved_digest_raw: []const u8,
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

    const digest_raw = try allocator.dupe(u8, resolved_digest_raw);
    errdefer allocator.free(digest_raw);

    const digest = Digest.parse(digest_raw) catch unreachable;
    return .{
        .registry = registry,
        .repository = repository,
        .tag = tag,
        .digest = digest,
        .digest_raw = digest_raw,
    };
}

fn notFoundErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    const reference = try resolver.canonicalReferenceAlloc(allocator, ref);
    return .{ .not_found = .{
        .registry = ref.registry,
        .reference = reference,
    } };
}

fn transportFailureAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView, http_status: ?u16) !ResolveError {
    const reference = try resolver.canonicalReferenceAlloc(allocator, ref);
    return resolver.transportFailure(ref.registry, reference, http_status);
}

fn platformNotFoundErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    const reference = try resolver.canonicalReferenceAlloc(allocator, ref);
    return .{ .platform_not_found = .{
        .registry = ref.registry,
        .reference = reference,
    } };
}

fn depthLimitExceededErrorAlloc(allocator: std.mem.Allocator, ref: AuthReferenceView) !ResolveError {
    const reference = try resolver.canonicalReferenceAlloc(allocator, ref);
    return .{ .depth_limit_exceeded = .{
        .registry = ref.registry,
        .reference = reference,
    } };
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
    switch (failure) {
        inline else => |value| allocator.free(value.reference),
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
        State.tokenExchange,
        State.manifestExchange,
    );

    try std.testing.expectEqual(ValidateOutcome.not_found, outcome);
}

test "resolveWithExchangers keeps multi-arch responses out of scope" {
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

    try std.testing.expectError(
        error.NotYetImplemented,
        resolveWithExchangers(
            std.testing.allocator,
            &client,
            Config{},
            ref,
            null,
            State.tokenExchange,
            State.manifestExchange,
        ),
    );
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
