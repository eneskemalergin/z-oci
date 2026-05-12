//! z-oci: Pure Zig OCI/Docker Registry API v2 toolkit.
//!
//! Current scope:
//! - offline OCI/Docker reference parsing and normalization
//! - OCI manifest, index, and descriptor types with JSON round-trip support
//! - auth engine: /v2/ probe, challenge parsing, token exchange, credential providers
//! - public resolver-surface stubs and ownership contracts ahead of Phase 3 HTTP work
//!
//! Not yet implemented:
//! - manifest fetch (HEAD/GET) and digest verification
//! - real `resolve`, `validate`, and `getManifest` behavior

const std = @import("std");

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
) ImplementationError!ResolveResult {
    _ = allocator;
    _ = client;
    _ = config;
    _ = ref;
    _ = platform;
    return error.NotYetImplemented;
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
) ImplementationError!bool {
    _ = allocator;
    _ = client;
    _ = config;
    _ = ref;
    return error.NotYetImplemented;
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
) ImplementationError!std.json.Parsed(Manifest) {
    _ = allocator;
    _ = client;
    _ = config;
    _ = ref;
    _ = platform;
    return error.NotYetImplemented;
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
    _ = @import("test_support.zig");
}

test "public API stubs return NotYetImplemented" {
    var client: std.http.Client = undefined;
    const ref = Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/alpine",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    try std.testing.expectError(error.NotYetImplemented, resolve(std.testing.allocator, &client, Config{}, ref, null));
    try std.testing.expectError(error.NotYetImplemented, validate(std.testing.allocator, &client, Config{}, ref));
    try std.testing.expectError(error.NotYetImplemented, getManifest(std.testing.allocator, &client, Config{}, ref, null));
}
