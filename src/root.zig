//! z-oci: Pure Zig OCI/Docker Registry API v2 client.
//!
//! Read-only. Resolves container image references to pinned SHA256 digests.
//! Built on Zig 0.16 std. Zero external dependencies.
//!
//! ## v0.0.1: Leaf Types
//!
//!   Digest       - algorithm + hex string, parse/validate
//!   MediaType    - OCI/Docker MIME types, detection helpers
//!   Platform     - os/arch/variant, partial match for multi-arch resolution
//!
//! ## v0.0.2: Reference Parser + OCI Types
//!
//!   Reference    - image reference parser (full Docker/OCI grammar)
//!   Descriptor   - OCI content descriptor
//!   Manifest     - OCI Image Manifest + Docker V2 Schema 2
//!   Index        - OciImageIndex + DockerManifestList + MultiArchManifest
//!
//! ## v0.0.3: JSON Infrastructure + API Contracts
//!
//!   json         - parse(T, alloc, bytes) wrapper; std.json.Parsed(T) lifecycle
//!   ResolveError - tagged error union with context fields
//!   ResolveResult - resolve result struct; clone() + deinit()
//!   Config       - config skeleton with CredentialProvider interface
//!
//! ## v0.0.4: Public API Stubs + Ownership Contract
//!
//!   resolve      - declare the public resolve surface before HTTP lands
//!   validate     - declare the manifest existence check surface
//!   getManifest  - declare the parsed manifest retrieval surface

const std = @import("std");

// v0.0.1: leaf types
pub const Digest = @import("Digest.zig");
pub const MediaType = @import("MediaType.zig").MediaType;
pub const Platform = @import("Platform.zig");

// v0.0.2: OCI types
pub const Descriptor = @import("Descriptor.zig");
pub const Manifest = @import("Manifest.zig");
pub const Index = @import("Index.zig");
pub const OciImageIndex = Index.OciImageIndex;
pub const DockerManifestList = Index.DockerManifestList;
pub const MultiArchManifest = Index.MultiArchManifest;
pub const Reference = @import("Reference.zig");

// v0.0.3: JSON infrastructure + API contracts
pub const json = @import("json.zig");
pub const ResolveError = @import("ResolveError.zig").ResolveError;
pub const ResolveResult = @import("ResolveResult.zig");
pub const Config = @import("Config.zig").Config;
pub const CredentialProvider = @import("Config.zig").CredentialProvider;
pub const Credential = @import("Config.zig").Credential;

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
    _ = @import("json.zig");
    _ = @import("ResolveError.zig");
    _ = @import("ResolveResult.zig");
    _ = @import("Config.zig");
}

test "v0.0.4 stubs: public APIs return NotYetImplemented" {
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
