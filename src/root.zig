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
//! ## Coming in later milestones
//!
//!   resolve / validate / getManifest stubs             (v0.0.4)

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
// TODO(v0.0.4): resolve, validate, getManifest

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
