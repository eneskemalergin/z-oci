//! z-oci: Pure Zig OCI/Docker Registry API v2 client.
//!
//! Read-only. Resolves container image references to pinned SHA256 digests.
//! Built on Zig 0.16 std. Zero external dependencies.
//!
//! ## Phase 1: Types and API Surface (v0.0.1 to v0.0.4)
//!
//!   Digest       - algorithm + hex string, parse/validate
//!   MediaType    - OCI/Docker MIME types, detection helpers
//!   Platform     - os/arch/variant, partial match for multi-arch resolution
//!
//! ## Coming in later milestones
//!
//!   Reference     - image reference parser             (v0.0.2)
//!   Descriptor    - OCI content descriptor             (v0.0.2)
//!   Manifest      - OCI Image Manifest + Docker V2     (v0.0.2)
//!   Index         - OciImageIndex + DockerManifestList (v0.0.2)
//!   ResolveError  - tagged error union                 (v0.0.3)
//!   ResolveResult - result struct                      (v0.0.3)
//!   Config        - config skeleton                    (v0.0.3)
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
// TODO(v0.0.3): ResolveError, ResolveResult, Config
// TODO(v0.0.4): resolve, validate, getManifest
