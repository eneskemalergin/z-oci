//! Platform resolver: multi-arch manifest filtering.
//!
//! ## Filtering Rules
//!
//!   Exact match on os + architecture.
//!   If caller specifies variant, it must match.
//!   If caller omits variant, accept any (e.g. arm64 matches arm64/v8).
//!   os.version prefix matching for Windows (major.minor).
//!
//! ## Recursion
//!
//!   Nested indexes up to configurable depth (default 3).
//!   Returns PlatformNotFound if no manifest matches the requested platform.
//!   Returns ManifestParseError if nesting depth exceeded.
//!
//! ## Types Handled
//!
//!   OciImageIndex       (application/vnd.oci.image.index.v1+json)
//!   DockerManifestList  (application/vnd.docker.distribution.manifest.list.v2+json)
//!   Distinct types, shared MultiArchManifest interface for resolution logic.
