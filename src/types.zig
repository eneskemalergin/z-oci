//! OCI data types: Digest, MediaType, Platform, Descriptor, Manifest.
//!
//! ## Types Defined
//!
//!   DigestAlgorithm    - enum { sha256 }
//!   Digest             - algorithm + raw bytes. Parse from / format to "sha256:hex".
//!   MediaType          - known media type constants (OCI + Docker) with detection helpers.
//!   Platform           - os, architecture, variant, os.version, os.features. Partial match.
//!   Descriptor         - OCI content descriptor (mediaType, digest, size, platform, annotations).
//!   Manifest           - OCI Image Manifest + Docker V2 Schema 2.
//!   OciImageIndex      - OCI Image Index (multi-arch).
//!   DockerManifestList - Docker Manifest List (multi-arch).
//!
//! ## Error Types
//!
//!   ResolveError       - tagged union covering all failure modes.
//!   ResolveResult      - digest, media_type, platform (null if single-arch).
//!
//! ## JSON
//!
//!   Custom jsonParse / jsonStringify for mixed camelCase/snake_case field names.
//!   Parsed(T) wrapper for arena-allocated parse results.
