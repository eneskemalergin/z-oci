//! Manifest client: registry communication for manifest fetch and digest resolution.
//!
//! ## Operations
//!
//!   resolve()     - given registry/repo:tag + platform → ResolveResult (SHA256 digest)
//!   validate()    - HEAD check: does a pinned digest still exist?
//!   getManifest() - full manifest metadata for inspection
//!   resolveMany() - batch resolve with shared TokenCache and session digest cache
//!
//! ## Protocol
//!
//!   HEAD /v2/{name}/manifests/{ref}  - fast path, Docker-Content-Digest header
//!   GET  /v2/{name}/manifests/{ref}  - verification path, SHA256 body vs header
//!
//!   Ordered Accept headers: OCI types first, Docker fallback.
//!   Content-Type case-insensitive normalization.
//!   Rejects legacy schema 1 (ContentTypeMismatch).
//!
//! ## Design
//!
//!   Caller-owned *std.http.Client - connection reuse across batch resolves.
//!   Caller-provided arena allocator - no hidden allocations.
//!   HEAD-first digest extraction - GET only for verification.
