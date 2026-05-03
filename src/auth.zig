//! Auth engine: OCI Bearer token flow (Distribution Spec).
//!
//! ## Flow
//!
//!   Probe /v2/             → initial challenge
//!   Parse WWW-Authenticate → extract realm, service, scope (Bearer only)
//!   Request token          → GET {realm}?service={s}&scope={s} (Basic auth if creds)
//!                            POST fallback for Azure ACR (application/x-www-form-urlencoded)
//!   Cache token            → per-scope, TTL from expires_in, keyed by hostname
//!
//! ## CredentialProvider Interface
//!
//!   Pluggable credential sources:
//!     - ~/.docker/config.json (credStore / credHelpers)
//!     - Env vars (ZENCELOT_REGISTRY_USER / ZENCELOT_REGISTRY_TOKEN)
//!     - Explicit config struct
//!     - ProcessCredentialProvider: shells out to docker-credential-* helpers
//!       (std.process.Child) for AWS ECR, GCP GCR, Azure ACR.
//!     - Anonymous: for public registries.
//!
//! ## Registries Handled
//!
//!   Docker Hub (registry-1.docker.io / index.docker.io aliases), GHCR, quay.io,
//!   GCR, ECR, ACR. Registry-agnostic parses WWW-Authenticate dynamically.
