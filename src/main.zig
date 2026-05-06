//! z-oci CLI: thin wrapper around the library for standalone use and CI/CD scripts.
//!
//! ## Commands (Phase 6)
//!
//!   z-oci resolve <image>           - resolve tag → pinned sha256: digest
//!   z-oci validate <image>@sha256:  - check if pinned digest still exists
//!   z-oci inspect <image>           - print manifest metadata
//!
//! ## Flags
//!
//!   --platform <os/arch/variant>    - multi-arch resolution
//!   --format text|json|toml         - output format (default: text)
//!   --verbose                       - print auth flow, headers, timing
//!
//! ## Exit Codes
//!
//!   0  success
//!   1  not found
//!   2  auth failure
//!   3  rate limited
//!   4  network error
//!
//! Ownership model (Phase 6 target):
//! - command-line args and short-lived parsing buffers should live in a per-run arena
//! - any ResolveResult kept after that arena must be cloned into caller-owned memory
//! - any std.json.Parsed(...) returned by library helpers must be deinitialized before exit

// CLI is implemented in Phase 6. Stub keeps the build clean until then.
pub fn main() void {}
