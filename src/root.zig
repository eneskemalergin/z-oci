//! z-oci: Pure Zig OCI/Docker Registry API v2 client.
//!
//! Read-only client for resolving container image references to pinned SHA256 digests.
//! Built entirely on Zig 0.16 std: `std.http.Client`, `std.json`, `std.crypto.hash.sha2`.
//!
//! ## Module Map
//!
//!   types.zig     - OCI data types (Digest, Platform, MediaType, Descriptor, Manifest)
//!   digest.zig    - SHA256 hash validation
//!   auth.zig      - Bearer token flow, CredentialProvider interface
//!   client.zig    - Manifest fetch (HEAD/GET), digest extraction
//!   platform.zig  - Multi-arch resolution, platform filtering
//!   ratelimit.zig - Rate limit parsing, backoff logic
//!
//! ## Public API
//!
//!   resolve(allocator, client, config, ref, platform) → ResolveResult | ResolveError
//!   validate(allocator, client, config, ref)          → bool | ResolveError
//!   getManifest(allocator, client, config, ref, plat) → Parsed(Manifest) | ResolveError

const std = @import("std");

pub const types = @import("types.zig");
pub const auth = @import("auth.zig");
pub const client = @import("client.zig");
pub const platform = @import("platform.zig");
pub const ratelimit = @import("ratelimit.zig");
pub const digest = @import("digest.zig");
