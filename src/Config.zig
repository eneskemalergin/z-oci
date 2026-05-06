//! Resolver configuration skeleton.
//!
//! Config holds all settings the resolver needs: credentials, timeouts, and
//! TLS options. All fields have defaults. A bare Config{} works for anonymous
//! access to public registries.
//!
//! CredentialProvider and Credential are defined here because they describe
//! the interface slot, not the implementation. Phase 2 provides concrete
//! implementations (EnvProvider, DockerConfigProvider, etc.).
//!
//! Config fields are copied by value. Slices (ca_bundle_path,
//! Credential.secret) borrow from the caller. The caller is responsible for
//! keeping those strings alive for the duration of any resolve call.

const std = @import("std");

/// A username/secret pair for HTTP Basic authentication.
pub const Credential = struct {
    username: []const u8,
    secret: []const u8,
};

/// Interface for supplying credentials per registry.
/// Callers implement getCredentialFn and plug it in via Config.
///
/// Example:
///   const provider = CredentialProvider{ .getCredentialFn = myGetCred };
///   const config = Config{ .credential_provider = &provider };
pub const CredentialProvider = struct {
    /// Returns credentials for the given registry hostname, or null for
    /// anonymous access. The returned Credential slices must remain valid
    /// for the duration of the resolve call.
    getCredentialFn: *const fn (registry: []const u8) ?Credential,

    /// Convenience wrapper so callers do not need to reach into the function pointer.
    pub fn getCredential(self: CredentialProvider, registry: []const u8) ?Credential {
        return self.getCredentialFn(registry);
    }
};

/// Resolver configuration. All fields are optional with safe defaults.
/// A bare Config{} compiles and works for anonymous public registry access.
pub const Config = struct {
    /// Credential provider for authenticated registries. Null means anonymous.
    credential_provider: ?*const CredentialProvider = null,

    /// TCP connection timeout in milliseconds. Applied per connection attempt.
    connect_timeout_ms: u32 = 10_000,

    /// Read timeout in milliseconds. Applied per HTTP response read.
    read_timeout_ms: u32 = 30_000,

    /// Maximum number of retries on transient errors (network, 5xx).
    max_retries: u8 = 1,

    /// Path to a CA bundle file for TLS verification. Null uses the system bundle.
    ca_bundle_path: ?[]const u8 = null,

    /// When true, the resolver tracks and honors Retry-After headers from the registry.
    rate_limit_enabled: bool = true,
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "Config: bare Config{} compiles with all defaults" {
    // A caller using Config{} for anonymous access must not need to set anything.
    const c = Config{};
    try std.testing.expect(c.credential_provider == null);
    try std.testing.expectEqual(@as(u32, 10_000), c.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 30_000), c.read_timeout_ms);
    try std.testing.expectEqual(@as(u8, 1), c.max_retries);
    try std.testing.expect(c.ca_bundle_path == null);
    try std.testing.expect(c.rate_limit_enabled);
}

test "Config: credential_provider slot accepts a provider" {
    // Arrange: a no-op provider that returns null for all registries.
    const provider = CredentialProvider{
        .getCredentialFn = struct {
            fn get(_: []const u8) ?Credential {
                return null;
            }
        }.get,
    };
    // Act
    const c = Config{ .credential_provider = &provider };
    // Assert: the provider is stored and callable.
    try std.testing.expect(c.credential_provider != null);
    try std.testing.expect(c.credential_provider.?.getCredential("example.com") == null);
}

test "Config: credential_provider returns credentials for a registry" {
    // Arrange
    const provider = CredentialProvider{
        .getCredentialFn = struct {
            fn get(registry: []const u8) ?Credential {
                if (std.mem.eql(u8, registry, "ghcr.io")) {
                    return Credential{ .username = "user", .secret = "token" };
                }
                return null;
            }
        }.get,
    };
    const c = Config{ .credential_provider = &provider };
    // Act
    const cred = c.credential_provider.?.getCredential("ghcr.io");
    // Assert
    try std.testing.expect(cred != null);
    try std.testing.expectEqualSlices(u8, "user", cred.?.username);
    try std.testing.expectEqualSlices(u8, "token", cred.?.secret);
}

test "Config: timeout fields accept custom values" {
    const c = Config{ .connect_timeout_ms = 5_000, .read_timeout_ms = 60_000 };
    try std.testing.expectEqual(@as(u32, 5_000), c.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 60_000), c.read_timeout_ms);
}

test "Config: rate_limit_enabled can be disabled" {
    const c = Config{ .rate_limit_enabled = false };
    try std.testing.expect(!c.rate_limit_enabled);
}

test "Config: ca_bundle_path stores and returns path" {
    const c = Config{ .ca_bundle_path = "/etc/ssl/certs/ca-certificates.crt" };
    try std.testing.expectEqualSlices(u8, "/etc/ssl/certs/ca-certificates.crt", c.ca_bundle_path.?);
}

test "Config: max_retries zero disables retries" {
    // A caller that wants no retries must be able to set max_retries to 0.
    const c = Config{ .max_retries = 0 };
    try std.testing.expectEqual(@as(u8, 0), c.max_retries);
}
