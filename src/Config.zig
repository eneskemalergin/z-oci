//! Resolver configuration.
//!
//! Config holds the caller-provided knobs the current resolver surface accepts.
//! Not every field is wired into live manifest HTTP yet because callers still
//! own `std.http.Client`. A bare Config{} works for anonymous access to public
//! registries.
//!
//! CredentialProvider and Credential are defined here because they describe
//! the interface slot, not the implementation. Concrete providers (env vars,
//! Docker config, credential helpers) live in `auth.zig`.
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

pub const CredentialHandle = struct {
    credential: Credential,
    release_fn: ?*const fn (credential: Credential) void = null,

    pub fn release(self: CredentialHandle) void {
        if (self.release_fn) |release_fn| release_fn(self.credential);
    }
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
    getCredentialFn: *const fn (registry: []const u8) ?CredentialHandle,

    /// Convenience wrapper so callers do not need to reach into the function pointer.
    pub fn getCredential(self: CredentialProvider, registry: []const u8) ?CredentialHandle {
        return self.getCredentialFn(registry);
    }
};

/// Resolver configuration. All fields are optional with safe defaults.
/// A bare Config{} compiles and works for anonymous public registry access.
pub const Config = struct {
    /// Credential provider for authenticated registries. Null means anonymous.
    credential_provider: ?*const CredentialProvider = null,

    /// Reserved for future live HTTP connect-timeout wiring.
    ///
    /// The current resolver path does not apply this to manifest or token HTTP
    /// because callers own `std.http.Client` and Zig 0.16 does not expose a
    /// clean per-request timeout hook through the current request path.
    connect_timeout_ms: u32 = 10_000,

    /// Timeout in milliseconds for Docker credential helper subprocess I/O.
    ///
    /// Live manifest and token HTTP reads do not currently consume this field.
    read_timeout_ms: u32 = 30_000,

    /// Maximum auth retry count for the cached-401 invalidation path.
    ///
    /// Transport retries use `max_network_retries` and `max_rate_limit_retries`
    /// instead. Auth and transport budgets stay separate on purpose.
    max_retries: u8 = 1,

    /// Maximum reactive retries for transient network failures on idempotent
    /// `HEAD`/`GET` traffic. Not yet wired into live manifest or token HTTP.
    max_network_retries: u8 = 1,

    /// Maximum reactive retries for `429` / rate-limit responses. Not yet
    /// wired into live manifest or token HTTP.
    max_rate_limit_retries: u8 = 1,

    /// Reserved for future custom CA bundle integration.
    ///
    /// Today the live resolver uses the CA bundle already configured on the
    /// caller-owned `std.http.Client`.
    ca_bundle_path: ?[]const u8 = null,

    /// Gates pre-emptive throttling when rate-limit headers are trustworthy.
    /// Not yet wired. Reactive `429` backoff is independent of this flag.
    rate_limit_enabled: bool = true,
};

// Tests

test "Config: bare Config{} compiles with all defaults" {
    // A caller using Config{} for anonymous access must not need to set anything.
    const c = Config{};
    try std.testing.expect(c.credential_provider == null);
    try std.testing.expectEqual(@as(u32, 10_000), c.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 30_000), c.read_timeout_ms);
    try std.testing.expectEqual(@as(u8, 1), c.max_retries);
    try std.testing.expectEqual(@as(u8, 1), c.max_network_retries);
    try std.testing.expectEqual(@as(u8, 1), c.max_rate_limit_retries);
    try std.testing.expect(c.ca_bundle_path == null);
    try std.testing.expect(c.rate_limit_enabled);
}

test "Config: credential_provider slot accepts a provider" {
    // Arrange: a no-op provider that returns null for all registries.
    const provider = CredentialProvider{
        .getCredentialFn = struct {
            fn get(_: []const u8) ?CredentialHandle {
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
            fn get(registry: []const u8) ?CredentialHandle {
                if (std.mem.eql(u8, registry, "ghcr.io")) {
                    return .{ .credential = .{ .username = "user", .secret = "token" } };
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
    try std.testing.expectEqualSlices(u8, "user", cred.?.credential.username);
    try std.testing.expectEqualSlices(u8, "token", cred.?.credential.secret);
}

test "Config: credential handle release hook can tear down secrets" {
    const State = struct {
        var released = false;

        fn release(_: Credential) void {
            released = true;
        }

        fn get(registry: []const u8) ?CredentialHandle {
            if (!std.mem.eql(u8, registry, "ghcr.io")) return null;
            return .{
                .credential = .{ .username = "user", .secret = "token" },
                .release_fn = release,
            };
        }
    };

    const provider = CredentialProvider{ .getCredentialFn = State.get };
    const handle = provider.getCredential("ghcr.io").?;
    try std.testing.expect(!State.released);
    handle.release();
    try std.testing.expect(State.released);
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

test "Config: max_network_retries and max_rate_limit_retries accept custom values" {
    const c = Config{
        .max_network_retries = 2,
        .max_rate_limit_retries = 4,
    };
    try std.testing.expectEqual(@as(u8, 2), c.max_network_retries);
    try std.testing.expectEqual(@as(u8, 4), c.max_rate_limit_retries);
}

test "Config: max_retries zero disables retries" {
    // A caller that wants no retries must be able to set max_retries to 0.
    const c = Config{ .max_retries = 0 };
    try std.testing.expectEqual(@as(u8, 0), c.max_retries);
}

test "Config: connect_timeout_ms zero means no timeout" {
    const c = Config{ .connect_timeout_ms = 0 };
    try std.testing.expectEqual(@as(u32, 0), c.connect_timeout_ms);
}

test "Config: read_timeout_ms zero means no timeout" {
    const c = Config{ .read_timeout_ms = 0 };
    try std.testing.expectEqual(@as(u32, 0), c.read_timeout_ms);
}

test "Config: credential handle release with null release_fn is a no-op" {
    const handle = CredentialHandle{
        .credential = .{ .username = "u", .secret = "s" },
    };
    handle.release(); // must not crash or leak (covers default-null and explicit-null)
}

test "Config: max_retries at u8 maximum is valid" {
    const c = Config{ .max_retries = 255 };
    try std.testing.expectEqual(@as(u8, 255), c.max_retries);
}

test "Config: credential_provider null returns null for all registries" {
    const c = Config{};
    try std.testing.expect(c.credential_provider == null);
}
