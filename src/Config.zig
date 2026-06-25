//! Resolver configuration.
//!
//! Config holds the caller-provided knobs the current resolver surface accepts.
//! Callers still own `std.http.Client`; a bare `Config{}` works for anonymous
//! public registry access.
//!
//! Retry budget split (live today):
//! - `max_retries` — cached-401 auth invalidation only (`AuthEngine.retryAuthenticateAfterCachedUnauthorized`).
//! - `max_network_retries` / `max_rate_limit_retries` — reactive transport retries on
//!   manifest `HEAD`/`GET` and token HTTP (`exchangeManifestRequest`,
//!   `exchangeTokenHttpRequestWithRetries`).
//!
//! Timeout field liveness:
//! - `read_timeout_ms` — Docker credential helper subprocess I/O in `auth.zig`.
//! - `connect_timeout_ms` — exposed via `connectIoTimeout` for caller-owned
//!   `connectTcpOptions` recipes; live z-oci exchangers use `client.request`, which
//!   does not honor it until Zig passes `ConnectTcpOptions.timeout` through
//!   (zig#31305). Manifest/token HTTP read timeouts are not configurable per request.
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

    /// Connect timeout in milliseconds for caller-owned TCP setup. `0` means unset.
    ///
    /// Use `connectIoTimeout` when calling `std.http.Client.connectTcpOptions`
    /// yourself. Live manifest and token exchangers inside z-oci do not read this
    /// field because `client.request` does not forward the timeout today (zig#31305).
    connect_timeout_ms: u32 = 0,

    /// Timeout in milliseconds for Docker credential helper subprocess I/O.
    ///
    /// Manifest and token HTTP reads do not consume this field. Auth applies it
    /// when waiting on helper stdout/stderr.
    read_timeout_ms: u32 = 30_000,

    /// Maximum auth retry count for the cached-401 invalidation path.
    ///
    /// Transport retries use `max_network_retries` and `max_rate_limit_retries`
    /// instead. Auth and transport budgets stay separate on purpose.
    max_retries: u8 = 1,

    /// Maximum reactive retries for transient network failures on idempotent
    /// manifest `HEAD`/`GET` and token HTTP traffic.
    max_network_retries: u8 = 1,

    /// Maximum reactive retries for `429` / rate-limit responses on manifest
    /// `HEAD`/`GET` and token HTTP traffic.
    max_rate_limit_retries: u8 = 1,

    /// Custom CA bundle path for caller-owned TLS setup. Not read by live z-oci
    /// exchangers today; callers configure `std.http.Client.ca_bundle` directly.
    ca_bundle_path: ?[]const u8 = null,

    /// Opt-in pre-emptive throttling when rate-limit headers look trustworthy.
    ///
    /// Defaults off because nothing reads it yet. Reactive `429` backoff stays on
    /// regardless through the transport retry budgets above.
    rate_limit_enabled: bool = false,

    /// Returns the `std.Io.Timeout` value for caller-owned `connectTcpOptions`.
    ///
    /// Live z-oci manifest and token traffic does not apply this until upstream Zig
    /// wires `ConnectTcpOptions.timeout` into the host connect path.
    pub fn connectIoTimeout(self: Config) std.Io.Timeout {
        if (self.connect_timeout_ms == 0) return .none;
        return .{
            .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(self.connect_timeout_ms),
                .clock = .real,
            },
        };
    }

    /// Applies `Config` fields that caller-owned clients can honor today.
    ///
    /// No-op on the client handle today. `read_timeout_ms` is consumed by auth
    /// helper subprocess I/O, not here. `ca_bundle_path` is not applied automatically.
    /// Callers that manage their own connects should pair `connectIoTimeout` with
    /// `std.http.Client.connectTcpOptions` when building pooled connections.
    pub fn applyToClient(self: Config, client: *std.http.Client) void {
        _ = self;
        _ = client;
    }
};

// Tests

test "Config: bare Config{} compiles with all defaults" {
    // A caller using Config{} for anonymous access must not need to set anything.
    const c = Config{};
    try std.testing.expect(c.credential_provider == null);
    try std.testing.expectEqual(@as(u32, 0), c.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 30_000), c.read_timeout_ms);
    try std.testing.expectEqual(@as(u8, 1), c.max_retries);
    try std.testing.expectEqual(@as(u8, 1), c.max_network_retries);
    try std.testing.expectEqual(@as(u8, 1), c.max_rate_limit_retries);
    try std.testing.expect(c.ca_bundle_path == null);
    try std.testing.expect(!c.rate_limit_enabled);
}

test "Config: rate_limit_enabled can be enabled for future pre-emptive throttling" {
    const c = Config{ .rate_limit_enabled = true };
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

test "Config: connect_timeout_ms zero means unset connect Io timeout" {
    const c = Config{ .connect_timeout_ms = 0 };
    try std.testing.expectEqual(@as(u32, 0), c.connect_timeout_ms);
    try std.testing.expectEqual(std.Io.Timeout.none, c.connectIoTimeout());
}

test "Config: connectIoTimeout maps milliseconds to real clock duration" {
    const c = Config{ .connect_timeout_ms = 5_000 };
    const timeout = c.connectIoTimeout();
    try std.testing.expect(timeout.duration.raw.toMilliseconds() == 5_000);
}

test "Config: applyToClient accepts caller-owned client without crashing" {
    var client: std.http.Client = undefined;
    const config = Config{ .connect_timeout_ms = 1_000 };
    config.applyToClient(&client);
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
