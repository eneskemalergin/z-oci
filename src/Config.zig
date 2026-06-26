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
//! TLS trust (`ca_bundle_path`):
//! - When unset, the caller-owned `std.http.Client` loads OS trust roots on the first
//!   HTTPS request (Linux: `/etc/ssl/certs/...` and distro-specific paths; macOS:
//!   Keychain via Zig `Certificate.Bundle.rescan`; BSD variants: `/etc/ssl/cert.pem`).
//! - When set, `applyToClient` replaces `client.ca_bundle` with PEM certs from that
//!   file only. It does not merge with the OS store. Enterprise deployments should
//!   concatenate corporate CAs with their distro bundle in the PEM file when both
//!   are required.
//! - Custom CA support does not make Windows a supported host. Zig 0.16 TLS on
//!   Windows remains out of scope for z-oci regardless of bundle configuration.
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
    /// Errors from `applyToClient` when `ca_bundle_path` is set.
    pub const ApplyError = error{
        OutOfMemory,
        CaBundleFileNotFound,
        CaBundleInvalid,
        CaBundleEmpty,
        CaBundleTlsDisabled,
    };

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

    /// Custom CA bundle PEM path for caller-owned TLS trust.
    ///
    /// When non-null, `applyToClient` loads this file into `std.http.Client.ca_bundle`
    /// before HTTPS traffic. The path may be absolute or relative to the process cwd.
    /// The file must contain one or more `BEGIN CERTIFICATE` blocks. When null, the
    /// client keeps Zig's lazy OS trust scan on first HTTPS.
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

    /// Applies caller-owned client configuration that z-oci can honor today.
    ///
    /// When `ca_bundle_path` is set, loads that PEM file into `client.ca_bundle` and
    /// pins `client.now` so Zig does not replace the bundle with an OS rescan on the
    /// next HTTPS request. When `ca_bundle_path` is null, this is a no-op.
    ///
    /// `read_timeout_ms` is consumed by auth helper subprocess I/O, not here.
    /// `connect_timeout_ms` is exposed via `connectIoTimeout` for caller-owned TCP
    /// setup; live manifest/token exchangers do not read it (zig#31305).
    pub fn applyToClient(self: Config, client: *std.http.Client) ApplyError!void {
        const ca_path = self.ca_bundle_path orelse return;
        if (comptime std.http.Client.disable_tls) return error.CaBundleTlsDisabled;

        const gpa = client.allocator;
        const io = client.io;

        var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
        const resolved_path: []const u8 = if (std.fs.path.isAbsolute(ca_path)) ca_path else resolved: {
            const len = std.Io.Dir.cwd().realPathFile(io, ca_path, &abs_buf) catch |err| switch (err) {
                error.FileNotFound => return error.CaBundleFileNotFound,
                else => return error.CaBundleInvalid,
            };
            break :resolved abs_buf[0..len];
        };

        var loaded: std.crypto.Certificate.Bundle = .empty;
        errdefer loaded.deinit(gpa);

        const now = std.Io.Clock.real.now(io);
        loaded.addCertsFromFilePathAbsolute(gpa, io, now, resolved_path) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.FileNotFound => return error.CaBundleFileNotFound,
            else => return error.CaBundleInvalid,
        };

        if (loaded.bytes.items.len == 0) return error.CaBundleEmpty;

        client.ca_bundle_lock.lockUncancelable(io);
        defer client.ca_bundle_lock.unlock(io);

        client.ca_bundle.deinit(gpa);
        client.ca_bundle = .empty;
        client.now = now;
        std.mem.swap(std.crypto.Certificate.Bundle, &client.ca_bundle, &loaded);
    }
};

// Tests

fn fixtureAbsPath(allocator: std.mem.Allocator, rel_path: []const u8) ![:0]u8 {
    return try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, rel_path, allocator);
}

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

test "Config: applyToClient is no-op when ca_bundle_path is null" {
    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const config = Config{};
    try config.applyToClient(&client);
}

test "Config: applyToClient loads fixture PEM into client ca_bundle" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const rel_path = "fixtures/tls/enterprise-test-ca.pem";
    const abs_path = try fixtureAbsPath(std.testing.allocator, rel_path);
    defer std.testing.allocator.free(abs_path);

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const config = Config{ .ca_bundle_path = abs_path };
    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    defer client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expect(client.ca_bundle.bytes.items.len > 0);
    try std.testing.expect(client.now != null);
}

test "Config: applyToClient accepts relative ca_bundle_path" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const config = Config{ .ca_bundle_path = "fixtures/tls/enterprise-test-ca.pem" };
    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    defer client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expect(client.ca_bundle.bytes.items.len > 0);
}

test "Config: applyToClient returns file not found for missing bundle path" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const config = Config{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" };
    try std.testing.expectError(error.CaBundleFileNotFound, config.applyToClient(&client));
}

test "Config: applyToClient rejects invalid PEM bundle" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const rel_path = "fixtures/tls/invalid-ca-bundle.pem";
    const abs_path = try fixtureAbsPath(std.testing.allocator, rel_path);
    defer std.testing.allocator.free(abs_path);

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const config = Config{ .ca_bundle_path = abs_path };
    try std.testing.expectError(error.CaBundleInvalid, config.applyToClient(&client));
}

test "Config: applyToClient rejects empty PEM bundle" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const rel_path = "empty-ca.pem";
    {
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
    }

    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_len = try tmp.dir.realPathFile(std.testing.io, rel_path, &abs_buf);
    const abs_path = abs_buf[0..abs_len];

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const config = Config{ .ca_bundle_path = abs_path };
    try std.testing.expectError(error.CaBundleEmpty, config.applyToClient(&client));
}

test "Config: applyToClient replaces prior bundle on second load" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const rel_path = "fixtures/tls/enterprise-test-ca.pem";
    const abs_path = try fixtureAbsPath(std.testing.allocator, rel_path);
    defer std.testing.allocator.free(abs_path);

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const config = Config{ .ca_bundle_path = abs_path };
    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    const first_len = client.ca_bundle.bytes.items.len;
    client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expect(first_len > 0);

    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    defer client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expectEqual(first_len, client.ca_bundle.bytes.items.len);
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
