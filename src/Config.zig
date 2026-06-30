//! Resolver configuration.
//!
//! Config holds the caller-provided knobs the current resolver surface accepts.
//! Callers still own `std.http.Client`; a bare `Config{}` works for anonymous
//! public registry access.
//!
//! Retry budget split (live today):
//! - `max_retries`: cached-401 auth invalidation only (`AuthEngine.retryAuthenticateAfterCachedUnauthorized`).
//! - `max_network_retries` / `max_rate_limit_retries`: reactive transport retries on
//!   manifest `HEAD`/`GET` and token HTTP (`exchangeManifestRequest`,
//!   `exchangeTokenHttpRequestWithRetries`).
//!
//! Timeout field liveness:
//! - `read_timeout_ms`: Docker credential helper subprocess I/O in `auth.zig`.
//! - `connect_timeout_ms`: exposed via `connectIoTimeout` for caller-owned
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
//! - Prefer an absolute `ca_bundle_path`. The file must be a public CA trust store
//!   (certificate PEM only). Private keys used for registry auth, client TLS, or
//!   credential helpers are unaffected; this check applies only to `ca_bundle_path`.
//!   On POSIX, that bundle file must not be world-writable (`other` write bit).
//!   Each public API entry reloads the file when this path is set.
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

/// Default maximum manifest or index GET body size for live HTTP transport.
pub const DEFAULT_MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
/// Default maximum token endpoint response body size for live HTTP transport.
pub const DEFAULT_MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;
/// Default maximum cached bearer tokens per `AuthEngine`. `0` means unbounded.
pub const DEFAULT_MAX_TOKEN_CACHE_ENTRIES: u32 = 128;

/// A username/secret pair for HTTP Basic authentication.
pub const Credential = struct {
    username: []const u8,
    secret: []const u8,
};

/// Credential returned by a provider, optionally with a custom release hook.
pub const CredentialHandle = struct {
    credential: Credential,
    /// When set, `release_allocator` must be the allocator that owns `credential` slices.
    /// `release_fn` must free through that allocator. Env/helper paths in `auth.zig`
    /// zero secrets via `freeOwnedOptionalSecretSlice` before `free`.
    release_fn: ?*const fn (allocator: std.mem.Allocator, credential: Credential) void = null,
    release_allocator: std.mem.Allocator = undefined,

    /// Invoke the provider release hook when one was supplied.
    pub fn release(self: CredentialHandle) void {
        if (self.release_fn) |release_fn| release_fn(self.release_allocator, self.credential);
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
        CaBundleInsecurePermissions,
        CaBundleContainsPrivateKey,
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
    /// before HTTPS traffic. Prefer an absolute path. The file must contain public CA
    /// certificates only; private keys belong in auth/TLS identity paths,
    /// not the trust store). On POSIX, the file must not be world-writable. When null,
    /// the client keeps Zig's lazy OS trust scan on first HTTPS.
    ca_bundle_path: ?[]const u8 = null,

    /// Opt-in pre-emptive throttling when prior manifest responses had trustworthy
    /// registry `RateLimit-*` headers with `remaining` at zero.
    ///
    /// Defaults off. Reactive `429` backoff stays on regardless through the
    /// transport retry budgets above.
    rate_limit_enabled: bool = false,

    /// Maximum manifest or index GET body size for live HTTP transport.
    max_manifest_bytes: usize = DEFAULT_MAX_MANIFEST_BYTES,

    /// Maximum token endpoint response body size for live HTTP transport.
    max_token_response_bytes: usize = DEFAULT_MAX_TOKEN_RESPONSE_BYTES,

    /// Maximum cached bearer tokens per `AuthEngine`. `0` means unbounded.
    max_token_cache_entries: u32 = DEFAULT_MAX_TOKEN_CACHE_ENTRIES,

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
    /// `resolve`, `validate`, and `getManifest` call this when `ca_bundle_path` is set.
    /// When the resolved path and file mtime match the last successful apply for the
    /// same client, the PEM is not re-read from disk.
    ///
    /// Only `ca_bundle_path` is applied here. `connect_timeout_ms` is exposed via
    /// `connectIoTimeout` for caller-owned TCP setup (zig#31305). `read_timeout_ms` is
    /// consumed by auth helper subprocess I/O, not here.
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

        var file = std.Io.Dir.openFileAbsolute(io, resolved_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.CaBundleFileNotFound,
            else => return error.CaBundleInvalid,
        };
        defer file.close(io);

        const stat = file.stat(io) catch return error.CaBundleInvalid;
        try validateCaBundleFileStat(stat);

        const mtime_nsec = stat.mtime.toNanoseconds();

        if (client.ca_bundle.bytes.items.len > 0 and
            caBundleApplyCacheMatches(client, resolved_path, mtime_nsec))
        {
            return;
        }

        var loaded: std.crypto.Certificate.Bundle = .empty;
        errdefer loaded.deinit(gpa);

        const now = std.Io.Clock.real.now(io);

        try loadCaBundleFromOpenFile(&loaded, gpa, io, &file, now);

        if (loaded.bytes.items.len == 0) return error.CaBundleEmpty;

        client.ca_bundle_lock.lockUncancelable(io);
        defer client.ca_bundle_lock.unlock(io);

        client.ca_bundle.deinit(gpa);
        client.ca_bundle = .empty;
        client.now = now;
        std.mem.swap(std.crypto.Certificate.Bundle, &client.ca_bundle, &loaded);

        caBundleApplyCacheRemember(client, resolved_path, mtime_nsec);
    }
};

// --- CA bundle helpers ---

const CaBundleApplyCache = struct {
    client: ?*std.http.Client = null,
    path: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize = 0,
    mtime_nsec: i128 = 0,
};

var ca_bundle_apply_cache: CaBundleApplyCache = .{};

fn caBundleApplyCacheMatches(client: *std.http.Client, path: []const u8, mtime_nsec: i128) bool {
    return ca_bundle_apply_cache.client == client and
        ca_bundle_apply_cache.mtime_nsec == mtime_nsec and
        ca_bundle_apply_cache.path_len == path.len and
        std.mem.eql(u8, ca_bundle_apply_cache.path[0..ca_bundle_apply_cache.path_len], path);
}

fn caBundleApplyCacheRemember(
    client: *std.http.Client,
    path: []const u8,
    mtime_nsec: i128,
) void {
    @memcpy(ca_bundle_apply_cache.path[0..path.len], path);
    ca_bundle_apply_cache.client = client;
    ca_bundle_apply_cache.path_len = path.len;
    ca_bundle_apply_cache.mtime_nsec = mtime_nsec;
}

const BASE64_DECODER = std.base64.standard.decoderWithIgnore(" \t\r\n");
const MAX_CA_BUNDLE_BYTES: u64 = 10 * 1024 * 1024;

// PEM blocks that belong in a key file, not in a CA trust bundle (`ca_bundle_path`).
const PRIVATE_KEY_PEM_MARKERS = [_][]const u8{
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
};

fn validateCaBundleFileStat(stat: std.Io.File.Stat) Config.ApplyError!void {
    if (stat.size > MAX_CA_BUNDLE_BYTES) return error.CaBundleInvalid;
    if (@hasDecl(std.Io.File.Permissions, "toMode")) {
        if (stat.permissions.toMode() & 0o002 != 0) return error.CaBundleInsecurePermissions;
    }
}

fn caBundlePemContainsPrivateKey(pem_bytes: []const u8) bool {
    if (!std.mem.containsAtLeast(u8, pem_bytes, 1, "BEGIN")) return false;
    inline for (PRIVATE_KEY_PEM_MARKERS) |marker| {
        if (std.mem.indexOf(u8, pem_bytes, marker) != null) return true;
    }
    return false;
}

const AddCertsFromPemBytesError = std.mem.Allocator.Error ||
    std.crypto.Certificate.Bundle.ParseCertError ||
    std.base64.Error ||
    error{MissingEndCertificateMarker};

// Parses `BEGIN CERTIFICATE` blocks from an in-memory PEM buffer.
// Vendored from `std.crypto.Certificate.Bundle.addCertsFromFile` so
// `loadCaBundleFromOpenFile` can read the file once and scan before parse.
fn addCertsFromPemBytes(
    cb: *std.crypto.Certificate.Bundle,
    gpa: std.mem.Allocator,
    encoded_bytes: []const u8,
    now_sec: i64,
) AddCertsFromPemBytesError!void {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    var start_index: usize = 0;
    while (std.mem.findPos(u8, encoded_bytes, start_index, begin_marker)) |begin_marker_start| {
        const cert_start = begin_marker_start + begin_marker.len;
        const cert_end = std.mem.findPos(u8, encoded_bytes, cert_start, end_marker) orelse
            return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;
        const encoded_cert = std.mem.trim(u8, encoded_bytes[cert_start..cert_end], " \t\r\n");
        const decoded_start: u32 = @intCast(cb.bytes.items.len);
        const decoded_upper = encoded_cert.len / 4 * 3 + 4;
        try cb.bytes.ensureUnusedCapacity(gpa, decoded_upper);
        const dest_buf = cb.bytes.allocatedSlice()[decoded_start..];
        cb.bytes.items.len += try BASE64_DECODER.decode(dest_buf, encoded_cert);
        try cb.parseCert(gpa, decoded_start, now_sec);
    }
}

fn loadCaBundleFromOpenFile(
    bundle: *std.crypto.Certificate.Bundle,
    gpa: std.mem.Allocator,
    io: std.Io,
    file: *std.Io.File,
    now: std.Io.Timestamp,
) Config.ApplyError!void {
    const stat = file.stat(io) catch return error.CaBundleInvalid;
    try validateCaBundleFileStat(stat);

    const read_len = std.math.cast(usize, stat.size) orelse return error.CaBundleInvalid;
    const pem_bytes = gpa.alloc(u8, read_len) catch return error.OutOfMemory;
    defer gpa.free(pem_bytes);

    var file_reader = file.reader(io, &.{});
    const n = file_reader.interface.readSliceShort(pem_bytes) catch return error.CaBundleInvalid;
    if (n != read_len) return error.CaBundleInvalid;

    if (caBundlePemContainsPrivateKey(pem_bytes)) return error.CaBundleContainsPrivateKey;
    addCertsFromPemBytes(bundle, gpa, pem_bytes, now.toSeconds()) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CaBundleInvalid,
    };
}

fn fixtureAbsPath(allocator: std.mem.Allocator, rel_path: []const u8) ![:0]u8 {
    return try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, rel_path, allocator);
}

// --- Tests ---

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

test "Config: field defaults and overrides are stored correctly" {
    const defaults = Config{};
    try std.testing.expect(!defaults.rate_limit_enabled);
    try std.testing.expectEqual(@as(u32, 0), defaults.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 30_000), defaults.read_timeout_ms);
    try std.testing.expectEqual(DEFAULT_MAX_MANIFEST_BYTES, defaults.max_manifest_bytes);
    try std.testing.expectEqual(DEFAULT_MAX_TOKEN_RESPONSE_BYTES, defaults.max_token_response_bytes);
    try std.testing.expectEqual(DEFAULT_MAX_TOKEN_CACHE_ENTRIES, defaults.max_token_cache_entries);
    try std.testing.expectEqual(std.Io.Timeout.none, defaults.connectIoTimeout());

    const cases = [_]struct {
        config: Config,
        rate_limit_enabled: ?bool = null,
        connect_timeout_ms: ?u32 = null,
        read_timeout_ms: ?u32 = null,
        max_network_retries: ?u8 = null,
        max_rate_limit_retries: ?u8 = null,
        max_retries: ?u8 = null,
        ca_bundle_path: ?[]const u8 = null,
    }{
        .{ .config = .{ .rate_limit_enabled = true }, .rate_limit_enabled = true },
        .{ .config = .{ .connect_timeout_ms = 5_000, .read_timeout_ms = 60_000 }, .connect_timeout_ms = 5_000, .read_timeout_ms = 60_000 },
        .{ .config = .{ .ca_bundle_path = "/etc/ssl/certs/ca-certificates.crt" }, .ca_bundle_path = "/etc/ssl/certs/ca-certificates.crt" },
        .{ .config = .{ .max_network_retries = 2, .max_rate_limit_retries = 4 }, .max_network_retries = 2, .max_rate_limit_retries = 4 },
        .{ .config = .{ .connect_timeout_ms = 0 }, .connect_timeout_ms = 0 },
        .{ .config = .{ .read_timeout_ms = 0 }, .read_timeout_ms = 0 },
        .{ .config = .{ .max_retries = 255 }, .max_retries = 255 },
    };

    for (cases) |case| {
        if (case.rate_limit_enabled) |value| try std.testing.expectEqual(value, case.config.rate_limit_enabled);
        if (case.connect_timeout_ms) |value| try std.testing.expectEqual(value, case.config.connect_timeout_ms);
        if (case.read_timeout_ms) |value| try std.testing.expectEqual(value, case.config.read_timeout_ms);
        if (case.max_network_retries) |value| try std.testing.expectEqual(value, case.config.max_network_retries);
        if (case.max_rate_limit_retries) |value| try std.testing.expectEqual(value, case.config.max_rate_limit_retries);
        if (case.max_retries) |value| try std.testing.expectEqual(value, case.config.max_retries);
        if (case.ca_bundle_path) |value| try std.testing.expectEqualSlices(u8, value, case.config.ca_bundle_path.?);
    }

    const connect_timeout = Config{ .connect_timeout_ms = 5_000 };
    try std.testing.expect(connect_timeout.connectIoTimeout().duration.raw.toMilliseconds() == 5_000);
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
    const MockHarness = struct {
        var released = false;

        fn release(_: std.mem.Allocator, _: Credential) void {
            released = true;
        }

        fn get(registry: []const u8) ?CredentialHandle {
            if (!std.mem.eql(u8, registry, "ghcr.io")) return null;
            return .{
                .credential = .{ .username = "user", .secret = "token" },
                .release_fn = release,
                .release_allocator = std.testing.allocator,
            };
        }
    };

    const provider = CredentialProvider{ .getCredentialFn = MockHarness.get };
    const handle = provider.getCredential("ghcr.io").?;
    try std.testing.expect(!MockHarness.released);
    handle.release();
    try std.testing.expect(MockHarness.released);
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

test "Config: applyToClient skips reload when path and mtime are unchanged" {
    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const abs_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/enterprise-test-ca.pem");
    defer std.testing.allocator.free(abs_path);

    const config = Config{ .ca_bundle_path = abs_path };
    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    const first_len = client.ca_bundle.bytes.items.len;
    client.ca_bundle_lock.unlockShared(std.testing.io);

    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    defer client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expectEqual(first_len, client.ca_bundle.bytes.items.len);
}

test "Config: applyToClient reloads bundle when file mtime changes" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const rel_path = "mtime-ca.pem";
    const enterprise = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "fixtures/tls/enterprise-test-ca.pem",
        std.testing.allocator,
        std.Io.Limit.limited64(MAX_CA_BUNDLE_BYTES),
    );
    defer std.testing.allocator.free(enterprise);
    {
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, enterprise);
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
    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    const first_len = client.ca_bundle.bytes.items.len;
    const first_count = client.ca_bundle.map.count();
    client.ca_bundle_lock.unlockShared(std.testing.io);

    const test_ca = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "fixtures/tls/test-ca.pem",
        std.testing.allocator,
        std.Io.Limit.limited64(MAX_CA_BUNDLE_BYTES),
    );
    defer std.testing.allocator.free(test_ca);
    try tmp.dir.deleteFile(std.testing.io, rel_path);
    {
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, test_ca);
    }

    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    defer client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expect(
        first_len != client.ca_bundle.bytes.items.len or
            first_count != client.ca_bundle.map.count(),
    );
}

test "Config: applyToClient allocation failures do not leak" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const abs_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/enterprise-test-ca.pem");
    defer std.testing.allocator.free(abs_path);

    const MockHarness = struct {
        fn run(failing_allocator: std.mem.Allocator, path: [:0]const u8) !void {
            var client = std.http.Client{
                .allocator = failing_allocator,
                .io = std.testing.io,
            };
            defer client.deinit();

            const config = Config{ .ca_bundle_path = path };
            try config.applyToClient(&client);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, MockHarness.run, .{abs_path});
}

test "Config: applyToClient repeated loads stay leak-free under DebugAllocator" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const abs_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/enterprise-test-ca.pem");
    defer std.testing.allocator.free(abs_path);

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const config = Config{ .ca_bundle_path = abs_path };

    for (0..32) |_| {
        var client = std.http.Client{
            .allocator = allocator,
            .io = std.testing.io,
        };
        try config.applyToClient(&client);
        client.deinit();
    }
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

test "Config: applyToClient rejects ca bundle files larger than MAX_CA_BUNDLE_BYTES" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const rel_path = "oversized-ca.pem";
    {
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try file.setLength(std.testing.io, MAX_CA_BUNDLE_BYTES + 1);
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

test "Config: applyToClient replaces prior bundle when ca_bundle_path changes" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const enterprise_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/enterprise-test-ca.pem");
    defer std.testing.allocator.free(enterprise_path);
    const test_ca_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/test-ca.pem");
    defer std.testing.allocator.free(test_ca_path);

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const enterprise_config = Config{ .ca_bundle_path = enterprise_path };
    try enterprise_config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    const first_len = client.ca_bundle.bytes.items.len;
    const first_count = client.ca_bundle.map.count();
    client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expect(first_count > 0);

    const test_ca_config = Config{ .ca_bundle_path = test_ca_path };
    try test_ca_config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    defer client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expect(client.ca_bundle.map.count() > 0);
    try std.testing.expect(
        first_len != client.ca_bundle.bytes.items.len or
            first_count != client.ca_bundle.map.count(),
    );
}

test "Config: applyToClient returns empty when pem contains only expired certificates" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const config = Config{ .ca_bundle_path = "fixtures/tls/expired-only-ca.pem" };
    try std.testing.expectError(error.CaBundleEmpty, config.applyToClient(&client));
}

test "Config: applyToClient rejects world-writable ca bundle file on POSIX" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;
    if (!@hasDecl(std.Io.File.Permissions, "toMode")) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const rel_path = "world-writable-ca.pem";
    const enterprise = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "fixtures/tls/enterprise-test-ca.pem",
        std.testing.allocator,
        std.Io.Limit.limited64(MAX_CA_BUNDLE_BYTES),
    );
    defer std.testing.allocator.free(enterprise);
    {
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, enterprise);
        try file.setPermissions(std.testing.io, std.Io.File.Permissions.fromMode(0o666));
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
    try std.testing.expectError(error.CaBundleInsecurePermissions, config.applyToClient(&client));
}

test "Config: applyToClient rejects pem files containing private key blocks" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const key_markers = [_][]const u8{
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    };

    const enterprise = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "fixtures/tls/enterprise-test-ca.pem",
        std.testing.allocator,
        std.Io.Limit.limited64(MAX_CA_BUNDLE_BYTES),
    );
    defer std.testing.allocator.free(enterprise);

    for (key_markers) |marker| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        const rel_path = "ca-with-key.pem";
        {
            var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
            defer file.close(std.testing.io);
            try file.writeStreamingAll(std.testing.io, enterprise);
            try file.writeStreamingAll(std.testing.io, "\n");
            try file.writeStreamingAll(std.testing.io, marker);
            try file.writeStreamingAll(std.testing.io, "\nZm9v\n-----END PRIVATE KEY-----\n");
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
        try std.testing.expectError(error.CaBundleContainsPrivateKey, config.applyToClient(&client));
    }
}

test "Config: loaded ca bundle verifies fixture server certificate signed by that ca" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const ca_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/test-ca.pem");
    defer std.testing.allocator.free(ca_path);
    const server_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/test-server.pem");
    defer std.testing.allocator.free(server_path);

    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(std.testing.allocator);

    const now = std.Io.Clock.real.now(std.testing.io);
    try ca_bundle.addCertsFromFilePathAbsolute(std.testing.allocator, std.testing.io, now, ca_path);

    var server_bundle: std.crypto.Certificate.Bundle = .empty;
    defer server_bundle.deinit(std.testing.allocator);
    try server_bundle.addCertsFromFilePathAbsolute(std.testing.allocator, std.testing.io, now, server_path);
    try std.testing.expect(server_bundle.bytes.items.len > 0);

    const server_cert: std.crypto.Certificate = .{
        .buffer = server_bundle.bytes.items,
        .index = 0,
    };
    const server_parsed = try server_cert.parse();
    try ca_bundle.verify(server_parsed, now.toSeconds());
}

test "Config: credential handle release with null release_fn is a no-op" {
    const handle = CredentialHandle{
        .credential = .{ .username = "u", .secret = "s" },
    };
    handle.release(); // must not crash or leak (covers default-null and explicit-null)
}

test "Config: credential_provider null returns null for all registries" {
    const c = Config{};
    try std.testing.expect(c.credential_provider == null);
}
