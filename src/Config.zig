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
//! Loopback cleartext (testing / local registry):
//! - URL builders still emit `https://`. Live manifest/token/ping exchangers rewrite
//!   to `http://` only when the registry host is `127.0.0.1`, `localhost`, or `::1`.
//! - No public Config switch. Public hostnames, RFC1918, and link-local hosts are
//!   never rewritten. See `testing_loopback.isLoopbackHost` for the exact allowlist.
//! - Runtime credential sources and zeroing policy: `auth.zig` file header.
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
//! CredentialProvider / CredentialSources are interface slots here; lookup
//! lives in `auth.zig`. Public resolve applies `credential_sources` only when
//! the caller injects them (no hidden process reads).
//!
//! Config fields are copied by value. Slices (`ca_bundle_path`,
//! `Credential.secret`, `CredentialSources.docker_config_json`) and
//! `CredentialSources.environ_map` / `process_io` borrow for the resolve call.

const std = @import("std");

pub const DEFAULT_MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
pub const DEFAULT_MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;
/// `0` means unbounded.
pub const DEFAULT_MAX_TOKEN_CACHE_ENTRIES: u32 = 128;

/// Opt-in auth sources for the public resolver path. Default `{}` is
/// provider-only / anonymous. Borrowed views must outlive the resolve call.
/// Precedence: `credential_provider`, then env, then Docker config/helpers.
pub const CredentialSources = struct {
    environ_map: ?*const std.process.Environ.Map = null,
    /// Wins over `load_docker_config_from_environ`.
    docker_config_json: ?[]const u8 = null,
    /// Requires `environ_map` and `process_io`, else `CredentialSourcesIncomplete`.
    load_docker_config_from_environ: bool = false,
    /// Enables helper spawn once a Docker config is loaded. Default runner is
    /// `docker-credential-*`; override with `helper_runner` for tests.
    process_io: ?std.Io = null,
    helper_runner: ?CredentialHelperRunner = null,
};

/// Matches `auth.DockerCredentialHelperRunner`. `anyerror` so Config does not
/// depend on the auth error set; auth maps unknown errors to `HelperFailed`.
pub const CredentialHelperRunner = *const fn (
    allocator: std.mem.Allocator,
    io: std.Io,
    helper_suffix: []const u8,
    server_url: []const u8,
    timeout: std.Io.Timeout,
) anyerror!CredentialHandle;

pub const Credential = struct {
    username: []const u8,
    secret: []const u8,
};

pub const CredentialHandle = struct {
    credential: Credential,
    // When set, `release_allocator` must be the allocator that owns `credential` slices.
    // `release_fn` must free through that allocator. Env/helper paths in `auth.zig`
    // zero secrets via `freeOwnedOptionalSecretSlice` before `free`.
    release_fn: ?*const fn (allocator: std.mem.Allocator, credential: Credential) void = null,
    release_allocator: std.mem.Allocator = undefined,

    pub fn release(self: CredentialHandle) void {
        if (self.release_fn) |release_fn| release_fn(self.release_allocator, self.credential);
    }
};

pub const CredentialProvider = struct {
    // Null = anonymous. Slices must outlive the resolve call.
    getCredentialFn: *const fn (registry: []const u8) ?CredentialHandle,

    pub fn getCredential(self: CredentialProvider, registry: []const u8) ?CredentialHandle {
        return self.getCredentialFn(registry);
    }
};

pub const Config = struct {
    pub const ApplyError = error{
        OutOfMemory,
        CaBundleFileNotFound,
        CaBundleInvalid,
        CaBundleEmpty,
        CaBundleTlsDisabled,
        CaBundleInsecurePermissions,
        CaBundleContainsPrivateKey,
        InvalidDockerConfig,
        CredentialSourcesIncomplete,
    };

    credential_provider: ?*const CredentialProvider = null,
    credential_sources: CredentialSources = .{},

    // Caller-owned TCP only; live exchangers ignore this (zig#31305). `0` = unset.
    connect_timeout_ms: u32 = 0,

    // Docker credential helper subprocess I/O only (not manifest/token HTTP).
    read_timeout_ms: u32 = 30_000,

    // Cached-401 auth invalidation only; transport uses the budgets below.
    max_retries: u8 = 1,

    max_network_retries: u8 = 1,
    max_rate_limit_retries: u8 = 1,

    // Public CA PEM only; see file header. Null = OS trust scan.
    ca_bundle_path: ?[]const u8 = null,

    // Opt-in pre-emptive pause on `RateLimit-*` remaining=0. Reactive 429 stays on.
    rate_limit_enabled: bool = false,

    max_manifest_bytes: usize = DEFAULT_MAX_MANIFEST_BYTES,
    max_token_response_bytes: usize = DEFAULT_MAX_TOKEN_RESPONSE_BYTES,
    // `0` means unbounded.
    max_token_cache_entries: u32 = DEFAULT_MAX_TOKEN_CACHE_ENTRIES,

    /// For caller-owned `connectTcpOptions` only (not live exchangers yet).
    pub fn connectIoTimeout(self: Config) std.Io.Timeout {
        if (self.connect_timeout_ms == 0) return .none;
        return .{
            .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(self.connect_timeout_ms),
                .clock = .real,
            },
        };
    }

    /// Loads `ca_bundle_path` into `client.ca_bundle` and pins `client.now` so Zig
    /// does not OS-rescan on the next HTTPS request. No-op when path is null.
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

fn skipUnlessTls() !void {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;
}

fn testClient() std.http.Client {
    return .{ .allocator = std.testing.allocator, .io = std.testing.io };
}

fn expectApplyError(ca_path: []const u8, expected: Config.ApplyError) !void {
    var client = testClient();
    defer client.deinit();
    const config = Config{ .ca_bundle_path = ca_path };
    try std.testing.expectError(expected, config.applyToClient(&client));
}

fn readTlsFixture(rel_path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        rel_path,
        std.testing.allocator,
        std.Io.Limit.limited64(MAX_CA_BUNDLE_BYTES),
    );
}

fn tmpFileAbsPath(tmp: std.testing.TmpDir, rel_path: []const u8, abs_buf: *[std.fs.max_path_bytes]u8) ![]const u8 {
    const abs_len = try tmp.dir.realPathFile(std.testing.io, rel_path, abs_buf);
    return abs_buf[0..abs_len];
}

// --- Tests ---

test "Config: default field values" {
    const defaults = Config{};

    try std.testing.expect(defaults.credential_provider == null);
    try std.testing.expect(defaults.credential_sources.environ_map == null);
    try std.testing.expect(defaults.credential_sources.docker_config_json == null);
    try std.testing.expect(!defaults.credential_sources.load_docker_config_from_environ);
    try std.testing.expect(defaults.credential_sources.process_io == null);
    try std.testing.expect(defaults.credential_sources.helper_runner == null);
    try std.testing.expect(!defaults.rate_limit_enabled);
    try std.testing.expect(defaults.ca_bundle_path == null);
    try std.testing.expectEqual(@as(u32, 0), defaults.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 30_000), defaults.read_timeout_ms);
    try std.testing.expectEqual(@as(u8, 1), defaults.max_retries);
    try std.testing.expectEqual(@as(u8, 1), defaults.max_network_retries);
    try std.testing.expectEqual(@as(u8, 1), defaults.max_rate_limit_retries);
    try std.testing.expectEqual(DEFAULT_MAX_MANIFEST_BYTES, defaults.max_manifest_bytes);
    try std.testing.expectEqual(DEFAULT_MAX_TOKEN_RESPONSE_BYTES, defaults.max_token_response_bytes);
    try std.testing.expectEqual(DEFAULT_MAX_TOKEN_CACHE_ENTRIES, defaults.max_token_cache_entries);
}

test "Config.connectIoTimeout: maps connect_timeout_ms to std.Io.Timeout" {
    try std.testing.expectEqual(std.Io.Timeout.none, (Config{}).connectIoTimeout());

    const timed = Config{ .connect_timeout_ms = 1 };
    const timeout = timed.connectIoTimeout();

    try std.testing.expect(timeout.duration.raw.toMilliseconds() == 1);
    try std.testing.expect(timeout.duration.clock == .real);
}

test "Config: non-default field values are stored by value" {
    const config = Config{
        .rate_limit_enabled = true,
        .connect_timeout_ms = 5_000,
        .read_timeout_ms = 60_000,
        .max_retries = 255,
        .max_network_retries = 2,
        .max_rate_limit_retries = 4,
        .max_manifest_bytes = 1024,
        .max_token_response_bytes = 2048,
        .max_token_cache_entries = 0,
        .ca_bundle_path = "/etc/ssl/certs/ca-certificates.crt",
    };
    try std.testing.expect(config.rate_limit_enabled);
    try std.testing.expectEqual(@as(u32, 5_000), config.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 60_000), config.read_timeout_ms);
    try std.testing.expectEqual(@as(u8, 255), config.max_retries);
    try std.testing.expectEqual(@as(u8, 2), config.max_network_retries);
    try std.testing.expectEqual(@as(u8, 4), config.max_rate_limit_retries);
    try std.testing.expectEqual(@as(usize, 1024), config.max_manifest_bytes);
    try std.testing.expectEqual(@as(usize, 2048), config.max_token_response_bytes);
    try std.testing.expectEqual(@as(u32, 0), config.max_token_cache_entries);
    try std.testing.expectEqualStrings("/etc/ssl/certs/ca-certificates.crt", config.ca_bundle_path.?);
}

test "Config.CredentialProvider: getCredential and Config credential slot" {
    const selective_provider = CredentialProvider{
        .getCredentialFn = struct {
            fn get(registry: []const u8) ?CredentialHandle {
                if (std.mem.eql(u8, registry, "ghcr.io")) {
                    return .{ .credential = .{ .username = "user", .secret = "token" } };
                }
                return null;
            }
        }.get,
    };

    try std.testing.expect(selective_provider.getCredential("docker.io") == null);
    const config = Config{ .credential_provider = &selective_provider };
    const cred = config.credential_provider.?.getCredential("ghcr.io").?;
    try std.testing.expectEqualSlices(u8, "user", cred.credential.username);
    try std.testing.expectEqualSlices(u8, "token", cred.credential.secret);
}

test "CredentialHandle.release: invokes release_fn when set" {
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

    MockHarness.released = false;
    const handle = (CredentialProvider{ .getCredentialFn = MockHarness.get }).getCredential("ghcr.io").?;

    try std.testing.expect(!MockHarness.released);
    handle.release();
    try std.testing.expect(MockHarness.released);
}

test "CredentialHandle.release: no-op when release_fn is null" {
    const noop = CredentialHandle{ .credential = .{ .username = "u", .secret = "s" } };

    noop.release();
}

test "Config.applyToClient: no-op when ca_bundle_path is null" {
    var client = testClient();
    defer client.deinit();
    const config = Config{};
    try config.applyToClient(&client);
}

test "Config.applyToClient: loads PEM and skips reload when path and mtime are unchanged" {
    try skipUnlessTls();

    const rel_path = "fixtures/tls/enterprise-test-ca.pem";
    const abs_path = try fixtureAbsPath(std.testing.allocator, rel_path);
    defer std.testing.allocator.free(abs_path);

    for ([_][]const u8{ abs_path, rel_path }) |ca_path| {
        var client = testClient();
        defer client.deinit();

        const config = Config{ .ca_bundle_path = ca_path };
        try config.applyToClient(&client);

        try client.ca_bundle_lock.lockShared(std.testing.io);
        const first_len = client.ca_bundle.bytes.items.len;
        try std.testing.expect(first_len > 0);
        try std.testing.expect(client.now != null);
        client.ca_bundle_lock.unlockShared(std.testing.io);

        try config.applyToClient(&client);

        try client.ca_bundle_lock.lockShared(std.testing.io);
        defer client.ca_bundle_lock.unlockShared(std.testing.io);
        try std.testing.expectEqual(first_len, client.ca_bundle.bytes.items.len);
    }
}

test "Config.applyToClient: replaces CA bundle when ca_bundle_path changes" {
    try skipUnlessTls();

    const enterprise_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/enterprise-test-ca.pem");
    defer std.testing.allocator.free(enterprise_path);
    const test_ca_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/test-ca.pem");
    defer std.testing.allocator.free(test_ca_path);

    var client = testClient();
    defer client.deinit();

    const enterprise_config = Config{ .ca_bundle_path = enterprise_path };
    try enterprise_config.applyToClient(&client);
    try client.ca_bundle_lock.lockShared(std.testing.io);
    const enterprise_len = client.ca_bundle.bytes.items.len;
    const enterprise_count = client.ca_bundle.map.count();
    client.ca_bundle_lock.unlockShared(std.testing.io);
    try std.testing.expect(enterprise_count > 0);

    const test_ca_config = Config{ .ca_bundle_path = test_ca_path };
    try test_ca_config.applyToClient(&client);
    try client.ca_bundle_lock.lockShared(std.testing.io);
    defer client.ca_bundle_lock.unlockShared(std.testing.io);
    const path_swap_len = client.ca_bundle.bytes.items.len;
    const path_swap_count = client.ca_bundle.map.count();

    try std.testing.expect(path_swap_count > 0);
    try std.testing.expect(enterprise_len != path_swap_len or enterprise_count != path_swap_count);
}

test "Config.applyToClient: reloads CA bundle when path unchanged but mtime changes" {
    try skipUnlessTls();

    var client = testClient();
    defer client.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const rel_path = "mtime-ca.pem";
    const enterprise = try readTlsFixture("fixtures/tls/enterprise-test-ca.pem");
    defer std.testing.allocator.free(enterprise);
    {
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, enterprise);
    }

    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmpFileAbsPath(tmp, rel_path, &abs_buf);
    const config = Config{ .ca_bundle_path = tmp_path };
    try config.applyToClient(&client);

    try client.ca_bundle_lock.lockShared(std.testing.io);
    const first_len = client.ca_bundle.bytes.items.len;
    const first_count = client.ca_bundle.map.count();
    client.ca_bundle_lock.unlockShared(std.testing.io);

    const test_ca = try readTlsFixture("fixtures/tls/test-ca.pem");
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

test "Config.applyToClient: maps fixture and missing paths to exact errors" {
    try skipUnlessTls();

    try expectApplyError("/nonexistent/z-oci-ca-bundle.pem", error.CaBundleFileNotFound);

    const invalid_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/invalid-ca-bundle.pem");
    defer std.testing.allocator.free(invalid_path);
    try expectApplyError(invalid_path, error.CaBundleInvalid);

    try expectApplyError("fixtures/tls/expired-only-ca.pem", error.CaBundleEmpty);
}

test "Config.applyToClient: maps tmp file stat and permission failures to exact errors" {
    try skipUnlessTls();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;

    {
        const rel_path = "oversized-ca.pem";
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try file.setLength(std.testing.io, MAX_CA_BUNDLE_BYTES + 1);
        try expectApplyError(try tmpFileAbsPath(tmp, rel_path, &abs_buf), error.CaBundleInvalid);
    }

    {
        const rel_path = "empty-ca.pem";
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try expectApplyError(try tmpFileAbsPath(tmp, rel_path, &abs_buf), error.CaBundleEmpty);
    }

    if (@hasDecl(std.Io.File.Permissions, "toMode")) {
        const rel_path = "world-writable-ca.pem";
        const enterprise = try readTlsFixture("fixtures/tls/enterprise-test-ca.pem");
        defer std.testing.allocator.free(enterprise);
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, enterprise);
        try file.setPermissions(std.testing.io, std.Io.File.Permissions.fromMode(0o666));
        try expectApplyError(try tmpFileAbsPath(tmp, rel_path, &abs_buf), error.CaBundleInsecurePermissions);
    }
}

test "Config.applyToClient: rejects PEM containing a private key marker" {
    try skipUnlessTls();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const enterprise = try readTlsFixture("fixtures/tls/enterprise-test-ca.pem");
    defer std.testing.allocator.free(enterprise);

    const rel_path = "ca-with-key.pem";
    {
        var file = try tmp.dir.createFile(std.testing.io, rel_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, enterprise);
        try file.writeStreamingAll(std.testing.io, "\n-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n");
    }

    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    try expectApplyError(try tmpFileAbsPath(tmp, rel_path, &abs_buf), error.CaBundleContainsPrivateKey);
}

test "Config.applyToClient: allocation failures do not leak" {
    try skipUnlessTls();

    const abs_path = try fixtureAbsPath(std.testing.allocator, "fixtures/tls/enterprise-test-ca.pem");
    defer std.testing.allocator.free(abs_path);

    const MockHarness = struct {
        fn run(failing_allocator: std.mem.Allocator, path: [:0]const u8) !void {
            var client = std.http.Client{ .allocator = failing_allocator, .io = std.testing.io };
            defer client.deinit();
            const config = Config{ .ca_bundle_path = path };
            try config.applyToClient(&client);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, MockHarness.run, .{abs_path});
}
