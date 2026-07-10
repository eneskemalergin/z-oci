//! Build-time guard: reject private-key PEM blocks and high-confidence credential
//! material in tracked repo paths.
//!
//! This tool is not linked into the z-oci library. It walks only the roots listed
//! in `SCAN_ROOTS` during `zig build security-check` / `zig build test`.
//!
//! Scan classes:
//! - Key-like extensions (`.pem`, `.key`, `.crt`, `.p12`, `.pfx`, `.jks`, `.netrc`):
//!   reject private-key PEM markers; oversized files fail closed.
//! - Env / docker credential filenames (`.env`, `.env.*`, `config.json` under a
//!   docker path, `.dockercfg`, `*credentials*`, `.netrc`): reject PEM markers,
//!   docker `auths` blobs with embedded `"auth"` values, and non-placeholder
//!   secret assignments.
//! - Non-source text under scan roots (`.md`, `.toml`, `.json`, `.yml`, `.yaml`,
//!   `.txt`, `.sh`): reject private-key PEM markers. `.zig` is intentionally not
//!   PEM-scanned so detector string literals and synthetic test PEMs do not
//!   false-positive; real key files must use key-like extensions.
//!
//! Files larger than `MAX_SCAN_BYTES` (10 MiB) are rejected. Empty files are allowed.
const std = @import("std");

const PRIVATE_KEY_MARKERS = [_][]const u8{
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
};

const SCAN_ROOTS = [_][]const u8{
    "fixtures",
    "src",
    "examples",
    "benchmarks",
    "tools",
};

const KEY_EXTENSIONS = [_][]const u8{
    ".pem",
    ".key",
    ".crt",
    ".p12",
    ".pfx",
    ".jks",
    ".netrc",
};

const TEXT_EXTENSIONS = [_][]const u8{
    ".md",
    ".toml",
    ".json",
    ".yml",
    ".yaml",
    ".txt",
    ".sh",
};

const MAX_SCAN_BYTES: u64 = 10 * 1024 * 1024;
const STACK_BUF_SIZE = 128 * 1024;
const CHUNK_SIZE = 8192;

const MAX_MARKER_LEN = blk: {
    var longest: usize = 0;
    for (PRIVATE_KEY_MARKERS) |marker| longest = @max(longest, marker.len);
    break :blk longest;
};

const MARKER_OVERLAP = MAX_MARKER_LEN - 1;

const ScanClass = enum {
    key_material,
    credential_file,
    text_pem_only,
};

const Finding = enum {
    private_key_pem,
    docker_auths,
    env_secret,
    oversized,
    short_read,
    size_overflow,
};

/// CI security-check entrypoint; scans `SCAN_ROOTS` for credential material.
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var failures: usize = 0;

    for (SCAN_ROOTS) |root| {
        var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer dir.close(io);

        var walker = try dir.walk(gpa);
        defer walker.deinit();

        while (try walker.next(io)) |entry| {
            if (entry.kind != .file) continue;
            const class = classifyPath(entry.path, entry.basename) orelse continue;
            if (try scanFile(io, entry.dir, entry.basename, class)) |finding| {
                std.log.err("{s} in {s}", .{ @tagName(finding), entry.path });
                failures += 1;
            }
        }
    }

    if (failures > 0) {
        std.log.err("found {d} file(s) with credential or private-key material", .{failures});
        return error.CredentialMaterialFound;
    }
}

fn classifyPath(path: []const u8, basename: []const u8) ?ScanClass {
    if (isCredentialBasename(basename) or isDockerConfigPath(path, basename)) {
        return .credential_file;
    }
    for (KEY_EXTENSIONS) |ext| {
        if (std.mem.endsWith(u8, basename, ext)) return .key_material;
    }
    for (TEXT_EXTENSIONS) |ext| {
        if (std.mem.endsWith(u8, basename, ext)) return .text_pem_only;
    }
    return null;
}

fn isCredentialBasename(name: []const u8) bool {
    if (std.mem.eql(u8, name, ".env")) return true;
    if (std.mem.startsWith(u8, name, ".env.")) return true;
    if (std.mem.eql(u8, name, ".dockercfg")) return true;
    if (std.mem.eql(u8, name, ".netrc")) return true;
    if (std.mem.indexOf(u8, name, "credentials") != null) return true;
    return false;
}

fn isDockerConfigPath(path: []const u8, basename: []const u8) bool {
    if (!std.mem.eql(u8, basename, "config.json")) return false;
    return std.mem.indexOf(u8, path, ".docker") != null or
        std.mem.indexOf(u8, path, "docker") != null;
}

fn containsPrivateKeyMarker(body: []const u8) bool {
    if (!std.mem.containsAtLeast(u8, body, 1, "BEGIN")) return false;
    inline for (PRIVATE_KEY_MARKERS) |marker| {
        if (std.mem.indexOf(u8, body, marker) != null) return true;
    }
    return false;
}

fn containsDockerAuths(body: []const u8) bool {
    // High-confidence docker config shape: an "auths" object with an "auth" value.
    if (std.mem.indexOf(u8, body, "\"auths\"") == null) return false;
    if (std.mem.indexOf(u8, body, "\"auth\"") == null) return false;
    // Require a non-empty auth string value, not just the key name.
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, body, search_from, "\"auth\"")) |idx| {
        const after_key = idx + "\"auth\"".len;
        var i = after_key;
        while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == '\n' or body[i] == '\r')) : (i += 1) {}
        if (i >= body.len or body[i] != ':') {
            search_from = after_key;
            continue;
        }
        i += 1;
        while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == '\n' or body[i] == '\r')) : (i += 1) {}
        if (i >= body.len or body[i] != '"') {
            search_from = after_key;
            continue;
        }
        i += 1;
        const value_start = i;
        while (i < body.len and body[i] != '"') : (i += 1) {}
        if (i > value_start) return true;
        search_from = i;
    }
    return false;
}

fn isPlaceholderSecretValue(value: []const u8) bool {
    if (value.len == 0) return true;
    const lower_buf_len = 64;
    var lower_buf: [lower_buf_len]u8 = undefined;
    const n = @min(value.len, lower_buf_len);
    for (value[0..n], 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
    const lower = lower_buf[0..n];
    const placeholders = [_][]const u8{
        "changeme",
        "replace-me",
        "replace_me",
        "your-token",
        "your_token",
        "your-password",
        "your_password",
        "example",
        "xxx",
        "todo",
        "redacted",
        "<token>",
        "<password>",
        "${",
    };
    for (placeholders) |p| {
        if (std.mem.indexOf(u8, lower, p) != null) return true;
    }
    return false;
}

fn secretAssignmentName(name: []const u8) bool {
    if (name.len == 0) return false;
    const needles = [_][]const u8{
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "AUTH_TOKEN",
        "BEARER",
    };
    for (needles) |needle| {
        if (std.mem.indexOf(u8, name, needle) != null) return true;
    }
    return false;
}

fn containsEnvSecretAssignment(body: []const u8) bool {
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw_line| {
        var line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.startsWith(u8, line, "export ")) {
            line = std.mem.trim(u8, line["export ".len..], " \t");
        }
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const name = std.mem.trim(u8, line[0..eq], " \t");
        if (!secretAssignmentName(name)) continue;
        var value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (value.len >= 2 and ((value[0] == '"' and value[value.len - 1] == '"') or
            (value[0] == '\'' and value[value.len - 1] == '\'')))
        {
            value = value[1 .. value.len - 1];
        }
        if (!isPlaceholderSecretValue(value)) return true;
    }
    return false;
}

fn findingForBody(body: []const u8, class: ScanClass) ?Finding {
    if (containsPrivateKeyMarker(body)) return .private_key_pem;
    switch (class) {
        .key_material, .text_pem_only => return null,
        .credential_file => {
            if (containsDockerAuths(body)) return .docker_auths;
            if (containsEnvSecretAssignment(body)) return .env_secret;
            return null;
        },
    }
}

fn scanFile(io: std.Io, dir: std.Io.Dir, name: []const u8, class: ScanClass) !?Finding {
    var file = try dir.openFile(io, name, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.size > MAX_SCAN_BYTES) return .oversized;

    if (stat.size == 0) return null;

    const read_len = std.math.cast(usize, stat.size) orelse return .size_overflow;

    if (read_len <= STACK_BUF_SIZE) {
        var stack_buf: [STACK_BUF_SIZE]u8 = undefined;
        return try scanFromBuffer(io, &file, stack_buf[0..read_len], class);
    }

    return try scanFileStreaming(io, &file, class);
}

fn scanFromBuffer(io: std.Io, file: *std.Io.File, buf: []u8, class: ScanClass) !?Finding {
    var file_reader = file.reader(io, &.{});
    const n = try file_reader.interface.readSliceShort(buf);
    if (n != buf.len) return .short_read;
    return findingForBody(buf, class);
}

fn scanFileStreaming(io: std.Io, file: *std.Io.File, class: ScanClass) !?Finding {
    // Streaming path only needs PEM overlap detection; credential heuristics require
    // full-file context and are limited to STACK_BUF_SIZE files via scanFromBuffer.
    _ = class;
    var file_reader = file.reader(io, &.{});
    var carry: [MARKER_OVERLAP]u8 = undefined;
    var carry_len: usize = 0;

    while (true) {
        var chunk: [CHUNK_SIZE]u8 = undefined;
        const n = try file_reader.interface.readSliceShort(&chunk);
        if (n == 0) break;

        const body = chunk[0..n];
        if (carry_len > 0) {
            var window: [MARKER_OVERLAP + CHUNK_SIZE]u8 = undefined;
            @memcpy(window[0..carry_len], carry[0..carry_len]);
            @memcpy(window[carry_len..][0..body.len], body);
            if (containsPrivateKeyMarker(window[0 .. carry_len + body.len])) return .private_key_pem;
        } else if (containsPrivateKeyMarker(body)) {
            return .private_key_pem;
        }

        if (body.len >= MARKER_OVERLAP) {
            @memcpy(carry[0..MARKER_OVERLAP], body[body.len - MARKER_OVERLAP ..]);
            carry_len = MARKER_OVERLAP;
        } else {
            const keep = @min(carry_len, MARKER_OVERLAP - body.len);
            if (keep > 0) {
                std.mem.copyForwards(u8, carry[0..keep], carry[carry_len - keep ..][0..keep]);
            }
            @memcpy(carry[keep..][0..body.len], body);
            carry_len = keep + body.len;
        }
    }

    if (carry_len > 0 and containsPrivateKeyMarker(carry[0..carry_len])) return .private_key_pem;
    return null;
}

test "containsPrivateKeyMarker rejects certificate-only PEM" {
    const cert_only =
        \\-----BEGIN CERTIFICATE-----
        \\Zm9v
        \\-----END CERTIFICATE-----
    ;
    try std.testing.expect(!containsPrivateKeyMarker(cert_only));
}

test "containsPrivateKeyMarker detects private key markers" {
    inline for (PRIVATE_KEY_MARKERS) |marker| {
        try std.testing.expect(containsPrivateKeyMarker(marker));
    }
}

test "classifyPath covers key, credential, and text classes" {
    try std.testing.expectEqual(ScanClass.key_material, classifyPath("fixtures/ca.pem", "ca.pem").?);
    try std.testing.expectEqual(ScanClass.key_material, classifyPath("fixtures/tls.p12", "tls.p12").?);
    try std.testing.expectEqual(ScanClass.credential_file, classifyPath("tools/.env", ".env").?);
    try std.testing.expectEqual(ScanClass.credential_file, classifyPath("tools/.env.local", ".env.local").?);
    try std.testing.expectEqual(
        ScanClass.credential_file,
        classifyPath("fixtures/docker/config.json", "config.json").?,
    );
    try std.testing.expectEqual(
        ScanClass.credential_file,
        classifyPath("tools/user-credentials.json", "user-credentials.json").?,
    );
    try std.testing.expectEqual(
        ScanClass.text_pem_only,
        classifyPath("fixtures/manifests/busybox.json", "busybox.json").?,
    );
    try std.testing.expect(classifyPath("src/root.zig", "root.zig") == null);
    try std.testing.expect(classifyPath("src/Config.zig", "Config.zig") == null);
    try std.testing.expect(classifyPath("fixtures/blob.bin", "blob.bin") == null);
}

test "containsDockerAuths detects non-empty auth values" {
    const with_auth =
        \\{"auths":{"registry.example.test":{"auth":"dXNlcjpwYXNz"}}}
    ;
    const empty_auth =
        \\{"auths":{"registry.example.test":{"auth":""}}}
    ;
    const no_auths =
        \\{"HttpHeaders":{"User-Agent":"z-oci"}}
    ;
    try std.testing.expect(containsDockerAuths(with_auth));
    try std.testing.expect(!containsDockerAuths(empty_auth));
    try std.testing.expect(!containsDockerAuths(no_auths));
}

test "containsEnvSecretAssignment ignores placeholders and comments" {
    try std.testing.expect(!containsEnvSecretAssignment("# TOKEN=real\nTOKEN=changeme\n"));
    try std.testing.expect(!containsEnvSecretAssignment("API_TOKEN=${SECRET_FROM_ENV}\n"));
    try std.testing.expect(containsEnvSecretAssignment("export DOCKER_PASSWORD=s3cret-value\n"));
    try std.testing.expect(containsEnvSecretAssignment("AUTH_TOKEN=\"live-token-value\"\n"));
}

test "findingForBody keeps zig-style bearer fixtures out of credential class" {
    const zig_with_bearer =
        \\const token_body = "{\"access_token\":\"batch-token\",\"expires_in\":3600}";
    ;
    try std.testing.expect(findingForBody(zig_with_bearer, .text_pem_only) == null);
    try std.testing.expect(findingForBody("-----BEGIN PRIVATE KEY-----\n", .text_pem_only) == .private_key_pem);
    try std.testing.expect(findingForBody(zig_with_bearer, .credential_file) == null);
}

test "streaming overlap window catches split marker" {
    const marker = PRIVATE_KEY_MARKERS[1];
    const split_at = 11;
    var carry: [MARKER_OVERLAP]u8 = undefined;
    @memcpy(carry[0..split_at], marker[0..split_at]);
    const carry_len = split_at;
    const rest = marker[split_at..];

    var window: [MARKER_OVERLAP + CHUNK_SIZE]u8 = undefined;
    @memcpy(window[0..carry_len], carry[0..carry_len]);
    @memcpy(window[carry_len..][0..rest.len], rest);
    try std.testing.expect(containsPrivateKeyMarker(window[0 .. carry_len + rest.len]));
}
