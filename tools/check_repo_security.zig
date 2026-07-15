//! Build-time guard: reject private-key PEM blocks, high-confidence credential
//! material, and development-only visibility leaks in tracked repo paths.
//!
//! This tool is not linked into the z-oci library. It walks the roots listed in
//! `SCAN_ROOTS` plus selected public root files during `zig build security-check`
//! / `zig build test`.
//!
//! Scan classes:
//! - Key-like extensions (`.pem`, `.key`, `.crt`, `.p12`, `.pfx`, `.jks`, `.netrc`):
//!   reject private-key PEM markers; oversized files fail closed.
//! - Env / docker credential filenames (`.env`, `.env.*`, `config.json` under a
//!   docker path, `.dockercfg`, `*credentials*`, `.netrc`): reject PEM markers,
//!   docker `auths` blobs with embedded `"auth"` values, and non-placeholder
//!   secret assignments.
//! - Non-source text under scan roots (`.md`, `.toml`, `.json`, `.yml`, `.yaml`,
//!   `.txt`, `.sh`): reject private-key PEM markers.
//! - `.zig` sources: reject non-placeholder Docker `auths` `"auth"` values only.
//!   PEM markers and `.env`-style assignments are not scanned in `.zig` (field names
//!   like `max_token_cache_entries` and test literals false-positive otherwise).
//! - Production text and Zig sources: reject development-only paths and numbered
//!   project phase/stage labels. Stable technical terms and user-visible limitations
//!   such as an unimplemented CLI are allowed.
//! - `benchmarks/tmp/` is ignored benchmark scratch and is skipped like the other
//!   development-only paths.
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
    "integration",
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

const PUBLIC_ROOT_FILES = [_][]const u8{
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "build.zig",
    "build.zig.zon",
};

const DEVELOPMENT_REFERENCE_MARKERS = [_][]const u8{
    "plan/",
    "temp/",
    "benchmarks/tmp/",
    ".agents/",
    ".codex/",
    "experiments/",
    "milestone",
    "roadmap",
    "scaffold",
    "scaffolding",
    "dev-level",
    "work-stage",
};

const MAX_SCAN_BYTES: u64 = 10 * 1024 * 1024;
const STACK_BUF_SIZE: usize = 128 * 1024;
const CHUNK_SIZE: usize = 8192;

const MAX_MARKER_LEN = blk: {
    var longest: usize = 0;
    for (PRIVATE_KEY_MARKERS) |marker| longest = @max(longest, marker.len);
    break :blk longest;
};

const MARKER_OVERLAP = MAX_MARKER_LEN - 1;

const MAX_DEVELOPMENT_MARKER_LEN: usize = blk: {
    var longest: usize = 0;
    for (DEVELOPMENT_REFERENCE_MARKERS) |marker| longest = @max(longest, marker.len);
    break :blk longest;
};

const SCAN_OVERLAP: usize = @max(MARKER_OVERLAP, MAX_DEVELOPMENT_MARKER_LEN - 1);

const BASE64_DECODER = std.base64.standard.decoderWithIgnore(" \t\r\n");

const ScanClass = enum {
    key_material,
    credential_file,
    text_pem_only,
    zig_source,
    public_text,
    security_tool,
};

const Finding = enum {
    private_key_pem,
    docker_auths,
    env_secret,
    oversized,
    short_read,
    size_overflow,
    development_reference,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var failures: usize = 0;

    const cwd = std.Io.Dir.cwd();
    for (PUBLIC_ROOT_FILES) |path| {
        if (try scanFile(io, cwd, path, .public_text)) |finding| {
            std.log.err("{s} in {s}", .{ @tagName(finding), path });
            failures += 1;
        }
    }

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
            if (isIgnoredDevelopmentPath(entry.path)) continue;
            if (containsDevelopmentReference(entry.path)) {
                std.log.err("development_reference in {s}", .{entry.path});
                failures += 1;
                continue;
            }
            const class = classifyPath(entry.path, entry.basename) orelse continue;
            if (try scanFile(io, entry.dir, entry.basename, class)) |finding| {
                std.log.err("{s} in {s}", .{ @tagName(finding), entry.path });
                failures += 1;
            }
        }
    }

    if (failures > 0) {
        std.log.err("found {d} file(s) with security or development-visibility findings", .{failures});
        return error.SecurityFinding;
    }
}

fn classifyPath(path: []const u8, basename: []const u8) ?ScanClass {
    if (std.mem.eql(u8, basename, "check_repo_security.zig")) return .security_tool;
    if (isCredentialBasename(basename) or isDockerConfigPath(path, basename)) {
        return .credential_file;
    }
    if (std.mem.endsWith(u8, basename, ".zig")) return .zig_source;
    for (KEY_EXTENSIONS) |ext| {
        if (std.mem.endsWith(u8, basename, ext)) return .key_material;
    }
    for (TEXT_EXTENSIONS) |ext| {
        if (std.mem.endsWith(u8, basename, ext)) return .text_pem_only;
    }
    return null;
}

fn isIgnoredDevelopmentPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "tmp") or std.mem.startsWith(u8, path, "tmp/");
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

fn containsAsciiIgnoreCase(body: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > body.len) return false;

    var start: usize = 0;
    while (start + needle.len <= body.len) : (start += 1) {
        var matches = true;
        for (needle, 0..) |expected, offset| {
            if (std.ascii.toLower(body[start + offset]) != std.ascii.toLower(expected)) {
                matches = false;
                break;
            }
        }
        if (matches) return true;
    }
    return false;
}

fn containsNumberedDevelopmentLabel(body: []const u8) bool {
    const labels = [_][]const u8{ "phase", "stage" };

    var start: usize = 0;
    while (start < body.len) : (start += 1) {
        for (labels) |label| {
            if (start + label.len > body.len) continue;
            if (!std.ascii.eqlIgnoreCase(body[start .. start + label.len], label)) continue;

            var after = start + label.len;
            while (after < body.len and (body[after] == ' ' or body[after] == '\t' or
                body[after] == '_' or body[after] == '-')) : (after += 1)
            {}
            if (after < body.len and std.ascii.isDigit(body[after])) return true;
        }
    }
    return false;
}

fn containsDevelopmentReference(body: []const u8) bool {
    for (DEVELOPMENT_REFERENCE_MARKERS) |marker| {
        if (containsAsciiIgnoreCase(body, marker)) return true;
    }
    return containsNumberedDevelopmentLabel(body);
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

fn containsNonPlaceholderDockerAuths(body: []const u8) bool {
    // Same `"auth"` JSON shape as containsDockerAuths; decodes base64 and rejects live credentials.
    if (std.mem.indexOf(u8, body, "\"auths\"") == null) return false;
    if (std.mem.indexOf(u8, body, "\"auth\"") == null) return false;

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
        if (i > value_start) {
            const value = body[value_start..i];
            if (!isPlaceholderDockerAuthBase64(value)) return true;
        }
        search_from = i;
    }
    return false;
}

fn isPlaceholderDockerAuthBase64(b64: []const u8) bool {
    if (b64.len == 0) return true;

    var decoded_buf: [256]u8 = undefined;
    const decoded_len = BASE64_DECODER.decode(decoded_buf[0..], b64) catch return false;
    return isPlaceholderCredentialLiteral(decoded_buf[0..decoded_len]);
}

fn isPlaceholderCredentialLiteral(decoded: []const u8) bool {
    if (decoded.len == 0) return true;

    const exact = [_][]const u8{
        "octocat:ghp_example",
        "dockeruser:secret",
        "internal-user:token",
        "user:secret",
        "user:pass",
        "no_colon",
        "octocat:first",
        "octocat:second",
        "home-user:home-token",
        "docker-user:docker-token",
    };
    for (exact) |known| {
        if (std.mem.eql(u8, decoded, known)) return true;
    }

    if (isPlaceholderSecretValue(decoded)) return true;

    const colon = std.mem.indexOfScalar(u8, decoded, ':') orelse return false;
    const user = decoded[0..colon];
    const secret = decoded[colon + 1 ..];

    const test_users = [_][]const u8{
        "octocat",
        "dockeruser",
        "internal-user",
        "user",
        "home-user",
        "docker-user",
    };
    const test_secrets = [_][]const u8{
        "ghp_example",
        "secret",
        "token",
        "pass",
        "first",
        "second",
        "home-token",
        "docker-token",
    };

    var user_ok = false;
    for (test_users) |u| {
        if (std.mem.eql(u8, user, u)) {
            user_ok = true;
            break;
        }
    }
    if (!user_ok) return false;

    for (test_secrets) |s| {
        if (std.mem.eql(u8, secret, s)) return true;
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
    switch (class) {
        .zig_source, .public_text, .security_tool => {
            if (class == .security_tool) return if (containsNonPlaceholderDockerAuths(body)) .docker_auths else null;
            if (containsDevelopmentReference(body)) return .development_reference;
        },
        .credential_file, .text_pem_only => {
            if (containsDevelopmentReference(body)) return .development_reference;
        },
        .key_material => {},
    }

    switch (class) {
        .zig_source => {
            if (containsNonPlaceholderDockerAuths(body)) return .docker_auths;
            return null;
        },
        .public_text => return null,
        else => {
            if (containsPrivateKeyMarker(body)) return .private_key_pem;
            switch (class) {
                .key_material, .text_pem_only => return null,
                .credential_file => {
                    if (containsDockerAuths(body)) return .docker_auths;
                    if (containsEnvSecretAssignment(body)) return .env_secret;
                    return null;
                },
                .zig_source, .public_text, .security_tool => unreachable,
            }
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
    // Credential heuristics require full-file context and are limited to
    // STACK_BUF_SIZE files via scanFromBuffer. Marker checks remain streaming-safe.
    const check_visibility = class != .key_material;
    var file_reader = file.reader(io, &.{});
    var carry: [SCAN_OVERLAP]u8 = undefined;
    var carry_len: usize = 0;

    while (true) {
        var chunk: [CHUNK_SIZE]u8 = undefined;
        const n = try file_reader.interface.readSliceShort(&chunk);
        if (n == 0) break;

        const body = chunk[0..n];
        if (carry_len > 0) {
            var window: [SCAN_OVERLAP + CHUNK_SIZE]u8 = undefined;
            @memcpy(window[0..carry_len], carry[0..carry_len]);
            @memcpy(window[carry_len..][0..body.len], body);
            const combined = window[0 .. carry_len + body.len];
            if (containsPrivateKeyMarker(combined)) return .private_key_pem;
            if (check_visibility and containsDevelopmentReference(combined)) return .development_reference;
        } else if (containsPrivateKeyMarker(body)) {
            return .private_key_pem;
        } else if (check_visibility and containsDevelopmentReference(body)) {
            return .development_reference;
        }

        if (body.len >= SCAN_OVERLAP) {
            @memcpy(carry[0..SCAN_OVERLAP], body[body.len - SCAN_OVERLAP ..]);
            carry_len = SCAN_OVERLAP;
        } else {
            const keep = @min(carry_len, SCAN_OVERLAP - body.len);
            if (keep > 0) {
                std.mem.copyForwards(u8, carry[0..keep], carry[carry_len - keep ..][0..keep]);
            }
            @memcpy(carry[keep..][0..body.len], body);
            carry_len = keep + body.len;
        }
    }

    if (carry_len > 0) {
        const remaining = carry[0..carry_len];
        if (containsPrivateKeyMarker(remaining)) return .private_key_pem;
        if (check_visibility and containsDevelopmentReference(remaining)) return .development_reference;
    }
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

test "containsDevelopmentReference rejects development-only paths and numbered labels" {
    try std.testing.expect(containsDevelopmentReference("See plan/phase6.1-pre-phase7.md"));
    try std.testing.expect(containsDevelopmentReference("Phase 1.4"));
    try std.testing.expect(containsDevelopmentReference("stage_2_auth"));
    try std.testing.expect(containsDevelopmentReference("temporary roadmap scaffold"));
    try std.testing.expect(!containsDevelopmentReference("HEAD request and temporary buffer"));
    try std.testing.expect(!containsDevelopmentReference("HTTP 307 temporary_redirect"));
}

test "findingForBody reports development references" {
    try std.testing.expectEqual(
        Finding.development_reference,
        findingForBody("phase6.1", .public_text).?,
    );
    try std.testing.expect(findingForBody("phase6.1", .key_material) == null);
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
    try std.testing.expectEqual(ScanClass.zig_source, classifyPath("src/root.zig", "root.zig").?);
    try std.testing.expectEqual(
        ScanClass.zig_source,
        classifyPath("integration/registry2/main.zig", "main.zig").?,
    );
    try std.testing.expectEqual(
        ScanClass.text_pem_only,
        classifyPath("integration/registry2/README.md", "README.md").?,
    );
    try std.testing.expect(classifyPath("fixtures/blob.bin", "blob.bin") == null);
}

test "isIgnoredDevelopmentPath skips benchmark scratch only" {
    try std.testing.expect(isIgnoredDevelopmentPath("tmp/phase6-debug.txt"));
    try std.testing.expect(!isIgnoredDevelopmentPath("baselines/v0.6.0.json"));
}

test "development references are rejected in production paths" {
    try std.testing.expect(containsDevelopmentReference("src/phase1_4.zig"));
    try std.testing.expect(containsDevelopmentReference("benchmarks/tmp/results.json"));
    try std.testing.expect(!containsDevelopmentReference("benchmarks/baselines/v0.6.0.json"));
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
    try std.testing.expect(findingForBody("-----BEGIN PRIVATE KEY-----\n", .zig_source) == null);
    try std.testing.expect(findingForBody(zig_with_bearer, .credential_file) == null);
    try std.testing.expect(findingForBody(zig_with_bearer, .zig_source) == null);
}

test "isPlaceholderDockerAuthBase64 accepts test fixture auths only" {
    try std.testing.expect(isPlaceholderDockerAuthBase64("b2N0b2NhdDpnaHBfZXhhbXBsZQ=="));
    try std.testing.expect(isPlaceholderDockerAuthBase64("ZG9ja2VydXNlcjpzZWNyZXQ="));
    try std.testing.expect(isPlaceholderDockerAuthBase64("dXNlcjpwYXNz"));
    try std.testing.expect(!isPlaceholderDockerAuthBase64("c3VwZXItc2VjcmV0LXRva2Vu"));
}

test "findingForBody zig_source flags live docker auths" {
    const fixture_auth =
        \\{"auths":{"registry.example.test":{"auth":"b2N0b2NhdDpnaHBfZXhhbXBsZQ=="}}}
    ;
    const live_auth_prefix = "{\"auths\":{\"registry.example.test\":{\"auth\":\"";
    const live_auth_suffix = "\"}}}";
    const live_auth_b64 = "c3VwZXItc2VjcmV0LXRva2Vu";
    var live_auth_buf: [256]u8 = undefined;
    const live_auth = try std.fmt.bufPrint(
        &live_auth_buf,
        "{s}{s}{s}",
        .{ live_auth_prefix, live_auth_b64, live_auth_suffix },
    );
    try std.testing.expect(findingForBody(fixture_auth, .zig_source) == null);
    try std.testing.expectEqual(Finding.docker_auths, findingForBody(live_auth, .zig_source).?);
}

test "streaming overlap window catches split marker" {
    const marker = PRIVATE_KEY_MARKERS[1];
    const split_at = 11;
    var carry: [SCAN_OVERLAP]u8 = undefined;
    @memcpy(carry[0..split_at], marker[0..split_at]);
    const carry_len = split_at;
    const rest = marker[split_at..];

    var window: [SCAN_OVERLAP + CHUNK_SIZE]u8 = undefined;
    @memcpy(window[0..carry_len], carry[0..carry_len]);
    @memcpy(window[carry_len..][0..rest.len], rest);
    try std.testing.expect(containsPrivateKeyMarker(window[0 .. carry_len + rest.len]));
}
