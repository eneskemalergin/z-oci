//! Image reference parser. Handles the full Docker/OCI reference grammar.
//!
//! A reference is: [registry/]repository[:tag][@digest]
//!
//! Registry detection: a path component is a registry if it has a dot
//! (hostname), is "localhost", or has a colon followed only by digits (port).
//! Everything else is treated as a Docker Hub path, and single-component
//! names get "library/" prepended.
//!
//! docker.io, index.docker.io, and case variants of registry-1.docker.io are
//! normalized to registry-1.docker.io.
//!
//! When neither tag nor digest is present, tag defaults to "latest".
//! When both tag and digest are present, digest wins for refString().
//!
//! Ownership:
//! - `registry`, `repository`, `tag`, and `digest_raw` are owned allocations.
//! - `digest.hex` is not separately owned; it points inside `digest_raw`.
//! - Call `deinit()` exactly once for parsed values you keep outside an arena.

const std = @import("std");
const Digest = @import("Digest.zig");

const DOCKER_HUB_LIBRARY_PREFIX = "library/";
const DOCKER_HUB_REGISTRY = "registry-1.docker.io";
const DOCKER_HUB_ALIASES = [_][]const u8{ "docker.io", "index.docker.io", DOCKER_HUB_REGISTRY };

/// Owned registry hostname.
registry: []const u8,
/// Owned repository path.
repository: []const u8,
/// Informational when digest is also present. refString() returns the digest then.
tag: ?[]const u8,
/// Parsed digest. .hex points into digest_raw when a digest is present.
digest: ?Digest,
/// "sha256:hex" allocated copy used by refString(). Freed by deinit.
digest_raw: ?[]const u8,

const Reference = @This();

pub const ParseError = error{
    Empty,
    InvalidDigest,
    InvalidReference,
    OutOfMemory,
};

pub fn parse(allocator: std.mem.Allocator, input: []const u8) ParseError!Reference {
    if (input.len == 0) return error.Empty;

    // Reject whitespace and control characters early.
    for (input) |c| {
        if (c <= ' ') return error.InvalidReference;
    }

    // Step 1: split off @digest if present.
    var rest = input;
    var digest: ?Digest = null;
    var digest_raw: ?[]const u8 = null;

    if (std.mem.indexOfScalar(u8, input, '@')) |at_pos| {
        if (at_pos == 0) return error.InvalidReference;
        const raw = input[at_pos + 1 ..];
        const parsed_digest = Digest.parse(raw) catch return error.InvalidDigest;
        digest_raw = try allocator.dupe(u8, raw);
        digest = Digest{
            .algorithm = parsed_digest.algorithm,
            .hex = digest_raw.?[digest_raw.?.len - parsed_digest.hex.len ..],
        };
        rest = input[0..at_pos];
    }
    errdefer if (digest_raw) |dr| allocator.free(dr);

    // Step 2: identify registry vs Docker Hub path.
    var registry_str: []const u8 = DOCKER_HUB_REGISTRY;
    var path_str: []const u8 = rest;

    if (std.mem.indexOfScalar(u8, rest, '/')) |slash_pos| {
        const first = rest[0..slash_pos];
        if (looksLikeRegistry(first)) {
            registry_str = first;
            path_str = rest[slash_pos + 1 ..];
        }
        // else: first segment is an org name on Docker Hub, not a registry.
    }

    // Normalize Docker Hub aliases to the canonical pull endpoint.
    for (DOCKER_HUB_ALIASES) |alias| {
        if (std.ascii.eqlIgnoreCase(registry_str, alias)) {
            registry_str = DOCKER_HUB_REGISTRY;
            break;
        }
    }

    // Step 3: extract tag from the last path segment.
    // Only the last segment can carry a tag. Earlier colons are registry ports.
    var tag_str: ?[]const u8 = null;
    var repo_str = path_str;

    const last_slash = std.mem.lastIndexOfScalar(u8, path_str, '/');
    const last_seg_start: usize = if (last_slash) |ls| ls + 1 else 0;
    const last_seg = path_str[last_seg_start..];

    if (last_seg.len == 0) return error.InvalidReference;

    if (std.mem.indexOfScalar(u8, last_seg, ':')) |colon_in_seg| {
        tag_str = last_seg[colon_in_seg + 1 ..];
        if (tag_str.?.len == 0) return error.InvalidReference;
        repo_str = path_str[0 .. last_seg_start + colon_in_seg];
    }

    if (repo_str.len == 0) return error.InvalidReference;
    try validateRepositoryPath(repo_str);

    // Step 4: Docker Hub single-component names get "library/" prefix.
    // "ubuntu" becomes "library/ubuntu"; "myorg/ubuntu" stays as-is.
    const needs_library_prefix =
        std.ascii.eqlIgnoreCase(registry_str, DOCKER_HUB_REGISTRY) and
        std.mem.indexOfScalar(u8, repo_str, '/') == null;

    // Step 5: default tag "latest" when no tag and no digest.
    if (tag_str == null and digest == null) {
        tag_str = "latest";
    }

    // Step 6: allocate all fields.
    const registry_owned = try allocator.dupe(u8, registry_str);
    errdefer allocator.free(registry_owned);

    const repository_owned = if (needs_library_prefix)
        try duplicateLibraryRepositoryPath(allocator, repo_str)
    else
        try allocator.dupe(u8, repo_str);
    errdefer allocator.free(repository_owned);

    const tag_owned: ?[]const u8 = if (tag_str) |t|
        try allocator.dupe(u8, t)
    else
        null;
    // No errdefer needed: tag is the last allocation; nothing allocates after it.

    return Reference{
        .registry = registry_owned,
        .repository = repository_owned,
        .tag = tag_owned,
        .digest = digest,
        .digest_raw = digest_raw,
    };
}

fn duplicateLibraryRepositoryPath(allocator: std.mem.Allocator, repository: []const u8) ![]const u8 {
    const owned = try allocator.alloc(u8, DOCKER_HUB_LIBRARY_PREFIX.len + repository.len);
    @memcpy(owned[0..DOCKER_HUB_LIBRARY_PREFIX.len], DOCKER_HUB_LIBRARY_PREFIX);
    @memcpy(owned[DOCKER_HUB_LIBRARY_PREFIX.len..], repository);
    return owned;
}

pub fn deinit(self: *Reference, allocator: std.mem.Allocator) void {
    allocator.free(self.registry);
    allocator.free(self.repository);
    if (self.tag) |t| allocator.free(t);
    if (self.digest_raw) |dr| allocator.free(dr);
    // digest.hex points inside digest_raw, so freeing digest_raw is enough.
}

/// Repository path for /v2/{name}/manifests/{ref} URL construction.
pub fn repositoryPath(self: Reference) []const u8 {
    return self.repository;
}

/// Ref string for the manifest URL. Digest wins when both tag and digest are set.
/// Returns "sha256:hex" for digest refs, or the tag string otherwise.
pub fn refString(self: Reference) []const u8 {
    if (self.digest_raw) |dr| return dr;
    return self.tag.?; // parse() guarantees at least one is set
}

// Returns true when a path component looks like a registry hostname.
fn looksLikeRegistry(segment: []const u8) bool {
    // Dotted hostname: ghcr.io, registry.example.com
    if (std.mem.indexOfScalar(u8, segment, '.') != null) return true;
    // localhost without a port
    if (std.ascii.eqlIgnoreCase(segment, "localhost")) return true;
    // Any host with a port: colon followed by digits only
    if (std.mem.indexOfScalar(u8, segment, ':')) |colon| {
        const after = segment[colon + 1 ..];
        if (after.len == 0) return false;
        for (after) |c| {
            if (c < '0' or c > '9') return false;
        }
        return true;
    }
    return false;
}

fn validateRepositoryPath(repository: []const u8) ParseError!void {
    var start: usize = 0;
    while (start < repository.len) {
        const end = std.mem.indexOfScalarPos(u8, repository, start, '/') orelse repository.len;
        const segment = repository[start..end];
        if (!isValidRepositoryComponent(segment)) return error.InvalidReference;
        start = end + 1;
    }
}

fn isValidRepositoryComponent(segment: []const u8) bool {
    if (segment.len == 0) return false;
    if (!isRepositoryAlphaNum(segment[0])) return false;
    if (!isRepositoryAlphaNum(segment[segment.len - 1])) return false;

    for (segment) |c| {
        switch (c) {
            'a'...'z', '0'...'9', '.', '_', '-' => {},
            else => return false,
        }
    }

    return true;
}

fn isRepositoryAlphaNum(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9');
}

const ReferenceCorpusCase = struct {
    input: []const u8,
    registry: []const u8,
    repository: []const u8,
    repository_path: []const u8,
    ref_string: []const u8,
};

// Tests
//
// parse: Docker Hub bare names ------------------------------------------------

test "parse: bare name expands to docker hub, library prefix, and latest tag" {
    // Arrange
    const alloc = std.testing.allocator;
    // Act
    var ref = try parse(alloc, "ubuntu");
    defer ref.deinit(alloc);
    // Assert: all three defaults are applied in one step.
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/ubuntu", ref.repository);
    try std.testing.expectEqualSlices(u8, "latest", ref.tag.?);
    try std.testing.expect(ref.digest == null);
}

test "parse: bare name with explicit tag, library prefix still applied" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ubuntu:22.04");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/ubuntu", ref.repository);
    try std.testing.expectEqualSlices(u8, "22.04", ref.tag.?);
}

test "parse: bare name with digest, no tag, no latest default" {
    // When a digest is present and no tag, tag stays null (no latest default).
    const alloc = std.testing.allocator;
    const hex = "a" ** 64;
    var ref = try parse(alloc, "ubuntu@sha256:" ++ hex);
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/ubuntu", ref.repository);
    try std.testing.expect(ref.tag == null);
    try std.testing.expect(ref.digest != null);
    try std.testing.expectEqualSlices(u8, hex, ref.digest.?.hex);
}

test "parse: tag with hyphens and dots is preserved exactly" {
    // Tags like "20.04-slim" must not be truncated or modified.
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ubuntu:20.04-slim");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "20.04-slim", ref.tag.?);
}

// parse: Docker Hub org paths -------------------------------------------------

test "parse: org/image path on Docker Hub gets no library prefix" {
    // "myorg/myimage" already has a slash, so no library/ prefix is added.
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "myorg/myimage:v2");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "myorg/myimage", ref.repository);
    try std.testing.expectEqualSlices(u8, "v2", ref.tag.?);
}

// parse: explicit registries --------------------------------------------------

test "parse: full registry/owner/repo:tag" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ghcr.io/owner/repo:v1.0");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "ghcr.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "owner/repo", ref.repository);
    try std.testing.expectEqualSlices(u8, "v1.0", ref.tag.?);
}

test "parse: registry with port is detected as registry" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "localhost:5000/myimage:dev");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "localhost:5000", ref.registry);
    try std.testing.expectEqualSlices(u8, "myimage", ref.repository);
    try std.testing.expectEqualSlices(u8, "dev", ref.tag.?);
}

test "parse: localhost without port is treated as registry" {
    // "localhost" is a special case: no dot, no port, but always a registry.
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "localhost/myimage:dev");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "localhost", ref.registry);
    try std.testing.expectEqualSlices(u8, "myimage", ref.repository);
}

test "parse: deeply nested repository path is preserved" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "registry.example.com/org/team/image:latest");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry.example.com", ref.registry);
    try std.testing.expectEqualSlices(u8, "org/team/image", ref.repository);
    try std.testing.expectEqualSlices(u8, "latest", ref.tag.?);
}

test "parse: registry with dot and port together" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "registry.example.com:443/repo:tag");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry.example.com:443", ref.registry);
    try std.testing.expectEqualSlices(u8, "repo", ref.repository);
    try std.testing.expectEqualSlices(u8, "tag", ref.tag.?);
}

test "parse: no tag and no digest defaults tag to latest" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ghcr.io/owner/repo");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "latest", ref.tag.?);
}

// parse: Docker Hub alias normalization ---------------------------------------

test "parse: docker.io alias is normalized to registry-1.docker.io" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "docker.io/library/ubuntu:20.04");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/ubuntu", ref.repository);
    try std.testing.expectEqualSlices(u8, "20.04", ref.tag.?);
}

test "parse: index.docker.io alias is normalized to registry-1.docker.io" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "index.docker.io/library/alpine:3.18");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
}

test "parse: docker.io alias normalization is case-insensitive" {
    // "DOCKER.IO" must normalize the same as "docker.io".
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "DOCKER.IO/library/ubuntu:latest");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
}

test "parse: canonical docker hub hostname is normalized case-insensitively" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "REGISTRY-1.DOCKER.IO/ubuntu:latest");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/ubuntu", ref.repository);
}

// parse: digest and tag together ----------------------------------------------

test "parse: tag and digest together, both fields are set" {
    const alloc = std.testing.allocator;
    const hex = "b" ** 64;
    var ref = try parse(alloc, "image:mytag@sha256:" ++ hex);
    defer ref.deinit(alloc);
    // Both must be stored.
    try std.testing.expectEqualSlices(u8, "mytag", ref.tag.?);
    try std.testing.expect(ref.digest != null);
}

test "parse: tag and digest together, refString returns digest not tag" {
    // Digest is canonical. The tag is informational only.
    const alloc = std.testing.allocator;
    const hex = "b" ** 64;
    var ref = try parse(alloc, "image:mytag@sha256:" ++ hex);
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "sha256:" ++ hex, ref.refString());
}

test "parse: digest only (no tag), refString returns the digest string" {
    const alloc = std.testing.allocator;
    const hex = "c" ** 64;
    var ref = try parse(alloc, "ghcr.io/owner/repo@sha256:" ++ hex);
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "sha256:" ++ hex, ref.refString());
}

// parse: error cases ----------------------------------------------------------

test "parse: rejects empty input with error.Empty" {
    try std.testing.expectError(error.Empty, parse(std.testing.allocator, ""));
}

test "parse: rejects space in input with error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ubuntu 22.04"));
}

test "parse: rejects tab character in input with error.InvalidReference" {
    // Guards against only checking space (0x20) and missing other control chars.
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ubuntu\t22.04"));
}

test "parse: rejects newline in input with error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ubuntu\n22.04"));
}

test "parse: rejects leading @ with error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "@sha256:" ++ "a" ** 64));
}

test "parse: rejects invalid digest format with error.InvalidDigest" {
    try std.testing.expectError(error.InvalidDigest, parse(std.testing.allocator, "ubuntu@notadigest"));
}

test "parse: rejects trailing colon with error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ubuntu:"));
}

test "parse: rejects trailing slash with error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "myorg/"));
}

test "parse: rejects uppercase repository component with error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ghcr.io/Owner/repo:latest"));
}

test "parse: rejects empty repository path segment with error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ghcr.io/owner//repo:latest"));
}

test "parse: rejects repository component with colon with error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ghcr.io/owner:team/repo:latest"));
}

// repositoryPath and refString ------------------------------------------------

test "real-world corpus: common registry references normalize to expected repositoryPath and refString values" {
    const cases = [_]ReferenceCorpusCase{
        .{
            .input = "ubuntu",
            .registry = "registry-1.docker.io",
            .repository = "library/ubuntu",
            .repository_path = "library/ubuntu",
            .ref_string = "latest",
        },
        .{
            .input = "docker.io/library/busybox:latest",
            .registry = "registry-1.docker.io",
            .repository = "library/busybox",
            .repository_path = "library/busybox",
            .ref_string = "latest",
        },
        .{
            .input = "ghcr.io/opencontainers/distribution-spec:v1.1.0",
            .registry = "ghcr.io",
            .repository = "opencontainers/distribution-spec",
            .repository_path = "opencontainers/distribution-spec",
            .ref_string = "v1.1.0",
        },
        .{
            .input = "quay.io/prometheus/busybox:latest",
            .registry = "quay.io",
            .repository = "prometheus/busybox",
            .repository_path = "prometheus/busybox",
            .ref_string = "latest",
        },
        .{
            .input = "mcr.microsoft.com/dotnet/runtime:8.0",
            .registry = "mcr.microsoft.com",
            .repository = "dotnet/runtime",
            .repository_path = "dotnet/runtime",
            .ref_string = "8.0",
        },
        .{
            .input = "registry.k8s.io/pause:3.10",
            .registry = "registry.k8s.io",
            .repository = "pause",
            .repository_path = "pause",
            .ref_string = "3.10",
        },
        .{
            .input = "localhost:5001/team/api:dev",
            .registry = "localhost:5001",
            .repository = "team/api",
            .repository_path = "team/api",
            .ref_string = "dev",
        },
        .{
            .input = "registry-1.docker.io/library/busybox@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            .registry = "registry-1.docker.io",
            .repository = "library/busybox",
            .repository_path = "library/busybox",
            .ref_string = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        },
    };

    for (cases) |case| {
        var ref = try parse(std.testing.allocator, case.input);
        defer ref.deinit(std.testing.allocator);

        try std.testing.expectEqualSlices(u8, case.registry, ref.registry);
        try std.testing.expectEqualSlices(u8, case.repository, ref.repository);
        try std.testing.expectEqualSlices(u8, case.repository_path, ref.repositoryPath());
        try std.testing.expectEqualSlices(u8, case.ref_string, ref.refString());
    }
}

test "parse: digest hex remains valid after caller input is freed" {
    // Tighten the ownership contract: digest.hex must point into owned memory,
    // not into the caller input slice.
    const alloc = std.testing.allocator;
    const input = try alloc.dupe(u8, "ghcr.io/owner/repo@sha256:" ++ "d" ** 64);
    var ref = try parse(alloc, input);
    alloc.free(input);
    defer ref.deinit(alloc);

    try std.testing.expect(ref.digest != null);
    try std.testing.expectEqualSlices(u8, "d" ** 64, ref.digest.?.hex);
}

test "parse and deinit: digest ref frees digest_raw and owned digest hex" {
    // digest_raw owns the full "sha256:hex" string. digest.hex points inside it.
    // deinit must free that allocation exactly once.
    const alloc = std.testing.allocator;
    const hex = "d" ** 64;
    const input = "ghcr.io/owner/repo@sha256:" ++ hex;
    var ref = try parse(alloc, input);
    ref.deinit(alloc);
    // No leak: digest_raw was freed, digest.hex needed no separate cleanup.
}

test "parse: allocation failures do not leak partially constructed references" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, input: []const u8) !void {
            var ref = try parse(allocator, input);
            defer ref.deinit(allocator);

            try std.testing.expectEqualSlices(u8, "ghcr.io", ref.registry);
            try std.testing.expectEqualSlices(u8, "owner/repo", ref.repository);
            try std.testing.expectEqualSlices(u8, "v1", ref.tag.?);
            try std.testing.expect(ref.digest != null);
        }
    }.run, .{"ghcr.io/owner/repo:v1@sha256:" ++ "f" ** 64});
}

test "parse: mixed success and failure cases leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const alloc = gpa.allocator();

    const valid_inputs = [_][]const u8{
        "ubuntu:22.04",
        "ghcr.io/owner/repo:v1@sha256:" ++ "a" ** 64,
        "REGISTRY-1.DOCKER.IO/ubuntu:latest",
    };
    const invalid_cases = [_]struct { []const u8, ParseError }{
        .{ "ghcr.io/Owner/repo@sha256:" ++ "b" ** 64, error.InvalidReference },
        .{ "ghcr.io/owner/repo@notadigest", error.InvalidDigest },
        .{ "ghcr.io/owner//repo:latest", error.InvalidReference },
    };

    for (valid_inputs) |input| {
        var ref = try parse(alloc, input);
        ref.deinit(alloc);
    }

    for (invalid_cases) |case| {
        try std.testing.expectError(case[1], parse(alloc, case[0]));
    }
}

test "parse: 10000 pseudo-random inputs never panic and only return declared outcomes" {
    // Fuzz-style smoke test. Success paths must deinit cleanly.
    var seed: u64 = 0x51ce_b00c;
    var buf: [128]u8 = undefined;

    for (0..10_000) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const len: usize = @intCast(seed % (buf.len + 1));

        for (buf[0..len]) |*b| {
            seed = seed *% 6364136223846793005 +% 1;
            b.* = @truncate(seed >> 32);
        }

        const result = parse(std.testing.allocator, buf[0..len]);
        if (result) |ref| {
            var owned = ref;
            defer owned.deinit(std.testing.allocator);

            try std.testing.expect(owned.repository.len > 0);
            try std.testing.expect(owned.registry.len > 0);
            try std.testing.expectEqualSlices(u8, owned.repository, owned.repositoryPath());
            try std.testing.expect(owned.repository[owned.repository.len - 1] != '/');

            for (owned.registry) |c| try std.testing.expect(c > ' ');
            for (owned.repository) |c| try std.testing.expect(c > ' ');

            if (owned.digest) |digest| {
                try std.testing.expectEqual(Digest.Algorithm.sha256, digest.algorithm);
                try std.testing.expect(owned.digest_raw != null);
                try std.testing.expectEqualSlices(u8, owned.digest_raw.?, owned.refString());
                try std.testing.expect(std.mem.startsWith(u8, owned.digest_raw.?, "sha256:"));
                try std.testing.expectEqual(@as(usize, 64), digest.hex.len);
                for (digest.hex) |c| switch (c) {
                    '0'...'9', 'a'...'f', 'A'...'F' => {},
                    else => return error.TestUnexpectedResult,
                };
            } else {
                try std.testing.expect(owned.tag != null);
                try std.testing.expect(owned.tag.?.len > 0);
                try std.testing.expectEqualSlices(u8, owned.tag.?, owned.refString());
                for (owned.tag.?) |c| try std.testing.expect(c > ' ');
            }
        } else |err| switch (err) {
            error.Empty,
            error.InvalidDigest,
            error.InvalidReference,
            error.OutOfMemory,
            => {},
        }
    }
}

test "parse: 1000x repeated parse/deinit with varying inputs under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const alloc = gpa.allocator();

    const inputs = [_][]const u8{
        "ubuntu:22.04",
        "ghcr.io/owner/repo:v1@sha256:" ++ "a" ** 64,
        "REGISTRY-1.DOCKER.IO/ubuntu:latest",
        "localhost:5000/myimage:dev",
        "registry.example.com:443/repo:tag",
        "myorg/myimage:v2",
    };

    for (0..1000) |i| {
        const input = inputs[i % inputs.len];
        var ref = try parse(alloc, input);
        ref.deinit(alloc);
    }
}

test "parse: 1000x repeated parse with random-like valid inputs under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const alloc = gpa.allocator();

    const registries = [_][]const u8{ "ghcr.io", "docker.io", "quay.io", "gcr.io", "localhost:5000", "" };
    const repos = [_][]const u8{ "owner/repo", "library/ubuntu", "team/project/service", "myimage", "a/b/c/d" };
    const tags = [_][]const u8{ "latest", "v1.0", "22.04-slim", "" };

    var seed: u64 = 0x5e_ed_b0_0c;
    for (0..1000) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const reg = registries[@as(usize, @truncate(seed)) % registries.len];
        seed = seed *% 6364136223846793005 +% 1;
        const repo = repos[@as(usize, @truncate(seed)) % repos.len];
        seed = seed *% 6364136223846793005 +% 1;
        const tag = tags[@as(usize, @truncate(seed)) % tags.len];

        var buf: [256]u8 = undefined;
        var input: []const u8 = undefined;
        if (reg.len == 0) {
            if (tag.len == 0) {
                input = repo;
            } else {
                const s = try std.fmt.bufPrint(&buf, "{s}:{s}", .{ repo, tag });
                input = s;
            }
        } else {
            if (tag.len == 0) {
                const s = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ reg, repo });
                input = s;
            } else {
                const s = try std.fmt.bufPrint(&buf, "{s}/{s}:{s}", .{ reg, repo, tag });
                input = s;
            }
        }

        const result = parse(alloc, input);
        if (result) |ref| {
            var owned = ref;
            defer owned.deinit(alloc);
            try std.testing.expect(owned.registry.len > 0);
            try std.testing.expect(owned.repository.len > 0);
        } else |err| switch (err) {
            error.InvalidReference, error.InvalidDigest, error.Empty, error.OutOfMemory => {},
        }
    }
}
