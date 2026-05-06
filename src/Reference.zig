//! Image reference parser. Handles the full Docker/OCI reference grammar.
//!
//! A reference is: [registry/]repository[:tag][@digest]
//!
//! Registry detection: a path component is a registry if it has a dot
//! (hostname), is "localhost", or has a colon followed only by digits (port).
//! Everything else is treated as a Docker Hub path, and single-component
//! names get "library/" prepended.
//!
//! docker.io and index.docker.io are normalized to registry-1.docker.io.
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

const docker_hub_registry = "registry-1.docker.io";
const docker_hub_aliases = [_][]const u8{ "docker.io", "index.docker.io" };

/// Owned registry hostname.
registry: []const u8,
/// Owned repository path.
repository: []const u8,
/// Informational when digest is also present. refString() returns the digest then.
tag: ?[]const u8,
/// Parsed digest. .hex points into digest_raw when a digest is present.
digest: ?Digest,
/// "sha256:hex" — allocated copy used by refString(). Freed by deinit.
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
    var registry_str: []const u8 = docker_hub_registry;
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
    for (docker_hub_aliases) |alias| {
        if (std.ascii.eqlIgnoreCase(registry_str, alias)) {
            registry_str = docker_hub_registry;
            break;
        }
    }

    // Step 3: extract tag from the last path segment.
    // Only the last segment can carry a tag — earlier colons are registry ports.
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

    // Step 4: Docker Hub single-component names get "library/" prefix.
    // "ubuntu" becomes "library/ubuntu"; "myorg/ubuntu" stays as-is.
    const needs_library_prefix =
        std.mem.eql(u8, registry_str, docker_hub_registry) and
        std.mem.indexOfScalar(u8, repo_str, '/') == null;

    // Step 5: default tag "latest" when no tag and no digest.
    if (tag_str == null and digest == null) {
        tag_str = "latest";
    }

    // Step 6: allocate all fields.
    const registry_owned = try allocator.dupe(u8, registry_str);
    errdefer allocator.free(registry_owned);

    const repository_owned = if (needs_library_prefix)
        try std.fmt.allocPrint(allocator, "library/{s}", .{repo_str})
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

// ── Tests ────────────────────────────────────────────────────────────────────
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
    // "myorg/myimage" has a slash, so it is already a full path — no library/ prefix.
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

test "parse: empty input returns error.Empty" {
    try std.testing.expectError(error.Empty, parse(std.testing.allocator, ""));
}

test "parse: space in input returns error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ubuntu 22.04"));
}

test "parse: tab character in input returns error.InvalidReference" {
    // Guards against only checking space (0x20) and missing other control chars.
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ubuntu\t22.04"));
}

test "parse: newline in input returns error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ubuntu\n22.04"));
}

test "parse: leading @ returns error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "@sha256:" ++ "a" ** 64));
}

test "parse: invalid digest format returns error.InvalidDigest" {
    try std.testing.expectError(error.InvalidDigest, parse(std.testing.allocator, "ubuntu@notadigest"));
}

test "parse: trailing colon returns error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "ubuntu:"));
}

test "parse: trailing slash returns error.InvalidReference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator, "myorg/"));
}

// repositoryPath and refString ------------------------------------------------

const ReferenceCorpusCase = struct {
    input: []const u8,
    registry: []const u8,
    repository: []const u8,
    repository_path: []const u8,
    ref_string: []const u8,
};

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

test "repositoryPath: returns the repository field" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ghcr.io/owner/repo:v1.0");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "owner/repo", ref.repositoryPath());
}

test "refString: returns tag when no digest is set" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ubuntu:22.04");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "22.04", ref.refString());
}

// lifecycle: memory management ------------------------------------------------

test "parse and deinit: testing allocator detects no leaks" {
    // The testing allocator fails the test if any allocation from parse()
    // is not freed by deinit(). This is the primary memory-safety check.
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ghcr.io/owner/repo:v1.0");
    ref.deinit(alloc);
    // If we reach here without a leak report, all fields were freed.
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
    // No leak → digest_raw was freed and digest.hex needed no separate cleanup.
}

test "parse and deinit: tag+digest ref frees all three string allocations" {
    const alloc = std.testing.allocator;
    const hex = "e" ** 64;
    var ref = try parse(alloc, "ghcr.io/owner/repo:v1@sha256:" ++ hex);
    ref.deinit(alloc);
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
