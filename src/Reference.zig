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
//! - Manual struct literals must obey the same alias rule; `deinit` asserts it
//!   in Debug builds.
//! - Call `deinit()` exactly once for parsed values you keep outside an arena.

const std = @import("std");
const builtin = @import("builtin");
const Digest = @import("Digest.zig");

const DOCKER_HUB_LIBRARY_PREFIX = "library/";
const DOCKER_HUB_REGISTRY = "registry-1.docker.io";
const DOCKER_HUB_ALIASES = [_][]const u8{ "docker.io", "index.docker.io", DOCKER_HUB_REGISTRY };

registry: []const u8,
repository: []const u8,
/// If a digest is present, `refString()` returns it instead of this tag.
tag: ?[]const u8,
/// `.hex` points into `digest_raw` when set.
digest: ?Digest,
/// `"sha256:hex"` for `refString()`; freed by `deinit`.
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

    for (DOCKER_HUB_ALIASES) |alias| {
        if (std.ascii.eqlIgnoreCase(registry_str, alias)) {
            registry_str = DOCKER_HUB_REGISTRY;
            break;
        }
    }

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

    const needs_library_prefix =
        std.ascii.eqlIgnoreCase(registry_str, DOCKER_HUB_REGISTRY) and
        std.mem.indexOfScalar(u8, repo_str, '/') == null;

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

/// Manual construction must keep `digest.hex` inside `digest_raw` (Debug-asserted).
pub fn deinit(self: *Reference, allocator: std.mem.Allocator) void {
    if (builtin.mode == .Debug) {
        if (self.digest) |d| {
            if (self.digest_raw) |raw| {
                std.debug.assert(slicePointsInto(d.hex, raw));
            } else {
                std.debug.assert(false);
            }
        }
    }
    allocator.free(self.registry);
    allocator.free(self.repository);
    if (self.tag) |t| allocator.free(t);
    if (self.digest_raw) |dr| allocator.free(dr);
    // digest.hex points inside digest_raw, so freeing digest_raw is enough.
}

fn slicePointsInto(inner: []const u8, outer: []const u8) bool {
    const inner_start = @intFromPtr(inner.ptr);
    const outer_start = @intFromPtr(outer.ptr);
    return inner_start >= outer_start and inner_start + inner.len <= outer_start + outer.len;
}

pub fn repositoryPath(self: Reference) []const u8 {
    return self.repository;
}

/// Digest wins when both tag and digest are set; otherwise tag or `"latest"`.
pub fn refString(self: Reference) []const u8 {
    if (self.digest_raw) |dr| return dr;
    return self.tag orelse "latest";
}

fn looksLikeRegistry(segment: []const u8) bool {
    if (std.mem.indexOfScalar(u8, segment, '.') != null) return true;
    if (std.ascii.eqlIgnoreCase(segment, "localhost")) return true;
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

fn expectParseError(input: []const u8, expected: ParseError) !void {
    try std.testing.expectError(expected, parse(std.testing.allocator, input));
}

test "Reference.parse: happy path and Docker Hub normalization table" {
    const alloc = std.testing.allocator;
    const hex = "a" ** 64;
    const cases = [_]struct {
        input: []const u8,
        registry: []const u8,
        repository: []const u8,
        tag: ?[]const u8 = null,
        ref_string: ?[]const u8 = null,
        has_digest: bool = false,
    }{
        .{ .input = "ubuntu", .registry = DOCKER_HUB_REGISTRY, .repository = "library/ubuntu", .ref_string = "latest" },
        .{ .input = "ubuntu:22.04", .registry = DOCKER_HUB_REGISTRY, .repository = "library/ubuntu", .tag = "22.04", .ref_string = "22.04" },
        .{ .input = "ubuntu@sha256:" ++ hex, .registry = DOCKER_HUB_REGISTRY, .repository = "library/ubuntu", .has_digest = true },
        .{ .input = "ubuntu:20.04-slim", .registry = DOCKER_HUB_REGISTRY, .repository = "library/ubuntu", .tag = "20.04-slim", .ref_string = "20.04-slim" },
        .{ .input = "myorg/myimage:v2", .registry = DOCKER_HUB_REGISTRY, .repository = "myorg/myimage", .tag = "v2", .ref_string = "v2" },
        .{ .input = "ghcr.io/owner/repo:v1.0", .registry = "ghcr.io", .repository = "owner/repo", .tag = "v1.0", .ref_string = "v1.0" },
        .{ .input = "ghcr.io/owner/repo", .registry = "ghcr.io", .repository = "owner/repo", .ref_string = "latest" },
        .{ .input = "localhost:5000/myimage:dev", .registry = "localhost:5000", .repository = "myimage", .tag = "dev", .ref_string = "dev" },
        .{ .input = "localhost/myimage:dev", .registry = "localhost", .repository = "myimage", .tag = "dev", .ref_string = "dev" },
        .{ .input = "registry.example.com/org/team/image:latest", .registry = "registry.example.com", .repository = "org/team/image", .tag = "latest", .ref_string = "latest" },
        .{ .input = "registry.example.com:443/repo:tag", .registry = "registry.example.com:443", .repository = "repo", .tag = "tag", .ref_string = "tag" },
        .{ .input = "docker.io/library/ubuntu:20.04", .registry = DOCKER_HUB_REGISTRY, .repository = "library/ubuntu", .tag = "20.04", .ref_string = "20.04" },
        .{ .input = "index.docker.io/library/alpine:3.18", .registry = DOCKER_HUB_REGISTRY, .repository = "library/alpine", .tag = "3.18", .ref_string = "3.18" },
        .{ .input = "DOCKER.IO/library/ubuntu:latest", .registry = DOCKER_HUB_REGISTRY, .repository = "library/ubuntu", .tag = "latest", .ref_string = "latest" },
        .{ .input = "REGISTRY-1.DOCKER.IO/ubuntu:latest", .registry = DOCKER_HUB_REGISTRY, .repository = "library/ubuntu", .tag = "latest", .ref_string = "latest" },
    };

    for (cases) |case| {
        var ref = try parse(alloc, case.input);
        defer ref.deinit(alloc);
        try std.testing.expectEqualSlices(u8, case.registry, ref.registry);
        try std.testing.expectEqualSlices(u8, case.repository, ref.repository);
        if (case.tag) |tag| {
            try std.testing.expectEqualSlices(u8, tag, ref.tag.?);
        } else {
            try std.testing.expect(ref.tag == null);
        }
        try std.testing.expect((ref.digest != null) == case.has_digest);
        if (case.ref_string) |label| {
            try std.testing.expectEqualStrings(label, ref.refString());
        } else if (case.has_digest) {
            try std.testing.expectEqualSlices(u8, "sha256:" ++ hex, ref.refString());
        }
    }
}

test "Reference.parse: tag, digest, and refString precedence" {
    const alloc = std.testing.allocator;
    const hex = "b" ** 64;
    const cases = [_]struct {
        input: []const u8,
        tag: ?[]const u8,
        ref_string: []const u8,
    }{
        .{ .input = "image:mytag@sha256:" ++ hex, .tag = "mytag", .ref_string = "sha256:" ++ hex },
        .{ .input = "ghcr.io/owner/repo@sha256:" ++ hex, .tag = null, .ref_string = "sha256:" ++ hex },
    };

    for (cases) |case| {
        var ref = try parse(alloc, case.input);
        defer ref.deinit(alloc);
        if (case.tag) |tag| {
            try std.testing.expectEqualSlices(u8, tag, ref.tag.?);
        } else {
            try std.testing.expect(ref.tag == null);
        }
        try std.testing.expect(ref.digest != null);
        try std.testing.expectEqualSlices(u8, case.ref_string, ref.refString());
    }
}

test "Reference.parse: maps malformed input to exact ParseError" {
    const hex = "a" ** 64;
    const cases = [_]struct { input: []const u8, expected: ParseError }{
        .{ .input = "", .expected = error.Empty },
        .{ .input = "ubuntu 22.04", .expected = error.InvalidReference },
        .{ .input = "ubuntu\t22.04", .expected = error.InvalidReference },
        .{ .input = "ubuntu\n22.04", .expected = error.InvalidReference },
        .{ .input = "@sha256:" ++ hex, .expected = error.InvalidReference },
        .{ .input = "ubuntu@notadigest", .expected = error.InvalidDigest },
        .{ .input = "ubuntu:", .expected = error.InvalidReference },
        .{ .input = "myorg/", .expected = error.InvalidReference },
        .{ .input = "ghcr.io/Owner/repo:latest", .expected = error.InvalidReference },
        .{ .input = "ghcr.io/owner//repo:latest", .expected = error.InvalidReference },
        .{ .input = "ghcr.io/owner:team/repo:latest", .expected = error.InvalidReference },
    };
    for (cases) |case| try expectParseError(case.input, case.expected);
}

test "Reference: repositoryPath and refString match parse on real-world corpus" {
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

test "Reference.parse: digest borrows owned digest_raw after caller input is freed" {
    const alloc = std.testing.allocator;
    const input = try alloc.dupe(u8, "ghcr.io/owner/repo@sha256:" ++ "d" ** 64);
    var ref = try parse(alloc, input);
    alloc.free(input);
    defer ref.deinit(alloc);

    try std.testing.expect(ref.digest != null);
    try std.testing.expectEqualSlices(u8, "d" ** 64, ref.digest.?.hex);
    try std.testing.expectEqualSlices(u8, ref.digest_raw.?, ref.refString());
    try std.testing.expect(slicePointsInto(ref.digest.?.hex, ref.digest_raw.?));
}

test "Reference.deinit: Debug asserts digest.hex aliases digest_raw" {
    if (builtin.mode != .Debug) return;
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ghcr.io/owner/repo@sha256:" ++ "a" ** 64);
    defer ref.deinit(alloc);
    try std.testing.expect(slicePointsInto(ref.digest.?.hex, ref.digest_raw.?));
}

test "Reference.parse: allocation failures do not leak partially constructed references" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, input: []const u8) !void {
            var ref = try parse(allocator, input);
            defer ref.deinit(allocator);
            try std.testing.expectEqualSlices(u8, "ghcr.io", ref.registry);
            try std.testing.expect(ref.digest != null);
        }
    }.run, .{"ghcr.io/owner/repo:v1@sha256:" ++ "f" ** 64});
}

test "Reference.parse: pseudo-random inputs never panic" {
    var seed: u64 = 0x51ce_b00c;
    var buf: [128]u8 = undefined;

    for (0..512) |_| {
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
            if (owned.digest) |digest| {
                try std.testing.expect(owned.digest_raw != null);
                try std.testing.expectEqualSlices(u8, owned.digest_raw.?, owned.refString());
                try std.testing.expectEqual(@as(usize, 64), digest.hex.len);
            } else if (owned.tag == null) {
                try std.testing.expectEqualStrings("latest", owned.refString());
            }
        } else |err| switch (err) {
            error.Empty, error.InvalidDigest, error.InvalidReference, error.OutOfMemory => {},
        }
    }
}
