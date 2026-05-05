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
//! Memory: parse() allocates all string fields into the provided allocator.
//! deinit() frees them. digest.hex borrows from the caller's input slice
//! (not from allocated memory) — consistent with Digest.zig.

const std = @import("std");
const Digest = @import("Digest.zig");

const docker_hub_registry = "registry-1.docker.io";
const docker_hub_aliases = [_][]const u8{ "docker.io", "index.docker.io" };

registry: []const u8,
repository: []const u8,
/// Informational when digest is also present. refString() returns the digest then.
tag: ?[]const u8,
/// Parsed digest. .hex borrows from the caller's input; not freed by deinit.
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
        digest = Digest.parse(raw) catch return error.InvalidDigest;
        digest_raw = try allocator.dupe(u8, raw);
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

    if (std.mem.indexOfScalar(u8, last_seg, ':')) |colon_in_seg| {
        tag_str = last_seg[colon_in_seg + 1 ..];
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
    // digest.hex borrows from caller input; not our memory to free.
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

test "parse: bare name defaults to docker hub, library prefix, latest tag" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ubuntu");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/ubuntu", ref.repository);
    try std.testing.expectEqualSlices(u8, "latest", ref.tag.?);
    try std.testing.expect(ref.digest == null);
}

test "parse: bare name with explicit tag" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ubuntu:22.04");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/ubuntu", ref.repository);
    try std.testing.expectEqualSlices(u8, "22.04", ref.tag.?);
}

test "parse: bare name with digest" {
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

test "parse: full path with explicit registry" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ghcr.io/owner/repo:v1.0");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "ghcr.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "owner/repo", ref.repository);
    try std.testing.expectEqualSlices(u8, "v1.0", ref.tag.?);
}

test "parse: registry with port" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "localhost:5000/myimage:dev");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "localhost:5000", ref.registry);
    try std.testing.expectEqualSlices(u8, "myimage", ref.repository);
    try std.testing.expectEqualSlices(u8, "dev", ref.tag.?);
}

test "parse: nested repository path" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "registry.example.com/org/team/image:latest");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry.example.com", ref.registry);
    try std.testing.expectEqualSlices(u8, "org/team/image", ref.repository);
    try std.testing.expectEqualSlices(u8, "latest", ref.tag.?);
}

test "parse: tag and digest together (digest wins for refString)" {
    const alloc = std.testing.allocator;
    const hex = "b" ** 64;
    var ref = try parse(alloc, "image:mytag@sha256:" ++ hex);
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "mytag", ref.tag.?);
    try std.testing.expect(ref.digest != null);
    try std.testing.expectEqualSlices(u8, "sha256:" ++ hex, ref.refString());
}

test "parse: docker.io alias normalized to registry-1.docker.io" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "docker.io/library/ubuntu:20.04");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "library/ubuntu", ref.repository);
    try std.testing.expectEqualSlices(u8, "20.04", ref.tag.?);
}

test "parse: index.docker.io alias normalized" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "index.docker.io/library/alpine:3.18");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
}

test "parse: org path on Docker Hub (no library prefix)" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "myorg/myimage:v2");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", ref.registry);
    try std.testing.expectEqualSlices(u8, "myorg/myimage", ref.repository);
    try std.testing.expectEqualSlices(u8, "v2", ref.tag.?);
}

test "parse: no tag and no digest defaults to latest" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ghcr.io/owner/repo");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "latest", ref.tag.?);
}

test "parse: empty input returns error.Empty" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.Empty, parse(alloc, ""));
}

test "parse: whitespace returns error.InvalidReference" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.InvalidReference, parse(alloc, "ubuntu 22.04"));
}

test "parse: leading @ returns error.InvalidReference" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.InvalidReference, parse(alloc, "@sha256:" ++ "a" ** 64));
}

test "parse: bad digest returns error.InvalidDigest" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.InvalidDigest, parse(alloc, "ubuntu@notadigest"));
}

test "repositoryPath returns repository" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ghcr.io/owner/repo:v1.0");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "owner/repo", ref.repositoryPath());
}

test "refString returns tag when no digest" {
    const alloc = std.testing.allocator;
    var ref = try parse(alloc, "ubuntu:22.04");
    defer ref.deinit(alloc);
    try std.testing.expectEqualSlices(u8, "22.04", ref.refString());
}
