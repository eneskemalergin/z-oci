//! Result of a successful OCI registry resolve operation.
//!
//! Values returned from the public `resolve` API are owned by the caller's
//! allocator and may be released with `deinit()`.
//!
//! `clone()` remains useful when you want to copy a result into a different
//! allocator or keep it alive after tearing a source arena down.
//!
//! Ownership:
//! - values returned from public resolve calls are owned by the caller allocator
//! - `clone()` produces an independent owned copy in a target allocator
//! - some owned layouts intentionally alias digest slices to avoid extra copies;
//!   `deinit()` handles those aliases safely

const std = @import("std");
const Digest = @import("Digest.zig");
const MediaType = @import("MediaType.zig").MediaType;
const Platform = @import("Platform.zig");
const Reference = @import("Reference.zig");

digest: Digest,
media_type: MediaType,
platform: ?Platform,
reference: Reference,

const ResolveResult = @This();

pub fn clone(self: ResolveResult, allocator: std.mem.Allocator) !ResolveResult {
    const registry = try allocator.dupe(u8, self.reference.registry);
    errdefer allocator.free(registry);

    const repository = try allocator.dupe(u8, self.reference.repository);
    errdefer allocator.free(repository);

    const tag: ?[]const u8 = if (self.reference.tag) |t|
        try allocator.dupe(u8, t)
    else
        null;
    errdefer if (tag) |t| allocator.free(t);

    const digest_hex = try allocator.dupe(u8, self.digest.hex);
    errdefer allocator.free(digest_hex);

    const reference_digest_hex: ?[]const u8 = if (self.reference.digest) |d|
        try allocator.dupe(u8, d.hex)
    else
        null;
    errdefer if (reference_digest_hex) |hex| allocator.free(hex);

    const digest_raw: ?[]const u8 = if (self.reference.digest_raw) |dr|
        try allocator.dupe(u8, dr)
    else
        null;
    errdefer if (digest_raw) |dr| allocator.free(dr);

    var platform: ?Platform = null;
    var plat_os: ?[]const u8 = null;
    var plat_arch: ?[]const u8 = null;
    var plat_variant: ?[]const u8 = null;
    var plat_os_version: ?[]const u8 = null;
    var plat_os_features: ?[]const []const u8 = null;

    if (self.platform) |p| {
        plat_os = try allocator.dupe(u8, p.os);
        errdefer if (plat_os) |s| allocator.free(s);

        plat_arch = try allocator.dupe(u8, p.architecture);
        errdefer if (plat_arch) |s| allocator.free(s);

        if (p.variant) |v| {
            plat_variant = try allocator.dupe(u8, v);
        }
        errdefer if (plat_variant) |s| allocator.free(s);

        if (p.os_version) |v| {
            plat_os_version = try allocator.dupe(u8, v);
        }
        errdefer if (plat_os_version) |s| allocator.free(s);

        if (p.os_features) |features| {
            const outer = try allocator.alloc([]const u8, features.len);
            errdefer allocator.free(outer);
            var n_cloned: usize = 0;
            errdefer for (outer[0..n_cloned]) |s| allocator.free(s);
            for (features, 0..) |feat, i| {
                outer[i] = try allocator.dupe(u8, feat);
                n_cloned += 1;
            }
            plat_os_features = outer;
        }

        platform = Platform{
            .os = plat_os.?,
            .architecture = plat_arch.?,
            .variant = plat_variant,
            .os_version = plat_os_version,
            .os_features = plat_os_features,
        };
    }

    return ResolveResult{
        .digest = Digest{
            .algorithm = self.digest.algorithm,
            .hex = digest_hex,
        },
        .media_type = self.media_type,
        .platform = platform,
        .reference = Reference{
            .registry = registry,
            .repository = repository,
            .tag = tag,
            .digest = if (self.reference.digest) |d| Digest{
                .algorithm = d.algorithm,
                .hex = reference_digest_hex.?,
            } else null,
            .digest_raw = digest_raw,
        },
    };
}

pub fn deinit(self: *ResolveResult, allocator: std.mem.Allocator) void {
    allocator.free(self.reference.registry);
    allocator.free(self.reference.repository);
    if (self.reference.tag) |t| allocator.free(t);
    if (self.reference.digest) |d| {
        if (shouldFreeReferenceDigestHex(self.*, d.hex)) allocator.free(d.hex);
    }
    if (shouldFreeResolvedDigestHex(self.*)) allocator.free(self.digest.hex);
    if (self.reference.digest_raw) |dr| allocator.free(dr);
    if (self.platform) |p| {
        allocator.free(p.os);
        allocator.free(p.architecture);
        if (p.variant) |v| allocator.free(v);
        if (p.os_version) |v| allocator.free(v);
        if (p.os_features) |features| {
            for (features) |feat| allocator.free(feat);
            allocator.free(features);
        }
    }
}

fn shouldFreeReferenceDigestHex(self: ResolveResult, hex: []const u8) bool {
    if (hex.ptr == self.digest.hex.ptr) return false;
    if (self.reference.digest_raw) |raw| {
        if (slicePointsInto(hex, raw)) return false;
    }
    return true;
}

fn shouldFreeResolvedDigestHex(self: ResolveResult) bool {
    if (self.reference.digest_raw) |raw| {
        if (slicePointsInto(self.digest.hex, raw)) return false;
    }
    return true;
}

fn slicePointsInto(inner: []const u8, outer: []const u8) bool {
    const inner_start = @intFromPtr(inner.ptr);
    const outer_start = @intFromPtr(outer.ptr);
    return inner_start >= outer_start and inner_start + inner.len <= outer_start + outer.len;
}

const sha256_a = "a" ** 64;
const sha256_b = "b" ** 64;
const sha256_f = "f" ** 64;

fn dupe(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return allocator.dupe(u8, bytes);
}

test "ResolveResult.clone: deep copies owned fields and survives arena teardown" {
    const CloneScenario = enum {
        basic_with_tag,
        null_platform,
        platform_with_os_features,
        distinct_reference_digest,
    };
    const cases = [_]CloneScenario{
        .basic_with_tag,
        .null_platform,
        .platform_with_os_features,
        .distinct_reference_digest,
    };

    for (cases) |scenario| {
        var cloned: ResolveResult = undefined;
        var registry_buf: ?[]u8 = null;
        {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            const arena_alloc = arena.allocator();

            const original: ResolveResult = switch (scenario) {
                .basic_with_tag => blk: {
                    registry_buf = try dupe(arena_alloc, "ghcr.io");
                    break :blk ResolveResult{
                        .digest = .{ .algorithm = .sha256, .hex = try dupe(arena_alloc, sha256_a) },
                        .media_type = .oci_manifest_v1,
                        .platform = null,
                        .reference = .{
                            .registry = registry_buf.?,
                            .repository = try dupe(arena_alloc, "owner/repo"),
                            .tag = try dupe(arena_alloc, "v1.0"),
                            .digest = null,
                            .digest_raw = null,
                        },
                    };
                },
                .null_platform => ResolveResult{
                    .digest = .{ .algorithm = .sha256, .hex = try dupe(arena_alloc, "d" ** 64) },
                    .media_type = .oci_manifest_v1,
                    .platform = null,
                    .reference = .{
                        .registry = try dupe(arena_alloc, "r"),
                        .repository = try dupe(arena_alloc, "repo"),
                        .tag = null,
                        .digest = null,
                        .digest_raw = null,
                    },
                },
                .platform_with_os_features => blk: {
                    const features = [_][]const u8{
                        try dupe(arena_alloc, "win32k"),
                        try dupe(arena_alloc, "hyperv"),
                    };
                    break :blk ResolveResult{
                        .digest = .{ .algorithm = .sha256, .hex = try dupe(arena_alloc, "c" ** 64) },
                        .media_type = .oci_manifest_v1,
                        .platform = .{
                            .os = try dupe(arena_alloc, "linux"),
                            .architecture = try dupe(arena_alloc, "arm64"),
                            .variant = try dupe(arena_alloc, "v8"),
                            .os_version = null,
                            .os_features = &features,
                        },
                        .reference = .{
                            .registry = try dupe(arena_alloc, "gcr.io"),
                            .repository = try dupe(arena_alloc, "proj/image"),
                            .tag = null,
                            .digest = null,
                            .digest_raw = null,
                        },
                    };
                },
                .distinct_reference_digest => ResolveResult{
                    .digest = .{ .algorithm = .sha256, .hex = try dupe(arena_alloc, sha256_a) },
                    .media_type = .oci_manifest_v1,
                    .platform = null,
                    .reference = .{
                        .registry = try dupe(arena_alloc, "ghcr.io"),
                        .repository = try dupe(arena_alloc, "owner/repo"),
                        .tag = null,
                        .digest = .{ .algorithm = .sha256, .hex = try dupe(arena_alloc, sha256_b) },
                        .digest_raw = try dupe(arena_alloc, "sha256:" ++ sha256_b),
                    },
                },
            };

            cloned = try original.clone(std.testing.allocator);
            if (registry_buf) |buf| buf[0] = 'X';
            arena.deinit();
        }
        defer cloned.deinit(std.testing.allocator);

        switch (scenario) {
            .basic_with_tag => {
                try std.testing.expectEqualSlices(u8, sha256_a, cloned.digest.hex);
                try std.testing.expectEqualSlices(u8, "ghcr.io", cloned.reference.registry);
                try std.testing.expectEqualSlices(u8, "owner/repo", cloned.reference.repository);
                try std.testing.expectEqualSlices(u8, "v1.0", cloned.reference.tag.?);
            },
            .null_platform => try std.testing.expect(cloned.platform == null),
            .platform_with_os_features => {
                const platform = cloned.platform.?;
                try std.testing.expectEqualSlices(u8, "linux", platform.os);
                try std.testing.expectEqualSlices(u8, "arm64", platform.architecture);
                try std.testing.expectEqualSlices(u8, "v8", platform.variant.?);
                const features = platform.os_features.?;
                try std.testing.expectEqual(@as(usize, 2), features.len);
                try std.testing.expectEqualSlices(u8, "win32k", features[0]);
                try std.testing.expectEqualSlices(u8, "hyperv", features[1]);
            },
            .distinct_reference_digest => {
                try std.testing.expectEqualSlices(u8, sha256_a, cloned.digest.hex);
                try std.testing.expectEqualSlices(u8, sha256_b, cloned.reference.digest.?.hex);
                try std.testing.expect(!std.mem.eql(u8, cloned.digest.hex, cloned.reference.digest.?.hex));
            },
        }
    }
}

test "ResolveResult: digest alias layouts deinit and clone safely" {
    const AliasScenario = enum {
        aliased_resolved_and_reference,
        reference_borrows_digest_raw,
        resolved_borrows_digest_raw_with_platform,
        clone_from_digest_raw_borrow,
    };
    const cases = [_]AliasScenario{
        .aliased_resolved_and_reference,
        .reference_borrows_digest_raw,
        .resolved_borrows_digest_raw_with_platform,
        .clone_from_digest_raw_borrow,
    };

    for (cases) |scenario| {
        switch (scenario) {
            .aliased_resolved_and_reference => {
                const digest_hex = try dupe(std.testing.allocator, "c" ** 64);
                errdefer std.testing.allocator.free(digest_hex);

                var owned = ResolveResult{
                    .digest = .{ .algorithm = .sha256, .hex = digest_hex },
                    .media_type = .oci_manifest_v1,
                    .platform = null,
                    .reference = .{
                        .registry = try dupe(std.testing.allocator, "registry-1.docker.io"),
                        .repository = try dupe(std.testing.allocator, "library/busybox"),
                        .tag = null,
                        .digest = .{ .algorithm = .sha256, .hex = digest_hex },
                        .digest_raw = try dupe(std.testing.allocator, "sha256:" ++ "c" ** 64),
                    },
                };
                defer owned.deinit(std.testing.allocator);
                try std.testing.expect(owned.digest.hex.ptr == owned.reference.digest.?.hex.ptr);
            },
            .reference_borrows_digest_raw => {
                const digest_hex = try dupe(std.testing.allocator, "d" ** 64);
                errdefer std.testing.allocator.free(digest_hex);
                const digest_raw = try dupe(std.testing.allocator, "sha256:" ++ "e" ** 64);
                errdefer std.testing.allocator.free(digest_raw);

                var owned = ResolveResult{
                    .digest = .{ .algorithm = .sha256, .hex = digest_hex },
                    .media_type = .oci_manifest_v1,
                    .platform = null,
                    .reference = .{
                        .registry = try dupe(std.testing.allocator, "ghcr.io"),
                        .repository = try dupe(std.testing.allocator, "owner/repo"),
                        .tag = null,
                        .digest = .{ .algorithm = .sha256, .hex = digest_raw[digest_raw.len - 64 ..] },
                        .digest_raw = digest_raw,
                    },
                };
                defer owned.deinit(std.testing.allocator);
                try std.testing.expect(slicePointsInto(owned.reference.digest.?.hex, owned.reference.digest_raw.?));
            },
            .resolved_borrows_digest_raw_with_platform => {
                var gpa = std.heap.DebugAllocator(.{}){};
                defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
                const alloc = gpa.allocator();

                const digest_raw = try alloc.dupe(u8, "sha256:" ++ sha256_f);
                const features = try alloc.alloc([]const u8, 2);
                features[0] = try alloc.dupe(u8, "win32k");
                features[1] = try alloc.dupe(u8, "hyperv");

                var owned = ResolveResult{
                    .digest = .{ .algorithm = .sha256, .hex = digest_raw[digest_raw.len - 64 ..] },
                    .media_type = .docker_manifest_v2,
                    .platform = .{
                        .os = try alloc.dupe(u8, "windows"),
                        .architecture = try alloc.dupe(u8, "amd64"),
                        .variant = try alloc.dupe(u8, "v1"),
                        .os_version = try alloc.dupe(u8, "10.0.20348.2402"),
                        .os_features = features,
                    },
                    .reference = .{
                        .registry = try alloc.dupe(u8, "mcr.microsoft.com"),
                        .repository = try alloc.dupe(u8, "windows/servercore"),
                        .tag = try alloc.dupe(u8, "ltsc2022"),
                        .digest = .{ .algorithm = .sha256, .hex = digest_raw[digest_raw.len - 64 ..] },
                        .digest_raw = digest_raw,
                    },
                };
                owned.deinit(alloc);
            },
            .clone_from_digest_raw_borrow => {
                var cloned: ResolveResult = undefined;
                {
                    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
                    defer arena.deinit();
                    const arena_alloc = arena.allocator();
                    const digest_raw = try arena_alloc.dupe(u8, "sha256:" ++ "7" ** 64);
                    const original = ResolveResult{
                        .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "6" ** 64) },
                        .media_type = .oci_manifest_v1,
                        .platform = null,
                        .reference = .{
                            .registry = try arena_alloc.dupe(u8, "ghcr.io"),
                            .repository = try arena_alloc.dupe(u8, "owner/repo"),
                            .tag = null,
                            .digest = .{ .algorithm = .sha256, .hex = digest_raw[digest_raw.len - 64 ..] },
                            .digest_raw = digest_raw,
                        },
                    };
                    cloned = try original.clone(std.testing.allocator);
                }
                defer cloned.deinit(std.testing.allocator);
                try std.testing.expectEqualSlices(u8, "7" ** 64, cloned.reference.digest.?.hex);
                try std.testing.expect(!slicePointsInto(cloned.reference.digest.?.hex, cloned.reference.digest_raw.?));
            },
        }
    }
}

test "ResolveResult.clone: allocation failures do not leak partially cloned state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const digest_raw = try arena_alloc.dupe(u8, "sha256:" ++ "8" ** 64);
    const features = [_][]const u8{
        try arena_alloc.dupe(u8, "win32k"),
        try arena_alloc.dupe(u8, "hyperv"),
    };
    const original = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "9" ** 64) },
        .media_type = .docker_manifest_v2,
        .platform = .{
            .os = try arena_alloc.dupe(u8, "windows"),
            .architecture = try arena_alloc.dupe(u8, "amd64"),
            .variant = try arena_alloc.dupe(u8, "v1"),
            .os_version = try arena_alloc.dupe(u8, "10.0.20348.2402"),
            .os_features = &features,
        },
        .reference = .{
            .registry = try arena_alloc.dupe(u8, "mcr.microsoft.com"),
            .repository = try arena_alloc.dupe(u8, "windows/nanoserver"),
            .tag = try arena_alloc.dupe(u8, "ltsc2022"),
            .digest = .{ .algorithm = .sha256, .hex = digest_raw[digest_raw.len - 64 ..] },
            .digest_raw = digest_raw,
        },
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, source: ResolveResult) !void {
            var cloned = try source.clone(allocator);
            defer cloned.deinit(allocator);
            try std.testing.expectEqualSlices(u8, "mcr.microsoft.com", cloned.reference.registry);
            try std.testing.expectEqualSlices(u8, "hyperv", cloned.platform.?.os_features.?[1]);
        }
    }.run, .{original});
}
