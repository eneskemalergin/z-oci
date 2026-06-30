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

/// The pinned digest of the resolved manifest.
digest: Digest,
/// The manifest media type (OCI or Docker).
media_type: MediaType,
/// The platform if resolution targeted a specific platform. Null for
/// single-arch manifests or when platform was not requested.
platform: ?Platform,
/// The parsed image reference.
reference: Reference,

const ResolveResult = @This();

/// clone produces an independent deep copy of all slice fields.
///
/// Use case: move a ResolveResult into a different allocator or keep it after
/// a source arena teardown.
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

/// deinit frees all slices owned by this ResolveResult.
///
/// This is valid for values returned from the public `resolve` API and for
/// values produced by `clone()`.
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

// Tests

test "ResolveResult.clone: produces independent copy surviving arena teardown and mutation" {
    var cloned: ResolveResult = undefined;
    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        const arena_alloc = arena.allocator();

        var registry_buf = try arena_alloc.dupe(u8, "ghcr.io");
        const hex = try arena_alloc.dupe(u8, "a" ** 64);
        const original = ResolveResult{
            .digest = .{ .algorithm = .sha256, .hex = hex },
            .media_type = .oci_manifest_v1,
            .platform = null,
            .reference = Reference{
                .registry = registry_buf,
                .repository = try arena_alloc.dupe(u8, "owner/repo"),
                .tag = try arena_alloc.dupe(u8, "v1.0"),
                .digest = null,
                .digest_raw = null,
            },
        };

        cloned = try original.clone(std.testing.allocator);
        registry_buf[0] = 'X';
        arena.deinit();
    }
    defer cloned.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "a" ** 64, cloned.digest.hex);
    try std.testing.expectEqualSlices(u8, "ghcr.io", cloned.reference.registry);
    try std.testing.expectEqualSlices(u8, "owner/repo", cloned.reference.repository);
    try std.testing.expectEqualSlices(u8, "v1.0", cloned.reference.tag.?);
}

test "ResolveResult.clone: platform fields are deep copied" {
    // Arrange
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const original = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "c" ** 64) },
        .media_type = .oci_manifest_v1,
        .platform = Platform{
            .os = try arena_alloc.dupe(u8, "linux"),
            .architecture = try arena_alloc.dupe(u8, "arm64"),
            .variant = try arena_alloc.dupe(u8, "v8"),
            .os_version = null,
        },
        .reference = Reference{
            .registry = try arena_alloc.dupe(u8, "gcr.io"),
            .repository = try arena_alloc.dupe(u8, "proj/image"),
            .tag = null,
            .digest = null,
            .digest_raw = null,
        },
    };

    // Act
    var cloned = try original.clone(std.testing.allocator);
    defer cloned.deinit(std.testing.allocator);

    // Assert
    try std.testing.expect(cloned.platform != null);
    try std.testing.expectEqualSlices(u8, "linux", cloned.platform.?.os);
    try std.testing.expectEqualSlices(u8, "arm64", cloned.platform.?.architecture);
    try std.testing.expectEqualSlices(u8, "v8", cloned.platform.?.variant.?);
}

test "ResolveResult.clone: null platform clones as null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const original = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "d" ** 64) },
        .media_type = .oci_manifest_v1,
        .platform = null,
        .reference = Reference{
            .registry = try arena_alloc.dupe(u8, "r"),
            .repository = try arena_alloc.dupe(u8, "repo"),
            .tag = null,
            .digest = null,
            .digest_raw = null,
        },
    };

    var cloned = try original.clone(std.testing.allocator);
    defer cloned.deinit(std.testing.allocator);

    try std.testing.expect(cloned.platform == null);
}

test "ResolveResult.clone: os_features are deep copied" {
    // os_features is a slice of slices. All levels must be cloned.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const features = [_][]const u8{
        try arena_alloc.dupe(u8, "win32k"),
        try arena_alloc.dupe(u8, "hyperv"),
    };
    const original = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "f" ** 64) },
        .media_type = .oci_manifest_v1,
        .platform = Platform{
            .os = try arena_alloc.dupe(u8, "windows"),
            .architecture = try arena_alloc.dupe(u8, "amd64"),
            .os_features = &features,
        },
        .reference = Reference{
            .registry = try arena_alloc.dupe(u8, "mcr.microsoft.com"),
            .repository = try arena_alloc.dupe(u8, "windows/servercore"),
            .tag = null,
            .digest = null,
            .digest_raw = null,
        },
    };

    var cloned = try original.clone(std.testing.allocator);
    defer cloned.deinit(std.testing.allocator);

    // Assert: all feature strings are cloned and readable.
    const cf = cloned.platform.?.os_features.?;
    try std.testing.expectEqual(@as(usize, 2), cf.len);
    try std.testing.expectEqualSlices(u8, "win32k", cf[0]);
    try std.testing.expectEqualSlices(u8, "hyperv", cf[1]);
    // Pointers must differ: clone owns its own memory.
    try std.testing.expect(cf.ptr != features[0..].ptr);
}

test "ResolveResult.clone: full smoke test survives arena teardown" {
    // Clone a fully populated value, tear the source arena down, then read every field.
    var cloned: ResolveResult = undefined;
    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        const digest_hex = try arena_alloc.dupe(u8, "9" ** 64);
        const digest_raw = try arena_alloc.dupe(u8, "sha256:" ++ "9" ** 64);
        const features = [_][]const u8{
            try arena_alloc.dupe(u8, "win32k"),
            try arena_alloc.dupe(u8, "hyperv"),
        };

        const original = ResolveResult{
            .digest = .{ .algorithm = .sha256, .hex = digest_hex },
            .media_type = .docker_manifest_v2,
            .platform = Platform{
                .os = try arena_alloc.dupe(u8, "windows"),
                .architecture = try arena_alloc.dupe(u8, "amd64"),
                .variant = try arena_alloc.dupe(u8, "v1"),
                .os_version = try arena_alloc.dupe(u8, "10.0.20348.2402"),
                .os_features = &features,
            },
            .reference = Reference{
                .registry = try arena_alloc.dupe(u8, "mcr.microsoft.com"),
                .repository = try arena_alloc.dupe(u8, "windows/nanoserver"),
                .tag = try arena_alloc.dupe(u8, "ltsc2022"),
                .digest = .{ .algorithm = .sha256, .hex = digest_hex },
                .digest_raw = digest_raw,
            },
        };

        cloned = try original.clone(std.testing.allocator);
    }
    defer cloned.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "9" ** 64, cloned.digest.hex);
    try std.testing.expectEqualSlices(u8, "mcr.microsoft.com", cloned.reference.registry);
    try std.testing.expectEqualSlices(u8, "windows/nanoserver", cloned.reference.repository);
    try std.testing.expectEqualSlices(u8, "ltsc2022", cloned.reference.tag.?);
    try std.testing.expectEqualSlices(u8, "sha256:" ++ "9" ** 64, cloned.reference.digest_raw.?);
    try std.testing.expect(cloned.reference.digest != null);
    try std.testing.expectEqualSlices(u8, cloned.digest.hex, cloned.reference.digest.?.hex);
    try std.testing.expectEqualSlices(u8, "windows", cloned.platform.?.os);
    try std.testing.expectEqualSlices(u8, "10.0.20348.2402", cloned.platform.?.os_version.?);
    try std.testing.expectEqual(@as(usize, 2), cloned.platform.?.os_features.?.len);
}

test "ResolveResult.clone: reference digest remains distinct from resolved digest" {
    // The resolved manifest digest and the original reference digest are related,
    // but they are not guaranteed to be the same slice or even the same value.
    // clone() must preserve both independently.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const original = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "a" ** 64) },
        .media_type = .oci_manifest_v1,
        .platform = null,
        .reference = Reference{
            .registry = try arena_alloc.dupe(u8, "ghcr.io"),
            .repository = try arena_alloc.dupe(u8, "owner/repo"),
            .tag = null,
            .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "b" ** 64) },
            .digest_raw = try arena_alloc.dupe(u8, "sha256:" ++ "b" ** 64),
        },
    };

    var cloned = try original.clone(std.testing.allocator);
    defer cloned.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "a" ** 64, cloned.digest.hex);
    try std.testing.expectEqualSlices(u8, "b" ** 64, cloned.reference.digest.?.hex);
    try std.testing.expect(!std.mem.eql(u8, cloned.digest.hex, cloned.reference.digest.?.hex));
}

test "ResolveResult digest aliases: deinit and clone handle shared hex slices" {
    const cases = [_]enum {
        aliased_resolved_and_reference,
        reference_borrows_digest_raw,
        resolved_borrows_digest_raw,
        clone_from_digest_raw_borrow,
    }{
        .aliased_resolved_and_reference,
        .reference_borrows_digest_raw,
        .resolved_borrows_digest_raw,
        .clone_from_digest_raw_borrow,
    };
    for (cases) |scenario| {
        switch (scenario) {
            .aliased_resolved_and_reference => {
                const digest_hex = try std.testing.allocator.dupe(u8, "c" ** 64);
                errdefer std.testing.allocator.free(digest_hex);

                var owned = ResolveResult{
                    .digest = .{ .algorithm = .sha256, .hex = digest_hex },
                    .media_type = .oci_manifest_v1,
                    .platform = null,
                    .reference = .{
                        .registry = try std.testing.allocator.dupe(u8, "registry-1.docker.io"),
                        .repository = try std.testing.allocator.dupe(u8, "library/busybox"),
                        .tag = null,
                        .digest = .{ .algorithm = .sha256, .hex = digest_hex },
                        .digest_raw = try std.testing.allocator.dupe(u8, "sha256:" ++ "c" ** 64),
                    },
                };
                defer owned.deinit(std.testing.allocator);

                try std.testing.expect(owned.digest.hex.ptr == owned.reference.digest.?.hex.ptr);
            },
            .reference_borrows_digest_raw => {
                const digest_hex = try std.testing.allocator.dupe(u8, "d" ** 64);
                errdefer std.testing.allocator.free(digest_hex);

                const digest_raw = try std.testing.allocator.dupe(u8, "sha256:" ++ "e" ** 64);
                errdefer std.testing.allocator.free(digest_raw);

                var owned = ResolveResult{
                    .digest = .{ .algorithm = .sha256, .hex = digest_hex },
                    .media_type = .oci_manifest_v1,
                    .platform = null,
                    .reference = .{
                        .registry = try std.testing.allocator.dupe(u8, "ghcr.io"),
                        .repository = try std.testing.allocator.dupe(u8, "owner/repo"),
                        .tag = null,
                        .digest = .{
                            .algorithm = .sha256,
                            .hex = digest_raw[digest_raw.len - 64 ..],
                        },
                        .digest_raw = digest_raw,
                    },
                };
                defer owned.deinit(std.testing.allocator);

                try std.testing.expect(slicePointsInto(owned.reference.digest.?.hex, owned.reference.digest_raw.?));
            },
            .resolved_borrows_digest_raw => {
                var gpa = std.heap.DebugAllocator(.{}){};
                defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
                const alloc = gpa.allocator();

                const digest_raw = try alloc.dupe(u8, "sha256:" ++ "f" ** 64);

                var owned = ResolveResult{
                    .digest = .{
                        .algorithm = .sha256,
                        .hex = digest_raw[digest_raw.len - 64 ..],
                    },
                    .media_type = .oci_manifest_v1,
                    .platform = null,
                    .reference = .{
                        .registry = try alloc.dupe(u8, "registry-1.docker.io"),
                        .repository = try alloc.dupe(u8, "library/busybox"),
                        .tag = try alloc.dupe(u8, "latest"),
                        .digest = .{
                            .algorithm = .sha256,
                            .hex = digest_raw[digest_raw.len - 64 ..],
                        },
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
                            .digest = .{
                                .algorithm = .sha256,
                                .hex = digest_raw[digest_raw.len - 64 ..],
                            },
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

test "ResolveResult.deinit: full platform teardown leaves no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const alloc = gpa.allocator();

    const digest_raw = try alloc.dupe(u8, "sha256:" ++ "3" ** 64);
    const features = try alloc.alloc([]const u8, 2);
    features[0] = try alloc.dupe(u8, "win32k");
    features[1] = try alloc.dupe(u8, "hyperv");

    var owned = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = try alloc.dupe(u8, "2" ** 64) },
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
            try std.testing.expectEqualSlices(u8, "windows/nanoserver", cloned.reference.repository);
            try std.testing.expectEqualSlices(u8, "ltsc2022", cloned.reference.tag.?);
            try std.testing.expect(cloned.platform != null);
            try std.testing.expectEqualSlices(u8, "hyperv", cloned.platform.?.os_features.?[1]);
        }
    }.run, .{original});
}

test "ResolveResult.clone: repeated clone and deinit leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const alloc = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const digest_raw = try arena_alloc.dupe(u8, "sha256:" ++ "4" ** 64);
    const features = [_][]const u8{
        try arena_alloc.dupe(u8, "win32k"),
        try arena_alloc.dupe(u8, "hyperv"),
    };
    const original = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "5" ** 64) },
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
            .repository = try arena_alloc.dupe(u8, "windows/servercore"),
            .tag = try arena_alloc.dupe(u8, "ltsc2022"),
            .digest = .{ .algorithm = .sha256, .hex = digest_raw[digest_raw.len - 64 ..] },
            .digest_raw = digest_raw,
        },
    };

    for (0..32) |_| {
        var cloned = try original.clone(alloc);
        cloned.deinit(alloc);
    }
}
