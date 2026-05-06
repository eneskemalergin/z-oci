//! Result of a successful OCI registry resolve operation.
//!
//! All slice fields in the original borrow from the per-call arena.
//! Call clone() to produce an independent copy that outlives that arena.
//! Call deinit() on the clone when it is no longer needed.
//!
//! The original ResolveResult (not a clone) does not need deinit — the
//! caller's arena teardown handles all cleanup.
//!
//! Ownership:
//! - values returned from future resolve calls borrow from the per-call allocator
//! - `clone()` produces a fully owned copy of every string slice
//! - the cloned `reference.digest.hex` may be distinct from `digest.hex` and is freed accordingly

const std = @import("std");
const Digest = @import("Digest.zig");
const MediaType = @import("MediaType.zig").MediaType;
const Platform = @import("Platform.zig");
const Reference = @import("Reference.zig");

/// The pinned digest of the resolved manifest. Borrowed in originals, owned in clones.
digest: Digest,
/// The manifest media type (OCI or Docker).
media_type: MediaType,
/// The platform if resolution targeted a specific platform. Null for
/// single-arch manifests or when platform was not requested.
platform: ?Platform,
/// The parsed image reference. Borrowed in originals, deep-copied by clone().
reference: Reference,

const ResolveResult = @This();

/// clone produces an independent deep copy of all slice fields.
///
/// Use case: batch resolve that keeps results after per-image arena teardown.
/// The caller owns the returned ResolveResult and must call deinit(allocator).
pub fn clone(self: ResolveResult, allocator: std.mem.Allocator) !ResolveResult {
    // Clone reference string fields.
    const registry = try allocator.dupe(u8, self.reference.registry);
    errdefer allocator.free(registry);

    const repository = try allocator.dupe(u8, self.reference.repository);
    errdefer allocator.free(repository);

    const tag: ?[]const u8 = if (self.reference.tag) |t|
        try allocator.dupe(u8, t)
    else
        null;
    errdefer if (tag) |t| allocator.free(t);

    // digest.hex borrows from caller input in the original, so clone it.
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

    // Clone platform string fields if present.
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
            errdefer if (plat_variant) |s| allocator.free(s);
        }
        if (p.os_version) |v| {
            plat_os_version = try allocator.dupe(u8, v);
            errdefer if (plat_os_version) |s| allocator.free(s);
        }
        if (p.os_features) |features| {
            // Clone the outer slice, then clone each inner string.
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

/// deinit frees all slices allocated by clone().
/// Do not call on the original ResolveResult — its memory belongs to the arena.
pub fn deinit(self: *ResolveResult, allocator: std.mem.Allocator) void {
    allocator.free(self.reference.registry);
    allocator.free(self.reference.repository);
    if (self.reference.tag) |t| allocator.free(t);
    if (self.reference.digest) |d| {
        if (d.hex.ptr != self.digest.hex.ptr) allocator.free(d.hex);
    }
    allocator.free(self.digest.hex);
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

// ── Tests ────────────────────────────────────────────────────────────────────

test "ResolveResult.clone: deep copy produces independent memory" {
    // Arrange: build a result backed by a short-lived arena.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const hex = try arena_alloc.dupe(u8, "a" ** 64);
    const original = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = hex },
        .media_type = .oci_manifest_v1,
        .platform = null,
        .reference = Reference{
            .registry = try arena_alloc.dupe(u8, "ghcr.io"),
            .repository = try arena_alloc.dupe(u8, "owner/repo"),
            .tag = try arena_alloc.dupe(u8, "v1.0"),
            .digest = null,
            .digest_raw = null,
        },
    };

    // Act: clone into testing.allocator before destroying the arena.
    var cloned = try original.clone(std.testing.allocator);
    defer cloned.deinit(std.testing.allocator);

    // Assert: cloned values match.
    try std.testing.expectEqualSlices(u8, "a" ** 64, cloned.digest.hex);
    try std.testing.expectEqualSlices(u8, "ghcr.io", cloned.reference.registry);
    try std.testing.expectEqualSlices(u8, "owner/repo", cloned.reference.repository);
    try std.testing.expectEqualSlices(u8, "v1.0", cloned.reference.tag.?);
}

test "ResolveResult.clone: clone is independent after arena teardown" {
    // Arrange: build result in a temporary arena, clone, then destroy arena.
    var cloned: ResolveResult = undefined;
    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        const hex = try arena_alloc.dupe(u8, "b" ** 64);
        const original = ResolveResult{
            .digest = .{ .algorithm = .sha256, .hex = hex },
            .media_type = .docker_manifest_v2,
            .platform = null,
            .reference = Reference{
                .registry = try arena_alloc.dupe(u8, "registry-1.docker.io"),
                .repository = try arena_alloc.dupe(u8, "library/alpine"),
                .tag = try arena_alloc.dupe(u8, "latest"),
                .digest = null,
                .digest_raw = null,
            },
        };
        cloned = try original.clone(std.testing.allocator);
        // Arena destroyed here.
    }
    defer cloned.deinit(std.testing.allocator);

    // Assert: clone still valid after arena is gone.
    try std.testing.expectEqualSlices(u8, "b" ** 64, cloned.digest.hex);
    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", cloned.reference.registry);
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

test "ResolveResult.clone: clone is independent from original" {
    // Mutating the original after cloning must not affect the clone.
    // This verifies deep copy, not a shallow pointer copy.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const arena_alloc = arena.allocator();

    var registry_buf = try arena_alloc.dupe(u8, "ghcr.io");
    const original = ResolveResult{
        .digest = .{ .algorithm = .sha256, .hex = try arena_alloc.dupe(u8, "e" ** 64) },
        .media_type = .oci_manifest_v1,
        .platform = null,
        .reference = Reference{
            .registry = registry_buf,
            .repository = try arena_alloc.dupe(u8, "owner/repo"),
            .tag = null,
            .digest = null,
            .digest_raw = null,
        },
    };

    var cloned = try original.clone(std.testing.allocator);
    defer cloned.deinit(std.testing.allocator);

    // Mutate the original registry string in-place after cloning.
    registry_buf[0] = 'X';
    arena.deinit();

    // Clone must retain the unmodified value.
    try std.testing.expectEqualSlices(u8, "ghcr.io", cloned.reference.registry);
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
    // This is the Phase 1 memory-model smoke test: clone a fully populated value,
    // tear the source arena down, then read every important field from the clone.
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
