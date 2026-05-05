//! Result of a successful OCI registry resolve operation.
//!
//! All slice fields in the original borrow from the per-call arena.
//! Call clone() to produce an independent copy that outlives that arena.
//! Call deinit() on the clone when it is no longer needed.
//!
//! The original ResolveResult (not a clone) does not need deinit — the
//! caller's arena teardown handles all cleanup.

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
        // os_features is not cloned: the field is not used by resolve() or
        // filterByPlatform() in Phase 1, and cloning a slice of slices adds
        // complexity without benefit yet.

        platform = Platform{
            .os = plat_os.?,
            .architecture = plat_arch.?,
            .variant = plat_variant,
            .os_version = plat_os_version,
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
                .hex = digest_hex,
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
    allocator.free(self.digest.hex);
    if (self.reference.digest_raw) |dr| allocator.free(dr);
    if (self.platform) |p| {
        allocator.free(p.os);
        allocator.free(p.architecture);
        if (p.variant) |v| allocator.free(v);
        if (p.os_version) |v| allocator.free(v);
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
