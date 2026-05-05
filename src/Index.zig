//! Multi-arch manifest index types.
//!
//! OciImageIndex and DockerManifestList are distinct spec types but share
//! the same resolution logic: both carry a list of Descriptors, each with
//! a platform field pointing at a single-arch manifest.
//!
//! MultiArchManifest is the tagged union callers use. It hides which spec
//! variant is underneath and exposes descriptors() and filterByPlatform().
//!
//! JSON field mapping is deferred to json.zig at v0.0.3.

const std = @import("std");
const MediaType = @import("MediaType.zig").MediaType;
const Descriptor = @import("Descriptor.zig");
const Platform = @import("Platform.zig");

/// OCI Image Index (application/vnd.oci.image.index.v1+json).
pub const OciImageIndex = struct {
    /// OCI spec field: schemaVersion. Always 2.
    schema_version: u8,
    /// OCI spec field: mediaType.
    media_type: MediaType,
    /// OCI spec field: manifests. One entry per platform.
    manifests: []const Descriptor,
    /// OCI spec field: annotations. Placeholder until json.zig in v0.0.3.
    annotations: ?[]const u8 = null,
};

/// Docker Manifest List (application/vnd.docker.distribution.manifest.list.v2+json).
pub const DockerManifestList = struct {
    /// OCI spec field: schemaVersion. Always 2.
    schema_version: u8,
    /// OCI spec field: mediaType.
    media_type: MediaType,
    /// Docker spec field: manifests. One entry per platform.
    manifests: []const Descriptor,
};

/// Tagged union over OciImageIndex and DockerManifestList.
/// Use this type in resolvers — do not branch on the spec variant outside this file.
pub const MultiArchManifest = union(enum) {
    oci: OciImageIndex,
    docker: DockerManifestList,

    /// Returns the descriptor list regardless of which spec variant is underneath.
    pub fn descriptors(self: MultiArchManifest) []const Descriptor {
        return switch (self) {
            .oci => |idx| idx.manifests,
            .docker => |lst| lst.manifests,
        };
    }

    /// Returns the first Descriptor whose platform satisfies Platform.match(candidate, filter).
    /// Returns null if no descriptor matches or if a descriptor has no platform field.
    pub fn filterByPlatform(self: MultiArchManifest, filter: Platform) ?Descriptor {
        for (self.descriptors()) |desc| {
            const plat = desc.platform orelse continue;
            if (Platform.match(plat, filter)) return desc;
        }
        return null;
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

const Digest = @import("Digest.zig");

fn makeDescriptor(hex_char: u8, os: []const u8, arch: []const u8) !Descriptor {
    var hex_buf: [64]u8 = undefined;
    @memset(&hex_buf, hex_char);
    const hex = hex_buf[0..];
    var digest_buf: [71]u8 = undefined; // "sha256:" + 64 chars
    const digest_str = try std.fmt.bufPrint(&digest_buf, "sha256:{s}", .{hex});
    return Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse(digest_str),
        .size = 512,
        .platform = .{ .os = os, .architecture = arch },
    };
}

test "MultiArchManifest(oci): descriptors() returns manifest list" {
    const amd64 = try makeDescriptor('a', "linux", "amd64");
    const arm64 = try makeDescriptor('b', "linux", "arm64");
    const manifests = [_]Descriptor{ amd64, arm64 };

    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };

    try std.testing.expectEqual(@as(usize, 2), m.descriptors().len);
}

test "MultiArchManifest(docker): descriptors() returns manifest list" {
    const amd64 = try makeDescriptor('c', "linux", "amd64");
    const manifests = [_]Descriptor{amd64};

    const m = MultiArchManifest{ .docker = .{
        .schema_version = 2,
        .media_type = .docker_manifest_list_v2,
        .manifests = &manifests,
    } };

    try std.testing.expectEqual(@as(usize, 1), m.descriptors().len);
}

test "filterByPlatform: match found" {
    const amd64 = try makeDescriptor('d', "linux", "amd64");
    const arm64 = try makeDescriptor('e', "linux", "arm64");
    const manifests = [_]Descriptor{ amd64, arm64 };

    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };

    const filter = Platform{ .os = "linux", .architecture = "arm64" };
    const result = m.filterByPlatform(filter);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "e" ** 64, result.?.digest.hex);
}

test "filterByPlatform: no match returns null" {
    const amd64 = try makeDescriptor('f', "linux", "amd64");
    const manifests = [_]Descriptor{amd64};

    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };

    const filter = Platform{ .os = "windows", .architecture = "amd64" };
    try std.testing.expect(m.filterByPlatform(filter) == null);
}

test "filterByPlatform: variant fallback (no variant in filter accepts any)" {
    var desc = try makeDescriptor('g', "linux", "arm");
    desc.platform.?.variant = "v7";
    const manifests = [_]Descriptor{desc};

    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };

    // Filter omits variant: should still match arm/v7.
    const filter = Platform{ .os = "linux", .architecture = "arm" };
    const result = m.filterByPlatform(filter);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "g" ** 64, result.?.digest.hex);
}

test "filterByPlatform: descriptor with no platform is skipped" {
    const hex = "h" ** 64;
    var digest_buf: [71]u8 = undefined;
    const digest_str = try std.fmt.bufPrint(&digest_buf, "sha256:{s}", .{hex});
    const no_platform = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse(digest_str),
        .size = 100,
        // platform intentionally absent
    };
    const manifests = [_]Descriptor{no_platform};

    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };

    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(m.filterByPlatform(filter) == null);
}
