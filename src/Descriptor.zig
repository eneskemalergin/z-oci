//! OCI content descriptor. Points to a manifest, config blob, or layer.
//!
//! Used in Index.zig to list per-platform manifests, and in Manifest.zig
//! for the config and layer entries.
//!
//! JSON field mapping (camelCase in spec, snake_case here) is handled in
//! json.zig at v0.0.3. For now this is a plain data struct.
//!
//! annotations is a string-keyed map in the OCI spec. Placeholder type
//! is []const u8 until json.zig lands in v0.0.3.

const MediaType = @import("MediaType.zig").MediaType;
const Digest = @import("Digest.zig");
const Platform = @import("Platform.zig");
const std = @import("std");

/// OCI spec field: mediaType
media_type: MediaType,
/// OCI spec field: digest
digest: Digest,
/// OCI spec field: size (bytes)
size: u64,
/// OCI spec field: platform. Only present in index/manifest-list entries.
platform: ?Platform = null,
/// OCI spec field: urls. Optional list of download URLs for the blob.
urls: ?[]const []const u8 = null,
/// OCI spec field: annotations. Placeholder until json.zig in v0.0.3.
annotations: ?[]const u8 = null,
/// OCI spec field: artifactType. Present when descriptor points to an artifact.
artifact_type: ?[]const u8 = null,

const Descriptor = @This();

// ── Tests ────────────────────────────────────────────────────────────────────

test "Descriptor: construct minimal (media_type, digest, size)" {
    const hex = "a" ** 64;
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ hex),
        .size = 1234,
    };
    try std.testing.expectEqual(MediaType.oci_manifest_v1, d.media_type);
    try std.testing.expectEqual(@as(u64, 1234), d.size);
    try std.testing.expectEqualSlices(u8, hex, d.digest.hex);
    try std.testing.expect(d.platform == null);
    try std.testing.expect(d.urls == null);
    try std.testing.expect(d.annotations == null);
    try std.testing.expect(d.artifact_type == null);
}

test "Descriptor: construct with platform" {
    const hex = "b" ** 64;
    const d = Descriptor{
        .media_type = .oci_index_v1,
        .digest = try Digest.parse("sha256:" ++ hex),
        .size = 512,
        .platform = .{ .os = "linux", .architecture = "amd64" },
    };
    try std.testing.expect(d.platform != null);
    try std.testing.expectEqualSlices(u8, "linux", d.platform.?.os);
    try std.testing.expectEqualSlices(u8, "amd64", d.platform.?.architecture);
}

test "Descriptor: construct with artifact_type" {
    const hex = "c" ** 64;
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ hex),
        .size = 0,
        .artifact_type = "application/vnd.example.sbom+json",
    };
    try std.testing.expectEqualSlices(u8, "application/vnd.example.sbom+json", d.artifact_type.?);
}
