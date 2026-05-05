//! OCI Image Manifest and Docker V2 Schema 2 manifest.
//!
//! Both spec formats share the same shape: schema version, media type,
//! a config descriptor, and a list of layer descriptors. The media_type
//! field tells them apart at runtime.
//!
//! JSON field mapping (schemaVersion, mediaType, etc.) is handled in
//! json.zig at v0.0.3. annotations is a placeholder until then.

const std = @import("std");
const MediaType = @import("MediaType.zig").MediaType;
const Descriptor = @import("Descriptor.zig");

/// OCI spec field: schemaVersion. Always 2 for current formats.
schema_version: u8,
/// OCI spec field: mediaType.
media_type: MediaType,
/// OCI spec field: config. Points to the image configuration blob.
config: Descriptor,
/// OCI spec field: layers. Ordered list of filesystem layer blobs.
layers: []const Descriptor,
/// OCI spec field: annotations. Placeholder until json.zig in v0.0.3.
annotations: ?[]const u8 = null,

const Manifest = @This();

// ── Tests ────────────────────────────────────────────────────────────────────

const Digest = @import("Digest.zig");

test "Manifest: OCI image manifest stores all required fields" {
    // Arrange
    const config = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "a" ** 64),
        .size = 256,
    };
    const layer = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "b" ** 64),
        .size = 4096,
    };
    const layers = [_]Descriptor{layer};
    // Act
    const m = Manifest{
        .schema_version = 2,
        .media_type = .oci_manifest_v1,
        .config = config,
        .layers = &layers,
    };
    // Assert
    try std.testing.expectEqual(@as(u8, 2), m.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, m.media_type);
    try std.testing.expectEqual(@as(u64, 256), m.config.size);
    try std.testing.expectEqualSlices(u8, "a" ** 64, m.config.digest.hex);
}

test "Manifest: annotations defaults to null" {
    const stub = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "a" ** 64),
        .size = 0,
    };
    const m = Manifest{
        .schema_version = 2,
        .media_type = .oci_manifest_v1,
        .config = stub,
        .layers = &.{},
    };
    try std.testing.expect(m.annotations == null);
}

test "Manifest: empty layers slice is valid" {
    // A manifest with no layers is legal (e.g. scratch-based images).
    const config = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "c" ** 64),
        .size = 128,
    };
    const m = Manifest{
        .schema_version = 2,
        .media_type = .oci_manifest_v1,
        .config = config,
        .layers = &.{},
    };
    try std.testing.expectEqual(@as(usize, 0), m.layers.len);
}

test "Manifest: layers are stored in declaration order" {
    // Guards against any reordering of the layers slice.
    const config = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "d" ** 64),
        .size = 0,
    };
    const layer0 = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "e" ** 64),
        .size = 100,
    };
    const layer1 = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "f" ** 64),
        .size = 200,
    };
    const layers = [_]Descriptor{ layer0, layer1 };
    const m = Manifest{
        .schema_version = 2,
        .media_type = .oci_manifest_v1,
        .config = config,
        .layers = &layers,
    };
    try std.testing.expectEqual(@as(usize, 2), m.layers.len);
    try std.testing.expectEqualSlices(u8, "e" ** 64, m.layers[0].digest.hex);
    try std.testing.expectEqualSlices(u8, "f" ** 64, m.layers[1].digest.hex);
}

test "Manifest: Docker V2 manifest has distinct media_type from OCI" {
    // Guards against the two formats being accidentally interchangeable.
    const stub = Descriptor{
        .media_type = .docker_manifest_v2,
        .digest = try Digest.parse("sha256:" ++ "0" ** 64),
        .size = 0,
    };
    const oci = Manifest{ .schema_version = 2, .media_type = .oci_manifest_v1, .config = stub, .layers = &.{} };
    const docker = Manifest{ .schema_version = 2, .media_type = .docker_manifest_v2, .config = stub, .layers = &.{} };
    try std.testing.expect(oci.media_type != docker.media_type);
    try std.testing.expect(!oci.media_type.isMultiArch());
    try std.testing.expect(!docker.media_type.isMultiArch());
}
