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

test "Manifest: construct OCI image manifest" {
    const Digest = @import("Digest.zig");

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

    const m = Manifest{
        .schema_version = 2,
        .media_type = .oci_manifest_v1,
        .config = config,
        .layers = &layers,
    };

    try std.testing.expectEqual(@as(u8, 2), m.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, m.media_type);
    try std.testing.expectEqual(@as(u64, 256), m.config.size);
    try std.testing.expectEqual(@as(usize, 1), m.layers.len);
    try std.testing.expectEqual(@as(u64, 4096), m.layers[0].size);
    try std.testing.expect(m.annotations == null);
}

test "Manifest: construct Docker V2 manifest" {
    const Digest = @import("Digest.zig");

    const config = Descriptor{
        .media_type = .docker_manifest_v2,
        .digest = try Digest.parse("sha256:" ++ "c" ** 64),
        .size = 512,
    };
    const layer_a = Descriptor{
        .media_type = .docker_manifest_v2,
        .digest = try Digest.parse("sha256:" ++ "d" ** 64),
        .size = 8192,
    };
    const layer_b = Descriptor{
        .media_type = .docker_manifest_v2,
        .digest = try Digest.parse("sha256:" ++ "e" ** 64),
        .size = 16384,
    };
    const layers = [_]Descriptor{ layer_a, layer_b };

    const m = Manifest{
        .schema_version = 2,
        .media_type = .docker_manifest_v2,
        .config = config,
        .layers = &layers,
    };

    try std.testing.expectEqual(MediaType.docker_manifest_v2, m.media_type);
    try std.testing.expectEqual(@as(usize, 2), m.layers.len);
    try std.testing.expectEqualSlices(u8, "d" ** 64, m.layers[0].digest.hex);
    try std.testing.expectEqualSlices(u8, "e" ** 64, m.layers[1].digest.hex);
}

test "Manifest: media_type distinguishes OCI from Docker" {
    const Digest = @import("Digest.zig");

    const stub = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "f" ** 64),
        .size = 0,
    };
    const layers: []const Descriptor = &.{};

    const oci = Manifest{ .schema_version = 2, .media_type = .oci_manifest_v1, .config = stub, .layers = layers };
    const docker = Manifest{ .schema_version = 2, .media_type = .docker_manifest_v2, .config = stub, .layers = layers };

    try std.testing.expect(!oci.media_type.isMultiArch());
    try std.testing.expect(!docker.media_type.isMultiArch());
    try std.testing.expect(oci.media_type != docker.media_type);
}
