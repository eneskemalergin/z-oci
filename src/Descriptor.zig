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

test "Descriptor: all optional fields default to null" {
    // Verifies the zero-default invariant. Any new optional field that forgets
    // a default value will make this test fail.
    const hex = "a" ** 64;
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ hex),
        .size = 1234,
    };
    try std.testing.expect(d.platform == null);
    try std.testing.expect(d.urls == null);
    try std.testing.expect(d.annotations == null);
    try std.testing.expect(d.artifact_type == null);
}

test "Descriptor: required fields are stored exactly" {
    const hex = "a" ** 64;
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ hex),
        .size = 1234,
    };
    try std.testing.expectEqual(MediaType.oci_manifest_v1, d.media_type);
    try std.testing.expectEqual(@as(u64, 1234), d.size);
    try std.testing.expectEqual(Digest.Algorithm.sha256, d.digest.algorithm);
    try std.testing.expectEqualSlices(u8, hex, d.digest.hex);
}

test "Descriptor: size zero is a valid blob size" {
    // A zero-byte blob (e.g. empty config) must be representable.
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "a" ** 64),
        .size = 0,
    };
    try std.testing.expectEqual(@as(u64, 0), d.size);
}

test "Descriptor: size at u64 maximum is valid" {
    // Ensures there is no artificial cap on size smaller than u64.
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "a" ** 64),
        .size = std.math.maxInt(u64),
    };
    try std.testing.expectEqual(std.math.maxInt(u64), d.size);
}

test "Descriptor: platform field is stored and readable" {
    const d = Descriptor{
        .media_type = .oci_index_v1,
        .digest = try Digest.parse("sha256:" ++ "b" ** 64),
        .size = 512,
        .platform = .{ .os = "linux", .architecture = "amd64" },
    };
    try std.testing.expect(d.platform != null);
    try std.testing.expectEqualSlices(u8, "linux", d.platform.?.os);
    try std.testing.expectEqualSlices(u8, "amd64", d.platform.?.architecture);
}

test "Descriptor: urls field is stored and readable" {
    const url_list = [_][]const u8{
        "https://cdn.example.com/layer.tar.gz",
        "https://fallback.example.com/layer.tar.gz",
    };
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "c" ** 64),
        .size = 8192,
        .urls = &url_list,
    };
    try std.testing.expect(d.urls != null);
    try std.testing.expectEqual(@as(usize, 2), d.urls.?.len);
    try std.testing.expectEqualSlices(u8, "https://cdn.example.com/layer.tar.gz", d.urls.?[0]);
}

test "Descriptor: artifact_type field is stored and readable" {
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ "d" ** 64),
        .size = 0,
        .artifact_type = "application/vnd.example.sbom+json",
    };
    try std.testing.expectEqualSlices(u8, "application/vnd.example.sbom+json", d.artifact_type.?);
}
