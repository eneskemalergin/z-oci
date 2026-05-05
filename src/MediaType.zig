//! OCI and Docker media types for manifest negotiation.
//!
//! Covers all types the client needs to request and handle.
//! Unknown content-types return null from fromString. The caller decides how to react.
//! Legacy v1 signed manifests are recognized and flagged for rejection.

const std = @import("std");

pub const MediaType = enum {
    oci_manifest_v1,
    oci_index_v1,
    docker_manifest_v2,
    docker_manifest_list_v2,
    /// Legacy schema 1. Recognized so the client can reject it cleanly.
    docker_manifest_v1_signed,

    const mime_table = [_]struct { []const u8, MediaType }{
        .{ "application/vnd.oci.image.manifest.v1+json", .oci_manifest_v1 },
        .{ "application/vnd.oci.image.index.v1+json", .oci_index_v1 },
        .{ "application/vnd.docker.distribution.manifest.v2+json", .docker_manifest_v2 },
        .{ "application/vnd.docker.distribution.manifest.list.v2+json", .docker_manifest_list_v2 },
        .{ "application/vnd.docker.distribution.manifest.v1+prettyjws", .docker_manifest_v1_signed },
    };

    /// Case-insensitive match against known MIME strings. Returns null for unknown types.
    pub fn fromString(content_type: []const u8) ?MediaType {
        for (mime_table) |entry| {
            if (std.ascii.eqlIgnoreCase(content_type, entry[0])) return entry[1];
        }
        return null;
    }

    /// Returns the canonical MIME string for this media type.
    pub fn toString(self: MediaType) []const u8 {
        return switch (self) {
            .oci_manifest_v1 => "application/vnd.oci.image.manifest.v1+json",
            .oci_index_v1 => "application/vnd.oci.image.index.v1+json",
            .docker_manifest_v2 => "application/vnd.docker.distribution.manifest.v2+json",
            .docker_manifest_list_v2 => "application/vnd.docker.distribution.manifest.list.v2+json",
            .docker_manifest_v1_signed => "application/vnd.docker.distribution.manifest.v1+prettyjws",
        };
    }

    /// True for index and manifest list types. Both carry a list of platform descriptors.
    pub fn isMultiArch(self: MediaType) bool {
        return switch (self) {
            .oci_index_v1, .docker_manifest_list_v2 => true,
            else => false,
        };
    }

    /// True for the legacy v1 signed manifest. The client rejects these on receipt.
    pub fn isLegacy(self: MediaType) bool {
        return self == .docker_manifest_v1_signed;
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "fromString: all known types round-trip" {
    const cases = [_]MediaType{
        .oci_manifest_v1,
        .oci_index_v1,
        .docker_manifest_v2,
        .docker_manifest_list_v2,
        .docker_manifest_v1_signed,
    };
    for (cases) |mt| {
        const result = MediaType.fromString(mt.toString());
        try std.testing.expectEqual(mt, result.?);
    }
}

test "fromString: unknown type returns null" {
    try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString("application/json"));
    try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString(""));
    try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString("text/plain"));
}

test "fromString: case-insensitive" {
    const lower = "application/vnd.oci.image.manifest.v1+json";
    const upper = "APPLICATION/VND.OCI.IMAGE.MANIFEST.V1+JSON";
    const mixed = "Application/Vnd.Oci.Image.Manifest.V1+Json";
    try std.testing.expectEqual(MediaType.oci_manifest_v1, MediaType.fromString(lower).?);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, MediaType.fromString(upper).?);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, MediaType.fromString(mixed).?);
}

test "isMultiArch" {
    try std.testing.expect(MediaType.oci_index_v1.isMultiArch());
    try std.testing.expect(MediaType.docker_manifest_list_v2.isMultiArch());
    try std.testing.expect(!MediaType.oci_manifest_v1.isMultiArch());
    try std.testing.expect(!MediaType.docker_manifest_v2.isMultiArch());
}

test "isLegacy" {
    try std.testing.expect(MediaType.docker_manifest_v1_signed.isLegacy());
    try std.testing.expect(!MediaType.oci_manifest_v1.isLegacy());
    try std.testing.expect(!MediaType.docker_manifest_v2.isLegacy());
}
