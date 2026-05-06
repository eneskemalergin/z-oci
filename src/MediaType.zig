//! OCI and Docker media types for manifest negotiation.
//!
//! Covers all types the resolver needs to recognize and, later, negotiate.
//! Unknown content-types return null from fromString. The caller decides how to react.
//! Legacy v1 signed manifests are recognized and flagged for rejection.

const std = @import("std");

pub const MediaType = enum {
    oci_manifest_v1,
    oci_index_v1,
    oci_config_v1,
    oci_empty_v1,
    oci_layer_v1_tar,
    oci_layer_v1_tar_gzip,
    oci_layer_v1_tar_zstd,
    oci_layer_nondistributable_v1_tar,
    oci_layer_nondistributable_v1_tar_gzip,
    docker_manifest_v2,
    docker_manifest_list_v2,
    docker_container_image_v1,
    docker_layer_gzip,
    docker_layer_foreign_gzip,
    /// Legacy schema 1. Recognized so the resolver can reject it cleanly.
    docker_manifest_v1_signed,

    const mime_table = [_]struct { []const u8, MediaType }{
        .{ "application/vnd.oci.image.manifest.v1+json", .oci_manifest_v1 },
        .{ "application/vnd.oci.image.index.v1+json", .oci_index_v1 },
        .{ "application/vnd.oci.image.config.v1+json", .oci_config_v1 },
        .{ "application/vnd.oci.empty.v1+json", .oci_empty_v1 },
        .{ "application/vnd.oci.image.layer.v1.tar", .oci_layer_v1_tar },
        .{ "application/vnd.oci.image.layer.v1.tar+gzip", .oci_layer_v1_tar_gzip },
        .{ "application/vnd.oci.image.layer.v1.tar+zstd", .oci_layer_v1_tar_zstd },
        .{ "application/vnd.oci.image.layer.nondistributable.v1.tar", .oci_layer_nondistributable_v1_tar },
        .{ "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", .oci_layer_nondistributable_v1_tar_gzip },
        .{ "application/vnd.docker.distribution.manifest.v2+json", .docker_manifest_v2 },
        .{ "application/vnd.docker.distribution.manifest.list.v2+json", .docker_manifest_list_v2 },
        .{ "application/vnd.docker.container.image.v1+json", .docker_container_image_v1 },
        .{ "application/vnd.docker.image.rootfs.diff.tar.gzip", .docker_layer_gzip },
        .{ "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip", .docker_layer_foreign_gzip },
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
            .oci_config_v1 => "application/vnd.oci.image.config.v1+json",
            .oci_empty_v1 => "application/vnd.oci.empty.v1+json",
            .oci_layer_v1_tar => "application/vnd.oci.image.layer.v1.tar",
            .oci_layer_v1_tar_gzip => "application/vnd.oci.image.layer.v1.tar+gzip",
            .oci_layer_v1_tar_zstd => "application/vnd.oci.image.layer.v1.tar+zstd",
            .oci_layer_nondistributable_v1_tar => "application/vnd.oci.image.layer.nondistributable.v1.tar",
            .oci_layer_nondistributable_v1_tar_gzip => "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
            .docker_manifest_v2 => "application/vnd.docker.distribution.manifest.v2+json",
            .docker_manifest_list_v2 => "application/vnd.docker.distribution.manifest.list.v2+json",
            .docker_container_image_v1 => "application/vnd.docker.container.image.v1+json",
            .docker_layer_gzip => "application/vnd.docker.image.rootfs.diff.tar.gzip",
            .docker_layer_foreign_gzip => "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
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

    /// True for the legacy v1 signed manifest. The resolver rejects these on receipt.
    pub fn isLegacy(self: MediaType) bool {
        return self == .docker_manifest_v1_signed;
    }

    /// Parse a JSON media type string into a MediaType variant.
    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !MediaType {
        const tok = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
        defer switch (tok) {
            .allocated_string => |s| allocator.free(s),
            else => {},
        };
        const s: []const u8 = switch (tok) {
            inline .string, .allocated_string => |v| v,
            else => return error.UnexpectedToken,
        };
        return MediaType.fromString(s) orelse error.UnexpectedToken;
    }

    /// Stringify as the canonical OCI/Docker MIME type string.
    pub fn jsonStringify(self: MediaType, jw: anytype) !void {
        try jw.write(self.toString());
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────
//
// fromString ------------------------------------------------------------------

test "fromString: all known types parse from their canonical MIME string" {
    // Each type must round-trip through toString → fromString.
    const cases = [_]MediaType{
        .oci_manifest_v1,
        .oci_index_v1,
        .oci_config_v1,
        .oci_empty_v1,
        .oci_layer_v1_tar,
        .oci_layer_v1_tar_gzip,
        .oci_layer_v1_tar_zstd,
        .oci_layer_nondistributable_v1_tar,
        .oci_layer_nondistributable_v1_tar_gzip,
        .docker_manifest_v2,
        .docker_manifest_list_v2,
        .docker_container_image_v1,
        .docker_layer_gzip,
        .docker_layer_foreign_gzip,
        .docker_manifest_v1_signed,
    };
    for (cases) |mt| {
        const result = MediaType.fromString(mt.toString());
        try std.testing.expectEqual(mt, result.?);
    }
}

test "fromString: empty string returns null" {
    try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString(""));
}

test "fromString: completely unknown MIME type returns null" {
    try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString("application/json"));
}

test "fromString: plain text returns null" {
    try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString("text/plain"));
}

test "fromString: prefix of a known type does not match" {
    // Guards against startsWith-style matching in the lookup.
    const prefix = "application/vnd.oci.image.manifest.v1+jso"; // missing trailing 'n'
    try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString(prefix));
}

test "fromString: known type with trailing suffix does not match" {
    // Guards against contains-style matching.
    const with_suffix = "application/vnd.oci.image.manifest.v1+json; charset=utf-8";
    try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString(with_suffix));
}

test "fromString: matching is case-insensitive for all casing variants" {
    // Verifies all three casing styles for one representative type.
    const lower = "application/vnd.oci.image.manifest.v1+json";
    const upper = "APPLICATION/VND.OCI.IMAGE.MANIFEST.V1+JSON";
    const mixed = "Application/Vnd.Oci.Image.Manifest.V1+Json";
    try std.testing.expectEqual(MediaType.oci_manifest_v1, MediaType.fromString(lower).?);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, MediaType.fromString(upper).?);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, MediaType.fromString(mixed).?);
}

// isMultiArch -----------------------------------------------------------------

test "isMultiArch: oci_index_v1 returns true" {
    try std.testing.expect(MediaType.oci_index_v1.isMultiArch());
}

test "isMultiArch: docker_manifest_list_v2 returns true" {
    try std.testing.expect(MediaType.docker_manifest_list_v2.isMultiArch());
}

test "isMultiArch: oci_manifest_v1 returns false" {
    // Guards against isMultiArch returning true for single-arch types.
    try std.testing.expect(!MediaType.oci_manifest_v1.isMultiArch());
}

test "isMultiArch: docker_manifest_v2 returns false" {
    try std.testing.expect(!MediaType.docker_manifest_v2.isMultiArch());
}

test "isMultiArch: docker_manifest_v1_signed returns false" {
    try std.testing.expect(!MediaType.docker_manifest_v1_signed.isMultiArch());
}

// isLegacy --------------------------------------------------------------------

test "isLegacy: docker_manifest_v1_signed returns true" {
    try std.testing.expect(MediaType.docker_manifest_v1_signed.isLegacy());
}

test "isLegacy: oci_manifest_v1 returns false" {
    // Guards against isLegacy returning true for current types.
    try std.testing.expect(!MediaType.oci_manifest_v1.isLegacy());
}

test "isLegacy: oci_index_v1 returns false" {
    try std.testing.expect(!MediaType.oci_index_v1.isLegacy());
}

test "isLegacy: docker_manifest_v2 returns false" {
    try std.testing.expect(!MediaType.docker_manifest_v2.isLegacy());
}

test "isLegacy: docker_manifest_list_v2 returns false" {
    try std.testing.expect(!MediaType.docker_manifest_list_v2.isLegacy());
}
