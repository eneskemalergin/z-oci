//! OCI and Docker media types for manifest negotiation.
//!
//! Covers all types the resolver needs to recognize today.
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
    // Recognized so the resolver can reject it cleanly.
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

    pub fn fromString(content_type: []const u8) ?MediaType {
        for (mime_table) |entry| {
            if (std.ascii.eqlIgnoreCase(content_type, entry[0])) return entry[1];
        }
        return null;
    }

    /// Shares one table entry with `fromString` (no second string table).
    pub fn toString(self: MediaType) []const u8 {
        for (mime_table) |entry| {
            if (entry[1] == self) return entry[0];
        }
        unreachable;
    }

    pub fn isMultiArch(self: MediaType) bool {
        return switch (self) {
            .oci_index_v1, .docker_manifest_list_v2 => true,
            else => false,
        };
    }

    pub fn isLegacy(self: MediaType) bool {
        return self == .docker_manifest_v1_signed;
    }

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

    pub fn jsonStringify(self: MediaType, jw: anytype) !void {
        try jw.write(self.toString());
    }
};

// --- Tests ---

const all_media_types = [_]MediaType{
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

test "MediaType.fromString: known MIME strings round-trip through toString" {
    for (all_media_types) |mt| {
        try std.testing.expectEqual(mt, MediaType.fromString(mt.toString()).?);
        try std.testing.expectEqualStrings(mt.toString(), MediaType.fromString(mt.toString()).?.toString());
    }

    // Case-insensitive match must not depend on wire casing.
    try std.testing.expectEqual(
        MediaType.oci_manifest_v1,
        MediaType.fromString("APPLICATION/VND.OCI.IMAGE.MANIFEST.V1+JSON").?,
    );
}

test "MediaType.fromString: unknown and near-miss inputs return null" {
    var nul_buf: [128]u8 = undefined;
    const base = "application/vnd.oci.image.manifest.v1+json";
    @memcpy(nul_buf[0..base.len], base);
    nul_buf[base.len] = 0;

    var long_buf: [64]u8 = undefined;
    @memset(&long_buf, 'x');

    const cases = [_][]const u8{
        "",
        "application/json",
        "text/plain",
        "application/vnd.oci.image.manifest.v1+jso", // prefix of known type
        "application/vnd.oci.image.manifest.v1+json; charset=utf-8", // suffix/parameters
        nul_buf[0 .. base.len + 1], // embedded NUL
        &long_buf,
    };

    for (cases) |input| {
        try std.testing.expectEqual(@as(?MediaType, null), MediaType.fromString(input));
    }
}

test "MediaType: isMultiArch and isLegacy classifiers" {
    const cases = [_]struct {
        mt: MediaType,
        multi_arch: bool,
        legacy: bool,
    }{
        .{ .mt = .oci_index_v1, .multi_arch = true, .legacy = false },
        .{ .mt = .docker_manifest_list_v2, .multi_arch = true, .legacy = false },
        .{ .mt = .oci_manifest_v1, .multi_arch = false, .legacy = false },
        .{ .mt = .docker_manifest_v2, .multi_arch = false, .legacy = false },
        .{ .mt = .docker_manifest_v1_signed, .multi_arch = false, .legacy = true },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.multi_arch, case.mt.isMultiArch());
        try std.testing.expectEqual(case.legacy, case.mt.isLegacy());
    }
}

test "MediaType jsonParse: maps string tokens and rejects non-matching input" {
    const happy_cases = [_]struct { json: []const u8, expected: MediaType }{
        .{ .json = "\"application/vnd.oci.image.manifest.v1+json\"", .expected = .oci_manifest_v1 },
        .{ .json = "\"APPLICATION/VND.OCI.IMAGE.INDEX.V1+JSON\"", .expected = .oci_index_v1 },
    };

    for (happy_cases) |case| {
        const parsed = try std.json.parseFromSlice(MediaType, std.testing.allocator, case.json, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(case.expected, parsed.value);
    }

    const error_cases = [_][]const u8{
        "123",
        "true",
        "[]",
        "\"\"",
        "\"application/x-unknown\"",
    };

    for (error_cases) |json| {
        try std.testing.expectError(
            error.UnexpectedToken,
            std.json.parseFromSlice(MediaType, std.testing.allocator, json, .{}),
        );
    }
}

test "MediaType jsonStringify: round-trip preserves every variant" {
    for (all_media_types) |mt| {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();
        var ws: std.json.Stringify = .{ .writer = &aw.writer };
        try ws.write(mt);

        const reparsed = try std.json.parseFromSlice(MediaType, std.testing.allocator, aw.written(), .{});
        defer reparsed.deinit();
        try std.testing.expectEqual(mt, reparsed.value);
        try std.testing.expectEqualStrings(mt.toString(), reparsed.value.toString());
    }
}

test "MediaType jsonParse: allocation failures do not leak" {
    const json_bytes = "\"application/vnd.oci.image.index.v1+json\"";
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const parsed = try std.json.parseFromSlice(MediaType, allocator, json_bytes, .{});
            defer parsed.deinit();
            try std.testing.expectEqual(MediaType.oci_index_v1, parsed.value);
        }
    }.run, .{});
}
