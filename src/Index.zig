//! Multi-arch manifest index types.
//!
//! OciImageIndex and DockerManifestList are distinct spec types but share
//! the same resolution logic: both carry a list of Descriptors, each with
//! a platform field pointing at a single-arch manifest.
//!
//! MultiArchManifest is the tagged union callers use. It hides which spec
//! variant is underneath and exposes descriptors() and filterByPlatform().
//!
//! jsonParse and jsonStringify on each type map camelCase JSON field names
//! (schemaVersion, mediaType) to snake_case Zig fields.

const std = @import("std");
const MediaType = @import("MediaType.zig").MediaType;
const Descriptor = @import("Descriptor.zig");
const Platform = @import("Platform.zig");
const json = @import("json.zig");
const Digest = @import("Digest.zig");
const test_support = @import("test_support.zig");

// --- Index types ---

/// OCI Image Index (application/vnd.oci.image.index.v1+json).
pub const OciImageIndex = struct {
    /// OCI spec field: schemaVersion. Always 2.
    schema_version: u8,
    /// OCI spec field: mediaType.
    media_type: MediaType,
    /// OCI spec field: manifests. One entry per platform.
    manifests: []const Descriptor,
    /// OCI spec field: annotations. Value is std.json.Value.object when present.
    annotations: ?std.json.Value = null,

    /// Parse a JSON OCI image index object.
    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !OciImageIndex {
        if (.object_begin != try source.next()) return error.UnexpectedToken;
        var result = OciImageIndex{
            .schema_version = undefined,
            .media_type = undefined,
            .manifests = undefined,
        };
        var seen_schema_version = false;
        var seen_media_type = false;
        var seen_manifests = false;
        while (true) {
            const tok = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
            const field_name: []const u8 = switch (tok) {
                inline .string, .allocated_string => |s| s,
                .object_end => break,
                else => return error.UnexpectedToken,
            };
            defer switch (tok) {
                .allocated_string => |s| allocator.free(s),
                else => {},
            };
            if (std.mem.eql(u8, field_name, "schemaVersion")) {
                result.schema_version = try std.json.innerParse(u8, allocator, source, options);
                seen_schema_version = true;
            } else if (std.mem.eql(u8, field_name, "mediaType")) {
                result.media_type = try std.json.innerParse(MediaType, allocator, source, options);
                seen_media_type = true;
            } else if (std.mem.eql(u8, field_name, "manifests")) {
                result.manifests = try std.json.innerParse([]const Descriptor, allocator, source, options);
                seen_manifests = true;
            } else if (std.mem.eql(u8, field_name, "annotations")) {
                result.annotations = try std.json.innerParse(?std.json.Value, allocator, source, options);
            } else {
                if (!options.ignore_unknown_fields) return error.UnknownField;
                try source.skipValue();
            }
        }
        if (!seen_schema_version or !seen_media_type or !seen_manifests) return error.MissingField;
        if (result.schema_version != 2) return error.UnexpectedToken;
        if (result.media_type != .oci_index_v1) return error.UnexpectedToken;
        return result;
    }

    /// Stringify to a JSON OCI image index with camelCase field names.
    pub fn jsonStringify(self: OciImageIndex, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("schemaVersion");
        try jw.write(self.schema_version);
        try jw.objectField("mediaType");
        try jw.write(self.media_type);
        try jw.objectField("manifests");
        try jw.write(self.manifests);
        if (self.annotations) |a| {
            try jw.objectField("annotations");
            try jw.write(a);
        }
        try jw.endObject();
    }
};

/// Docker Manifest List (application/vnd.docker.distribution.manifest.list.v2+json).
pub const DockerManifestList = struct {
    /// Docker schema 2 field: schemaVersion. Always 2.
    schema_version: u8,
    /// Docker schema 2 field: mediaType.
    media_type: MediaType,
    /// Docker spec field: manifests. One entry per platform.
    manifests: []const Descriptor,

    /// Parse a JSON Docker manifest list object.
    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !DockerManifestList {
        if (.object_begin != try source.next()) return error.UnexpectedToken;
        var result = DockerManifestList{
            .schema_version = undefined,
            .media_type = undefined,
            .manifests = undefined,
        };
        var seen_schema_version = false;
        var seen_media_type = false;
        var seen_manifests = false;
        while (true) {
            const tok = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
            const field_name: []const u8 = switch (tok) {
                inline .string, .allocated_string => |s| s,
                .object_end => break,
                else => return error.UnexpectedToken,
            };
            defer switch (tok) {
                .allocated_string => |s| allocator.free(s),
                else => {},
            };
            if (std.mem.eql(u8, field_name, "schemaVersion")) {
                result.schema_version = try std.json.innerParse(u8, allocator, source, options);
                seen_schema_version = true;
            } else if (std.mem.eql(u8, field_name, "mediaType")) {
                result.media_type = try std.json.innerParse(MediaType, allocator, source, options);
                seen_media_type = true;
            } else if (std.mem.eql(u8, field_name, "manifests")) {
                result.manifests = try std.json.innerParse([]const Descriptor, allocator, source, options);
                seen_manifests = true;
            } else {
                if (!options.ignore_unknown_fields) return error.UnknownField;
                try source.skipValue();
            }
        }
        if (!seen_schema_version or !seen_media_type or !seen_manifests) return error.MissingField;
        if (result.schema_version != 2) return error.UnexpectedToken;
        if (result.media_type != .docker_manifest_list_v2) return error.UnexpectedToken;
        return result;
    }

    /// Stringify to a JSON Docker manifest list with camelCase field names.
    pub fn jsonStringify(self: DockerManifestList, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("schemaVersion");
        try jw.write(self.schema_version);
        try jw.objectField("mediaType");
        try jw.write(self.media_type);
        try jw.objectField("manifests");
        try jw.write(self.manifests);
        try jw.endObject();
    }
};

/// Tagged union over OciImageIndex and DockerManifestList.
/// Use this type in resolvers. Do not branch on the spec variant outside this file.
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

    /// Returns the first platform-matching descriptor that points to another
    /// manifest document the resolver can fetch.
    pub fn selectChildDescriptorByPlatform(self: MultiArchManifest, filter: Platform) ?Descriptor {
        for (self.descriptors()) |desc| {
            const plat = desc.platform orelse continue;
            if (!Platform.match(plat, filter)) continue;
            if (isResolvableChildMediaType(desc.media_type)) return desc;
        }
        return null;
    }
};

fn isResolvableChildMediaType(media_type: MediaType) bool {
    return switch (media_type) {
        .oci_manifest_v1,
        .docker_manifest_v2,
        .oci_index_v1,
        .docker_manifest_list_v2,
        => true,
        else => false,
    };
}

// --- Private helpers ---

const TestDescriptor = struct {
    descriptor: Descriptor,
    digest_hex: []u8,

    fn deinit(self: TestDescriptor, allocator: std.mem.Allocator) void {
        allocator.free(self.digest_hex);
    }
};

// makeDescriptor builds a test Descriptor with all hex bytes set to hex_char.
// hex_char must be a valid ASCII hex digit (0-9, a-f).
fn makeDescriptor(hex_char: u8, os: []const u8, arch: []const u8) !TestDescriptor {
    const digest_hex = try std.testing.allocator.alloc(u8, 64);
    errdefer std.testing.allocator.free(digest_hex);
    @memset(digest_hex, hex_char);

    return .{
        .digest_hex = digest_hex,
        .descriptor = Descriptor{
            .media_type = .oci_manifest_v1,
            .digest = .{ .algorithm = .sha256, .hex = digest_hex },
            .size = 512,
            .platform = .{ .os = os, .architecture = arch },
        },
    };
}

// --- Tests ---

test "descriptors: OciImageIndex returns all entries" {
    // Arrange
    const amd64 = try makeDescriptor('a', "linux", "amd64");
    defer amd64.deinit(std.testing.allocator);
    const arm64 = try makeDescriptor('b', "linux", "arm64");
    defer arm64.deinit(std.testing.allocator);
    const manifests = [_]Descriptor{ amd64.descriptor, arm64.descriptor };
    // Act
    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };
    // Assert
    try std.testing.expectEqual(@as(usize, 2), m.descriptors().len);
}

test "descriptors: DockerManifestList returns all entries" {
    const amd64 = try makeDescriptor('c', "linux", "amd64");
    defer amd64.deinit(std.testing.allocator);
    const manifests = [_]Descriptor{amd64.descriptor};
    const m = MultiArchManifest{ .docker = .{
        .schema_version = 2,
        .media_type = .docker_manifest_list_v2,
        .manifests = &manifests,
    } };
    try std.testing.expectEqual(@as(usize, 1), m.descriptors().len);
}

test "selectChildDescriptorByPlatform: skips auxiliary descriptor and returns manifest child" {
    const aux = try makeDescriptor('d', "linux", "arm64");
    defer aux.deinit(std.testing.allocator);
    const child = try makeDescriptor('e', "linux", "arm64");
    defer child.deinit(std.testing.allocator);

    const manifests = [_]Descriptor{
        Descriptor{
            .media_type = .oci_config_v1,
            .digest = aux.descriptor.digest,
            .size = aux.descriptor.size,
            .platform = aux.descriptor.platform,
        },
        child.descriptor,
    };

    const multi = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };

    const selected = multi.selectChildDescriptorByPlatform(.{ .os = "linux", .architecture = "arm64" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, selected.?.media_type);
    try std.testing.expectEqualSlices(u8, child.descriptor.digest.hex, selected.?.digest.hex);
}

test "selectChildDescriptorByPlatform: accepts nested index descriptor" {
    const nested = try makeDescriptor('f', "linux", "arm64");
    defer nested.deinit(std.testing.allocator);

    const manifests = [_]Descriptor{Descriptor{
        .media_type = .oci_index_v1,
        .digest = nested.descriptor.digest,
        .size = nested.descriptor.size,
        .platform = nested.descriptor.platform,
    }};

    const multi = MultiArchManifest{ .docker = .{
        .schema_version = 2,
        .media_type = .docker_manifest_list_v2,
        .manifests = &manifests,
    } };

    const selected = multi.selectChildDescriptorByPlatform(.{ .os = "linux", .architecture = "arm64" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(MediaType.oci_index_v1, selected.?.media_type);
}

test "selectChildDescriptorByPlatform: returns null when only auxiliary descriptor matches" {
    const aux = try makeDescriptor('1', "linux", "arm64");
    defer aux.deinit(std.testing.allocator);

    const manifests = [_]Descriptor{Descriptor{
        .media_type = .oci_config_v1,
        .digest = aux.descriptor.digest,
        .size = aux.descriptor.size,
        .platform = aux.descriptor.platform,
    }};

    const multi = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };

    try std.testing.expect(multi.selectChildDescriptorByPlatform(.{ .os = "linux", .architecture = "arm64" }) == null);
}

test "descriptors: empty manifest list returns empty slice" {
    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &.{},
    } };
    try std.testing.expectEqual(@as(usize, 0), m.descriptors().len);
}

// filterByPlatform ------------------------------------------------------------

test "filterByPlatform: returns the matching descriptor" {
    // Arrange: two descriptors, only arm64 should match.
    const amd64 = try makeDescriptor('d', "linux", "amd64");
    defer amd64.deinit(std.testing.allocator);
    const arm64 = try makeDescriptor('e', "linux", "arm64");
    defer arm64.deinit(std.testing.allocator);
    const manifests = [_]Descriptor{ amd64.descriptor, arm64.descriptor };
    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };
    // Act
    const filter = Platform{ .os = "linux", .architecture = "arm64" };
    const result = m.filterByPlatform(filter);
    // Assert: result is the arm64 descriptor, not the amd64 one.
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "e" ** 64, result.?.digest.hex);
}

test "filterByPlatform: no matching platform returns null" {
    const amd64 = try makeDescriptor('f', "linux", "amd64");
    defer amd64.deinit(std.testing.allocator);
    const manifests = [_]Descriptor{amd64.descriptor};
    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };
    const filter = Platform{ .os = "windows", .architecture = "amd64" };
    try std.testing.expect(m.filterByPlatform(filter) == null);
}

test "filterByPlatform: empty manifest list returns null" {
    // Guards against an off-by-one when the loop has zero iterations.
    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &.{},
    } };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(m.filterByPlatform(filter) == null);
}

test "filterByPlatform: first matching descriptor wins, not the second" {
    // When two descriptors satisfy the filter, the first in the list is returned.
    // Guards against iterating backwards or using the last match.
    const first = try makeDescriptor('1', "linux", "amd64");
    defer first.deinit(std.testing.allocator);
    const second = try makeDescriptor('2', "linux", "amd64");
    defer second.deinit(std.testing.allocator);
    const manifests = [_]Descriptor{ first.descriptor, second.descriptor };
    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    const result = m.filterByPlatform(filter);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "1" ** 64, result.?.digest.hex);
}

test "filterByPlatform: filter omits variant, descriptor with variant still matches" {
    // Verifies partial match: no variant in filter accepts any candidate variant.
    var desc = try makeDescriptor('a', "linux", "arm");
    defer desc.deinit(std.testing.allocator);
    desc.descriptor.platform.?.variant = "v7";
    const manifests = [_]Descriptor{desc.descriptor};
    const m = MultiArchManifest{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = &manifests,
    } };
    const filter = Platform{ .os = "linux", .architecture = "arm" };
    const result = m.filterByPlatform(filter);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "a" ** 64, result.?.digest.hex);
}

test "filterByPlatform: descriptor without platform field is skipped" {
    // A descriptor in an index may legitimately omit platform (e.g. attestation blobs).
    // It must not be matched even if the filter would otherwise match anything.
    const digest_hex = try std.testing.allocator.dupe(u8, "a" ** 64);
    defer std.testing.allocator.free(digest_hex);
    const no_platform = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = .{ .algorithm = .sha256, .hex = digest_hex },
        .size = 100,
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

test "filterByPlatform: DockerManifestList variant finds the correct platform" {
    // Verifies that filterByPlatform works through the .docker union arm,
    // not just the .oci arm.
    const arm64 = try makeDescriptor('a', "linux", "arm64");
    defer arm64.deinit(std.testing.allocator);
    const manifests = [_]Descriptor{arm64.descriptor};
    const m = MultiArchManifest{ .docker = .{
        .schema_version = 2,
        .media_type = .docker_manifest_list_v2,
        .manifests = &manifests,
    } };
    const filter = Platform{ .os = "linux", .architecture = "arm64" };
    const result = m.filterByPlatform(filter);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, "a" ** 64, result.?.digest.hex);
}

test "OciImageIndex JSON: parses required fields" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\      "size": 512,
        \\      "platform": { "os": "linux", "architecture": "amd64" }
        \\    }
        \\  ]
        \\}
    ;

    const parsed = try json.parse(OciImageIndex, std.testing.allocator, json_bytes);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_index_v1, parsed.value.media_type);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.manifests.len);
    try std.testing.expectEqualSlices(u8, "linux", parsed.value.manifests[0].platform.?.os);
}

test "DockerManifestList JSON: parses required fields" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        \\      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\      "size": 1024,
        \\      "platform": { "os": "linux", "architecture": "arm64" }
        \\    }
        \\  ]
        \\}
    ;

    const parsed = try json.parse(DockerManifestList, std.testing.allocator, json_bytes);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.docker_manifest_list_v2, parsed.value.media_type);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.manifests.len);
    try std.testing.expectEqualSlices(u8, "arm64", parsed.value.manifests[0].platform.?.architecture);
}

test "OciImageIndex JSON: stringify/reparse preserves annotations leak-free" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": [],
        \\  "annotations": {
        \\    "org.opencontainers.image.description": "multi-arch index"
        \\  }
        \\}
    ;

    const parsed = try json.parse(OciImageIndex, std.testing.allocator, json_bytes);
    defer parsed.deinit();

    var aw = try json.stringifyForTest(parsed.value);
    defer aw.deinit();
    const out = aw.written();

    const reparsed = try json.parse(OciImageIndex, std.testing.allocator, out);
    defer reparsed.deinit();

    try std.testing.expect(std.mem.indexOf(u8, out, "\"annotations\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "org.opencontainers.image.description") != null);
    try std.testing.expect(reparsed.value.annotations != null);
}

test "OciImageIndex JSON: rejects schemaVersion other than 2" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 1,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": []
        \\}
    ;

    try std.testing.expectError(error.UnexpectedToken, json.parse(OciImageIndex, std.testing.allocator, json_bytes));
}

test "OciImageIndex JSON: rejects docker manifest list mediaType" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        \\  "manifests": []
        \\}
    ;

    try std.testing.expectError(error.UnexpectedToken, json.parse(OciImageIndex, std.testing.allocator, json_bytes));
}

test "DockerManifestList JSON: rejects schemaVersion other than 2" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 1,
        \\  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        \\  "manifests": []
        \\}
    ;

    try std.testing.expectError(error.UnexpectedToken, json.parse(DockerManifestList, std.testing.allocator, json_bytes));
}

test "DockerManifestList JSON: rejects OCI index mediaType" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": []
        \\}
    ;

    try std.testing.expectError(error.UnexpectedToken, json.parse(DockerManifestList, std.testing.allocator, json_bytes));
}

test "OciImageIndex JSON: parses upstream OCI index fixture" {
    const parsed = try test_support.parseFixture(
        OciImageIndex,
        "fixtures/indexes/oci-image-index-spec-example.json",
        16 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_index_v1, parsed.value.media_type);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.manifests.len);
    try std.testing.expectEqualSlices(u8, "ppc64le", parsed.value.manifests[0].platform.?.architecture);
    try std.testing.expect(parsed.value.annotations != null);

    const multi = MultiArchManifest{ .oci = parsed.value };
    const selected = multi.filterByPlatform(.{ .os = "linux", .architecture = "amd64" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqualSlices(u8, "5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270", selected.?.digest.hex);
}

test "DockerManifestList JSON: parses upstream Docker manifest list fixture" {
    const parsed = try test_support.parseFixture(
        DockerManifestList,
        "fixtures/indexes/docker-manifest-list-spec-example.json",
        16 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.docker_manifest_list_v2, parsed.value.media_type);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.manifests.len);
    try std.testing.expectEqualSlices(u8, "amd64", parsed.value.manifests[1].platform.?.architecture);

    const multi = MultiArchManifest{ .docker = parsed.value };
    const selected = multi.filterByPlatform(.{ .os = "linux", .architecture = "amd64" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqualSlices(u8, "5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270", selected.?.digest.hex);
}

test "OciImageIndex JSON: parses live busybox OCI index fixture" {
    const parsed = try test_support.parseFixture(
        OciImageIndex,
        "fixtures/indexes/busybox-latest-live-oci-index.json",
        32 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_index_v1, parsed.value.media_type);
    try std.testing.expect(parsed.value.manifests.len >= 8);

    const multi = MultiArchManifest{ .oci = parsed.value };
    const selected = multi.filterByPlatform(.{ .os = "linux", .architecture = "amd64" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, selected.?.media_type);
    try std.testing.expectEqualSlices(u8, "b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65", selected.?.digest.hex);
    try std.testing.expectEqual(@as(u64, 610), selected.?.size);
}

test "OciImageIndex JSON: live busybox fixture selects arm64 variant-bearing descriptor" {
    const parsed = try test_support.parseFixture(
        OciImageIndex,
        "fixtures/indexes/busybox-latest-live-oci-index.json",
        32 * 1024,
    );
    defer parsed.deinit();

    const multi = MultiArchManifest{ .oci = parsed.value };
    const selected = multi.filterByPlatform(.{ .os = "linux", .architecture = "arm64", .variant = "v8" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, selected.?.media_type);
    try std.testing.expectEqualSlices(u8, "c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6", selected.?.digest.hex);
    try std.testing.expect(selected.?.platform != null);
    try std.testing.expectEqualSlices(u8, "arm64", selected.?.platform.?.architecture);
    try std.testing.expectEqualSlices(u8, "v8", selected.?.platform.?.variant.?);
}

test "OciImageIndex JSON: live busybox fixture returns null when no platform matches" {
    const parsed = try test_support.parseFixture(
        OciImageIndex,
        "fixtures/indexes/busybox-latest-live-oci-index.json",
        32 * 1024,
    );
    defer parsed.deinit();

    const multi = MultiArchManifest{ .oci = parsed.value };
    try std.testing.expect(multi.filterByPlatform(.{ .os = "windows", .architecture = "amd64" }) == null);
}

test "DockerManifestList JSON: parses live Quay busybox manifest list fixture" {
    const parsed = try test_support.parseFixture(
        DockerManifestList,
        "fixtures/indexes/quay-prometheus-busybox-latest-live-docker-manifest-list.json",
        16 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.docker_manifest_list_v2, parsed.value.media_type);
    try std.testing.expectEqual(@as(usize, 6), parsed.value.manifests.len);

    const multi = MultiArchManifest{ .docker = parsed.value };
    const selected = multi.filterByPlatform(.{ .os = "linux", .architecture = "amd64" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(MediaType.docker_manifest_v2, selected.?.media_type);
    try std.testing.expectEqualSlices(u8, "35e7e430350711653810b2b3cc889fec2a6e0175c078e4114964c7252c411209", selected.?.digest.hex);
    try std.testing.expectEqual(@as(u64, 736), selected.?.size);
}

test "DockerManifestList JSON: live Quay fixture selects linux arm64 descriptor" {
    const parsed = try test_support.parseFixture(
        DockerManifestList,
        "fixtures/indexes/quay-prometheus-busybox-latest-live-docker-manifest-list.json",
        16 * 1024,
    );
    defer parsed.deinit();

    const multi = MultiArchManifest{ .docker = parsed.value };
    const selected = multi.filterByPlatform(.{ .os = "linux", .architecture = "arm64" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(MediaType.docker_manifest_v2, selected.?.media_type);
    try std.testing.expectEqualSlices(u8, "8f03274c62c8fff16d451d31ad57a6af6873c882273833368782231ebd07d0cf", selected.?.digest.hex);
    try std.testing.expect(selected.?.platform != null);
    try std.testing.expectEqualSlices(u8, "arm64", selected.?.platform.?.architecture);
}

test "OciImageIndex JSON: allocation failures do not leak" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\      "size": 512,
        \\      "platform": { "os": "linux", "architecture": "amd64" }
        \\    }
        \\  ]
        \\}
    ;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            const parsed = try json.parse(OciImageIndex, allocator, bytes);
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
        }
    }.run, .{json_bytes});
}

test "OciImageIndex JSON: repeated parse rounds leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\      "size": 512,
        \\      "platform": { "os": "linux", "architecture": "amd64" }
        \\    }
        \\  ]
        \\}
    ;
    for (0..16) |_| {
        const parsed = try json.parse(OciImageIndex, allocator, json_bytes);
        parsed.deinit();
    }
}

test "DockerManifestList JSON: allocation failures do not leak" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        \\      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\      "size": 1024,
        \\      "platform": { "os": "linux", "architecture": "arm64" }
        \\    }
        \\  ]
        \\}
    ;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            const parsed = try json.parse(DockerManifestList, allocator, bytes);
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
        }
    }.run, .{json_bytes});
}

test "DockerManifestList JSON: repeated parse rounds leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        \\  "manifests": []
        \\}
    ;
    for (0..16) |_| {
        const parsed = try json.parse(DockerManifestList, allocator, json_bytes);
        parsed.deinit();
    }
}

test "OciImageIndex JSON: 1000x repeated parse/deinit under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\      "size": 512,
        \\      "platform": { "os": "linux", "architecture": "amd64" }
        \\    }
        \\  ]
        \\}
    ;
    for (0..1000) |_| {
        const parsed = try json.parse(OciImageIndex, allocator, json_bytes);
        parsed.deinit();
    }
}

test "DockerManifestList JSON: 1000x repeated parse/deinit under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        \\      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\      "size": 1024,
        \\      "platform": { "os": "linux", "architecture": "arm64" }
        \\    }
        \\  ]
        \\}
    ;
    for (0..1000) |_| {
        const parsed = try json.parse(DockerManifestList, allocator, json_bytes);
        parsed.deinit();
    }
}
