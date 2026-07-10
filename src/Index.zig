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
const test_support = @import("test_support.zig");

// --- Index types ---

pub const OciImageIndex = struct {
    schema_version: u8,
    media_type: MediaType,
    manifests: []const Descriptor,
    annotations: ?std.json.Value = null,

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

pub const DockerManifestList = struct {
    schema_version: u8,
    media_type: MediaType,
    manifests: []const Descriptor,

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

/// Prefer this over branching on OCI vs Docker outside this file.
pub const MultiArchManifest = union(enum) {
    oci: OciImageIndex,
    docker: DockerManifestList,

    pub fn descriptors(self: MultiArchManifest) []const Descriptor {
        return switch (self) {
            .oci => |idx| idx.manifests,
            .docker => |lst| lst.manifests,
        };
    }

    pub fn filterByPlatform(self: MultiArchManifest, filter: Platform) ?Descriptor {
        for (self.descriptors()) |desc| {
            const plat = desc.platform orelse continue;
            if (Platform.match(plat, filter)) return desc;
        }
        return null;
    }

    /// Like `filterByPlatform`, but only media types the resolver can fetch as children.
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

const minimal_oci_index_json =
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

const minimal_docker_list_json =
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

fn ociMulti(manifests: []const Descriptor) MultiArchManifest {
    return .{ .oci = .{
        .schema_version = 2,
        .media_type = .oci_index_v1,
        .manifests = manifests,
    } };
}

fn dockerMulti(manifests: []const Descriptor) MultiArchManifest {
    return .{ .docker = .{
        .schema_version = 2,
        .media_type = .docker_manifest_list_v2,
        .manifests = manifests,
    } };
}

fn expectJsonParseError(comptime T: type, json_bytes: []const u8, expected: anyerror) !void {
    try std.testing.expectError(expected, json.parse(T, std.testing.allocator, json_bytes));
}

test "MultiArchManifest.descriptors: entry counts per union arm" {
    const amd64 = try makeDescriptor('a', "linux", "amd64");
    defer amd64.deinit(std.testing.allocator);
    const arm64 = try makeDescriptor('b', "linux", "arm64");
    defer arm64.deinit(std.testing.allocator);

    const cases = [_]struct { multi: MultiArchManifest, expected_len: usize }{
        .{ .multi = ociMulti(&.{ amd64.descriptor, arm64.descriptor }), .expected_len = 2 },
        .{ .multi = dockerMulti(&.{amd64.descriptor}), .expected_len = 1 },
        .{ .multi = ociMulti(&.{}), .expected_len = 0 },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expected_len, case.multi.descriptors().len);
    }
}

test "MultiArchManifest.filterByPlatform: platform selection table" {
    const amd64 = try makeDescriptor('d', "linux", "amd64");
    defer amd64.deinit(std.testing.allocator);
    const arm64 = try makeDescriptor('e', "linux", "arm64");
    defer arm64.deinit(std.testing.allocator);
    const first = try makeDescriptor('1', "linux", "amd64");
    defer first.deinit(std.testing.allocator);
    const second = try makeDescriptor('2', "linux", "amd64");
    defer second.deinit(std.testing.allocator);

    var variant_desc = try makeDescriptor('a', "linux", "arm");
    defer variant_desc.deinit(std.testing.allocator);
    variant_desc.descriptor.platform.?.variant = "v7";

    const digest_hex = try std.testing.allocator.dupe(u8, "a" ** 64);
    defer std.testing.allocator.free(digest_hex);
    const no_platform = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = .{ .algorithm = .sha256, .hex = digest_hex },
        .size = 100,
    };

    const filter = Platform{ .os = "linux", .architecture = "arm64" };
    const cases = [_]struct {
        multi: MultiArchManifest,
        platform: Platform,
        expect_hex: ?[]const u8,
    }{
        .{ .multi = ociMulti(&.{ amd64.descriptor, arm64.descriptor }), .platform = filter, .expect_hex = "e" ** 64 },
        .{ .multi = ociMulti(&.{amd64.descriptor}), .platform = .{ .os = "windows", .architecture = "amd64" }, .expect_hex = null },
        .{ .multi = ociMulti(&.{}), .platform = .{ .os = "linux", .architecture = "amd64" }, .expect_hex = null },
        .{ .multi = ociMulti(&.{ first.descriptor, second.descriptor }), .platform = .{ .os = "linux", .architecture = "amd64" }, .expect_hex = "1" ** 64 },
        .{ .multi = ociMulti(&.{variant_desc.descriptor}), .platform = .{ .os = "linux", .architecture = "arm" }, .expect_hex = "a" ** 64 },
        .{ .multi = ociMulti(&.{no_platform}), .platform = .{ .os = "linux", .architecture = "amd64" }, .expect_hex = null },
        .{ .multi = dockerMulti(&.{arm64.descriptor}), .platform = filter, .expect_hex = "e" ** 64 },
    };

    for (cases) |case| {
        const selected = case.multi.filterByPlatform(case.platform);
        if (case.expect_hex) |hex| {
            try std.testing.expect(selected != null);
            try std.testing.expectEqualSlices(u8, hex, selected.?.digest.hex);
        } else {
            try std.testing.expect(selected == null);
        }
    }
}

test "MultiArchManifest.selectChildDescriptorByPlatform: resolvable child selection table" {
    const aux = try makeDescriptor('d', "linux", "arm64");
    defer aux.deinit(std.testing.allocator);
    const child = try makeDescriptor('e', "linux", "arm64");
    defer child.deinit(std.testing.allocator);
    const nested = try makeDescriptor('f', "linux", "arm64");
    defer nested.deinit(std.testing.allocator);
    const aux_only = try makeDescriptor('1', "linux", "arm64");
    defer aux_only.deinit(std.testing.allocator);

    const aux_desc = Descriptor{
        .media_type = .oci_config_v1,
        .digest = aux.descriptor.digest,
        .size = aux.descriptor.size,
        .platform = aux.descriptor.platform,
    };

    const filter = Platform{ .os = "linux", .architecture = "arm64" };
    const cases = [_]struct {
        multi: MultiArchManifest,
        expected_media_type: ?MediaType,
        expected_hex: ?[]const u8,
        filter_returns_aux: bool = false,
    }{
        .{
            .multi = ociMulti(&.{ aux_desc, child.descriptor }),
            .expected_media_type = .oci_manifest_v1,
            .expected_hex = "e" ** 64,
        },
        .{
            .multi = dockerMulti(&.{Descriptor{
                .media_type = .oci_index_v1,
                .digest = nested.descriptor.digest,
                .size = nested.descriptor.size,
                .platform = nested.descriptor.platform,
            }}),
            .expected_media_type = .oci_index_v1,
            .expected_hex = "f" ** 64,
        },
        .{
            .multi = ociMulti(&.{Descriptor{
                .media_type = .oci_config_v1,
                .digest = aux_only.descriptor.digest,
                .size = aux_only.descriptor.size,
                .platform = aux_only.descriptor.platform,
            }}),
            .expected_media_type = null,
            .expected_hex = null,
            .filter_returns_aux = true,
        },
    };

    for (cases) |case| {
        const selected = case.multi.selectChildDescriptorByPlatform(filter);
        if (case.expected_media_type) |media_type| {
            try std.testing.expect(selected != null);
            try std.testing.expectEqual(media_type, selected.?.media_type);
            try std.testing.expectEqualSlices(u8, case.expected_hex.?, selected.?.digest.hex);
        } else {
            try std.testing.expect(selected == null);
        }
        if (case.filter_returns_aux) {
            try std.testing.expect(case.multi.filterByPlatform(filter) != null);
        }
    }
}

test "OciImageIndex.jsonParse: parses minimal index and platform fields" {
    const parsed = try json.parse(OciImageIndex, std.testing.allocator, minimal_oci_index_json);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_index_v1, parsed.value.media_type);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.manifests.len);
    try std.testing.expectEqualSlices(u8, "linux", parsed.value.manifests[0].platform.?.os);
}

test "OciImageIndex.jsonParse: annotations round-trip through stringifyForTest" {
    const annotated_json =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": [],
        \\  "annotations": { "org.opencontainers.image.description": "multi-arch index" }
        \\}
    ;
    const annotated = try json.parse(OciImageIndex, std.testing.allocator, annotated_json);
    defer annotated.deinit();

    var aw = try json.stringifyForTest(annotated.value);
    defer aw.deinit();
    const out = aw.written();

    try std.testing.expect(std.mem.indexOf(u8, out, "\"annotations\"") != null);

    const reparsed = try json.parse(OciImageIndex, std.testing.allocator, out);
    defer reparsed.deinit();

    try std.testing.expect(reparsed.value.annotations != null);
}

test "OciImageIndex.jsonParse: malformed payloads return exact errors" {
    const errors = [_]struct { json_bytes: []const u8, expected: anyerror }{
        .{
            .json_bytes =
            \\{"schemaVersion":1,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}
            ,
            .expected = error.UnexpectedToken,
        },
        .{
            .json_bytes =
            \\{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[]}
            ,
            .expected = error.UnexpectedToken,
        },
        .{
            .json_bytes =
            \\{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}
            ,
            .expected = error.MissingField,
        },
    };

    for (errors) |case| try expectJsonParseError(OciImageIndex, case.json_bytes, case.expected);
}

test "OciImageIndex.jsonParse: rejects unknown fields when ignore_unknown_fields is false" {
    var scanner = std.json.Scanner.initCompleteInput(std.testing.allocator, "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[],\"extra\":1}");
    defer scanner.deinit();

    try std.testing.expectError(error.UnknownField, OciImageIndex.jsonParse(std.testing.allocator, &scanner, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
        .max_value_len = std.json.default_max_value_len,
    }));
}

test "DockerManifestList.jsonParse: parses minimal manifest list" {
    const parsed = try json.parse(DockerManifestList, std.testing.allocator, minimal_docker_list_json);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.docker_manifest_list_v2, parsed.value.media_type);
    try std.testing.expectEqualSlices(u8, "arm64", parsed.value.manifests[0].platform.?.architecture);
}

test "DockerManifestList.jsonStringify: emits schemaVersion, mediaType, and digest" {
    const arm64 = try makeDescriptor('a', "linux", "amd64");
    defer arm64.deinit(std.testing.allocator);
    const list = DockerManifestList{
        .schema_version = 2,
        .media_type = .docker_manifest_list_v2,
        .manifests = &.{arm64.descriptor},
    };

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(list);
    const out = aw.written();

    try std.testing.expect(std.mem.indexOf(u8, out, "\"schemaVersion\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"mediaType\":\"application/vnd.docker.distribution.manifest.list.v2+json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, arm64.descriptor.digest.hex) != null);
}

test "DockerManifestList.jsonParse: malformed payloads return exact errors" {
    const errors = [_]struct { json_bytes: []const u8, expected: anyerror }{
        .{
            .json_bytes =
            \\{"schemaVersion":1,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[]}
            ,
            .expected = error.UnexpectedToken,
        },
        .{
            .json_bytes =
            \\{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}
            ,
            .expected = error.UnexpectedToken,
        },
        .{
            .json_bytes =
            \\{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json"}
            ,
            .expected = error.MissingField,
        },
    };

    for (errors) |case| try expectJsonParseError(DockerManifestList, case.json_bytes, case.expected);
}

test "MultiArchManifest.filterByPlatform: spec fixtures and live busybox/quay selection" {
    const oci = try test_support.parseFixture(
        OciImageIndex,
        "fixtures/indexes/oci-image-index-spec-example.json",
        16 * 1024,
    );
    defer oci.deinit();
    try std.testing.expectEqual(@as(usize, 2), oci.value.manifests.len);
    try std.testing.expect(oci.value.annotations != null);
    const oci_multi = MultiArchManifest{ .oci = oci.value };
    const oci_selected = oci_multi.filterByPlatform(.{ .os = "linux", .architecture = "amd64" });
    try std.testing.expectEqualSlices(u8, "5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270", oci_selected.?.digest.hex);

    const docker = try test_support.parseFixture(
        DockerManifestList,
        "fixtures/indexes/docker-manifest-list-spec-example.json",
        16 * 1024,
    );
    defer docker.deinit();
    try std.testing.expectEqual(@as(usize, 2), docker.value.manifests.len);
    const docker_multi = MultiArchManifest{ .docker = docker.value };
    const docker_selected = docker_multi.filterByPlatform(.{ .os = "linux", .architecture = "amd64" });
    try std.testing.expectEqualSlices(u8, "5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270", docker_selected.?.digest.hex);

    const busybox = try test_support.parseFixture(
        OciImageIndex,
        "fixtures/indexes/busybox-latest-live-oci-index.json",
        32 * 1024,
    );
    defer busybox.deinit();
    try std.testing.expect(busybox.value.manifests.len >= 8);
    const busybox_multi = MultiArchManifest{ .oci = busybox.value };
    const busybox_cases = [_]struct {
        platform: Platform,
        expect_match: bool,
        digest_hex: ?[]const u8 = null,
    }{
        .{
            .platform = .{ .os = "linux", .architecture = "amd64" },
            .expect_match = true,
            .digest_hex = "b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        },
        .{
            .platform = .{ .os = "linux", .architecture = "arm64", .variant = "v8" },
            .expect_match = true,
            .digest_hex = "c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6",
        },
        .{ .platform = .{ .os = "windows", .architecture = "amd64" }, .expect_match = false },
    };
    for (busybox_cases) |case| {
        const selected = busybox_multi.filterByPlatform(case.platform);
        if (!case.expect_match) {
            try std.testing.expect(selected == null);
            continue;
        }
        try std.testing.expectEqualSlices(u8, case.digest_hex.?, selected.?.digest.hex);
    }

    const quay = try test_support.parseFixture(
        DockerManifestList,
        "fixtures/indexes/quay-prometheus-busybox-latest-live-docker-manifest-list.json",
        16 * 1024,
    );
    defer quay.deinit();
    try std.testing.expectEqual(@as(usize, 6), quay.value.manifests.len);
    const quay_multi = MultiArchManifest{ .docker = quay.value };
    const quay_amd64 = quay_multi.filterByPlatform(.{ .os = "linux", .architecture = "amd64" });
    try std.testing.expectEqual(MediaType.docker_manifest_v2, quay_amd64.?.media_type);
    try std.testing.expectEqualSlices(u8, "35e7e430350711653810b2b3cc889fec2a6e0175c078e4114964c7252c411209", quay_amd64.?.digest.hex);
}

test "OciImageIndex.jsonParse: allocation failures do not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            const parsed = try json.parse(OciImageIndex, allocator, bytes);
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
        }
    }.run, .{minimal_oci_index_json});
}

test "DockerManifestList.jsonParse: allocation failures do not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            const parsed = try json.parse(DockerManifestList, allocator, bytes);
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
        }
    }.run, .{minimal_docker_list_json});
}

test "OciImageIndex.jsonParse: pseudo-random inputs never panic" {
    var seed: u64 = 0x51ce_b00c;
    var buf: [256]u8 = undefined;

    for (0..512) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const len: usize = @intCast(seed % (buf.len + 1));
        for (buf[0..len]) |*b| {
            seed = seed *% 6364136223846793005 +% 1;
            b.* = @truncate(seed >> 32);
        }

        const result = json.parse(OciImageIndex, std.testing.allocator, buf[0..len]);
        if (result) |parsed| {
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
            try std.testing.expectEqual(MediaType.oci_index_v1, parsed.value.media_type);
        } else |_| {}
    }
}
