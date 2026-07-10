//! OCI Image Manifest and Docker V2 Schema 2 manifest.
//!
//! `config` and `layers` descriptors borrow from the parse arena after
//! `jsonParse`. Nested slice fields follow the same borrow rules as
//! `Descriptor.zig`.

const std = @import("std");
const MediaType = @import("MediaType.zig").MediaType;
const Descriptor = @import("Descriptor.zig");
const json = @import("json.zig");
const Digest = @import("Digest.zig");
const test_support = @import("test_support.zig");

schema_version: u8,
media_type: MediaType,
config: Descriptor,
layers: []const Descriptor,
annotations: ?std.json.Value = null,

const Manifest = @This();

pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Manifest {
    if (.object_begin != try source.next()) return error.UnexpectedToken;
    var result = Manifest{
        .schema_version = undefined,
        .media_type = undefined,
        .config = undefined,
        .layers = undefined,
    };
    var seen_schema_version = false;
    var seen_media_type = false;
    var seen_config = false;
    var seen_layers = false;
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
        } else if (std.mem.eql(u8, field_name, "config")) {
            result.config = try std.json.innerParse(Descriptor, allocator, source, options);
            seen_config = true;
        } else if (std.mem.eql(u8, field_name, "layers")) {
            result.layers = try std.json.innerParse([]const Descriptor, allocator, source, options);
            seen_layers = true;
        } else if (std.mem.eql(u8, field_name, "annotations")) {
            result.annotations = try std.json.innerParse(?std.json.Value, allocator, source, options);
        } else {
            if (!options.ignore_unknown_fields) return error.UnknownField;
            try source.skipValue();
        }
    }
    if (!seen_schema_version or !seen_media_type or !seen_config or !seen_layers) return error.MissingField;
    if (result.schema_version != 2) return error.UnexpectedToken;
    switch (result.media_type) {
        .oci_manifest_v1, .docker_manifest_v2 => {},
        else => return error.UnexpectedToken,
    }
    return result;
}

pub fn parseMediaTypeShallow(allocator: std.mem.Allocator, bytes: []const u8) !MediaType {
    var parsed = try std.json.parseFromSlice(
        ManifestMediaTypeProbe,
        allocator,
        bytes,
        .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_if_needed,
        },
    );
    defer parsed.deinit();
    return parsed.value.media_type;
}

const ManifestMediaTypeProbe = struct {
    media_type: MediaType,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !ManifestMediaTypeProbe {
        if (.object_begin != try source.next()) return error.UnexpectedToken;
        var seen_media_type = false;
        var media_type: MediaType = undefined;
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
            if (std.mem.eql(u8, field_name, "mediaType")) {
                media_type = try std.json.innerParse(MediaType, allocator, source, options);
                seen_media_type = true;
            } else {
                try source.skipValue();
            }
        }
        if (!seen_media_type) return error.MissingField;
        return .{ .media_type = media_type };
    }
};

pub fn jsonStringify(self: Manifest, jw: anytype) !void {
    try jw.beginObject();
    try jw.objectField("schemaVersion");
    try jw.write(self.schema_version);
    try jw.objectField("mediaType");
    try jw.write(self.media_type);
    try jw.objectField("config");
    try jw.write(self.config);
    try jw.objectField("layers");
    try jw.write(self.layers);
    if (self.annotations) |a| {
        try jw.objectField("annotations");
        try jw.write(a);
    }
    try jw.endObject();
}

// --- Tests ---

const hex_a = "a" ** 64;
const hex_b = "b" ** 64;
const hex_c = "c" ** 64;
const hex_1 = "1" ** 64;
const oci_manifest_mt = "application/vnd.oci.image.manifest.v1+json";
const docker_manifest_mt = "application/vnd.docker.distribution.manifest.v2+json";
const oci_config_mt = "application/vnd.oci.image.config.v1+json";
const oci_layer_mt = "application/vnd.oci.image.layer.v1.tar+gzip";

const config_field = "{\"mediaType\":\"" ++ oci_config_mt ++ "\",\"digest\":\"sha256:" ++ hex_a ++ "\",\"size\":256}";
const layer_field = "{\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"digest\":\"sha256:" ++ hex_b ++ "\",\"size\":4096}";
const minimal_manifest_json =
    "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":" ++ config_field ++ ",\"layers\":[]}";
const manifest_with_layer_json =
    "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":" ++ config_field ++ ",\"layers\":[" ++ layer_field ++ "]}";

// jsonParse -------------------------------------------------------------------

test "Manifest jsonParse: valid OCI and Docker payloads parse expected fields" {
    const minimal = try json.parse(Manifest, std.testing.allocator, minimal_manifest_json);
    defer minimal.deinit();
    try std.testing.expectEqual(@as(u8, 2), minimal.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, minimal.value.media_type);
    try std.testing.expectEqual(@as(u64, 256), minimal.value.config.size);
    try std.testing.expectEqual(@as(usize, 0), minimal.value.layers.len);
    try std.testing.expect(minimal.value.annotations == null);

    const with_layer = try json.parse(Manifest, std.testing.allocator, manifest_with_layer_json);
    defer with_layer.deinit();
    try std.testing.expectEqual(@as(usize, 1), with_layer.value.layers.len);
    try std.testing.expectEqual(@as(u64, 4096), with_layer.value.layers[0].size);
    try std.testing.expectEqualSlices(u8, hex_b, with_layer.value.layers[0].digest.hex);

    const annotated_json = "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":" ++ config_field ++ ",\"layers\":[],\"annotations\":{\"org.opencontainers.image.ref.name\":\"stable\"},\"vendorExtension\":\"value\"}";
    const annotated = try json.parse(Manifest, std.testing.allocator, annotated_json);
    defer annotated.deinit();
    try std.testing.expectEqualSlices(
        u8,
        "stable",
        annotated.value.annotations.?.object.get("org.opencontainers.image.ref.name").?.string,
    );

    const docker_json = "{\"schemaVersion\":2,\"mediaType\":\"" ++ docker_manifest_mt ++ "\",\"config\":" ++ config_field ++ ",\"layers\":[]}";
    const docker = try json.parse(Manifest, std.testing.allocator, docker_json);
    defer docker.deinit();
    try std.testing.expectEqual(MediaType.docker_manifest_v2, docker.value.media_type);
}

test "Manifest jsonParse: rejects invalid roots, missing fields, unknown keys, and validation rules" {
    const missing_cases = [_][]const u8{
        "{}",
        "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":" ++ config_field ++ "}",
    };
    for (missing_cases) |json_bytes| {
        try std.testing.expectError(error.MissingField, json.parse(Manifest, std.testing.allocator, json_bytes));
    }

    for ([_][]const u8{ "null", "[]" }) |json_bytes| {
        try std.testing.expectError(error.UnexpectedToken, json.parse(Manifest, std.testing.allocator, json_bytes));
    }

    const unknown_json = minimal_manifest_json[0 .. minimal_manifest_json.len - 1] ++ ",\"customField\":\"value\"}";
    try std.testing.expectError(
        error.UnknownField,
        std.json.parseFromSlice(Manifest, std.testing.allocator, unknown_json, .{ .ignore_unknown_fields = false }),
    );

    const validation_cases = [_]struct { []const u8, anyerror }{
        .{
            "{\"schemaVersion\":1,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":" ++ config_field ++ ",\"layers\":[]}",
            error.UnexpectedToken,
        },
        .{
            "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"config\":" ++ config_field ++ ",\"layers\":[]}",
            error.UnexpectedToken,
        },
    };
    for (validation_cases) |case| {
        try std.testing.expectError(case[1], json.parse(Manifest, std.testing.allocator, case[0]));
    }
}

test "Manifest jsonParse: malformed nested values return specific errors" {
    const cases = [_]struct { []const u8, anyerror }{
        .{
            "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":{\"mediaType\":\"" ++ oci_config_mt ++ "\",\"digest\":\"not-a-digest\",\"size\":1},\"layers\":[]}",
            error.UnexpectedToken,
        },
        .{
            "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":\"not-an-object\",\"layers\":[]}",
            error.UnexpectedToken,
        },
        .{
            "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":" ++ config_field ++ ",\"layers\":\"not-an-array\"}",
            error.UnexpectedToken,
        },
    };
    for (cases) |case| {
        try std.testing.expectError(case[1], json.parse(Manifest, std.testing.allocator, case[0]));
    }
}

test "Manifest jsonParse: parses checked-in manifest fixtures" {
    const cases = [_]struct {
        path: []const u8,
        media_type: MediaType,
        config_media_type: MediaType,
        layer_count: usize,
    }{
        .{
            .path = "fixtures/manifests/oci-image-manifest-spec-example.json",
            .media_type = .oci_manifest_v1,
            .config_media_type = .oci_config_v1,
            .layer_count = 3,
        },
        .{
            .path = "fixtures/manifests/busybox-amd64-live-oci-manifest.json",
            .media_type = .oci_manifest_v1,
            .config_media_type = .oci_config_v1,
            .layer_count = 1,
        },
        .{
            .path = "fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json",
            .media_type = .docker_manifest_v2,
            .config_media_type = .docker_container_image_v1,
            .layer_count = 2,
        },
    };

    for (cases) |case| {
        const parsed = try test_support.parseFixture(Manifest, case.path, 16 * 1024);
        defer parsed.deinit();
        try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
        try std.testing.expectEqual(case.media_type, parsed.value.media_type);
        try std.testing.expectEqual(case.config_media_type, parsed.value.config.media_type);
        try std.testing.expectEqual(case.layer_count, parsed.value.layers.len);
    }
}

test "Manifest jsonParse: allocation failures do not leak" {
    const json_bytes = "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":{\"mediaType\":\"" ++ oci_config_mt ++ "\",\"digest\":\"sha256:" ++ hex_c ++ "\",\"size\":7023},\"layers\":[{\"mediaType\":\"" ++ oci_layer_mt ++ "\",\"digest\":\"sha256:" ++ hex_b ++ "\",\"size\":32654}]}";

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            const parsed = try json.parse(Manifest, allocator, bytes);
            defer parsed.deinit();
            try std.testing.expectEqual(@as(usize, 1), parsed.value.layers.len);
        }
    }.run, .{json_bytes});
}

test "Manifest jsonParse: repeated parse rounds leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");

    for (0..16) |_| {
        const parsed = try json.parse(Manifest, gpa.allocator(), minimal_manifest_json);
        parsed.deinit();
    }
}

// parseMediaTypeShallow ---------------------------------------------------------

test "Manifest parseMediaTypeShallow: extracts mediaType without full manifest validation" {
    const success_cases = [_]struct { []const u8, MediaType }{
        .{ minimal_manifest_json, .oci_manifest_v1 },
        .{ "{\"mediaType\":\"" ++ docker_manifest_mt ++ "\"}", .docker_manifest_v2 },
        .{ "{\"mediaType\":\"application/vnd.oci.image.index.v1+json\"}", .oci_index_v1 },
    };
    for (success_cases) |case| {
        const mt = try Manifest.parseMediaTypeShallow(std.testing.allocator, case[0]);
        try std.testing.expectEqual(case[1], mt);
    }

    try std.testing.expectError(error.MissingField, Manifest.parseMediaTypeShallow(std.testing.allocator, "{\"schemaVersion\":2}"));
    try std.testing.expectError(error.UnexpectedToken, Manifest.parseMediaTypeShallow(std.testing.allocator, "null"));
}

// jsonStringify ----------------------------------------------------------------

test "Manifest jsonStringify: omits null annotations" {
    const config = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ hex_a),
        .size = 256,
    };
    const m = Manifest{
        .schema_version = 2,
        .media_type = .oci_manifest_v1,
        .config = config,
        .layers = &.{},
    };

    var aw = try json.stringifyForTest(m);
    defer aw.deinit();
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\"annotations\"") == null);
}

test "Manifest jsonStringify: round-trip preserves all fields" {
    const json_bytes = "{\"schemaVersion\":2,\"mediaType\":\"" ++ oci_manifest_mt ++ "\",\"config\":{\"mediaType\":\"" ++ oci_config_mt ++ "\",\"digest\":\"sha256:" ++ hex_1 ++ "\",\"size\":64},\"layers\":[" ++ layer_field ++ "],\"annotations\":{\"org.opencontainers.image.ref.name\":\"stable\"}}";

    const parsed = try json.parse(Manifest, std.testing.allocator, json_bytes);
    defer parsed.deinit();

    var aw = try json.stringifyForTest(parsed.value);
    defer aw.deinit();

    const reparsed = try json.parse(Manifest, std.testing.allocator, aw.written());
    defer reparsed.deinit();

    try std.testing.expectEqual(parsed.value.schema_version, reparsed.value.schema_version);
    try std.testing.expectEqual(parsed.value.media_type, reparsed.value.media_type);
    try std.testing.expectEqualSlices(u8, parsed.value.config.digest.hex, reparsed.value.config.digest.hex);
    try std.testing.expectEqual(parsed.value.layers.len, reparsed.value.layers.len);
    try std.testing.expectEqualSlices(u8, parsed.value.layers[0].digest.hex, reparsed.value.layers[0].digest.hex);
    try std.testing.expectEqualSlices(
        u8,
        "stable",
        reparsed.value.annotations.?.object.get("org.opencontainers.image.ref.name").?.string,
    );
}
