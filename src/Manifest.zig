//! OCI Image Manifest and Docker V2 Schema 2 manifest.
//!
//! Both spec formats share the same shape: schema version, media type,
//! a config descriptor, and a list of layer descriptors. The media_type
//! field tells them apart at runtime.
//!
//! jsonParse and jsonStringify map camelCase JSON field names (schemaVersion,
//! mediaType) to snake_case Zig fields.

const std = @import("std");
const MediaType = @import("MediaType.zig").MediaType;
const Descriptor = @import("Descriptor.zig");
const json = @import("json.zig");

/// OCI spec field: schemaVersion. Always 2 for current formats.
schema_version: u8,
/// OCI spec field: mediaType.
media_type: MediaType,
/// OCI spec field: config. Points to the image configuration blob.
config: Descriptor,
/// OCI spec field: layers. Ordered list of filesystem layer blobs.
layers: []const Descriptor,
/// OCI spec field: annotations. Value is std.json.Value.object when present.
annotations: ?std.json.Value = null,

const Manifest = @This();

/// Parse a JSON manifest object. Maps camelCase JSON names to Zig fields.
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
    return result;
}

/// Stringify to a JSON manifest object with camelCase OCI field names.
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

test "Manifest JSON: round-trip" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "size": 256
        \\  },
        \\  "layers": [
        \\    {
        \\      "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\      "size": 4096
        \\    }
        \\  ]
        \\}
    ;

    const parsed = try json.parse(Manifest, std.testing.allocator, json_bytes);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
    try std.testing.expectEqual(@as(u64, 256), parsed.value.config.size);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.layers.len);
    try std.testing.expectEqual(@as(u64, 4096), parsed.value.layers[0].size);
}

test "Manifest JSON: stringifies with camelCase field names" {
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

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(m);
    const out = aw.written();

    try std.testing.expect(std.mem.indexOf(u8, out, "\"schemaVersion\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"mediaType\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"config\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"layers\"") != null);
}

test "Manifest JSON: annotations round-trip and deinit leak-free" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\    "digest": "sha256:1212121212121212121212121212121212121212121212121212121212121212",
        \\    "size": 64
        \\  },
        \\  "layers": [],
        \\  "annotations": {
        \\    "org.opencontainers.image.ref.name": "stable"
        \\  }
        \\}
    ;

    const parsed = try json.parse(Manifest, std.testing.allocator, json_bytes);
    defer parsed.deinit();

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(parsed.value);
    const out = aw.written();

    const reparsed = try json.parse(Manifest, std.testing.allocator, out);
    defer reparsed.deinit();

    try std.testing.expect(std.mem.indexOf(u8, out, "\"annotations\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "org.opencontainers.image.ref.name") != null);
    try std.testing.expect(reparsed.value.annotations != null);
}
