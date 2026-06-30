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
    if (result.schema_version != 2) return error.UnexpectedToken;
    switch (result.media_type) {
        .oci_manifest_v1, .docker_manifest_v2 => {},
        else => return error.UnexpectedToken,
    }
    return result;
}

/// Parse only the `mediaType` field for resolve-depth workloads.
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

    /// Parse only the `mediaType` field from a manifest JSON object.
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

// --- Tests ---

test "Manifest: struct literal stores required fields and defaults" {
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
    try std.testing.expectEqualSlices(u8, "a" ** 64, m.config.digest.hex);
    try std.testing.expect(m.annotations == null);

    const empty_layers = Manifest{
        .schema_version = 2,
        .media_type = .oci_manifest_v1,
        .config = config,
        .layers = &.{},
    };
    try std.testing.expectEqual(@as(usize, 0), empty_layers.layers.len);
}

test "Manifest parseMediaTypeShallow: extracts mediaType from manifest JSON" {
    const oci_manifest =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "size": 1
        \\  },
        \\  "layers": []
        \\}
    ;

    const mt = try Manifest.parseMediaTypeShallow(std.testing.allocator, oci_manifest);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, mt);
}

test "Manifest parseMediaTypeShallow: minimal JSON with only mediaType" {
    const minimal = "{\"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\"}";
    const mt = try Manifest.parseMediaTypeShallow(std.testing.allocator, minimal);
    try std.testing.expectEqual(MediaType.docker_manifest_v2, mt);
}

test "Manifest parseMediaTypeShallow: missing mediaType returns MissingField" {
    const json_bytes = "{\"schemaVersion\": 2}";
    try std.testing.expectError(error.MissingField, Manifest.parseMediaTypeShallow(std.testing.allocator, json_bytes));
}

test "Manifest parseMediaTypeShallow: index mediaType is parsed without manifest validation" {
    const index_json = "{\"mediaType\": \"application/vnd.oci.image.index.v1+json\"}";
    const mt = try Manifest.parseMediaTypeShallow(std.testing.allocator, index_json);
    try std.testing.expectEqual(MediaType.oci_index_v1, mt);
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

test "Manifest JSON: parses required fields" {
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

    var aw = try json.stringifyForTest(m);
    defer aw.deinit();
    const out = aw.written();

    try std.testing.expect(std.mem.indexOf(u8, out, "\"schemaVersion\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"mediaType\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"config\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"layers\"") != null);
}

test "Manifest JSON: stringify/reparse preserves annotations leak-free" {
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

    var aw = try json.stringifyForTest(parsed.value);
    defer aw.deinit();
    const out = aw.written();

    const reparsed = try json.parse(Manifest, std.testing.allocator, out);
    defer reparsed.deinit();

    try std.testing.expect(std.mem.indexOf(u8, out, "\"annotations\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "org.opencontainers.image.ref.name") != null);
    try std.testing.expect(reparsed.value.annotations != null);
}

test "Manifest JSON: rejects schemaVersion other than 2" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 1,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:1212121212121212121212121212121212121212121212121212121212121212",
        \\    "size": 64
        \\  },
        \\  "layers": []
        \\}
    ;

    try std.testing.expectError(error.UnexpectedToken, json.parse(Manifest, std.testing.allocator, json_bytes));
}

test "Manifest JSON: rejects index mediaType for manifest payloads" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:3434343434343434343434343434343434343434343434343434343434343434",
        \\    "size": 64
        \\  },
        \\  "layers": []
        \\}
    ;

    try std.testing.expectError(error.UnexpectedToken, json.parse(Manifest, std.testing.allocator, json_bytes));
}

test "Manifest JSON: parses upstream OCI manifest fixture with real config and layer media types" {
    const parsed = try test_support.parseFixture(
        Manifest,
        "fixtures/manifests/oci-image-manifest-spec-example.json",
        16 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
    try std.testing.expectEqual(MediaType.oci_config_v1, parsed.value.config.media_type);
    try std.testing.expectEqual(@as(u64, 7023), parsed.value.config.size);
    try std.testing.expectEqual(@as(usize, 3), parsed.value.layers.len);
    try std.testing.expectEqual(MediaType.oci_layer_v1_tar_gzip, parsed.value.layers[0].media_type);
    try std.testing.expectEqual(@as(u64, 73109), parsed.value.layers[2].size);
    try std.testing.expect(parsed.value.annotations != null);
}

test "Manifest JSON: parses live busybox amd64 OCI manifest fixture" {
    const parsed = try test_support.parseFixture(
        Manifest,
        "fixtures/manifests/busybox-amd64-live-oci-manifest.json",
        16 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
    try std.testing.expectEqual(MediaType.oci_config_v1, parsed.value.config.media_type);
    try std.testing.expectEqualSlices(u8, "925ff61909aebae4bcc9bc04bb96a8bd15cd2271f13159fe95ce4338824531dd", parsed.value.config.digest.hex);
    try std.testing.expectEqual(@as(u64, 459), parsed.value.config.size);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.layers.len);
    try std.testing.expectEqual(MediaType.oci_layer_v1_tar_gzip, parsed.value.layers[0].media_type);
    try std.testing.expectEqual(@as(u64, 2211398), parsed.value.layers[0].size);
    try std.testing.expect(parsed.value.annotations != null);
}

test "Manifest JSON: parses live Quay busybox amd64 Docker manifest fixture" {
    const parsed = try test_support.parseFixture(
        Manifest,
        "fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json",
        16 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.docker_manifest_v2, parsed.value.media_type);
    try std.testing.expectEqual(MediaType.docker_container_image_v1, parsed.value.config.media_type);
    try std.testing.expectEqualSlices(u8, "e00da1501c19257e522754fabd8c68feadcd501657722353d0583852343aad0d", parsed.value.config.digest.hex);
    try std.testing.expectEqual(@as(u64, 891), parsed.value.config.size);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.layers.len);
    try std.testing.expectEqual(MediaType.docker_layer_gzip, parsed.value.layers[0].media_type);
    try std.testing.expectEqual(@as(u64, 324609), parsed.value.layers[1].size);
}

test "Manifest JSON: allocation failures do not leak" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "size": 7023
        \\  },
        \\  "layers": [
        \\    {
        \\      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        \\      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\      "size": 32654
        \\    }
        \\  ]
        \\}
    ;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            const parsed = try json.parse(Manifest, allocator, bytes);
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
            try std.testing.expectEqual(@as(usize, 1), parsed.value.layers.len);
        }
    }.run, .{json_bytes});
}

test "Manifest JSON: repeated parse rounds leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\    "size": 1
        \\  },
        \\  "layers": []
        \\}
    ;
    const iterations = [_]usize{ 16, 1000 };
    for (iterations) |n| {
        for (0..n) |_| {
            const parsed = try json.parse(Manifest, allocator, json_bytes);
            parsed.deinit();
        }
    }
}

test "Manifest JSON: missing layers returns MissingField" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:1212121212121212121212121212121212121212121212121212121212121212",
        \\    "size": 64
        \\  }
        \\}
    ;
    try std.testing.expectError(error.MissingField, json.parse(Manifest, std.testing.allocator, json_bytes));
}
