//! OCI content descriptor. Points to a manifest, config blob, or layer.
//!
//! Slice fields and nested `Platform` values borrow from their source unless
//! explicitly duplicated. `jsonParse` results borrow from the parse arena.
//! `Digest.hex` borrows from the parsed digest string (see `Digest.zig`).

const std = @import("std");
const MediaType = @import("MediaType.zig").MediaType;
const Digest = @import("Digest.zig");
const Platform = @import("Platform.zig");
const json = @import("json.zig");
const test_support = @import("test_support.zig");

media_type: MediaType,
digest: Digest,
size: u64,
/// Used only for index or manifest-list entries.
platform: ?Platform = null,
urls: ?[]const []const u8 = null,
annotations: ?std.json.Value = null,
artifact_type: ?[]const u8 = null,

const Descriptor = @This();

pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Descriptor {
    if (.object_begin != try source.next()) return error.UnexpectedToken;
    var result = Descriptor{
        .media_type = undefined,
        .digest = undefined,
        .size = undefined,
    };
    var seen_media_type = false;
    var seen_digest = false;
    var seen_size = false;
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
            result.media_type = try std.json.innerParse(MediaType, allocator, source, options);
            seen_media_type = true;
        } else if (std.mem.eql(u8, field_name, "digest")) {
            result.digest = try std.json.innerParse(Digest, allocator, source, options);
            seen_digest = true;
        } else if (std.mem.eql(u8, field_name, "size")) {
            result.size = try std.json.innerParse(u64, allocator, source, options);
            seen_size = true;
        } else if (std.mem.eql(u8, field_name, "platform")) {
            result.platform = try std.json.innerParse(?Platform, allocator, source, options);
        } else if (std.mem.eql(u8, field_name, "urls")) {
            result.urls = try std.json.innerParse(?[]const []const u8, allocator, source, options);
        } else if (std.mem.eql(u8, field_name, "annotations")) {
            result.annotations = try std.json.innerParse(?std.json.Value, allocator, source, options);
        } else if (std.mem.eql(u8, field_name, "artifactType")) {
            result.artifact_type = try std.json.innerParse(?[]const u8, allocator, source, options);
        } else {
            if (!options.ignore_unknown_fields) return error.UnknownField;
            try source.skipValue();
        }
    }
    if (!seen_media_type or !seen_digest or !seen_size) return error.MissingField;
    return result;
}

pub fn jsonStringify(self: Descriptor, jw: anytype) !void {
    try jw.beginObject();
    try jw.objectField("mediaType");
    try jw.write(self.media_type);
    try jw.objectField("digest");
    try jw.write(self.digest);
    try jw.objectField("size");
    try jw.write(self.size);
    if (self.platform) |p| {
        try jw.objectField("platform");
        try jw.write(p);
    }
    if (self.urls) |u| {
        try jw.objectField("urls");
        try jw.write(u);
    }
    if (self.annotations) |a| {
        try jw.objectField("annotations");
        try jw.write(a);
    }
    if (self.artifact_type) |t| {
        try jw.objectField("artifactType");
        try jw.write(t);
    }
    try jw.endObject();
}

const hex_a = "a" ** 64;
const hex_d = "d" ** 64;
const hex_1 = "1" ** 64;
const manifest_media_type = "application/vnd.oci.image.manifest.v1+json";
const minimal_json =
    "{\"mediaType\":\"" ++ manifest_media_type ++ "\",\"digest\":\"sha256:" ++ hex_a ++ "\",\"size\":1234}";

test "Descriptor jsonParse: valid payloads parse expected fields" {
    const full_json =
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\  "size": 256,
        \\  "platform": {
        \\    "os": "linux",
        \\    "architecture": "arm64",
        \\    "variant": "v8",
        \\    "os.version": "5.10.0",
        \\    "os.features": ["seccomp"]
        \\  },
        \\  "urls": [
        \\    "https://cdn.example.com/layer.tar.gz",
        \\    "https://fallback.example.com/layer.tar.gz"
        \\  ],
        \\  "annotations": {
        \\    "org.opencontainers.image.source": "https://github.com/example/repo"
        \\  },
        \\  "artifactType": "application/vnd.example.sbom.v1",
        \\  "vendorExtension": "value"
        \\}
    ;

    const minimal = try json.parse(Descriptor, std.testing.allocator, minimal_json);
    defer minimal.deinit();
    try std.testing.expectEqual(MediaType.oci_manifest_v1, minimal.value.media_type);
    try std.testing.expectEqual(Digest.Algorithm.sha256, minimal.value.digest.algorithm);
    try std.testing.expectEqualSlices(u8, hex_a, minimal.value.digest.hex);
    try std.testing.expectEqual(@as(u64, 1234), minimal.value.size);
    try std.testing.expect(minimal.value.platform == null);
    try std.testing.expect(minimal.value.urls == null);
    try std.testing.expect(minimal.value.annotations == null);
    try std.testing.expect(minimal.value.artifact_type == null);

    const full = try json.parse(Descriptor, std.testing.allocator, full_json);
    defer full.deinit();
    const plat = full.value.platform.?;
    try std.testing.expectEqualSlices(u8, "linux", plat.os);
    try std.testing.expectEqualSlices(u8, "arm64", plat.architecture);
    try std.testing.expectEqualSlices(u8, "v8", plat.variant.?);
    try std.testing.expectEqualSlices(u8, "5.10.0", plat.os_version.?);
    try std.testing.expectEqual(@as(usize, 1), plat.os_features.?.len);
    try std.testing.expectEqual(@as(usize, 2), full.value.urls.?.len);
    try std.testing.expectEqualSlices(u8, "https://cdn.example.com/layer.tar.gz", full.value.urls.?[0]);
    try std.testing.expectEqualSlices(u8, "application/vnd.example.sbom.v1", full.value.artifact_type.?);
    try std.testing.expectEqualSlices(
        u8,
        "https://github.com/example/repo",
        full.value.annotations.?.object.get("org.opencontainers.image.source").?.string,
    );
}

test "Descriptor jsonParse: rejects invalid roots, missing fields, and unknown keys" {
    const missing_cases = [_][]const u8{
        "{}",
        "{\"mediaType\":\"" ++ manifest_media_type ++ "\",\"digest\":\"sha256:" ++ hex_a ++ "\"}",
    };
    for (missing_cases) |json_bytes| {
        try std.testing.expectError(error.MissingField, json.parse(Descriptor, std.testing.allocator, json_bytes));
    }

    for ([_][]const u8{ "null", "[]" }) |json_bytes| {
        try std.testing.expectError(error.UnexpectedToken, json.parse(Descriptor, std.testing.allocator, json_bytes));
    }

    const unknown_json =
        "{\"mediaType\":\"" ++ manifest_media_type ++ "\",\"digest\":\"sha256:" ++ hex_a ++ "\",\"size\":1,\"customField\":\"value\"}";
    try std.testing.expectError(
        error.UnknownField,
        std.json.parseFromSlice(Descriptor, std.testing.allocator, unknown_json, .{ .ignore_unknown_fields = false }),
    );
}

test "Descriptor jsonParse: malformed field values return specific errors" {
    const prefix = "{\"mediaType\":\"" ++ manifest_media_type ++ "\",";
    const cases = [_]struct { []const u8, anyerror }{
        .{ prefix ++ "\"digest\":\"sha256:" ++ hex_a ++ "\",\"size\":\"not-a-number\"}", error.InvalidCharacter },
        .{ prefix ++ "\"digest\":\"not-a-digest\",\"size\":1234}", error.UnexpectedToken },
        .{ prefix ++ "\"digest\":\"sha256:" ++ ("a" ** 63) ++ "\",\"size\":1}", error.UnexpectedToken },
        .{ "{\"mediaType\":\"application/x-custom-unknown-type\",\"digest\":\"sha256:" ++ hex_a ++ "\",\"size\":1}", error.UnexpectedToken },
        .{ prefix ++ "\"digest\":\"sha256:" ++ hex_a ++ "\",\"size\":1,\"platform\":\"linux\"}", error.UnexpectedToken },
        .{ prefix ++ "\"digest\":\"sha256:" ++ hex_a ++ "\",\"size\":1,\"urls\":\"https://example.com/blob\"}", error.UnexpectedToken },
    };
    for (cases) |case| {
        try std.testing.expectError(case[1], json.parse(Descriptor, std.testing.allocator, case[0]));
    }
}

test "Descriptor jsonParse: parses upstream OCI descriptor fixture" {
    const parsed = try test_support.parseFixture(
        Descriptor,
        "fixtures/descriptors/oci-descriptor-artifact-spec-example.json",
        16 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
    try std.testing.expectEqual(@as(u64, 123), parsed.value.size);
    try std.testing.expectEqualSlices(u8, "87923725d74f4bfb94c9e86d64170f7521aad8221a5de834851470ca142da630", parsed.value.digest.hex);
    try std.testing.expectEqualSlices(u8, "application/vnd.example.sbom.v1", parsed.value.artifact_type.?);
}

test "Descriptor jsonParse: allocation failures do not leak" {
    const json_bytes = "{\"mediaType\":\"" ++ manifest_media_type ++ "\",\"digest\":\"sha256:" ++ hex_d ++ "\",\"size\":1234,\"urls\":[\"https://example.com/blob\"],\"artifactType\":\"application/vnd.example.sbom.v1\"}";

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            const parsed = try json.parse(Descriptor, allocator, bytes);
            defer parsed.deinit();
            try std.testing.expectEqual(@as(usize, 1), parsed.value.urls.?.len);
        }
    }.run, .{json_bytes});
}

test "Descriptor jsonParse: repeated parse rounds leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");

    for (0..16) |_| {
        const parsed = try json.parse(Descriptor, gpa.allocator(), minimal_json);
        parsed.deinit();
    }
}

test "Descriptor jsonStringify: omits null optional fields" {
    const d = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ hex_a),
        .size = 0,
    };

    var aw = try json.stringifyForTest(d);
    defer aw.deinit();
    const out = aw.written();

    try std.testing.expect(std.mem.indexOf(u8, out, "\"platform\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"urls\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"annotations\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"artifactType\"") == null);
}

test "Descriptor jsonStringify: round-trip preserves all fields" {
    const json_bytes = "{\"mediaType\":\"" ++ manifest_media_type ++ "\",\"digest\":\"sha256:" ++ hex_1 ++ "\",\"size\":512,\"platform\":{\"os\":\"linux\",\"architecture\":\"arm64\",\"variant\":\"v8\"},\"urls\":[\"https://example.com/blob\"],\"annotations\":{\"org.opencontainers.image.source\":\"https://github.com/example/repo\"},\"artifactType\":\"application/vnd.example.sbom.v1\"}";

    const parsed = try json.parse(Descriptor, std.testing.allocator, json_bytes);
    defer parsed.deinit();

    var aw = try json.stringifyForTest(parsed.value);
    defer aw.deinit();

    const reparsed = try json.parse(Descriptor, std.testing.allocator, aw.written());
    defer reparsed.deinit();

    try std.testing.expectEqual(parsed.value.media_type, reparsed.value.media_type);
    try std.testing.expectEqual(parsed.value.size, reparsed.value.size);
    try std.testing.expectEqualSlices(u8, parsed.value.digest.hex, reparsed.value.digest.hex);
    try std.testing.expectEqualSlices(u8, parsed.value.platform.?.os, reparsed.value.platform.?.os);
    try std.testing.expectEqualSlices(u8, parsed.value.urls.?[0], reparsed.value.urls.?[0]);
    try std.testing.expectEqualSlices(u8, parsed.value.artifact_type.?, reparsed.value.artifact_type.?);
    try std.testing.expectEqualSlices(
        u8,
        "https://github.com/example/repo",
        reparsed.value.annotations.?.object.get("org.opencontainers.image.source").?.string,
    );
}
