//! OCI content descriptor. Points to a manifest, config blob, or layer.
//!
//! Used in Index.zig to list per-platform manifests, and in Manifest.zig
//! for the config and layer entries.
//!
//! jsonParse and jsonStringify map camelCase JSON field names (mediaType,
//! artifactType) to snake_case Zig fields.
//!
//! annotations stores the raw JSON value from the OCI spec annotations map.
//! The value is a std.json.Value.object when present.

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
/// OCI spec field: annotations. Value is std.json.Value.object when present.
annotations: ?std.json.Value = null,
/// OCI spec field: artifactType. Present when descriptor points to an artifact.
artifact_type: ?[]const u8 = null,

const Descriptor = @This();

/// Parse a JSON descriptor object. Maps camelCase JSON names to Zig fields.
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

/// Stringify to a JSON descriptor object with camelCase OCI field names.
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
