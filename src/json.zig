//! JSON helpers for z-oci types.
//!
//! parse() is a thin wrapper around std.json.parseFromSlice that sets the
//! options callers need for OCI payloads: ignore unknown fields (the spec
//! allows extension fields) and allocate strings from the provided allocator.
//!
//! The returned std.json.Parsed(T) owns an arena. Call .deinit() when done.
//! All string slices in the parsed value point into that arena.

const std = @import("std");

/// Parse JSON bytes into T. Unknown fields are silently ignored so
/// the caller handles spec extensions without error.
///
/// alloc_always: every string is copied into the arena so Parsed(T) is
/// self-contained. Callers may free json_bytes as soon as parse returns.
pub fn parse(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

// ── Tests ────────────────────────────────────────────────────────────────────

const Manifest = @import("Manifest.zig");
const Descriptor = @import("Descriptor.zig");
const Digest = @import("Digest.zig");
const MediaType = @import("MediaType.zig").MediaType;
const Index = @import("Index.zig");
const Platform = @import("Platform.zig");

// Descriptor round-trip -------------------------------------------------------

test "json: Descriptor round-trip" {
    // Arrange
    const json_bytes =
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\  "size": 1234
        \\}
    ;
    // Act: parse
    const parsed = try parse(Descriptor, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    const d = parsed.value;
    // Assert: fields
    try std.testing.expectEqual(MediaType.oci_manifest_v1, d.media_type);
    try std.testing.expectEqual(Digest.Algorithm.sha256, d.digest.algorithm);
    try std.testing.expectEqualSlices(u8, "a" ** 64, d.digest.hex);
    try std.testing.expectEqual(@as(u64, 1234), d.size);
}

test "json: Descriptor stringifies with camelCase field names" {
    // Arrange
    const hex = "b" ** 64;
    const d = Descriptor{
        .media_type = .oci_index_v1,
        .digest = try Digest.parse("sha256:" ++ hex),
        .size = 512,
    };
    // Act
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(d);
    const out = aw.written();
    // Assert: camelCase keys present
    try std.testing.expect(std.mem.indexOf(u8, out, "\"mediaType\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"digest\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"size\"") != null);
}

test "json: Descriptor round-trip with platform" {
    // Arrange
    const json_bytes =
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\  "size": 256,
        \\  "platform": { "os": "linux", "architecture": "arm64", "variant": "v8" }
        \\}
    ;
    // Act
    const parsed = try parse(Descriptor, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    const d = parsed.value;
    // Assert
    try std.testing.expect(d.platform != null);
    try std.testing.expectEqualSlices(u8, "linux", d.platform.?.os);
    try std.testing.expectEqualSlices(u8, "arm64", d.platform.?.architecture);
    try std.testing.expectEqualSlices(u8, "v8", d.platform.?.variant.?);
}

// Manifest round-trip ---------------------------------------------------------

test "json: Manifest round-trip" {
    // Arrange
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
    // Act
    const parsed = try parse(Manifest, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    const m = parsed.value;
    // Assert
    try std.testing.expectEqual(@as(u8, 2), m.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, m.media_type);
    try std.testing.expectEqual(@as(u64, 256), m.config.size);
    try std.testing.expectEqual(@as(usize, 1), m.layers.len);
    try std.testing.expectEqual(@as(u64, 4096), m.layers[0].size);
}

test "json: Manifest stringifies with camelCase field names" {
    // Arrange
    const hex_a = "a" ** 64;
    const hex_b = "b" ** 64;
    const config = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ hex_a),
        .size = 256,
    };
    const layer = Descriptor{
        .media_type = .oci_manifest_v1,
        .digest = try Digest.parse("sha256:" ++ hex_b),
        .size = 4096,
    };
    const layers = [_]Descriptor{layer};
    const m = Manifest{
        .schema_version = 2,
        .media_type = .oci_manifest_v1,
        .config = config,
        .layers = &layers,
    };
    // Act
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(m);
    const out = aw.written();
    // Assert camelCase keys
    try std.testing.expect(std.mem.indexOf(u8, out, "\"schemaVersion\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"mediaType\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"config\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"layers\"") != null);
}

// OciImageIndex round-trip ----------------------------------------------------

test "json: OciImageIndex round-trip" {
    // Arrange
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
    // Act
    const parsed = try parse(Index.OciImageIndex, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    const idx = parsed.value;
    // Assert
    try std.testing.expectEqual(@as(u8, 2), idx.schema_version);
    try std.testing.expectEqual(MediaType.oci_index_v1, idx.media_type);
    try std.testing.expectEqual(@as(usize, 1), idx.manifests.len);
    try std.testing.expectEqualSlices(u8, "linux", idx.manifests[0].platform.?.os);
}

// DockerManifestList round-trip -----------------------------------------------

test "json: DockerManifestList round-trip" {
    // Arrange
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
    // Act
    const parsed = try parse(Index.DockerManifestList, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    const lst = parsed.value;
    // Assert
    try std.testing.expectEqual(@as(u8, 2), lst.schema_version);
    try std.testing.expectEqual(MediaType.docker_manifest_list_v2, lst.media_type);
    try std.testing.expectEqual(@as(usize, 1), lst.manifests.len);
    try std.testing.expectEqualSlices(u8, "arm64", lst.manifests[0].platform.?.architecture);
}

// Lifecycle test: Parsed(T).deinit frees all memory --------------------------

test "json: Parsed lifecycle with testing allocator" {
    // Arrange: use testing.allocator to detect leaks.
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\    "size": 1
        \\  },
        \\  "layers": []
        \\}
    ;
    // Act + Assert: no leak detected by testing.allocator
    const parsed = try parse(Manifest, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
}

// Unknown fields are ignored (spec extensions) --------------------------------

test "json: unknown fields in JSON are silently ignored" {
    // Arrange: the OCI spec allows vendor extension fields.
    const json_bytes =
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\  "size": 99,
        \\  "unknownExtensionField": "vendor-specific-value"
        \\}
    ;
    // Act: should succeed without error
    const parsed = try parse(Descriptor, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    // Assert
    try std.testing.expectEqual(@as(u64, 99), parsed.value.size);
}

// Parsed(T) is self-contained: input bytes can be freed after parse() ---------

test "json: Parsed(T) does not borrow from input bytes" {
    // Arrange: allocate json_bytes on the heap then free before using parsed value.
    const json_bytes = try std.testing.allocator.dupe(u8,
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        \\  "size": 77
        \\}
    );
    const parsed = try parse(Descriptor, std.testing.allocator, json_bytes);
    // Free the input before reading the parsed value.
    std.testing.allocator.free(json_bytes);
    defer parsed.deinit();
    // Assert: values are readable — they live in the arena, not in json_bytes.
    try std.testing.expectEqual(@as(u64, 77), parsed.value.size);
    try std.testing.expectEqualSlices(u8, "e" ** 64, parsed.value.digest.hex);
}

// Error paths — missing required fields ---------------------------------------

test "json: Descriptor missing required field returns error" {
    // Missing "size" is a required field.
    const json_bytes =
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\}
    ;
    const result = parse(Descriptor, std.testing.allocator, json_bytes);
    try std.testing.expectError(error.MissingField, result);
}

test "json: Manifest missing required config field returns error" {
    // Missing "config" — layers alone is not enough.
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "layers": []
        \\}
    ;
    const result = parse(Manifest, std.testing.allocator, json_bytes);
    try std.testing.expectError(error.MissingField, result);
}

// Error paths — malformed values ----------------------------------------------

test "json: invalid digest string returns error" {
    // The digest has 63 hex chars — one short of the required 64.
    const json_bytes =
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\  "size": 1
        \\}
    ;
    const result = parse(Descriptor, std.testing.allocator, json_bytes);
    try std.testing.expectError(error.UnexpectedToken, result);
}

test "json: unrecognized media type string returns error" {
    // Unknown MIME type must be rejected by MediaType.jsonParse.
    const json_bytes =
        \\{
        \\  "mediaType": "application/x-custom-unknown-type",
        \\  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\  "size": 1
        \\}
    ;
    const result = parse(Descriptor, std.testing.allocator, json_bytes);
    try std.testing.expectError(error.UnexpectedToken, result);
}

test "json: wrong JSON type for size returns error" {
    // "size" is a string, not a number.
    const json_bytes =
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\  "size": "not-a-number"
        \\}
    ;
    const result = parse(Descriptor, std.testing.allocator, json_bytes);
    try std.testing.expect(if (result) |p| blk: {
        p.deinit();
        break :blk false;
    } else |_| true);
}

// Platform round-trip with os.version and os.features ------------------------

test "json: Platform round-trip with os.version and os.features" {
    // Arrange: a Windows platform entry with os.version and os.features.
    const json_bytes =
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        \\  "size": 256,
        \\  "platform": {
        \\    "os": "windows",
        \\    "architecture": "amd64",
        \\    "os.version": "10.0.17763.1234",
        \\    "os.features": ["win32k"]
        \\  }
        \\}
    ;
    // Act
    const parsed = try parse(Descriptor, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    const plat = parsed.value.platform.?;
    // Assert
    try std.testing.expectEqualSlices(u8, "windows", plat.os);
    try std.testing.expectEqualSlices(u8, "10.0.17763.1234", plat.os_version.?);
    try std.testing.expectEqual(@as(usize, 1), plat.os_features.?.len);
    try std.testing.expectEqualSlices(u8, "win32k", plat.os_features.?[0]);
}
