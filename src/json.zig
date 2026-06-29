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

/// Parse JSON bytes into T with strings borrowed from `bytes` when possible.
///
/// `bytes` must outlive the returned `Parsed(T)` and any values read from it.
/// Call `.deinit()` when done; it frees only arena-allocated storage.
pub fn parseBorrowing(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    });
}

/// Deep-copy a `Parsed(T)` from a transient arena onto `caller_allocator`.
///
/// The input `parsed` is deinitialized; the returned value owns its own arena
/// through `caller_allocator`.
pub fn promoteParsed(
    comptime T: type,
    caller_allocator: std.mem.Allocator,
    parsed: std.json.Parsed(T),
) !std.json.Parsed(T) {
    const scratch_allocator = parsed.arena.allocator();
    var aw: std.Io.Writer.Allocating = .init(scratch_allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(parsed.value);

    const bytes = try caller_allocator.dupe(u8, aw.written());
    errdefer caller_allocator.free(bytes);

    const promoted = try parse(T, caller_allocator, bytes);
    caller_allocator.free(bytes);
    parsed.deinit();
    return promoted;
}

/// Test helper: stringify any json-serializable value into an owned buffer.
/// The caller owns the returned Allocating writer and must call .deinit().
pub fn stringifyForTest(value: anytype) !std.Io.Writer.Allocating {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(value);
    return aw;
}

// Tests

const Manifest = @import("Manifest.zig");
const Descriptor = @import("Descriptor.zig");

// Lifecycle: Parsed(T).deinit frees all memory

test "json: parseBorrowing requires input bytes to outlive parsed value" {
    const json_bytes = try std.testing.allocator.dupe(u8,
        \\{
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        \\  "size": 256
        \\}
    );
    defer std.testing.allocator.free(json_bytes);

    const parsed = try parseBorrowing(Descriptor, std.testing.allocator, json_bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u64, 256), parsed.value.size);
}

test "json: promoteParsed copies parsed value onto caller allocator" {
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

    var transient_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer transient_arena.deinit();
    const transient = transient_arena.allocator();

    const transient_parsed = try parse(Manifest, transient, json_bytes);
    const promoted = try promoteParsed(Manifest, std.testing.allocator, transient_parsed);
    defer promoted.deinit();

    try std.testing.expectEqual(@as(u32, 2), promoted.value.schema_version);
    try std.testing.expectEqualStrings("application/vnd.oci.image.manifest.v1+json", promoted.value.media_type.toString());
}

fn expectManifestFieldsMatch(expected: Manifest, actual: Manifest) !void {
    try std.testing.expectEqual(expected.schema_version, actual.schema_version);
    try std.testing.expectEqual(expected.media_type, actual.media_type);
    try std.testing.expectEqual(expected.config.media_type, actual.config.media_type);
    try std.testing.expectEqual(expected.config.size, actual.config.size);
    try std.testing.expectEqualSlices(u8, expected.config.digest.hex, actual.config.digest.hex);
    try std.testing.expectEqual(expected.layers.len, actual.layers.len);
    for (expected.layers, actual.layers) |expected_layer, actual_layer| {
        try std.testing.expectEqual(expected_layer.media_type, actual_layer.media_type);
        try std.testing.expectEqual(expected_layer.size, actual_layer.size);
        try std.testing.expectEqualSlices(u8, expected_layer.digest.hex, actual_layer.digest.hex);
    }
    try std.testing.expectEqual(expected.annotations != null, actual.annotations != null);
    if (expected.annotations) |expected_annotations| {
        const actual_annotations = actual.annotations.?;
        try std.testing.expectEqual(expected_annotations.object.count(), actual_annotations.object.count());
        var it = expected_annotations.object.iterator();
        while (it.next()) |entry| {
            const actual_value = actual_annotations.object.get(entry.key_ptr.*) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(std.meta.activeTag(entry.value_ptr.*), std.meta.activeTag(actual_value));
            switch (entry.value_ptr.*) {
                .string => |expected_string| try std.testing.expectEqualStrings(expected_string, actual_value.string),
                else => return error.TestUnexpectedResult,
            }
        }
    }
}

fn readBusyboxManifestFixtureAlloc(allocator: std.mem.Allocator) ![]u8 {
    var buffer: [16 * 1024 + 1]u8 = undefined;
    const bytes = std.Io.Dir.cwd().readFile(
        std.testing.io,
        "fixtures/manifests/busybox-amd64-live-oci-manifest.json",
        &buffer,
    ) catch return error.TestUnexpectedResult;
    return try allocator.dupe(u8, bytes);
}

test "json: promoteParsed matches direct parse for live busybox fixture" {
    const json_bytes = try readBusyboxManifestFixtureAlloc(std.testing.allocator);
    defer std.testing.allocator.free(json_bytes);

    const direct = try parse(Manifest, std.testing.allocator, json_bytes);
    defer direct.deinit();

    var transient_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer transient_arena.deinit();
    const transient = transient_arena.allocator();

    const transient_parsed = try parse(Manifest, transient, json_bytes);
    const promoted = try promoteParsed(Manifest, std.testing.allocator, transient_parsed);
    defer promoted.deinit();

    try expectManifestFieldsMatch(direct.value, promoted.value);
}

test "json: promoteParsed allocation failures preserve input parsed value" {
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

    const State = struct {
        fn run(caller_allocator: std.mem.Allocator) !void {
            var transient_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer transient_arena.deinit();
            const transient = transient_arena.allocator();

            var transient_parsed = try parse(Manifest, transient, json_bytes);
            errdefer transient_parsed.deinit();

            const promoted = try promoteParsed(Manifest, caller_allocator, transient_parsed);
            promoted.deinit();
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}

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

// Unknown fields are ignored (spec extensions allowed by OCI)

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

// Parsed(T) does not borrow from input bytes

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
    // Assert: values are readable (they live in the arena, not in json_bytes).
    try std.testing.expectEqual(@as(u64, 77), parsed.value.size);
    try std.testing.expectEqualSlices(u8, "e" ** 64, parsed.value.digest.hex);
}

test "json: allocation failures do not leak partially parsed arena state" {
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
            const parsed = try parse(Manifest, allocator, bytes);
            defer parsed.deinit();

            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
            try std.testing.expectEqual(@as(usize, 1), parsed.value.layers.len);
            try std.testing.expectEqualSlices(u8, "b" ** 64, parsed.value.layers[0].digest.hex);
        }
    }.run, .{json_bytes});
}

test "json: repeated success and parse failures leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const valid_manifest =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\    "size": 17
        \\  },
        \\  "layers": []
        \\}
    ;
    const invalid_cases = [_]struct { []const u8, anyerror }{
        .{
            \\{
            \\  "schemaVersion": 2,
            \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
            \\  "layers": []
            \\}
            ,
            error.MissingField,
        },
        .{
            \\{
            \\  "schemaVersion": 2,
            \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
            \\  "config": {
            \\    "mediaType": "application/vnd.oci.image.config.v1+json",
            \\    "digest": "not-a-digest",
            \\    "size": 1
            \\  },
            \\  "layers": []
            \\}
            ,
            error.UnexpectedToken,
        },
    };

    for (0..16) |_| {
        const parsed = try parse(Manifest, allocator, valid_manifest);
        parsed.deinit();
    }

    for (invalid_cases) |case| {
        try std.testing.expectError(case[1], parse(Manifest, allocator, case[0]));
    }
}

// Error paths: missing required fields

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
    // Missing "config": layers alone is not enough.
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

// Error paths: malformed values

test "json: invalid digest string returns error" {
    // The digest has 63 hex chars: one short of the required 64.
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

// Platform round-trip with os.version and os.features

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

test "json: 10000 pseudo-random manifest payloads never panic" {
    // Fuzz-style smoke test. Malformed JSON must fail with an error, not a panic.
    var seed: u64 = 0xabad_1dea;
    var buf: [256]u8 = undefined;

    for (0..10_000) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const len: usize = @intCast(seed % (buf.len + 1));

        for (buf[0..len]) |*b| {
            seed = seed *% 6364136223846793005 +% 1;
            b.* = @truncate(seed >> 32);
        }

        const result = parse(Manifest, std.testing.allocator, buf[0..len]);
        if (result) |parsed| {
            var owned = parsed;
            defer owned.deinit();

            try std.testing.expect(owned.value.schema_version <= std.math.maxInt(u8));
            try std.testing.expect(owned.value.media_type.toString().len > 0);
            try std.testing.expectEqual(@as(usize, 64), owned.value.config.digest.hex.len);
            for (owned.value.config.digest.hex) |c| switch (c) {
                '0'...'9', 'a'...'f', 'A'...'F' => {},
                else => return error.TestUnexpectedResult,
            };
            for (owned.value.layers) |layer| {
                try std.testing.expect(layer.media_type.toString().len > 0);
                try std.testing.expectEqual(@as(usize, 64), layer.digest.hex.len);
            }

            var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
            defer aw.deinit();
            var ws: std.json.Stringify = .{ .writer = &aw.writer };
            try ws.write(owned.value);

            const reparsed = try parse(Manifest, std.testing.allocator, aw.written());
            defer reparsed.deinit();
            try std.testing.expectEqual(owned.value.schema_version, reparsed.value.schema_version);
            try std.testing.expectEqual(owned.value.media_type, reparsed.value.media_type);
            try std.testing.expectEqualSlices(u8, owned.value.config.digest.hex, reparsed.value.config.digest.hex);
            try std.testing.expectEqual(owned.value.layers.len, reparsed.value.layers.len);
        } else |_| {}
    }
}
