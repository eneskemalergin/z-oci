//! JSON helpers for z-oci types.
//!
//! parse() is a thin wrapper around std.json.parseFromSlice that sets the
//! options callers need for OCI payloads: ignore unknown fields (the spec
//! allows extension fields) and allocate strings from the provided allocator.
//!
//! `parse()` returns an arena-owned std.json.Parsed(T); call `.deinit()` when
//! done. `parseBorrowing()` can retain string slices into its input, which must
//! outlive the parsed value; call `.deinit()` for its arena as well.

const std = @import("std");

const Manifest = @import("Manifest.zig");
const Platform = @import("Platform.zig");
const MediaType = @import("MediaType.zig").MediaType;

/// `alloc_always`: self-contained arena; caller may free `bytes` immediately.
pub fn parse(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

/// Strings may borrow from `bytes`; `bytes` must outlive the result.
pub fn parseBorrowing(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    });
}

/// Moves a transient `Parsed(T)` onto `caller_allocator`.
///
/// On success, deinitializes `parsed`. On error, leaves `parsed` owned by the
/// caller, which must deinitialize it.
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

/// Caller owns the returned writer (`deinit` required).
pub fn stringifyForTest(allocator: std.mem.Allocator, value: anytype) !std.Io.Writer.Allocating {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(value);
    return aw;
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

const minimal_manifest_json =
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

test "json.parse: arena-owned Manifest survives freeing input buffer" {
    const json_bytes = try std.testing.allocator.dupe(u8,
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
    );

    const parsed = try parse(Manifest, std.testing.allocator, json_bytes);
    std.testing.allocator.free(json_bytes);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
    try std.testing.expectEqualSlices(u8, "c" ** 64, parsed.value.config.digest.hex);
}

test "json.parse: ignores unknown top-level fields on Manifest" {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\    "size": 17
        \\  },
        \\  "layers": [],
        \\  "io.zoci.extension": "allowed"
        \\}
    ;

    const parsed = try parse(Manifest, std.testing.allocator, json_bytes);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, parsed.value.media_type);
}

test "json: parse returns specific errors for malformed manifests and JSON" {
    const cases = [_]struct { payload: []const u8, err: anyerror }{
        .{
            .payload =
            \\{
            \\  "schemaVersion": 2,
            \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
            \\  "layers": []
            \\}
            ,
            .err = error.MissingField,
        },
        .{
            .payload =
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
            .err = error.UnexpectedToken,
        },
        .{ .payload = "{", .err = error.UnexpectedEndOfInput },
    };
    for (cases) |case| try std.testing.expectError(case.err, parse(Manifest, std.testing.allocator, case.payload));
}

test "json: parse allocation failures do not leak partially parsed arena state" {
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
        }
    }.run, .{json_bytes});
}

test "json.parseBorrowing: parsed Platform aliases input buffer after mutation" {
    var json_bytes: [64]u8 = undefined;
    const content = "{\"os\": \"linux\", \"architecture\": \"amd64\"}";
    @memcpy(json_bytes[0..content.len], content);

    const parsed = try parseBorrowing(Platform, std.testing.allocator, json_bytes[0..content.len]);
    defer parsed.deinit();

    try std.testing.expectEqualSlices(u8, "linux", parsed.value.os);

    @memset(json_bytes[0..content.len], 'X');

    try std.testing.expectEqual(@as(u8, 'X'), parsed.value.os[0]);
}

test "json.stringifyForTest: round-trips Platform through parseBorrowing" {
    const platform = Platform{ .os = "linux", .architecture = "amd64" };

    var aw = try stringifyForTest(std.testing.allocator, platform);
    defer aw.deinit();

    const reparsed = try parseBorrowing(Platform, std.testing.allocator, aw.written());
    defer reparsed.deinit();

    try std.testing.expectEqualSlices(u8, "linux", reparsed.value.os);
    try std.testing.expectEqualSlices(u8, "amd64", reparsed.value.architecture);
}

test "json: promoteParsed matches direct parse on busybox fixture" {
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

test "json: promoteParsed allocation failures do not leak transient parsed value" {
    const MockHarness = struct {
        fn run(caller_allocator: std.mem.Allocator) !void {
            var transient_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer transient_arena.deinit();
            const transient = transient_arena.allocator();

            var transient_parsed = try parse(Manifest, transient, minimal_manifest_json);
            errdefer transient_parsed.deinit();

            const promoted = try promoteParsed(Manifest, caller_allocator, transient_parsed);
            promoted.deinit();
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, MockHarness.run, .{});
}

test "json: pseudo-random payloads never panic when parsed as Manifest" {
    var seed: u64 = 0xabad_1dea;
    var buf: [256]u8 = undefined;

    for (0..256) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const len: usize = @intCast(seed % (buf.len + 1));
        for (buf[0..len]) |*b| {
            seed = seed *% 6364136223846793005 +% 1;
            b.* = @truncate(seed >> 32);
        }

        const result = parse(Manifest, std.testing.allocator, buf[0..len]);
        if (result) |parsed| {
            defer parsed.deinit();
            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
        } else |_| {}
    }
}
