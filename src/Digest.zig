//! OCI content digest: algorithm + hex string.
//!
//! Parses "algorithm:hex" strings (e.g. "sha256:<64 hex chars>").
//! The hex slice borrows from the input. No allocation.
//! SHA256 is the only algorithm in v1. The Algorithm enum is extensible.

const std = @import("std");

pub const Algorithm = enum {
    sha256,

    pub fn hexLen(self: Algorithm) usize {
        return switch (self) {
            .sha256 => 64,
        };
    }
};

pub const ParseError = error{
    MissingColon,
    UnsupportedAlgorithm,
    InvalidHexLength,
    InvalidHexChar,
};

algorithm: Algorithm,
/// Borrows from the parse input (or arena after `jsonParse`).
hex: []const u8,

const Digest = @This();

/// Returns a borrowed view into `input` (no allocation).
pub fn parse(input: []const u8) ParseError!Digest {
    const colon = std.mem.indexOfScalar(u8, input, ':') orelse return error.MissingColon;
    const alg_str = input[0..colon];
    const hex = input[colon + 1 ..];

    const alg: Algorithm = if (std.mem.eql(u8, alg_str, "sha256"))
        .sha256
    else
        return error.UnsupportedAlgorithm;

    if (hex.len != alg.hexLen()) return error.InvalidHexLength;

    for (hex) |c| {
        switch (c) {
            '0'...'9', 'a'...'f', 'A'...'F' => {},
            else => return error.InvalidHexChar,
        }
    }

    return .{ .algorithm = alg, .hex = hex };
}

pub fn eql(a: Digest, b: Digest) bool {
    return a.algorithm == b.algorithm and std.mem.eql(u8, a.hex, b.hex);
}

pub fn format(self: Digest, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("{s}:{s}", .{ @tagName(self.algorithm), self.hex });
}

/// Dupes hex into the arena so the result does not borrow the scanner buffer.
pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Digest {
    const tok = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
    defer switch (tok) {
        .allocated_string => |s| allocator.free(s),
        else => {},
    };
    const s: []const u8 = switch (tok) {
        inline .string, .allocated_string => |v| v,
        else => return error.UnexpectedToken,
    };
    const d = Digest.parse(s) catch return error.UnexpectedToken;
    const hex_owned = try allocator.dupe(u8, d.hex);
    return Digest{ .algorithm = d.algorithm, .hex = hex_owned };
}

pub fn jsonStringify(self: Digest, jw: anytype) !void {
    // "sha256:" (7) + 64 hex = 71; headroom for future algorithms.
    var buf: [128]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{s}:{s}", .{ @tagName(self.algorithm), self.hex }) catch unreachable;
    try jw.write(s);
}

// Tests
//
// parse

test "Digest.parse: valid inputs borrow hex slice and return expected fields" {
    const hex_lower = "abcdef0123456789" ** 4;
    const cases = [_]struct {
        input: []const u8,
        expect_hex: []const u8,
    }{
        .{ .input = "sha256:" ++ hex_lower, .expect_hex = hex_lower },
        .{ .input = "sha256:aAbBcCdDeEfF" ++ "0" ** 52, .expect_hex = "aAbBcCdDeEfF" ++ "0" ** 52 },
        .{ .input = "sha256:" ++ "00" ++ "ff" ++ "aa" ++ "a" ** 58, .expect_hex = "00ffaa" ++ "a" ** 58 },
    };
    for (cases) |tc| {
        const d = try parse(tc.input);
        try std.testing.expectEqual(Algorithm.sha256, d.algorithm);
        try std.testing.expectEqualSlices(u8, tc.expect_hex, d.hex);
    }
    // First case also guards the zero-allocation borrow contract.
    const borrow_input = cases[0].input;
    const borrowed = try parse(borrow_input);
    try std.testing.expectEqual(borrow_input.ptr + 7, borrowed.hex.ptr);
    try std.testing.expectEqual(@as(usize, 64), borrowed.hex.len);
}

test "Digest.parse: malformed inputs return specific errors" {
    const cases = [_]struct { input: []const u8, err: ParseError }{
        .{ .input = "", .err = error.MissingColon },
        .{ .input = ":" ++ "a" ** 64, .err = error.UnsupportedAlgorithm },
        .{ .input = "sha256" ++ "a" ** 64, .err = error.MissingColon },
        .{ .input = "md5:" ++ "a" ** 32, .err = error.UnsupportedAlgorithm },
        .{ .input = "sha384:" ++ "a" ** 64, .err = error.UnsupportedAlgorithm },
        .{ .input = "SHA256:" ++ "a" ** 64, .err = error.UnsupportedAlgorithm },
        .{ .input = "sha256:", .err = error.InvalidHexLength },
        .{ .input = "sha256:" ++ "a" ** 63, .err = error.InvalidHexLength },
        .{ .input = "sha256:" ++ "a" ** 65, .err = error.InvalidHexLength },
        .{ .input = "sha256:" ++ "a" ** 63 ++ "z", .err = error.InvalidHexChar },
        .{ .input = "sha256:z" ++ "a" ** 63, .err = error.InvalidHexChar },
        .{ .input = "sha256:" ++ "a" ** 63 ++ ":", .err = error.InvalidHexChar },
    };
    for (cases) |tc| try std.testing.expectError(tc.err, parse(tc.input));
}

test "Digest.parse: pseudo-random inputs never panic and only return declared errors" {
    var seed: u64 = 0x5eed_d1ce_57;
    var buf: [96]u8 = undefined;
    for (0..256) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const len: usize = @intCast(seed % (buf.len + 1));
        for (buf[0..len]) |*b| {
            seed = seed *% 6364136223846793005 +% 1;
            b.* = @truncate(seed >> 32);
        }
        const result = parse(buf[0..len]);
        if (result) |digest| {
            try std.testing.expectEqual(Algorithm.sha256, digest.algorithm);
            try std.testing.expectEqual(@as(usize, 64), digest.hex.len);
        } else |err| switch (err) {
            error.MissingColon, error.UnsupportedAlgorithm, error.InvalidHexLength, error.InvalidHexChar => {},
        }
    }
}

// eql

test "Digest.eql: compares algorithm and hex case-sensitively" {
    const hex = "d" ** 64;
    var other_buf: [7 + 64]u8 = undefined;
    @memcpy(other_buf[0..7], "sha256:");
    @memcpy(other_buf[7..], hex);
    const same_a = try parse("sha256:" ++ hex);
    const same_b = try parse(other_buf[0..]);
    const cases = [_]struct { a: []const u8, b: []const u8 }{
        .{ .a = "sha256:" ++ "a" ** 64, .b = "sha256:" ++ "b" ** 64 },
        .{ .a = "sha256:" ++ "a" ** 63 ++ "b", .b = "sha256:" ++ "a" ** 63 ++ "c" },
        .{ .a = "sha256:a" ++ "b" ** 63, .b = "sha256:c" ++ "b" ** 63 },
        .{ .a = "sha256:" ++ "a" ** 64, .b = "sha256:" ++ "A" ** 64 },
    };
    try std.testing.expect(eql(same_a, same_b));
    for (cases) |tc| {
        const a = try parse(tc.a);
        const b = try parse(tc.b);
        try std.testing.expect(!eql(a, b));
    }
}

// format / jsonStringify

test "Digest: format and jsonStringify emit canonical algorithm:hex" {
    const d = try parse("sha256:" ++ "b" ** 64);
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try d.format(&w);
    try std.testing.expectEqualSlices(u8, "sha256:" ++ "b" ** 64, w.buffered());

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(d);
    try std.testing.expectEqualSlices(u8, "\"sha256:" ++ "b" ** 64 ++ "\"", aw.written());
}

test "Digest.jsonParse: round-trip preserves digest and arena-owns hex" {
    const hex = "d" ** 64;
    const d = try parse("sha256:" ++ hex);
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(d);
    const out = aw.written();
    try std.testing.expectEqualSlices(u8, "\"sha256:" ++ hex ++ "\"", out);

    const reparsed = try std.json.parseFromSlice(Digest, std.testing.allocator, out, .{});
    defer reparsed.deinit();
    try std.testing.expect(eql(d, reparsed.value));
    const json_start: usize = @intFromPtr(out.ptr);
    const json_end = json_start + out.len;
    const hex_ptr: usize = @intFromPtr(reparsed.value.hex.ptr);
    try std.testing.expect(!(hex_ptr >= json_start and hex_ptr < json_end));
}

// jsonParse

test "Digest jsonParse: bad tokens return UnexpectedToken" {
    const bad_tokens = [_][]const u8{ "123", "true", "null", "{}", "\"not-a-digest\"", "\"\"" };
    for (bad_tokens) |json| {
        try std.testing.expectError(error.UnexpectedToken, std.json.parseFromSlice(Digest, std.testing.allocator, json, .{}));
    }
}

test "Digest jsonParse: allocation failures do not leak" {
    const json_bytes = "\"sha256:" ++ "c" ** 64 ++ "\"";
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const parsed = try std.json.parseFromSlice(Digest, allocator, json_bytes, .{});
            defer parsed.deinit();
            try std.testing.expectEqual(Algorithm.sha256, parsed.value.algorithm);
        }
    }.run, .{});
}

test "Digest jsonParse: repeated rounds leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();
    for (0..4) |_| {
        const parsed = try std.json.parseFromSlice(Digest, allocator, "\"sha256:" ++ "f" ** 64 ++ "\"", .{});
        parsed.deinit();
    }
}
