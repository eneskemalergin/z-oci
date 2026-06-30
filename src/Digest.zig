//! OCI content digest: algorithm + hex string.
//!
//! Parses "algorithm:hex" strings (e.g. "sha256:<64 hex chars>").
//! The hex slice borrows from the input. No allocation.
//! SHA256 is the only algorithm in v1. The Algorithm enum is extensible.

const std = @import("std");

/// The hash algorithm. Only sha256 in v1.
pub const Algorithm = enum {
    sha256,

    /// Expected hex string length for this algorithm.
    pub fn hexLen(self: Algorithm) usize {
        return switch (self) {
            .sha256 => 64,
        };
    }
};

/// Errors from [`parse`].
pub const ParseError = error{
    MissingColon,
    UnsupportedAlgorithm,
    InvalidHexLength,
    InvalidHexChar,
};

algorithm: Algorithm,
/// Borrowed slice into the original input. No copy made.
hex: []const u8,

const Digest = @This();

/// Parse "algorithm:hex" into a Digest. Returns a borrowed view into `input`.
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

/// Case-sensitive equality. Both algorithm and hex must match.
pub fn eql(a: Digest, b: Digest) bool {
    return a.algorithm == b.algorithm and std.mem.eql(u8, a.hex, b.hex);
}

/// Formats as "sha256:<hex>". Use "{f}" in format strings.
pub fn format(self: Digest, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("{s}:{s}", .{ @tagName(self.algorithm), self.hex });
}

/// Parse a JSON string value as "algorithm:hex".
/// The hex slice is copied into the arena allocator so the returned Digest
/// does not borrow from the scanner buffer.
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
    // Dupe hex into the arena so the Digest does not borrow from the
    // scanner input buffer. Callers can free the input after parse().
    const hex_owned = try allocator.dupe(u8, d.hex);
    return Digest{ .algorithm = d.algorithm, .hex = hex_owned };
}

/// Stringify as a JSON string "algorithm:hex".
pub fn jsonStringify(self: Digest, jw: anytype) !void {
    // Stack buffer: "sha256:" (7) + 64 hex = 71; extra headroom for future algorithms.
    var buf: [128]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{s}:{s}", .{ @tagName(self.algorithm), self.hex }) catch unreachable;
    try jw.write(s);
}

// Tests

test "parse: hex slice borrows from input without copying" {
    // Guards the zero-allocation contract: d.hex must point inside input,
    // not into a separately allocated buffer.
    const input = "sha256:" ++ "b" ** 64;
    const d = try parse(input);
    // "sha256:" is 7 bytes; hex starts at offset 7.
    try std.testing.expectEqual(input.ptr + 7, d.hex.ptr);
    try std.testing.expectEqual(@as(usize, 64), d.hex.len);
}

test "parse: mixed case hex is accepted" {
    // All of 0-9, a-f, A-F must be valid hex digits.
    const d = try parse("sha256:aAbBcCdDeEfF" ++ "0" ** 52);
    try std.testing.expectEqual(Algorithm.sha256, d.algorithm);
}

test "parse: algorithm matching is case-sensitive, SHA256 uppercase is rejected" {
    // Guards against accidentally using eqlIgnoreCase for the algorithm string.
    // OCI spec uses lowercase algorithm names.
    try std.testing.expectError(error.UnsupportedAlgorithm, parse("SHA256:" ++ "a" ** 64));
}

test "parse: malformed inputs return specific errors" {
    const cases = [_]struct { input: []const u8, err: ParseError }{
        .{ .input = "", .err = error.MissingColon },
        .{ .input = ":" ++ "a" ** 64, .err = error.UnsupportedAlgorithm },
        .{ .input = "sha256" ++ "a" ** 64, .err = error.MissingColon },
        .{ .input = "md5:" ++ "a" ** 32, .err = error.UnsupportedAlgorithm },
        .{ .input = "sha256:", .err = error.InvalidHexLength },
        .{ .input = "sha256:" ++ "a" ** 63, .err = error.InvalidHexLength },
        .{ .input = "sha256:" ++ "a" ** 65, .err = error.InvalidHexLength },
        .{ .input = "sha256:" ++ "a" ** 63 ++ "z", .err = error.InvalidHexChar },
        .{ .input = "sha256:z" ++ "a" ** 63, .err = error.InvalidHexChar },
    };
    for (cases) |tc| {
        try std.testing.expectError(tc.err, parse(tc.input));
    }
}

// eql -------------------------------------------------------------------------

test "eql: identical digests return true" {
    const hex = "abcdef0123456789" ** 4;
    const a = try parse("sha256:" ++ hex);
    const b = try parse("sha256:" ++ hex);
    try std.testing.expect(eql(a, b));
}

test "eql: differing hex strings return false" {
    const cases = [_]struct { a: []const u8, b: []const u8 }{
        .{ .a = "sha256:" ++ "a" ** 64, .b = "sha256:" ++ "b" ** 64 },
        .{ .a = "sha256:" ++ "a" ** 63 ++ "b", .b = "sha256:" ++ "a" ** 63 ++ "c" },
        .{ .a = "sha256:a" ++ "b" ** 63, .b = "sha256:c" ++ "b" ** 63 },
    };
    for (cases) |tc| {
        const a = try parse(tc.a);
        const b = try parse(tc.b);
        try std.testing.expect(!eql(a, b));
    }
}

test "parse: 10000 pseudo-random inputs either parse correctly or return a known error" {
    // Fuzz-style smoke test. The parser must never panic on arbitrary bytes.
    var seed: u64 = 0x5eed_d1ce_57;
    var buf: [96]u8 = undefined;

    for (0..10_000) |_| {
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
            for (digest.hex) |c| switch (c) {
                '0'...'9', 'a'...'f', 'A'...'F' => {},
                else => return error.TestUnexpectedResult,
            };
        } else |err| switch (err) {
            error.MissingColon,
            error.UnsupportedAlgorithm,
            error.InvalidHexLength,
            error.InvalidHexChar,
            => {},
        }
    }
}

// jsonParse / jsonStringify ---------------------------------------------------

test "Digest jsonParse: valid sha256 hex string" {
    const json_bytes = "\"sha256:" ++ "a" ** 64 ++ "\"";
    const parsed = try std.json.parseFromSlice(Digest, std.testing.allocator, json_bytes, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(Algorithm.sha256, parsed.value.algorithm);
    try std.testing.expectEqualSlices(u8, "a" ** 64, parsed.value.hex);
}

test "Digest jsonParse: non-string token returns UnexpectedToken" {
    try std.testing.expectError(error.UnexpectedToken, std.json.parseFromSlice(Digest, std.testing.allocator, "123", .{}));
}

test "Digest jsonParse: invalid digest string returns UnexpectedToken" {
    try std.testing.expectError(error.UnexpectedToken, std.json.parseFromSlice(Digest, std.testing.allocator, "\"not-a-digest\"", .{}));
}

test "Digest format: produces canonical algorithm:hex string" {
    const d = try parse("sha256:" ++ "b" ** 64);
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try d.format(&w);
    try std.testing.expectEqualSlices(u8, "sha256:" ++ "b" ** 64, w.buffered());
}

test "Digest jsonStringify: produces canonical algorithm:hex JSON string" {
    const d = try parse("sha256:" ++ "b" ** 64);
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(d);
    try std.testing.expectEqualSlices(u8, "\"sha256:" ++ "b" ** 64 ++ "\"", aw.written());
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

test "parse: 00, ff, and boundary hex values are accepted" {
    const d = try parse("sha256:" ++ "00" ++ "ff" ++ "aa" ++ "a" ** 58);
    try std.testing.expectEqualSlices(u8, "00ffaa" ++ "a" ** 58, d.hex);
}

test "Digest jsonStringify: round-trip preserves digest" {
    const hex = "d" ** 64;
    const d = try parse("sha256:" ++ hex);
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(d);
    const out = aw.written();
    const reparsed = try std.json.parseFromSlice(Digest, std.testing.allocator, out, .{});
    defer reparsed.deinit();
    try std.testing.expectEqual(Algorithm.sha256, reparsed.value.algorithm);
    try std.testing.expectEqualSlices(u8, hex, reparsed.value.hex);
}
