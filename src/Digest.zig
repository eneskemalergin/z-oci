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

// ── Tests ────────────────────────────────────────────────────────────────────

test "parse: valid sha256" {
    const hex = "a" ** 64;
    const d = try parse("sha256:" ++ hex);
    try std.testing.expectEqual(Algorithm.sha256, d.algorithm);
    try std.testing.expectEqualSlices(u8, hex, d.hex);
}

test "parse: missing colon" {
    try std.testing.expectError(error.MissingColon, parse("sha256" ++ "a" ** 64));
}

test "parse: unsupported algorithm" {
    try std.testing.expectError(error.UnsupportedAlgorithm, parse("md5:" ++ "a" ** 32));
}

test "parse: hex too short" {
    try std.testing.expectError(error.InvalidHexLength, parse("sha256:abc"));
}

test "parse: hex too long" {
    try std.testing.expectError(error.InvalidHexLength, parse("sha256:" ++ "a" ** 65));
}

test "parse: invalid hex char" {
    try std.testing.expectError(error.InvalidHexChar, parse("sha256:" ++ "z" ** 64));
}

test "parse: uppercase hex is valid" {
    const hex = "A" ** 64;
    const d = try parse("sha256:" ++ hex);
    try std.testing.expectEqualSlices(u8, hex, d.hex);
}

test "eql: same digest" {
    const hex = "abcdef1234567890" ** 4;
    const a = try parse("sha256:" ++ hex);
    const b = try parse("sha256:" ++ hex);
    try std.testing.expect(eql(a, b));
}

test "eql: different hex" {
    const a = try parse("sha256:" ++ "a" ** 64);
    const b = try parse("sha256:" ++ "b" ** 64);
    try std.testing.expect(!eql(a, b));
}
