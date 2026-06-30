//! Shared helpers for fixture-backed tests.
//!
//! Tests stay colocated with the owning source files, so small test helpers live
//! in src/ as well. These helpers are intentionally narrow: they only cover the
//! repeated fixture loading and parsing scaffolding used across the colocated
//! descriptor, manifest, and index tests.

const std = @import("std");
const json = @import("json.zig");
const Descriptor = @import("Descriptor.zig");

/// Read a fixture into a temporary buffer, parse it into a self-contained
/// std.json.Parsed(T), then free the raw bytes before returning.
///
/// The caller owns the returned Parsed(T) arena and must call .deinit().
pub fn parseFixture(comptime T: type, path: []const u8, comptime max_bytes: usize) !std.json.Parsed(T) {
    return parseFixtureWithAllocator(T, std.testing.allocator, path, max_bytes);
}

fn parseFixtureWithAllocator(
    comptime T: type,
    allocator: std.mem.Allocator,
    path: []const u8,
    comptime max_bytes: usize,
) !std.json.Parsed(T) {
    var bytes_buffer: [max_bytes + 1]u8 = undefined;
    const bytes = try readBoundedFixture(path, &bytes_buffer, max_bytes);

    return json.parse(T, allocator, bytes);
}

fn readBoundedFixture(path: []const u8, buffer: []u8, max_bytes: usize) ![]u8 {
    const bytes = try std.Io.Dir.cwd().readFile(std.testing.io, path, buffer);
    if (bytes.len > max_bytes) return error.StreamTooLong;
    return bytes;
}

test "test_support: parseFixture result survives helper buffer teardown" {
    const parsed = try parseFixture(
        Descriptor,
        "fixtures/descriptors/oci-descriptor-artifact-spec-example.json",
        16 * 1024,
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u64, 123), parsed.value.size);
    try std.testing.expectEqualSlices(
        u8,
        "87923725d74f4bfb94c9e86d64170f7521aad8221a5de834851470ca142da630",
        parsed.value.digest.hex,
    );
    try std.testing.expect(parsed.value.artifact_type != null);
}

test "test_support: parseFixture returns error for nonexistent path" {
    try std.testing.expectError(
        error.FileNotFound,
        parseFixture(Descriptor, "fixtures/does-not-exist.json", 16 * 1024),
    );
}

test "test_support: parseFixture enforces the max-bytes limit" {
    try std.testing.expectError(
        error.StreamTooLong,
        parseFixture(
            Descriptor,
            "fixtures/descriptors/oci-descriptor-artifact-spec-example.json",
            32,
        ),
    );
}

test "test_support: fixture helper success and failure paths leave no residual allocations under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    for (0..8) |_| {
        const parsed = try parseFixtureWithAllocator(
            Descriptor,
            allocator,
            "fixtures/descriptors/oci-descriptor-artifact-spec-example.json",
            16 * 1024,
        );
        parsed.deinit();
    }

    try std.testing.expectError(
        error.StreamTooLong,
        parseFixtureWithAllocator(
            Descriptor,
            allocator,
            "fixtures/descriptors/oci-descriptor-artifact-spec-example.json",
            32,
        ),
    );
}
