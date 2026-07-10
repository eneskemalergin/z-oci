//! Shared helpers for fixture-backed tests.
//!
//! Tests stay colocated with the owning source files, so small test helpers live
//! in src/ as well. These helpers are intentionally narrow: they only cover the
//! repeated fixture loading and parsing scaffolding used across the colocated
//! descriptor, manifest, and index tests.

const std = @import("std");
const json = @import("json.zig");
const Descriptor = @import("Descriptor.zig");

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

const descriptor_fixture = "fixtures/descriptors/oci-descriptor-artifact-spec-example.json";
const descriptor_fixture_limit = 16 * 1024;

test "test_support.parseFixture: copies fixture bytes into caller-owned arena" {
    const parsed = try parseFixture(Descriptor, descriptor_fixture, descriptor_fixture_limit);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u64, 123), parsed.value.size);
    try std.testing.expectEqualSlices(
        u8,
        "87923725d74f4bfb94c9e86d64170f7521aad8221a5de834851470ca142da630",
        parsed.value.digest.hex,
    );
    try std.testing.expectEqualSlices(
        u8,
        "application/vnd.example.sbom.v1",
        parsed.value.artifact_type.?,
    );
}

test "test_support.parseFixture: maps missing file and oversize stream to exact errors" {
    try std.testing.expectError(
        error.FileNotFound,
        parseFixture(Descriptor, "fixtures/does-not-exist.json", descriptor_fixture_limit),
    );

    try std.testing.expectError(error.StreamTooLong, parseFixture(Descriptor, descriptor_fixture, 32));
}

test "test_support.parseFixture: stays leak-free under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");

    const parsed = try parseFixtureWithAllocator(
        Descriptor,
        gpa.allocator(),
        descriptor_fixture,
        descriptor_fixture_limit,
    );
    parsed.deinit();
}
