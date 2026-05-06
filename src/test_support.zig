//! Shared helpers for fixture-backed tests.
//!
//! Phase 1 keeps tests colocated with the owning source files, so small test
//! helpers live in src/ as well. These helpers are intentionally narrow: they
//! only cover the repeated fixture loading and parsing scaffolding used across
//! the colocated descriptor, manifest, and index tests.

const std = @import("std");
const json = @import("json.zig");
const Descriptor = @import("Descriptor.zig");

/// Read a fixture into a temporary buffer, parse it into a self-contained
/// std.json.Parsed(T), then free the raw bytes before returning.
///
/// The caller owns the returned Parsed(T) arena and must call .deinit().
pub fn parseFixture(comptime T: type, path: []const u8, max_bytes: usize) !std.json.Parsed(T) {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        std.testing.allocator,
        .limited(max_bytes),
    );
    defer std.testing.allocator.free(bytes);

    return json.parse(T, std.testing.allocator, bytes);
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
