//! Small offline workflow smoke matrix.
//!
//! These tests sit above the owning unit tests and below any future integration
//! layer. They exercise the current toolkit the way a real user would: parse a
//! fixture, derive a reference URL component, select a platform, and keep a
//! cloned result alive past arena teardown.

const std = @import("std");
const z_oci = @import("z_oci");

test "workflow smoke: parse manifest fixture, stringify, and reparse" {
    const parsed = try parseWorkflowFixture(
        z_oci.Manifest,
        "fixtures/manifests/busybox-amd64-live-oci-manifest.json",
        32 * 1024,
    );
    defer parsed.deinit();

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(parsed.value);

    const reparsed = try z_oci.json.parse(z_oci.Manifest, std.testing.allocator, aw.written());
    defer reparsed.deinit();

    try std.testing.expectEqual(parsed.value.media_type, reparsed.value.media_type);
    try std.testing.expectEqual(parsed.value.config.media_type, reparsed.value.config.media_type);
    try std.testing.expectEqual(parsed.value.layers.len, reparsed.value.layers.len);
    try std.testing.expectEqualSlices(u8, parsed.value.config.digest.hex, reparsed.value.config.digest.hex);
}

test "workflow smoke: parse image reference and derive repository path and ref string" {
    const cases = [_]struct {
        input: []const u8,
        repository_path: []const u8,
        ref_string: []const u8,
    }{
        .{
            .input = "ubuntu:22.04",
            .repository_path = "library/ubuntu",
            .ref_string = "22.04",
        },
        .{
            .input = "registry-1.docker.io/library/busybox@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            .repository_path = "library/busybox",
            .ref_string = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        },
    };

    for (cases) |case| {
        var ref = try z_oci.Reference.parse(std.testing.allocator, case.input);
        defer ref.deinit(std.testing.allocator);

        try std.testing.expectEqualSlices(u8, case.repository_path, ref.repositoryPath());
        try std.testing.expectEqualSlices(u8, case.ref_string, ref.refString());
    }
}

test "workflow smoke: parse index fixture, select platform, and assert descriptor digest" {
    const parsed = try parseWorkflowFixture(
        z_oci.OciImageIndex,
        "fixtures/indexes/busybox-latest-live-oci-index.json",
        32 * 1024,
    );
    defer parsed.deinit();

    const multi = z_oci.MultiArchManifest{ .oci = parsed.value };
    const selected = multi.filterByPlatform(.{ .os = "linux", .architecture = "arm64", .variant = "v8" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqualSlices(u8, "c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6", selected.?.digest.hex);
}

test "workflow smoke: ResolveResult clone survives arena teardown" {
    var cloned: z_oci.ResolveResult = undefined;
    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        const original = z_oci.ResolveResult{
            .digest = .{
                .algorithm = .sha256,
                .hex = try arena_alloc.dupe(u8, "f" ** 64),
            },
            .media_type = .oci_manifest_v1,
            .platform = .{
                .os = try arena_alloc.dupe(u8, "linux"),
                .architecture = try arena_alloc.dupe(u8, "arm64"),
                .variant = try arena_alloc.dupe(u8, "v8"),
            },
            .reference = .{
                .registry = try arena_alloc.dupe(u8, "registry-1.docker.io"),
                .repository = try arena_alloc.dupe(u8, "library/busybox"),
                .tag = try arena_alloc.dupe(u8, "latest"),
                .digest = null,
                .digest_raw = null,
            },
        };

        cloned = try original.clone(std.testing.allocator);
    }
    defer cloned.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", cloned.reference.registry);
    try std.testing.expectEqualSlices(u8, "library/busybox", cloned.reference.repository);
    try std.testing.expectEqualSlices(u8, "latest", cloned.reference.refString());
    try std.testing.expect(cloned.platform != null);
    try std.testing.expectEqualSlices(u8, "linux", cloned.platform.?.os);
    try std.testing.expectEqualSlices(u8, "arm64", cloned.platform.?.architecture);
    try std.testing.expectEqualSlices(u8, "v8", cloned.platform.?.variant.?);
}

// Kept local on purpose: workflow_smoke builds as its own root module under
// `zig build test`, so importing test_support.zig here would make that file
// belong to two modules at once.
fn parseWorkflowFixture(comptime T: type, path: []const u8, max_bytes: usize) !std.json.Parsed(T) {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        std.testing.allocator,
        .limited(max_bytes),
    );
    defer std.testing.allocator.free(bytes);

    return z_oci.json.parse(T, std.testing.allocator, bytes);
}
