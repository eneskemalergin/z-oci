//! Resolve a small batch through injected offline exchangers.
//!
//! Ownership notes:
//! - Parsed input references use `init.gpa` and are deinitialized explicitly.
//! - `resolveManyWithExchangers` returns an owned `ResolveManyResult`; this example
//!   calls `result.deinit(init.gpa)` once after printing every item.
//! - The manifest body comes from a checked-in fixture, so the example does not
//!   perform network I/O.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const MANIFEST_PATH = "fixtures/manifests/busybox-amd64-live-oci-manifest.json";
const MANIFEST_DIGEST = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65";

const MockRegistry = struct {
    var manifest_body: []const u8 = "";
    var manifest_calls: usize = 0;

    fn tokenExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.auth.TokenHttpRequest,
    ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
        request.deinit(allocator);
        return error.TokenExchangeFailed;
    }

    fn manifestExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.testing.ManifestHttpRequest,
    ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
        defer request.deinit(allocator);
        manifest_calls += 1;

        if (std.mem.endsWith(u8, request.url, "/manifests/missing")) {
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .not_found,
            }, null);
        }

        return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
            .status = .ok,
            .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
            .docker_content_digest = MANIFEST_DIGEST,
        }, manifest_body);
    }
};

/// Offline batch resolution example; see file header for ownership.
pub fn main(init: std.process.Init) !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};
    const stdout = &stdout_writer.interface;

    var manifest_buffer: [32 * 1024 + 1]u8 = undefined;
    const manifest_body = try Io.Dir.cwd().readFile(init.io, MANIFEST_PATH, &manifest_buffer);
    if (manifest_body.len > 32 * 1024) return error.StreamTooLong;

    MockRegistry.manifest_body = manifest_body;
    MockRegistry.manifest_calls = 0;

    var refs = [_]z_oci.Reference{
        try z_oci.Reference.parse(init.gpa, "registry-1.docker.io/library/busybox"),
        try z_oci.Reference.parse(init.gpa, "registry-1.docker.io/library/busybox:latest"),
        try z_oci.Reference.parse(init.gpa, "registry-1.docker.io/library/busybox:missing"),
    };
    defer for (&refs) |*ref| ref.deinit(init.gpa);

    var client: std.http.Client = undefined;
    var result = try z_oci.testing.resolveManyWithExchangers(
        init.gpa,
        &client,
        z_oci.Config{},
        refs[0..],
        .{},
        MockRegistry.tokenExchange,
        MockRegistry.manifestExchange,
        .{},
    );
    defer result.deinit(init.gpa);

    try stdout.print("items: {d}\n", .{result.items.len});
    try stdout.print("manifestCalls: {d}\n", .{MockRegistry.manifest_calls});

    for (result.items, 0..) |item, index| {
        switch (item) {
            .success => |resolved| {
                try stdout.print(
                    "item[{d}]: success {s}/{s}@{f}\n",
                    .{ index, resolved.reference.registry, resolved.reference.repository, resolved.digest },
                );
            },
            .failure => |failure| {
                try stdout.print("item[{d}]: failure {f}\n", .{ index, failure });
            },
        }
    }

    try stdout.flush();
}
