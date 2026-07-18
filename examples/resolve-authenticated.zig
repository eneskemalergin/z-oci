//! Resolve a reference through an offline authenticated Bearer flow.
//!
//! The injected exchanges model an unauthorized manifest request, a token
//! exchange, and the authenticated retry. No registry or credential is used;
//! the example focuses on the public resolver's authentication boundary.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const FIXTURE_PATH = "fixtures/manifests/busybox-amd64-live-oci-manifest.json";
const DIGEST = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65";
const IMAGE = "registry.example.test/library/busybox:latest";

const Harness = struct {
    var manifest_body: []const u8 = "";
    var manifest_calls: usize = 0;

    fn tokenExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.auth.TokenHttpRequest,
    ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
        request.deinit(allocator);
        return .{ .status = .ok, .body = "{\"access_token\":\"example-token\",\"expires_in\":3600}" };
    }

    fn manifestExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.testing.ManifestHttpRequest,
    ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
        defer request.deinit(allocator);
        manifest_calls += 1;

        if (manifest_calls == 1) {
            if (request.authorization != null) return error.TransportFailed;
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .unauthorized,
                .www_authenticate_headers = &.{
                    "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:library/busybox:pull\"",
                },
            }, null);
        }

        if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Bearer example-token")) {
            return error.TransportFailed;
        }

        return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
            .status = .ok,
            .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
            .docker_content_digest = DIGEST,
        }, manifest_body);
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var manifest_buffer: [32 * 1024 + 1]u8 = undefined;
    Harness.manifest_body = try Io.Dir.cwd().readFile(init.io, FIXTURE_PATH, &manifest_buffer);
    Harness.manifest_calls = 0;

    var client: std.http.Client = undefined;
    var reference = try z_oci.Reference.parse(allocator, IMAGE);
    const outcome = blk: {
        errdefer reference.deinit(allocator);
        break :blk try z_oci.testing.resolveWithExchangers(
            allocator,
            &client,
            z_oci.Config{},
            reference,
            null,
            Harness.tokenExchange,
            Harness.manifestExchange,
            .{},
        );
    };

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};

    switch (outcome) {
        .success => |result| {
            var owned = result;
            defer owned.deinit(allocator);
            try stdout_writer.interface.print("authenticated: true\nresolved: {s}/{s}@{f}\n", .{
                owned.reference.registry,
                owned.reference.repository,
                owned.digest,
            });
        },
        .failure => |failure| {
            failure.deinitOwned(allocator);
            reference.deinit(allocator);
            return error.ResolveFailed;
        },
    }
    try stdout_writer.interface.flush();
}
