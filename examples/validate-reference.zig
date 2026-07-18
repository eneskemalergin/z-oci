//! Validate a digest-pinned reference through the public validate API.
//!
//! This example is deterministic and offline. The injected manifest exchanger
//! models a registry HEAD response with Docker-Content-Digest metadata, so the
//! example demonstrates the public digest-validation contract without network
//! access or credentials.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const DIGEST = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65";
const IMAGE = "registry-1.docker.io/library/busybox@" ++ DIGEST;

fn manifestExchange(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    request: z_oci.testing.ManifestHttpRequest,
) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
    defer request.deinit(allocator);
    if (request.method != .head) return error.TransportFailed;

    return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
        .status = .ok,
        .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
        .docker_content_digest = DIGEST,
    }, null);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};

    var reference = try z_oci.Reference.parse(allocator, IMAGE);
    defer reference.deinit(allocator);

    var client = std.http.Client{ .allocator = allocator, .io = init.io };
    defer client.deinit();

    const outcome = try z_oci.testing.validateWithExchangers(
        allocator,
        &client,
        z_oci.Config{},
        reference,
        null,
        z_oci.testing.refuseTokenExchange,
        manifestExchange,
        .{},
    );

    switch (outcome) {
        .valid => try stdout_writer.interface.print("validated: {s}\n", .{IMAGE}),
        .not_found => return error.ReferenceNotFound,
        .failure => |failure| {
            failure.deinitOwned(allocator);
            return error.ValidationFailed;
        },
    }
    try stdout_writer.interface.flush();
}
