//! Inspect a manifest fixture and print a compact summary.
//!
//! Ownership notes:
//! - The raw file bytes live in a bounded stack buffer and are discarded after parsing.
//! - z_oci.json.parse returns std.json.Parsed(Manifest), which owns its own
//!   arena-backed strings and must be deinitialized explicitly.
//! - This example uses `init.gpa` for the parse arena because it keeps the
//!   parsed value alive across the reporting loop, then tears it down with
//!   `parsed.deinit()` before exit.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const DEFAULT_MANIFEST_PATH = "fixtures/manifests/busybox-amd64-live-oci-manifest.json";

const USAGE_TEXT =
    \\usage: inspect-manifest [manifest-json-path]
    \\
    \\Example:
    \\  zig build example-inspect-manifest
    \\
    \\Default path:
    \\  fixtures/manifests/busybox-amd64-live-oci-manifest.json
    \\
;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(init.io, &stderr_buffer);
    defer stderr_writer.end() catch {};
    const stderr = &stderr_writer.interface;

    if (args.len > 2) {
        try stderr.writeAll(USAGE_TEXT);
        return error.InvalidArguments;
    }

    const manifest_path = if (args.len == 2) args[1] else DEFAULT_MANIFEST_PATH;
    var bytes_buffer: [32 * 1024 + 1]u8 = undefined;
    const bytes = try Io.Dir.cwd().readFile(init.io, manifest_path, &bytes_buffer);
    if (bytes.len > 32 * 1024) return error.StreamTooLong;

    const parsed = try z_oci.json.parse(z_oci.Manifest, init.gpa, bytes);
    defer parsed.deinit();

    const manifest = parsed.value;
    const total_compressed_layer_size = totalLayerSize(manifest.layers);

    try stdout.print("path: {s}\n", .{manifest_path});
    try stdout.print("schemaVersion: {d}\n", .{manifest.schema_version});
    try stdout.print("manifest.kind: {s}\n", .{manifestKind(manifest.media_type)});
    try stdout.print("manifest.mediaType: {s}\n", .{manifest.media_type.toString()});
    try stdout.print("config.kind: {s}\n", .{configKind(manifest.config.media_type)});
    try stdout.print("config.mediaType: {s}\n", .{manifest.config.media_type.toString()});
    try stdout.print("config.digest: {f}\n", .{manifest.config.digest});
    try stdout.print("config.size: {d}\n", .{manifest.config.size});
    try stdout.print("layers.count: {d}\n", .{manifest.layers.len});
    try stdout.print("layers.totalCompressedSize: {d}\n", .{total_compressed_layer_size});

    for (manifest.layers, 0..) |layer, index| {
        try stdout.print("layer[{d}].kind: {s}\n", .{ index, layerKind(layer.media_type) });
        try stdout.print("layer[{d}].mediaType: {s}\n", .{ index, layer.media_type.toString() });
        try stdout.print("layer[{d}].digest: {f}\n", .{ index, layer.digest });
        try stdout.print("layer[{d}].size: {d}\n", .{ index, layer.size });
    }

    try stdout.print("annotations: {s}\n", .{if (manifest.annotations != null) "present" else "none"});
    try stdout.flush();
}

fn totalLayerSize(layers: []const z_oci.Descriptor) u64 {
    var total: u64 = 0;
    for (layers) |layer| total += layer.size;
    return total;
}

fn manifestKind(media_type: z_oci.MediaType) []const u8 {
    return switch (media_type) {
        .oci_manifest_v1 => "OCI image manifest",
        .docker_manifest_v2 => "Docker schema 2 manifest",
        else => "other manifest",
    };
}

fn configKind(media_type: z_oci.MediaType) []const u8 {
    return switch (media_type) {
        .oci_config_v1 => "OCI image config",
        .docker_container_image_v1 => "Docker container config",
        .oci_empty_v1 => "OCI empty config",
        else => "other config",
    };
}

fn layerKind(media_type: z_oci.MediaType) []const u8 {
    return switch (media_type) {
        .oci_layer_v1_tar => "OCI tar layer",
        .oci_layer_v1_tar_gzip => "OCI gzip layer",
        .oci_layer_v1_tar_zstd => "OCI zstd layer",
        .oci_layer_nondistributable_v1_tar => "OCI nondistributable tar layer",
        .oci_layer_nondistributable_v1_tar_gzip => "OCI nondistributable gzip layer",
        .docker_layer_gzip => "Docker gzip layer",
        .docker_layer_foreign_gzip => "Docker foreign gzip layer",
        else => "other layer",
    };
}
