//! Select one platform descriptor from an OCI index or Docker manifest list.
//!
//! Ownership notes:
//! - CLI args come from `init.arena` and are treated as borrowed configuration
//!   inputs for the duration of main.
//! - The raw JSON bytes live in a bounded stack buffer and are discarded after parsing.
//! - Each parsed index/list is a std.json.Parsed(T); its arena owns all string
//!   slices exposed through descriptors(), so the selected Descriptor must not
//!   outlive the surrounding `parsed` value.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const default_index_path = "fixtures/indexes/busybox-latest-live-oci-index.json";

const usage_text =
    \\usage:
    \\  select-platform
    \\  select-platform <os> <arch>
    \\  select-platform <index-json-path> <os> <arch> [variant]
    \\
    \\Defaults:
    \\  path    fixtures/indexes/busybox-latest-live-oci-index.json
    \\  filter  linux amd64
    \\
;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [2048]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(init.io, &stderr_buffer);
    defer stderr_writer.end() catch {};
    const stderr = &stderr_writer.interface;

    var index_path: []const u8 = default_index_path;
    var filter = z_oci.Platform{ .os = "linux", .architecture = "amd64" };

    switch (args.len) {
        1 => {},
        3 => {
            filter.os = args[1];
            filter.architecture = args[2];
        },
        4 => {
            index_path = args[1];
            filter.os = args[2];
            filter.architecture = args[3];
        },
        5 => {
            index_path = args[1];
            filter.os = args[2];
            filter.architecture = args[3];
            filter.variant = args[4];
        },
        else => {
            try stderr.writeAll(usage_text);
            return error.InvalidArguments;
        },
    }

    var bytes_buffer: [32 * 1024 + 1]u8 = undefined;
    const bytes = try Io.Dir.cwd().readFile(init.io, index_path, &bytes_buffer);
    if (bytes.len > 32 * 1024) return error.StreamTooLong;

    try stdout.print("path: {s}\n", .{index_path});
    try stdout.print("requested: {s}/{s}", .{ filter.os, filter.architecture });
    if (filter.variant) |variant| try stdout.print("/{s}", .{variant});
    try stdout.writeAll("\n");
    try stdout.flush();

    if (z_oci.json.parse(z_oci.OciImageIndex, init.gpa, bytes)) |parsed| {
        defer parsed.deinit();
        const multi = z_oci.MultiArchManifest{ .oci = parsed.value };
        // `selected` borrows from `parsed`, so it is only used within this scope.
        const selected = multi.filterByPlatform(filter) orelse {
            try printNoMatch(stderr, parsed.value.media_type.toString(), multi.descriptors(), filter);
            return error.NoMatchingPlatform;
        };
        try printSelection(stdout, parsed.value.media_type.toString(), selected);
    } else |_| {
        const parsed = try z_oci.json.parse(z_oci.DockerManifestList, init.gpa, bytes);
        defer parsed.deinit();
        const multi = z_oci.MultiArchManifest{ .docker = parsed.value };
        // `selected` borrows from `parsed`, so it is only used within this scope.
        const selected = multi.filterByPlatform(filter) orelse {
            try printNoMatch(stderr, parsed.value.media_type.toString(), multi.descriptors(), filter);
            return error.NoMatchingPlatform;
        };
        try printSelection(stdout, parsed.value.media_type.toString(), selected);
    }

    try stdout.flush();
}

fn printSelection(stdout: *Io.Writer, root_media_type: []const u8, selected: z_oci.Descriptor) !void {
    try stdout.print("index.mediaType: {s}\n", .{root_media_type});
    try stdout.print("selected.mediaType: {s}\n", .{selected.media_type.toString()});
    try stdout.print("selected.digest: {f}\n", .{selected.digest});
    try stdout.print("selected.size: {d}\n", .{selected.size});
    if (selected.platform) |platform| {
        try stdout.print("selected.platform: {s}/{s}", .{ platform.os, platform.architecture });
        if (platform.variant) |variant| try stdout.print("/{s}", .{variant});
        try stdout.writeAll("\n");
    }
}

fn printNoMatch(stderr: *Io.Writer, root_media_type: []const u8, descriptors: []const z_oci.Descriptor, requested: z_oci.Platform) !void {
    var hidden_auxiliary_entries: usize = 0;

    try stderr.print("no exact platform match in {s} for {s}/{s}", .{ root_media_type, requested.os, requested.architecture });
    if (requested.variant) |variant| try stderr.print("/{s}", .{variant});
    try stderr.writeAll("\n");
    try stderr.writeAll("available platforms:\n");

    for (descriptors) |desc| {
        if (desc.platform) |platform| {
            if (std.ascii.eqlIgnoreCase(platform.os, "unknown") and std.ascii.eqlIgnoreCase(platform.architecture, "unknown")) {
                hidden_auxiliary_entries += 1;
                continue;
            }
            try stderr.writeAll("- ");
            try printPlatform(stderr, platform);
            try stderr.print(" ({s}, {d} bytes)\n", .{ desc.media_type.toString(), desc.size });
        }
    }

    if (hidden_auxiliary_entries > 0) {
        try stderr.print("- omitted {d} auxiliary descriptor(s) with platform unknown/unknown\n", .{hidden_auxiliary_entries});
    }

    try stderr.flush();
}

fn printPlatform(writer: *Io.Writer, platform: z_oci.Platform) !void {
    try writer.print("{s}/{s}", .{ platform.os, platform.architecture });
    if (platform.variant) |variant| try writer.print("/{s}", .{variant});
}
