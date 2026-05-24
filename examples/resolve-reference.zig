//! Resolve a live image reference to a pinned manifest digest.
//!
//! Ownership notes:
//! - CLI args and the parsed input Reference live in `init.arena`, which is
//!   sufficient for this short-lived example.
//! - The returned ResolveResult is allocated through `init.gpa` and is
//!   explicitly deinitialized before exit.
//! - std.http.Client owns connection-pool state and must be deinitialized.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const usage_text =
    \\usage: resolve-reference <image-reference> [os/arch[/variant]]
    \\
    \\Examples:
    \\  zig build example-resolve-reference -- ubuntu:22.04
    \\  zig build example-resolve-reference -- ubuntu:22.04 linux/amd64
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [2048]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [2048]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(init.io, &stderr_buffer);
    defer stderr_writer.end() catch {};
    const stderr = &stderr_writer.interface;

    if (args.len < 2 or args.len > 3) {
        try stderr.writeAll(usage_text);
        return error.InvalidArguments;
    }

    const platform = if (args.len == 3)
        try parsePlatformArg(args[2])
    else
        null;

    const reference = try z_oci.Reference.parse(arena, args[1]);

    var client = std.http.Client{
        .allocator = init.gpa,
        .io = init.io,
    };
    defer client.deinit();

    const outcome = try z_oci.resolve(init.gpa, &client, z_oci.Config{}, reference, platform);
    switch (outcome) {
        .success => |result| {
            var owned_result = result;
            defer owned_result.deinit(init.gpa);

            try stdout.print("input: {s}\n", .{args[1]});
            if (platform) |selected| {
                try stdout.writeAll("requested.platform: ");
                try printPlatform(stdout, selected);
                try stdout.writeAll("\n");
            }
            try stdout.print("resolved.mediaType: {s}\n", .{owned_result.media_type.toString()});
            try stdout.print("resolved.digest: {f}\n", .{owned_result.digest});
            try stdout.print("resolved.reference: {s}/{s}@{s}\n", .{
                owned_result.reference.registry,
                owned_result.reference.repository,
                owned_result.reference.refString(),
            });
            if (owned_result.platform) |resolved_platform| {
                try stdout.writeAll("resolved.platform: ");
                try printPlatform(stdout, resolved_platform);
                try stdout.writeAll("\n");
            }
            try stdout.flush();
        },
        .failure => |failure| {
            defer failure.deinitOwned(init.gpa);
            try stderr.print("resolve failed: {f}\n", .{failure});
            return error.ResolveFailed;
        },
    }
}

fn parsePlatformArg(text: []const u8) !z_oci.Platform {
    var iter = std.mem.splitScalar(u8, text, '/');
    const os = iter.next() orelse return error.InvalidPlatform;
    const architecture = iter.next() orelse return error.InvalidPlatform;
    const variant = iter.next();

    if (os.len == 0 or architecture.len == 0) return error.InvalidPlatform;
    if (variant) |value| {
        if (value.len == 0) return error.InvalidPlatform;
    }
    if (iter.next() != null) return error.InvalidPlatform;

    return .{
        .os = os,
        .architecture = architecture,
        .variant = variant,
    };
}

fn printPlatform(writer: *Io.Writer, platform: z_oci.Platform) !void {
    try writer.print("{s}/{s}", .{ platform.os, platform.architecture });
    if (platform.variant) |variant| try writer.print("/{s}", .{variant});
}
