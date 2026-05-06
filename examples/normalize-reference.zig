const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const usage_text =
    \\usage: normalize-reference <image-reference>
    \\
    \\Example:
    \\  zig build example-normalize-reference -- ubuntu:22.04
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(init.io, &stderr_buffer);
    defer stderr_writer.end() catch {};
    const stderr = &stderr_writer.interface;

    if (args.len != 2) {
        try stderr.writeAll(usage_text);
        return error.InvalidArguments;
    }

    const reference = try z_oci.Reference.parse(arena, args[1]);

    try stdout.print("registry: {s}\n", .{reference.registry});
    try stdout.print("repository: {s}\n", .{reference.repository});
    try stdout.print("repositoryPath: {s}\n", .{reference.repositoryPath()});
    try stdout.print("ref: {s}\n", .{reference.refString()});

    if (reference.digest != null) {
        try stdout.print("normalized: {s}/{s}@{s}\n", .{ reference.registry, reference.repository, reference.refString() });
    } else {
        try stdout.print("normalized: {s}/{s}:{s}\n", .{ reference.registry, reference.repository, reference.refString() });
    }

    try stdout.flush();
}
