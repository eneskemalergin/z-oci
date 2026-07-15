//! z-oci executable process adapter.
//!
//! Argument parsing, help, version, and usage diagnostics live in `cli.zig`.
//! Resolver-backed command execution will use the existing public API.

const std = @import("std");
const build_options = @import("build_options");
const cli = @import("cli.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var stdout_buffer: [2048]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [512]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    defer stderr_writer.end() catch {};
    const stderr = &stderr_writer.interface;

    const outcome = try cli.parse(init.gpa, args);
    switch (outcome) {
        .help => |target| try cli.writeHelp(stdout, target),
        .version => |target| {
            _ = target;
            try cli.writeVersion(stdout, build_options.package_version);
        },
        .usage => |failure| {
            try cli.writeUsageError(stderr, failure);
            try stderr.flush();
            std.process.exit(5);
        },
        .command => |command| {
            var parsed = command;
            const write_result = stderr.writeAll(cli.COMMAND_NOT_IMPLEMENTED);
            parsed.deinit(init.gpa);
            try write_result;
            try stderr.flush();
            std.process.exit(12);
        },
    }
}
