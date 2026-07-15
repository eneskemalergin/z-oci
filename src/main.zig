//! z-oci executable process adapter.
//!
//! This module owns process arguments, standard-output writers, the caller-owned
//! HTTP client, and projection of process state into the public resolver
//! configuration. Resolver command execution is not implemented in this adapter.

const std = @import("std");
const build_options = @import("build_options");
const cli = @import("cli.zig");
const z_oci = @import("z_oci");

const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    var stdout_buffer: [2048]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [2048]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(init.io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    const exit_code = run(init, stdout, stderr) catch {
        _ = cli.writeFailureText(stderr, .{ .unexpected = {} }) catch {};
        _ = stdout_writer.end() catch {};
        _ = stderr_writer.end() catch {};
        std.process.exit(@intFromEnum(cli.ExitCode.unexpected_failure));
    };

    var writer_failed = false;
    stdout_writer.end() catch {
        writer_failed = true;
    };
    if (writer_failed) _ = cli.writeFailureText(stderr, .{ .unexpected = {} }) catch {};
    stderr_writer.end() catch {
        writer_failed = true;
    };
    if (writer_failed) std.process.exit(@intFromEnum(cli.ExitCode.unexpected_failure));
    if (exit_code != .success) std.process.exit(@intFromEnum(exit_code));
}

fn run(init: std.process.Init, stdout: *Io.Writer, stderr: *Io.Writer) !cli.ExitCode {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const outcome = try cli.parse(init.gpa, args);

    switch (outcome) {
        .help => |target| {
            try cli.writeHelp(stdout, target);
            return .success;
        },
        .version => |target| {
            _ = target;
            try cli.writeVersion(stdout, build_options.package_version);
            return .success;
        },
        .usage => |failure| {
            try cli.writeUsageError(stderr, failure);
            return .usage_failure;
        },
        .command => |command| {
            var parsed = command;
            defer parsed.deinit(init.gpa);

            var config = configFromProcess(parsed.global, init.environ_map, init.io);
            var client = std.http.Client{
                .allocator = init.gpa,
                .io = init.io,
            };
            defer client.deinit();

            config.applyToClient(&client) catch |err| {
                const failure = cli.CliFailure{ .config = err };
                switch (parsed.options.format) {
                    .text => try cli.writeFailureText(stderr, failure),
                    .json => try cli.writeFailureJson(stdout, failure),
                }
                return cli.exitCodeForFailure(failure);
            };

            try stderr.writeAll(cli.COMMAND_NOT_IMPLEMENTED);
            return .unexpected_failure;
        },
    }
}

fn configFromProcess(
    global: cli.GlobalOptions,
    environ_map: *std.process.Environ.Map,
    io: Io,
) z_oci.Config {
    var config: z_oci.Config = .{
        .ca_bundle_path = global.ca_bundle_path,
        .credential_sources = .{
            .environ_map = environ_map,
            .load_docker_config_from_environ = true,
            .process_io = io,
        },
    };
    if (global.helper_timeout_ms) |timeout_ms| config.read_timeout_ms = timeout_ms;
    return config;
}

test "process config projection preserves defaults and injects process sources" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("DOCKER_CONFIG", "/tmp/z-oci-test-config");

    const global = cli.GlobalOptions{
        .ca_bundle_path = "ca.pem",
        .helper_timeout_ms = 1234,
    };
    const config = configFromProcess(global, &environ_map, std.testing.io);
    const defaults = z_oci.Config{};

    try std.testing.expectEqualStrings("ca.pem", config.ca_bundle_path.?);
    try std.testing.expectEqual(@as(u32, 1234), config.read_timeout_ms);
    try std.testing.expect(config.credential_provider == null);
    try std.testing.expect(config.credential_sources.environ_map.? == &environ_map);
    try std.testing.expect(config.credential_sources.docker_config_json == null);
    try std.testing.expect(config.credential_sources.load_docker_config_from_environ);
    try std.testing.expectEqualDeep(std.testing.io, config.credential_sources.process_io.?);
    try std.testing.expect(config.credential_sources.helper_runner == null);

    try std.testing.expectEqual(defaults.connect_timeout_ms, config.connect_timeout_ms);
    try std.testing.expectEqual(defaults.max_retries, config.max_retries);
    try std.testing.expectEqual(defaults.max_network_retries, config.max_network_retries);
    try std.testing.expectEqual(defaults.max_rate_limit_retries, config.max_rate_limit_retries);
    try std.testing.expectEqual(defaults.rate_limit_enabled, config.rate_limit_enabled);
    try std.testing.expectEqual(defaults.max_manifest_bytes, config.max_manifest_bytes);
    try std.testing.expectEqual(defaults.max_token_response_bytes, config.max_token_response_bytes);
    try std.testing.expectEqual(defaults.max_token_cache_entries, config.max_token_cache_entries);
}

test "process config projection keeps default values when options are absent" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const config = configFromProcess(.{}, &environ_map, std.testing.io);
    try std.testing.expect(config.ca_bundle_path == null);
    try std.testing.expectEqual(@as(u32, 30_000), config.read_timeout_ms);
    try std.testing.expect(config.credential_sources.load_docker_config_from_environ);
    try std.testing.expectEqualDeep(std.testing.io, config.credential_sources.process_io.?);
}

fn testProcessInit(
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    environ_map: *std.process.Environ.Map,
    argv: []const [*:0]const u8,
) std.process.Init {
    return .{
        .minimal = .{
            .args = .{ .vector = argv },
            .environ = .{ .block = .empty },
        },
        .arena = arena,
        .gpa = allocator,
        .io = std.testing.io,
        .environ_map = environ_map,
        .preopens = .empty,
    };
}

test "process command writer failure releases parsed command" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{ "z-oci", "resolve", "ubuntu" };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);

    var stdout_buffer: [128]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [0]u8 = .{};
    var stderr = Io.Writer.fixed(&stderr_buffer);
    try std.testing.expectError(error.WriteFailed, run(init, &stdout, &stderr));
}

test "process command allocation failure releases partial reference" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{ "z-oci", "resolve", "ubuntu" };
    var fail_index: usize = 0;
    while (fail_index < 8) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const init = testProcessInit(failing.allocator(), &arena, &environ_map, &argv);

            var stdout_buffer: [128]u8 = undefined;
            var stdout = Io.Writer.fixed(&stdout_buffer);
            var stderr_buffer: [128]u8 = undefined;
            var stderr = Io.Writer.fixed(&stderr_buffer);
            const result = run(init, &stdout, &stderr) catch |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
                    continue;
                },
                else => return err,
            };
            if (!failing.has_induced_failure) break;
            try std.testing.expectEqual(cli.ExitCode.unexpected_failure, result);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
    }
}
