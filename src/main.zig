//! z-oci executable entry point and process adapter.
//!
//! `main` handles process arguments, bounded standard-output and standard-error
//! writers, one command-scoped HTTP client, and projection of process state into
//! the public resolver configuration. Help, version, and usage failures return
//! before client setup or credential lookup.
//!
//! The `resolve`, `validate`, and `inspect` commands call the existing public
//! resolver APIs. The adapter projects explicit credential sources, custom CA
//! configuration, and credential-helper timeout settings, then routes owned
//! results and failures through the executable renderers. It deinitializes the
//! client and command results before returning the mapped process exit code.

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
    return runWithOperations(init, stdout, stderr, z_oci.resolve, z_oci.validate, z_oci.inspect, monotonicNow);
}

fn runWithResolve(
    init: std.process.Init,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
    comptime resolve_fn: anytype,
    comptime now_fn: anytype,
) !cli.ExitCode {
    return runWithOperations(init, stdout, stderr, resolve_fn, z_oci.validate, z_oci.inspect, now_fn);
}

fn runWithOperations(
    init: std.process.Init,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
    comptime resolve_fn: anytype,
    comptime validate_fn: anytype,
    comptime inspect_fn: anytype,
    comptime now_fn: anytype,
) !cli.ExitCode {
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
            var reference_owned = true;
            defer if (reference_owned) parsed.deinit(init.gpa);

            var config = configFromProcess(parsed.global, init.environ_map, init.io);
            var client = std.http.Client{
                .allocator = init.gpa,
                .io = init.io,
            };
            defer client.deinit();

            const started_at = if (isExecutedCommand(parsed.command) and parsed.options.verbose)
                now_fn(init.io)
            else
                null;
            config.applyToClient(&client) catch |err| {
                const failure = cli.CliFailure{ .config = err };
                try writeFailure(stdout, stderr, parsed.options.format, failure);
                if (started_at != null) {
                    try cli.writeVerbose(
                        stderr,
                        parsed.command,
                        cli.verboseOutcomeForFailure(failure),
                        elapsedMilliseconds(now_fn, init.io, started_at.?),
                    );
                }
                return cli.exitCodeForFailure(failure);
            };

            switch (parsed.command) {
                .resolve => {
                    const resolve_outcome = resolve_fn(
                        init.gpa,
                        &client,
                        config,
                        parsed.reference,
                        parsed.options.platform,
                    ) catch |err| {
                        const failure = cli.CliFailure{ .config = err };
                        try writeFailure(stdout, stderr, parsed.options.format, failure);
                        if (started_at != null) {
                            try cli.writeVerbose(
                                stderr,
                                .resolve,
                                cli.verboseOutcomeForFailure(failure),
                                elapsedMilliseconds(now_fn, init.io, started_at.?),
                            );
                        }
                        return cli.exitCodeForFailure(failure);
                    };
                    const elapsed_ms = if (started_at != null)
                        elapsedMilliseconds(now_fn, init.io, started_at.?)
                    else
                        0;

                    switch (resolve_outcome) {
                        .success => |result| {
                            reference_owned = false;
                            var owned_result = result;
                            defer owned_result.deinit(init.gpa);
                            try writeResolveSuccess(stdout, parsed.options.format, parsed.input, owned_result);
                            if (started_at != null) {
                                try cli.writeVerbose(stderr, .resolve, .success, elapsed_ms);
                            }
                            return .success;
                        },
                        .failure => |failure| {
                            defer z_oci.deinitResolveFailure(failure, init.gpa);
                            try writeFailure(stdout, stderr, parsed.options.format, .{ .resolve = failure });
                            if (started_at != null) {
                                try cli.writeVerbose(
                                    stderr,
                                    .resolve,
                                    cli.verboseOutcomeForFailure(.{ .resolve = failure }),
                                    elapsed_ms,
                                );
                            }
                            return cli.exitCodeForFailure(.{ .resolve = failure });
                        },
                    }
                },
                .validate => {
                    const validate_outcome = validate_fn(
                        init.gpa,
                        &client,
                        config,
                        parsed.reference,
                        null,
                    ) catch |err| {
                        const failure = cli.CliFailure{ .config = err };
                        try writeFailure(stdout, stderr, parsed.options.format, failure);
                        if (started_at != null) {
                            try cli.writeVerbose(
                                stderr,
                                .validate,
                                cli.verboseOutcomeForFailure(failure),
                                elapsedMilliseconds(now_fn, init.io, started_at.?),
                            );
                        }
                        return cli.exitCodeForFailure(failure);
                    };
                    const elapsed_ms = if (started_at != null)
                        elapsedMilliseconds(now_fn, init.io, started_at.?)
                    else
                        0;

                    switch (validate_outcome) {
                        .valid => {
                            try writeValidateSuccess(stdout, parsed.options.format, parsed.reference, true);
                            if (started_at != null) {
                                try cli.writeVerbose(stderr, .validate, .success, elapsed_ms);
                            }
                            return .success;
                        },
                        .not_found => {
                            try writeValidateSuccess(stdout, parsed.options.format, parsed.reference, false);
                            if (started_at != null) {
                                try cli.writeVerbose(stderr, .validate, .not_found, elapsed_ms);
                            }
                            return .not_found;
                        },
                        .failure => |failure| {
                            defer z_oci.deinitResolveFailure(failure, init.gpa);
                            try writeFailure(stdout, stderr, parsed.options.format, .{ .resolve = failure });
                            if (started_at != null) {
                                try cli.writeVerbose(
                                    stderr,
                                    .validate,
                                    cli.verboseOutcomeForFailure(.{ .resolve = failure }),
                                    elapsed_ms,
                                );
                            }
                            return cli.exitCodeForFailure(.{ .resolve = failure });
                        },
                    }
                },
                .inspect => {
                    const inspect_outcome = inspect_fn(
                        init.gpa,
                        &client,
                        config,
                        parsed.reference,
                        parsed.options.platform,
                    ) catch |err| {
                        const failure = cli.CliFailure{ .config = err };
                        try writeFailure(stdout, stderr, parsed.options.format, failure);
                        if (started_at != null) {
                            try cli.writeVerbose(
                                stderr,
                                .inspect,
                                cli.verboseOutcomeForFailure(failure),
                                elapsedMilliseconds(now_fn, init.io, started_at.?),
                            );
                        }
                        return cli.exitCodeForFailure(failure);
                    };
                    const elapsed_ms = if (started_at != null)
                        elapsedMilliseconds(now_fn, init.io, started_at.?)
                    else
                        0;

                    switch (inspect_outcome) {
                        .success => |result| {
                            var owned_result = result;
                            defer owned_result.deinit();
                            try writeInspectSuccess(
                                stdout,
                                parsed.options.format,
                                parsed.reference,
                                parsed.options.platform,
                                owned_result,
                            );
                            if (started_at != null) {
                                try cli.writeVerbose(stderr, .inspect, .success, elapsed_ms);
                            }
                            return .success;
                        },
                        .failure => |failure| {
                            defer z_oci.deinitResolveFailure(failure, init.gpa);
                            try writeFailure(stdout, stderr, parsed.options.format, .{ .resolve = failure });
                            if (started_at != null) {
                                try cli.writeVerbose(
                                    stderr,
                                    .inspect,
                                    cli.verboseOutcomeForFailure(.{ .resolve = failure }),
                                    elapsed_ms,
                                );
                            }
                            return cli.exitCodeForFailure(.{ .resolve = failure });
                        },
                    }
                },
            }
        },
    }
}

fn isExecutedCommand(command: cli.Command) bool {
    return command == .resolve or command == .validate or command == .inspect;
}

fn writeResolveSuccess(
    stdout: *Io.Writer,
    format: cli.Format,
    input: []const u8,
    result: z_oci.ResolveResult,
) Io.Writer.Error!void {
    switch (format) {
        .text => try cli.writeResolveText(stdout, result),
        .json => try cli.writeResolveJson(stdout, input, result),
    }
}

fn writeValidateSuccess(
    stdout: *Io.Writer,
    format: cli.Format,
    reference: z_oci.Reference,
    valid: bool,
) Io.Writer.Error!void {
    switch (format) {
        .text => try cli.writeValidateText(stdout, valid),
        .json => try cli.writeValidateJson(stdout, reference, valid),
    }
}

fn writeInspectSuccess(
    stdout: *Io.Writer,
    format: cli.Format,
    reference: z_oci.Reference,
    requested_platform: ?z_oci.Platform,
    result: z_oci.InspectionResult,
) Io.Writer.Error!void {
    switch (format) {
        .text => try cli.writeInspectText(stdout, reference, requested_platform, result),
        .json => try cli.writeInspectJson(stdout, reference, requested_platform, result),
    }
}

fn writeFailure(
    stdout: *Io.Writer,
    stderr: *Io.Writer,
    format: cli.Format,
    failure: cli.CliFailure,
) Io.Writer.Error!void {
    switch (format) {
        .text => try cli.writeFailureText(stderr, failure),
        .json => try cli.writeFailureJson(stdout, failure),
    }
}

fn monotonicNow(io: Io) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.now(io, .awake);
}

fn elapsedMilliseconds(
    comptime now_fn: anytype,
    io: Io,
    started_at: std.Io.Clock.Timestamp,
) u64 {
    const elapsed = started_at.durationTo(now_fn(io)).raw.toMilliseconds();
    return if (elapsed < 0) 0 else @intCast(elapsed);
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

test "process adapter projects options and process sources into Config" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("DOCKER_CONFIG", "config.json");

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

test "process adapter preserves Config defaults without optional options" {
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

fn testResolveSuccess(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: z_oci.Config,
    ref: z_oci.Reference,
    _: ?z_oci.Platform,
) z_oci.PublicApiError!z_oci.ResolveOutcome {
    TestResolveCalls.calls += 1;
    var resolved = ref;
    const digest_raw = try allocator.dupe(u8, "sha256:" ++ ("a" ** 64));
    resolved.digest_raw = digest_raw;
    resolved.digest = z_oci.Digest.parse(digest_raw) catch unreachable;
    return .{ .success = .{
        .digest = resolved.digest.?,
        .media_type = .oci_manifest_v1,
        .platform = null,
        .reference = resolved,
    } };
}

fn testResolveNotFound(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: z_oci.Config,
    ref: z_oci.Reference,
    _: ?z_oci.Platform,
) z_oci.PublicApiError!z_oci.ResolveOutcome {
    TestResolveCalls.calls += 1;
    const reference = try std.fmt.allocPrint(allocator, "{s}/{s}:{s}", .{
        ref.registry,
        ref.repository,
        ref.refString(),
    });
    return .{ .failure = .{ .not_found = .{
        .registry = ref.registry,
        .reference = reference,
        .http_status = 404,
    } } };
}

fn testResolvePlatformSuccess(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: z_oci.Config,
    ref: z_oci.Reference,
    platform: ?z_oci.Platform,
) z_oci.PublicApiError!z_oci.ResolveOutcome {
    TestResolveCalls.calls += 1;
    TestResolveCalls.platform = platform;
    var resolved = ref;
    const digest_raw = try allocator.dupe(u8, "sha256:" ++ ("b" ** 64));
    errdefer allocator.free(digest_raw);
    resolved.digest_raw = digest_raw;
    resolved.digest = z_oci.Digest.parse(digest_raw) catch unreachable;
    const os = try allocator.dupe(u8, "linux");
    errdefer allocator.free(os);
    const architecture = try allocator.dupe(u8, "amd64");
    return .{ .success = .{
        .digest = resolved.digest.?,
        .media_type = .oci_manifest_v1,
        .platform = .{ .os = os, .architecture = architecture },
        .reference = resolved,
    } };
}

fn testValidateValid(
    _: std.mem.Allocator,
    _: *std.http.Client,
    _: z_oci.Config,
    _: z_oci.Reference,
    platform: ?z_oci.Platform,
) z_oci.PublicApiError!z_oci.ValidateOutcome {
    TestValidateCalls.calls += 1;
    TestValidateCalls.platform = platform;
    return .valid;
}

fn testValidateNotFound(
    _: std.mem.Allocator,
    _: *std.http.Client,
    _: z_oci.Config,
    _: z_oci.Reference,
    platform: ?z_oci.Platform,
) z_oci.PublicApiError!z_oci.ValidateOutcome {
    TestValidateCalls.calls += 1;
    TestValidateCalls.platform = platform;
    return .not_found;
}

fn testValidateAuthFailure(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: z_oci.Config,
    ref: z_oci.Reference,
    platform: ?z_oci.Platform,
) z_oci.PublicApiError!z_oci.ValidateOutcome {
    TestValidateCalls.calls += 1;
    TestValidateCalls.platform = platform;
    const reference = try std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{
        ref.registry,
        ref.repository,
        ref.refString(),
    });
    return .{ .failure = .{ .auth_failed = .{
        .registry = ref.registry,
        .reference = reference,
        .http_status = 401,
    } } };
}

const test_inspect_manifest_json =
    "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"sha256:" ++ ("a" ** 64) ++ "\",\"size\":123},\"layers\":[]}";
const test_inspect_index_json =
    "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:" ++ ("b" ** 64) ++ "\",\"size\":456,\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\"}}]}";

fn testInspectResult(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: z_oci.Config,
    _: z_oci.Reference,
    platform: ?z_oci.Platform,
) z_oci.PublicApiError!z_oci.InspectionOutcome {
    TestInspectCalls.calls += 1;
    TestInspectCalls.platform = platform;
    if (platform == null) {
        const manifest = z_oci.json.parse(z_oci.Manifest, allocator, test_inspect_manifest_json) catch unreachable;
        return .{ .success = .{ .top_level = .{ .manifest = manifest } } };
    }

    var result = z_oci.InspectionResult{
        .top_level = .{ .oci_index = z_oci.json.parse(z_oci.OciImageIndex, allocator, test_inspect_index_json) catch unreachable },
    };
    errdefer result.deinit();
    result.selected_leaf = z_oci.json.parse(z_oci.Manifest, allocator, test_inspect_manifest_json) catch unreachable;
    return .{ .success = result };
}

fn testInspectPlatformFailure(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: z_oci.Config,
    ref: z_oci.Reference,
    platform: ?z_oci.Platform,
) z_oci.PublicApiError!z_oci.InspectionOutcome {
    TestInspectCalls.calls += 1;
    TestInspectCalls.platform = platform;
    const reference = try std.fmt.allocPrint(allocator, "{s}/{s}:{s}", .{
        ref.registry,
        ref.repository,
        ref.refString(),
    });
    return .{ .failure = .{ .platform_not_found = .{
        .registry = ref.registry,
        .reference = reference,
        .http_status = null,
    } } };
}

const TestResolveCalls = struct {
    var calls: usize = 0;
    var platform: ?z_oci.Platform = null;

    fn reset() void {
        calls = 0;
        platform = null;
    }
};

const TestValidateCalls = struct {
    var calls: usize = 0;
    var platform: ?z_oci.Platform = null;

    fn reset() void {
        calls = 0;
        platform = null;
    }
};

const TestInspectCalls = struct {
    var calls: usize = 0;
    var platform: ?z_oci.Platform = null;

    fn reset() void {
        calls = 0;
        platform = null;
    }
};

const TestClock = struct {
    var calls: usize = 0;

    fn reset() void {
        calls = 0;
    }

    fn now(_: Io) std.Io.Clock.Timestamp {
        const nanoseconds: i96 = if (calls == 0) 0 else 37 * std.time.ns_per_ms;
        calls += 1;
        return .{
            .raw = .{ .nanoseconds = nanoseconds },
            .clock = .awake,
        };
    }
};

test "process adapter releases parsed command when output fails" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{ "z-oci", "resolve", "--verbose", "ubuntu" };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);

    var stdout_buffer: [128]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [0]u8 = .{};
    var stderr = Io.Writer.fixed(&stderr_buffer);
    try std.testing.expectError(
        error.WriteFailed,
        runWithResolve(init, &stdout, &stderr, testResolveSuccess, TestClock.now),
    );
}

test "process adapter releases partial reference on allocation failure" {
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
            const result = runWithResolve(init, &stdout, &stderr, testResolveSuccess, TestClock.now) catch |err| switch (err) {
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

test "resolve command renders injected success and verbose timing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "resolve",
        "--verbose",
        "ubuntu:22.04",
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [512]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [256]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestResolveCalls.reset();
    TestClock.reset();
    defer TestResolveCalls.reset();
    defer TestClock.reset();
    try std.testing.expectEqual(
        cli.ExitCode.success,
        runWithResolve(init, &stdout, &stderr, testResolveSuccess, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestResolveCalls.calls);
    try std.testing.expectEqualStrings(
        "registry-1.docker.io/library/ubuntu@sha256:" ++ ("a" ** 64) ++ "\n",
        stdout_buffer[0..stdout.end],
    );
    try std.testing.expectEqualStrings(
        "z-oci verbose: command=resolve outcome=success elapsed_ms=37\n",
        stderr_buffer[0..stderr.end],
    );
}

test "resolve command renders injected not-found JSON with code one" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "resolve",
        "--format",
        "json",
        "ubuntu:22.04",
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [512]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestResolveCalls.reset();
    defer TestResolveCalls.reset();
    try std.testing.expectEqual(
        cli.ExitCode.not_found,
        runWithResolve(init, &stdout, &stderr, testResolveNotFound, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestResolveCalls.calls);
    try std.testing.expectEqualStrings(
        "{\"error\":{\"code\":\"not_found\",\"message\":\"not found\",\"http_status\":404}}",
        stdout_buffer[0..stdout.end],
    );
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "resolve command preserves selected platform in JSON" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "resolve",
        "--format",
        "json",
        "--platform",
        "linux/amd64",
        "ubuntu:22.04",
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [768]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestResolveCalls.reset();
    defer TestResolveCalls.reset();
    try std.testing.expectEqual(
        cli.ExitCode.success,
        runWithResolve(init, &stdout, &stderr, testResolvePlatformSuccess, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestResolveCalls.calls);
    try std.testing.expect(TestResolveCalls.platform != null);
    try std.testing.expectEqualStrings("linux", TestResolveCalls.platform.?.os);
    try std.testing.expectEqualStrings("amd64", TestResolveCalls.platform.?.architecture);
    try std.testing.expectEqualStrings(
        "{\"command\":\"resolve\",\"input\":\"ubuntu:22.04\",\"reference\":\"registry-1.docker.io/library/ubuntu@sha256:" ++ ("b" ** 64) ++ "\",\"digest\":\"sha256:" ++ ("b" ** 64) ++ "\",\"media_type\":\"application/vnd.oci.image.manifest.v1+json\",\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\",\"variant\":null,\"os_version\":null,\"os_features\":null}}",
        stdout_buffer[0..stdout.end],
    );
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "resolve command uses the live resolver on an anonymous loopback peer" {
    const allocator = std.testing.allocator;
    const body =
        \\{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}
    ;
    const mock = try z_oci.testing.mock_registry.MockRegistry.start(allocator, std.testing.io, .{
        .repository = "library/alpine",
        .tag = "latest",
        .body = body,
        .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
    }, 1);
    defer mock.deinit();

    const reference_text = try mock.imageReferenceAlloc(allocator);
    defer allocator.free(reference_text);
    const reference_z = try allocator.dupeZ(u8, reference_text);
    defer allocator.free(reference_z);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    const argv = [_][*:0]const u8{ "z-oci", "resolve", reference_z.ptr };
    const init = testProcessInit(allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [512]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectEqual(cli.ExitCode.success, run(init, &stdout, &stderr));
    var expected_buffer: [512]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buffer, "{s}/library/alpine@{s}\n", .{
        mock.registry_host,
        mock.digest_header.?,
    });
    try std.testing.expectEqualStrings(expected, stdout_buffer[0..stdout.end]);
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "validate command renders injected valid text and verbose timing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "validate",
        "--verbose",
        "ubuntu@sha256:" ++ ("a" ** 64),
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [256]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [256]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestValidateCalls.reset();
    TestClock.reset();
    defer TestValidateCalls.reset();
    defer TestClock.reset();
    try std.testing.expectEqual(
        cli.ExitCode.success,
        runWithOperations(init, &stdout, &stderr, testResolveSuccess, testValidateValid, testInspectResult, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestValidateCalls.calls);
    try std.testing.expect(TestValidateCalls.platform == null);
    try std.testing.expectEqualStrings("validate success: valid\n", stdout_buffer[0..stdout.end]);
    try std.testing.expectEqualStrings(
        "z-oci verbose: command=validate outcome=success elapsed_ms=37\n",
        stderr_buffer[0..stderr.end],
    );
}

test "validate command renders injected not-found JSON with code one" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "validate",
        "--format",
        "json",
        "ubuntu@sha256:" ++ ("a" ** 64),
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [512]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestValidateCalls.reset();
    defer TestValidateCalls.reset();
    try std.testing.expectEqual(
        cli.ExitCode.not_found,
        runWithOperations(init, &stdout, &stderr, testResolveSuccess, testValidateNotFound, testInspectResult, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestValidateCalls.calls);
    try std.testing.expect(TestValidateCalls.platform == null);
    try std.testing.expectEqualStrings(
        "{\"command\":\"validate\",\"reference\":\"registry-1.docker.io/library/ubuntu@sha256:" ++ ("a" ** 64) ++ "\",\"valid\":false}",
        stdout_buffer[0..stdout.end],
    );
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "validate command maps injected failure through shared JSON diagnostics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "validate",
        "--format",
        "json",
        "ubuntu@sha256:" ++ ("a" ** 64),
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [512]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestValidateCalls.reset();
    defer TestValidateCalls.reset();
    try std.testing.expectEqual(
        cli.ExitCode.authentication_failure,
        runWithOperations(init, &stdout, &stderr, testResolveSuccess, testValidateAuthFailure, testInspectResult, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestValidateCalls.calls);
    try std.testing.expect(TestValidateCalls.platform == null);
    try std.testing.expectEqualStrings(
        "{\"error\":{\"code\":\"auth_failed\",\"message\":\"authentication failure\",\"http_status\":401}}",
        stdout_buffer[0..stdout.end],
    );
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "validate command uses the live resolver for an existing digest" {
    const allocator = std.testing.allocator;
    const body =
        \\{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}
    ;
    const mock = try z_oci.testing.mock_registry.MockRegistry.start(allocator, std.testing.io, .{
        .repository = "library/alpine",
        .tag = "latest",
        .body = body,
        .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
    }, 1);
    defer mock.deinit();

    const reference_text = try std.fmt.allocPrint(allocator, "{s}/library/alpine@{s}", .{
        mock.registry_host,
        mock.digest_header.?,
    });
    defer allocator.free(reference_text);
    const reference_z = try allocator.dupeZ(u8, reference_text);
    defer allocator.free(reference_z);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    const argv = [_][*:0]const u8{ "z-oci", "validate", reference_z.ptr };
    const init = testProcessInit(allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [128]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectEqual(cli.ExitCode.success, run(init, &stdout, &stderr));
    try std.testing.expectEqualStrings("validate success: valid\n", stdout_buffer[0..stdout.end]);
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "validate command uses the live resolver for a missing digest" {
    const allocator = std.testing.allocator;
    const body =
        \\{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}
    ;
    const mock = try z_oci.testing.mock_registry.MockRegistry.start(allocator, std.testing.io, .{
        .repository = "library/alpine",
        .tag = "latest",
        .body = body,
        .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
    }, 1);
    defer mock.deinit();

    const reference_text = try std.fmt.allocPrint(allocator, "{s}/library/alpine@sha256:{s}", .{
        mock.registry_host,
        "f" ** 64,
    });
    defer allocator.free(reference_text);
    const reference_z = try allocator.dupeZ(u8, reference_text);
    defer allocator.free(reference_z);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    const argv = [_][*:0]const u8{ "z-oci", "validate", reference_z.ptr };
    const init = testProcessInit(allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [128]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectEqual(cli.ExitCode.not_found, run(init, &stdout, &stderr));
    try std.testing.expectEqualStrings("validate not found: not-found\n", stdout_buffer[0..stdout.end]);
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "validate command maps a live authentication-required response" {
    const allocator = std.testing.allocator;
    const mock = try z_oci.testing.mock_registry.MockRegistry.startWithHandler(
        allocator,
        std.testing.io,
        1,
        struct {
            fn handle(_: *z_oci.testing.mock_registry.MockRegistry, request: *std.http.Server.Request) anyerror!void {
                try request.respond("", .{ .status = .unauthorized, .keep_alive = false });
            }
        }.handle,
        null,
    );
    defer mock.deinit();

    const reference_text = try std.fmt.allocPrint(allocator, "{s}/library/alpine@sha256:{s}", .{
        mock.registry_host,
        "a" ** 64,
    });
    defer allocator.free(reference_text);
    const reference_z = try allocator.dupeZ(u8, reference_text);
    defer allocator.free(reference_z);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    const argv = [_][*:0]const u8{ "z-oci", "validate", reference_z.ptr };
    const init = testProcessInit(allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [128]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [256]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectEqual(cli.ExitCode.authentication_failure, run(init, &stdout, &stderr));
    var expected_buffer: [512]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buffer, "z-oci: error: authentication failure (code=2) [registry={s}] [reference={s}] [http_status=401]\n", .{
        mock.registry_host,
        reference_text,
    });
    try std.testing.expectEqualStrings(
        expected,
        stderr_buffer[0..stderr.end],
    );
}

test "validate command maps a live digest mismatch" {
    const allocator = std.testing.allocator;
    const mock = try z_oci.testing.mock_registry.MockRegistry.startWithHandler(
        allocator,
        std.testing.io,
        1,
        struct {
            fn handle(_: *z_oci.testing.mock_registry.MockRegistry, request: *std.http.Server.Request) anyerror!void {
                try request.respond("", .{
                    .status = .ok,
                    .keep_alive = false,
                    .extra_headers = &.{
                        .{ .name = "Content-Type", .value = z_oci.MediaType.oci_manifest_v1.toString() },
                        .{ .name = "Docker-Content-Digest", .value = "sha256:" ++ ("b" ** 64) },
                    },
                });
            }
        }.handle,
        null,
    );
    defer mock.deinit();

    const reference_text = try std.fmt.allocPrint(allocator, "{s}/library/alpine@sha256:{s}", .{
        mock.registry_host,
        "a" ** 64,
    });
    defer allocator.free(reference_text);
    const reference_z = try allocator.dupeZ(u8, reference_text);
    defer allocator.free(reference_z);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    const argv = [_][*:0]const u8{ "z-oci", "validate", reference_z.ptr };
    const init = testProcessInit(allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [128]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [256]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectEqual(cli.ExitCode.digest_failure, run(init, &stdout, &stderr));
    var expected_buffer: [512]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buffer, "z-oci: error: digest failure (code=7) [registry={s}] [reference={s}] [http_status=200]\n", .{
        mock.registry_host,
        reference_text,
    });
    try std.testing.expectEqualStrings(
        expected,
        stderr_buffer[0..stderr.end],
    );
}

test "validate command maps a live transport failure" {
    const allocator = std.testing.allocator;
    const mock = try z_oci.testing.mock_registry.MockRegistry.startWithHandler(
        allocator,
        std.testing.io,
        1,
        struct {
            fn handle(_: *z_oci.testing.mock_registry.MockRegistry, _: *std.http.Server.Request) anyerror!void {
                return error.ConnectionResetByPeer;
            }
        }.handle,
        null,
    );
    defer mock.deinit();

    const reference_text = try std.fmt.allocPrint(allocator, "{s}/library/alpine@sha256:{s}", .{
        mock.registry_host,
        "a" ** 64,
    });
    defer allocator.free(reference_text);
    const reference_z = try allocator.dupeZ(u8, reference_text);
    defer allocator.free(reference_z);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    const argv = [_][*:0]const u8{ "z-oci", "validate", reference_z.ptr };
    const init = testProcessInit(allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [128]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [256]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectEqual(cli.ExitCode.network_failure, run(init, &stdout, &stderr));
    try std.testing.expect(std.mem.startsWith(u8, stderr_buffer[0..stderr.end], "z-oci: error: network failure (code=4)"));
}

test "inspect command renders injected single-arch text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{ "z-oci", "inspect", "ubuntu:22.04" };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [512]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestInspectCalls.reset();
    defer TestInspectCalls.reset();
    try std.testing.expectEqual(
        cli.ExitCode.success,
        runWithOperations(init, &stdout, &stderr, testResolveSuccess, testValidateValid, testInspectResult, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestInspectCalls.calls);
    try std.testing.expect(TestInspectCalls.platform == null);
    try std.testing.expectEqualStrings(
        "inspect:\n" ++
            "  reference: registry-1.docker.io/library/ubuntu:22.04\n" ++
            "  top_level.kind: manifest\n" ++
            "  top_level.media_type: application/vnd.oci.image.manifest.v1+json\n" ++
            "  top_level.config_digest: sha256:" ++ ("a" ** 64) ++ "\n" ++
            "  top_level.layers.count: 0\n",
        stdout_buffer[0..stdout.end],
    );
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "inspect command renders verbose timing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{ "z-oci", "inspect", "--verbose", "ubuntu:22.04" };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [512]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestInspectCalls.reset();
    TestClock.reset();
    defer TestInspectCalls.reset();
    defer TestClock.reset();
    try std.testing.expectEqual(
        cli.ExitCode.success,
        runWithOperations(init, &stdout, &stderr, testResolveSuccess, testValidateValid, testInspectResult, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestInspectCalls.calls);
    try std.testing.expectEqualStrings(
        "z-oci verbose: command=inspect outcome=success elapsed_ms=37\n",
        stderr_buffer[0..stderr.end],
    );
}

test "inspect command renders injected selected JSON" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "inspect",
        "--format",
        "json",
        "--platform",
        "linux/amd64",
        "ubuntu:22.04",
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [2048]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestInspectCalls.reset();
    defer TestInspectCalls.reset();
    try std.testing.expectEqual(
        cli.ExitCode.success,
        runWithOperations(init, &stdout, &stderr, testResolveSuccess, testValidateValid, testInspectResult, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestInspectCalls.calls);
    try std.testing.expect(TestInspectCalls.platform != null);
    try std.testing.expectEqualStrings("linux", TestInspectCalls.platform.?.os);
    try std.testing.expectEqualStrings("amd64", TestInspectCalls.platform.?.architecture);
    try std.testing.expectEqualStrings(
        "{\"command\":\"inspect\",\"reference\":\"registry-1.docker.io/library/ubuntu:22.04\",\"top_level\":{\"kind\":\"oci_image_index\",\"media_type\":\"application/vnd.oci.image.index.v1+json\",\"config_digest\":null,\"layer_count\":null,\"platforms\":[{\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\",\"variant\":null,\"os_version\":null,\"os_features\":null},\"media_type\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:" ++ ("b" ** 64) ++ "\",\"size\":456}]},\"selected_leaf\":{\"requested_platform\":{\"os\":\"linux\",\"architecture\":\"amd64\",\"variant\":null,\"os_version\":null,\"os_features\":null},\"media_type\":\"application/vnd.oci.image.manifest.v1+json\",\"config_digest\":\"sha256:" ++ ("a" ** 64) ++ "\",\"layer_count\":0}}",
        stdout_buffer[0..stdout.end],
    );
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "inspect command maps injected platform failure through shared JSON diagnostics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "inspect",
        "--format",
        "json",
        "--platform",
        "linux/amd64",
        "ubuntu:22.04",
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [512]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [128]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    TestInspectCalls.reset();
    defer TestInspectCalls.reset();
    try std.testing.expectEqual(
        cli.ExitCode.platform_selection_failure,
        runWithOperations(init, &stdout, &stderr, testResolveSuccess, testValidateValid, testInspectPlatformFailure, TestClock.now),
    );
    try std.testing.expectEqual(@as(usize, 1), TestInspectCalls.calls);
    try std.testing.expect(TestInspectCalls.platform != null);
    try std.testing.expectEqualStrings(
        "{\"error\":{\"code\":\"platform_not_found\",\"message\":\"platform selection failure\",\"http_status\":null}}",
        stdout_buffer[0..stdout.end],
    );
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "inspect command writer failure releases returned documents" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{ "z-oci", "inspect", "ubuntu:22.04" };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [0]u8 = .{};
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [0]u8 = .{};
    var stderr = Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectError(
        error.WriteFailed,
        runWithOperations(init, &stdout, &stderr, testResolveSuccess, testValidateValid, testInspectResult, TestClock.now),
    );
}

test "process adapter keeps configuration preflight active for parsed commands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const argv = [_][*:0]const u8{
        "z-oci",
        "--ca-bundle",
        "missing-ca-bundle.pem",
        "validate",
        "ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    const init = testProcessInit(std.testing.allocator, &arena, &environ_map, &argv);
    var stdout_buffer: [128]u8 = undefined;
    var stdout = Io.Writer.fixed(&stdout_buffer);
    var stderr_buffer: [256]u8 = undefined;
    var stderr = Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectEqual(
        cli.ExitCode.local_configuration_failure,
        runWithResolve(init, &stdout, &stderr, testResolveSuccess, TestClock.now),
    );
    try std.testing.expectEqualStrings(
        "z-oci: error: local configuration failure (code=6)\n",
        stderr_buffer[0..stderr.end],
    );
}
