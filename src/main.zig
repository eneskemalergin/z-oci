//! z-oci executable process adapter.
//!
//! This module owns process arguments, standard-output writers, the caller-owned
//! HTTP client, and projection of process state into the public resolver
//! configuration. The `resolve` command invokes the public resolver and routes
//! its owned result or failure through the executable renderers.

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
    return runWithResolve(init, stdout, stderr, z_oci.resolve, monotonicNow);
}

fn runWithResolve(
    init: std.process.Init,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
    comptime resolve_fn: anytype,
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

            const started_at = if (parsed.command == .resolve and parsed.options.verbose)
                now_fn(init.io)
            else
                null;
            config.applyToClient(&client) catch |err| {
                const failure = cli.CliFailure{ .config = err };
                try writeFailure(stdout, stderr, parsed.options.format, failure);
                if (parsed.command == .resolve and parsed.options.verbose) {
                    try cli.writeVerbose(
                        stderr,
                        .resolve,
                        cli.verboseOutcomeForFailure(failure),
                        elapsedMilliseconds(now_fn, init.io, started_at.?),
                    );
                }
                return cli.exitCodeForFailure(failure);
            };

            if (parsed.command != .resolve) {
                try stderr.writeAll(cli.COMMAND_NOT_IMPLEMENTED);
                return .unexpected_failure;
            }

            const resolve_outcome = resolve_fn(
                init.gpa,
                &client,
                config,
                parsed.reference,
                parsed.options.platform,
            ) catch |err| {
                const failure = cli.CliFailure{ .config = err };
                try writeFailure(stdout, stderr, parsed.options.format, failure);
                if (parsed.options.verbose) {
                    try cli.writeVerbose(
                        stderr,
                        .resolve,
                        cli.verboseOutcomeForFailure(failure),
                        elapsedMilliseconds(now_fn, init.io, started_at.?),
                    );
                }
                return cli.exitCodeForFailure(failure);
            };
            const elapsed_ms = if (parsed.options.verbose)
                elapsedMilliseconds(now_fn, init.io, started_at.?)
            else
                0;

            switch (resolve_outcome) {
                .success => |result| {
                    reference_owned = false;
                    var owned_result = result;
                    defer owned_result.deinit(init.gpa);
                    try writeResolveSuccess(stdout, parsed.options.format, parsed.input, owned_result);
                    if (parsed.options.verbose) {
                        try cli.writeVerbose(stderr, .resolve, .success, elapsed_ms);
                    }
                    return .success;
                },
                .failure => |failure| {
                    defer z_oci.deinitResolveFailure(failure, init.gpa);
                    try writeFailure(stdout, stderr, parsed.options.format, .{ .resolve = failure });
                    if (parsed.options.verbose) {
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
    }
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

test "process config projection preserves defaults and injects process sources" {
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

const TestResolveCalls = struct {
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

test "process command writer failure releases parsed command" {
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

test "process configuration preflight remains active for parsed non-resolve commands" {
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
