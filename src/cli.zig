//! Executable-only command parsing and help/version output for z-oci.
//!
//! Parsed option slices borrow the argument storage. Parsed references own their
//! fields through the allocator passed to `parse` and must be released with
//! `ParsedCommand.deinit`.

const std = @import("std");
const z_oci = @import("z_oci");

const Reference = z_oci.Reference;
const Platform = z_oci.Platform;

pub const Command = enum {
    resolve,
    validate,
    inspect,
};

pub const Format = enum {
    text,
    json,
};

pub const HelpTarget = enum {
    top_level,
    resolve,
    validate,
    inspect,
};

pub const UsageReason = enum {
    missing_command,
    unknown_command,
    unknown_option,
    option_not_allowed,
    missing_option_value,
    duplicate_option,
    extra_argument,
    missing_argument,
    invalid_number,
    invalid_format,
    invalid_path,
    invalid_reference,
    invalid_platform,
    unsupported_combination,
};

pub const UsageFailure = struct {
    reason: UsageReason,
    help_target: HelpTarget,
};

pub const GlobalOptions = struct {
    ca_bundle_path: ?[]const u8 = null,
    helper_timeout_ms: ?u32 = null,
};

pub const CommandOptions = struct {
    platform: ?Platform = null,
    format: Format = .text,
    verbose: bool = false,
};

pub const ParsedCommand = struct {
    command: Command,
    global: GlobalOptions,
    options: CommandOptions,
    reference: Reference,

    pub fn deinit(self: *ParsedCommand, allocator: std.mem.Allocator) void {
        self.reference.deinit(allocator);
    }
};

pub const ParseOutcome = union(enum) {
    command: ParsedCommand,
    help: HelpTarget,
    version: HelpTarget,
    usage: UsageFailure,
};

pub const ParseError = error{
    OutOfMemory,
};

pub const TOP_LEVEL_HELP =
    \\Usage:
    \\  z-oci [global-options] <command> [command-options] <image>
    \\
    \\Commands:
    \\  resolve <image>             Resolve an image to a verified digest.
    \\  validate <image@sha256:...> Check whether an exact digest exists.
    \\  inspect <image>             Show manifest and platform metadata.
    \\
    \\Global options:
    \\  --ca-bundle <path>          Use a public CA bundle for registry HTTPS.
    \\  --helper-timeout-ms <ms>    Set credential-helper I/O timeout.
    \\  --help                      Show this help.
    \\  --version                   Show the package version.
    \\
    \\Run "z-oci <command> --help" for command-specific help.
    \\
;

const RESOLVE_HELP =
    \\Usage:
    \\  z-oci resolve [command-options] <image>
    \\
    \\Resolve an image reference to a verified digest-pinned reference.
    \\
    \\Options:
    \\  --platform <os/arch[/variant]>  Select a platform for multi-arch images.
    \\  --format text|json              Select output format. Default: text.
    \\  --verbose                       Show elapsed time and outcome on stderr.
    \\
;

const VALIDATE_HELP =
    \\Usage:
    \\  z-oci validate [command-options] <image@sha256:...>
    \\
    \\Check whether an exact sha256 digest exists in the registry.
    \\
    \\Options:
    \\  --format text|json  Select output format. Default: text.
    \\  --verbose           Show elapsed time and outcome on stderr.
    \\
;

const INSPECT_HELP =
    \\Usage:
    \\  z-oci inspect [command-options] <image>
    \\
    \\Show the top-level manifest or index and optional selected-leaf metadata.
    \\
    \\Options:
    \\  --platform <os/arch[/variant]>  Select a platform for multi-arch images.
    \\  --format text|json              Select output format. Default: text.
    \\  --verbose                       Show elapsed time and outcome on stderr.
    \\
;

pub const COMMAND_NOT_IMPLEMENTED = "z-oci: command execution is not implemented yet.\n";

pub fn parse(allocator: std.mem.Allocator, args: []const []const u8) ParseError!ParseOutcome {
    if (args.len <= 1) return usage(.missing_command, .top_level);

    var global: GlobalOptions = .{};
    var index: usize = 1;

    while (index < args.len) {
        const arg = args[index];
        if (!std.mem.startsWith(u8, arg, "-")) break;

        if (std.mem.eql(u8, arg, "--help")) {
            if (index + 1 != args.len) return usage(.option_not_allowed, .top_level);
            return .{ .help = .top_level };
        }
        if (std.mem.eql(u8, arg, "--version")) {
            if (index + 1 != args.len) return usage(.option_not_allowed, .top_level);
            return .{ .version = .top_level };
        }
        if (std.mem.eql(u8, arg, "--ca-bundle")) {
            if (global.ca_bundle_path != null) return usage(.duplicate_option, .top_level);
            const value = optionValue(args, &index) orelse return usage(.missing_option_value, .top_level);
            if (value.len == 0) return usage(.invalid_path, .top_level);
            global.ca_bundle_path = value;
            continue;
        }
        if (std.mem.eql(u8, arg, "--helper-timeout-ms")) {
            if (global.helper_timeout_ms != null) return usage(.duplicate_option, .top_level);
            const value = optionValue(args, &index) orelse return usage(.missing_option_value, .top_level);
            global.helper_timeout_ms = std.fmt.parseInt(u32, value, 10) catch {
                return usage(.invalid_number, .top_level);
            };
            continue;
        }
        if (isCommandOption(arg)) return usage(.option_not_allowed, .top_level);
        return usage(.unknown_option, .top_level);
    }

    if (index == args.len) return usage(.missing_command, .top_level);
    const command = parseCommand(args[index]) orelse return usage(.unknown_command, .top_level);
    const command_target = helpTarget(command);
    index += 1;

    var options: CommandOptions = .{};
    var platform_seen = false;
    var format_seen = false;
    var verbose_seen = false;

    while (index < args.len) {
        const arg = args[index];
        if (!std.mem.startsWith(u8, arg, "-")) break;

        if (std.mem.eql(u8, arg, "--help")) {
            if (index + 1 != args.len or hasGlobalOptions(global) or platform_seen or format_seen or verbose_seen) {
                return usage(.option_not_allowed, command_target);
            }
            return .{ .help = command_target };
        }
        if (std.mem.eql(u8, arg, "--version")) {
            if (index + 1 != args.len or hasGlobalOptions(global) or platform_seen or format_seen or verbose_seen) {
                return usage(.option_not_allowed, command_target);
            }
            return .{ .version = command_target };
        }
        if (std.mem.eql(u8, arg, "--ca-bundle") or std.mem.eql(u8, arg, "--helper-timeout-ms")) {
            return usage(.option_not_allowed, command_target);
        }
        if (std.mem.eql(u8, arg, "--platform")) {
            if (command == .validate) return usage(.unsupported_combination, command_target);
            if (platform_seen) return usage(.duplicate_option, command_target);
            const value = optionValue(args, &index) orelse return usage(.missing_option_value, command_target);
            options.platform = parsePlatform(value) catch return usage(.invalid_platform, command_target);
            platform_seen = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--format")) {
            if (format_seen) return usage(.duplicate_option, command_target);
            const value = optionValue(args, &index) orelse return usage(.missing_option_value, command_target);
            options.format = parseFormat(value) orelse return usage(.invalid_format, command_target);
            format_seen = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--verbose")) {
            if (verbose_seen) return usage(.duplicate_option, command_target);
            options.verbose = true;
            verbose_seen = true;
            index += 1;
            continue;
        }
        return usage(.unknown_option, command_target);
    }

    if (index == args.len) return usage(.missing_argument, command_target);
    if (index + 1 != args.len) return usage(.extra_argument, command_target);

    var reference = Reference.parse(allocator, args[index]) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return usage(.invalid_reference, command_target),
    };
    errdefer reference.deinit(allocator);

    if (command == .validate and reference.digest == null) {
        reference.deinit(allocator);
        return usage(.invalid_reference, command_target);
    }

    return .{ .command = .{
        .command = command,
        .global = global,
        .options = options,
        .reference = reference,
    } };
}

pub fn writeHelp(writer: *std.Io.Writer, target: HelpTarget) std.Io.Writer.Error!void {
    try writer.writeAll(helpText(target));
}

pub fn writeVersion(writer: *std.Io.Writer, package_version: []const u8) std.Io.Writer.Error!void {
    try writer.print("z-oci {s}\n", .{package_version});
}

pub fn writeUsageError(writer: *std.Io.Writer, failure: UsageFailure) std.Io.Writer.Error!void {
    try writer.print("z-oci: usage error: code={s}\nRun \"{s}\" for help.\n", .{
        @tagName(failure.reason),
        helpCommand(failure.help_target),
    });
}

fn usage(reason: UsageReason, target: HelpTarget) ParseOutcome {
    return .{ .usage = .{ .reason = reason, .help_target = target } };
}

fn optionValue(args: []const []const u8, index: *usize) ?[]const u8 {
    if (index.* + 1 >= args.len) return null;
    if (std.mem.startsWith(u8, args[index.* + 1], "--")) return null;
    index.* += 2;
    return args[index.* - 1];
}

fn hasGlobalOptions(options: GlobalOptions) bool {
    return options.ca_bundle_path != null or options.helper_timeout_ms != null;
}

fn isCommandOption(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--platform") or
        std.mem.eql(u8, arg, "--format") or
        std.mem.eql(u8, arg, "--verbose");
}

fn parseCommand(arg: []const u8) ?Command {
    if (std.mem.eql(u8, arg, "resolve")) return .resolve;
    if (std.mem.eql(u8, arg, "validate")) return .validate;
    if (std.mem.eql(u8, arg, "inspect")) return .inspect;
    return null;
}

fn helpTarget(command: Command) HelpTarget {
    return switch (command) {
        .resolve => .resolve,
        .validate => .validate,
        .inspect => .inspect,
    };
}

fn parseFormat(arg: []const u8) ?Format {
    if (std.mem.eql(u8, arg, "text")) return .text;
    if (std.mem.eql(u8, arg, "json")) return .json;
    return null;
}

fn parsePlatform(arg: []const u8) error{InvalidPlatform}!Platform {
    var parts: [3][]const u8 = undefined;
    var count: usize = 0;
    var iterator = std.mem.splitScalar(u8, arg, '/');
    while (iterator.next()) |part| {
        if (part.len == 0 or count == parts.len) return error.InvalidPlatform;
        parts[count] = part;
        count += 1;
    }
    if (count < 2) return error.InvalidPlatform;
    return .{
        .os = parts[0],
        .architecture = parts[1],
        .variant = if (count == 3) parts[2] else null,
    };
}

fn helpText(target: HelpTarget) []const u8 {
    return switch (target) {
        .top_level => TOP_LEVEL_HELP,
        .resolve => RESOLVE_HELP,
        .validate => VALIDATE_HELP,
        .inspect => INSPECT_HELP,
    };
}

fn helpCommand(target: HelpTarget) []const u8 {
    return switch (target) {
        .top_level => "z-oci --help",
        .resolve => "z-oci resolve --help",
        .validate => "z-oci validate --help",
        .inspect => "z-oci inspect --help",
    };
}

fn expectUsage(args: []const []const u8, reason: UsageReason, target: HelpTarget) !void {
    const outcome = try parse(std.testing.allocator, args);
    switch (outcome) {
        .usage => |failure| {
            try std.testing.expectEqual(reason, failure.reason);
            try std.testing.expectEqual(target, failure.help_target);
        },
        else => return error.UnexpectedParseOutcome,
    }
}

fn expectHelp(args: []const []const u8, target: HelpTarget) !void {
    const outcome = try parse(std.testing.allocator, args);
    switch (outcome) {
        .help => |actual| try std.testing.expectEqual(target, actual),
        else => return error.UnexpectedParseOutcome,
    }
}

fn expectVersion(args: []const []const u8, target: HelpTarget) !void {
    const outcome = try parse(std.testing.allocator, args);
    switch (outcome) {
        .version => |actual| try std.testing.expectEqual(target, actual),
        else => return error.UnexpectedParseOutcome,
    }
}

test "parse: valid commands preserve options and owned references" {
    const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const args = [_][]const u8{
        "z-oci",      "--ca-bundle",    "ca.pem",   "--helper-timeout-ms", "0",         "resolve",
        "--platform", "linux/amd64/v3", "--format", "json",                "--verbose", "ubuntu:22.04",
    };

    var outcome = try parse(std.testing.allocator, &args);
    defer if (outcome == .command) outcome.command.deinit(std.testing.allocator);

    switch (outcome) {
        .command => |command| {
            try std.testing.expectEqual(Command.resolve, command.command);
            try std.testing.expectEqualStrings("ca.pem", command.global.ca_bundle_path.?);
            try std.testing.expectEqual(@as(u32, 0), command.global.helper_timeout_ms.?);
            try std.testing.expectEqual(Format.json, command.options.format);
            try std.testing.expect(command.options.verbose);
            try std.testing.expectEqualStrings("linux", command.options.platform.?.os);
            try std.testing.expectEqualStrings("amd64", command.options.platform.?.architecture);
            try std.testing.expectEqualStrings("v3", command.options.platform.?.variant.?);
            try std.testing.expectEqualStrings("library/ubuntu", command.reference.repository);
        },
        else => return error.UnexpectedParseOutcome,
    }

    const validate_args = [_][]const u8{ "z-oci", "validate", "ubuntu@" ++ digest };
    var validate_outcome = try parse(std.testing.allocator, &validate_args);
    defer if (validate_outcome == .command) validate_outcome.command.deinit(std.testing.allocator);
    try std.testing.expect(validate_outcome == .command);

    const inspect_args = [_][]const u8{ "z-oci", "inspect", "--format", "text", "ubuntu:22.04" };
    var inspect_outcome = try parse(std.testing.allocator, &inspect_args);
    defer if (inspect_outcome == .command) inspect_outcome.command.deinit(std.testing.allocator);
    try std.testing.expect(inspect_outcome == .command);
}

test "parse: standalone help and version targets" {
    try expectHelp(&.{ "z-oci", "--help" }, .top_level);
    try expectVersion(&.{ "z-oci", "--version" }, .top_level);
    try expectHelp(&.{ "z-oci", "resolve", "--help" }, .resolve);
    try expectVersion(&.{ "z-oci", "resolve", "--version" }, .resolve);
    try expectHelp(&.{ "z-oci", "validate", "--help" }, .validate);
    try expectVersion(&.{ "z-oci", "validate", "--version" }, .validate);
    try expectHelp(&.{ "z-oci", "inspect", "--help" }, .inspect);
    try expectVersion(&.{ "z-oci", "inspect", "--version" }, .inspect);
}

test "parse: invalid option placement and combinations use the command help target" {
    try expectUsage(&.{ "z-oci", "--platform", "linux/amd64", "resolve", "ubuntu" }, .option_not_allowed, .top_level);
    try expectUsage(&.{ "z-oci", "resolve", "--ca-bundle", "ca.pem", "ubuntu" }, .option_not_allowed, .resolve);
    try expectUsage(&.{ "z-oci", "validate", "--platform", "linux/amd64", "ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, .unsupported_combination, .validate);
    try expectUsage(&.{ "z-oci", "resolve", "--help", "ubuntu" }, .option_not_allowed, .resolve);
    try expectUsage(&.{ "z-oci", "--help", "resolve" }, .option_not_allowed, .top_level);
}

test "parse: rejects duplicate, missing, unknown, and extra options" {
    try expectUsage(&.{ "z-oci", "resolve", "--verbose", "--verbose", "ubuntu" }, .duplicate_option, .resolve);
    try expectUsage(&.{ "z-oci", "--ca-bundle" }, .missing_option_value, .top_level);
    try expectUsage(&.{ "z-oci", "resolve", "--format" }, .missing_option_value, .resolve);
    try expectUsage(&.{ "z-oci", "resolve", "--unknown", "ubuntu" }, .unknown_option, .resolve);
    try expectUsage(&.{ "z-oci", "resolve", "-v", "ubuntu" }, .unknown_option, .resolve);
    try expectUsage(&.{ "z-oci", "resolve", "ubuntu", "extra" }, .extra_argument, .resolve);
    try expectUsage(&.{"z-oci"}, .missing_command, .top_level);
    try expectUsage(&.{ "z-oci", "unknown", "ubuntu" }, .unknown_command, .top_level);
}

test "parse: validates numbers, formats, paths, references, and command arguments" {
    const pinned = "ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try expectUsage(&.{ "z-oci", "--helper-timeout-ms", "4294967296", "resolve", "ubuntu" }, .invalid_number, .top_level);
    try expectUsage(&.{ "z-oci", "resolve", "--format", "yaml", "ubuntu" }, .invalid_format, .resolve);
    try expectUsage(&.{ "z-oci", "--ca-bundle", "", "resolve", "ubuntu" }, .invalid_path, .top_level);
    try expectUsage(&.{ "z-oci", "resolve", "--platform", "linux/", "ubuntu" }, .invalid_platform, .resolve);
    try expectUsage(&.{ "z-oci", "resolve", "--platform", "linux/amd64/one/two", "ubuntu" }, .invalid_platform, .resolve);
    try expectUsage(&.{ "z-oci", "resolve", "not a reference" }, .invalid_reference, .resolve);
    try expectUsage(&.{ "z-oci", "validate", "ubuntu:latest" }, .invalid_reference, .validate);
    try expectUsage(&.{ "z-oci", "resolve" }, .missing_argument, .resolve);
    try expectUsage(&.{ "z-oci", "resolve", pinned, "extra" }, .extra_argument, .resolve);
}

test "help and version output use the locked plain-text shapes" {
    const snapshots = [_]struct { target: HelpTarget, expected: []const u8 }{
        .{
            .target = .top_level,
            .expected = "Usage:\n" ++
                "  z-oci [global-options] <command> [command-options] <image>\n\n" ++
                "Commands:\n" ++
                "  resolve <image>             Resolve an image to a verified digest.\n" ++
                "  validate <image@sha256:...> Check whether an exact digest exists.\n" ++
                "  inspect <image>             Show manifest and platform metadata.\n\n" ++
                "Global options:\n" ++
                "  --ca-bundle <path>          Use a public CA bundle for registry HTTPS.\n" ++
                "  --helper-timeout-ms <ms>    Set credential-helper I/O timeout.\n" ++
                "  --help                      Show this help.\n" ++
                "  --version                   Show the package version.\n\n" ++
                "Run \"z-oci <command> --help\" for command-specific help.\n",
        },
        .{
            .target = .resolve,
            .expected = "Usage:\n" ++
                "  z-oci resolve [command-options] <image>\n\n" ++
                "Resolve an image reference to a verified digest-pinned reference.\n\n" ++
                "Options:\n" ++
                "  --platform <os/arch[/variant]>  Select a platform for multi-arch images.\n" ++
                "  --format text|json              Select output format. Default: text.\n" ++
                "  --verbose                       Show elapsed time and outcome on stderr.\n",
        },
        .{
            .target = .validate,
            .expected = "Usage:\n" ++
                "  z-oci validate [command-options] <image@sha256:...>\n\n" ++
                "Check whether an exact sha256 digest exists in the registry.\n\n" ++
                "Options:\n" ++
                "  --format text|json  Select output format. Default: text.\n" ++
                "  --verbose           Show elapsed time and outcome on stderr.\n",
        },
        .{
            .target = .inspect,
            .expected = "Usage:\n" ++
                "  z-oci inspect [command-options] <image>\n\n" ++
                "Show the top-level manifest or index and optional selected-leaf metadata.\n\n" ++
                "Options:\n" ++
                "  --platform <os/arch[/variant]>  Select a platform for multi-arch images.\n" ++
                "  --format text|json              Select output format. Default: text.\n" ++
                "  --verbose                       Show elapsed time and outcome on stderr.\n",
        },
    };

    for (snapshots) |snapshot| {
        var help_buffer: [2048]u8 = undefined;
        var help_writer = std.Io.Writer.fixed(&help_buffer);
        try writeHelp(&help_writer, snapshot.target);
        try std.testing.expectEqualStrings(snapshot.expected, help_buffer[0..help_writer.end]);
        try std.testing.expect(std.mem.endsWith(u8, snapshot.expected, "\n"));
        try std.testing.expect(!std.mem.endsWith(u8, snapshot.expected, "\n\n"));
        try std.testing.expect(std.mem.indexOfScalar(u8, snapshot.expected, 0x1b) == null);
    }

    var version_buffer: [64]u8 = undefined;
    var version_writer = std.Io.Writer.fixed(&version_buffer);
    try writeVersion(&version_writer, "test-version");
    try std.testing.expectEqualStrings("z-oci test-version\n", version_buffer[0..version_writer.end]);
}

test "usage diagnostics use two lines and the selected help command" {
    const cases = [_]struct {
        reason: UsageReason,
        reason_text: []const u8,
        target: HelpTarget,
        help_command: []const u8,
    }{
        .{ .reason = .missing_command, .reason_text = "missing_command", .target = .top_level, .help_command = "z-oci --help" },
        .{ .reason = .unknown_command, .reason_text = "unknown_command", .target = .top_level, .help_command = "z-oci --help" },
        .{ .reason = .unknown_option, .reason_text = "unknown_option", .target = .top_level, .help_command = "z-oci --help" },
        .{ .reason = .option_not_allowed, .reason_text = "option_not_allowed", .target = .resolve, .help_command = "z-oci resolve --help" },
        .{ .reason = .missing_option_value, .reason_text = "missing_option_value", .target = .top_level, .help_command = "z-oci --help" },
        .{ .reason = .duplicate_option, .reason_text = "duplicate_option", .target = .resolve, .help_command = "z-oci resolve --help" },
        .{ .reason = .extra_argument, .reason_text = "extra_argument", .target = .resolve, .help_command = "z-oci resolve --help" },
        .{ .reason = .missing_argument, .reason_text = "missing_argument", .target = .resolve, .help_command = "z-oci resolve --help" },
        .{ .reason = .invalid_number, .reason_text = "invalid_number", .target = .top_level, .help_command = "z-oci --help" },
        .{ .reason = .invalid_format, .reason_text = "invalid_format", .target = .resolve, .help_command = "z-oci resolve --help" },
        .{ .reason = .invalid_path, .reason_text = "invalid_path", .target = .top_level, .help_command = "z-oci --help" },
        .{ .reason = .invalid_reference, .reason_text = "invalid_reference", .target = .resolve, .help_command = "z-oci resolve --help" },
        .{ .reason = .invalid_platform, .reason_text = "invalid_platform", .target = .inspect, .help_command = "z-oci inspect --help" },
        .{ .reason = .unsupported_combination, .reason_text = "unsupported_combination", .target = .validate, .help_command = "z-oci validate --help" },
    };

    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try writeUsageError(&writer, .{ .reason = case.reason, .help_target = case.target });
        var expected_buffer: [256]u8 = undefined;
        const expected = try std.fmt.bufPrint(&expected_buffer, "z-oci: usage error: code={s}\nRun \"{s}\" for help.\n", .{
            case.reason_text,
            case.help_command,
        });
        try std.testing.expectEqualStrings(
            expected,
            buffer[0..writer.end],
        );
    }
}
