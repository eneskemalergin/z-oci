//! Executable-only command parsing, rendering, and process-facing output for z-oci.
//!
//! Parsed option slices borrow the argument storage. Parsed references own their
//! fields through the allocator passed to `parse` and must be released with
//! `ParsedCommand.deinit`. Renderers borrow public resolver results and stream
//! output without copying them.

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
    input: []const u8,
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

pub const ExitCode = enum(u8) {
    success = 0,
    not_found = 1,
    authentication_failure = 2,
    rate_limited = 3,
    network_failure = 4,
    usage_failure = 5,
    local_configuration_failure = 6,
    digest_failure = 7,
    content_type_failure = 8,
    manifest_content_failure = 9,
    timeout = 10,
    platform_selection_failure = 11,
    unexpected_failure = 12,
};

pub const VerboseOutcome = enum {
    success,
    not_found,
    auth_failed,
    rate_limited,
    network_error,
    local_config,
    digest,
    content_type,
    manifest_content,
    timeout,
    platform_selection,
    unexpected,
};

pub const CliFailure = union(enum) {
    resolve: z_oci.ResolveError,
    config: z_oci.Config.ApplyError,
    out_of_memory,
    unexpected,
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
        .input = args[index],
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

pub fn writeResolveText(writer: *std.Io.Writer, result: z_oci.ResolveResult) std.Io.Writer.Error!void {
    try writePinnedReference(writer, result.reference, result.digest);
    try writer.writeByte('\n');
}

pub fn writeValidateText(writer: *std.Io.Writer, valid: bool) std.Io.Writer.Error!void {
    try writer.writeAll(if (valid) "validate success: valid\n" else "validate not found: not-found\n");
}

pub fn writeInspectText(
    writer: *std.Io.Writer,
    reference: z_oci.Reference,
    requested_platform: ?Platform,
    result: z_oci.InspectionResult,
) std.Io.Writer.Error!void {
    try writer.writeAll("inspect:\n  reference: ");
    try writeReference(writer, reference);
    try writer.writeByte('\n');

    switch (result.top_level) {
        .manifest => |parsed| {
            try writer.writeAll("  top_level.kind: manifest\n  top_level.media_type: ");
            try writer.writeAll(parsed.value.media_type.toString());
            try writer.writeAll("\n  top_level.config_digest: ");
            try parsed.value.config.digest.format(writer);
            try writer.print("\n  top_level.layers.count: {d}\n", .{parsed.value.layers.len});
        },
        .oci_index => |parsed| {
            try writeIndexText(writer, parsed.value.manifests, "oci_image_index", parsed.value.media_type);
        },
        .docker_manifest_list => |parsed| {
            try writeIndexText(writer, parsed.value.manifests, "docker_manifest_list", parsed.value.media_type);
        },
    }

    if (result.selected_leaf) |leaf| {
        try writer.writeAll("  selected.requested_platform: ");
        try writeTextPlatform(writer, requested_platform.?);
        try writer.writeAll("\n  selected.media_type: ");
        try writer.writeAll(leaf.value.media_type.toString());
        try writer.writeAll("\n  selected.config_digest: ");
        try leaf.value.config.digest.format(writer);
        try writer.print("\n  selected.layers.count: {d}\n", .{leaf.value.layers.len});
    }
}

pub fn writeResolveJson(
    writer: *std.Io.Writer,
    input: []const u8,
    result: z_oci.ResolveResult,
) std.Io.Writer.Error!void {
    var json = std.json.Stringify{ .writer = writer };
    try json.beginObject();
    try json.objectField("command");
    try json.write("resolve");
    try json.objectField("input");
    try writeJsonStringValue(&json, input);
    try json.objectField("reference");
    try writeJsonPinnedReference(&json, result.reference, result.digest);
    try json.objectField("digest");
    try json.write(result.digest);
    try json.objectField("media_type");
    try json.write(result.media_type.toString());
    try json.objectField("platform");
    try writeJsonPlatform(&json, result.platform);
    try json.endObject();
}

pub fn writeValidateJson(
    writer: *std.Io.Writer,
    reference: z_oci.Reference,
    valid: bool,
) std.Io.Writer.Error!void {
    var json = std.json.Stringify{ .writer = writer };
    try json.beginObject();
    try json.objectField("command");
    try json.write("validate");
    try json.objectField("reference");
    try writeJsonReference(&json, reference);
    try json.objectField("valid");
    try json.write(valid);
    try json.endObject();
}

pub fn writeInspectJson(
    writer: *std.Io.Writer,
    reference: z_oci.Reference,
    requested_platform: ?Platform,
    result: z_oci.InspectionResult,
) std.Io.Writer.Error!void {
    var json = std.json.Stringify{ .writer = writer };
    try json.beginObject();
    try json.objectField("command");
    try json.write("inspect");
    try json.objectField("reference");
    try writeJsonReference(&json, reference);
    try json.objectField("top_level");
    try writeJsonInspectionTopLevel(&json, result.top_level);
    try json.objectField("selected_leaf");
    if (result.selected_leaf) |leaf| {
        try writeJsonSelectedLeaf(&json, requested_platform.?, leaf.value);
    } else {
        try json.write(@as(?[]const u8, null));
    }
    try json.endObject();
}

pub fn writeFailureText(writer: *std.Io.Writer, failure: CliFailure) std.Io.Writer.Error!void {
    try writer.print("z-oci: error: {s} (code={d})", .{
        failureSummary(failure),
        @intFromEnum(exitCodeForFailure(failure)),
    });
    switch (failure) {
        .resolve => |resolve_failure| {
            try writer.print(" [registry={s}] [reference={s}]", .{
                resolveFailureRegistry(resolve_failure),
                resolveFailureReference(resolve_failure),
            });
            if (resolveFailureHttpStatus(resolve_failure)) |status| {
                try writer.print(" [http_status={d}]", .{status});
            }
        },
        .config, .out_of_memory, .unexpected => {},
    }
    try writer.writeByte('\n');
}

pub fn writeFailureJson(writer: *std.Io.Writer, failure: CliFailure) std.Io.Writer.Error!void {
    var json = std.json.Stringify{ .writer = writer };
    try json.beginObject();
    try json.objectField("error");
    try json.beginObject();
    try json.objectField("code");
    try json.write(failureCode(failure));
    try json.objectField("message");
    try json.write(failureSummary(failure));
    try json.objectField("http_status");
    switch (failure) {
        .resolve => |resolve_failure| try json.write(resolveFailureHttpStatus(resolve_failure)),
        .config, .out_of_memory, .unexpected => try json.write(@as(?u16, null)),
    }
    try json.endObject();
    try json.endObject();
}

pub fn writeVerbose(
    writer: *std.Io.Writer,
    command: Command,
    outcome: VerboseOutcome,
    elapsed_ms: u64,
) std.Io.Writer.Error!void {
    try writer.print("z-oci verbose: command={s} outcome={s} elapsed_ms={d}\n", .{
        @tagName(command),
        @tagName(outcome),
        elapsed_ms,
    });
}

pub fn exitCodeForFailure(failure: CliFailure) ExitCode {
    return switch (failure) {
        .resolve => |resolve_failure| exitCodeForResolveError(resolve_failure),
        .config => |config_failure| if (config_failure == error.OutOfMemory) .unexpected_failure else .local_configuration_failure,
        .out_of_memory, .unexpected => .unexpected_failure,
    };
}

pub fn exitCodeForResolveError(failure: z_oci.ResolveError) ExitCode {
    return switch (failure) {
        .not_found => .not_found,
        .auth_failed => .authentication_failure,
        .rate_limited => .rate_limited,
        .network_error => .network_failure,
        .digest_mismatch, .unsupported_algorithm => .digest_failure,
        .content_type_mismatch => .content_type_failure,
        .manifest_parse_error, .response_too_large, .depth_limit_exceeded => .manifest_content_failure,
        .timeout => .timeout,
        .platform_not_found, .platform_required => .platform_selection_failure,
    };
}

pub fn failureCode(failure: CliFailure) []const u8 {
    return switch (failure) {
        .resolve => |resolve_failure| resolveFailureCode(resolve_failure),
        .config => |config_failure| configFailureCode(config_failure),
        .out_of_memory => "out_of_memory",
        .unexpected => "unexpected",
    };
}

pub fn verboseOutcomeForFailure(failure: CliFailure) VerboseOutcome {
    return switch (failure) {
        .resolve => |resolve_failure| switch (resolve_failure) {
            .not_found => .not_found,
            .auth_failed => .auth_failed,
            .rate_limited => .rate_limited,
            .network_error => .network_error,
            .digest_mismatch, .unsupported_algorithm => .digest,
            .content_type_mismatch => .content_type,
            .manifest_parse_error, .response_too_large, .depth_limit_exceeded => .manifest_content,
            .timeout => .timeout,
            .platform_not_found, .platform_required => .platform_selection,
        },
        .config => |config_failure| if (config_failure == error.OutOfMemory) .unexpected else .local_config,
        .out_of_memory, .unexpected => .unexpected,
    };
}

fn writeIndexText(
    writer: *std.Io.Writer,
    manifests: []const z_oci.Descriptor,
    kind: []const u8,
    media_type: z_oci.MediaType,
) std.Io.Writer.Error!void {
    try writer.writeAll("  top_level.kind: ");
    try writer.writeAll(kind);
    try writer.writeAll("\n  top_level.media_type: ");
    try writer.writeAll(media_type.toString());
    try writer.writeByte('\n');

    for (manifests, 0..) |descriptor, index| {
        try writer.print("  platform[{d}].platform: ", .{index});
        try writeTextPlatform(writer, descriptor.platform);
        try writer.print("\n  platform[{d}].media_type: {s}\n", .{ index, descriptor.media_type.toString() });
        try writer.print("  platform[{d}].digest: ", .{index});
        try descriptor.digest.format(writer);
        try writer.print("\n  platform[{d}].size: {d}\n", .{ index, descriptor.size });
    }
}

fn writeReference(writer: *std.Io.Writer, reference: z_oci.Reference) std.Io.Writer.Error!void {
    try writer.print("{s}/{s}{s}{s}", .{
        reference.registry,
        reference.repository,
        if (reference.digest != null) "@" else ":",
        reference.refString(),
    });
}

fn writePinnedReference(writer: *std.Io.Writer, reference: z_oci.Reference, digest: z_oci.Digest) std.Io.Writer.Error!void {
    try writer.print("{s}/{s}@", .{ reference.registry, reference.repository });
    try digest.format(writer);
}

fn writeJsonReference(json: *std.json.Stringify, reference: z_oci.Reference) std.Io.Writer.Error!void {
    try json.beginWriteRaw();
    try json.writer.writeByte('"');
    try writeJsonBytes(json.writer, reference.registry);
    try json.writer.writeByte('/');
    try writeJsonBytes(json.writer, reference.repository);
    try json.writer.writeByte(if (reference.digest != null) '@' else ':');
    try writeJsonBytes(json.writer, reference.refString());
    try json.writer.writeByte('"');
    json.endWriteRaw();
}

fn writeJsonPinnedReference(json: *std.json.Stringify, reference: z_oci.Reference, digest: z_oci.Digest) std.Io.Writer.Error!void {
    try json.beginWriteRaw();
    try json.writer.writeByte('"');
    try writeJsonBytes(json.writer, reference.registry);
    try json.writer.writeByte('/');
    try writeJsonBytes(json.writer, reference.repository);
    try json.writer.writeByte('@');
    try json.writer.writeAll(@tagName(digest.algorithm));
    try json.writer.writeByte(':');
    try writeJsonBytes(json.writer, digest.hex);
    try json.writer.writeByte('"');
    json.endWriteRaw();
}

fn writeJsonStringValue(json: *std.json.Stringify, value: []const u8) std.Io.Writer.Error!void {
    try json.beginWriteRaw();
    try json.writer.writeByte('"');
    try writeJsonBytes(json.writer, value);
    try json.writer.writeByte('"');
    json.endWriteRaw();
}

fn writeJsonBytes(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    const hex = "0123456789abcdef";
    for (value) |byte| {
        switch (byte) {
            '"', '\\' => {
                try writer.writeByte('\\');
                try writer.writeByte(byte);
            },
            8 => try writer.writeAll("\\b"),
            12 => try writer.writeAll("\\f"),
            10 => try writer.writeAll("\\n"),
            13 => try writer.writeAll("\\r"),
            9 => try writer.writeAll("\\t"),
            0...7, 11, 14...0x1f, 0x7f => {
                try writer.writeAll("\\u00");
                try writer.writeByte(hex[byte >> 4]);
                try writer.writeByte(hex[byte & 0xf]);
            },
            else => try writer.writeByte(byte),
        }
    }
}

fn writeTextPlatform(writer: *std.Io.Writer, platform: ?Platform) std.Io.Writer.Error!void {
    const value = platform orelse {
        try writer.writeAll("null");
        return;
    };
    try writeTextPlatformPart(writer, value.os);
    try writer.writeAll("\\/");
    try writeTextPlatformPart(writer, value.architecture);
    if (value.variant) |variant| {
        try writer.writeAll("\\/");
        try writeTextPlatformPart(writer, variant);
    }
}

fn writeTextPlatformPart(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    const hex = "0123456789abcdef";
    for (value) |byte| {
        switch (byte) {
            '\\' => try writer.writeAll("\\\\"),
            '/' => try writer.writeAll("\\/"),
            0...0x1f, 0x7f => {
                try writer.writeAll("\\x");
                try writer.writeByte(hex[byte >> 4]);
                try writer.writeByte(hex[byte & 0xf]);
            },
            else => try writer.writeByte(byte),
        }
    }
}

fn writeJsonPlatform(json: *std.json.Stringify, platform: ?Platform) std.Io.Writer.Error!void {
    if (platform) |value| {
        try json.beginObject();
        try json.objectField("os");
        try writeJsonStringValue(json, value.os);
        try json.objectField("architecture");
        try writeJsonStringValue(json, value.architecture);
        try json.objectField("variant");
        try json.write(value.variant);
        try json.objectField("os_version");
        try json.write(value.os_version);
        try json.objectField("os_features");
        try json.write(value.os_features);
        try json.endObject();
    } else {
        try json.write(@as(?[]const u8, null));
    }
}

fn writeJsonInspectionTopLevel(json: *std.json.Stringify, document: z_oci.InspectionDocument) std.Io.Writer.Error!void {
    try json.beginObject();
    switch (document) {
        .manifest => |parsed| {
            try json.objectField("kind");
            try json.write("manifest");
            try json.objectField("media_type");
            try json.write(parsed.value.media_type.toString());
            try json.objectField("config_digest");
            try json.write(@as(?z_oci.Digest, parsed.value.config.digest));
            try json.objectField("layer_count");
            try json.write(@as(?usize, parsed.value.layers.len));
            try json.objectField("platforms");
            try json.write(@as(?[]const u8, null));
        },
        .oci_index => |parsed| {
            try writeJsonIndexTopLevel(json, "oci_image_index", parsed.value.media_type, parsed.value.manifests);
        },
        .docker_manifest_list => |parsed| {
            try writeJsonIndexTopLevel(json, "docker_manifest_list", parsed.value.media_type, parsed.value.manifests);
        },
    }
    try json.endObject();
}

fn writeJsonIndexTopLevel(
    json: *std.json.Stringify,
    kind: []const u8,
    media_type: z_oci.MediaType,
    manifests: []const z_oci.Descriptor,
) std.Io.Writer.Error!void {
    try json.objectField("kind");
    try json.write(kind);
    try json.objectField("media_type");
    try json.write(media_type.toString());
    try json.objectField("config_digest");
    try json.write(@as(?[]const u8, null));
    try json.objectField("layer_count");
    try json.write(@as(?usize, null));
    try json.objectField("platforms");
    try json.beginArray();
    for (manifests) |descriptor| {
        try json.beginObject();
        try json.objectField("platform");
        try writeJsonPlatform(json, descriptor.platform);
        try json.objectField("media_type");
        try json.write(descriptor.media_type.toString());
        try json.objectField("digest");
        try json.write(descriptor.digest);
        try json.objectField("size");
        try json.write(descriptor.size);
        try json.endObject();
    }
    try json.endArray();
}

fn writeJsonSelectedLeaf(
    json: *std.json.Stringify,
    requested_platform: Platform,
    manifest: z_oci.Manifest,
) std.Io.Writer.Error!void {
    try json.beginObject();
    try json.objectField("requested_platform");
    try writeJsonPlatform(json, requested_platform);
    try json.objectField("media_type");
    try json.write(manifest.media_type.toString());
    try json.objectField("config_digest");
    try json.write(manifest.config.digest);
    try json.objectField("layer_count");
    try json.write(manifest.layers.len);
    try json.endObject();
}

fn failureSummary(failure: CliFailure) []const u8 {
    return switch (failure) {
        .resolve => |resolve_failure| resolveFailureSummary(resolve_failure),
        .config => |config_failure| if (config_failure == error.OutOfMemory) "unexpected failure" else "local configuration failure",
        .out_of_memory, .unexpected => "unexpected failure",
    };
}

fn resolveFailureSummary(failure: z_oci.ResolveError) []const u8 {
    return switch (failure) {
        .auth_failed => "authentication failure",
        .not_found => "not found",
        .rate_limited => "rate limited",
        .digest_mismatch, .unsupported_algorithm => "digest failure",
        .platform_not_found, .platform_required => "platform selection failure",
        .manifest_parse_error, .depth_limit_exceeded, .response_too_large => "manifest content failure",
        .network_error => "network failure",
        .content_type_mismatch => "content type failure",
        .timeout => "timeout",
    };
}

fn resolveFailureCode(failure: z_oci.ResolveError) []const u8 {
    return switch (failure) {
        .auth_failed => "auth_failed",
        .not_found => "not_found",
        .rate_limited => "rate_limited",
        .digest_mismatch => "digest_mismatch",
        .platform_not_found => "platform_not_found",
        .platform_required => "platform_required",
        .manifest_parse_error => "manifest_parse_error",
        .network_error => "network_error",
        .unsupported_algorithm => "unsupported_algorithm",
        .content_type_mismatch => "content_type_mismatch",
        .timeout => "timeout",
        .depth_limit_exceeded => "depth_limit_exceeded",
        .response_too_large => "response_too_large",
    };
}

fn configFailureCode(failure: z_oci.Config.ApplyError) []const u8 {
    return switch (failure) {
        error.OutOfMemory => "out_of_memory",
        error.CaBundleFileNotFound => "ca_bundle_file_not_found",
        error.CaBundleInvalid => "ca_bundle_invalid",
        error.CaBundleEmpty => "ca_bundle_empty",
        error.CaBundleTlsDisabled => "ca_bundle_tls_disabled",
        error.CaBundleInsecurePermissions => "ca_bundle_insecure_permissions",
        error.CaBundleContainsPrivateKey => "ca_bundle_contains_private_key",
        error.InvalidDockerConfig => "invalid_docker_config",
        error.CredentialSourcesIncomplete => "credential_sources_incomplete",
    };
}

fn resolveFailureRegistry(failure: z_oci.ResolveError) []const u8 {
    return switch (failure) {
        inline else => |value| value.registry,
    };
}

fn resolveFailureReference(failure: z_oci.ResolveError) []const u8 {
    return switch (failure) {
        inline else => |value| value.reference,
    };
}

fn resolveFailureHttpStatus(failure: z_oci.ResolveError) ?u16 {
    return switch (failure) {
        inline else => |value| value.http_status,
    };
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
            try std.testing.expectEqualStrings("ubuntu:22.04", command.input);
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
    try expectUsage(&.{ "z-oci", "validate", "ubuntu@sha512:" ++ ("a" ** 64) }, .invalid_reference, .validate);
    try expectUsage(&.{ "z-oci", "validate", "ubuntu@sha256:" ++ ("a" ** 63) }, .invalid_reference, .validate);
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

const renderer_hex_a = "a" ** 64;
const renderer_hex_b = "b" ** 64;
const renderer_manifest_json =
    "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"sha256:" ++ renderer_hex_a ++ "\",\"size\":256},\"layers\":[{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"sha256:" ++ renderer_hex_b ++ "\",\"size\":4096}]}";
const renderer_index_json =
    "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[" ++
    "{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:" ++ renderer_hex_a ++ "\",\"size\":512,\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\",\"variant\":\"v3\",\"os.version\":\"6.1\",\"os.features\":[\"feature-a\"]}}," ++
    "{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:" ++ renderer_hex_b ++ "\",\"size\":1024,\"platform\":{\"os\":\"linux\",\"architecture\":\"arm64\"}}," ++
    "{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:" ++ renderer_hex_a ++ "\",\"size\":2048,\"platform\":null}]}";
const renderer_control_index_json =
    "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:" ++ renderer_hex_a ++ "\",\"size\":512,\"platform\":{\"os\":\"li\\u0001n\",\"architecture\":\"amd64\",\"variant\":\"v/\\\\\\u007f\",\"os.version\":\"6.1\",\"os.features\":[\"feature-a\"]}}]}";

fn makeRendererResolveResult() !z_oci.ResolveResult {
    var reference = try z_oci.Reference.parse(std.testing.allocator, "ubuntu:22.04");
    errdefer reference.deinit(std.testing.allocator);
    const digest_hex = try std.testing.allocator.dupe(u8, renderer_hex_a);
    errdefer std.testing.allocator.free(digest_hex);
    return .{
        .digest = .{ .algorithm = .sha256, .hex = digest_hex },
        .media_type = .oci_manifest_v1,
        .platform = null,
        .reference = reference,
    };
}

fn rendererResolveFailure(tag: std.meta.Tag(z_oci.ResolveError)) z_oci.ResolveError {
    return switch (tag) {
        .auth_failed => .{ .auth_failed = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = 401 } },
        .not_found => .{ .not_found = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = 404 } },
        .rate_limited => .{ .rate_limited = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = 429, .transport_retries_exhausted = true } },
        .digest_mismatch => .{ .digest_mismatch = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = 200 } },
        .platform_not_found => .{ .platform_not_found = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = null } },
        .platform_required => .{ .platform_required = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = null } },
        .manifest_parse_error => .{ .manifest_parse_error = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = 200 } },
        .network_error => .{ .network_error = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = null, .transport_retries_exhausted = true } },
        .unsupported_algorithm => .{ .unsupported_algorithm = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = null } },
        .content_type_mismatch => .{ .content_type_mismatch = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = 200 } },
        .timeout => .{ .timeout = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = null, .transport_retries_exhausted = true } },
        .depth_limit_exceeded => .{ .depth_limit_exceeded = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = null } },
        .response_too_large => .{ .response_too_large = .{ .registry = "registry.example", .reference = "registry.example/app:v1", .http_status = null } },
    };
}

fn expectJsonObjectKeys(value: std.json.Value, expected: []const []const u8) !void {
    const object = switch (value) {
        .object => |object| object,
        else => return error.ExpectedJsonObject,
    };
    try std.testing.expectEqual(expected.len, object.count());
    for (expected) |key| try std.testing.expect(object.get(key) != null);
}

fn expectFailureJsonCode(failure: CliFailure, expected_code: []const u8) !void {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeFailureJson(&writer, failure);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buffer[0..writer.end], .{});
    defer parsed.deinit();
    try expectJsonObjectKeys(parsed.value, &.{"error"});
    const error_object = parsed.value.object.get("error").?.object;
    try expectJsonObjectKeys(.{ .object = error_object }, &.{ "code", "message", "http_status" });
    try std.testing.expectEqualStrings(expected_code, error_object.get("code").?.string);
}

test "render: text snapshots cover resolve, validate, and inspection presence rules" {
    var resolve_result = try makeRendererResolveResult();
    defer resolve_result.deinit(std.testing.allocator);

    var resolve_buffer: [256]u8 = undefined;
    var resolve_writer = std.Io.Writer.fixed(&resolve_buffer);
    try writeResolveText(&resolve_writer, resolve_result);
    try std.testing.expectEqualStrings(
        "registry-1.docker.io/library/ubuntu@sha256:" ++ renderer_hex_a ++ "\n",
        resolve_buffer[0..resolve_writer.end],
    );

    var validate_buffer: [128]u8 = undefined;
    var validate_writer = std.Io.Writer.fixed(&validate_buffer);
    try writeValidateText(&validate_writer, true);
    try std.testing.expectEqualStrings("validate success: valid\n", validate_buffer[0..validate_writer.end]);
    validate_writer = std.Io.Writer.fixed(&validate_buffer);
    try writeValidateText(&validate_writer, false);
    try std.testing.expectEqualStrings("validate not found: not-found\n", validate_buffer[0..validate_writer.end]);

    var reference = try z_oci.Reference.parse(std.testing.allocator, "ubuntu:22.04");
    defer reference.deinit(std.testing.allocator);
    const manifest = try z_oci.json.parse(z_oci.Manifest, std.testing.allocator, renderer_manifest_json);
    var single_arch = z_oci.InspectionResult{ .top_level = .{ .manifest = manifest } };
    defer single_arch.deinit();

    var inspect_buffer: [4096]u8 = undefined;
    var inspect_writer = std.Io.Writer.fixed(&inspect_buffer);
    try writeInspectText(&inspect_writer, reference, null, single_arch);
    try std.testing.expectEqualStrings(
        "inspect:\n" ++
            "  reference: registry-1.docker.io/library/ubuntu:22.04\n" ++
            "  top_level.kind: manifest\n" ++
            "  top_level.media_type: application/vnd.oci.image.manifest.v1+json\n" ++
            "  top_level.config_digest: sha256:" ++ renderer_hex_a ++ "\n" ++
            "  top_level.layers.count: 1\n",
        inspect_buffer[0..inspect_writer.end],
    );

    const index = try z_oci.json.parse(z_oci.OciImageIndex, std.testing.allocator, renderer_index_json);
    const leaf = try z_oci.json.parse(z_oci.Manifest, std.testing.allocator, renderer_manifest_json);
    var multi_arch = z_oci.InspectionResult{
        .top_level = .{ .oci_index = index },
        .selected_leaf = leaf,
    };
    defer multi_arch.deinit();
    inspect_writer = std.Io.Writer.fixed(&inspect_buffer);
    try writeInspectText(&inspect_writer, reference, .{ .os = "linux", .architecture = "amd64", .variant = "v3" }, multi_arch);
    try std.testing.expectEqualStrings(
        "inspect:\n" ++
            "  reference: registry-1.docker.io/library/ubuntu:22.04\n" ++
            "  top_level.kind: oci_image_index\n" ++
            "  top_level.media_type: application/vnd.oci.image.index.v1+json\n" ++
            "  platform[0].platform: linux\\/amd64\\/v3\n" ++
            "  platform[0].media_type: application/vnd.oci.image.manifest.v1+json\n" ++
            "  platform[0].digest: sha256:" ++ renderer_hex_a ++ "\n" ++
            "  platform[0].size: 512\n" ++
            "  platform[1].platform: linux\\/arm64\n" ++
            "  platform[1].media_type: application/vnd.oci.image.manifest.v1+json\n" ++
            "  platform[1].digest: sha256:" ++ renderer_hex_b ++ "\n" ++
            "  platform[1].size: 1024\n" ++
            "  platform[2].platform: null\n" ++
            "  platform[2].media_type: application/vnd.oci.image.manifest.v1+json\n" ++
            "  platform[2].digest: sha256:" ++ renderer_hex_a ++ "\n" ++
            "  platform[2].size: 2048\n" ++
            "  selected.requested_platform: linux\\/amd64\\/v3\n" ++
            "  selected.media_type: application/vnd.oci.image.manifest.v1+json\n" ++
            "  selected.config_digest: sha256:" ++ renderer_hex_a ++ "\n" ++
            "  selected.layers.count: 1\n",
        inspect_buffer[0..inspect_writer.end],
    );

    const control_index = try z_oci.json.parse(z_oci.OciImageIndex, std.testing.allocator, renderer_control_index_json);
    var control_inspection = z_oci.InspectionResult{ .top_level = .{ .oci_index = control_index } };
    defer control_inspection.deinit();
    inspect_writer = std.Io.Writer.fixed(&inspect_buffer);
    try writeInspectText(&inspect_writer, reference, null, control_inspection);
    const escaped_platform = "li\\x01n" ++ "\\/" ++ "amd64" ++ "\\/" ++ "v" ++ "\\/" ++ "\\\\" ++ "\\x7f";
    try std.testing.expect(std.mem.indexOf(u8, inspect_buffer[0..inspect_writer.end], "  platform[0].platform: " ++ escaped_platform ++ "\n") != null);
}

test "render: JSON snapshots preserve exact fields, nulls, and platform details" {
    var resolve_result = try makeRendererResolveResult();
    defer resolve_result.deinit(std.testing.allocator);
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeResolveJson(&writer, "ubuntu:22.04", resolve_result);
    try std.testing.expectEqualStrings(
        "{\"command\":\"resolve\",\"input\":\"ubuntu:22.04\",\"reference\":\"registry-1.docker.io/library/ubuntu@sha256:" ++ renderer_hex_a ++ "\",\"digest\":\"sha256:" ++ renderer_hex_a ++ "\",\"media_type\":\"application/vnd.oci.image.manifest.v1+json\",\"platform\":null}",
        buffer[0..writer.end],
    );
    const resolve_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buffer[0..writer.end], .{ .parse_numbers = true });
    defer resolve_json.deinit();
    try expectJsonObjectKeys(resolve_json.value, &.{ "command", "input", "reference", "digest", "media_type", "platform" });
    try std.testing.expectEqualStrings("resolve", resolve_json.value.object.get("command").?.string);
    try std.testing.expect(resolve_json.value.object.get("platform").? == .null);

    var reference = try z_oci.Reference.parse(std.testing.allocator, "ubuntu@sha256:" ++ renderer_hex_a);
    defer reference.deinit(std.testing.allocator);
    writer = std.Io.Writer.fixed(&buffer);
    try writeValidateJson(&writer, reference, false);
    try std.testing.expectEqualStrings(
        "{\"command\":\"validate\",\"reference\":\"registry-1.docker.io/library/ubuntu@sha256:" ++ renderer_hex_a ++ "\",\"valid\":false}",
        buffer[0..writer.end],
    );

    const index = try z_oci.json.parse(z_oci.OciImageIndex, std.testing.allocator, renderer_control_index_json);
    var inspection = z_oci.InspectionResult{ .top_level = .{ .oci_index = index } };
    defer inspection.deinit();
    writer = std.Io.Writer.fixed(&buffer);
    try writeInspectJson(&writer, reference, null, inspection);
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..writer.end], "\\u0001") != null);
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..writer.end], "os_version") != null);
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..writer.end], "os_features") != null);
    const inspect_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buffer[0..writer.end], .{ .parse_numbers = true });
    defer inspect_json.deinit();
    try expectJsonObjectKeys(inspect_json.value, &.{ "command", "reference", "top_level", "selected_leaf" });
    const top_level = inspect_json.value.object.get("top_level").?.object;
    try expectJsonObjectKeys(.{ .object = top_level }, &.{ "kind", "media_type", "config_digest", "layer_count", "platforms" });
    try std.testing.expect((top_level.get("config_digest").? == .null));
    try std.testing.expect((top_level.get("layer_count").? == .null));
    try std.testing.expect(top_level.get("platforms").?.array.items.len == 1);
    const platform = top_level.get("platforms").?.array.items[0].object.get("platform").?.object;
    try expectJsonObjectKeys(.{ .object = platform }, &.{ "os", "architecture", "variant", "os_version", "os_features" });
    try std.testing.expectEqualStrings("li\x01n", platform.get("os").?.string);
    try std.testing.expect(platform.get("os_features").?.array.items.len == 1);
    try std.testing.expect((inspect_json.value.object.get("selected_leaf").? == .null));
}

test "render: resolver and process failures map exhaustively" {
    const cases = [_]struct {
        tag: std.meta.Tag(z_oci.ResolveError),
        code: []const u8,
        exit_code: ExitCode,
        verbose: VerboseOutcome,
    }{
        .{ .tag = .auth_failed, .code = "auth_failed", .exit_code = .authentication_failure, .verbose = .auth_failed },
        .{ .tag = .not_found, .code = "not_found", .exit_code = .not_found, .verbose = .not_found },
        .{ .tag = .rate_limited, .code = "rate_limited", .exit_code = .rate_limited, .verbose = .rate_limited },
        .{ .tag = .digest_mismatch, .code = "digest_mismatch", .exit_code = .digest_failure, .verbose = .digest },
        .{ .tag = .platform_not_found, .code = "platform_not_found", .exit_code = .platform_selection_failure, .verbose = .platform_selection },
        .{ .tag = .platform_required, .code = "platform_required", .exit_code = .platform_selection_failure, .verbose = .platform_selection },
        .{ .tag = .manifest_parse_error, .code = "manifest_parse_error", .exit_code = .manifest_content_failure, .verbose = .manifest_content },
        .{ .tag = .network_error, .code = "network_error", .exit_code = .network_failure, .verbose = .network_error },
        .{ .tag = .unsupported_algorithm, .code = "unsupported_algorithm", .exit_code = .digest_failure, .verbose = .digest },
        .{ .tag = .content_type_mismatch, .code = "content_type_mismatch", .exit_code = .content_type_failure, .verbose = .content_type },
        .{ .tag = .timeout, .code = "timeout", .exit_code = .timeout, .verbose = .timeout },
        .{ .tag = .depth_limit_exceeded, .code = "depth_limit_exceeded", .exit_code = .manifest_content_failure, .verbose = .manifest_content },
        .{ .tag = .response_too_large, .code = "response_too_large", .exit_code = .manifest_content_failure, .verbose = .manifest_content },
    };
    for (cases) |case| {
        const failure = CliFailure{ .resolve = rendererResolveFailure(case.tag) };
        try std.testing.expectEqual(case.exit_code, exitCodeForFailure(failure));
        try std.testing.expectEqualStrings(case.code, failureCode(failure));
        try std.testing.expectEqual(case.verbose, verboseOutcomeForFailure(failure));
        try expectFailureJsonCode(failure, case.code);
    }

    const config_cases = [_]struct {
        value: z_oci.Config.ApplyError,
        code: []const u8,
        exit_code: ExitCode,
        verbose: VerboseOutcome,
    }{
        .{ .value = error.OutOfMemory, .code = "out_of_memory", .exit_code = .unexpected_failure, .verbose = .unexpected },
        .{ .value = error.CaBundleFileNotFound, .code = "ca_bundle_file_not_found", .exit_code = .local_configuration_failure, .verbose = .local_config },
        .{ .value = error.CaBundleInvalid, .code = "ca_bundle_invalid", .exit_code = .local_configuration_failure, .verbose = .local_config },
        .{ .value = error.CaBundleEmpty, .code = "ca_bundle_empty", .exit_code = .local_configuration_failure, .verbose = .local_config },
        .{ .value = error.CaBundleTlsDisabled, .code = "ca_bundle_tls_disabled", .exit_code = .local_configuration_failure, .verbose = .local_config },
        .{ .value = error.CaBundleInsecurePermissions, .code = "ca_bundle_insecure_permissions", .exit_code = .local_configuration_failure, .verbose = .local_config },
        .{ .value = error.CaBundleContainsPrivateKey, .code = "ca_bundle_contains_private_key", .exit_code = .local_configuration_failure, .verbose = .local_config },
        .{ .value = error.InvalidDockerConfig, .code = "invalid_docker_config", .exit_code = .local_configuration_failure, .verbose = .local_config },
        .{ .value = error.CredentialSourcesIncomplete, .code = "credential_sources_incomplete", .exit_code = .local_configuration_failure, .verbose = .local_config },
    };
    for (config_cases) |case| {
        const failure = CliFailure{ .config = case.value };
        try std.testing.expectEqual(case.exit_code, exitCodeForFailure(failure));
        try std.testing.expectEqualStrings(case.code, failureCode(failure));
        try std.testing.expectEqual(case.verbose, verboseOutcomeForFailure(failure));
        try expectFailureJsonCode(failure, case.code);
    }

    try expectFailureJsonCode(.{ .out_of_memory = {} }, "out_of_memory");
    try expectFailureJsonCode(.{ .unexpected = {} }, "unexpected");

    const all_exit_codes = [_]ExitCode{
        .success,
        .not_found,
        .authentication_failure,
        .rate_limited,
        .network_failure,
        .usage_failure,
        .local_configuration_failure,
        .digest_failure,
        .content_type_failure,
        .manifest_content_failure,
        .timeout,
        .platform_selection_failure,
        .unexpected_failure,
    };
    for (all_exit_codes, 0..) |code, index| try std.testing.expectEqual(@as(u8, @intCast(index)), @intFromEnum(code));
}

test "render: diagnostics use fixed safe context" {
    const failure = CliFailure{ .resolve = .{ .auth_failed = .{
        .registry = "registry.example",
        .reference = "registry.example/app:v1",
        .http_status = 401,
    } } };
    var text_buffer: [512]u8 = undefined;
    var text_writer = std.Io.Writer.fixed(&text_buffer);
    try writeFailureText(&text_writer, failure);
    try std.testing.expectEqualStrings(
        "z-oci: error: authentication failure (code=2) [registry=registry.example] [reference=registry.example/app:v1] [http_status=401]\n",
        text_buffer[0..text_writer.end],
    );

    var json_buffer: [512]u8 = undefined;
    var json_writer = std.Io.Writer.fixed(&json_buffer);
    try writeFailureJson(&json_writer, failure);
    try std.testing.expectEqualStrings(
        "{\"error\":{\"code\":\"auth_failed\",\"message\":\"authentication failure\",\"http_status\":401}}",
        json_buffer[0..json_writer.end],
    );
    text_writer = std.Io.Writer.fixed(&text_buffer);
    try writeFailureText(&text_writer, .{ .config = error.CaBundleInvalid });
    try std.testing.expectEqualStrings("z-oci: error: local configuration failure (code=6)\n", text_buffer[0..text_writer.end]);
    text_writer = std.Io.Writer.fixed(&text_buffer);
    try writeFailureText(&text_writer, .{ .unexpected = {} });
    try std.testing.expectEqualStrings("z-oci: error: unexpected failure (code=12)\n", text_buffer[0..text_writer.end]);
    json_writer = std.Io.Writer.fixed(&json_buffer);
    try writeFailureJson(&json_writer, .{ .out_of_memory = {} });
    try std.testing.expectEqualStrings(
        "{\"error\":{\"code\":\"out_of_memory\",\"message\":\"unexpected failure\",\"http_status\":null}}",
        json_buffer[0..json_writer.end],
    );
}

test "render: verbose lines use the locked timing grammar" {
    var buffer: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeVerbose(&writer, .resolve, .success, 0);
    try std.testing.expectEqualStrings("z-oci verbose: command=resolve outcome=success elapsed_ms=0\n", buffer[0..writer.end]);
    writer = std.Io.Writer.fixed(&buffer);
    try writeVerbose(&writer, .inspect, .manifest_content, 37);
    try std.testing.expectEqualStrings("z-oci verbose: command=inspect outcome=manifest_content elapsed_ms=37\n", buffer[0..writer.end]);
}
