//! Resolve a live image reference to a pinned manifest digest.
//!
//! Uses a bare `Config{}` for anonymous public-registry access. Defaults apply for
//! retry budgets, body-size limits, and TLS trust via the caller-owned
//! `std.http.Client` (OS trust roots on first HTTPS when `ca_bundle_path` is unset).
//! Set `ca_bundle_path`, `credential_provider`, or `rate_limit_enabled` on `Config`
//! when enterprise TLS, auth, or pre-emptive throttling is required.
//!
//! Ownership notes:
//! - CLI args live in `init.arena` (short-lived process).
//! - The input `Reference` is parsed with `init.gpa`. On success, `resolve` moves
//!   `registry` / `repository` / `tag` into the result; do not `ref.deinit` after
//!   success. On failure, `registry` on the error still borrows the input
//!   `Reference`: format/log the failure first, then `deinitOwned` and
//!   `reference.deinit`.
//! - The returned `ResolveResult` (including moved reference fields and digest
//!   buffers) is owned by `init.gpa` and must be `deinit`ed with that allocator.
//! - `std.http.Client` owns connection-pool state and must be deinitialized.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const USAGE_TEXT =
    \\usage: resolve-reference <image-reference> [os/arch[/variant]]
    \\
    \\Examples:
    \\  zig build example-resolve-reference -- ubuntu:22.04
    \\  zig build example-resolve-reference -- ubuntu:22.04 linux/amd64
    \\
;

/// Live resolve example; see file header for `Config` and ownership.
pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
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
        try stderr.writeAll(USAGE_TEXT);
        return error.InvalidArguments;
    }

    const platform = if (args.len == 3)
        try parsePlatformArg(args[2])
    else
        null;

    var reference = try z_oci.Reference.parse(gpa, args[1]);

    var client = std.http.Client{
        .allocator = gpa,
        .io = init.io,
    };
    defer client.deinit();

    // Anonymous defaults: OS TLS trust, retry budgets, and body-size limits from Config{}.
    const outcome = try z_oci.resolve(gpa, &client, z_oci.Config{}, reference, platform);
    switch (outcome) {
        .success => |result| {
            // Success moves reference fields into the result.
            var owned_result = result;
            defer owned_result.deinit(gpa);

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
            // Single-resolve failures borrow `registry` from the input Reference.
            // Format (or copy) before freeing that reference.
            try stderr.print("resolve failed: {f}\n", .{failure});
            failure.deinitOwned(gpa);
            reference.deinit(gpa);
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
