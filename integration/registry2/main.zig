//! Opt-in registry:2 interoperability checks against a local Distribution peer.
//!
//! Expects loopback cleartext rewrite in live exchangers. Invoked by
//! `integration/registry2/run.sh` after the registry is up and an image is loaded.
//! Not part of `zig build test`.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(arena);

    var stderr_buffer: [2048]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(init.io, &stderr_buffer);
    defer stderr_writer.end() catch {};
    const stderr = &stderr_writer.interface;

    var stdout_buffer: [2048]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};
    const stdout = &stdout_writer.interface;

    if (args.len != 3) {
        try stderr.writeAll("usage: registry2-harness <tag-ref> <missing-tag-ref>\n");
        return error.InvalidArguments;
    }

    const tag_ref_str = args[1];
    const missing_ref_str = args[2];

    var client = std.http.Client{
        .allocator = gpa,
        .io = init.io,
    };
    defer client.deinit();

    const config = z_oci.Config{};

    var tag_ref = try z_oci.Reference.parse(gpa, tag_ref_str);
    const tag_outcome = blk: {
        errdefer tag_ref.deinit(gpa);
        break :blk try z_oci.resolve(gpa, &client, config, tag_ref, null);
    };
    const tag_result = switch (tag_outcome) {
        .success => |result| result,
        .failure => |failure| {
            try stderr.print("resolve(tag) failed: {s}\n", .{@tagName(failure)});
            z_oci.deinitResolveFailure(failure, gpa);
            tag_ref.deinit(gpa);
            return error.ResolveTagFailed;
        },
    };
    defer {
        var owned = tag_result;
        owned.deinit(gpa);
    }

    var digest_buf: [80]u8 = undefined;
    const digest_str = try std.fmt.bufPrint(&digest_buf, "{f}", .{tag_result.digest});
    try stdout.print("resolve(tag): ok digest={s} mediaType={s}\n", .{
        digest_str,
        tag_result.media_type.toString(),
    });

    // Digest-addressed resolve must match the tag pin (registry compat proof).
    var digest_ref_buf: [256]u8 = undefined;
    const digest_ref_str = try std.fmt.bufPrint(&digest_ref_buf, "{s}/{s}@{s}", .{
        tag_result.reference.registry,
        tag_result.reference.repository,
        digest_str,
    });
    var digest_ref = try z_oci.Reference.parse(gpa, digest_ref_str);
    const digest_outcome = blk: {
        errdefer digest_ref.deinit(gpa);
        break :blk try z_oci.resolve(gpa, &client, config, digest_ref, null);
    };
    const digest_result = switch (digest_outcome) {
        .success => |result| result,
        .failure => |failure| {
            try stderr.print("resolve(digest) failed: {s}\n", .{@tagName(failure)});
            z_oci.deinitResolveFailure(failure, gpa);
            digest_ref.deinit(gpa);
            return error.ResolveDigestFailed;
        },
    };
    defer {
        var owned = digest_result;
        owned.deinit(gpa);
    }

    var digest2_buf: [80]u8 = undefined;
    const digest2_str = try std.fmt.bufPrint(&digest2_buf, "{f}", .{digest_result.digest});
    if (!std.mem.eql(u8, digest_str, digest2_str)) {
        try stderr.print("resolve(digest) mismatch: tag={s} digest={s}\n", .{ digest_str, digest2_str });
        return error.DigestMismatch;
    }
    try stdout.print("resolve(digest): ok digest={s}\n", .{digest2_str});

    // Missing tag must be not_found (not a transport surprise).
    var missing_ref = try z_oci.Reference.parse(gpa, missing_ref_str);
    defer missing_ref.deinit(gpa);
    const validate_outcome = try z_oci.validate(gpa, &client, config, missing_ref, null);
    switch (validate_outcome) {
        .not_found => {},
        .valid => {
            try stderr.writeAll("validate(missing) unexpectedly valid\n");
            return error.UnexpectedValid;
        },
        .failure => |failure| {
            try stderr.print("validate(missing) failed: {s}\n", .{@tagName(failure)});
            z_oci.deinitResolveFailure(failure, gpa);
            return error.ValidateMissingFailed;
        },
    }
    try stdout.writeAll("validate(missing): ok not_found\n");
    try stdout.flush();
}
