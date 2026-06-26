//! Build-time guard: reject private-key PEM blocks in tracked repo material.
//!
//! This tool is not linked into the z-oci library. It scans the working tree
//! during `zig build security-check` / `zig build test` only.
const std = @import("std");

const private_key_markers = [_][]const u8{
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
};

const scan_roots = [_][]const u8{
    "fixtures",
    "src",
    "examples",
    "benchmarks",
};

const scan_extensions = [_][]const u8{
    ".pem",
    ".key",
    ".crt",
};

const max_scan_bytes: u64 = 10 * 1024 * 1024;
const stack_buf_size = 128 * 1024;
const chunk_size = 8192;

const max_marker_len = blk: {
    var longest: usize = 0;
    for (private_key_markers) |marker| longest = @max(longest, marker.len);
    break :blk longest;
};

const marker_overlap = max_marker_len - 1;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var failures: usize = 0;

    for (scan_roots) |root| {
        var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer dir.close(io);

        var walker = try dir.walk(gpa);
        defer walker.deinit();

        while (try walker.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (!shouldScan(entry.basename)) continue;
            if (try scanFile(io, entry.dir, entry.basename)) {
                std.log.err("private-key marker in {s}", .{entry.path});
                failures += 1;
            }
        }
    }

    if (failures > 0) {
        std.log.err("found {d} file(s) with private-key PEM markers", .{failures});
        return error.PrivateKeyMaterialFound;
    }
}

fn shouldScan(name: []const u8) bool {
    for (scan_extensions) |ext| {
        if (std.mem.endsWith(u8, name, ext)) return true;
    }
    return false;
}

fn containsPrivateKeyMarker(body: []const u8) bool {
    if (!std.mem.containsAtLeast(u8, body, 1, "BEGIN")) return false;
    inline for (private_key_markers) |marker| {
        if (std.mem.indexOf(u8, body, marker) != null) return true;
    }
    return false;
}

/// Returns `true` when the file must be rejected.
fn scanFile(io: std.Io, dir: std.Io.Dir, name: []const u8) !bool {
    var file = try dir.openFile(io, name, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.size > max_scan_bytes) {
        std.log.err("PEM/key file exceeds scan limit ({d} bytes): {s}", .{ stat.size, name });
        return true;
    }

    if (stat.size == 0) return false;

    const read_len = std.math.cast(usize, stat.size) orelse {
        std.log.err("PEM/key file size overflows usize: {s}", .{name});
        return true;
    };

    if (read_len <= stack_buf_size) {
        var stack_buf: [stack_buf_size]u8 = undefined;
        return try scanFromBuffer(io, &file, stack_buf[0..read_len]);
    }

    return try scanFileStreaming(io, &file);
}

fn scanFromBuffer(io: std.Io, file: *std.Io.File, buf: []u8) !bool {
    var file_reader = file.reader(io, &.{});
    const n = try file_reader.interface.readSliceShort(buf);
    if (n != buf.len) {
        std.log.err("short read while scanning PEM/key file ({d}/{d} bytes)", .{ n, buf.len });
        return true;
    }
    return containsPrivateKeyMarker(buf);
}

fn scanFileStreaming(io: std.Io, file: *std.Io.File) !bool {
    var file_reader = file.reader(io, &.{});
    var carry: [marker_overlap]u8 = undefined;
    var carry_len: usize = 0;

    while (true) {
        var chunk: [chunk_size]u8 = undefined;
        const n = try file_reader.interface.readSliceShort(&chunk);
        if (n == 0) break;

        const body = chunk[0..n];
        if (carry_len > 0) {
            var window: [marker_overlap + chunk_size]u8 = undefined;
            @memcpy(window[0..carry_len], carry[0..carry_len]);
            @memcpy(window[carry_len..][0..body.len], body);
            if (containsPrivateKeyMarker(window[0 .. carry_len + body.len])) return true;
        } else if (containsPrivateKeyMarker(body)) {
            return true;
        }

        if (body.len >= marker_overlap) {
            @memcpy(carry[0..marker_overlap], body[body.len - marker_overlap ..]);
            carry_len = marker_overlap;
        } else {
            const keep = @min(carry_len, marker_overlap - body.len);
            if (keep > 0) {
                std.mem.copyForwards(u8, carry[0..keep], carry[carry_len - keep ..][0..keep]);
            }
            @memcpy(carry[keep..][0..body.len], body);
            carry_len = keep + body.len;
        }
    }

    return carry_len > 0 and containsPrivateKeyMarker(carry[0..carry_len]);
}

test "containsPrivateKeyMarker rejects certificate-only PEM" {
    const cert_only =
        \\-----BEGIN CERTIFICATE-----
        \\Zm9v
        \\-----END CERTIFICATE-----
    ;
    try std.testing.expect(!containsPrivateKeyMarker(cert_only));
}

test "containsPrivateKeyMarker detects private key markers" {
    inline for (private_key_markers) |marker| {
        try std.testing.expect(containsPrivateKeyMarker(marker));
    }
}

test "shouldScan matches expected extensions only" {
    try std.testing.expect(shouldScan("enterprise-test-ca.pem"));
    try std.testing.expect(shouldScan("tls.key"));
    try std.testing.expect(!shouldScan("manifest.json"));
    try std.testing.expect(!shouldScan("notapem"));
}

test "streaming overlap window catches split marker" {
    const marker = private_key_markers[1];
    const split_at = 11;
    var carry: [marker_overlap]u8 = undefined;
    @memcpy(carry[0..split_at], marker[0..split_at]);
    const carry_len = split_at;
    const rest = marker[split_at..];

    var window: [marker_overlap + chunk_size]u8 = undefined;
    @memcpy(window[0..carry_len], carry[0..carry_len]);
    @memcpy(window[carry_len..][0..rest.len], rest);
    try std.testing.expect(containsPrivateKeyMarker(window[0 .. carry_len + rest.len]));
}
