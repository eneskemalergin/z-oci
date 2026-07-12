//! Testing-only cleartext rewrite for loopback registry hosts.
//!
//! Production URL builders stay `https://`. Live HTTP exchangers call
//! `cleartextLoopbackUrlAlloc` so in-process mocks and local `registry:2` can
//! speak plain HTTP on `127.0.0.1` / `localhost` / `::1` without a public
//! Config switch.
//!
//! Only `localhost`, `127.0.0.1`, and `::1` match `isLoopbackHost`. No suffix forms
//! (`*.localhost`), no other RFC1918/link-local ranges, and no public registry hostnames
//! are rewritten. Widening this list would expose bearer traffic on cleartext HTTP and
//! must not ship without an explicit product decision.

const std = @import("std");

/// True only for `localhost`, `127.0.0.1`, and `::1` (not `*.localhost` or other loopback ranges).
pub fn isLoopbackHost(host: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    if (std.mem.eql(u8, host, "127.0.0.1")) return true;
    if (std.mem.eql(u8, host, "::1")) return true;
    return false;
}

/// Host only: strips `:port` and `[...]` so loopback checks ignore the authority form.
pub fn authorityHost(authority: []const u8) ?[]const u8 {
    if (authority.len == 0) return null;
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return null;
        if (close < 1) return null;
        return authority[1..close];
    }
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        const maybe_port = authority[colon + 1 ..];
        if (maybe_port.len > 0 and isAllDigits(maybe_port)) {
            return authority[0..colon];
        }
    }
    return authority;
}

/// When `url` is `https://` to a loopback host, returns an owned `http://` URL.
/// Otherwise returns null (caller keeps using `url` unchanged).
pub fn cleartextLoopbackUrlAlloc(allocator: std.mem.Allocator, url: []const u8) error{OutOfMemory}!?[]u8 {
    const https_prefix = "https://";
    if (!std.mem.startsWith(u8, url, https_prefix)) return null;
    const rest = url[https_prefix.len..];
    const authority_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..authority_end];
    const host = authorityHost(authority) orelse return null;
    if (!isLoopbackHost(host)) return null;
    return try std.fmt.allocPrint(allocator, "http://{s}", .{rest});
}

fn isAllDigits(bytes: []const u8) bool {
    for (bytes) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

test "isLoopbackHost: localhost ipv4 ipv6 only" {
    try std.testing.expect(isLoopbackHost("localhost"));
    try std.testing.expect(isLoopbackHost("LOCALHOST"));
    try std.testing.expect(isLoopbackHost("127.0.0.1"));
    try std.testing.expect(isLoopbackHost("::1"));
    try std.testing.expect(!isLoopbackHost("registry-1.docker.io"));
    try std.testing.expect(!isLoopbackHost("ghcr.io"));
    try std.testing.expect(!isLoopbackHost("127.0.0.2"));
    try std.testing.expect(!isLoopbackHost("0.0.0.0"));
    try std.testing.expect(!isLoopbackHost("10.0.0.1"));
    try std.testing.expect(!isLoopbackHost("example.localhost"));
}

test "authorityHost: host port and bracketed ipv6" {
    try std.testing.expectEqualStrings("localhost", authorityHost("localhost").?);
    try std.testing.expectEqualStrings("localhost", authorityHost("localhost:5000").?);
    try std.testing.expectEqualStrings("127.0.0.1", authorityHost("127.0.0.1:1234").?);
    try std.testing.expectEqualStrings("::1", authorityHost("[::1]").?);
    try std.testing.expectEqualStrings("::1", authorityHost("[::1]:5000").?);
}

test "cleartextLoopbackUrlAlloc: rewrites loopback https only" {
    const alloc = std.testing.allocator;

    const rewritten = try cleartextLoopbackUrlAlloc(alloc, "https://127.0.0.1:9/v2/library/alpine/manifests/latest");
    defer alloc.free(rewritten.?);
    try std.testing.expectEqualStrings("http://127.0.0.1:9/v2/library/alpine/manifests/latest", rewritten.?);

    const localhost = try cleartextLoopbackUrlAlloc(alloc, "https://localhost/v2/");
    defer alloc.free(localhost.?);
    try std.testing.expectEqualStrings("http://localhost/v2/", localhost.?);

    try std.testing.expect(try cleartextLoopbackUrlAlloc(alloc, "https://ghcr.io/v2/") == null);
    try std.testing.expect(try cleartextLoopbackUrlAlloc(alloc, "https://registry-1.docker.io/v2/") == null);
    try std.testing.expect(try cleartextLoopbackUrlAlloc(alloc, "https://10.0.0.1:5000/v2/") == null);
    try std.testing.expect(try cleartextLoopbackUrlAlloc(alloc, "http://127.0.0.1/v2/") == null);
}
