//! Registry `/v2/` connectivity probe.
//!
//! Answers reachable anonymously, reachable with auth required, or unreachable.
//! Does not fetch manifests. Resolve never calls this path.
//!
//! Failures use `RegistryPingFailure` (no image reference). CA preflight stays
//! on the public `PublicApiError` surface in `root.zig`.
//!
//! Classification locks (status-only probe; Distribution API header not required):
//! - `200` maps to `reachable_anonymous`
//! - `401` maps to `reachable_auth_required`
//! - `403` and other statuses map to `unexpected_status` (not auth-required)
//! - Redirects are unhandled by the live ping exchanger

const std = @import("std");
const resilience = @import("resilience.zig");
const testing_loopback = @import("testing_loopback.zig");

pub const RegistryPingStatus = enum {
    reachable_anonymous,
    reachable_auth_required,
};

pub const RegistryPingFailureKind = enum {
    network,
    timeout,
    tls,
    unexpected_status,
    other,
};

pub const RegistryPingFailure = struct {
    http_status: ?u16 = null,
    kind: RegistryPingFailureKind,
};

pub const RegistryPingResult = union(enum) {
    ok: RegistryPingStatus,
    failure: RegistryPingFailure,
};

pub const PingExchangeError = error{
    OutOfMemory,
    Timeout,
    ConnectionResetByPeer,
    NetworkUnreachable,
    ConnectionRefused,
    UnknownHostName,
    TlsFailure,
    TransportFailed,
};

pub const PingHttpRequest = struct {
    url: []u8,

    pub fn deinit(self: PingHttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
    }
};

pub const PingHttpResponse = struct {
    status: std.http.Status,
};

pub const PingHttpExchanger = *const fn (
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: PingHttpRequest,
) PingExchangeError!PingHttpResponse;

pub fn pingRegistryUriAlloc(allocator: std.mem.Allocator, registry: []const u8) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(allocator, "https://{s}/v2/", .{registry});
}

pub fn classifyPingHttpStatus(status: std.http.Status) RegistryPingResult {
    return switch (status) {
        .ok => .{ .ok = .reachable_anonymous },
        .unauthorized => .{ .ok = .reachable_auth_required },
        else => .{ .failure = .{
            .http_status = @intCast(@intFromEnum(status)),
            .kind = .unexpected_status,
        } },
    };
}

pub fn mapPingExchangeError(err: PingExchangeError) RegistryPingFailure {
    return switch (err) {
        error.OutOfMemory => .{ .kind = .other },
        error.Timeout => .{ .kind = .timeout },
        error.TlsFailure => .{ .kind = .tls },
        error.ConnectionResetByPeer,
        error.NetworkUnreachable,
        error.ConnectionRefused,
        error.UnknownHostName,
        error.TransportFailed,
        => .{ .kind = .network },
    };
}

/// Probe `https://{registry}/v2/` through `exchanger`. Caller owns CA setup.
///
/// The probe URL buffer is owned by this function; exchangers must not free
/// `request.url` (borrow only for the duration of the call).
pub fn pingRegistryWithExchanger(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    registry: []const u8,
    exchanger: PingHttpExchanger,
) error{OutOfMemory}!RegistryPingResult {
    if (registry.len == 0) {
        return .{ .failure = .{ .kind = .other } };
    }

    const url = try pingRegistryUriAlloc(allocator, registry);
    defer allocator.free(url);
    const response = exchanger(allocator, client, .{ .url = url }) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return .{ .failure = mapPingExchangeError(err) };
    };
    return classifyPingHttpStatus(response.status);
}

pub fn livePingHttpExchanger(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: PingHttpRequest,
) PingExchangeError!PingHttpResponse {
    const loopback_url = testing_loopback.cleartextLoopbackUrlAlloc(allocator, request.url) catch return error.OutOfMemory;
    defer if (loopback_url) |url| allocator.free(url);
    const request_url = loopback_url orelse request.url;

    const uri = std.Uri.parse(request_url) catch return error.TransportFailed;
    var http_request = client.request(.GET, uri, .{
        .redirect_behavior = .unhandled,
    }) catch |err| return mapLivePingTransportError(err);
    defer http_request.deinit();

    http_request.sendBodiless() catch |err| return mapLivePingTransportError(err);

    var redirect_buffer: [8 * 1024]u8 = undefined;
    var response = http_request.receiveHead(&redirect_buffer) catch |err| return mapLivePingTransportError(err);
    const status = response.head.status;

    // Drain so keep-alive reuse after ping does not see a leftover body.
    const body = resilience.readHttpResponseBodyAlloc(allocator, response.reader(&.{}), 64 * 1024) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BodyTooLarge => return error.TransportFailed,
        else => return mapLivePingTransportError(err),
    };
    allocator.free(body);

    return .{ .status = status };
}

fn mapLivePingTransportError(err: anyerror) PingExchangeError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Timeout => error.Timeout,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.NetworkUnreachable => error.NetworkUnreachable,
        error.ConnectionRefused => error.ConnectionRefused,
        error.UnknownHostName => error.UnknownHostName,
        else => blk: {
            const name = @errorName(err);
            if (std.mem.indexOf(u8, name, "Tls") != null or std.mem.indexOf(u8, name, "Certificate") != null) {
                break :blk error.TlsFailure;
            }
            break :blk error.TransportFailed;
        },
    };
}

test "pingRegistryUriAlloc: builds https /v2/ URL" {
    const url = try pingRegistryUriAlloc(std.testing.allocator, "registry-1.docker.io");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://registry-1.docker.io/v2/", url);
}

test "classifyPingHttpStatus: anonymous, auth required, forbidden, and unexpected" {
    try std.testing.expectEqual(RegistryPingStatus.reachable_anonymous, classifyPingHttpStatus(.ok).ok);
    try std.testing.expectEqual(RegistryPingStatus.reachable_auth_required, classifyPingHttpStatus(.unauthorized).ok);
    const forbidden = classifyPingHttpStatus(.forbidden);
    try std.testing.expectEqual(RegistryPingFailureKind.unexpected_status, forbidden.failure.kind);
    try std.testing.expectEqual(@as(?u16, 403), forbidden.failure.http_status);
    const unexpected = classifyPingHttpStatus(.not_found);
    try std.testing.expectEqual(RegistryPingFailureKind.unexpected_status, unexpected.failure.kind);
    try std.testing.expectEqual(@as(?u16, 404), unexpected.failure.http_status);
}

test "pingRegistryWithExchanger: empty registry maps to other failure" {
    var client: std.http.Client = undefined;
    const result = try pingRegistryWithExchanger(
        std.testing.allocator,
        &client,
        "",
        struct {
            fn exchange(_: std.mem.Allocator, _: *std.http.Client, _: PingHttpRequest) PingExchangeError!PingHttpResponse {
                return error.TransportFailed;
            }
        }.exchange,
    );
    try std.testing.expectEqual(RegistryPingFailureKind.other, result.failure.kind);
}

test "pingRegistryWithExchanger: status and transport matrix" {
    const MockHarness = struct {
        var mode: enum { ok, unauthorized, not_found, timeout, network } = .ok;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: PingHttpRequest) PingExchangeError!PingHttpResponse {
            if (!std.mem.eql(u8, request.url, "https://ghcr.io/v2/")) return error.TransportFailed;
            return switch (mode) {
                .ok => .{ .status = .ok },
                .unauthorized => .{ .status = .unauthorized },
                .not_found => .{ .status = .not_found },
                .timeout => error.Timeout,
                .network => error.ConnectionRefused,
            };
        }
    };

    var client: std.http.Client = undefined;

    MockHarness.mode = .ok;
    try std.testing.expectEqual(
        RegistryPingStatus.reachable_anonymous,
        (try pingRegistryWithExchanger(std.testing.allocator, &client, "ghcr.io", MockHarness.exchange)).ok,
    );

    MockHarness.mode = .unauthorized;
    try std.testing.expectEqual(
        RegistryPingStatus.reachable_auth_required,
        (try pingRegistryWithExchanger(std.testing.allocator, &client, "ghcr.io", MockHarness.exchange)).ok,
    );

    MockHarness.mode = .not_found;
    const unexpected = try pingRegistryWithExchanger(std.testing.allocator, &client, "ghcr.io", MockHarness.exchange);
    try std.testing.expectEqual(RegistryPingFailureKind.unexpected_status, unexpected.failure.kind);
    try std.testing.expectEqual(@as(?u16, 404), unexpected.failure.http_status);

    MockHarness.mode = .timeout;
    try std.testing.expectEqual(
        RegistryPingFailureKind.timeout,
        (try pingRegistryWithExchanger(std.testing.allocator, &client, "ghcr.io", MockHarness.exchange)).failure.kind,
    );

    MockHarness.mode = .network;
    try std.testing.expectEqual(
        RegistryPingFailureKind.network,
        (try pingRegistryWithExchanger(std.testing.allocator, &client, "ghcr.io", MockHarness.exchange)).failure.kind,
    );
}

test "mapPingExchangeError: timeout network tls and other kinds" {
    try std.testing.expectEqual(RegistryPingFailureKind.timeout, mapPingExchangeError(error.Timeout).kind);
    try std.testing.expectEqual(RegistryPingFailureKind.network, mapPingExchangeError(error.ConnectionRefused).kind);
    try std.testing.expectEqual(RegistryPingFailureKind.tls, mapPingExchangeError(error.TlsFailure).kind);
    try std.testing.expectEqual(RegistryPingFailureKind.other, mapPingExchangeError(error.OutOfMemory).kind);
}

test "livePingHttpExchanger: loopback mock peer uses cleartext rewrite" {
    const mock_registry = @import("mock_registry.zig");
    const io = std.testing.io;
    const mock = try mock_registry.MockRegistry.startWithHandler(
        std.testing.allocator,
        io,
        2,
        struct {
            fn handle(_: *mock_registry.MockRegistry, request: *std.http.Server.Request) anyerror!void {
                if (!std.mem.eql(u8, request.head.target, "/v2/") and !std.mem.eql(u8, request.head.target, "/v2")) {
                    try request.respond("not found", .{ .status = .not_found, .keep_alive = false });
                    return;
                }
                try request.respond("{}", .{ .status = .unauthorized, .keep_alive = false });
            }
        }.handle,
        null,
    );
    defer mock.deinit();

    var client: std.http.Client = .{ .allocator = std.testing.allocator, .io = io };
    defer client.deinit();

    const url = try pingRegistryUriAlloc(std.testing.allocator, mock.registry_host);
    defer std.testing.allocator.free(url);

    const response = try livePingHttpExchanger(std.testing.allocator, &client, .{ .url = url });
    try std.testing.expectEqual(std.http.Status.unauthorized, response.status);
}

test "pingRegistryWithExchanger: allocation failures do not leak ping URL" {
    const MockHarness = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, _: PingHttpRequest) PingExchangeError!PingHttpResponse {
            return .{ .status = .ok };
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var client: std.http.Client = undefined;
            _ = try pingRegistryWithExchanger(allocator, &client, "ghcr.io", MockHarness.exchange);
        }
    }.run, .{});
}

test "pingRegistryWithExchanger: propagates exchanger OutOfMemory" {
    const OomHarness = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, _: PingHttpRequest) PingExchangeError!PingHttpResponse {
            return error.OutOfMemory;
        }
    };

    var client: std.http.Client = undefined;
    try std.testing.expectError(
        error.OutOfMemory,
        pingRegistryWithExchanger(std.testing.allocator, &client, "ghcr.io", OomHarness.exchange),
    );
}

test "pingRegistryWithExchanger: exchange error without exchanger deinit does not leak URL" {
    const LeakProbe = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, _: PingHttpRequest) PingExchangeError!PingHttpResponse {
            return error.TransportFailed;
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var client: std.http.Client = undefined;
            const result = try pingRegistryWithExchanger(allocator, &client, "ghcr.io", LeakProbe.exchange);
            try std.testing.expectEqual(RegistryPingFailureKind.network, result.failure.kind);
        }
    }.run, .{});
}

test "livePingHttpExchanger: allocation failures do not leak request URL" {
    const mock_registry = @import("mock_registry.zig");
    const io = std.testing.io;
    const mock = try mock_registry.MockRegistry.startWithHandler(
        std.testing.allocator,
        io,
        4,
        struct {
            fn handle(_: *mock_registry.MockRegistry, request: *std.http.Server.Request) !void {
                try request.respond("{}", .{ .status = .ok, .keep_alive = false });
            }
        }.handle,
        null,
    );
    defer mock.deinit();

    var client: std.http.Client = .{ .allocator = std.testing.allocator, .io = io };
    defer client.deinit();

    const url = try pingRegistryUriAlloc(std.testing.allocator, mock.registry_host);
    defer std.testing.allocator.free(url);

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, ping_url: []const u8, http_client: *std.http.Client) !void {
            const owned = try allocator.dupe(u8, ping_url);
            defer allocator.free(owned);
            _ = try livePingHttpExchanger(allocator, http_client, .{ .url = owned });
        }
    }.run, .{ url, &client });
}

test "livePingHttpExchanger: invalid URL maps to TransportFailed" {
    var client: std.http.Client = undefined;
    const url = try std.testing.allocator.dupe(u8, "not a url");
    defer std.testing.allocator.free(url);
    try std.testing.expectError(
        error.TransportFailed,
        livePingHttpExchanger(std.testing.allocator, &client, .{ .url = url }),
    );
}
