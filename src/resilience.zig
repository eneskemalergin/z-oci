//! Resilience helpers: rate-limit metadata, retry classification, and
//! transport-policy inputs.
//!
//! Header parsers for `RateLimit-*`, `X-RateLimit-*`, and `Retry-After` live
//! in this module alongside the pure policy helpers resolver and auth transport
//! wrappers share.
//!
//! Bundled Zig 0.16.0 HTTP/TLS notes:
//! - Manifest traffic uses `std.http.Client.request` with no timeout field on
//!   `RequestOptions`.
//! - Token traffic uses `client.fetch` with no timeout field on `FetchOptions`.
//! - `ConnectTcpOptions.timeout` exists, but `connectTcpOptions` does not pass
//!   it through to `host.connect` today (zig#31305).
//! - Custom CA trust lives on `std.http.Client.ca_bundle`; `Config.ca_bundle_path`
//!   still needs a caller-side apply helper.
//!
//! Retry budgets:
//! - `Config.max_retries` stays auth-only (cached-401 invalidation).
//! - `Config.max_network_retries` and `Config.max_rate_limit_retries` own
//!   transport retry budgets separately.

const std = @import("std");
const Config = @import("Config.zig").Config;

/// Parsed rate-limit snapshot from response headers.
///
/// Populated by the rate-limit header parsers. Callers treat missing fields as
/// "header not provided", not zero.
pub const RateLimitInfo = struct {
    pub const Source = enum {
        none,
        registry_rate_limit,
        api_x_rate_limit,
    };

    source: Source = .none,
    limit: ?u32 = null,
    remaining: ?u32 = null,
    reset_unix_seconds: ?u64 = null,
    window_seconds: ?u32 = null,

    pub fn isSet(self: RateLimitInfo) bool {
        return self.source != .none;
    }
};

/// Parsed retry delay instruction.
///
/// Registries mix seconds, HTTP-date, and (on Docker Hub) Unix timestamps in
/// `Retry-After` / `X-Retry-After`. Store the normalized form, not raw bytes.
pub const RetryAfter = union(enum) {
    delay_seconds: u32,
    retry_at_unix_seconds: i64,
};

/// Which reactive retry bucket a failure belongs to.
pub const RetryKind = enum {
    none,
    rate_limit,
    network,
};

/// Borrowed HTTP header pair for parser tests and live response metadata.
pub const HttpHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Narrow view of `Config` fields that drive transport resilience policy.
///
/// Auth cached-401 retry stays on `Config.max_retries` outside this view so
/// transport policy does not collide with token invalidation.
pub const ResilienceConfigView = struct {
    connect_timeout_ms: u32,
    read_timeout_ms: u32,
    max_network_retries: u8,
    max_rate_limit_retries: u8,
    ca_bundle_path: ?[]const u8,
    /// Gates pre-emptive throttling only. Reactive `429` backoff is independent
    /// of this flag once transport retries are wired.
    rate_limit_enabled: bool,
};

/// Tracks transport retry attempts against separate budgets.
pub const RetryBudget = struct {
    network_attempts_used: u8 = 0,
    rate_limit_attempts_used: u8 = 0,
    max_network_retries: u8,
    max_rate_limit_retries: u8,

    pub fn init(view: ResilienceConfigView) RetryBudget {
        return .{
            .max_network_retries = view.max_network_retries,
            .max_rate_limit_retries = view.max_rate_limit_retries,
        };
    }

    pub fn canRetryNetwork(self: RetryBudget) bool {
        return self.network_attempts_used < self.max_network_retries;
    }

    pub fn canRetryRateLimit(self: RetryBudget) bool {
        return self.rate_limit_attempts_used < self.max_rate_limit_retries;
    }

    pub fn recordNetworkAttempt(self: *RetryBudget) void {
        self.network_attempts_used +%= 1;
    }

    pub fn recordRateLimitAttempt(self: *RetryBudget) void {
        self.rate_limit_attempts_used +%= 1;
    }
};

pub fn resilienceConfigView(config: Config) ResilienceConfigView {
    return .{
        .connect_timeout_ms = config.connect_timeout_ms,
        .read_timeout_ms = config.read_timeout_ms,
        .max_network_retries = config.max_network_retries,
        .max_rate_limit_retries = config.max_rate_limit_retries,
        .ca_bundle_path = config.ca_bundle_path,
        .rate_limit_enabled = config.rate_limit_enabled,
    };
}

/// Case-insensitive header lookup for parser entry points.
pub fn findHeaderValue(headers: []const HttpHeader, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

pub fn classifyHttpStatus(status: std.http.Status) RetryKind {
    return switch (status) {
        .too_many_requests => .rate_limit,
        .bad_gateway, .service_unavailable, .gateway_timeout => .network,
        else => .none,
    };
}

pub fn isRetryableHttpStatus(status: std.http.Status) bool {
    return classifyHttpStatus(status) != .none;
}

/// Classify transient transport failures that may succeed on idempotent retry.
///
/// Hard auth, parse, and digest failures stay outside this helper.
pub fn classifyNetworkTransportError(err: anyerror) RetryKind {
    return switch (err) {
        error.ConnectionResetByPeer,
        error.Timeout,
        error.NetworkUnreachable,
        error.ConnectionRefused,
        => .network,
        else => .none,
    };
}

test {
    std.testing.refAllDecls(@This());
}

test "resilienceConfigView projects transport retry fields and leaves auth max_retries separate" {
    const config = Config{
        .connect_timeout_ms = 5_000,
        .read_timeout_ms = 60_000,
        .max_retries = 9,
        .max_network_retries = 2,
        .max_rate_limit_retries = 3,
        .ca_bundle_path = "/tmp/custom-ca.pem",
        .rate_limit_enabled = false,
    };

    const view = resilienceConfigView(config);

    try std.testing.expectEqual(@as(u32, 5_000), view.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 60_000), view.read_timeout_ms);
    try std.testing.expectEqual(@as(u8, 2), view.max_network_retries);
    try std.testing.expectEqual(@as(u8, 3), view.max_rate_limit_retries);
    try std.testing.expectEqualStrings("/tmp/custom-ca.pem", view.ca_bundle_path.?);
    try std.testing.expect(!view.rate_limit_enabled);
    try std.testing.expectEqual(@as(u8, 9), config.max_retries);
}

test "classifyHttpStatus maps 429 to rate_limit and 5xx gateway errors to network" {
    try std.testing.expectEqual(RetryKind.rate_limit, classifyHttpStatus(.too_many_requests));
    try std.testing.expectEqual(RetryKind.network, classifyHttpStatus(.bad_gateway));
    try std.testing.expectEqual(RetryKind.network, classifyHttpStatus(.service_unavailable));
    try std.testing.expectEqual(RetryKind.network, classifyHttpStatus(.gateway_timeout));
    try std.testing.expectEqual(RetryKind.none, classifyHttpStatus(.not_found));
    try std.testing.expectEqual(RetryKind.none, classifyHttpStatus(.unauthorized));
}

test "classifyNetworkTransportError maps transient socket failures to network" {
    try std.testing.expectEqual(RetryKind.network, classifyNetworkTransportError(error.ConnectionResetByPeer));
    try std.testing.expectEqual(RetryKind.network, classifyNetworkTransportError(error.Timeout));
    try std.testing.expectEqual(RetryKind.none, classifyNetworkTransportError(error.OutOfMemory));
}

test "RetryBudget tracks separate network and rate-limit attempt limits" {
    const view = resilienceConfigView(.{
        .max_network_retries = 1,
        .max_rate_limit_retries = 2,
    });

    var budget = RetryBudget.init(view);
    try std.testing.expect(budget.canRetryNetwork());
    try std.testing.expect(budget.canRetryRateLimit());

    budget.recordNetworkAttempt();
    try std.testing.expect(!budget.canRetryNetwork());
    try std.testing.expect(budget.canRetryRateLimit());

    budget.recordRateLimitAttempt();
    try std.testing.expect(budget.canRetryRateLimit());
    budget.recordRateLimitAttempt();
    try std.testing.expect(!budget.canRetryRateLimit());
}

test "findHeaderValue matches registry rate-limit headers case-insensitively" {
    const headers = [_]HttpHeader{
        .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
        .{ .name = "RateLimit-Remaining", .value = "87" },
        .{ .name = "Docker-Content-Digest", .value = "sha256:abc" },
    };

    try std.testing.expectEqualStrings("100;w=21600", findHeaderValue(&headers, "ratelimit-limit").?);
    try std.testing.expectEqualStrings("87", findHeaderValue(&headers, "RATELIMIT-REMAINING").?);
    try std.testing.expect(findHeaderValue(&headers, "RateLimit-Reset") == null);
}

test "findHeaderValue matches Docker Hub API x-ratelimit headers from fixture bytes" {
    const headers = [_]HttpHeader{
        .{ .name = "x-ratelimit-limit", .value = "180" },
        .{ .name = "x-ratelimit-remaining", .value = "0" },
        .{ .name = "x-ratelimit-reset", .value = "1746136938" },
        .{ .name = "retry-after", .value = "1746136938" },
    };

    try std.testing.expectEqualStrings("180", findHeaderValue(&headers, "X-RateLimit-Limit").?);
    try std.testing.expectEqualStrings("0", findHeaderValue(&headers, "X-RateLimit-Remaining").?);
    try std.testing.expectEqualStrings("1746136938", findHeaderValue(&headers, "Retry-After").?);
}

test "RateLimitInfo defaults to unset source" {
    const info: RateLimitInfo = .{};
    try std.testing.expect(!info.isSet());
    try std.testing.expect(info.limit == null);
    try std.testing.expect(info.remaining == null);
}

test "RetryAfter union stores delay and absolute retry instants separately" {
    const delay: RetryAfter = .{ .delay_seconds = 120 };
    const absolute: RetryAfter = .{ .retry_at_unix_seconds = 1_746_136_938 };

    try std.testing.expectEqual(@as(u32, 120), delay.delay_seconds);
    try std.testing.expectEqual(@as(i64, 1_746_136_938), absolute.retry_at_unix_seconds);
}
