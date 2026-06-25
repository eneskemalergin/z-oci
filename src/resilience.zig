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

pub const ResilienceParseError = error{
    InvalidRateLimitHeader,
    InvalidRetryAfterHeader,
    InvalidHttpDate,
};

/// Numeric `Retry-After` values at or above this are treated as Unix epoch
/// seconds. Docker Hub sends epoch timestamps in `Retry-After` instead of a
/// delay in seconds.
const retry_after_unix_epoch_threshold: u64 = 1_000_000_000;

const epoch = std.time.epoch;

/// Parse registry pull rate-limit headers (`RateLimit-*`).
///
/// Returns `.source == .none` when no registry rate-limit headers are present.
pub fn parseRegistryRateLimitHeaders(headers: []const HttpHeader) ResilienceParseError!RateLimitInfo {
    const limit_raw = findHeaderValue(headers, "RateLimit-Limit");
    const remaining_raw = findHeaderValue(headers, "RateLimit-Remaining");
    const reset_raw = findHeaderValue(headers, "RateLimit-Reset");

    if (limit_raw == null and remaining_raw == null and reset_raw == null) {
        return .{};
    }

    var info: RateLimitInfo = .{ .source = .registry_rate_limit };

    if (limit_raw) |raw| {
        const parsed = try parseRegistryRateLimitQuantity(raw);
        info.limit = parsed.limit;
        if (info.window_seconds == null) info.window_seconds = parsed.window_seconds;
    }

    if (remaining_raw) |raw| {
        const parsed = try parseRegistryRateLimitQuantity(raw);
        info.remaining = parsed.limit;
        if (info.window_seconds == null) info.window_seconds = parsed.window_seconds;
    }

    if (reset_raw) |raw| {
        info.reset_unix_seconds = try parseU64Decimal(raw, ResilienceParseError.InvalidRateLimitHeader);
    }

    return info;
}

/// Parse API rate-limit headers (`X-RateLimit-*`).
///
/// Returns `.source == .none` when no API rate-limit headers are present.
pub fn parseApiRateLimitHeaders(headers: []const HttpHeader) ResilienceParseError!RateLimitInfo {
    const limit_raw = findHeaderValue(headers, "X-RateLimit-Limit");
    const remaining_raw = findHeaderValue(headers, "X-RateLimit-Remaining");
    const reset_raw = findHeaderValue(headers, "X-RateLimit-Reset");

    if (limit_raw == null and remaining_raw == null and reset_raw == null) {
        return .{};
    }

    var info: RateLimitInfo = .{ .source = .api_x_rate_limit };

    if (limit_raw) |raw| info.limit = try parseU32Decimal(raw, ResilienceParseError.InvalidRateLimitHeader);
    if (remaining_raw) |raw| info.remaining = try parseU32Decimal(raw, ResilienceParseError.InvalidRateLimitHeader);
    if (reset_raw) |raw| info.reset_unix_seconds = try parseU64Decimal(raw, ResilienceParseError.InvalidRateLimitHeader);

    return info;
}

/// Parse rate-limit headers, preferring registry `RateLimit-*` over API
/// `X-RateLimit-*` when both families are present.
pub fn parseRateLimitHeaders(headers: []const HttpHeader) ResilienceParseError!RateLimitInfo {
    const registry = try parseRegistryRateLimitHeaders(headers);
    if (registry.isSet()) return registry;
    return parseApiRateLimitHeaders(headers);
}

/// Parse `Retry-After` or `X-Retry-After` when either header is present.
///
/// Returns `null` when neither header exists. `response_date_unix_seconds` is
/// optional context for callers that already parsed the response `Date` header.
pub fn parseRetryAfterFromHeaders(
    headers: []const HttpHeader,
    response_date_unix_seconds: ?i64,
) ResilienceParseError!?RetryAfter {
    _ = response_date_unix_seconds;

    if (findHeaderValue(headers, "Retry-After")) |raw| {
        return try parseRetryAfterValue(raw);
    }
    if (findHeaderValue(headers, "X-Retry-After")) |raw| {
        return try parseRetryAfterValue(raw);
    }
    return null;
}

pub fn parseRetryAfterValue(raw: []const u8) ResilienceParseError!RetryAfter {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidRetryAfterHeader;

    if (looksLikeHttpDate(trimmed)) {
        return .{ .retry_at_unix_seconds = try parseImfFixdateHttpDate(trimmed) };
    }

    const digits_only = allAsciiDigits(trimmed);
    if (!digits_only) return error.InvalidRetryAfterHeader;

    const parsed = std.fmt.parseInt(u64, trimmed, 10) catch return error.InvalidRetryAfterHeader;
    if (parsed >= retry_after_unix_epoch_threshold) {
        return .{ .retry_at_unix_seconds = @intCast(parsed) };
    }

    if (parsed > std.math.maxInt(u32)) return error.InvalidRetryAfterHeader;
    return .{ .delay_seconds = @intCast(parsed) };
}

const RegistryRateLimitQuantity = struct {
    limit: u32,
    window_seconds: ?u32 = null,
};

fn parseRegistryRateLimitQuantity(raw: []const u8) ResilienceParseError!RegistryRateLimitQuantity {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidRateLimitHeader;

    const semicolon = std.mem.indexOfScalar(u8, trimmed, ';') orelse {
        return .{ .limit = try parseU32Decimal(trimmed, ResilienceParseError.InvalidRateLimitHeader) };
    };

    const limit_part = std.mem.trim(u8, trimmed[0..semicolon], " \t\r\n");
    const param_part = std.mem.trim(u8, trimmed[semicolon + 1 ..], " \t\r\n");

    var quantity = RegistryRateLimitQuantity{
        .limit = try parseU32Decimal(limit_part, ResilienceParseError.InvalidRateLimitHeader),
    };

    if (std.mem.startsWith(u8, param_part, "w=")) {
        quantity.window_seconds = try parseU32Decimal(
            std.mem.trim(u8, param_part[2..], " \t\r\n"),
            ResilienceParseError.InvalidRateLimitHeader,
        );
    }

    return quantity;
}

fn parseU32Decimal(raw: []const u8, invalid: ResilienceParseError) ResilienceParseError!u32 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return invalid;
    return std.fmt.parseInt(u32, trimmed, 10) catch invalid;
}

fn parseU64Decimal(raw: []const u8, invalid: ResilienceParseError) ResilienceParseError!u64 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return invalid;
    return std.fmt.parseInt(u64, trimmed, 10) catch invalid;
}

fn allAsciiDigits(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

fn looksLikeHttpDate(value: []const u8) bool {
    return std.mem.indexOfScalar(u8, value, ',') != null and std.mem.indexOfScalar(u8, value, ':') != null;
}

fn parseImfFixdateHttpDate(raw: []const u8) ResilienceParseError!i64 {
    var value = std.mem.trim(u8, raw, " \t\r\n");
    if (value.len < 20) return error.InvalidHttpDate;

    if (std.ascii.eqlIgnoreCase(value[value.len - 3 ..], "GMT")) {
        value = std.mem.trim(u8, value[0 .. value.len - 3], " \t\r\n");
    } else {
        return error.InvalidHttpDate;
    }

    const comma = std.mem.indexOfScalar(u8, value, ',') orelse return error.InvalidHttpDate;
    const rest = std.mem.trim(u8, value[comma + 1 ..], " \t\r\n");

    var parts = std.mem.splitScalar(u8, rest, ' ');
    var part_count: usize = 0;
    var day: u5 = 0;
    var month: epoch.Month = undefined;
    var year: u16 = 0;
    var hour: u5 = 0;
    var minute: u6 = 0;
    var second: u6 = 0;

    while (parts.next()) |part| {
        const token = std.mem.trim(u8, part, " \t\r\n");
        if (token.len == 0) continue;
        part_count += 1;
        switch (part_count) {
            1 => day = std.fmt.parseInt(u5, token, 10) catch return error.InvalidHttpDate,
            2 => month = parseHttpMonthAbbrev(token) orelse return error.InvalidHttpDate,
            3 => year = std.fmt.parseInt(u16, token, 10) catch return error.InvalidHttpDate,
            4 => {
                const colon1 = std.mem.indexOfScalar(u8, token, ':') orelse return error.InvalidHttpDate;
                const colon2 = std.mem.indexOfScalar(u8, token[colon1 + 1 ..], ':') orelse return error.InvalidHttpDate;
                const hour_part = token[0..colon1];
                const minute_part = token[colon1 + 1 .. colon1 + 1 + colon2];
                const second_part = token[colon1 + 1 + colon2 + 1 ..];
                hour = std.fmt.parseInt(u5, hour_part, 10) catch return error.InvalidHttpDate;
                minute = std.fmt.parseInt(u6, minute_part, 10) catch return error.InvalidHttpDate;
                second = std.fmt.parseInt(u6, second_part, 10) catch return error.InvalidHttpDate;
            },
            else => return error.InvalidHttpDate,
        }
    }

    if (part_count != 4) return error.InvalidHttpDate;
    if (day == 0 or day > 31 or hour > 23 or minute > 59 or second > 59) return error.InvalidHttpDate;

    return unixSecondsFromUtc(.{
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
    });
}

const UtcDateTime = struct {
    year: u16,
    month: epoch.Month,
    day: u5,
    hour: u5,
    minute: u6,
    second: u6,
};

fn unixSecondsFromUtc(date_time: UtcDateTime) ResilienceParseError!i64 {
    if (date_time.year < epoch.epoch_year) return error.InvalidHttpDate;

    var days: u64 = 0;
    var year: u16 = epoch.epoch_year;
    while (year < date_time.year) : (year += 1) {
        days += epoch.getDaysInYear(year);
    }

    var month_index: u4 = 1;
    while (month_index < date_time.month.numeric()) : (month_index += 1) {
        const month = @as(epoch.Month, @enumFromInt(month_index));
        days += epoch.getDaysInMonth(date_time.year, month);
    }

    days += date_time.day - 1;

    const seconds = days * epoch.secs_per_day +
        @as(u64, date_time.hour) * 3600 +
        @as(u64, date_time.minute) * 60 +
        @as(u64, date_time.second);

    return @intCast(seconds);
}

fn parseHttpMonthAbbrev(token: []const u8) ?epoch.Month {
    if (token.len < 3) return null;
    const abbrev = token[0..3];
    if (std.ascii.eqlIgnoreCase(abbrev, "Jan")) return .jan;
    if (std.ascii.eqlIgnoreCase(abbrev, "Feb")) return .feb;
    if (std.ascii.eqlIgnoreCase(abbrev, "Mar")) return .mar;
    if (std.ascii.eqlIgnoreCase(abbrev, "Apr")) return .apr;
    if (std.ascii.eqlIgnoreCase(abbrev, "May")) return .may;
    if (std.ascii.eqlIgnoreCase(abbrev, "Jun")) return .jun;
    if (std.ascii.eqlIgnoreCase(abbrev, "Jul")) return .jul;
    if (std.ascii.eqlIgnoreCase(abbrev, "Aug")) return .aug;
    if (std.ascii.eqlIgnoreCase(abbrev, "Sep")) return .sep;
    if (std.ascii.eqlIgnoreCase(abbrev, "Oct")) return .oct;
    if (std.ascii.eqlIgnoreCase(abbrev, "Nov")) return .nov;
    if (std.ascii.eqlIgnoreCase(abbrev, "Dec")) return .dec;
    return null;
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

test "parseRegistryRateLimitHeaders parses docker registry pull headers with window" {
    const headers = [_]HttpHeader{
        .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
        .{ .name = "RateLimit-Remaining", .value = "87;w=21600" },
    };

    const info = try parseRegistryRateLimitHeaders(&headers);
    try std.testing.expect(info.isSet());
    try std.testing.expectEqual(RateLimitInfo.Source.registry_rate_limit, info.source);
    try std.testing.expectEqual(@as(u32, 100), info.limit.?);
    try std.testing.expectEqual(@as(u32, 87), info.remaining.?);
    try std.testing.expectEqual(@as(u32, 21600), info.window_seconds.?);
}

test "parseApiRateLimitHeaders parses docker hub API x-ratelimit headers" {
    const headers = [_]HttpHeader{
        .{ .name = "X-RateLimit-Limit", .value = "180" },
        .{ .name = "X-RateLimit-Remaining", .value = "0" },
        .{ .name = "X-RateLimit-Reset", .value = "1746136938" },
    };

    const info = try parseApiRateLimitHeaders(&headers);
    try std.testing.expectEqual(RateLimitInfo.Source.api_x_rate_limit, info.source);
    try std.testing.expectEqual(@as(u32, 180), info.limit.?);
    try std.testing.expectEqual(@as(u32, 0), info.remaining.?);
    try std.testing.expectEqual(@as(u64, 1_746_136_938), info.reset_unix_seconds.?);
}

test "parseRateLimitHeaders prefers registry headers over API headers" {
    const headers = [_]HttpHeader{
        .{ .name = "RateLimit-Remaining", .value = "12" },
        .{ .name = "X-RateLimit-Remaining", .value = "0" },
    };

    const info = try parseRateLimitHeaders(&headers);
    try std.testing.expectEqual(RateLimitInfo.Source.registry_rate_limit, info.source);
    try std.testing.expectEqual(@as(u32, 12), info.remaining.?);
}

test "parseRateLimitHeaders returns unset info when no rate-limit headers exist" {
    const headers = [_]HttpHeader{
        .{ .name = "Content-Type", .value = "application/json" },
    };

    const info = try parseRateLimitHeaders(&headers);
    try std.testing.expect(!info.isSet());
}

test "parseRetryAfterValue treats small integers as delay seconds" {
    const parsed = try parseRetryAfterValue("120");
    try std.testing.expectEqual(@as(u32, 120), parsed.delay_seconds);
}

test "parseRetryAfterValue treats docker hub epoch values as absolute retry time" {
    const parsed = try parseRetryAfterValue("1746136938");
    try std.testing.expectEqual(@as(i64, 1_746_136_938), parsed.retry_at_unix_seconds);
}

test "parseRetryAfterValue parses IMF-fixdate HTTP-date values" {
    const parsed = try parseRetryAfterValue("Thu, 01 May 2025 22:02:18 GMT");
    try std.testing.expectEqual(@as(i64, 1_746_136_938), parsed.retry_at_unix_seconds);
}

test "parseRetryAfterFromHeaders prefers Retry-After over X-Retry-After" {
    const headers = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "X-Retry-After", .value = "99" },
    };

    const parsed = (try parseRetryAfterFromHeaders(&headers, null)).?;
    try std.testing.expectEqual(@as(u32, 30), parsed.delay_seconds);
}

test "parseRetryAfterFromHeaders falls back to X-Retry-After" {
    const headers = [_]HttpHeader{
        .{ .name = "X-Retry-After", .value = "45" },
    };

    const parsed = (try parseRetryAfterFromHeaders(&headers, null)).?;
    try std.testing.expectEqual(@as(u32, 45), parsed.delay_seconds);
}

test "parseRetryAfterFromHeaders returns null when retry headers are absent" {
    const headers = [_]HttpHeader{
        .{ .name = "Content-Type", .value = "application/json" },
    };

    try std.testing.expect(try parseRetryAfterFromHeaders(&headers, null) == null);
}

test "rate-limit and retry-after parsers reject malformed header values" {
    const bad_registry = [_]HttpHeader{
        .{ .name = "RateLimit-Limit", .value = "not-a-number" },
    };
    try std.testing.expectError(error.InvalidRateLimitHeader, parseRegistryRateLimitHeaders(&bad_registry));

    const bad_api = [_]HttpHeader{
        .{ .name = "X-RateLimit-Remaining", .value = "" },
    };
    try std.testing.expectError(error.InvalidRateLimitHeader, parseApiRateLimitHeaders(&bad_api));

    try std.testing.expectError(error.InvalidRetryAfterHeader, parseRetryAfterValue(""));
    try std.testing.expectError(error.InvalidRetryAfterHeader, parseRetryAfterValue("soon"));
    try std.testing.expectError(error.InvalidHttpDate, parseRetryAfterValue("Thu, 99 Foo 2025 99:99:99 GMT"));
}

test "rate-limit header fragments parse deterministically across table cases" {
    const cases = [_]struct {
        headers: []const HttpHeader,
        expected_source: RateLimitInfo.Source,
        expected_remaining: ?u32,
    }{
        .{
            .headers = &.{
                .{ .name = "ratelimit-remaining", .value = "5" },
            },
            .expected_source = .registry_rate_limit,
            .expected_remaining = 5,
        },
        .{
            .headers = &.{
                .{ .name = "x-ratelimit-remaining", .value = "1" },
            },
            .expected_source = .api_x_rate_limit,
            .expected_remaining = 1,
        },
        .{
            .headers = &.{
                .{ .name = "RateLimit-Limit", .value = "200;w=3600" },
            },
            .expected_source = .registry_rate_limit,
            .expected_remaining = null,
        },
    };

    for (cases) |case| {
        const info = try parseRateLimitHeaders(case.headers);
        try std.testing.expectEqual(case.expected_source, info.source);
        try std.testing.expectEqual(case.expected_remaining, info.remaining);
    }
}
