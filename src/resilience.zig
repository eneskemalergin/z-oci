//! Resilience helpers: rate-limit metadata, retry classification, reactive
//! retry policy, and transport-policy inputs.
//!
//! Header parsers for `RateLimit-*`, `X-RateLimit-*`, and `Retry-After` live
//! in this module alongside the pure policy helpers resolver and auth transport
//! wrappers share.
//!
//! Bundled Zig 0.16.0 HTTP/TLS notes:
//! - Manifest and token traffic use `std.http.Client.request`; `RequestOptions`
//!   has no per-request read/connect timeout field today.
//! - `ConnectTcpOptions.timeout` exists, but `connectTcpOptions` does not pass
//!   it through to `host.connect` today (zig#31305).
//! - Custom CA trust lives on `std.http.Client.ca_bundle`; `Config.ca_bundle_path`
//!   is not applied automatically on caller-owned clients today.
//!
//! Config field liveness:
//! - Live on transport path: `max_network_retries`, `max_rate_limit_retries`.
//! - Live on helper subprocess only: `read_timeout_ms` (via auth, not this module).
//! - Caller recipe via `Config.connectIoTimeout` / `Config.applyToClient`; live
//!   manifest/token `client.request` paths do not enforce connect timeout (zig#31305).
//! - Stored but not consumed on live transport yet: manifest/token HTTP read
//!   timeouts, `ca_bundle_path`, `rate_limit_enabled` (pre-emptive throttling).
//!
//! Parser liveness:
//! - Live on transport path: `retryAfterFromHeaders` / `parseRetryAfterFromHeaders`
//!   (`Retry-After`, `X-Retry-After`, optional response `Date` anchoring).
//! - Parser-only on live transport: `parseRateLimitHeaders` and the registry/API
//!   rate-limit parsers. Headers are captured on responses but rate-limit snapshots
//!   do not affect retry policy yet.
//!
//! Policy liveness:
//! - Pure policy core: `RetryPolicy`, `decideHttpRetry`, `decideTransportRetry`,
//!   `RetryBackoffConfig` defaults, injected `RetryClock` / `RetryRandomSource`.
//! - Live via transport wrappers: `retryPolicyFromConfig` on manifest HEAD/GET and
//!   token HTTP paths. Wrappers sleep on `RetryDecision.delay_ms` and re-invoke
//!   the inner exchanger.
//! - `TransportHooks` sleep wiring is a transport concern, not part of the pure
//!   policy decision. `retryPolicyFromConfig` only borrows clock/RNG hooks.
//! - `classifyNetworkTransportError` only retries errors the exchanger surfaces.
//!   Opaque `TransportFailed` / `TokenExchangeFailed` stay non-retryable at the
//!   policy layer even when the underlying fault was transient.
//!
//! Retry budgets:
//! - `Config.max_retries` stays auth-only (cached-401 invalidation).
//! - `Config.max_network_retries` and `Config.max_rate_limit_retries` own
//!   transport retry budgets separately.

const std = @import("std");
const Config = @import("Config.zig").Config;
const json = @import("json.zig");

/// Parsed rate-limit snapshot from response headers.
///
/// Populated by the rate-limit header parsers. Transport wrappers do not read
/// this today; pre-emptive throttling would consume `parseRateLimitHeaders`.
/// Callers treat missing fields as "header not provided", not zero.
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

/// Fields that actually drive `RetryBudget` on the live transport path.
///
/// Kept separate from `ResilienceConfigView` so reserved config slots do not
/// look wired into retry policy before their live paths land.
pub const RetryBudgetConfig = struct {
    max_network_retries: u8,
    max_rate_limit_retries: u8,
};

/// Narrow view of `Config` fields reserved for upcoming resilience milestones.
///
/// `resilienceConfigView` projects the full struct for callers that need one
/// snapshot. Only `max_network_retries` and `max_rate_limit_retries` feed
/// `RetryPolicy` today via `retryBudgetConfig`.
pub const ResilienceConfigView = struct {
    /// Connect timeout for caller recipes. `0` means unset. Projected in
    /// `ResilienceConfigView` only; does not feed `RetryPolicy` directly.
    connect_timeout_ms: u32,
    /// Manifest/token HTTP read timeout. Helper subprocess I/O reads
    /// `Config.read_timeout_ms` directly in auth instead of through this view.
    read_timeout_ms: u32,
    /// Live: reactive retry budget for transient `5xx` and socket errors.
    max_network_retries: u8,
    /// Live: reactive retry budget for `429` responses.
    max_rate_limit_retries: u8,
    /// Custom CA bundle path. Not applied by live transport wrappers today.
    ca_bundle_path: ?[]const u8,
    /// Pre-emptive throttling gate. Reactive `429` backoff ignores this today.
    rate_limit_enabled: bool,
};

/// Tracks transport retry attempts against separate budgets.
pub const RetryBudget = struct {
    network_attempts_used: u8 = 0,
    rate_limit_attempts_used: u8 = 0,
    max_network_retries: u8,
    max_rate_limit_retries: u8,

    pub fn init(config: RetryBudgetConfig) RetryBudget {
        return .{
            .max_network_retries = config.max_network_retries,
            .max_rate_limit_retries = config.max_rate_limit_retries,
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

/// Exponential backoff parameters for reactive transport retries.
///
/// Fixed defaults today. `Config` does not tune these yet; callers cannot mistake
/// config fields for backoff control until a future milestone adds them.
pub const RetryBackoffConfig = struct {
    base_delay_ms: u32 = 1_000,
    max_delay_ms: u32 = 30_000,
};

/// Injectable Unix clock for `RetryAfter` math and policy tests.
pub const RetryClock = struct {
    now_unix_seconds: *const fn () i64,
};

/// Injectable jitter source. Transport wrappers pass a real RNG; tests pin values.
pub const RetryRandomSource = *const fn () u64;

/// Outcome of a single reactive retry policy evaluation.
pub const RetryDecision = struct {
    pub const Action = enum {
        retry,
        give_up,
    };

    action: Action,
    kind: RetryKind = .none,
    delay_ms: u32 = 0,
};

/// Pure reactive retry policy shared by manifest and token transport wrappers.
///
/// Evaluates one retry decision at a time. Transport wrappers own the sleep/retry
/// loop; auth cached-401 retry stays on `Config.max_retries` outside this type.
pub const RetryPolicy = struct {
    backoff: RetryBackoffConfig = .{},
    budget: RetryBudget,
    random_u64: RetryRandomSource,
    clock: RetryClock,

    pub fn init(
        policy_config: RetryPolicyConfig,
        random_u64: RetryRandomSource,
        clock: RetryClock,
    ) RetryPolicy {
        return .{
            .backoff = policy_config.backoff,
            .budget = RetryBudget.init(policy_config.budget),
            .random_u64 = random_u64,
            .clock = clock,
        };
    }

    pub fn decideHttpRetry(
        self: *RetryPolicy,
        status: std.http.Status,
        retry_after: ?RetryAfter,
    ) RetryDecision {
        return self.decideRetry(classifyHttpStatus(status), retry_after);
    }

    pub fn decideTransportRetry(self: *RetryPolicy, err: anyerror) RetryDecision {
        return self.decideRetry(classifyNetworkTransportError(err), null);
    }

    fn decideRetry(self: *RetryPolicy, kind: RetryKind, retry_after: ?RetryAfter) RetryDecision {
        switch (kind) {
            .none => return .{ .action = .give_up },
            .rate_limit => {
                if (!self.budget.canRetryRateLimit()) {
                    return .{ .action = .give_up, .kind = kind };
                }
                const delay_ms = computeRateLimitDelayMs(
                    self,
                    retry_after,
                    self.clock.now_unix_seconds(),
                );
                self.budget.recordRateLimitAttempt();
                return .{ .action = .retry, .kind = kind, .delay_ms = delay_ms };
            },
            .network => {
                if (!self.budget.canRetryNetwork()) {
                    return .{ .action = .give_up, .kind = kind };
                }
                const delay_ms = computeNetworkDelayMs(self);
                self.budget.recordNetworkAttempt();
                return .{ .action = .retry, .kind = kind, .delay_ms = delay_ms };
            },
        }
    }
};

/// Inputs that actually drive `RetryPolicy` today.
///
/// `Config` only supplies the budget half via `retryPolicyConfig`. Backoff stays
/// on fixed defaults until a future milestone exposes tuning fields.
pub const RetryPolicyConfig = struct {
    budget: RetryBudgetConfig,
    backoff: RetryBackoffConfig = .{},
};

/// Injectable sleep hook so unit tests avoid real delays.
pub const TransportSleeper = *const fn (delay_ms: u32) void;

/// Hooks transport wrappers inject for clock, jitter, and sleep.
pub const TransportHooks = struct {
    sleeper: TransportSleeper = noopTransportSleeper,
    random_u64: RetryRandomSource = systemRetryRandomU64,
    clock: RetryClock = systemRetryClock,
    /// When true, resolver/auth sleep through `std.http.Client.io` instead of `sleeper`.
    use_live_sleep: bool = false,
};

pub fn noopTransportSleeper(_: u32) void {}

pub fn liveTransportHooks() TransportHooks {
    return .{ .use_live_sleep = true };
}

fn systemNowUnixSeconds() i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

threadlocal var transport_prng_initialized = false;
threadlocal var transport_prng: std.Random.DefaultPrng = undefined;

fn systemRetryRandomU64() u64 {
    if (!transport_prng_initialized) {
        transport_prng = std.Random.DefaultPrng.init(@bitCast(systemNowUnixSeconds()));
        transport_prng_initialized = true;
    }
    return transport_prng.random().int(u64);
}

pub const systemRetryClock: RetryClock = .{ .now_unix_seconds = systemNowUnixSeconds };

pub fn retryPolicyConfig(config: Config) RetryPolicyConfig {
    return .{ .budget = retryBudgetConfig(config) };
}

pub fn retryPolicyFromConfig(config: Config, hooks: TransportHooks) RetryPolicy {
    return RetryPolicy.init(retryPolicyConfig(config), hooks.random_u64, hooks.clock);
}

pub fn sleepForTransportRetry(
    client: *std.http.Client,
    hooks: TransportHooks,
    delay_ms: u32,
) void {
    if (delay_ms == 0) return;
    if (hooks.use_live_sleep) {
        std.Io.Timeout.sleep(.{
            .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(delay_ms),
                .clock = .real,
            },
        }, client.io) catch {
            hooks.sleeper(delay_ms);
        };
        return;
    }
    hooks.sleeper(delay_ms);
}

/// Returns true for rate-limit and retry-after header names the transport layer keeps.
pub fn isTrackedResilienceHeaderName(name: []const u8) bool {
    if (std.mem.startsWith(u8, name, "RateLimit-")) return true;
    if (std.ascii.startsWithIgnoreCase(name, "X-RateLimit-")) return true;
    if (std.ascii.eqlIgnoreCase(name, "Retry-After")) return true;
    if (std.ascii.eqlIgnoreCase(name, "X-Retry-After")) return true;
    if (std.ascii.eqlIgnoreCase(name, "Date")) return true;
    return false;
}

pub fn retryAfterFromHeaders(
    headers: []const HttpHeader,
) ResilienceParseError!?RetryAfter {
    return parseRetryAfterFromHeaders(headers, null);
}

/// Parse the response `Date` header into Unix seconds when present.
pub fn responseDateUnixSecondsFromHeaders(headers: []const HttpHeader) ResilienceParseError!?i64 {
    const raw = findHeaderValue(headers, "Date") orelse return null;
    return try parseImfFixdateHttpDate(std.mem.trim(u8, raw, " \t\r\n"));
}

pub fn deinitOwnedHttpHeaders(allocator: std.mem.Allocator, headers: []HttpHeader) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

pub fn duplicateHttpHeadersAlloc(
    allocator: std.mem.Allocator,
    headers: []const HttpHeader,
) ![]HttpHeader {
    const owned = try allocator.alloc(HttpHeader, headers.len);
    errdefer allocator.free(owned);

    for (headers, 0..) |header, index| {
        owned[index] = .{
            .name = try allocator.dupe(u8, header.name),
            .value = try allocator.dupe(u8, header.value),
        };
    }

    return owned;
}

/// Convert a parsed `Retry-After` value into milliseconds to sleep from `now`.
pub fn retryAfterDelayMs(retry_after: RetryAfter, now_unix_seconds: i64) u32 {
    switch (retry_after) {
        .delay_seconds => |seconds| return seconds * 1000,
        .retry_at_unix_seconds => |retry_at| {
            const delta_seconds = retry_at - now_unix_seconds;
            if (delta_seconds <= 0) return 0;
            const delta_ms = delta_seconds * 1000;
            if (delta_ms > std.math.maxInt(u32)) return std.math.maxInt(u32);
            return @intCast(delta_ms);
        },
    }
}

fn computeRateLimitDelayMs(
    policy: *const RetryPolicy,
    retry_after: ?RetryAfter,
    now_unix_seconds: i64,
) u32 {
    if (retry_after) |header| {
        return retryAfterDelayMs(header, now_unix_seconds);
    }
    return exponentialBackoffDelayMs(
        policy.backoff,
        policy.budget.rate_limit_attempts_used,
        policy.random_u64(),
    );
}

fn computeNetworkDelayMs(policy: *const RetryPolicy) u32 {
    return exponentialBackoffDelayMs(
        policy.backoff,
        policy.budget.network_attempts_used,
        policy.random_u64(),
    );
}

fn exponentialBackoffDelayMs(
    config: RetryBackoffConfig,
    attempt_index: u8,
    random_u64: u64,
) u32 {
    const shift: u4 = @intCast(@min(attempt_index, 15));
    const multiplier: u32 = @as(u32, 1) << shift;
    const uncapped = config.base_delay_ms *% multiplier;
    const capped = @min(uncapped, config.max_delay_ms);
    if (capped == 0) return 0;
    return @intCast(random_u64 % (@as(u64, capped) + 1));
}

pub fn retryBudgetConfig(config: Config) RetryBudgetConfig {
    return .{
        .max_network_retries = config.max_network_retries,
        .max_rate_limit_retries = config.max_rate_limit_retries,
    };
}

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
/// Hard auth, parse, and digest failures stay outside this helper. Opaque wrapper
/// errors such as `error.TransportFailed` map to `.none` so policy does not retry
/// faults the exchanger collapsed.
pub fn classifyNetworkTransportError(err: anyerror) RetryKind {
    return switch (err) {
        error.ConnectionResetByPeer,
        error.Timeout,
        error.NetworkUnreachable,
        error.ConnectionRefused,
        error.UnknownHostName,
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
///
/// Parser-only on live transport today. Reactive transport retry uses
/// `retryAfterFromHeaders` instead; captured rate-limit header names on responses
/// are not fed here yet.
pub fn parseRateLimitHeaders(headers: []const HttpHeader) ResilienceParseError!RateLimitInfo {
    const registry = try parseRegistryRateLimitHeaders(headers);
    if (registry.isSet()) return registry;
    return parseApiRateLimitHeaders(headers);
}

/// Parse `Retry-After` or `X-Retry-After` when either header is present.
///
/// Returns `null` when neither header exists. When `response_date_unix_seconds`
/// is null, a captured `Date` header in `headers` anchors integer-second delays
/// per RFC 7231 (seconds after the response time).
pub fn parseRetryAfterFromHeaders(
    headers: []const HttpHeader,
    response_date_unix_seconds: ?i64,
) ResilienceParseError!?RetryAfter {
    const response_date: ?i64 = if (response_date_unix_seconds) |date|
        date
    else
        try responseDateUnixSecondsFromHeaders(headers);

    if (findHeaderValue(headers, "Retry-After")) |raw| {
        return try parseRetryAfterValueWithContext(raw, response_date);
    }
    if (findHeaderValue(headers, "X-Retry-After")) |raw| {
        return try parseRetryAfterValueWithContext(raw, response_date);
    }
    return null;
}

pub fn parseRetryAfterValue(raw: []const u8) ResilienceParseError!RetryAfter {
    return parseRetryAfterValueWithContext(raw, null);
}

fn parseRetryAfterValueWithContext(
    raw: []const u8,
    response_date_unix_seconds: ?i64,
) ResilienceParseError!RetryAfter {
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
    const delay_seconds: u32 = @intCast(parsed);

    if (response_date_unix_seconds) |response_date| {
        return .{ .retry_at_unix_seconds = response_date + @as(i64, delay_seconds) };
    }

    return .{ .delay_seconds = delay_seconds };
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

test "retryBudgetConfig projects only transport retry limits" {
    const config = Config{
        .connect_timeout_ms = 5_000,
        .read_timeout_ms = 60_000,
        .max_retries = 9,
        .max_network_retries = 2,
        .max_rate_limit_retries = 3,
        .ca_bundle_path = "/tmp/custom-ca.pem",
        .rate_limit_enabled = true,
    };

    const budget_config = retryBudgetConfig(config);
    try std.testing.expectEqual(@as(u8, 2), budget_config.max_network_retries);
    try std.testing.expectEqual(@as(u8, 3), budget_config.max_rate_limit_retries);
    try std.testing.expectEqual(@as(u8, 9), config.max_retries);
}

test "resilienceConfigView projects reserved fields without implying they drive RetryPolicy" {
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
    try std.testing.expectEqual(RetryKind.network, classifyNetworkTransportError(error.UnknownHostName));
    try std.testing.expectEqual(RetryKind.none, classifyNetworkTransportError(error.OutOfMemory));
}

test "classifyNetworkTransportError ignores opaque collapsed transport errors" {
    // Manifest/token wrappers often collapse socket failures to a single opaque
    // error before policy sees them. Those stay non-retryable here by design.
    try std.testing.expectEqual(RetryKind.none, classifyNetworkTransportError(error.UnexpectedEndOfInput));
}

test "RetryBudget tracks separate network and rate-limit attempt limits" {
    const budget_config = retryBudgetConfig(.{
        .max_network_retries = 1,
        .max_rate_limit_retries = 2,
    });
    var budget = RetryBudget.init(budget_config);
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

test "parseRegistryRateLimitHeaders parses RateLimit-Reset on registry path" {
    const headers = [_]HttpHeader{
        .{ .name = "RateLimit-Limit", .value = "200" },
        .{ .name = "RateLimit-Remaining", .value = "5" },
        .{ .name = "RateLimit-Reset", .value = "1746136938" },
    };

    const info = try parseRegistryRateLimitHeaders(&headers);
    try std.testing.expectEqual(RateLimitInfo.Source.registry_rate_limit, info.source);
    try std.testing.expectEqual(@as(u32, 200), info.limit.?);
    try std.testing.expectEqual(@as(u32, 5), info.remaining.?);
    try std.testing.expectEqual(@as(u64, 1_746_136_938), info.reset_unix_seconds.?);
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

test "parseRetryAfterFromHeaders anchors integer delays to response Date" {
    const headers = [_]HttpHeader{
        .{ .name = "Date", .value = "Thu, 01 May 2025 22:02:18 GMT" },
        .{ .name = "Retry-After", .value = "60" },
    };

    const parsed = (try parseRetryAfterFromHeaders(&headers, null)).?;
    const response_date = (try responseDateUnixSecondsFromHeaders(&headers)).?;
    try std.testing.expectEqual(
        response_date + 60,
        parsed.retry_at_unix_seconds,
    );
    try std.testing.expectEqual(
        @as(u32, 30_000),
        retryAfterDelayMs(parsed, response_date + 30),
    );
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
        expected_window_seconds: ?u32 = null,
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
            .expected_window_seconds = 3600,
        },
    };

    for (cases) |case| {
        const info = try parseRateLimitHeaders(case.headers);
        try std.testing.expectEqual(case.expected_source, info.source);
        try std.testing.expectEqual(case.expected_remaining, info.remaining);
        if (case.expected_window_seconds) |window| {
            try std.testing.expectEqual(window, info.window_seconds.?);
        }
    }
}

test "parser liveness: transport retry uses retry-after parsers only" {
    const headers = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "RateLimit-Remaining", .value = "0" },
    };

    const retry_after = (try retryAfterFromHeaders(&headers)).?;
    try std.testing.expectEqual(@as(u32, 30), retry_after.delay_seconds);

    const rate_limit = try parseRateLimitHeaders(&headers);
    try std.testing.expect(rate_limit.isSet());
}

const ResilienceHeaderFixture = struct {
    headers: []const struct {
        name: []const u8,
        value: []const u8,
    },
};

test "parseRateLimitHeaders parses checked-in docker hub 429 fixture" {
    var bytes_buffer: [4 * 1024]u8 = undefined;
    const bytes = try std.Io.Dir.cwd().readFile(
        std.testing.io,
        "fixtures/resilience/docker-hub-429-headers.json",
        &bytes_buffer,
    );

    const parsed = try json.parse(ResilienceHeaderFixture, std.testing.allocator, bytes);
    defer parsed.deinit();

    var headers: [8]HttpHeader = undefined;
    try std.testing.expect(parsed.value.headers.len <= headers.len);
    for (parsed.value.headers, 0..) |entry, index| {
        headers[index] = .{ .name = entry.name, .value = entry.value };
    }
    const header_slice = headers[0..parsed.value.headers.len];

    const rate_limit = try parseRateLimitHeaders(header_slice);
    try std.testing.expectEqual(RateLimitInfo.Source.registry_rate_limit, rate_limit.source);
    try std.testing.expectEqual(@as(u32, 100), rate_limit.limit.?);
    try std.testing.expectEqual(@as(u32, 0), rate_limit.remaining.?);
    try std.testing.expectEqual(@as(u64, 1_746_136_938), rate_limit.reset_unix_seconds.?);
    try std.testing.expectEqual(@as(u32, 21_600), rate_limit.window_seconds.?);

    const retry_after = (try parseRetryAfterFromHeaders(header_slice, null)).?;
    const response_date = (try responseDateUnixSecondsFromHeaders(header_slice)).?;
    try std.testing.expectEqual(response_date + 60, retry_after.retry_at_unix_seconds);
}

test "findHeaderValue returns the first match when duplicate headers exist" {
    const headers = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "retry-after", .value = "99" },
    };

    try std.testing.expectEqualStrings("30", findHeaderValue(&headers, "Retry-After").?);
}

test "retryAfterDelayMs converts delay seconds and absolute retry instants" {
    try std.testing.expectEqual(@as(u32, 120_000), retryAfterDelayMs(.{ .delay_seconds = 120 }, 1_700_000_000));
    try std.testing.expectEqual(@as(u32, 45_000), retryAfterDelayMs(.{ .retry_at_unix_seconds = 1_700_000_045 }, 1_700_000_000));
    try std.testing.expectEqual(@as(u32, 0), retryAfterDelayMs(.{ .retry_at_unix_seconds = 1_699_999_999 }, 1_700_000_000));
}

var test_policy_now_unix_seconds: i64 = 1_700_000_000;
var test_policy_random_u64: u64 = 7;

fn testPolicyNowUnixSeconds() i64 {
    return test_policy_now_unix_seconds;
}

fn testPolicyRandomU64() u64 {
    return test_policy_random_u64;
}

fn testRetryPolicy(budget_config: RetryBudgetConfig) RetryPolicy {
    return RetryPolicy.init(.{ .budget = budget_config }, testPolicyRandomU64, .{
        .now_unix_seconds = testPolicyNowUnixSeconds,
    });
}

test "retryPolicyConfig projects only budget fields from Config" {
    const config = Config{
        .max_network_retries = 4,
        .max_rate_limit_retries = 5,
        .connect_timeout_ms = 9_000,
        .rate_limit_enabled = true,
    };

    const policy_config = retryPolicyConfig(config);
    try std.testing.expectEqual(@as(u8, 4), policy_config.budget.max_network_retries);
    try std.testing.expectEqual(@as(u8, 5), policy_config.budget.max_rate_limit_retries);
    try std.testing.expectEqual(@as(u32, 1_000), policy_config.backoff.base_delay_ms);
    try std.testing.expectEqual(@as(u32, 30_000), policy_config.backoff.max_delay_ms);
}

test "retryPolicyFromConfig uses injected clock and random hooks" {
    test_policy_now_unix_seconds = 1_700_000_000;
    test_policy_random_u64 = 0;

    var policy = retryPolicyFromConfig(.{
        .max_rate_limit_retries = 1,
    }, .{
        .clock = .{ .now_unix_seconds = testPolicyNowUnixSeconds },
        .random_u64 = testPolicyRandomU64,
    });

    const decision = policy.decideHttpRetry(.too_many_requests, .{
        .retry_at_unix_seconds = 1_700_000_120,
    });
    try std.testing.expectEqual(RetryDecision.Action.retry, decision.action);
    try std.testing.expectEqual(@as(u32, 120_000), decision.delay_ms);
}

test "RetryPolicy keeps network and rate-limit budgets independent" {
    test_policy_random_u64 = 0;

    var policy = testRetryPolicy(retryBudgetConfig(.{
        .max_network_retries = 1,
        .max_rate_limit_retries = 1,
    }));

    const rate_limited = policy.decideHttpRetry(.too_many_requests, .{ .delay_seconds = 5 });
    try std.testing.expectEqual(RetryDecision.Action.retry, rate_limited.action);
    try std.testing.expectEqual(@as(u8, 1), policy.budget.rate_limit_attempts_used);
    try std.testing.expectEqual(@as(u8, 0), policy.budget.network_attempts_used);

    const gateway = policy.decideHttpRetry(.bad_gateway, null);
    try std.testing.expectEqual(RetryDecision.Action.retry, gateway.action);
    try std.testing.expectEqual(@as(u8, 1), policy.budget.rate_limit_attempts_used);
    try std.testing.expectEqual(@as(u8, 1), policy.budget.network_attempts_used);
}

test "RetryPolicy uses jitter backoff for 429 without Retry-After" {
    test_policy_random_u64 = 999;

    var policy = testRetryPolicy(retryBudgetConfig(.{
        .max_rate_limit_retries = 1,
    }));

    const decision = policy.decideHttpRetry(.too_many_requests, null);
    try std.testing.expectEqual(RetryDecision.Action.retry, decision.action);
    try std.testing.expectEqual(RetryKind.rate_limit, decision.kind);
    try std.testing.expectEqual(@as(u32, 999), decision.delay_ms);
}

test "RetryPolicy classifies 502 and 504 as network retries" {
    var policy = testRetryPolicy(retryBudgetConfig(.{
        .max_network_retries = 2,
    }));

    const bad_gateway = policy.decideHttpRetry(.bad_gateway, null);
    try std.testing.expectEqual(RetryKind.network, bad_gateway.kind);
    try std.testing.expectEqual(RetryDecision.Action.retry, bad_gateway.action);

    const gateway_timeout = policy.decideHttpRetry(.gateway_timeout, null);
    try std.testing.expectEqual(RetryKind.network, gateway_timeout.kind);
    try std.testing.expectEqual(RetryDecision.Action.retry, gateway_timeout.action);

    try std.testing.expectEqual(@as(u8, 2), policy.budget.network_attempts_used);
}

test "RetryPolicy ignores reserved config fields when budgets are built from Config" {
    var tight = testRetryPolicy(retryBudgetConfig(.{
        .max_network_retries = 0,
        .max_rate_limit_retries = 0,
        .rate_limit_enabled = true,
        .connect_timeout_ms = 60_000,
    }));
    var loose = testRetryPolicy(retryBudgetConfig(.{
        .max_network_retries = 2,
        .max_rate_limit_retries = 2,
        .rate_limit_enabled = false,
        .connect_timeout_ms = 0,
    }));

    const tight_decision = tight.decideHttpRetry(.service_unavailable, null);
    try std.testing.expectEqual(RetryDecision.Action.give_up, tight_decision.action);

    const loose_decision = loose.decideHttpRetry(.service_unavailable, null);
    try std.testing.expectEqual(RetryDecision.Action.retry, loose_decision.action);
    _ = loose.decideHttpRetry(.too_many_requests, null);
    try std.testing.expectEqual(@as(u8, 1), loose.budget.rate_limit_attempts_used);
}

test "RetryPolicy retries 429 using Retry-After delay and separate rate-limit budget" {
    test_policy_now_unix_seconds = 1_700_000_000;
    test_policy_random_u64 = 0;

    var policy = testRetryPolicy(retryBudgetConfig(.{
        .max_network_retries = 1,
        .max_rate_limit_retries = 2,
    }));

    const first = policy.decideHttpRetry(.too_many_requests, .{ .delay_seconds = 30 });
    try std.testing.expectEqual(RetryDecision.Action.retry, first.action);
    try std.testing.expectEqual(RetryKind.rate_limit, first.kind);
    try std.testing.expectEqual(@as(u32, 30_000), first.delay_ms);
    try std.testing.expectEqual(@as(u8, 1), policy.budget.rate_limit_attempts_used);
    try std.testing.expectEqual(@as(u8, 0), policy.budget.network_attempts_used);

    const second = policy.decideHttpRetry(.too_many_requests, null);
    try std.testing.expectEqual(RetryDecision.Action.retry, second.action);
    try std.testing.expectEqual(@as(u32, 0), second.delay_ms);
    try std.testing.expectEqual(@as(u8, 2), policy.budget.rate_limit_attempts_used);

    const exhausted = policy.decideHttpRetry(.too_many_requests, null);
    try std.testing.expectEqual(RetryDecision.Action.give_up, exhausted.action);
}

test "RetryPolicy retries transient 5xx and transport errors on the network budget" {
    test_policy_random_u64 = 4;

    var policy = testRetryPolicy(retryBudgetConfig(.{
        .max_network_retries = 2,
        .max_rate_limit_retries = 0,
    }));

    const gateway = policy.decideHttpRetry(.bad_gateway, null);
    try std.testing.expectEqual(RetryDecision.Action.retry, gateway.action);
    try std.testing.expectEqual(RetryKind.network, gateway.kind);
    try std.testing.expectEqual(@as(u32, 4), gateway.delay_ms);
    try std.testing.expectEqual(@as(u8, 1), policy.budget.network_attempts_used);

    const reset = policy.decideTransportRetry(error.ConnectionResetByPeer);
    try std.testing.expectEqual(RetryDecision.Action.retry, reset.action);
    try std.testing.expectEqual(@as(u8, 2), policy.budget.network_attempts_used);

    const exhausted = policy.decideTransportRetry(error.Timeout);
    try std.testing.expectEqual(RetryDecision.Action.give_up, exhausted.action);
}

test "RetryPolicy gives up on non-retryable HTTP statuses and transport errors" {
    var policy = testRetryPolicy(retryBudgetConfig(.{
        .max_network_retries = 3,
        .max_rate_limit_retries = 3,
    }));

    const not_found = policy.decideHttpRetry(.not_found, null);
    try std.testing.expectEqual(RetryDecision.Action.give_up, not_found.action);
    try std.testing.expectEqual(@as(u8, 0), policy.budget.network_attempts_used);
    try std.testing.expectEqual(@as(u8, 0), policy.budget.rate_limit_attempts_used);

    const opaque_transport = policy.decideTransportRetry(error.UnexpectedEndOfInput);
    try std.testing.expectEqual(RetryDecision.Action.give_up, opaque_transport.action);
    try std.testing.expectEqual(@as(u8, 0), policy.budget.network_attempts_used);
}

test "exponential backoff caps delay and applies full jitter deterministically" {
    const delay = exponentialBackoffDelayMs(.{
        .base_delay_ms = 1_000,
        .max_delay_ms = 5_000,
    }, 10, 4_999);
    try std.testing.expectEqual(@as(u32, 4_999), delay);

    const capped = exponentialBackoffDelayMs(.{
        .base_delay_ms = 1_000,
        .max_delay_ms = 2_000,
    }, 3, 1_500);
    try std.testing.expectEqual(@as(u32, 1_500), capped);

    const first_attempt = exponentialBackoffDelayMs(.{}, 0, 0);
    try std.testing.expectEqual(@as(u32, 0), first_attempt);
}

test "sleepForTransportRetry invokes injected sleeper with delay" {
    const State = struct {
        var recorded_ms: u32 = 0;

        fn sleeper(delay_ms: u32) void {
            recorded_ms = delay_ms;
        }
    };

    State.recorded_ms = 0;
    var client: std.http.Client = undefined;
    sleepForTransportRetry(&client, .{ .sleeper = State.sleeper }, 250);
    try std.testing.expectEqual(@as(u32, 250), State.recorded_ms);
}
