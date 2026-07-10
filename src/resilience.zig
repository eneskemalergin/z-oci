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
//! - Custom CA trust lives on `std.http.Client.ca_bundle`. When `Config.ca_bundle_path`
//!   is set, `Config.applyToClient` loads that PEM file at the public API boundary
//!   (`resolve`, `validate`, `getManifest`). When unset, Zig lazy-scans OS trust.
//!
//! Config field liveness:
//! - Live on transport path: `max_network_retries`, `max_rate_limit_retries`.
//! - Live on helper subprocess only: `read_timeout_ms` (via auth, not this module).
//! - Caller recipe via `Config.connectIoTimeout`; live manifest/token `client.request`
//!   paths do not enforce connect timeout (zig#31305).
//! - Live on public API boundary: `ca_bundle_path` via `Config.applyToClient`.
//! - Live on manifest transport when `rate_limit_enabled`: `ManifestThrottle`
//!   and `parseRateLimitHeaders` for opt-in pre-emptive throttling.
//!
//! Parser liveness:
//! - Live on transport path: `retryAfterFromHeaders` / `parseRetryAfterFromHeaders`
//!   (`Retry-After`, `X-Retry-After`, optional response `Date` anchoring).
//! - Live on manifest transport when pre-emptive mode is enabled: `parseRateLimitHeaders`.
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

/// Last trustworthy registry snapshot is recorded via `ManifestThrottle` when pre-emption is on.
pub const RateLimitInfo = struct {
    /// Registry pull vs API token-bucket header family.
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

    /// False for the empty default snapshot.
    pub fn isSet(self: RateLimitInfo) bool {
        return self.source != .none;
    }
};
/// Normalized delay; registries mix seconds, HTTP-date, and (Docker Hub) Unix timestamps.
///
/// Parser assumptions:
/// - Integer `Retry-After` above `1_000_000_000` is treated as a Unix instant (Docker Hub).
/// - `RateLimit-Reset` / `X-RateLimit-Reset` are Unix epoch seconds when present.
/// - `Retry-After` wins over `X-Retry-After`; integer delays anchor to response `Date` when available.
/// - Pre-emptive throttling trusts complete registry `RateLimit-*` only, not API `X-RateLimit-*` alone.
pub const RetryAfter = union(enum) {
    delay_seconds: u32,
    retry_at_unix_seconds: i64,
};
pub const RetryKind = enum {
    none,
    rate_limit,
    network,
};
/// HTTP header pair. Borrowed on the wire; owned after `duplicateHttpHeadersAlloc`.
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
/// `configView` projects the full struct for callers that need one
/// snapshot. Only `max_network_retries` and `max_rate_limit_retries` feed
/// `RetryPolicy` today via `retryBudgetConfig`.
pub const ResilienceConfigView = struct {
    /// Projected only; does not feed `RetryPolicy`. `0` = unset.
    connect_timeout_ms: u32,
    /// Projected only; helper I/O reads `Config.read_timeout_ms` in auth instead.
    read_timeout_ms: u32,
    /// Live: reactive budget for transient `5xx` / socket errors.
    max_network_retries: u8,
    /// Live: reactive budget for `429`.
    max_rate_limit_retries: u8,
    /// Not applied by live transport wrappers today.
    ca_bundle_path: ?[]const u8,
    /// Opt-in pre-emptive pause on trusted `RateLimit-*` remaining=0; reactive `429` ignores this.
    rate_limit_enabled: bool,
};
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

    /// True after at least one rate-limit retry was recorded (not "budget empty").
    pub fn rateLimitRetriesExhausted(self: RetryBudget) bool {
        return self.rate_limit_attempts_used > 0;
    }

    /// True after at least one network retry was recorded (not "budget empty").
    pub fn networkRetriesExhausted(self: RetryBudget) bool {
        return self.network_attempts_used > 0;
    }
};
/// Fixed defaults; `Config` does not tune backoff yet.
pub const RetryBackoffConfig = struct {
    base_delay_ms: u32 = 1_000,
    max_delay_ms: u32 = 30_000,
};
pub const RetryClock = struct {
    now_unix_seconds: *const fn () i64,
};
pub const RetryRandomSource = *const fn () u64;
pub const RetryDecision = struct {
    pub const Action = enum {
        retry,
        give_up,
    };

    action: Action,
    kind: RetryKind = .none,
    delay_ms: u32 = 0,
};
/// Shared by manifest and token wrappers. Auth cached-401 uses `Config.max_retries` instead.
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
pub const TransportSleeper = *const fn (delay_ms: u32) void;
pub const TransportHooks = struct {
    sleeper: TransportSleeper = noopTransportSleeper,
    random_u64: RetryRandomSource = systemRetryRandomU64,
    clock: RetryClock = SYSTEM_RETRY_CLOCK,
    /// When true, resolver/auth sleep through `std.http.Client.io` instead of `sleeper`.
    use_live_sleep: bool = false,
};
pub fn noopTransportSleeper(_: u32) void {}

pub fn liveTransportHooks() TransportHooks {
    return .{ .use_live_sleep = true };
}
pub const SYSTEM_RETRY_CLOCK: RetryClock = .{ .now_unix_seconds = systemNowUnixSeconds };
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
pub const HttpRetryLoopHooks = struct {
    before_first_attempt: ?*const fn (*anyopaque) void = null,
    after_successful_exchange: ?*const fn (*anyopaque, std.http.Status, []const HttpHeader) void = null,
};
pub fn HttpRetryLoopResult(comptime Response: type, comptime ExchangeError: type) type {
    return union(enum) {
        ok: struct {
            response: Response,
            budget: RetryBudget,
        },
        transport_failed: struct {
            err: ExchangeError,
            budget: RetryBudget,
        },
    };
}
/// Manifest path uses `before_first_attempt` / `after_successful_exchange` for pre-emptive throttling.
pub fn runHttpRetryLoop(
    client: *std.http.Client,
    transport_hooks: TransportHooks,
    policy: *RetryPolicy,
    loop_hooks: HttpRetryLoopHooks,
    comptime ExchangeError: type,
    comptime Response: type,
    exchange_ctx: *anyopaque,
    exchange_once: *const fn (*anyopaque) ExchangeError!Response,
    response_status: *const fn (Response) std.http.Status,
    response_headers: *const fn (Response) []const HttpHeader,
    deinit_response: *const fn (std.mem.Allocator, Response) void,
    allocator: std.mem.Allocator,
) HttpRetryLoopResult(Response, ExchangeError) {
    if (loop_hooks.before_first_attempt) |hook| hook(exchange_ctx);

    while (true) {
        const response = exchange_once(exchange_ctx) catch |err| {
            const decision = policy.decideTransportRetry(err);
            if (decision.action == .give_up) {
                return .{ .transport_failed = .{ .err = err, .budget = policy.budget } };
            }
            sleepForTransportRetry(client, transport_hooks, decision.delay_ms);
            continue;
        };

        if (loop_hooks.after_successful_exchange) |hook| {
            hook(exchange_ctx, response_status(response), response_headers(response));
        }

        const retry_after = retryAfterFromHeaders(response_headers(response)) catch null;
        // Malformed Retry-After headers fall back to exponential backoff instead of failing the exchange.
        const decision = policy.decideHttpRetry(response_status(response), retry_after);
        if (decision.action == .give_up) {
            return .{ .ok = .{ .response = response, .budget = policy.budget } };
        }

        deinit_response(allocator, response);
        sleepForTransportRetry(client, transport_hooks, decision.delay_ms);
    }
}
/// Unlisted headers are dropped early; only retry/throttle metadata is retained.
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
/// Owned copy so retry loops can release the response buffer.
pub fn duplicateHttpHeadersAlloc(
    allocator: std.mem.Allocator,
    headers: []const HttpHeader,
) ![]HttpHeader {
    const owned = try allocator.alloc(HttpHeader, headers.len);
    errdefer allocator.free(owned);

    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
    }

    for (headers, 0..) |header, index| {
        const name = try allocator.dupe(u8, header.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, header.value);
        owned[index] = .{ .name = name, .value = value };
        initialized += 1;
    }

    return owned;
}
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
pub fn retryBudgetConfig(config: Config) RetryBudgetConfig {
    return .{
        .max_network_retries = config.max_network_retries,
        .max_rate_limit_retries = config.max_rate_limit_retries,
    };
}
pub fn configView(config: Config) ResilienceConfigView {
    return .{
        .connect_timeout_ms = config.connect_timeout_ms,
        .read_timeout_ms = config.read_timeout_ms,
        .max_network_retries = config.max_network_retries,
        .max_rate_limit_retries = config.max_rate_limit_retries,
        .ca_bundle_path = config.ca_bundle_path,
        .rate_limit_enabled = config.rate_limit_enabled,
    };
}
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
/// Opaque `TransportFailed` / collapsed wrapper errors map to `.none` (not retried).
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
pub const HttpBodyReadError = error{
    OutOfMemory,
    BodyTooLarge,
} || std.Io.Reader.ShortError;
pub fn readHttpResponseBodyAlloc(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    max_bytes: usize,
) HttpBodyReadError![]u8 {
    return reader.allocRemaining(allocator, .limited(max_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.BodyTooLarge,
        else => |e| return e,
    };
}
pub const ResilienceParseError = error{
    InvalidRateLimitHeader,
    InvalidRetryAfterHeader,
    InvalidHttpDate,
};
// --- Resilience header parsers ---

/// Partial registry sets are kept for logging but fail pre-emptive trust checks.
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
/// Pre-emptive throttling ignores API-only snapshots (not pull-bucket trustworthy).
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
/// Prefers registry `RateLimit-*` over API `X-RateLimit-*` when both are present.
pub fn parseRateLimitHeaders(headers: []const HttpHeader) ResilienceParseError!RateLimitInfo {
    const registry = try parseRegistryRateLimitHeaders(headers);
    if (registry.isSet()) return registry;
    return parseApiRateLimitHeaders(headers);
}
/// Requires registry source plus `limit`, `remaining`, and `RateLimit-Reset`.
pub fn isTrustworthyPreemptiveRateLimit(info: RateLimitInfo) bool {
    if (info.source != .registry_rate_limit) return false;
    if (info.limit == null or info.remaining == null) return false;
    if (info.reset_unix_seconds == null) return false;
    return true;
}
/// `null` when disabled, untrusted, remaining above threshold, or reset already passed.
pub fn preemptiveRateLimitDelayMs(
    rate_limit_enabled: bool,
    info: RateLimitInfo,
    now_unix_seconds: i64,
    remaining_threshold: u32,
) ?u32 {
    if (!rate_limit_enabled) return null;
    if (!isTrustworthyPreemptiveRateLimit(info)) return null;
    if (info.remaining.? > remaining_threshold) return null;

    const reset_at: i64 = @intCast(info.reset_unix_seconds.?);
    const delay = retryAfterDelayMs(.{ .retry_at_unix_seconds = reset_at }, now_unix_seconds);
    if (delay == 0) return null;
    return delay;
}
/// Last trustworthy registry snapshot across HEAD/GET in one operation (`ResolverParams.manifest_throttle`).
pub const ManifestThrottle = struct {
    prior: ?RateLimitInfo = null,

    /// Record trustworthy registry pull headers from the latest manifest response.
    pub fn recordManifestResponseHeaders(self: *ManifestThrottle, headers: []const HttpHeader) void {
        const parsed = parseRateLimitHeaders(headers) catch {
            self.prior = null;
            return;
        };
        if (isTrustworthyPreemptiveRateLimit(parsed)) {
            self.prior = parsed;
        } else {
            self.prior = null;
        }
    }

    /// Sleep before the next manifest request when pre-emptive mode and prior snapshot require it.
    pub fn sleepBeforeManifestRequestIfNeeded(
        self: *const ManifestThrottle,
        config: Config,
        client: *std.http.Client,
        hooks: TransportHooks,
    ) void {
        const prior = self.prior orelse return;
        const delay = preemptiveRateLimitDelayMs(
            config.rate_limit_enabled,
            prior,
            hooks.clock.now_unix_seconds(),
            0,
        ) orelse return;
        sleepForTransportRetry(client, hooks, delay);
    }
};
/// `null` if neither header exists; malformed values are `ResilienceParseError` (wrappers fall back to backoff).
pub fn parseRetryAfterFromHeaders(
    headers: []const HttpHeader,
    response_date_unix_seconds: ?i64,
) ResilienceParseError!?RetryAfter {
    const response_date: ?i64 = if (response_date_unix_seconds) |date|
        date
    else
        try responseDateUnixSecondsFromHeaders(headers);

    if (findHeaderValue(headers, "Retry-After")) |raw| {
        return try parseRetryAfterHeaderValue(raw, response_date);
    }
    if (findHeaderValue(headers, "X-Retry-After")) |raw| {
        return try parseRetryAfterHeaderValue(raw, response_date);
    }
    return null;
}
/// No response `Date` anchoring.
pub fn parseRetryAfterValue(raw: []const u8) ResilienceParseError!RetryAfter {
    return parseRetryAfterHeaderValue(raw, null);
}

// --- Private helpers ---

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
// Numeric `Retry-After` values at or above this are treated as Unix epoch seconds.
const RETRY_AFTER_UNIX_EPOCH_THRESHOLD: u64 = 1_000_000_000;
const epoch = std.time.epoch;
fn parseRetryAfterHeaderValue(
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
    if (parsed >= RETRY_AFTER_UNIX_EPOCH_THRESHOLD) {
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
const ResilienceHeaderFixture = struct {
    headers: []const struct {
        name: []const u8,
        value: []const u8,
    },
};
const MalformedResilienceHeaderFixture = struct {
    cases: []const struct {
        headers: []const struct {
            name: []const u8,
            value: []const u8,
        },
        expected_error: []const u8,
    },
};
var test_policy_now_unix_seconds: i64 = 1_700_000_000;
var test_policy_random_u64: u64 = 7;
const test_http_date = "Thu, 01 May 2025 22:02:18 GMT";
const test_epoch_seconds: i64 = 1_746_136_938;

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
fn testTransportHooks() TransportHooks {
    return .{
        .clock = .{ .now_unix_seconds = testPolicyNowUnixSeconds },
        .random_u64 = testPolicyRandomU64,
    };
}
fn loadResilienceFixture(comptime T: type, path: []const u8, buffer: []u8) !std.json.Parsed(T) {
    const bytes = try std.Io.Dir.cwd().readFile(std.testing.io, path, buffer);
    return json.parse(T, std.testing.allocator, bytes);
}
fn copyFixtureHeaders(entries: anytype, out: []HttpHeader) []const HttpHeader {
    for (entries, 0..) |entry, index| out[index] = .{ .name = entry.name, .value = entry.value };
    return out[0..entries.len];
}
fn runHttpRetryLoopForTest(
    comptime ExchangeError: type,
    comptime Response: type,
    policy_config: Config,
    transport_hooks: TransportHooks,
    exchange_ctx: *anyopaque,
    exchange_once: *const fn (*anyopaque) ExchangeError!Response,
    response_status: *const fn (Response) std.http.Status,
    response_headers: *const fn (Response) []const HttpHeader,
    deinit_response: *const fn (std.mem.Allocator, Response) void,
) HttpRetryLoopResult(Response, ExchangeError) {
    var client: std.http.Client = undefined;
    var policy = retryPolicyFromConfig(policy_config, transport_hooks);
    return runHttpRetryLoop(
        &client,
        transport_hooks,
        &policy,
        .{},
        ExchangeError,
        Response,
        exchange_ctx,
        exchange_once,
        response_status,
        response_headers,
        deinit_response,
        std.testing.allocator,
    );
}

// --- Tests ---

test {
    std.testing.refAllDecls(@This());
}

test "resilience.retryBudgetConfig: maps network and rate-limit retry caps" {
    const config = Config{
        .max_network_retries = 2,
        .max_rate_limit_retries = 3,
    };

    const budget = retryBudgetConfig(config);

    try std.testing.expectEqual(@as(u8, 2), budget.max_network_retries);
    try std.testing.expectEqual(@as(u8, 3), budget.max_rate_limit_retries);
}

test "resilience.configView: exposes transport and CA fields" {
    const config = Config{
        .connect_timeout_ms = 5_000,
        .read_timeout_ms = 60_000,
        .max_retries = 9,
        .ca_bundle_path = "/tmp/custom-ca.pem",
        .rate_limit_enabled = false,
    };

    const view = configView(config);

    try std.testing.expectEqual(@as(u32, 5_000), view.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 60_000), view.read_timeout_ms);
    try std.testing.expectEqualStrings("/tmp/custom-ca.pem", view.ca_bundle_path.?);
    try std.testing.expect(!view.rate_limit_enabled);
}

test "resilience.retryPolicyConfig: maps budget and backoff defaults" {
    const config = Config{
        .max_network_retries = 2,
        .max_rate_limit_retries = 3,
    };

    const policy_config = retryPolicyConfig(config);

    try std.testing.expectEqual(@as(u8, 2), policy_config.budget.max_network_retries);
    try std.testing.expectEqual(@as(u32, 1_000), policy_config.backoff.base_delay_ms);
}

test "RetryPolicy.decideHttpRetry: gives up when budgets are zero" {
    var tight = testRetryPolicy(retryBudgetConfig(.{
        .max_network_retries = 0,
        .max_rate_limit_retries = 0,
        .rate_limit_enabled = true,
        .connect_timeout_ms = 60_000,
    }));

    try std.testing.expectEqual(RetryDecision.Action.give_up, tight.decideHttpRetry(.service_unavailable, null).action);
}

test "classifyHttpStatus: maps HTTP statuses to retry kinds" {
    const http_cases = [_]struct { std.http.Status, RetryKind }{
        .{ .too_many_requests, .rate_limit },
        .{ .bad_gateway, .network },
        .{ .service_unavailable, .network },
        .{ .gateway_timeout, .network },
        .{ .not_found, .none },
        .{ .unauthorized, .none },
    };

    for (http_cases) |case| {
        try std.testing.expectEqual(case[1], classifyHttpStatus(case[0]));
        try std.testing.expectEqual(case[1] != .none, isRetryableHttpStatus(case[0]));
    }
}

test "classifyNetworkTransportError: maps transport errors to retry kinds" {
    const transport_cases = [_]struct { anyerror, RetryKind }{
        .{ error.ConnectionResetByPeer, .network },
        .{ error.Timeout, .network },
        .{ error.NetworkUnreachable, .network },
        .{ error.ConnectionRefused, .network },
        .{ error.UnknownHostName, .network },
        .{ error.OutOfMemory, .none },
        .{ error.UnexpectedEndOfInput, .none },
    };

    for (transport_cases) |case| {
        try std.testing.expectEqual(case[1], classifyNetworkTransportError(case[0]));
    }
}

test "resilience: RetryBudget tracks separate network and rate-limit counters" {
    var budget = RetryBudget.init(.{ .max_network_retries = 1, .max_rate_limit_retries = 2 });
    try std.testing.expect(budget.canRetryNetwork());
    try std.testing.expect(budget.canRetryRateLimit());
    try std.testing.expect(!budget.networkRetriesExhausted());
    try std.testing.expect(!budget.rateLimitRetriesExhausted());

    budget.recordNetworkAttempt();
    try std.testing.expect(!budget.canRetryNetwork());
    try std.testing.expect(budget.networkRetriesExhausted());

    budget.recordRateLimitAttempt();
    budget.recordRateLimitAttempt();
    try std.testing.expect(!budget.canRetryRateLimit());
    try std.testing.expect(budget.rateLimitRetriesExhausted());
}

test "resilience: findHeaderValue matches retry and rate-limit names case-insensitively" {
    const headers = [_]HttpHeader{
        .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
        .{ .name = "x-ratelimit-remaining", .value = "0" },
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "retry-after", .value = "99" },
    };
    try std.testing.expectEqualStrings("100;w=21600", findHeaderValue(&headers, "ratelimit-limit").?);
    try std.testing.expectEqualStrings("0", findHeaderValue(&headers, "X-RateLimit-Remaining").?);
    try std.testing.expectEqualStrings("30", findHeaderValue(&headers, "RETRY-AFTER").?);
    try std.testing.expect(findHeaderValue(&headers, "RateLimit-Reset") == null);
}

test "resilience: parseRateLimitHeaders parses registry, API, and fixture snapshots" {
    const registry = try parseRegistryRateLimitHeaders(&[_]HttpHeader{
        .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
        .{ .name = "RateLimit-Remaining", .value = "87;w=21600" },
        .{ .name = "RateLimit-Reset", .value = "1746136938" },
    });
    try std.testing.expectEqual(RateLimitInfo.Source.registry_rate_limit, registry.source);
    try std.testing.expectEqual(@as(u32, 100), registry.limit.?);
    try std.testing.expectEqual(@as(u32, 87), registry.remaining.?);
    try std.testing.expectEqual(@as(u32, 21_600), registry.window_seconds.?);

    const api = try parseApiRateLimitHeaders(&[_]HttpHeader{
        .{ .name = "X-RateLimit-Limit", .value = "180" },
        .{ .name = "X-RateLimit-Remaining", .value = "0" },
        .{ .name = "X-RateLimit-Reset", .value = "1746136938" },
    });
    try std.testing.expectEqual(RateLimitInfo.Source.api_x_rate_limit, api.source);
    try std.testing.expectEqual(@as(u32, 0), api.remaining.?);

    const mixed = try parseRateLimitHeaders(&[_]HttpHeader{
        .{ .name = "RateLimit-Remaining", .value = "12" },
        .{ .name = "X-RateLimit-Remaining", .value = "0" },
    });
    try std.testing.expectEqual(RateLimitInfo.Source.registry_rate_limit, mixed.source);
    try std.testing.expectEqual(@as(u32, 12), mixed.remaining.?);

    const empty = try parseRateLimitHeaders(&[_]HttpHeader{
        .{ .name = "Content-Type", .value = "application/json" },
    });
    try std.testing.expect(!empty.isSet());

    var fixture_buffer: [4 * 1024]u8 = undefined;
    const fixture = try loadResilienceFixture(ResilienceHeaderFixture, "fixtures/resilience/docker-hub-429-headers.json", &fixture_buffer);
    defer fixture.deinit();
    var header_storage: [8]HttpHeader = undefined;
    const header_slice = copyFixtureHeaders(fixture.value.headers, &header_storage);
    const hub = try parseRateLimitHeaders(header_slice);
    try std.testing.expectEqual(@as(u32, 100), hub.limit.?);
    try std.testing.expectEqual(@as(u32, 0), hub.remaining.?);
    try std.testing.expectEqual(@as(u64, test_epoch_seconds), hub.reset_unix_seconds.?);
}

test "parseRetryAfterValue: parses delay seconds, unix epoch, and HTTP-date" {
    const value_cases = [_]struct { []const u8, RetryAfter }{
        .{ "120", .{ .delay_seconds = 120 } },
        .{ "1746136938", .{ .retry_at_unix_seconds = test_epoch_seconds } },
        .{ test_http_date, .{ .retry_at_unix_seconds = test_epoch_seconds } },
    };

    for (value_cases) |case| {
        try std.testing.expectEqualDeep(case[1], try parseRetryAfterValue(case[0]));
    }
}

test "parseRetryAfterFromHeaders: prefers Retry-After over X-Retry-After and anchors to Date" {
    const date_headers = [_]HttpHeader{
        .{ .name = "Date", .value = test_http_date },
        .{ .name = "Retry-After", .value = "60" },
    };
    const anchored = (try parseRetryAfterFromHeaders(&date_headers, null)).?;
    const response_date = (try responseDateUnixSecondsFromHeaders(&date_headers)).?;

    try std.testing.expectEqual(response_date + 60, anchored.retry_at_unix_seconds);

    const prefer_headers = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "X-Retry-After", .value = "99" },
    };

    try std.testing.expectEqual(@as(u32, 30), (try parseRetryAfterFromHeaders(&prefer_headers, null)).?.delay_seconds);

    const fallback_headers = [_]HttpHeader{.{
        .name = "X-Retry-After",
        .value = "45",
    }};

    try std.testing.expectEqual(@as(u32, 45), (try parseRetryAfterFromHeaders(&fallback_headers, null)).?.delay_seconds);
    try std.testing.expect(try parseRetryAfterFromHeaders(&[_]HttpHeader{
        .{ .name = "Content-Type", .value = "application/json" },
    }, null) == null);
}

test "retryAfterFromHeaders: reads Retry-After when rate-limit headers present" {
    const retry_headers = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "RateLimit-Remaining", .value = "0" },
    };

    try std.testing.expectEqual(@as(u32, 30), (try retryAfterFromHeaders(&retry_headers)).?.delay_seconds);
}

test "parseRetryAfterValue: rejects empty and malformed HTTP-date strings" {
    try std.testing.expectError(error.InvalidRetryAfterHeader, parseRetryAfterValue(""));
    try std.testing.expectError(error.InvalidHttpDate, parseRetryAfterValue("Thu, 99 Foo 2025 99:99:99 GMT"));
}

test "resilience: malformed header fixture maps to exact parser errors" {
    var fixture_buffer: [8 * 1024]u8 = undefined;
    const fixture = try loadResilienceFixture(
        MalformedResilienceHeaderFixture,
        "fixtures/resilience/malformed-rate-limit-headers.json",
        &fixture_buffer,
    );
    defer fixture.deinit();

    var header_storage: [4]HttpHeader = undefined;
    for (fixture.value.cases) |case| {
        const header_slice = copyFixtureHeaders(case.headers, &header_storage);
        if (std.mem.eql(u8, case.expected_error, "InvalidRateLimitHeader")) {
            try std.testing.expectError(error.InvalidRateLimitHeader, parseRateLimitHeaders(header_slice));
        } else if (std.mem.eql(u8, case.expected_error, "InvalidRetryAfterHeader")) {
            try std.testing.expectError(error.InvalidRetryAfterHeader, parseRetryAfterValue(case.headers[0].value));
        } else return error.TestUnexpectedResult;
    }
}

test "resilience: retryAfterDelayMs converts delays and clamps past instants" {
    try std.testing.expectEqual(@as(u32, 120_000), retryAfterDelayMs(.{ .delay_seconds = 120 }, test_policy_now_unix_seconds));
    try std.testing.expectEqual(@as(u32, 45_000), retryAfterDelayMs(.{ .retry_at_unix_seconds = test_policy_now_unix_seconds + 45 }, test_policy_now_unix_seconds));
    try std.testing.expectEqual(@as(u32, 0), retryAfterDelayMs(.{ .retry_at_unix_seconds = test_policy_now_unix_seconds - 1 }, test_policy_now_unix_seconds));
    try std.testing.expectEqual(@as(u32, 30_000), retryAfterDelayMs(.{ .retry_at_unix_seconds = test_epoch_seconds }, test_epoch_seconds - 30));
}

test "resilience: isTrackedResilienceHeaderName filters retry metadata families" {
    for ([_][]const u8{
        "RateLimit-Limit",
        "X-RateLimit-Reset",
        "Retry-After",
        "Date",
    }) |name| try std.testing.expect(isTrackedResilienceHeaderName(name));
    for ([_][]const u8{ "Content-Type", "WWW-Authenticate", "Docker-Content-Digest" }) |name| {
        try std.testing.expect(!isTrackedResilienceHeaderName(name));
    }
}

test "isTrustworthyPreemptiveRateLimit: registry snapshots trusted and API snapshots rejected" {
    const trusted: RateLimitInfo = .{
        .source = .registry_rate_limit,
        .limit = 100,
        .remaining = 0,
        .reset_unix_seconds = 1_700_000_045,
    };

    try std.testing.expect(isTrustworthyPreemptiveRateLimit(trusted));
    try std.testing.expect(!isTrustworthyPreemptiveRateLimit(.{
        .source = .api_x_rate_limit,
        .limit = 180,
        .remaining = 0,
        .reset_unix_seconds = 1_700_000_045,
    }));
}

test "preemptiveRateLimitDelayMs: returns delay only when enabled and registry exhausted" {
    const trusted: RateLimitInfo = .{
        .source = .registry_rate_limit,
        .limit = 100,
        .remaining = 0,
        .reset_unix_seconds = 1_700_000_045,
    };

    try std.testing.expectEqual(@as(?u32, 45_000), preemptiveRateLimitDelayMs(true, trusted, test_policy_now_unix_seconds, 0));
    try std.testing.expect(preemptiveRateLimitDelayMs(false, trusted, test_policy_now_unix_seconds, 0) == null);
    try std.testing.expect(preemptiveRateLimitDelayMs(true, trusted, test_policy_now_unix_seconds + 100, 0) == null);
    try std.testing.expect(preemptiveRateLimitDelayMs(true, .{
        .source = .registry_rate_limit,
        .limit = 100,
        .remaining = 3,
        .reset_unix_seconds = 1_700_000_045,
    }, test_policy_now_unix_seconds, 0) == null);
}

test "ManifestThrottle.recordManifestResponseHeaders: registry RateLimit wins over X-RateLimit" {
    var throttle: ManifestThrottle = .{};

    throttle.recordManifestResponseHeaders(&[_]HttpHeader{
        .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
        .{ .name = "RateLimit-Remaining", .value = "0" },
        .{ .name = "RateLimit-Reset", .value = "1700000045" },
    });

    try std.testing.expectEqual(@as(u32, 0), throttle.prior.?.remaining.?);

    throttle.recordManifestResponseHeaders(&[_]HttpHeader{
        .{ .name = "X-RateLimit-Remaining", .value = "0" },
        .{ .name = "X-RateLimit-Reset", .value = "1700000045" },
        .{ .name = "X-RateLimit-Limit", .value = "180" },
    });

    try std.testing.expect(throttle.prior == null);
}

test "ManifestThrottle.sleepBeforeManifestRequestIfNeeded: sleeps reset window via injected sleeper" {
    const SleepHarness = struct {
        var slept_ms: u32 = 0;
        fn sleeper(delay_ms: u32) void {
            slept_ms = delay_ms;
        }
    };
    defer SleepHarness.slept_ms = 0;
    test_policy_now_unix_seconds = 1_700_000_000;

    var throttle: ManifestThrottle = .{
        .prior = .{
            .source = .registry_rate_limit,
            .limit = 100,
            .remaining = 0,
            .reset_unix_seconds = 1_700_000_030,
        },
    };
    var client: std.http.Client = undefined;

    throttle.sleepBeforeManifestRequestIfNeeded(.{ .rate_limit_enabled = true }, &client, .{
        .sleeper = SleepHarness.sleeper,
        .clock = .{ .now_unix_seconds = testPolicyNowUnixSeconds },
    });

    try std.testing.expectEqual(@as(u32, 30_000), SleepHarness.slept_ms);
}

test "resilience: RetryPolicy applies HTTP retry budgets and Retry-After delays" {
    test_policy_now_unix_seconds = 1_700_000_000;
    test_policy_random_u64 = 0;

    var policy = retryPolicyFromConfig(.{
        .max_network_retries = 1,
        .max_rate_limit_retries = 2,
    }, testTransportHooks());

    const first = policy.decideHttpRetry(.too_many_requests, .{ .delay_seconds = 30 });
    try std.testing.expectEqual(RetryDecision.Action.retry, first.action);
    try std.testing.expectEqual(RetryKind.rate_limit, first.kind);
    try std.testing.expectEqual(@as(u32, 30_000), first.delay_ms);
    try std.testing.expectEqual(@as(u8, 1), policy.budget.rate_limit_attempts_used);

    const second = policy.decideHttpRetry(.too_many_requests, null);
    try std.testing.expectEqual(RetryDecision.Action.retry, second.action);
    try std.testing.expectEqual(@as(u8, 2), policy.budget.rate_limit_attempts_used);
    try std.testing.expectEqual(RetryDecision.Action.give_up, policy.decideHttpRetry(.too_many_requests, null).action);

    const gateway = policy.decideHttpRetry(.bad_gateway, null);
    try std.testing.expectEqual(RetryKind.network, gateway.kind);
    try std.testing.expectEqual(RetryDecision.Action.retry, gateway.action);
    try std.testing.expectEqual(@as(u8, 1), policy.budget.network_attempts_used);
    try std.testing.expectEqual(@as(u8, 2), policy.budget.rate_limit_attempts_used);

    try std.testing.expectEqual(RetryDecision.Action.give_up, policy.decideHttpRetry(.not_found, null).action);
}

test "RetryPolicy.decideHttpRetry: jitter backoff when Retry-After absent" {
    test_policy_random_u64 = 999;
    var policy = testRetryPolicy(retryBudgetConfig(.{ .max_network_retries = 2, .max_rate_limit_retries = 1 }));

    const jitter = policy.decideHttpRetry(.too_many_requests, null);

    try std.testing.expectEqual(RetryDecision.Action.retry, jitter.action);
    try std.testing.expectEqual(@as(u32, 999), jitter.delay_ms);

    test_policy_random_u64 = 4;
    const gateway = policy.decideHttpRetry(.bad_gateway, null);

    try std.testing.expectEqual(@as(u32, 4), gateway.delay_ms);
}

test "RetryPolicy.decideTransportRetry: retries reset until budget exhausted then gives up" {
    test_policy_random_u64 = 999;
    var policy = testRetryPolicy(retryBudgetConfig(.{ .max_network_retries = 2, .max_rate_limit_retries = 1 }));
    _ = policy.decideHttpRetry(.too_many_requests, null);
    test_policy_random_u64 = 4;
    _ = policy.decideHttpRetry(.bad_gateway, null);

    const reset = policy.decideTransportRetry(error.ConnectionResetByPeer);

    try std.testing.expectEqual(RetryDecision.Action.retry, reset.action);
    try std.testing.expectEqual(@as(u8, 2), policy.budget.network_attempts_used);
    try std.testing.expectEqual(RetryDecision.Action.give_up, policy.decideTransportRetry(error.Timeout).action);
    try std.testing.expectEqual(RetryDecision.Action.give_up, policy.decideTransportRetry(error.UnexpectedEndOfInput).action);
}

test "sleepForTransportRetry: forwards delay to injected sleeper" {
    const SleepHarness = struct {
        var recorded_ms: u32 = 0;
        fn sleeper(delay_ms: u32) void {
            recorded_ms = delay_ms;
        }
    };
    SleepHarness.recorded_ms = 0;
    var client: std.http.Client = undefined;

    sleepForTransportRetry(&client, .{ .sleeper = SleepHarness.sleeper }, 250);

    try std.testing.expectEqual(@as(u32, 250), SleepHarness.recorded_ms);
}

test "readHttpResponseBodyAlloc: reads within max and returns BodyTooLarge" {
    var reader_ok = std.Io.Reader.fixed("abc");
    const body = try readHttpResponseBodyAlloc(std.testing.allocator, &reader_ok, 4);
    defer std.testing.allocator.free(body);

    try std.testing.expectEqualStrings("abc", body);

    var reader_too_large = std.Io.Reader.fixed("abcd");

    try std.testing.expectError(error.BodyTooLarge, readHttpResponseBodyAlloc(std.testing.allocator, &reader_too_large, 3));
}

test "readHttpResponseBodyAlloc: allocation failures do not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var reader = std.Io.Reader.fixed("abc");
            const owned = try readHttpResponseBodyAlloc(allocator, &reader, 4);
            defer allocator.free(owned);
        }
    }.run, .{});
}

test "duplicateHttpHeadersAlloc: deep-copies borrowed name and value slices" {
    const borrowed = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "RateLimit-Remaining", .value = "0" },
    };

    const owned = try duplicateHttpHeadersAlloc(std.testing.allocator, &borrowed);
    defer deinitOwnedHttpHeaders(std.testing.allocator, owned);

    try std.testing.expectEqualStrings("30", owned[0].value);
    try std.testing.expectEqualStrings("0", owned[1].value);
}

test "duplicateHttpHeadersAlloc: allocation failures do not leak" {
    const borrowed = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "RateLimit-Remaining", .value = "0" },
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const copied = try duplicateHttpHeadersAlloc(allocator, &borrowed);
            defer deinitOwnedHttpHeaders(allocator, copied);
            try std.testing.expectEqual(@as(usize, 2), copied.len);
        }
    }.run, .{});
}

test "runHttpRetryLoop: 429 with Retry-After retries then succeeds" {
    const ExchangeError = error{ConnectionResetByPeer};
    const LoopResponse = struct {
        status: std.http.Status,
        headers: []const HttpHeader = &.{},
    };
    const RateLimitedHarness = struct {
        var attempts: usize = 0;
        var sleep_count: usize = 0;
        var last_sleep_ms: u32 = 0;
        const rate_limited_headers = [_]HttpHeader{
            .{ .name = "Retry-After", .value = "30" },
        };
        fn exchangeOnce(_: *anyopaque) ExchangeError!LoopResponse {
            attempts += 1;
            if (attempts == 1) return .{ .status = .too_many_requests, .headers = &rate_limited_headers };
            return .{ .status = .ok };
        }
        fn sleeper(delay_ms: u32) void {
            sleep_count += 1;
            last_sleep_ms = delay_ms;
        }
    };
    RateLimitedHarness.attempts = 0;
    RateLimitedHarness.sleep_count = 0;
    RateLimitedHarness.last_sleep_ms = 0;
    test_policy_now_unix_seconds = 1_700_000_000;

    const rate_limited = runHttpRetryLoopForTest(
        ExchangeError,
        LoopResponse,
        .{ .max_rate_limit_retries = 1 },
        .{ .sleeper = RateLimitedHarness.sleeper, .clock = .{ .now_unix_seconds = testPolicyNowUnixSeconds } },
        @ptrCast(&RateLimitedHarness.attempts),
        struct {
            fn call(ctx: *anyopaque) ExchangeError!LoopResponse {
                return RateLimitedHarness.exchangeOnce(ctx);
            }
        }.call,
        struct {
            fn call(response: LoopResponse) std.http.Status {
                return response.status;
            }
        }.call,
        struct {
            fn call(response: LoopResponse) []const HttpHeader {
                return response.headers;
            }
        }.call,
        struct {
            fn call(_: std.mem.Allocator, _: LoopResponse) void {}
        }.call,
    );

    switch (rate_limited) {
        .ok => |ok| {
            try std.testing.expectEqual(std.http.Status.ok, ok.response.status);
            try std.testing.expectEqual(@as(usize, 2), RateLimitedHarness.attempts);
            try std.testing.expectEqual(@as(u32, 30_000), RateLimitedHarness.last_sleep_ms);
            try std.testing.expectEqual(@as(u8, 1), ok.budget.rate_limit_attempts_used);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "runHttpRetryLoop: malformed Retry-After falls back to jitter backoff" {
    const ExchangeError = error{ConnectionResetByPeer};
    const LoopResponse = struct {
        status: std.http.Status,
        headers: []const HttpHeader = &.{},
    };
    const BackoffHarness = struct {
        var attempts: usize = 0;
        var last_sleep_ms: u32 = 0;
        const bad_headers = [_]HttpHeader{
            .{ .name = "Retry-After", .value = "soon" },
        };
        fn exchangeOnce(_: *anyopaque) ExchangeError!LoopResponse {
            attempts += 1;
            if (attempts == 1) return .{ .status = .too_many_requests, .headers = &bad_headers };
            return .{ .status = .ok };
        }
        fn sleeper(delay_ms: u32) void {
            last_sleep_ms = delay_ms;
        }
    };
    BackoffHarness.attempts = 0;
    BackoffHarness.last_sleep_ms = 0;
    test_policy_random_u64 = 999;

    const malformed = runHttpRetryLoopForTest(
        ExchangeError,
        LoopResponse,
        .{ .max_rate_limit_retries = 1 },
        .{ .sleeper = BackoffHarness.sleeper, .random_u64 = testPolicyRandomU64 },
        @ptrCast(&BackoffHarness.attempts),
        struct {
            fn call(ctx: *anyopaque) ExchangeError!LoopResponse {
                return BackoffHarness.exchangeOnce(ctx);
            }
        }.call,
        struct {
            fn call(response: LoopResponse) std.http.Status {
                return response.status;
            }
        }.call,
        struct {
            fn call(response: LoopResponse) []const HttpHeader {
                return response.headers;
            }
        }.call,
        struct {
            fn call(_: std.mem.Allocator, _: LoopResponse) void {}
        }.call,
    );

    switch (malformed) {
        .ok => |ok| {
            try std.testing.expectEqual(@as(u32, 999), BackoffHarness.last_sleep_ms);
            try std.testing.expectEqual(@as(usize, 2), BackoffHarness.attempts);
            _ = ok;
        },
        else => return error.TestUnexpectedResult,
    }
}

test "runHttpRetryLoop: transport failure exhausts network budget" {
    const ExchangeError = error{ConnectionResetByPeer};
    const LoopResponse = struct {
        status: std.http.Status,
        headers: []const HttpHeader = &.{},
    };
    const FailHarness = struct {
        var attempts: usize = 0;
        fn exchangeOnce(_: *anyopaque) ExchangeError!LoopResponse {
            attempts += 1;
            return error.ConnectionResetByPeer;
        }
    };
    FailHarness.attempts = 0;

    const failed = runHttpRetryLoopForTest(
        ExchangeError,
        LoopResponse,
        .{ .max_network_retries = 1 },
        .{ .sleeper = noopTransportSleeper },
        @ptrCast(&FailHarness.attempts),
        struct {
            fn call(ctx: *anyopaque) ExchangeError!LoopResponse {
                return FailHarness.exchangeOnce(ctx);
            }
        }.call,
        struct {
            fn call(response: LoopResponse) std.http.Status {
                return response.status;
            }
        }.call,
        struct {
            fn call(response: LoopResponse) []const HttpHeader {
                return response.headers;
            }
        }.call,
        struct {
            fn call(_: std.mem.Allocator, _: LoopResponse) void {}
        }.call,
    );

    switch (failed) {
        .transport_failed => |transport_failed| {
            try std.testing.expectEqual(error.ConnectionResetByPeer, transport_failed.err);
            try std.testing.expectEqual(@as(usize, 2), FailHarness.attempts);
            try std.testing.expectEqual(@as(u8, 1), transport_failed.budget.network_attempts_used);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "resilience: runHttpRetryLoop transport and HTTP retry chain stays leak-free" {
    const ExchangeError = error{ConnectionResetByPeer};
    const TestResponse = struct { status: std.http.Status };

    const Harness = struct {
        var attempts: usize = 0;
        fn exchangeOnce(_: *anyopaque) ExchangeError!TestResponse {
            attempts += 1;
            if (attempts == 1) return error.ConnectionResetByPeer;
            if (attempts == 2) return .{ .status = .service_unavailable };
            return .{ .status = .ok };
        }
    };
    Harness.attempts = 0;

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");

    var client: std.http.Client = undefined;
    var policy = retryPolicyFromConfig(.{ .max_network_retries = 2 }, .{ .sleeper = noopTransportSleeper });
    var loop_ctx: usize = 0;
    const result = runHttpRetryLoop(
        &client,
        .{ .sleeper = noopTransportSleeper },
        &policy,
        .{},
        ExchangeError,
        TestResponse,
        @ptrCast(&loop_ctx),
        struct {
            fn call(ctx: *anyopaque) ExchangeError!TestResponse {
                return Harness.exchangeOnce(ctx);
            }
        }.call,
        struct {
            fn call(response: TestResponse) std.http.Status {
                return response.status;
            }
        }.call,
        struct {
            fn call(_: TestResponse) []const HttpHeader {
                return &.{};
            }
        }.call,
        struct {
            fn call(_: std.mem.Allocator, _: TestResponse) void {}
        }.call,
        gpa.allocator(),
    );

    switch (result) {
        .ok => |ok| {
            try std.testing.expectEqual(std.http.Status.ok, ok.response.status);
            try std.testing.expectEqual(@as(usize, 3), Harness.attempts);
        },
        else => return error.TestUnexpectedResult,
    }
}
