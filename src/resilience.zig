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

/// Parsed rate-limit snapshot from response headers.
///
/// Populated by the rate-limit header parsers. Manifest transport records the
/// last trustworthy registry snapshot via `ManifestThrottle` for opt-in
/// pre-emptive throttling when `Config.rate_limit_enabled` is true.
pub const RateLimitInfo = struct {
    /// Which header family populated this snapshot (registry pull vs API token bucket).
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

    /// True when any rate-limit header was parsed (not an empty default).
    pub fn isSet(self: RateLimitInfo) bool {
        return self.source != .none;
    }
};
/// Parsed retry delay instruction.
///
/// Registries mix seconds, HTTP-date, and (on Docker Hub) Unix timestamps in
/// `Retry-After` / `X-Retry-After`. Store the normalized form, not raw bytes.
///
/// Registry assumptions encoded in the parsers:
/// - Docker Hub may send large integer `Retry-After` values as Unix epoch seconds
///   rather than delay seconds; values above `1_000_000_000` are treated as absolute
///   retry instants.
/// - `X-RateLimit-Reset` on Docker Hub token/API responses is a Unix epoch second.
///   Registry `RateLimit-Reset` follows the same rule when present.
/// - `Retry-After` wins over `X-Retry-After` when both are present.
/// - Integer delay seconds anchor to the response `Date` header when available.
/// - Pre-emptive throttling trusts registry `RateLimit-*` only, not `X-RateLimit-*`
///   alone, and requires `limit`, `remaining`, and `RateLimit-Reset`.
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
/// HTTP header pair. Borrowed on the wire; owned after `duplicateHttpHeadersAlloc`.
pub const HttpHeader = struct {
    /// Header name. Borrowed from the response unless duplicated.
    name: []const u8,
    /// Header value. Borrowed from the response unless duplicated.
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
    /// Pre-emptive throttling gate. When true, manifest transport may pause before
    /// the next request when the prior response had trustworthy registry `RateLimit-*`
    /// headers with `remaining` at zero. Reactive `429` backoff ignores this.
    rate_limit_enabled: bool,
};
/// Tracks transport retry attempts against separate budgets.
pub const RetryBudget = struct {
    network_attempts_used: u8 = 0,
    rate_limit_attempts_used: u8 = 0,
    max_network_retries: u8,
    max_rate_limit_retries: u8,

    /// Build a fresh budget from config limits (counters start at zero).
    pub fn init(config: RetryBudgetConfig) RetryBudget {
        return .{
            .max_network_retries = config.max_network_retries,
            .max_rate_limit_retries = config.max_rate_limit_retries,
        };
    }

    /// True while reactive network retries remain under `max_network_retries`.
    pub fn canRetryNetwork(self: RetryBudget) bool {
        return self.network_attempts_used < self.max_network_retries;
    }

    /// True while reactive rate-limit retries remain under `max_rate_limit_retries`.
    pub fn canRetryRateLimit(self: RetryBudget) bool {
        return self.rate_limit_attempts_used < self.max_rate_limit_retries;
    }

    /// Increment the network retry counter before sleeping and re-issuing the request.
    pub fn recordNetworkAttempt(self: *RetryBudget) void {
        self.network_attempts_used +%= 1;
    }

    /// Increment the rate-limit retry counter before sleeping and re-issuing the request.
    pub fn recordRateLimitAttempt(self: *RetryBudget) void {
        self.rate_limit_attempts_used +%= 1;
    }

    /// True when at least one reactive rate-limit retry was attempted.
    pub fn rateLimitRetriesExhausted(self: RetryBudget) bool {
        return self.rate_limit_attempts_used > 0;
    }

    /// True when at least one reactive network retry was attempted.
    pub fn networkRetriesExhausted(self: RetryBudget) bool {
        return self.network_attempts_used > 0;
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
    /// Whether the transport wrapper should sleep and retry or return the response/error.
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

    /// Build a policy from config budgets and injected clock/RNG hooks.
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

    /// Classify an HTTP status and optional `Retry-After` into one reactive retry decision.
    pub fn decideHttpRetry(
        self: *RetryPolicy,
        status: std.http.Status,
        retry_after: ?RetryAfter,
    ) RetryDecision {
        return self.decideRetry(classifyHttpStatus(status), retry_after);
    }

    /// Classify a transport error into one reactive retry decision (no header delay).
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
    clock: RetryClock = SYSTEM_RETRY_CLOCK,
    /// When true, resolver/auth sleep through `std.http.Client.io` instead of `sleeper`.
    use_live_sleep: bool = false,
};
/// No-op sleep hook for unit tests that assert retry counts without delaying.
pub fn noopTransportSleeper(_: u32) void {}

/// Production transport hooks: real clock, jitter, and `std.http.Client` sleep.
pub fn liveTransportHooks() TransportHooks {
    return .{ .use_live_sleep = true };
}
/// Default clock wired into transport hooks when callers do not inject one.
pub const SYSTEM_RETRY_CLOCK: RetryClock = .{ .now_unix_seconds = systemNowUnixSeconds };
/// Extract retry budget inputs from `Config` (backoff stays on fixed defaults).
pub fn retryPolicyConfig(config: Config) RetryPolicyConfig {
    return .{ .budget = retryBudgetConfig(config) };
}
/// Build a `RetryPolicy` from config budgets and transport hook clock/RNG.
pub fn retryPolicyFromConfig(config: Config, hooks: TransportHooks) RetryPolicy {
    return RetryPolicy.init(retryPolicyConfig(config), hooks.random_u64, hooks.clock);
}
/// Sleep for reactive or pre-emptive transport delays (live I/O or injected sleeper).
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
/// Optional hooks for the shared manifest/token transport retry loop.
pub const HttpRetryLoopHooks = struct {
    before_first_attempt: ?*const fn (*anyopaque) void = null,
    after_successful_exchange: ?*const fn (*anyopaque, std.http.Status, []const HttpHeader) void = null,
};
/// Outcome of `runHttpRetryLoop` for manifest and token transport wrappers.
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
/// Shared reactive retry loop for manifest and token HTTP exchangers.
///
/// Transport wrappers pass exchange-specific callbacks; manifest transport uses
/// `before_first_attempt` for opt-in pre-emptive rate limiting and
/// `after_successful_exchange` to record rate-limit headers.
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
/// Header names the manifest/token transport layers retain for retry and throttle parsing.
///
/// Unlisted headers are dropped early so resilience parsers only see rate-limit and
/// retry metadata the policy layer understands.
pub fn isTrackedResilienceHeaderName(name: []const u8) bool {
    if (std.mem.startsWith(u8, name, "RateLimit-")) return true;
    if (std.ascii.startsWithIgnoreCase(name, "X-RateLimit-")) return true;
    if (std.ascii.eqlIgnoreCase(name, "Retry-After")) return true;
    if (std.ascii.eqlIgnoreCase(name, "X-Retry-After")) return true;
    if (std.ascii.eqlIgnoreCase(name, "Date")) return true;
    return false;
}
/// Parse reactive retry delay from retained response headers (prefers `Retry-After`).
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
/// Free header name/value pairs allocated by `duplicateHttpHeadersAlloc`.
pub fn deinitOwnedHttpHeaders(allocator: std.mem.Allocator, headers: []HttpHeader) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}
/// Deep-copy borrowed wire headers so retry loops can release the response buffer.
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
/// Map `Config` transport retry limits into a `RetryBudgetConfig` snapshot.
pub fn retryBudgetConfig(config: Config) RetryBudgetConfig {
    return .{
        .max_network_retries = config.max_network_retries,
        .max_rate_limit_retries = config.max_rate_limit_retries,
    };
}
/// Narrow config view for resilience helpers and tests (no auth-only fields).
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
/// Case-insensitive header lookup for parser entry points.
pub fn findHeaderValue(headers: []const HttpHeader, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}
/// Map HTTP status to reactive retry bucket (`429` vs gateway/timeout vs none).
pub fn classifyHttpStatus(status: std.http.Status) RetryKind {
    return switch (status) {
        .too_many_requests => .rate_limit,
        .bad_gateway, .service_unavailable, .gateway_timeout => .network,
        else => .none,
    };
}
/// True when `classifyHttpStatus` would schedule a reactive transport retry.
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
/// Errors while reading a bounded HTTP response body into an owned buffer.
pub const HttpBodyReadError = error{
    OutOfMemory,
    BodyTooLarge,
} || std.Io.Reader.ShortError;
/// Read up to `max_bytes` from the response body stream into caller-owned storage.
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
/// Malformed rate-limit or retry-after header values from registry responses.
pub const ResilienceParseError = error{
    InvalidRateLimitHeader,
    InvalidRetryAfterHeader,
    InvalidHttpDate,
};
// --- Resilience header parsers ---

/// Parse registry pull rate-limit headers (`RateLimit-*`).
///
/// Empty `.source` when no registry headers are present. Partial registry sets are
/// kept for logging but rejected by pre-emptive throttling trust checks.
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
/// Empty `.source` when no API headers are present. Pre-emptive throttling ignores
/// API-only snapshots because token-bucket metadata is not pull-bucket trustworthy.
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
/// Live on manifest transport via `ManifestThrottle` when pre-emptive
/// throttling is enabled. Reactive transport retry uses `retryAfterFromHeaders`.
pub fn parseRateLimitHeaders(headers: []const HttpHeader) ResilienceParseError!RateLimitInfo {
    const registry = try parseRegistryRateLimitHeaders(headers);
    if (registry.isSet()) return registry;
    return parseApiRateLimitHeaders(headers);
}
/// True when registry pull `RateLimit-*` headers form a complete Docker Hub-style snapshot.
///
/// Requires registry source plus `limit`, `remaining`, and `RateLimit-Reset`. Partial
/// sets and API-only headers are rejected so unreliable metadata does not slow pulls.
pub fn isTrustworthyPreemptiveRateLimit(info: RateLimitInfo) bool {
    if (info.source != .registry_rate_limit) return false;
    if (info.limit == null or info.remaining == null) return false;
    if (info.reset_unix_seconds == null) return false;
    return true;
}
/// Milliseconds to sleep before the next manifest request when the pull bucket is exhausted.
///
/// `null` when pre-emption is disabled, headers fail the trust check, remaining is above
/// `remaining_threshold`, or the reset time has already passed.
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
/// Carries the last trustworthy registry rate-limit snapshot across manifest HTTP
/// calls within one resolve/validate/get operation via `ResolverParams.manifest_throttle`.
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
/// Parse `Retry-After` or `X-Retry-After` when either header is present.
///
/// `null` when neither header exists. Integer-second delays anchor to
/// `response_date_unix_seconds` or a captured `Date` header per RFC 7231. Malformed
/// values surface as `ResilienceParseError`; transport wrappers fall back to backoff.
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
/// Parse a single raw `Retry-After` value without response `Date` anchoring.
pub fn parseRetryAfterValue(raw: []const u8) ResilienceParseError!RetryAfter {
    return parseRetryAfterValueWithContext(raw, null);
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
const ConflictingRetryAfterFixture = struct {
    headers: []const struct {
        name: []const u8,
        value: []const u8,
    },
    expected_delay_seconds: u32,
};
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

// --- Tests ---

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
test "configView projects reserved fields without implying they drive RetryPolicy" {
    const config = Config{
        .connect_timeout_ms = 5_000,
        .read_timeout_ms = 60_000,
        .max_retries = 9,
        .max_network_retries = 2,
        .max_rate_limit_retries = 3,
        .ca_bundle_path = "/tmp/custom-ca.pem",
        .rate_limit_enabled = false,
    };

    const view = configView(config);

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
    const cases = [_]struct {
        err: anyerror,
        expected: RetryKind,
    }{
        .{ .err = error.ConnectionResetByPeer, .expected = .network },
        .{ .err = error.Timeout, .expected = .network },
        .{ .err = error.NetworkUnreachable, .expected = .network },
        .{ .err = error.ConnectionRefused, .expected = .network },
        .{ .err = error.UnknownHostName, .expected = .network },
        .{ .err = error.OutOfMemory, .expected = .none },
        .{ .err = error.UnexpectedEndOfInput, .expected = .none },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expected, classifyNetworkTransportError(case.err));
    }
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
test "RetryBudget retry exhaustion flags flip after attempts" {
    const cases = [_]struct {
        record_network: bool,
        record_rate_limit: bool,
        network_exhausted: bool,
        rate_limit_exhausted: bool,
    }{
        .{ .record_network = false, .record_rate_limit = false, .network_exhausted = false, .rate_limit_exhausted = false },
        .{ .record_network = true, .record_rate_limit = false, .network_exhausted = true, .rate_limit_exhausted = false },
        .{ .record_network = false, .record_rate_limit = true, .network_exhausted = false, .rate_limit_exhausted = true },
        .{ .record_network = true, .record_rate_limit = true, .network_exhausted = true, .rate_limit_exhausted = true },
    };

    for (cases) |case| {
        var budget = RetryBudget.init(.{ .max_network_retries = 2, .max_rate_limit_retries = 2 });
        if (case.record_network) budget.recordNetworkAttempt();
        if (case.record_rate_limit) budget.recordRateLimitAttempt();
        try std.testing.expectEqual(case.network_exhausted, budget.networkRetriesExhausted());
        try std.testing.expectEqual(case.rate_limit_exhausted, budget.rateLimitRetriesExhausted());
    }
}
test "findHeaderValue matches rate-limit and retry headers case-insensitively" {
    const cases = [_]struct {
        headers: []const HttpHeader,
        name: []const u8,
        expected: ?[]const u8,
    }{
        .{
            .headers = &.{
                .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
                .{ .name = "RateLimit-Remaining", .value = "87" },
                .{ .name = "Docker-Content-Digest", .value = "sha256:abc" },
            },
            .name = "ratelimit-limit",
            .expected = "100;w=21600",
        },
        .{
            .headers = &.{
                .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
                .{ .name = "RateLimit-Remaining", .value = "87" },
            },
            .name = "RATELIMIT-REMAINING",
            .expected = "87",
        },
        .{
            .headers = &.{
                .{ .name = "x-ratelimit-limit", .value = "180" },
                .{ .name = "x-ratelimit-remaining", .value = "0" },
                .{ .name = "x-ratelimit-reset", .value = "1746136938" },
                .{ .name = "retry-after", .value = "1746136938" },
            },
            .name = "X-RateLimit-Limit",
            .expected = "180",
        },
        .{
            .headers = &.{
                .{ .name = "Retry-After", .value = "30" },
                .{ .name = "retry-after", .value = "99" },
            },
            .name = "Retry-After",
            .expected = "30",
        },
        .{
            .headers = &.{
                .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
            },
            .name = "RateLimit-Reset",
            .expected = null,
        },
    };

    for (cases) |case| {
        const found = findHeaderValue(case.headers, case.name);
        if (case.expected) |value| {
            try std.testing.expectEqualStrings(value, found.?);
        } else {
            try std.testing.expect(found == null);
        }
    }
}
test "RateLimitInfo defaults to unset source" {
    const info: RateLimitInfo = .{};
    try std.testing.expect(!info.isSet());
    try std.testing.expect(info.limit == null);
    try std.testing.expect(info.remaining == null);
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
test "parseRetryAfterValue parses delay seconds, epoch, and HTTP-date forms" {
    const cases = [_]struct {
        raw: []const u8,
        expected: RetryAfter,
    }{
        .{ .raw = "120", .expected = .{ .delay_seconds = 120 } },
        .{ .raw = "1746136938", .expected = .{ .retry_at_unix_seconds = 1_746_136_938 } },
        .{ .raw = "Thu, 01 May 2025 22:02:18 GMT", .expected = .{ .retry_at_unix_seconds = 1_746_136_938 } },
    };

    for (cases) |case| {
        const parsed = try parseRetryAfterValue(case.raw);
        try std.testing.expectEqualDeep(case.expected, parsed);
    }
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
test "malformed resilience header fixture rejects invalid rate-limit and retry-after values" {
    var bytes_buffer: [8 * 1024]u8 = undefined;
    const bytes = try std.Io.Dir.cwd().readFile(
        std.testing.io,
        "fixtures/resilience/malformed-rate-limit-headers.json",
        &bytes_buffer,
    );

    const parsed = try json.parse(MalformedResilienceHeaderFixture, std.testing.allocator, bytes);
    defer parsed.deinit();

    for (parsed.value.cases) |case| {
        var headers: [4]HttpHeader = undefined;
        try std.testing.expect(case.headers.len <= headers.len);
        for (case.headers, 0..) |entry, index| {
            headers[index] = .{ .name = entry.name, .value = entry.value };
        }
        const header_slice = headers[0..case.headers.len];

        if (std.mem.eql(u8, case.expected_error, "InvalidRateLimitHeader")) {
            try std.testing.expectError(error.InvalidRateLimitHeader, parseRateLimitHeaders(header_slice));
            continue;
        }
        if (std.mem.eql(u8, case.expected_error, "InvalidRetryAfterHeader")) {
            try std.testing.expectError(error.InvalidRetryAfterHeader, parseRetryAfterValue(case.headers[0].value));
            continue;
        }
        return error.TestUnexpectedResult;
    }
}
test "conflicting retry-after fixture prefers Retry-After over X-Retry-After" {
    var bytes_buffer: [4 * 1024]u8 = undefined;
    const bytes = try std.Io.Dir.cwd().readFile(
        std.testing.io,
        "fixtures/resilience/conflicting-retry-after.json",
        &bytes_buffer,
    );

    const parsed = try json.parse(ConflictingRetryAfterFixture, std.testing.allocator, bytes);
    defer parsed.deinit();

    var headers: [4]HttpHeader = undefined;
    try std.testing.expect(parsed.value.headers.len <= headers.len);
    for (parsed.value.headers, 0..) |entry, index| {
        headers[index] = .{ .name = entry.name, .value = entry.value };
    }
    const header_slice = headers[0..parsed.value.headers.len];

    const retry_after = (try parseRetryAfterFromHeaders(header_slice, null)).?;
    const response_date = (try responseDateUnixSecondsFromHeaders(header_slice)).?;
    try std.testing.expectEqual(response_date + parsed.value.expected_delay_seconds, retry_after.retry_at_unix_seconds);
}
test "retryAfterDelayMs converts delay seconds and absolute retry instants" {
    const delay: RetryAfter = .{ .delay_seconds = 120 };
    const absolute: RetryAfter = .{ .retry_at_unix_seconds = 1_746_136_938 };

    try std.testing.expectEqual(@as(u32, 120_000), retryAfterDelayMs(delay, 1_700_000_000));
    try std.testing.expectEqual(@as(u32, 120_000), retryAfterDelayMs(.{ .delay_seconds = 120 }, 1_700_000_000));
    try std.testing.expectEqual(@as(u32, 45_000), retryAfterDelayMs(.{ .retry_at_unix_seconds = 1_700_000_045 }, 1_700_000_000));
    try std.testing.expectEqual(@as(u32, 0), retryAfterDelayMs(.{ .retry_at_unix_seconds = 1_699_999_999 }, 1_700_000_000));
    try std.testing.expectEqual(
        @as(u32, 30_000),
        retryAfterDelayMs(absolute, 1_746_136_908),
    );
}
test "isTrackedResilienceHeaderName recognizes retry and rate-limit families" {
    const positive = [_][]const u8{
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Retry-After",
        "X-Retry-After",
        "Date",
    };
    const negative = [_][]const u8{
        "Content-Type",
        "WWW-Authenticate",
        "Docker-Content-Digest",
        "Authorization",
    };

    for (positive) |name| try std.testing.expect(isTrackedResilienceHeaderName(name));
    for (negative) |name| try std.testing.expect(!isTrackedResilienceHeaderName(name));
}
test "isTrustworthyPreemptiveRateLimit requires registry RateLimit family with limit remaining reset" {
    const trusted: RateLimitInfo = .{
        .source = .registry_rate_limit,
        .limit = 100,
        .remaining = 0,
        .reset_unix_seconds = 1_700_000_060,
        .window_seconds = 21_600,
    };
    try std.testing.expect(isTrustworthyPreemptiveRateLimit(trusted));

    const api_only: RateLimitInfo = .{
        .source = .api_x_rate_limit,
        .limit = 180,
        .remaining = 0,
        .reset_unix_seconds = 1_700_000_060,
    };
    try std.testing.expect(!isTrustworthyPreemptiveRateLimit(api_only));

    const partial: RateLimitInfo = .{
        .source = .registry_rate_limit,
        .remaining = 0,
    };
    try std.testing.expect(!isTrustworthyPreemptiveRateLimit(partial));
}
test "preemptiveRateLimitDelayMs sleeps until reset when remaining is zero" {
    test_policy_now_unix_seconds = 1_700_000_000;
    const info: RateLimitInfo = .{
        .source = .registry_rate_limit,
        .limit = 100,
        .remaining = 0,
        .reset_unix_seconds = 1_700_000_045,
    };
    try std.testing.expectEqual(@as(?u32, 45_000), preemptiveRateLimitDelayMs(true, info, 1_700_000_000, 0));
    try std.testing.expect(preemptiveRateLimitDelayMs(false, info, 1_700_000_000, 0) == null);
    try std.testing.expect(preemptiveRateLimitDelayMs(true, info, 1_700_000_100, 0) == null);
}
test "preemptiveRateLimitDelayMs ignores remaining above threshold" {
    const info: RateLimitInfo = .{
        .source = .registry_rate_limit,
        .limit = 100,
        .remaining = 3,
        .reset_unix_seconds = 1_700_000_045,
    };
    try std.testing.expect(preemptiveRateLimitDelayMs(true, info, 1_700_000_000, 0) == null);
}
test "ManifestThrottle records trustworthy headers and rejects partial API headers" {
    var state: ManifestThrottle = .{};
    const registry_headers = [_]HttpHeader{
        .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
        .{ .name = "RateLimit-Remaining", .value = "0" },
        .{ .name = "RateLimit-Reset", .value = "1700000045" },
    };
    state.recordManifestResponseHeaders(&registry_headers);
    try std.testing.expect(state.prior != null);
    try std.testing.expectEqual(@as(u32, 0), state.prior.?.remaining.?);

    const api_headers = [_]HttpHeader{
        .{ .name = "X-RateLimit-Remaining", .value = "0" },
        .{ .name = "X-RateLimit-Reset", .value = "1700000045" },
        .{ .name = "X-RateLimit-Limit", .value = "180" },
    };
    state.recordManifestResponseHeaders(&api_headers);
    try std.testing.expect(state.prior == null);
}
test "ManifestThrottle sleepBeforeManifestRequestIfNeeded uses transport hooks" {
    const MockHarness = struct {
        var slept_ms: u32 = 0;

        fn sleeper(delay_ms: u32) void {
            slept_ms = delay_ms;
        }
    };
    defer MockHarness.slept_ms = 0;

    test_policy_now_unix_seconds = 1_700_000_000;
    var state: ManifestThrottle = .{
        .prior = .{
            .source = .registry_rate_limit,
            .limit = 100,
            .remaining = 0,
            .reset_unix_seconds = 1_700_000_030,
        },
    };

    var client: std.http.Client = undefined;
    const config = Config{ .rate_limit_enabled = true };
    state.sleepBeforeManifestRequestIfNeeded(config, &client, .{
        .sleeper = MockHarness.sleeper,
        .clock = .{ .now_unix_seconds = testPolicyNowUnixSeconds },
    });
    try std.testing.expectEqual(@as(u32, 30_000), MockHarness.slept_ms);

    state.sleepBeforeManifestRequestIfNeeded(.{ .rate_limit_enabled = false }, &client, .{
        .sleeper = MockHarness.sleeper,
        .clock = .{ .now_unix_seconds = testPolicyNowUnixSeconds },
    });
    try std.testing.expectEqual(@as(u32, 30_000), MockHarness.slept_ms);
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
    const MockHarness = struct {
        var recorded_ms: u32 = 0;

        fn sleeper(delay_ms: u32) void {
            recorded_ms = delay_ms;
        }
    };

    MockHarness.recorded_ms = 0;
    var client: std.http.Client = undefined;
    sleepForTransportRetry(&client, .{ .sleeper = MockHarness.sleeper }, 250);
    try std.testing.expectEqual(@as(u32, 250), MockHarness.recorded_ms);
}
test "readHttpResponseBodyAlloc accepts bodies below the limit" {
    const payload = "abc";
    var reader = std.Io.Reader.fixed(payload);

    const body = try readHttpResponseBodyAlloc(std.testing.allocator, &reader, 4);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(payload, body);
}
test "readHttpResponseBodyAlloc rejects bodies above the limit" {
    const payload = "abcd";
    var reader = std.Io.Reader.fixed(payload);

    try std.testing.expectError(error.BodyTooLarge, readHttpResponseBodyAlloc(std.testing.allocator, &reader, 3));
}
test "readHttpResponseBodyAlloc allocation failures do not leak" {
    const payload = "abc";

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var fixed_reader = std.Io.Reader.fixed(payload);
            const body = try readHttpResponseBodyAlloc(allocator, &fixed_reader, 4);
            defer allocator.free(body);
            try std.testing.expectEqualStrings(payload, body);
        }
    }.run, .{});
}
test "duplicateHttpHeadersAlloc round-trips borrowed headers" {
    const borrowed = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "RateLimit-Remaining", .value = "0" },
    };

    const owned = try duplicateHttpHeadersAlloc(std.testing.allocator, &borrowed);
    defer deinitOwnedHttpHeaders(std.testing.allocator, owned);

    try std.testing.expectEqual(@as(usize, 2), owned.len);
    try std.testing.expectEqualStrings("Retry-After", owned[0].name);
    try std.testing.expectEqualStrings("30", owned[0].value);
    try std.testing.expectEqualStrings("RateLimit-Remaining", owned[1].name);
    try std.testing.expectEqualStrings("0", owned[1].value);
}
test "duplicateHttpHeadersAlloc allocation failures do not leak partial copies" {
    const headers = [_]HttpHeader{
        .{ .name = "Retry-After", .value = "30" },
        .{ .name = "Date", .value = "Thu, 01 May 2025 22:02:18 GMT" },
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const owned = try duplicateHttpHeadersAlloc(allocator, &headers);
            defer deinitOwnedHttpHeaders(allocator, owned);
            try std.testing.expectEqual(@as(usize, 2), owned.len);
        }
    }.run, .{});
}
test "runHttpRetryLoop: transport and HTTP retries stay leak-free under DebugAllocator" {
    const ExchangeError = error{
        ConnectionResetByPeer,
    };

    const TestResponse = struct {
        status: std.http.Status,
        body: ?[]u8 = null,
    };

    const MockHarness = struct {
        var attempts: usize = 0;

        fn exchangeOnce(_: *anyopaque) ExchangeError!TestResponse {
            attempts += 1;
            if (attempts == 1) return error.ConnectionResetByPeer;
            if (attempts == 2) return .{ .status = .service_unavailable };
            return .{ .status = .ok };
        }

        fn responseStatus(response: TestResponse) std.http.Status {
            return response.status;
        }

        fn responseHeaders(_: TestResponse) []const HttpHeader {
            return &.{};
        }

        fn deinitResponse(allocator: std.mem.Allocator, response: TestResponse) void {
            if (response.body) |body| allocator.free(body);
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;
    const transport_hooks = TransportHooks{ .sleeper = noopTransportSleeper };

    for (0..16) |_| {
        MockHarness.attempts = 0;
        var policy = retryPolicyFromConfig(.{ .max_network_retries = 2 }, transport_hooks);
        var loop_ctx: usize = 0;

        const result = runHttpRetryLoop(
            &client,
            transport_hooks,
            &policy,
            .{},
            ExchangeError,
            TestResponse,
            @ptrCast(&loop_ctx),
            struct {
                fn call(ctx_ptr: *anyopaque) ExchangeError!TestResponse {
                    return MockHarness.exchangeOnce(ctx_ptr);
                }
            }.call,
            struct {
                fn call(response: TestResponse) std.http.Status {
                    return MockHarness.responseStatus(response);
                }
            }.call,
            struct {
                fn call(response: TestResponse) []const HttpHeader {
                    return MockHarness.responseHeaders(response);
                }
            }.call,
            struct {
                fn call(alloc: std.mem.Allocator, response: TestResponse) void {
                    MockHarness.deinitResponse(alloc, response);
                }
            }.call,
            allocator,
        );

        switch (result) {
            .ok => |ok| {
                try std.testing.expectEqual(std.http.Status.ok, MockHarness.responseStatus(ok.response));
                try std.testing.expectEqual(@as(usize, 3), MockHarness.attempts);
            },
            else => return error.TestUnexpectedResult,
        }
    }
}
test "runHttpRetryLoop: 429 with Retry-After sleeps then succeeds" {
    const ExchangeError = error{};

    const LoopResponse = struct {
        status: std.http.Status,
        headers: []const HttpHeader = &.{},
    };

    const MockHarness = struct {
        var attempts: usize = 0;
        var sleep_count: usize = 0;
        var last_sleep_ms: u32 = 0;

        const rate_limited_headers = [_]HttpHeader{
            .{ .name = "Retry-After", .value = "30" },
        };

        fn exchangeOnce(_: *anyopaque) ExchangeError!LoopResponse {
            attempts += 1;
            if (attempts == 1) {
                return .{ .status = .too_many_requests, .headers = &rate_limited_headers };
            }
            return .{ .status = .ok };
        }

        fn sleeper(delay_ms: u32) void {
            sleep_count += 1;
            last_sleep_ms = delay_ms;
        }
    };

    MockHarness.attempts = 0;
    MockHarness.sleep_count = 0;
    MockHarness.last_sleep_ms = 0;
    test_policy_now_unix_seconds = 1_700_000_000;

    var client: std.http.Client = undefined;
    const transport_hooks = TransportHooks{
        .sleeper = MockHarness.sleeper,
        .clock = .{ .now_unix_seconds = testPolicyNowUnixSeconds },
    };
    var policy = retryPolicyFromConfig(.{ .max_rate_limit_retries = 1 }, transport_hooks);
    var loop_ctx: usize = 0;

    const result = runHttpRetryLoop(
        &client,
        transport_hooks,
        &policy,
        .{},
        ExchangeError,
        LoopResponse,
        @ptrCast(&loop_ctx),
        struct {
            fn call(ctx_ptr: *anyopaque) ExchangeError!LoopResponse {
                return MockHarness.exchangeOnce(ctx_ptr);
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
        std.testing.allocator,
    );

    switch (result) {
        .ok => |ok| {
            try std.testing.expectEqual(std.http.Status.ok, ok.response.status);
            try std.testing.expectEqual(@as(usize, 2), MockHarness.attempts);
            try std.testing.expectEqual(@as(usize, 1), MockHarness.sleep_count);
            try std.testing.expectEqual(@as(u32, 30_000), MockHarness.last_sleep_ms);
            try std.testing.expectEqual(@as(u8, 1), ok.budget.rate_limit_attempts_used);
        },
        else => return error.TestUnexpectedResult,
    }
}
test "runHttpRetryLoop: malformed Retry-After on 429 uses policy backoff" {
    const ExchangeError = error{};

    const LoopResponse = struct {
        status: std.http.Status,
        headers: []const HttpHeader = &.{},
    };

    const MockHarness = struct {
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

    MockHarness.attempts = 0;
    MockHarness.last_sleep_ms = 0;
    test_policy_random_u64 = 999;

    var client: std.http.Client = undefined;
    const transport_hooks = TransportHooks{
        .sleeper = MockHarness.sleeper,
        .random_u64 = testPolicyRandomU64,
    };
    var policy = retryPolicyFromConfig(.{ .max_rate_limit_retries = 1 }, transport_hooks);
    var loop_ctx: usize = 0;

    const result = runHttpRetryLoop(
        &client,
        transport_hooks,
        &policy,
        .{},
        ExchangeError,
        LoopResponse,
        @ptrCast(&loop_ctx),
        struct {
            fn call(ctx_ptr: *anyopaque) ExchangeError!LoopResponse {
                return MockHarness.exchangeOnce(ctx_ptr);
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
        std.testing.allocator,
    );

    switch (result) {
        .ok => |ok| {
            try std.testing.expectEqual(std.http.Status.ok, ok.response.status);
            try std.testing.expectEqual(@as(usize, 2), MockHarness.attempts);
            try std.testing.expectEqual(@as(u32, 999), MockHarness.last_sleep_ms);
        },
        else => return error.TestUnexpectedResult,
    }
}
test "runHttpRetryLoop: transport give-up returns transport_failed when budget exhausted" {
    const ExchangeError = error{
        ConnectionResetByPeer,
    };

    const LoopResponse = struct {
        status: std.http.Status,
    };

    const MockHarness = struct {
        var attempts: usize = 0;

        fn exchangeOnce(_: *anyopaque) ExchangeError!LoopResponse {
            attempts += 1;
            return error.ConnectionResetByPeer;
        }
    };

    MockHarness.attempts = 0;

    var client: std.http.Client = undefined;
    const transport_hooks = TransportHooks{ .sleeper = noopTransportSleeper };
    var policy = retryPolicyFromConfig(.{ .max_network_retries = 1 }, transport_hooks);
    var loop_ctx: usize = 0;

    const result = runHttpRetryLoop(
        &client,
        transport_hooks,
        &policy,
        .{},
        ExchangeError,
        LoopResponse,
        @ptrCast(&loop_ctx),
        struct {
            fn call(ctx_ptr: *anyopaque) ExchangeError!LoopResponse {
                return MockHarness.exchangeOnce(ctx_ptr);
            }
        }.call,
        struct {
            fn call(_: LoopResponse) std.http.Status {
                return .ok;
            }
        }.call,
        struct {
            fn call(_: LoopResponse) []const HttpHeader {
                return &.{};
            }
        }.call,
        struct {
            fn call(_: std.mem.Allocator, _: LoopResponse) void {}
        }.call,
        std.testing.allocator,
    );

    switch (result) {
        .transport_failed => |failed| {
            try std.testing.expectEqual(error.ConnectionResetByPeer, failed.err);
            try std.testing.expectEqual(@as(usize, 2), MockHarness.attempts);
            try std.testing.expectEqual(@as(u8, 1), failed.budget.network_attempts_used);
        },
        else => return error.TestUnexpectedResult,
    }
}
