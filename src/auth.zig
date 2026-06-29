//! Auth engine for registry token exchange and credential resolution.
//!
//! Live resolve/validate/getManifest traffic probes registries through manifest
//! `HEAD`/`GET` (see `root.zig` auth handoff docs). A `401` with
//! `WWW-Authenticate` triggers bearer challenge parsing, token exchange (GET +
//! POST fallback), credential-provider chain, and per-scope token caching.
//!
//! Docker config (`setDockerConfigBytes`, `loadDockerConfigFromEnvironment`)
//! stores raw JSON and loads registry credentials lazily on first lookup.
//! Parse time builds a registry index (`auths` / `credHelpers` keys and value
//! offsets) so lookups avoid rescanning the full document. Auth decode stays
//! lazy per registry. `validateDockerConfigJson` checks document shape only;
//! per-entry auth validity is enforced at lookup.
//!
//! `AuthError` stays separate from `ResolveError`; the resolver maps auth failures
//! into public `ResolveError` variants at the manifest boundary.
//!
//! Credential ownership (`CredentialHandle`):
//! - Config `CredentialProvider` hits borrow caller-owned slices for the resolve call.
//! - Environment and docker-credential-helper hits dup username/secret onto the engine
//!   allocator and set `release_fn`; call `release()` when the handle is done.
//!   Secrets are zeroed via `freeOwnedOptionalSecretSlice` before `free` (same as
//!   token POST bodies). No automated test proves zero at `free` time.
//! - Docker config inline auth borrows from the engine `auth_cache` until `deinit()`;
//!   `release()` is a no-op for those hits.
const std = @import("std");
const builtin = @import("builtin");
const ConfigModule = @import("Config.zig");
const Config = ConfigModule.Config;
const CredentialHandle = ConfigModule.CredentialHandle;
const CredentialProvider = ConfigModule.CredentialProvider;
const Reference = @import("Reference.zig");
const json = @import("json.zig");
const resilience = @import("resilience.zig");

/// Internal auth error set for token exchange and credential helpers.
///
/// Stays separate from `ResolveError` inside auth. The resolver maps selected
/// variants into public `ResolveError` at manifest boundaries for
/// `resolve`, `validate`, and `getManifest`.
pub const AuthError = error{
    NotYetImplemented,
    OutOfMemory,
    InvalidDockerConfig,
    MissingAuthenticateHeader,
    UnsupportedAuthenticateScheme,
    InvalidAuthenticateHeader,
    UnsupportedProbeStatus,
    InsecureRealmUrl,
    InvalidTokenResponse,
    TokenExchangeFailed,
    RateLimited,
    HelperFailed,
    HelperTimedOut,
    ConnectionResetByPeer,
    Timeout,
    NetworkUnreachable,
    ConnectionRefused,
    UnknownHostName,
};
pub const TokenRequestMethod = enum {
    get,
    post,
};
pub const TokenHttpRequest = struct {
    method: TokenRequestMethod,
    url: []u8,
    authorization: ?[]u8 = null,
    content_type: ?[]const u8 = null,
    body: ?[]u8 = null,
    max_response_body_bytes: usize = ConfigModule.DEFAULT_MAX_TOKEN_RESPONSE_BYTES,

    /// Releases owned URL, authorization, and POST body buffers.
    /// Authorization and body slices are `secureZero`ed before `free` via `freeOwnedOptionalSecretSlice`.
    pub fn deinit(self: TokenHttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        freeOwnedOptionalSecretSlice(allocator, self.authorization);
        freeOwnedOptionalSecretSlice(allocator, self.body);
    }
};
pub const TokenExchangeResponse = struct {
    status: std.http.Status,
    body: []const u8,
    owned_body: ?[]u8 = null,
    resilience_headers: []const resilience.HttpHeader = &.{},
    owned_resilience_headers: ?[]resilience.HttpHeader = null,

    pub fn deinit(self: TokenExchangeResponse, allocator: std.mem.Allocator) void {
        if (self.owned_resilience_headers) |headers| {
            resilience.deinitOwnedHttpHeaders(allocator, headers);
        }
        const owned_body = self.owned_body orelse return;
        std.crypto.secureZero(u8, owned_body);
        allocator.free(owned_body);
    }
};
/// Exchanges a `TokenHttpRequest` for a token response.
///
/// Ownership: the exchanger takes ownership of `request` and must call
/// `request.deinit(allocator)` on every return path, including errors.
/// The engine does not deinit the request after a failed exchange.
pub const TokenHttpExchanger = *const fn (
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: TokenHttpRequest,
) AuthError!TokenExchangeResponse;
pub const ENV_REGISTRY_HOST = "Z_OCI_REGISTRY_HOST";
pub const ENV_REGISTRY_USER = "Z_OCI_REGISTRY_USER";
pub const ENV_REGISTRY_TOKEN = "Z_OCI_REGISTRY_TOKEN";
pub const DOCKER_CONFIG_DIR_VAR = "DOCKER_CONFIG";
pub const HOME_DIR_VAR = "HOME";
pub const USERPROFILE_DIR_VAR = "USERPROFILE";
pub const DOCKER_HUB_AUTH_KEY = "https://index.docker.io/v1/";
pub const DockerCredentialHelperRunner = *const fn (
    allocator: std.mem.Allocator,
    io: std.Io,
    helper_suffix: []const u8,
    server_url: []const u8,
    timeout: std.Io.Timeout,
) AuthError!CredentialHandle;
/// Borrowed Bearer challenge data parsed from the authenticate header.
///
/// These slices borrow from the header input passed to the parser.
/// Request-building code duplicates selected fields before freeing the
/// original header bytes.
pub const BearerChallenge = struct {
    realm: []const u8,
    service: ?[]const u8 = null,
    scope: ?[]const u8 = null,
};
/// Borrowed auth challenge view. Parsed values borrow from the header input.
pub const AuthChallenge = union(enum) {
    bearer: BearerChallenge,
    other: []const u8,
};
pub const ProbeResult = union(enum) {
    ok,
    auth_required: AuthChallenge,
    not_found,
};
pub const Token = struct {
    /// Borrowed token bytes for transient auth operations.
    ///
    /// The token cache does not store this struct directly; cached entries own
    /// their token bytes through `CachedToken.initOwned`.
    value: []const u8,
    expires_in_seconds: ?u64 = null,
};
pub const TOKEN_REFRESH_WINDOW_SECONDS: u64 = 5;
pub const DEFAULT_TOKEN_CACHE_TTL_SECONDS: u64 = 60;
pub const TokenResponse = struct {
    /// Owned token-response payload.
    access_token: Token,
    /// Explicit non-goal for `v0.2.0`; parsed only so later phases can choose
    /// to ignore or surface it deliberately.
    refresh_token: ?[]const u8 = null,
    /// When false, `access_token.value` is borrowed from the engine token cache.
    /// The borrow is valid only while that cache entry remains and before
    /// `AuthEngine.deinit()`. Do not retain the response across another
    /// `authenticate()` for the same `realm + service + scope`.
    /// `deinit()` does not free or zero borrowed bytes.
    owns_access_token: bool = true,

    pub fn deinit(self: *TokenResponse, allocator: std.mem.Allocator) void {
        if (self.owns_access_token) {
            std.crypto.secureZero(u8, @constCast(self.access_token.value));
            allocator.free(self.access_token.value);
        }
        if (self.refresh_token) |refresh_token| {
            std.crypto.secureZero(u8, @constCast(refresh_token));
            allocator.free(refresh_token);
        }
    }
};
/// Owned cache lookup key.
///
/// `realm`, `service`, and `scope` are duplicated onto the caller-owned
/// allocator when the key is constructed for cached storage.
pub const TokenCacheKey = struct {
    realm: []const u8,
    service: ?[]const u8 = null,
    scope: ?[]const u8 = null,

    pub fn initOwned(
        allocator: std.mem.Allocator,
        realm: []const u8,
        service: ?[]const u8,
        scope: ?[]const u8,
    ) !TokenCacheKey {
        const owned_realm = try allocator.dupe(u8, realm);
        errdefer allocator.free(owned_realm);

        const owned_service = if (service) |s|
            try allocator.dupe(u8, s)
        else
            null;
        errdefer if (owned_service) |s| allocator.free(s);

        const owned_scope = if (scope) |s|
            try allocator.dupe(u8, s)
        else
            null;
        errdefer if (owned_scope) |s| allocator.free(s);

        return .{
            .realm = owned_realm,
            .service = owned_service,
            .scope = owned_scope,
        };
    }

    pub fn initOwnedFromRequest(
        allocator: std.mem.Allocator,
        request: AuthenticateRequest,
    ) !TokenCacheKey {
        return initOwned(allocator, request.challenge.realm, request.service(), request.scope());
    }

    pub fn deinit(self: *TokenCacheKey, allocator: std.mem.Allocator) void {
        allocator.free(self.realm);
        if (self.service) |s| allocator.free(s);
        if (self.scope) |s| allocator.free(s);
    }
};
/// Owned cached token storage.
///
/// Unlike `Token`, this storage owns its token bytes. `deinit()` zeroes the
/// token before freeing it from the caller-owned allocator.
pub const CachedToken = struct {
    token: Token,
    valid_until_unix_seconds: ?u64 = null,
    last_used_unix_seconds: u64 = 0,

    pub fn initOwned(
        allocator: std.mem.Allocator,
        token: Token,
        valid_until_unix_seconds: ?u64,
    ) !CachedToken {
        return .{
            .token = .{
                .value = try allocator.dupe(u8, token.value),
                .expires_in_seconds = token.expires_in_seconds,
            },
            .valid_until_unix_seconds = valid_until_unix_seconds,
        };
    }

    pub fn deinit(self: *CachedToken, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, @constCast(self.token.value));
        allocator.free(self.token.value);
    }
};
/// Narrow auth-facing view of `Config`.
///
/// Live today: credentials, helper `read_timeout_ms`, cached-401 auth retry
/// (`max_retries`), transport retry budgets on token HTTP (via resilience), and
/// `ca_bundle_path` via `Config.applyToClient` at the public API boundary.
/// Pre-emptive rate limiting (`rate_limit_enabled`) applies on manifest transport
/// via resolver `ResolverParams.manifest_throttle`.
pub const AuthConfigView = struct {
    credential_provider: ?*const CredentialProvider,
    connect_timeout_ms: u32,
    read_timeout_ms: u32,
    ca_bundle_path: ?[]const u8,
    env_registry_host: []const u8 = ENV_REGISTRY_HOST,
    env_registry_user: []const u8 = ENV_REGISTRY_USER,
    env_registry_token: []const u8 = ENV_REGISTRY_TOKEN,
};
/// Borrowed view of the normalized reference data auth consumes.
///
/// This codifies the Phase 1/Phase 2 boundary: auth does not re-parse raw
/// image strings. It uses the canonical registry, repository path, and ref
/// string already produced by `Reference.parse`.
///
/// Phase 3 handoff contract:
/// - manifest resolution derives this view exactly once from the caller-owned
///   `Reference`
/// - auth only consumes the borrowed normalized fields in this view; it does
///   not mutate or retain the `Reference`
/// - `registry` is the registry identity used for credential lookup
/// - `repository_path` and `ref_string` stay under resolver ownership for
///   manifest URLs and follow-up HEAD/GET requests
pub const AuthReferenceView = struct {
    registry: []const u8,
    repository_path: []const u8,
    ref_string: []const u8,

    pub fn probeUriAlloc(self: AuthReferenceView, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "https://{s}/v2/", .{self.registry});
    }
};
pub const AuthenticateRequest = struct {
    registry: []const u8,
    challenge: BearerChallenge,

    /// Build the auth request Phase 3 passes into token exchange.
    ///
    /// Contract:
    /// - `registry` must be the normalized registry host from `AuthReferenceView`
    /// - `challenge` must come from a `401` bearer challenge on the target
    ///   registry or token-requiring manifest request
    /// - the request borrows its inputs; callers keep the challenge/header
    ///   storage alive for the duration of `authenticate()`
    pub fn init(registry: []const u8, challenge: BearerChallenge) AuthError!AuthenticateRequest {
        try validateRealmUrl(challenge.realm);
        return .{
            .registry = registry,
            .challenge = challenge,
        };
    }

    pub fn scope(self: AuthenticateRequest) ?[]const u8 {
        return self.challenge.scope;
    }

    pub fn service(self: AuthenticateRequest) ?[]const u8 {
        return self.challenge.service;
    }
};
pub const ProbeHttpResponse = struct {
    status: std.http.Status,
    www_authenticate_headers: []const []const u8 = &.{},

    /// Classify a registry probe or manifest response for Phase 3.
    ///
    /// Contract:
    /// - `.ok` means the registry/manifest request succeeded without an auth
    ///   challenge and resolver code should continue anonymously
    /// - `.auth_required` yields the bearer challenge Phase 3 turns into an
    ///   `AuthenticateRequest`
    /// - `.not_found` is a terminal resolution result and must not be retried
    ///   through auth
    pub fn classify(self: ProbeHttpResponse) AuthError!ProbeResult {
        return classifyProbeResponse(self.status, self.www_authenticate_headers);
    }
};
// --- Auth engine ---

/// Explicit process boundary for helper execution.
///
/// `std.http.Client` already owns the `std.Io` it needs for network requests in
/// Zig 0.16. Docker credential helpers are different: `std.process.spawn`,
/// `child.wait`, and `child.kill` need an explicit `std.Io` boundary. Keeping
/// that context separate lets `authenticate()` stay provisional without forcing
/// `io` through every auth call immediately.
pub const DockerHelperConfig = struct {
    io: std.Io,
    runner: DockerCredentialHelperRunner = runDockerCredentialHelperBySuffix,
};
/// Phase 2 auth engine.
///
/// HTTP requests carry `io` through `std.http.Client`. Helper execution
/// passes an explicit `std.Io` boundary through `DockerHelperConfig`.
pub const AuthEngine = struct {
    allocator: std.mem.Allocator,
    config: Config,
    docker_helper_config: ?DockerHelperConfig = null,
    token_http_exchanger: ?TokenHttpExchanger = null,
    transport_hooks: resilience.TransportHooks = .{},
    now_unix_seconds_fn: NowUnixSecondsFn = currentUnixSeconds,
    environ_map: ?*const std.process.Environ.Map = null,
    docker_config: ?DockerConfig = null,
    /// Per-scope token cache with TTL expiry and LRU eviction at
    /// `config.max_token_cache_entries`.
    ///
    /// Cache identity: realm + service + scope. Entries older than
    /// valid_until_unix_seconds (accounting for the fixed refresh window)
    /// are dropped on lookup.
    token_cache: TokenCacheMap = .empty,
    preferred_token_method_by_realm: std.StringHashMapUnmanaged(TokenRequestMethod) = .{},

    pub fn init(allocator: std.mem.Allocator, config: Config) AuthEngine {
        return .{
            .allocator = allocator,
            .config = config,
            .now_unix_seconds_fn = currentUnixSeconds,
        };
    }

    pub fn initWithDockerHelperConfig(
        allocator: std.mem.Allocator,
        config: Config,
        docker_helper_config: DockerHelperConfig,
    ) AuthEngine {
        return .{
            .allocator = allocator,
            .config = config,
            .docker_helper_config = docker_helper_config,
            .now_unix_seconds_fn = currentUnixSeconds,
        };
    }

    pub fn initWithTokenHttpExchanger(
        allocator: std.mem.Allocator,
        config: Config,
        token_http_exchanger: TokenHttpExchanger,
    ) AuthEngine {
        return initWithTokenHttpExchangerAndHooks(allocator, config, token_http_exchanger, .{});
    }

    /// `config` must match `ResolverParams.config` on the same public API call.
    pub fn initWithTokenHttpExchangerAndHooks(
        allocator: std.mem.Allocator,
        config: Config,
        token_http_exchanger: TokenHttpExchanger,
        transport_hooks: resilience.TransportHooks,
    ) AuthEngine {
        return .{
            .allocator = allocator,
            .config = config,
            .token_http_exchanger = token_http_exchanger,
            .transport_hooks = transport_hooks,
            .now_unix_seconds_fn = currentUnixSeconds,
        };
    }

    pub fn initWithTokenHttpExchangerLive(
        allocator: std.mem.Allocator,
        config: Config,
        token_http_exchanger: TokenHttpExchanger,
    ) AuthEngine {
        return initWithTokenHttpExchangerAndHooks(
            allocator,
            config,
            token_http_exchanger,
            resilience.liveTransportHooks(),
        );
    }

    pub fn initWithEnvironmentMap(
        allocator: std.mem.Allocator,
        config: Config,
        environ_map: *const std.process.Environ.Map,
    ) AuthEngine {
        return .{
            .allocator = allocator,
            .config = config,
            .environ_map = environ_map,
            .now_unix_seconds_fn = currentUnixSeconds,
        };
    }

    pub fn initWithDockerConfigBytes(
        allocator: std.mem.Allocator,
        config: Config,
        docker_config_json: []const u8,
    ) AuthError!AuthEngine {
        var engine = init(allocator, config);
        try engine.setDockerConfigBytes(docker_config_json);
        return engine;
    }

    pub fn deinit(self: *AuthEngine) void {
        var it = self.token_cache.iterator();
        while (it.next()) |entry| {
            var key = entry.key_ptr.*;
            key.deinit(self.allocator);
            var cached_token = entry.value_ptr.*;
            cached_token.deinit(self.allocator);
        }
        self.token_cache.deinit(self.allocator);

        var preferred_methods = self.preferred_token_method_by_realm.iterator();
        while (preferred_methods.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.preferred_token_method_by_realm.deinit(self.allocator);

        if (self.docker_config) |*docker_config| {
            docker_config.deinit(self.allocator);
            self.docker_config = null;
        }
    }

    pub fn setDockerConfigBytes(self: *AuthEngine, docker_config_json: []const u8) AuthError!void {
        const docker_config = try parseDockerConfig(self.allocator, docker_config_json);

        if (self.docker_config) |*existing| existing.deinit(self.allocator);
        self.docker_config = docker_config;
    }

    pub fn loadDockerConfigFromEnvironment(self: *AuthEngine, io: std.Io) AuthError!bool {
        const environ_map = self.environ_map orelse return false;
        const config_path = try dockerConfigPathFromEnvironmentAlloc(self.allocator, environ_map) orelse return false;
        defer self.allocator.free(config_path);

        const docker_config_json = std.Io.Dir.cwd().readFileAlloc(
            io,
            config_path,
            self.allocator,
            .limited(DOCKER_CONFIG_FILE_SIZE_LIMIT),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return false,
        };
        defer {
            std.crypto.secureZero(u8, docker_config_json);
            self.allocator.free(docker_config_json);
        }

        try self.setDockerConfigBytes(docker_config_json);
        return true;
    }

    pub fn dockerHelperConfig(self: AuthEngine) ?DockerHelperConfig {
        return self.docker_helper_config;
    }

    pub fn configView(self: AuthEngine) AuthConfigView {
        return authConfigView(self.config);
    }

    /// Exchange a bearer token for a single normalized registry/challenge pair.
    ///
    /// Phase 3 handoff contract:
    /// - call this only after a registry or manifest request returns a bearer
    ///   challenge that has been classified into an `AuthenticateRequest`
    /// - credential precedence is explicit config provider -> env -> Docker
    ///   config/helper -> anonymous token request
    /// - helper failures and helper timeouts are terminal; auth does not silently
    ///   downgrade them to anonymous requests
    /// - successful responses borrow the cached access token
    ///   (`owns_access_token == false`); call `deinit()` to release any owned
    ///   refresh token only. The access token borrow is invalidated by
    ///   `AuthEngine.deinit()`, cache eviction, or another auth call that
    ///   replaces the same `realm + service + scope` entry
    /// - successful responses are cached inside the engine by
    ///   `realm + service + scope` for reuse across later manifest requests
    pub fn authenticate(
        self: *AuthEngine,
        client: *std.http.Client,
        request: AuthenticateRequest,
    ) AuthError!?TokenResponse {
        _ = self.token_http_exchanger orelse return error.NotYetImplemented;
        try validateRealmUrl(request.challenge.realm);

        if (try self.cachedTokenResponseForRequest(client, request)) |cached_response| {
            return cached_response;
        }

        const credential_handle = try self.credentialForRegistryForAuth(request.registry);
        defer if (credential_handle) |handle| handle.release();

        const credential = if (credential_handle) |handle| handle.credential else null;
        var token_response = try self.exchangeTokenResponse(client, request, credential);
        self.storeTokenResponseForRequest(client, request, &token_response) catch |err| {
            token_response.deinit(self.allocator);
            return err;
        };
        if (token_response.refresh_token) |refresh_token| {
            std.crypto.secureZero(u8, @constCast(refresh_token));
            self.allocator.free(refresh_token);
            token_response.refresh_token = null;
        }
        return self.borrowedCachedTokenResponseForRequest(request) orelse error.TokenExchangeFailed;
    }

    /// Retry auth exactly once after an upstream request rejects a cached token.
    ///
    /// Phase 3 handoff contract:
    /// - call this only after the resolver already used a bearer token from this
    ///   engine for the same `AuthenticateRequest` and the registry responded
    ///   `401 Unauthorized`
    /// - retry scope is exact-key only: auth invalidates the cached entry for the
    ///   same `realm + service + scope` and leaves unrelated cached tokens intact
    /// - when `config.max_retries == 0`, this returns `error.TokenExchangeFailed`
    ///   and Phase 3 must surface the auth failure instead of looping
    /// - the returned response follows the same ownership rules as `authenticate()`
    pub fn retryAuthenticateAfterCachedUnauthorized(
        self: *AuthEngine,
        client: *std.http.Client,
        request: AuthenticateRequest,
    ) AuthError!?TokenResponse {
        if (self.config.max_retries == 0) return error.TokenExchangeFailed;
        _ = try self.invalidateCachedTokenForRequest(request);
        return try self.authenticate(client, request);
    }

    fn cachedTokenResponseForRequest(self: *AuthEngine, client: *std.http.Client, request: AuthenticateRequest) AuthError!?TokenResponse {
        const entry = self.token_cache.getPtrAdapted(request, TokenCacheRequestContext{}) orelse return null;
        if (self.cachedTokenIsExpired(client, entry.*)) {
            _ = self.removeCachedTokenForRequest(request);
            return null;
        }

        entry.last_used_unix_seconds = self.now_unix_seconds_fn(client);
        return borrowedCachedTokenResponse(entry.*);
    }

    fn borrowedCachedTokenResponseForRequest(self: *AuthEngine, request: AuthenticateRequest) ?TokenResponse {
        const entry = self.token_cache.getPtrAdapted(request, TokenCacheRequestContext{}) orelse return null;
        return borrowedCachedTokenResponse(entry.*);
    }

    fn exchangeTokenResponse(
        self: *AuthEngine,
        client: *std.http.Client,
        request: AuthenticateRequest,
        credential: ?ConfigModule.Credential,
    ) AuthError!TokenResponse {
        const methods = preferredTokenMethodsForRealm(self, request.challenge.realm);

        var saw_rate_limited = false;
        var saw_non_rate_limited_failure = false;
        for (methods) |method| {
            const response = try exchangeTokenHttpRequestWithRetries(
                self,
                client,
                request,
                method,
                credential,
            );
            defer response.deinit(self.allocator);
            if (response.status == .too_many_requests) {
                saw_rate_limited = true;
                continue;
            }
            if (response.status != .ok) {
                saw_non_rate_limited_failure = true;
                continue;
            }

            try rememberPreferredTokenMethod(self, request.challenge.realm, method);
            return try parseTokenResponse(self.allocator, response.body);
        }

        if (saw_rate_limited and !saw_non_rate_limited_failure) return error.RateLimited;
        return error.TokenExchangeFailed;
    }

    fn rememberPreferredTokenMethod(
        self: *AuthEngine,
        realm: []const u8,
        method: TokenRequestMethod,
    ) AuthError!void {
        const gop = try self.preferred_token_method_by_realm.getOrPut(self.allocator, realm);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, realm);
        }
        gop.value_ptr.* = method;
    }

    fn exchangeTokenHttpRequestWithRetries(
        self: *AuthEngine,
        client: *std.http.Client,
        request: AuthenticateRequest,
        method: TokenRequestMethod,
        credential: ?ConfigModule.Credential,
    ) AuthError!TokenExchangeResponse {
        if (self.token_http_exchanger == null) return error.NotYetImplemented;
        var policy = resilience.retryPolicyFromConfig(self.config, self.transport_hooks);

        var loop_ctx = TokenExchangeLoop{
            .engine = self,
            .client = client,
            .request = request,
            .method = method,
            .credential = credential,
        };
        defer {
            const allocator = self.allocator;
            if (loop_ctx.cached_url) |url| allocator.free(url);
            if (loop_ctx.cached_authorization) |authorization| {
                std.crypto.secureZero(u8, authorization);
                allocator.free(authorization);
            }
            if (loop_ctx.cached_body) |body| allocator.free(body);
        }

        const loop_outcome = resilience.runHttpRetryLoop(
            client,
            self.transport_hooks,
            &policy,
            .{},
            AuthError,
            TokenExchangeResponse,
            @ptrCast(&loop_ctx),
            tokenExchangeOnceOpaque,
            tokenExchangeResponseStatus,
            tokenExchangeResponseHeaders,
            deinitTokenExchangeResponse,
            self.allocator,
        );

        return switch (loop_outcome) {
            .ok => |ok| ok.response,
            .transport_failed => |failure| failure.err,
        };
    }

    fn cachedTokenIsExpired(self: *AuthEngine, client: *std.http.Client, cached_token: CachedToken) bool {
        const valid_until = cached_token.valid_until_unix_seconds orelse return true;
        return valid_until <= self.now_unix_seconds_fn(client);
    }

    fn storeTokenResponseForRequest(
        self: *AuthEngine,
        client: *std.http.Client,
        request: AuthenticateRequest,
        token_response: *TokenResponse,
    ) AuthError!void {
        var key = try TokenCacheKey.initOwnedFromRequest(self.allocator, request);
        errdefer key.deinit(self.allocator);

        const gop = try self.token_cache.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            key.deinit(self.allocator);
            var old_token = gop.value_ptr.*;
            old_token.deinit(self.allocator);
        }

        const now = self.now_unix_seconds_fn(client);
        gop.value_ptr.* = cachedTokenFromResponse(token_response, now, DEFAULT_TOKEN_CACHE_TTL_SECONDS);
        self.evictLruTokenCacheEntriesUntilWithinLimit();
    }

    fn evictLruTokenCacheEntriesUntilWithinLimit(self: *AuthEngine) void {
        const limit = self.config.max_token_cache_entries;
        if (limit == 0) return;

        while (self.token_cache.count() > limit) {
            var victim_key: ?TokenCacheKey = null;
            var victim_last_used: u64 = std.math.maxInt(u64);

            var it = self.token_cache.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.last_used_unix_seconds <= victim_last_used) {
                    victim_last_used = entry.value_ptr.last_used_unix_seconds;
                    victim_key = entry.key_ptr.*;
                }
            }

            const key = victim_key orelse break;
            const removed = self.token_cache.fetchRemove(key) orelse break;
            var removed_key = removed.key;
            removed_key.deinit(self.allocator);
            var removed_token = removed.value;
            removed_token.deinit(self.allocator);
        }
    }

    fn invalidateCachedTokenForRequest(self: *AuthEngine, request: AuthenticateRequest) AuthError!bool {
        return self.removeCachedTokenForRequest(request);
    }

    fn removeCachedTokenForRequest(self: *AuthEngine, request: AuthenticateRequest) bool {
        const removed = self.token_cache.fetchRemoveAdapted(request, TokenCacheRequestContext{}) orelse return false;
        var key = removed.key;
        key.deinit(self.allocator);
        var cached_token = removed.value;
        cached_token.deinit(self.allocator);
        return true;
    }

    fn credentialForRegistryForAuth(self: *AuthEngine, registry: []const u8) AuthError!?CredentialHandle {
        if (self.config.credential_provider) |provider| {
            if (provider.getCredential(registry)) |handle| return handle;
        }

        if (self.environ_map) |environ_map| {
            if (try envCredentialForRegistry(self.allocator, environ_map, registry)) |handle| return handle;
        }

        return try self.dockerCredentialForRegistry(registry);
    }

    /// Resolve credentials for `registry` in provider order: config provider,
    /// environment map, then lazy docker config auth.
    ///
    /// `self` must be the live engine (pointer required so docker config cache
    /// updates stay on the same `AuthEngine` instance).
    ///
    /// Environment and helper hits dup username/secret onto the engine allocator
    /// and require `release()`. Docker config inline auth borrows from the engine's
    /// `auth_cache` until `deinit()`; `release()` is a no-op for those hits.
    ///
    /// Environment or docker-config allocation failure returns `OutOfMemory`.
    /// Malformed docker config auth for the requested registry returns `null`
    /// here (not `InvalidDockerConfig`). Use `authenticate()` when auth errors
    /// must propagate.
    pub fn credentialForRegistry(self: *AuthEngine, registry: []const u8) AuthError!?CredentialHandle {
        if (self.config.credential_provider) |provider| {
            if (provider.getCredential(registry)) |handle| return handle;
        }

        if (self.environ_map) |environ_map| {
            if (try envCredentialForRegistry(self.allocator, environ_map, registry)) |handle| return handle;
        }

        if (self.docker_config) |*docker_config| {
            if (try docker_config.credentialForRegistry(self.allocator, registry)) |handle| return handle;
        }

        return null;
    }

    fn dockerCredentialForRegistry(self: *AuthEngine, registry: []const u8) AuthError!?CredentialHandle {
        if (self.docker_config == null) return null;
        const docker_config = &self.docker_config.?;
        const helper_timeout = dockerCredentialHelperTimeout(self.config);

        if (self.docker_helper_config) |context| {
            if (try docker_config.registrySpecificHelperLookupForRegistry(self.allocator, registry)) |helper_lookup| {
                const helper_server = try canonicalDockerCredentialHelperServerAlloc(self.allocator, helper_lookup.server_url);
                defer self.allocator.free(helper_server);
                return try context.runner(self.allocator, context.io, helper_lookup.helper_suffix, helper_server, helper_timeout);
            }
        }

        if (try docker_config.authCredentialForRegistry(self.allocator, registry)) |credential| {
            return .{ .credential = credential };
        }

        if (self.docker_helper_config) |context| {
            if (try docker_config.globalHelperLookupForRegistry(self.allocator, registry)) |helper_lookup| {
                const helper_server = try canonicalDockerCredentialHelperServerAlloc(self.allocator, helper_lookup.server_url);
                defer self.allocator.free(helper_server);
                return try context.runner(self.allocator, context.io, helper_lookup.helper_suffix, helper_server, helper_timeout);
            }
        }

        return null;
    }
};
// --- Credential and token request helpers ---

pub fn authConfigView(config: Config) AuthConfigView {
    return .{
        .credential_provider = config.credential_provider,
        .connect_timeout_ms = config.connect_timeout_ms,
        .read_timeout_ms = config.read_timeout_ms,
        .ca_bundle_path = config.ca_bundle_path,
    };
}
pub fn envCredentialForRegistry(
    allocator: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
    registry: []const u8,
) AuthError!?CredentialHandle {
    const host = environ_map.get(ENV_REGISTRY_HOST) orelse return null;
    if (!registryHostMatches(host, registry)) return null;

    const username = environ_map.get(ENV_REGISTRY_USER) orelse return null;
    const token = environ_map.get(ENV_REGISTRY_TOKEN) orelse return null;
    if (username.len == 0 or token.len == 0) return null;

    return try ownedCredentialHandle(allocator, username, token);
}
pub fn referenceView(ref: Reference) AuthReferenceView {
    return .{
        .registry = ref.registry,
        .repository_path = ref.repositoryPath(),
        .ref_string = ref.refString(),
    };
}
pub fn buildTokenHttpRequest(
    allocator: std.mem.Allocator,
    request: AuthenticateRequest,
    method: TokenRequestMethod,
    credential: ?ConfigModule.Credential,
) AuthError!TokenHttpRequest {
    try validateRealmUrl(request.challenge.realm);

    const query = try buildTokenQueryAlloc(allocator, request);
    defer allocator.free(query);

    const url = switch (method) {
        .get => if (query.len == 0)
            try allocator.dupe(u8, request.challenge.realm)
        else
            try std.fmt.allocPrint(allocator, "{s}?{s}", .{ request.challenge.realm, query }),
        .post => try allocator.dupe(u8, request.challenge.realm),
    };
    errdefer allocator.free(url);

    const authorization = if (credential) |cred|
        try buildBasicAuthorizationAlloc(allocator, cred)
    else
        null;
    errdefer if (authorization) |header| allocator.free(header);

    const body = switch (method) {
        .get => null,
        .post => try allocator.dupe(u8, query),
    };

    return .{
        .method = method,
        .url = url,
        .authorization = authorization,
        .content_type = if (method == .post) "application/x-www-form-urlencoded" else null,
        .body = body,
    };
}
pub fn buildTokenQueryAlloc(allocator: std.mem.Allocator, request: AuthenticateRequest) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    var first = true;
    if (request.service()) |service| {
        writeFormField(&aw.writer, &first, "service", service) catch return error.OutOfMemory;
    }
    if (request.scope()) |scope| {
        var scope_it = std.mem.tokenizeAny(u8, scope, " \t");
        while (scope_it.next()) |scope_entry| {
            writeFormField(&aw.writer, &first, "scope", scope_entry) catch return error.OutOfMemory;
        }
    }

    return aw.toOwnedSlice() catch return error.OutOfMemory;
}
pub fn buildBasicAuthorizationAlloc(allocator: std.mem.Allocator, credential: ConfigModule.Credential) ![]u8 {
    const joined = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ credential.username, credential.secret });
    defer {
        std.crypto.secureZero(u8, joined);
        allocator.free(joined);
    }

    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(joined.len);
    const buffer = try allocator.alloc(u8, "Basic ".len + encoded_len);
    errdefer allocator.free(buffer);

    @memcpy(buffer[0.."Basic ".len], "Basic ");
    _ = encoder.encode(buffer["Basic ".len..], joined);
    return buffer;
}
/// Live HTTP exchanger for token requests using Zig 0.16 `std.http.Client`.
pub fn liveTokenHttpExchanger(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: TokenHttpRequest,
) AuthError!TokenExchangeResponse {
    defer request.deinit(allocator);

    const uri = std.Uri.parse(request.url) catch return error.TokenExchangeFailed;

    var http_request = client.request(
        switch (request.method) {
            .get => .GET,
            .post => .POST,
        },
        uri,
        .{
            .headers = .{
                .authorization = if (request.authorization) |authorization|
                    .{ .override = authorization }
                else
                    .default,
                .content_type = if (request.content_type) |content_type|
                    .{ .override = content_type }
                else
                    .default,
            },
        },
    ) catch |err| return mapLiveTokenTransportError(err);
    defer http_request.deinit();

    if (request.body) |body| {
        http_request.transfer_encoding = .{ .content_length = body.len };
        var req_body = http_request.sendBodyUnflushed(&.{}) catch |err| return mapLiveTokenTransportError(err);
        req_body.writer.writeAll(body) catch |err| return mapLiveTokenTransportError(err);
        req_body.end() catch |err| return mapLiveTokenTransportError(err);
        http_request.connection.?.flush() catch |err| return mapLiveTokenTransportError(err);
    } else {
        http_request.sendBodiless() catch |err| return mapLiveTokenTransportError(err);
    }

    var head_buffer: [8 * 1024]u8 = undefined;
    var response = http_request.receiveHead(&head_buffer) catch |err| return mapLiveTokenTransportError(err);

    var resilience_headers = std.ArrayList(resilience.HttpHeader).empty;
    errdefer {
        resilience.deinitOwnedHttpHeaders(allocator, resilience_headers.items);
        resilience_headers.deinit(allocator);
    }

    var header_it = response.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (!resilience.isTrackedResilienceHeaderName(header.name)) continue;
        try resilience_headers.append(allocator, .{
            .name = try allocator.dupe(u8, header.name),
            .value = try allocator.dupe(u8, header.value),
        });
    }

    const owned_body = resilience.readHttpResponseBodyAlloc(allocator, response.reader(&.{}), request.max_response_body_bytes) catch |err| return mapLiveTokenTransportError(err);

    const owned_headers = try resilience_headers.toOwnedSlice(allocator);
    return .{
        .status = response.head.status,
        .body = owned_body,
        .owned_body = owned_body,
        .resilience_headers = owned_headers,
        .owned_resilience_headers = owned_headers,
    };
}
pub fn parseTokenResponse(allocator: std.mem.Allocator, body: []const u8) AuthError!TokenResponse {
    const parsed = json.parse(ParsedTokenBody, allocator, body) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidTokenResponse,
    };
    defer parsed.deinit();

    const token_value = tokenValueFromParsedBody(parsed.value) orelse return error.InvalidTokenResponse;
    if (token_value.len == 0) return error.InvalidTokenResponse;

    const expires_in_seconds: ?u64 = if (parsed.value.expires_in) |expires_in| blk: {
        if (expires_in == 0 or expires_in > std.math.maxInt(u32)) return error.InvalidTokenResponse;
        break :blk expires_in;
    } else null;

    if (parsed.value.refresh_token) |refresh_token| {
        if (refresh_token.len == 0) return error.InvalidTokenResponse;
    }

    const access_token_value = try allocator.dupe(u8, token_value);
    errdefer {
        std.crypto.secureZero(u8, access_token_value);
        allocator.free(access_token_value);
    }

    const owned_refresh_token = if (parsed.value.refresh_token) |refresh_token|
        try allocator.dupe(u8, refresh_token)
    else
        null;

    return .{
        .access_token = .{
            .value = access_token_value,
            .expires_in_seconds = expires_in_seconds,
        },
        .refresh_token = owned_refresh_token,
    };
}
pub fn classifyProbeResponse(
    status: std.http.Status,
    www_authenticate_headers: []const []const u8,
) AuthError!ProbeResult {
    return switch (status) {
        .ok => .ok,
        .unauthorized => .{ .auth_required = try parseAuthenticateHeaders(www_authenticate_headers) },
        .not_found => .not_found,
        else => error.UnsupportedProbeStatus,
    };
}
pub fn parseAuthenticateHeaders(raw_headers: []const []const u8) AuthError!AuthChallenge {
    if (raw_headers.len == 0) return error.MissingAuthenticateHeader;

    var saw_unsupported = false;
    for (raw_headers) |raw| {
        const challenge = parseAuthenticateHeader(raw) catch |err| switch (err) {
            error.UnsupportedAuthenticateScheme => {
                saw_unsupported = true;
                continue;
            },
            else => |parse_err| return parse_err,
        };

        return challenge;
    }

    if (saw_unsupported) return error.UnsupportedAuthenticateScheme;
    return error.MissingAuthenticateHeader;
}
pub fn parseAuthenticateHeader(raw: []const u8) AuthError!AuthChallenge {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return error.MissingAuthenticateHeader;

    var cursor: usize = 0;
    while (cursor < trimmed.len) {
        const next_challenge = try findNextChallengeStart(trimmed, cursor);
        const end = next_challenge orelse trimmed.len;
        const chunk = std.mem.trim(u8, trimmed[cursor..end], " \t,");
        if (chunk.len == 0) return error.InvalidAuthenticateHeader;

        const challenge = try parseChallengeChunk(chunk);
        if (challenge == .bearer) return challenge;

        cursor = next_challenge orelse break;
    }

    return error.UnsupportedAuthenticateScheme;
}

// --- Private helpers ---

fn freeOwnedOptionalSecretSlice(allocator: std.mem.Allocator, bytes: ?[]u8) void {
    const slice = bytes orelse return;
    std.crypto.secureZero(u8, slice);
    if (builtin.is_test) {
        for (slice) |byte| std.debug.assert(byte == 0);
    }
    allocator.free(slice);
}
const DOCKER_CONFIG_FILE_SIZE_LIMIT = 1024 * 1024;
const DOCKER_HELPER_STDOUT_LIMIT = 64 * 1024;
const DOCKER_HELPER_STDERR_LIMIT = 64 * 1024;
const ParsedDockerCredentialHelperResponse = struct {
    Username: ?[]const u8 = null,
    Secret: ?[]const u8 = null,
};
const DockerCredentialHelperLookup = struct {
    server_url: []const u8,
    helper_suffix: []const u8,
};
const DockerCredentialSource = union(enum) {
    auth: ConfigModule.Credential,
    helper: DockerCredentialHelperLookup,
};
const DockerConfigSection = enum { auths, cred_helpers };
const DockerConfigIndexedRegistry = struct {
    section: DockerConfigSection,
    config_key: []u8,
    value_offset: usize,

    fn deinit(self: DockerConfigIndexedRegistry, allocator: std.mem.Allocator) void {
        allocator.free(self.config_key);
    }
};
const DockerConfig = struct {
    owned_json: []u8,
    registry_entries: std.ArrayListUnmanaged(DockerConfigIndexedRegistry) = .empty,
    exact_registry_entry: std.StringHashMapUnmanaged(usize) = .empty,
    creds_store: ?[]const u8 = null,
    creds_store_resolved: bool = false,
    auth_cache: std.StringHashMapUnmanaged(ConfigModule.Credential) = .empty,
    helper_suffix_cache: std.StringHashMapUnmanaged([]const u8) = .empty,

    fn deinit(self: *DockerConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.owned_json);

        for (self.registry_entries.items) |entry| entry.deinit(allocator);
        self.registry_entries.deinit(allocator);

        var exact_it = self.exact_registry_entry.iterator();
        while (exact_it.next()) |entry| allocator.free(entry.key_ptr.*);
        self.exact_registry_entry.deinit(allocator);

        var auth_it = self.auth_cache.iterator();
        while (auth_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.username);
            std.crypto.secureZero(u8, @constCast(entry.value_ptr.secret));
            allocator.free(entry.value_ptr.secret);
        }
        self.auth_cache.deinit(allocator);

        var helper_it = self.helper_suffix_cache.iterator();
        while (helper_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.helper_suffix_cache.deinit(allocator);

        if (self.creds_store) |creds_store| allocator.free(creds_store);
    }

    fn credentialForRegistry(self: *DockerConfig, allocator: std.mem.Allocator, registry: []const u8) AuthError!?CredentialHandle {
        const credential = self.authCredentialForRegistry(allocator, registry) catch |err| switch (err) {
            error.InvalidDockerConfig => return null,
            else => return err,
        } orelse return null;
        return .{ .credential = credential };
    }

    fn authCredentialForRegistry(self: *DockerConfig, allocator: std.mem.Allocator, registry: []const u8) AuthError!?ConfigModule.Credential {
        const cache_key = try dockerConfigRegistryCacheKeyAlloc(allocator, registry);
        defer allocator.free(cache_key);

        if (self.auth_cache.get(cache_key)) |cached| return cached;

        const encoded_auth = try self.authEncodedForRegistry(allocator, registry) orelse return null;
        defer allocator.free(encoded_auth);

        const credential = try decodeDockerConfigAuthCredential(allocator, encoded_auth);
        errdefer {
            allocator.free(@constCast(credential.username));
            std.crypto.secureZero(u8, @constCast(credential.secret));
            allocator.free(@constCast(credential.secret));
        }

        const owned_key = try allocator.dupe(u8, cache_key);
        errdefer allocator.free(owned_key);
        try self.auth_cache.put(allocator, owned_key, credential);

        return self.auth_cache.get(owned_key).?;
    }

    fn credentialSourceForRegistry(self: *DockerConfig, allocator: std.mem.Allocator, registry: []const u8) AuthError!?DockerCredentialSource {
        if (try self.registrySpecificHelperLookupForRegistry(allocator, registry)) |helper_lookup| {
            return .{ .helper = helper_lookup };
        }

        if (try self.authCredentialForRegistry(allocator, registry)) |credential| {
            return .{ .auth = credential };
        }

        if (try self.globalHelperLookupForRegistry(allocator, registry)) |helper_lookup| {
            return .{ .helper = helper_lookup };
        }

        return null;
    }

    fn registrySpecificHelperLookupForRegistry(
        self: *DockerConfig,
        allocator: std.mem.Allocator,
        registry: []const u8,
    ) AuthError!?DockerCredentialHelperLookup {
        const cache_key = try dockerConfigRegistryCacheKeyAlloc(allocator, registry);
        defer allocator.free(cache_key);

        const helper_suffix = if (self.helper_suffix_cache.get(cache_key)) |cached|
            cached
        else blk: {
            const owned_suffix = try self.helperSuffixForRegistry(allocator, registry) orelse return null;
            const owned_key = try allocator.dupe(u8, cache_key);
            errdefer allocator.free(owned_key);
            errdefer allocator.free(owned_suffix);
            try self.helper_suffix_cache.put(allocator, owned_key, owned_suffix);
            break :blk owned_suffix;
        };

        return .{
            .server_url = dockerCredentialHelperServer(registry),
            .helper_suffix = helper_suffix,
        };
    }

    fn globalHelperLookupForRegistry(self: *DockerConfig, allocator: std.mem.Allocator, registry: []const u8) AuthError!?DockerCredentialHelperLookup {
        try self.resolveCredsStore(allocator);
        const helper_suffix = self.creds_store orelse return null;
        return .{
            .server_url = dockerCredentialHelperServer(registry),
            .helper_suffix = helper_suffix,
        };
    }

    fn authEncodedForRegistry(self: *DockerConfig, allocator: std.mem.Allocator, registry: []const u8) AuthError!?[]const u8 {
        return self.indexedRegistrySectionValue(allocator, .auths, registry, "auth");
    }

    fn helperSuffixForRegistry(self: *DockerConfig, allocator: std.mem.Allocator, registry: []const u8) AuthError!?[]const u8 {
        return self.indexedRegistrySectionValue(allocator, .cred_helpers, registry, null);
    }

    fn indexedRegistrySectionValue(
        self: *DockerConfig,
        allocator: std.mem.Allocator,
        section: DockerConfigSection,
        registry: []const u8,
        object_field: ?[]const u8,
    ) AuthError!?[]const u8 {
        const entry_index = self.findRegistryEntryIndex(registry, section) orelse return null;
        const entry = self.registry_entries.items[entry_index];
        return dockerConfigValueFromIndexEntry(allocator, self.owned_json, entry, object_field);
    }

    fn findRegistryEntryIndex(self: *DockerConfig, registry: []const u8, section: DockerConfigSection) ?usize {
        if (self.registry_entries.items.len != 0) {
            var cache_key_buffer: [256]u8 = undefined;
            if (registry.len <= cache_key_buffer.len) {
                for (registry, 0..) |char, index| cache_key_buffer[index] = std.ascii.toLower(char);
                const cache_key = cache_key_buffer[0..registry.len];
                if (self.exact_registry_entry.get(cache_key)) |entry_index| {
                    const entry = self.registry_entries.items[entry_index];
                    if (entry.section == section and dockerConfigRegistryKeyMatches(entry.config_key, registry)) {
                        return entry_index;
                    }
                }
            }
        }

        for (self.registry_entries.items, 0..) |entry, index| {
            if (entry.section == section and dockerConfigRegistryKeyMatches(entry.config_key, registry)) {
                return index;
            }
        }

        return null;
    }

    fn resolveCredsStore(self: *DockerConfig, allocator: std.mem.Allocator) AuthError!void {
        if (self.creds_store_resolved) return;
        self.creds_store_resolved = true;
        if (try dockerConfigRootStringField(allocator, self.owned_json, "credsStore")) |value| {
            self.creds_store = value;
        }
    }
};
const ParsedTokenBody = struct {
    access_token: ?[]const u8 = null,
    token: ?[]const u8 = null,
    expires_in: ?u64 = null,
    refresh_token: ?[]const u8 = null,
};
const TokenCacheMap = std.HashMapUnmanaged(TokenCacheKey, CachedToken, TokenCacheKeyContext, 80);
const TokenCacheKeyContext = struct {
    pub fn hash(_: @This(), key: TokenCacheKey) u64 {
        return hashTokenCacheFields(key.realm, key.service, key.scope);
    }

    pub fn eql(_: @This(), a: TokenCacheKey, b: TokenCacheKey) bool {
        return tokenCacheKeysEqual(a, b);
    }
};
const TokenCacheRequestContext = struct {
    pub fn hash(_: @This(), request: AuthenticateRequest) u64 {
        return hashTokenCacheFields(request.challenge.realm, request.service(), request.scope());
    }

    pub fn eql(_: @This(), request: AuthenticateRequest, key: TokenCacheKey) bool {
        return tokenCacheKeyMatchesRequest(key, request);
    }
};
const NowUnixSecondsFn = *const fn (client: *std.http.Client) u64;
fn mapDockerConfigJsonError(err: anyerror) AuthError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidDockerConfig,
    };
}
fn dockerConfigScannerNext(scanner: *std.json.Scanner) AuthError!std.json.Scanner.Token {
    return scanner.next() catch |err| return mapDockerConfigJsonError(err);
}
fn dockerConfigScannerNextAllocMax(scanner: *std.json.Scanner) AuthError!std.json.Scanner.Token {
    return scanner.nextAllocMax(std.heap.page_allocator, .alloc_if_needed, DOCKER_CONFIG_FILE_SIZE_LIMIT) catch |err| return mapDockerConfigJsonError(err);
}
fn dockerConfigScannerSkipValue(scanner: *std.json.Scanner) AuthError!void {
    return scanner.skipValue() catch |err| return mapDockerConfigJsonError(err);
}
fn dockerConfigScannerPeekTokenType(scanner: *std.json.Scanner) AuthError!std.json.Scanner.TokenType {
    return scanner.peekNextTokenType() catch |err| return mapDockerConfigJsonError(err);
}
fn parseDockerConfig(allocator: std.mem.Allocator, docker_config_json: []const u8) AuthError!DockerConfig {
    var registry_entries: std.ArrayListUnmanaged(DockerConfigIndexedRegistry) = .empty;
    errdefer {
        for (registry_entries.items) |entry| entry.deinit(allocator);
        registry_entries.deinit(allocator);
    }

    var exact_registry_entry: std.StringHashMapUnmanaged(usize) = .empty;
    errdefer {
        var it = exact_registry_entry.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        exact_registry_entry.deinit(allocator);
    }

    try validateAndBuildDockerConfigIndex(
        allocator,
        docker_config_json,
        &registry_entries,
        &exact_registry_entry,
    );

    return .{
        .owned_json = try allocator.dupe(u8, docker_config_json),
        .registry_entries = registry_entries,
        .exact_registry_entry = exact_registry_entry,
    };
}
fn validateAndBuildDockerConfigIndex(
    allocator: std.mem.Allocator,
    docker_config_json: []const u8,
    registry_entries: *std.ArrayListUnmanaged(DockerConfigIndexedRegistry),
    exact_registry_entry: *std.StringHashMapUnmanaged(usize),
) AuthError!void {
    var scanner = std.json.Scanner.initCompleteInput(std.heap.page_allocator, docker_config_json);
    defer scanner.deinit();

    switch (try dockerConfigScannerNext(&scanner)) {
        .object_begin => {},
        else => return error.InvalidDockerConfig,
    }

    while (true) {
        const key_token = try dockerConfigScannerNextAllocMax(&scanner);
        switch (key_token) {
            .string, .allocated_string => |key| {
                const section: ?DockerConfigSection = if (std.mem.eql(u8, key, "auths"))
                    .auths
                else if (std.mem.eql(u8, key, "credHelpers"))
                    .cred_helpers
                else
                    null;

                freeDockerConfigScannerToken(std.heap.page_allocator, key_token);

                if (section) |indexed_section| {
                    switch (try dockerConfigScannerPeekTokenType(&scanner)) {
                        .object_begin => {},
                        else => return error.InvalidDockerConfig,
                    }

                    _ = try dockerConfigScannerNext(&scanner);
                    while (true) {
                        const entry_key_token = try dockerConfigScannerNextAllocMax(&scanner);
                        switch (entry_key_token) {
                            .string, .allocated_string => |entry_key| {
                                _ = try dockerConfigScannerPeekTokenType(&scanner);
                                const value_offset = scanner.cursor;
                                try dockerConfigScannerSkipValue(&scanner);

                                const owned_config_key = try allocator.dupe(u8, entry_key);
                                var owned_config_key_owned = true;
                                defer if (owned_config_key_owned) allocator.free(owned_config_key);

                                const entry_index = registry_entries.items.len;
                                try registry_entries.append(allocator, .{
                                    .section = indexed_section,
                                    .config_key = owned_config_key,
                                    .value_offset = value_offset,
                                });
                                owned_config_key_owned = false;

                                const cache_key = try dockerConfigRegistryCacheKeyAlloc(allocator, entry_key);
                                var cache_key_owned = true;
                                defer if (cache_key_owned) allocator.free(cache_key);

                                if (exact_registry_entry.contains(cache_key)) {
                                    allocator.free(cache_key);
                                    cache_key_owned = false;
                                } else {
                                    try exact_registry_entry.put(allocator, cache_key, entry_index);
                                    cache_key_owned = false;
                                }

                                freeDockerConfigScannerToken(std.heap.page_allocator, entry_key_token);
                            },
                            .object_end => {
                                freeDockerConfigScannerToken(std.heap.page_allocator, entry_key_token);
                                break;
                            },
                            else => return error.InvalidDockerConfig,
                        }
                    }
                    continue;
                }

                try dockerConfigScannerSkipValue(&scanner);
            },
            .object_end => break,
            else => return error.InvalidDockerConfig,
        }
    }

    switch (try dockerConfigScannerNext(&scanner)) {
        .end_of_document => {},
        else => return error.InvalidDockerConfig,
    }
}
fn validateDockerConfigJson(docker_config_json: []const u8) AuthError!void {
    var registry_entries: std.ArrayListUnmanaged(DockerConfigIndexedRegistry) = .empty;
    defer {
        for (registry_entries.items) |entry| entry.deinit(std.heap.page_allocator);
        registry_entries.deinit(std.heap.page_allocator);
    }

    var exact_registry_entry: std.StringHashMapUnmanaged(usize) = .empty;
    defer {
        var it = exact_registry_entry.iterator();
        while (it.next()) |entry| std.heap.page_allocator.free(entry.key_ptr.*);
        exact_registry_entry.deinit(std.heap.page_allocator);
    }

    try validateAndBuildDockerConfigIndex(
        std.heap.page_allocator,
        docker_config_json,
        &registry_entries,
        &exact_registry_entry,
    );
}
fn dockerConfigValueFromIndexEntry(
    allocator: std.mem.Allocator,
    docker_config_json: []const u8,
    entry: DockerConfigIndexedRegistry,
    object_field: ?[]const u8,
) AuthError!?[]const u8 {
    if (entry.value_offset >= docker_config_json.len) return error.InvalidDockerConfig;

    var scanner = std.json.Scanner.initCompleteInput(std.heap.page_allocator, docker_config_json[entry.value_offset..]);
    defer scanner.deinit();

    if (object_field) |field_name| {
        switch (try dockerConfigScannerNext(&scanner)) {
            .object_begin => {},
            else => return error.InvalidDockerConfig,
        }
        return dockerConfigReadObjectStringField(allocator, &scanner, field_name);
    }

    const value_token = try dockerConfigScannerNextAllocMax(&scanner);
    return try dockerConfigStringFromScannerToken(allocator, value_token);
}
fn dockerConfigRegistryCacheKeyAlloc(allocator: std.mem.Allocator, registry: []const u8) AuthError![]u8 {
    const owned = try allocator.alloc(u8, registry.len);
    for (registry, 0..) |char, index| {
        owned[index] = std.ascii.toLower(char);
    }
    return owned;
}
fn freeDockerConfigScannerToken(allocator: std.mem.Allocator, token: std.json.Scanner.Token) void {
    switch (token) {
        .allocated_string, .allocated_number => |owned| allocator.free(owned),
        else => {},
    }
}
fn dockerConfigStringFromScannerToken(allocator: std.mem.Allocator, token: std.json.Scanner.Token) AuthError![]const u8 {
    switch (token) {
        .string => |value| return try allocator.dupe(u8, value),
        .allocated_string => |value| {
            defer std.heap.page_allocator.free(value);
            return try allocator.dupe(u8, value);
        },
        else => {
            freeDockerConfigScannerToken(std.heap.page_allocator, token);
            return error.InvalidDockerConfig;
        },
    }
}
fn dockerConfigRootStringField(
    allocator: std.mem.Allocator,
    docker_config_json: []const u8,
    field_name: []const u8,
) AuthError!?[]const u8 {
    var scanner = std.json.Scanner.initCompleteInput(std.heap.page_allocator, docker_config_json);
    defer scanner.deinit();

    switch (try dockerConfigScannerNext(&scanner)) {
        .object_begin => {},
        else => return error.InvalidDockerConfig,
    }

    while (true) {
        const key_token = try dockerConfigScannerNextAllocMax(&scanner);
        switch (key_token) {
            .string, .allocated_string => |key| {
                if (!std.mem.eql(u8, key, field_name)) {
                    freeDockerConfigScannerToken(std.heap.page_allocator, key_token);
                    try dockerConfigScannerSkipValue(&scanner);
                    continue;
                }
                freeDockerConfigScannerToken(std.heap.page_allocator, key_token);

                const value_token = try dockerConfigScannerNextAllocMax(&scanner);
                return try dockerConfigStringFromScannerToken(allocator, value_token);
            },
            .object_end => return null,
            else => return error.InvalidDockerConfig,
        }
    }
}
fn dockerConfigReadObjectStringField(
    allocator: std.mem.Allocator,
    scanner: *std.json.Scanner,
    field_name: []const u8,
) AuthError!?[]const u8 {
    while (true) {
        const key_token = try dockerConfigScannerNextAllocMax(scanner);
        switch (key_token) {
            .string, .allocated_string => |key| {
                if (!std.mem.eql(u8, key, field_name)) {
                    freeDockerConfigScannerToken(std.heap.page_allocator, key_token);
                    try dockerConfigScannerSkipValue(scanner);
                    continue;
                }
                freeDockerConfigScannerToken(std.heap.page_allocator, key_token);

                const value_token = try dockerConfigScannerNextAllocMax(scanner);
                return try dockerConfigStringFromScannerToken(allocator, value_token);
            },
            .object_end => return null,
            else => return error.InvalidDockerConfig,
        }
    }
}
fn decodeDockerConfigAuthCredential(
    allocator: std.mem.Allocator,
    encoded_auth: []const u8,
) AuthError!ConfigModule.Credential {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(encoded_auth) catch return error.InvalidDockerConfig;
    const decoded_auth = try allocator.alloc(u8, decoded_len);
    defer {
        std.crypto.secureZero(u8, decoded_auth);
        allocator.free(decoded_auth);
    }

    decoder.decode(decoded_auth, encoded_auth) catch return error.InvalidDockerConfig;
    const decoded = decoded_auth;
    const separator_index = std.mem.indexOfScalar(u8, decoded, ':') orelse return error.InvalidDockerConfig;
    if (separator_index == 0 or separator_index + 1 >= decoded.len) return error.InvalidDockerConfig;

    const username = try allocator.dupe(u8, decoded[0..separator_index]);
    errdefer allocator.free(username);
    const secret = try allocator.dupe(u8, decoded[separator_index + 1 ..]);
    errdefer {
        std.crypto.secureZero(u8, secret);
        allocator.free(secret);
    }

    return .{
        .username = username,
        .secret = secret,
    };
}
fn dockerConfigPathFromEnvironmentAlloc(
    allocator: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
) AuthError!?[]u8 {
    if (environ_map.get(DOCKER_CONFIG_DIR_VAR)) |docker_config_dir| {
        if (docker_config_dir.len != 0) {
            return try std.fs.path.join(allocator, &.{ docker_config_dir, "config.json" });
        }
    }

    if (environ_map.get(HOME_DIR_VAR)) |home_dir| {
        if (home_dir.len != 0) {
            return try std.fs.path.join(allocator, &.{ home_dir, ".docker", "config.json" });
        }
    }

    if (environ_map.get(USERPROFILE_DIR_VAR)) |userprofile_dir| {
        if (userprofile_dir.len != 0) {
            return try std.fs.path.join(allocator, &.{ userprofile_dir, ".docker", "config.json" });
        }
    }

    return null;
}
fn dockerCredentialHelperServer(registry: []const u8) []const u8 {
    if (std.mem.eql(u8, registry, "registry-1.docker.io")) return DOCKER_HUB_AUTH_KEY;
    return registry;
}
fn canonicalDockerCredentialHelperServerAlloc(allocator: std.mem.Allocator, server_url: []const u8) AuthError![]u8 {
    const owned = try allocator.alloc(u8, server_url.len);
    for (server_url, 0..) |char, index| {
        owned[index] = std.ascii.toLower(char);
    }
    return owned;
}
fn dockerCredentialHelperCommandAlloc(
    allocator: std.mem.Allocator,
    helper_suffix: []const u8,
) AuthError![]u8 {
    if (!isValidDockerHelperSuffix(helper_suffix)) return error.InvalidDockerConfig;
    return std.fmt.allocPrint(allocator, "docker-credential-{s}", .{helper_suffix});
}
fn isValidDockerHelperSuffix(helper_suffix: []const u8) bool {
    if (helper_suffix.len == 0) return false;

    for (helper_suffix) |byte| {
        if (std.ascii.isWhitespace(byte) or byte == '/' or byte == '\\') return false;
    }

    return true;
}
fn runDockerCredentialHelperBySuffix(
    allocator: std.mem.Allocator,
    io: std.Io,
    helper_suffix: []const u8,
    server_url: []const u8,
    timeout: std.Io.Timeout,
) AuthError!CredentialHandle {
    const command = try dockerCredentialHelperCommandAlloc(allocator, helper_suffix);
    defer allocator.free(command);

    const argv = [_][]const u8{ command, "get" };
    return runDockerCredentialHelperCommand(allocator, io, &argv, server_url, timeout);
}
fn runDockerCredentialHelperCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    server_url: []const u8,
    timeout: std.Io.Timeout,
) AuthError!CredentialHandle {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.HelperFailed,
    };
    defer child.kill(io);

    {
        var stdin_writer = child.stdin.?.writer(io, &.{});
        stdin_writer.interface.writeAll(server_url) catch |err| switch (err) {
            error.WriteFailed => return error.HelperFailed,
        };
        stdin_writer.interface.writeByte('\n') catch |err| switch (err) {
            error.WriteFailed => return error.HelperFailed,
        };
        stdin_writer.interface.flush() catch |err| switch (err) {
            error.WriteFailed => return error.HelperFailed,
        };
    }
    child.stdin.?.close(io);
    child.stdin = null;

    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(allocator, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();

    while (multi_reader.fill(1, timeout)) |_| {
        if (multi_reader.reader(0).buffered().len > DOCKER_HELPER_STDOUT_LIMIT) return error.HelperFailed;
        if (multi_reader.reader(1).buffered().len > DOCKER_HELPER_STDERR_LIMIT) return error.HelperFailed;
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.Timeout => {
            child.kill(io);
            return error.HelperTimedOut;
        },
        else => return error.HelperFailed,
    }

    multi_reader.checkAnyError() catch return error.HelperFailed;

    const term = child.wait(io) catch return error.HelperFailed;

    const stdout_contents = try multi_reader.toOwnedSlice(0);
    defer {
        std.crypto.secureZero(u8, stdout_contents);
        allocator.free(stdout_contents);
    }

    const stderr_contents = try multi_reader.toOwnedSlice(1);
    defer allocator.free(stderr_contents);

    switch (term) {
        .exited => |code| if (code != 0) return error.HelperFailed,
        else => return error.HelperFailed,
    }

    return parseDockerCredentialHelperResponse(allocator, stdout_contents);
}
fn parseDockerCredentialHelperResponse(
    allocator: std.mem.Allocator,
    helper_stdout: []const u8,
) AuthError!CredentialHandle {
    const parsed = json.parse(ParsedDockerCredentialHelperResponse, allocator, helper_stdout) catch return error.HelperFailed;
    defer parsed.deinit();

    const username = parsed.value.Username orelse return error.HelperFailed;
    const secret = parsed.value.Secret orelse return error.HelperFailed;
    if (username.len == 0 or secret.len == 0) return error.HelperFailed;

    return ownedCredentialHandle(allocator, username, secret);
}
fn ownedCredentialHandle(
    allocator: std.mem.Allocator,
    username: []const u8,
    secret: []const u8,
) AuthError!CredentialHandle {
    const owned_username = try allocator.dupe(u8, username);
    errdefer allocator.free(owned_username);

    const owned_secret = try allocator.dupe(u8, secret);
    errdefer {
        std.crypto.secureZero(u8, owned_secret);
        allocator.free(owned_secret);
    }

    return .{
        .credential = .{
            .username = owned_username,
            .secret = owned_secret,
        },
        .release_fn = releaseOwnedCredential,
        .release_allocator = allocator,
    };
}
fn releaseOwnedCredential(allocator: std.mem.Allocator, credential: ConfigModule.Credential) void {
    allocator.free(@constCast(credential.username));
    freeOwnedOptionalSecretSlice(allocator, @constCast(credential.secret));
}
fn dockerCredentialHelperTimeout(config: Config) std.Io.Timeout {
    if (config.read_timeout_ms == 0) return .none;

    return .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(config.read_timeout_ms),
        .clock = .awake,
    } };
}
fn currentUnixSeconds(_: *std.http.Client) u64 {
    var ts: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => return @intCast(ts.sec),
        else => return 0,
    }
}
fn preferredTokenMethodsForRealm(engine: *const AuthEngine, realm: []const u8) [2]TokenRequestMethod {
    if (engine.preferred_token_method_by_realm.get(realm)) |method| {
        return switch (method) {
            .get => .{ .get, .post },
            .post => .{ .post, .get },
        };
    }
    return .{ .get, .post };
}
fn hashTokenCacheFields(realm: []const u8, service: ?[]const u8, scope: ?[]const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(realm);
    hasher.update(&[_]u8{if (service != null) 1 else 0});
    if (service) |value| hasher.update(value);
    hasher.update(&[_]u8{if (scope != null) 1 else 0});
    if (scope) |value| hasher.update(value);
    return hasher.final();
}
fn tokenCacheKeysEqual(a: TokenCacheKey, b: TokenCacheKey) bool {
    if (!std.mem.eql(u8, a.realm, b.realm)) return false;

    if ((a.service == null) != (b.service == null)) return false;
    if (a.service) |service| {
        if (!std.mem.eql(u8, service, b.service.?)) return false;
    }

    if ((a.scope == null) != (b.scope == null)) return false;
    if (a.scope) |scope| {
        if (!std.mem.eql(u8, scope, b.scope.?)) return false;
    }

    return true;
}
fn tokenCacheKeyMatchesRequest(key: TokenCacheKey, request: AuthenticateRequest) bool {
    return tokenCacheKeyMatchesBorrowed(
        key,
        request.challenge.realm,
        request.service(),
        request.scope(),
    );
}
fn tokenCacheKeyMatchesBorrowed(
    key: TokenCacheKey,
    realm: []const u8,
    service: ?[]const u8,
    scope: ?[]const u8,
) bool {
    return tokenCacheKeysEqual(key, .{
        .realm = realm,
        .service = service,
        .scope = scope,
    });
}
fn putCachedTokenEntryForTest(
    engine: *AuthEngine,
    request: AuthenticateRequest,
    cached_token: CachedToken,
) !void {
    var key = try TokenCacheKey.initOwnedFromRequest(engine.allocator, request);
    errdefer key.deinit(engine.allocator);

    const gop = try engine.token_cache.getOrPut(engine.allocator, key);
    if (gop.found_existing) {
        key.deinit(engine.allocator);
        var old_token = gop.value_ptr.*;
        old_token.deinit(engine.allocator);
    }
    gop.value_ptr.* = cached_token;
}
fn borrowedCachedTokenResponse(cached_token: CachedToken) TokenResponse {
    return .{
        .access_token = .{
            .value = cached_token.token.value,
            .expires_in_seconds = cached_token.token.expires_in_seconds,
        },
        .owns_access_token = false,
    };
}
fn cachedTokenFromResponse(
    token_response: *TokenResponse,
    now_unix_seconds: u64,
    default_ttl_seconds: u64,
) CachedToken {
    const ttl_seconds = token_response.access_token.expires_in_seconds orelse default_ttl_seconds;
    const usable_lifetime = ttl_seconds -| TOKEN_REFRESH_WINDOW_SECONDS;
    const stolen_value = token_response.access_token.value;
    token_response.access_token.value = &.{};
    token_response.owns_access_token = false;

    return .{
        .token = .{
            .value = stolen_value,
            .expires_in_seconds = token_response.access_token.expires_in_seconds,
        },
        .valid_until_unix_seconds = now_unix_seconds + usable_lifetime,
        .last_used_unix_seconds = now_unix_seconds,
    };
}
fn dockerConfigRegistryKeyMatches(config_key: []const u8, registry: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(config_key, registry)) return true;
    if (!isDockerHubRegistryAlias(registry)) return false;

    return std.ascii.eqlIgnoreCase(config_key, DOCKER_HUB_AUTH_KEY) or
        std.ascii.eqlIgnoreCase(config_key, "https://index.docker.io/v1") or
        isDockerHubRegistryAlias(config_key);
}
fn registryHostMatches(configured_host: []const u8, registry: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(configured_host, registry)) return true;
    return isDockerHubRegistryAlias(configured_host) and isDockerHubRegistryAlias(registry);
}
fn isDockerHubRegistryAlias(host: []const u8) bool {
    return std.ascii.eqlIgnoreCase(host, "docker.io") or
        std.ascii.eqlIgnoreCase(host, "index.docker.io") or
        std.ascii.eqlIgnoreCase(host, "registry-1.docker.io");
}
const TokenExchangeLoop = struct {
    engine: *AuthEngine,
    client: *std.http.Client,
    request: AuthenticateRequest,
    method: TokenRequestMethod,
    credential: ?ConfigModule.Credential,
    cached_url: ?[]u8 = null,
    cached_authorization: ?[]u8 = null,
    cached_content_type: ?[]const u8 = null,
    cached_body: ?[]u8 = null,
    exchange_attempt: usize = 0,
};
fn tokenExchangeOnceOpaque(ctx_ptr: *anyopaque) AuthError!TokenExchangeResponse {
    const loop_ctx: *TokenExchangeLoop = @ptrCast(@alignCast(ctx_ptr));
    const allocator = loop_ctx.engine.allocator;
    const exchanger = loop_ctx.engine.token_http_exchanger orelse return error.NotYetImplemented;
    loop_ctx.exchange_attempt += 1;

    if (loop_ctx.cached_url) |cached_url| {
        const http_request = TokenHttpRequest{
            .method = loop_ctx.method,
            .url = try allocator.dupe(u8, cached_url),
            .authorization = if (loop_ctx.cached_authorization) |authorization|
                try allocator.dupe(u8, authorization)
            else
                null,
            .content_type = loop_ctx.cached_content_type,
            .body = if (loop_ctx.cached_body) |body| try allocator.dupe(u8, body) else null,
            .max_response_body_bytes = loop_ctx.engine.config.max_token_response_bytes,
        };
        return exchanger(allocator, loop_ctx.client, http_request);
    }

    var built = try buildTokenHttpRequest(
        allocator,
        loop_ctx.request,
        loop_ctx.method,
        loop_ctx.credential,
    );
    built.max_response_body_bytes = loop_ctx.engine.config.max_token_response_bytes;

    if (loop_ctx.exchange_attempt > 1) {
        loop_ctx.cached_url = try allocator.dupe(u8, built.url);
        loop_ctx.cached_authorization = if (built.authorization) |authorization|
            try allocator.dupe(u8, authorization)
        else
            null;
        loop_ctx.cached_content_type = built.content_type;
        if (built.body) |body| {
            loop_ctx.cached_body = try allocator.dupe(u8, body);
        }
    }

    return exchanger(allocator, loop_ctx.client, built);
}
fn tokenExchangeResponseStatus(response: TokenExchangeResponse) std.http.Status {
    return response.status;
}
fn tokenExchangeResponseHeaders(response: TokenExchangeResponse) []const resilience.HttpHeader {
    return response.resilience_headers;
}
fn deinitTokenExchangeResponse(allocator: std.mem.Allocator, response: TokenExchangeResponse) void {
    var owned = response;
    owned.deinit(allocator);
}
fn mapLiveTokenTransportError(err: anyerror) AuthError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.BodyTooLarge => error.InvalidTokenResponse,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.Timeout => error.Timeout,
        error.NetworkUnreachable => error.NetworkUnreachable,
        error.ConnectionRefused => error.ConnectionRefused,
        error.UnknownHostName => error.UnknownHostName,
        else => error.TokenExchangeFailed,
    };
}
fn tokenValueFromParsedBody(parsed: ParsedTokenBody) ?[]const u8 {
    if (parsed.access_token) |access_token| {
        if (parsed.token) |token| {
            if (!std.mem.eql(u8, access_token, token)) return null;
        }
        return access_token;
    }

    return parsed.token;
}
fn parseChallengeChunk(raw: []const u8) AuthError!AuthChallenge {
    const space_index = std.mem.indexOfAny(u8, raw, " \t") orelse raw.len;
    const scheme = raw[0..space_index];
    const remainder = std.mem.trim(u8, raw[space_index..], " \t");

    if (std.ascii.eqlIgnoreCase(scheme, "Bearer")) {
        return .{ .bearer = try parseBearerChallenge(remainder) };
    }

    return .{ .other = scheme };
}
fn parseBearerChallenge(params: []const u8) AuthError!BearerChallenge {
    var challenge = BearerChallenge{ .realm = "" };
    var cursor: usize = 0;
    while (try nextCommaSeparatedChunk(params, &cursor)) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;

        const eq_index = std.mem.indexOfScalar(u8, trimmed, '=') orelse return error.InvalidAuthenticateHeader;
        const name = std.mem.trim(u8, trimmed[0..eq_index], " \t");
        const value = try parseAuthParamValue(trimmed[eq_index + 1 ..]);

        if (std.ascii.eqlIgnoreCase(name, "realm")) {
            if (challenge.realm.len != 0) return error.InvalidAuthenticateHeader;
            if (value.len == 0) return error.InvalidAuthenticateHeader;
            challenge.realm = value;
        } else if (std.ascii.eqlIgnoreCase(name, "service")) {
            if (challenge.service != null) return error.InvalidAuthenticateHeader;
            if (value.len == 0) return error.InvalidAuthenticateHeader;
            challenge.service = value;
        } else if (std.ascii.eqlIgnoreCase(name, "scope")) {
            if (challenge.scope != null) return error.InvalidAuthenticateHeader;
            if (value.len == 0) return error.InvalidAuthenticateHeader;
            challenge.scope = value;
        }
    }

    if (challenge.realm.len == 0) return error.InvalidAuthenticateHeader;
    try validateRealmUrl(challenge.realm);
    return challenge;
}
fn validateRealmUrl(realm: []const u8) AuthError!void {
    const parsed = std.Uri.parse(realm) catch return error.InsecureRealmUrl;
    if (!std.ascii.eqlIgnoreCase(parsed.scheme, "https")) return error.InsecureRealmUrl;
    if (parsed.host == null) return error.InsecureRealmUrl;
}
fn writeFormField(writer: *std.Io.Writer, first: *bool, key: []const u8, value: []const u8) std.Io.Writer.Error!void {
    if (!first.*) try writer.writeByte('&');
    first.* = false;
    try writer.writeAll(key);
    try writer.writeByte('=');
    try std.Uri.Component.percentEncode(writer, value, isFormValueChar);
}
fn isFormValueChar(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or char == '-' or char == '_' or char == '.' or char == '~';
}
fn parseAuthParamValue(raw: []const u8) AuthError![]const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return error.InvalidAuthenticateHeader;

    if (trimmed[0] == '"') {
        if (trimmed.len < 2 or trimmed[trimmed.len - 1] != '"') {
            return error.InvalidAuthenticateHeader;
        }
        var i: usize = 1;
        while (i < trimmed.len - 1) : (i += 1) {
            switch (trimmed[i]) {
                '\\' => {
                    if (i + 1 >= trimmed.len - 1) return error.InvalidAuthenticateHeader;
                    i += 1;
                },
                '"' => return error.InvalidAuthenticateHeader,
                else => {},
            }
        }
        return trimmed[1 .. trimmed.len - 1];
    }

    if (std.mem.indexOfScalar(u8, trimmed, '"') != null) {
        return error.InvalidAuthenticateHeader;
    }

    return trimmed;
}
fn nextCommaSeparatedChunk(raw: []const u8, cursor: *usize) AuthError!?[]const u8 {
    if (cursor.* >= raw.len) return null;

    const start = cursor.*;
    var in_quotes = false;
    var i = start;
    while (i < raw.len) : (i += 1) {
        switch (raw[i]) {
            '"' => in_quotes = !in_quotes,
            '\\' => if (in_quotes and i + 1 < raw.len) {
                i += 1;
            },
            ',' => if (!in_quotes) {
                cursor.* = i + 1;
                return raw[start..i];
            },
            else => {},
        }
    }

    if (in_quotes) return error.InvalidAuthenticateHeader;
    cursor.* = raw.len;
    return raw[start..];
}
fn findNextChallengeStart(raw: []const u8, start: usize) AuthError!?usize {
    var in_quotes = false;
    var i = start;
    while (i < raw.len) : (i += 1) {
        switch (raw[i]) {
            '"' => in_quotes = !in_quotes,
            '\\' => if (in_quotes and i + 1 < raw.len) {
                i += 1;
            },
            ',' => if (!in_quotes) {
                var candidate = i + 1;
                while (candidate < raw.len and isAuthWhitespace(raw[candidate])) : (candidate += 1) {}
                if (candidate >= raw.len) continue;
                if (isChallengeStart(raw[candidate..])) return candidate;
            },
            else => {},
        }
    }

    if (in_quotes) return error.InvalidAuthenticateHeader;
    return null;
}
fn isChallengeStart(raw: []const u8) bool {
    var token_end: usize = 0;
    while (token_end < raw.len and !isAuthWhitespace(raw[token_end]) and raw[token_end] != ',' and raw[token_end] != '=') : (token_end += 1) {}
    if (token_end == 0) return false;
    if (token_end == raw.len) return true;
    if (!isAuthWhitespace(raw[token_end])) return false;

    var value_start = token_end;
    while (value_start < raw.len and isAuthWhitespace(raw[value_start])) : (value_start += 1) {}
    return value_start > token_end and (value_start == raw.len or raw[value_start] != '=');
}
fn isAuthWhitespace(char: u8) bool {
    return char == ' ' or char == '\t';
}
// Tests
// Fuzz tests for the WWW-Authenticate parser ----------------------------------
// Memory stress tests ---------------------------------------------------------

// --- Tests ---

test "auth scaffolding: types compile with representative values" {
    const bearer = BearerChallenge{
        .realm = "https://auth.example.test/token",
        .service = "registry.example.test",
        .scope = "repository:owner/image:pull",
    };

    const challenge = AuthChallenge{ .bearer = bearer };
    const probe = ProbeResult{ .auth_required = challenge };
    const token = Token{ .value = "opaque-token", .expires_in_seconds = 300 };
    const response = TokenResponse{ .access_token = token };
    const key = TokenCacheKey{
        .realm = bearer.realm,
        .service = bearer.service,
        .scope = bearer.scope.?,
    };
    const cached = CachedToken{ .token = token, .valid_until_unix_seconds = 1_700_000_000 };
    const docker_helper_config = DockerHelperConfig{ .io = std.testing.io };

    try std.testing.expect(probe == .auth_required);
    try std.testing.expectEqualStrings("https://auth.example.test/token", bearer.realm);
    try std.testing.expectEqualStrings("opaque-token", response.access_token.value);
    try std.testing.expectEqualStrings("repository:owner/image:pull", key.scope.?);
    try std.testing.expectEqual(@as(?u64, 1_700_000_000), cached.valid_until_unix_seconds);
    _ = docker_helper_config;
}
test "auth scaffolding: engine authenticate remains a stub without exchanger" {
    var engine = AuthEngine.init(std.testing.allocator, Config{});
    defer engine.deinit();
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry-1.docker.io",
        .{ .realm = "https://auth.example.test/token", .scope = "repository:library/ubuntu:pull" },
    );

    try std.testing.expectError(error.NotYetImplemented, engine.authenticate(&client, request));
}
test "auth scaffolding: explicit helper process context is optional" {
    const engine = AuthEngine.initWithDockerHelperConfig(
        std.testing.allocator,
        Config{},
        .{ .io = std.testing.io },
    );

    try std.testing.expect(engine.dockerHelperConfig() != null);
}
test "auth scaffolding: authConfigView keeps only auth-relevant fields" {
    const provider = CredentialProvider{
        .getCredentialFn = struct {
            fn get(_: []const u8) ?CredentialHandle {
                return null;
            }
        }.get,
    };
    const config = Config{
        .credential_provider = &provider,
        .connect_timeout_ms = 5_000,
        .read_timeout_ms = 60_000,
        .max_retries = 9,
        .ca_bundle_path = "/tmp/custom-ca.pem",
        .rate_limit_enabled = false,
    };
    const view = authConfigView(config);

    try std.testing.expect(view.credential_provider == &provider);
    try std.testing.expectEqual(@as(u32, 5_000), view.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 60_000), view.read_timeout_ms);
    try std.testing.expectEqualStrings("/tmp/custom-ca.pem", view.ca_bundle_path.?);
}
test "auth scaffolding: provider credentials borrow provider-owned storage" {
    const State = struct {
        var username = [_]u8{ 'u', 's', 'e', 'r' };
        var secret = [_]u8{ 't', 'o', 'k', 'e', 'n' };

        fn get(registry: []const u8) ?CredentialHandle {
            if (!std.mem.eql(u8, registry, "ghcr.io")) return null;
            return .{ .credential = .{
                .username = username[0..],
                .secret = secret[0..],
            } };
        }
    };

    const provider = CredentialProvider{ .getCredentialFn = State.get };
    const cred = provider.getCredential("ghcr.io").?.credential;

    try std.testing.expectEqual(@intFromPtr(cred.username.ptr), @intFromPtr(&State.username[0]));
    try std.testing.expectEqual(@intFromPtr(cred.secret.ptr), @intFromPtr(&State.secret[0]));

    State.secret[0] = 'T';
    try std.testing.expectEqual(@as(u8, 'T'), cred.secret[0]);
    State.secret[0] = 't';
}
test "auth scaffolding: engine can request credential handle" {
    const provider = CredentialProvider{
        .getCredentialFn = struct {
            fn get(registry: []const u8) ?CredentialHandle {
                if (!std.mem.eql(u8, registry, "ghcr.io")) return null;
                return .{ .credential = .{ .username = "user", .secret = "token" } };
            }
        }.get,
    };
    var engine = AuthEngine.init(std.testing.allocator, .{ .credential_provider = &provider });
    const handle = (try engine.credentialForRegistry("ghcr.io")).?;

    try std.testing.expectEqualStrings("user", handle.credential.username);
    try std.testing.expectEqualStrings("token", handle.credential.secret);
}
test "auth scaffolding: authConfigView records env credential variable names" {
    const view = authConfigView(Config{});

    try std.testing.expectEqualStrings("Z_OCI_REGISTRY_HOST", view.env_registry_host);
    try std.testing.expectEqualStrings("Z_OCI_REGISTRY_USER", view.env_registry_user);
    try std.testing.expectEqualStrings("Z_OCI_REGISTRY_TOKEN", view.env_registry_token);
}
test "AuthEngine.credentialForRegistry: explicit config provider wins before env" {
    const State = struct {
        fn get(registry: []const u8) ?CredentialHandle {
            if (!std.mem.eql(u8, registry, "ghcr.io")) return null;
            return .{ .credential = .{ .username = "config-user", .secret = "config-token" } };
        }
    };

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(ENV_REGISTRY_USER, "env-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "env-token");

    const provider = CredentialProvider{ .getCredentialFn = State.get };
    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, .{ .credential_provider = &provider }, &environ_map);
    const handle = (try engine.credentialForRegistry("ghcr.io")).?;

    try std.testing.expectEqualStrings("config-user", handle.credential.username);
    try std.testing.expectEqualStrings("config-token", handle.credential.secret);
}
test "AuthEngine.credentialForRegistry: env provider supplies fallback credentials" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(ENV_REGISTRY_USER, "env-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "env-token");

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    const handle = (try engine.credentialForRegistry("ghcr.io")).?;
    defer handle.release();

    try std.testing.expectEqualStrings("env-user", handle.credential.username);
    try std.testing.expectEqualStrings("env-token", handle.credential.secret);
}
test "envCredentialForRegistry: returns owned copies independent of environ map" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(ENV_REGISTRY_USER, "env-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "env-token");

    const handle = (try envCredentialForRegistry(std.testing.allocator, &environ_map, "ghcr.io")).?;
    defer handle.release();

    try std.testing.expect(handle.release_fn != null);
    try environ_map.put(ENV_REGISTRY_USER, "mutated-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "mutated-token");
    try std.testing.expectEqualStrings("env-user", handle.credential.username);
    try std.testing.expectEqualStrings("env-token", handle.credential.secret);
}
test "ownedCredentialHandle: allocation failures do not leak username or secret" {
    const State = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const handle = try ownedCredentialHandle(allocator, "user", "secret");
            handle.release();
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "envCredentialForRegistry: allocation failures do not leak" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(ENV_REGISTRY_USER, "env-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "env-token");

    const State = struct {
        fn run(allocator: std.mem.Allocator, env_map: *const std.process.Environ.Map) !void {
            const handle = (try envCredentialForRegistry(allocator, env_map, "ghcr.io")) orelse
                return;
            handle.release();
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{&environ_map});
}
test "AuthEngine.credentialForRegistry: env allocation failures propagate without leaking" {
    const State = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var environ_map = std.process.Environ.Map.init(allocator);
            defer environ_map.deinit();
            try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
            try environ_map.put(ENV_REGISTRY_USER, "env-user");
            try environ_map.put(ENV_REGISTRY_TOKEN, "env-token");

            var engine = AuthEngine.initWithEnvironmentMap(allocator, Config{}, &environ_map);
            defer engine.deinit();

            const handle = try engine.credentialForRegistry("ghcr.io");
            if (handle) |owned| owned.release();
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "ownedCredentialHandle: release_allocator matches dup allocator" {
    const handle = try ownedCredentialHandle(std.testing.allocator, "user", "secret");
    defer handle.release();

    try std.testing.expect(handle.release_fn != null);
    try std.testing.expectEqual(std.testing.allocator.ptr, handle.release_allocator.ptr);
}
test "AuthEngine.credentialForRegistry: env provider normalizes Docker Hub aliases" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "docker.io");
    try environ_map.put(ENV_REGISTRY_USER, "env-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "env-token");

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    const handle = (try engine.credentialForRegistry("registry-1.docker.io")).?;
    defer handle.release();

    try std.testing.expectEqualStrings("env-user", handle.credential.username);
    try std.testing.expectEqualStrings("env-token", handle.credential.secret);
}
test "AuthEngine.credentialForRegistry: env provider treats GHCR host case-insensitively" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(ENV_REGISTRY_USER, "env-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "env-token");

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    const handle = (try engine.credentialForRegistry("GHCR.IO")).?;
    defer handle.release();

    try std.testing.expectEqualStrings("env-user", handle.credential.username);
    try std.testing.expectEqualStrings("env-token", handle.credential.secret);
}
test "AuthEngine.credentialForRegistry: env provider ignores registry mismatch and partial env" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(ENV_REGISTRY_USER, "env-user");

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    try std.testing.expect((try engine.credentialForRegistry("registry-1.docker.io")) == null);
    try std.testing.expect((try engine.credentialForRegistry("ghcr.io")) == null);
}
test "AuthEngine.credentialForRegistry: anonymous fallback is explicit when no provider matches" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    const provider = CredentialProvider{
        .getCredentialFn = struct {
            fn get(_: []const u8) ?CredentialHandle {
                return null;
            }
        }.get,
    };
    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, .{ .credential_provider = &provider }, &environ_map);

    try std.testing.expect((try engine.credentialForRegistry("registry-1.docker.io")) == null);
}
test "parseDockerConfig: decodes auths and records helper metadata" {
    var docker_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    },
        \\    "https://index.docker.io/v1/": {
        \\      "auth": "ZG9ja2VydXNlcjpzZWNyZXQ="
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "ghcr.io": "secretservice"
        \\  },
        \\  "credsStore": "pass"
        \\}
    );
    defer docker_config.deinit(std.testing.allocator);

    const ghcr_auth = (try docker_config.authCredentialForRegistry(std.testing.allocator, "ghcr.io")).?;
    try std.testing.expectEqualStrings("octocat", ghcr_auth.username);
    try std.testing.expectEqualStrings("ghp_example", ghcr_auth.secret);

    const docker_hub_auth = (try docker_config.authCredentialForRegistry(std.testing.allocator, "registry-1.docker.io")).?;
    try std.testing.expectEqualStrings("dockeruser", docker_hub_auth.username);
    try std.testing.expectEqualStrings("secret", docker_hub_auth.secret);

    const ghcr_helper = (try docker_config.registrySpecificHelperLookupForRegistry(std.testing.allocator, "ghcr.io")).?;
    try std.testing.expectEqualStrings("secretservice", ghcr_helper.helper_suffix);

    try docker_config.resolveCredsStore(std.testing.allocator);
    try std.testing.expectEqualStrings("pass", docker_config.creds_store.?);
}
test "AuthEngine.credentialForRegistry: malformed docker config auth returns null" {
    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "not-base64"
        \\    }
        \\  }
        \\}
    );
    defer engine.deinit();

    try std.testing.expect((try engine.credentialForRegistry("ghcr.io")) == null);
}
test "parseDockerConfig: rejects malformed auth entries at lookup time" {
    var docker_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "not-base64"
        \\    }
        \\  }
        \\}
    );
    defer docker_config.deinit(std.testing.allocator);

    try std.testing.expectError(error.InvalidDockerConfig, docker_config.authCredentialForRegistry(std.testing.allocator, "ghcr.io"));

    var valid_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "bm9fY29sb24="
        \\    }
        \\  }
        \\}
    );
    defer valid_config.deinit(std.testing.allocator);

    try std.testing.expectError(error.InvalidDockerConfig, valid_config.authCredentialForRegistry(std.testing.allocator, "ghcr.io"));
}
test "decodeDockerConfigAuthCredential: allocation failures do not leak username or secret" {
    const encoded_auth = "b2N0b2NhdDpnaHBfZXhhbXBsZQ==";

    const State = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const credential = try decodeDockerConfigAuthCredential(allocator, encoded_auth);
            defer {
                allocator.free(@constCast(credential.username));
                std.crypto.secureZero(u8, @constCast(credential.secret));
                allocator.free(@constCast(credential.secret));
            }

            try std.testing.expectEqualStrings("octocat", credential.username);
            try std.testing.expectEqualStrings("ghp_example", credential.secret);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "parseDockerConfig: authCredentialForRegistry allocation failures do not leak on cache insert" {
    // Index is built with std.testing.allocator; only lookup/insert runs under failing allocator.
    const docker_config_json =
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  }
        \\}
    ;

    const State = struct {
        fn run(failing_allocator: std.mem.Allocator) !void {
            var docker_config = try parseDockerConfig(std.testing.allocator, docker_config_json);
            defer docker_config.deinit(std.testing.allocator);

            const credential = (try docker_config.authCredentialForRegistry(failing_allocator, "ghcr.io")) orelse
                return error.TestExpectedEqual;
            try std.testing.expectEqualStrings("octocat", credential.username);
            try std.testing.expectEqualStrings("ghp_example", credential.secret);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "parseDockerConfig: parse and deinit stay safe under allocation failures" {
    const docker_config_json =
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    },
        \\    "quay.io": {
        \\      "auth": "dXNlcjpwYXNz"
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "ghcr.io": "secretservice"
        \\  },
        \\  "credsStore": "pass"
        \\}
    ;

    const State = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var docker_config = try parseDockerConfig(allocator, docker_config_json);
            defer docker_config.deinit(allocator);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "parseDockerConfig: single-registry lookup ignores malformed auths for other registries" {
    var docker_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    },
        \\    "quay.io": {
        \\      "auth": "not-base64"
        \\    }
        \\  }
        \\}
    );
    defer docker_config.deinit(std.testing.allocator);

    const ghcr_auth = (try docker_config.authCredentialForRegistry(std.testing.allocator, "ghcr.io")).?;
    try std.testing.expectEqualStrings("octocat", ghcr_auth.username);
    try std.testing.expectEqualStrings("ghp_example", ghcr_auth.secret);
}
test "parseDockerConfig: rejects malformed auth entries" {
    try std.testing.expectError(error.InvalidDockerConfig, parseDockerConfig(std.testing.allocator,
        \\{ not json }
    ));

    try std.testing.expectError(error.InvalidDockerConfig, parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": []
        \\}
    ));
}
test "dockerConfigRegistryKeyMatches: recognizes Docker Hub historical key" {
    try std.testing.expect(dockerConfigRegistryKeyMatches(DOCKER_HUB_AUTH_KEY, "registry-1.docker.io"));
    try std.testing.expect(dockerConfigRegistryKeyMatches("docker.io", "registry-1.docker.io"));
    try std.testing.expect(!dockerConfigRegistryKeyMatches("https://index.docker.io/v1/", "ghcr.io"));
}
test "dockerConfigRegistryKeyMatches: treats GHCR and Quay hosts case-insensitively" {
    try std.testing.expect(dockerConfigRegistryKeyMatches("ghcr.io", "GHCR.IO"));
    try std.testing.expect(dockerConfigRegistryKeyMatches("quay.io", "QuAy.IO"));
}
test "parseDockerConfig: indexed lookup uses case-insensitive exact-key hash" {
    var docker_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "GHCR.IO": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  }
        \\}
    );
    defer docker_config.deinit(std.testing.allocator);

    const credential = (try docker_config.authCredentialForRegistry(std.testing.allocator, "ghcr.io")).?;
    try std.testing.expectEqualStrings("octocat", credential.username);
    try std.testing.expectEqualStrings("ghp_example", credential.secret);
}
test "parseDockerConfig: Docker Hub alias resolves to first matching entry in JSON order" {
    var first_wins = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "https://index.docker.io/v1/": {
        \\      "auth": "b2N0b2NhdDpmaXJzdA=="
        \\    },
        \\    "docker.io": {
        \\      "auth": "b2N0b2NhdDpzZWNvbmQ="
        \\    }
        \\  }
        \\}
    );
    defer first_wins.deinit(std.testing.allocator);

    const first_credential = (try first_wins.authCredentialForRegistry(std.testing.allocator, "registry-1.docker.io")).?;
    try std.testing.expectEqualStrings("octocat", first_credential.username);
    try std.testing.expectEqualStrings("first", first_credential.secret);

    var second_wins = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "docker.io": {
        \\      "auth": "b2N0b2NhdDpzZWNvbmQ="
        \\    },
        \\    "https://index.docker.io/v1/": {
        \\      "auth": "b2N0b2NhdDpmaXJzdA=="
        \\    }
        \\  }
        \\}
    );
    defer second_wins.deinit(std.testing.allocator);

    const second_credential = (try second_wins.authCredentialForRegistry(std.testing.allocator, "registry-1.docker.io")).?;
    try std.testing.expectEqualStrings("octocat", second_credential.username);
    try std.testing.expectEqualStrings("second", second_credential.secret);
}
test "parseDockerConfig: duplicate auths keys keep first entry for lookup" {
    var docker_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpmaXJzdA=="
        \\    },
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpzZWNvbmQ="
        \\    }
        \\  }
        \\}
    );
    defer docker_config.deinit(std.testing.allocator);

    const credential = (try docker_config.authCredentialForRegistry(std.testing.allocator, "ghcr.io")).?;
    try std.testing.expectEqualStrings("octocat", credential.username);
    try std.testing.expectEqualStrings("first", credential.secret);
}
test "parseDockerConfig: credHelpers indexed lookup preserves helper suffix" {
    var docker_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "credHelpers": {
        \\    "quay.io": "quay-helper"
        \\  }
        \\}
    );
    defer docker_config.deinit(std.testing.allocator);

    const helper = (try docker_config.registrySpecificHelperLookupForRegistry(std.testing.allocator, "QUAY.IO")).?;
    try std.testing.expectEqualStrings("quay-helper", helper.helper_suffix);
}
test "AuthEngine.credentialForRegistry: docker config auth supplies fallback credentials" {
    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  }
        \\}
    );
    defer engine.deinit();

    const handle = (try engine.credentialForRegistry("ghcr.io")).?;

    try std.testing.expectEqualStrings("octocat", handle.credential.username);
    try std.testing.expectEqualStrings("ghp_example", handle.credential.secret);
}
test "AuthEngine.credentialForRegistry: Docker Hub lookup normalizes to historical config key" {
    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "https://index.docker.io/v1/": {
        \\      "auth": "ZG9ja2VydXNlcjpzZWNyZXQ="
        \\    }
        \\  }
        \\}
    );
    defer engine.deinit();

    const handle = (try engine.credentialForRegistry("registry-1.docker.io")).?;

    try std.testing.expectEqualStrings("dockeruser", handle.credential.username);
    try std.testing.expectEqualStrings("secret", handle.credential.secret);
}
test "AuthEngine.credentialForRegistry: env remains ahead of docker config" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(ENV_REGISTRY_USER, "env-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "env-token");

    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  }
        \\}
    );
    defer engine.deinit();
    engine.environ_map = &environ_map;

    const handle = (try engine.credentialForRegistry("ghcr.io")).?;
    defer handle.release();

    try std.testing.expectEqualStrings("env-user", handle.credential.username);
    try std.testing.expectEqualStrings("env-token", handle.credential.secret);
}
test "DockerConfig.credentialSourceForRegistry: registry helper beats auth and global store" {
    var docker_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    },
        \\    "registry.example.com": {
        \\      "auth": "aW50ZXJuYWwtdXNlcjp0b2tlbg=="
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "ghcr.io": "secretservice"
        \\  },
        \\  "credsStore": "pass"
        \\}
    );
    defer docker_config.deinit(std.testing.allocator);

    const ghcr_source = (try docker_config.credentialSourceForRegistry(std.testing.allocator, "ghcr.io")).?;
    switch (ghcr_source) {
        .helper => |helper| {
            try std.testing.expectEqualStrings("ghcr.io", helper.server_url);
            try std.testing.expectEqualStrings("secretservice", helper.helper_suffix);
        },
        else => return error.TestUnexpectedResult,
    }

    const self_hosted_source = (try docker_config.credentialSourceForRegistry(std.testing.allocator, "registry.example.com")).?;
    switch (self_hosted_source) {
        .auth => |credential| {
            try std.testing.expectEqualStrings("internal-user", credential.username);
            try std.testing.expectEqualStrings("token", credential.secret);
        },
        else => return error.TestUnexpectedResult,
    }

    const quay_source = (try docker_config.credentialSourceForRegistry(std.testing.allocator, "quay.io")).?;
    switch (quay_source) {
        .helper => |helper| {
            try std.testing.expectEqualStrings("quay.io", helper.server_url);
            try std.testing.expectEqualStrings("pass", helper.helper_suffix);
        },
        else => return error.TestUnexpectedResult,
    }
}
test "DockerConfig.credentialSourceForRegistry: Docker Hub helper uses historical server key" {
    var docker_config = try parseDockerConfig(std.testing.allocator,
        \\{
        \\  "credHelpers": {
        \\    "docker.io": "secretservice"
        \\  }
        \\}
    );
    defer docker_config.deinit(std.testing.allocator);

    const source = (try docker_config.credentialSourceForRegistry(std.testing.allocator, "registry-1.docker.io")).?;
    switch (source) {
        .helper => |helper| {
            try std.testing.expectEqualStrings(DOCKER_HUB_AUTH_KEY, helper.server_url);
            try std.testing.expectEqualStrings("secretservice", helper.helper_suffix);
        },
        else => return error.TestUnexpectedResult,
    }
}
test "dockerCredentialHelperCommandAlloc: expands helper binary names and rejects invalid suffixes" {
    const command = try dockerCredentialHelperCommandAlloc(std.testing.allocator, "ecr-login");
    defer std.testing.allocator.free(command);

    try std.testing.expectEqualStrings("docker-credential-ecr-login", command);
    try std.testing.expectError(error.InvalidDockerConfig, dockerCredentialHelperCommandAlloc(std.testing.allocator, ""));
    try std.testing.expectError(error.InvalidDockerConfig, dockerCredentialHelperCommandAlloc(std.testing.allocator, "bad helper"));
    try std.testing.expectError(error.InvalidDockerConfig, dockerCredentialHelperCommandAlloc(std.testing.allocator, "../pass"));
}
test "AuthEngine.loadDockerConfigFromEnvironment: loads HOME docker config" {
    const io = std.testing.io;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var docker_dir = try tmp_dir.dir.createDirPathOpen(io, ".docker", .{});
    defer docker_dir.close(io);

    const file = try docker_dir.createFile(io, "config.json", .{ .read = true });
    defer file.close(io);

    var file_buffer: [256]u8 = undefined;
    var file_writer = file.writer(io, &file_buffer);
    try file_writer.interface.writeAll(
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  }
        \\}
    );
    try file_writer.interface.flush();

    const home_dir = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", tmp_dir.sub_path[0..] });
    defer std.testing.allocator.free(home_dir);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(HOME_DIR_VAR, home_dir);

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    defer engine.deinit();

    try std.testing.expect(try engine.loadDockerConfigFromEnvironment(io));

    const handle = (try engine.credentialForRegistry("ghcr.io")).?;
    try std.testing.expectEqualStrings("octocat", handle.credential.username);
    try std.testing.expectEqualStrings("ghp_example", handle.credential.secret);
}
test "AuthEngine.loadDockerConfigFromEnvironment: DOCKER_CONFIG overrides HOME" {
    const io = std.testing.io;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var home_docker_dir = try tmp_dir.dir.createDirPathOpen(io, ".docker", .{});
    defer home_docker_dir.close(io);
    const home_file = try home_docker_dir.createFile(io, "config.json", .{ .read = true });
    defer home_file.close(io);
    var home_buffer: [256]u8 = undefined;
    var home_writer = home_file.writer(io, &home_buffer);
    try home_writer.interface.writeAll(
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "aG9tZS11c2VyOmhvbWUtdG9rZW4="
        \\    }
        \\  }
        \\}
    );
    try home_writer.interface.flush();

    var docker_config_dir = try tmp_dir.dir.createDirPathOpen(io, "docker-config", .{});
    defer docker_config_dir.close(io);
    const docker_config_file = try docker_config_dir.createFile(io, "config.json", .{ .read = true });
    defer docker_config_file.close(io);
    var docker_config_buffer: [256]u8 = undefined;
    var docker_config_writer = docker_config_file.writer(io, &docker_config_buffer);
    try docker_config_writer.interface.writeAll(
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "ZG9ja2VyLXVzZXI6ZG9ja2VyLXRva2Vu"
        \\    }
        \\  }
        \\}
    );
    try docker_config_writer.interface.flush();

    const home_dir = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", tmp_dir.sub_path[0..] });
    defer std.testing.allocator.free(home_dir);
    const docker_config_path = try std.fs.path.join(std.testing.allocator, &.{ home_dir, "docker-config" });
    defer std.testing.allocator.free(docker_config_path);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(HOME_DIR_VAR, home_dir);
    try environ_map.put(DOCKER_CONFIG_DIR_VAR, docker_config_path);

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    defer engine.deinit();

    try std.testing.expect(try engine.loadDockerConfigFromEnvironment(io));

    const handle = (try engine.credentialForRegistry("ghcr.io")).?;
    try std.testing.expectEqualStrings("docker-user", handle.credential.username);
    try std.testing.expectEqualStrings("docker-token", handle.credential.secret);
}
test "AuthEngine.loadDockerConfigFromEnvironment: missing file is a clean miss" {
    const io = std.testing.io;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const home_dir = try std.fs.path.join(std.testing.allocator, &.{ ".zig-cache", "tmp", tmp_dir.sub_path[0..] });
    defer std.testing.allocator.free(home_dir);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(HOME_DIR_VAR, home_dir);

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    defer engine.deinit();

    try std.testing.expect(!(try engine.loadDockerConfigFromEnvironment(io)));
    try std.testing.expect((try engine.credentialForRegistry("ghcr.io")) == null);
}
test "parseDockerCredentialHelperResponse: accepts helper JSON and token-style usernames" {
    const handle = try parseDockerCredentialHelperResponse(std.testing.allocator,
        \\{
        \\  "Username": "<token>",
        \\  "Secret": "eyJhbGciOi..."
        \\}
    );
    defer handle.release();

    try std.testing.expectEqualStrings("<token>", handle.credential.username);
    try std.testing.expectEqualStrings("eyJhbGciOi...", handle.credential.secret);
}
test "parseDockerCredentialHelperResponse: rejects malformed helper payloads" {
    try std.testing.expectError(error.HelperFailed, parseDockerCredentialHelperResponse(std.testing.allocator,
        \\{
        \\  "Username": "david"
        \\}
    ));
    try std.testing.expectError(error.HelperFailed, parseDockerCredentialHelperResponse(std.testing.allocator,
        \\{
        \\  "Username": "david",
        \\  "Secret": ""
        \\}
    ));
    try std.testing.expectError(error.HelperFailed, parseDockerCredentialHelperResponse(std.testing.allocator, "not-json"));
}
test "runDockerCredentialHelperCommand: writes stdin and parses stdout" {
    if (builtin.os.tag == .windows) return;

    const handle = try runDockerCredentialHelperCommand(
        std.testing.allocator,
        std.testing.io,
        &.{
            "/bin/sh",
            "-c",
            "IFS= read -r server || exit 7\n[ \"$1\" = get ] || exit 9\n[ \"$server\" = \"https://index.docker.io/v1/\" ] || exit 8\nprintf '{\"Username\":\"david\",\"Secret\":\"passw0rd1\"}'\n",
            "docker-credential-secretservice",
            "get",
        },
        DOCKER_HUB_AUTH_KEY,
        .none,
    );
    defer handle.release();

    try std.testing.expectEqualStrings("david", handle.credential.username);
    try std.testing.expectEqualStrings("passw0rd1", handle.credential.secret);
}
test "runDockerCredentialHelperCommand: rejects non-zero exit and malformed JSON" {
    if (builtin.os.tag == .windows) return;

    try std.testing.expectError(error.HelperFailed, runDockerCredentialHelperCommand(
        std.testing.allocator,
        std.testing.io,
        &.{
            "/bin/sh",
            "-c",
            "echo helper failed >&2\nexit 3\n",
            "docker-credential-secretservice",
            "get",
        },
        "ghcr.io",
        .none,
    ));

    try std.testing.expectError(error.HelperFailed, runDockerCredentialHelperCommand(
        std.testing.allocator,
        std.testing.io,
        &.{
            "/bin/sh",
            "-c",
            "IFS= read -r _ || exit 7\nprintf 'not-json'\n",
            "docker-credential-secretservice",
            "get",
        },
        "ghcr.io",
        .none,
    ));
}
test "runDockerCredentialHelperCommand: timeout kills hung helper" {
    if (builtin.os.tag == .windows) return;

    try std.testing.expectError(error.HelperTimedOut, runDockerCredentialHelperCommand(
        std.testing.allocator,
        std.testing.io,
        &.{
            "/bin/sh",
            "-c",
            "IFS= read -r _ || exit 7\nsleep 1\nprintf '{\"Username\":\"late\",\"Secret\":\"late\"}'\n",
            "docker-credential-secretservice",
            "get",
        },
        "ghcr.io",
        .{ .duration = .{ .raw = std.Io.Duration.fromMilliseconds(10), .clock = .awake } },
    ));
}
test "runDockerCredentialHelperCommand: timeout does not poison the next helper run" {
    if (builtin.os.tag == .windows) return;

    try std.testing.expectError(error.HelperTimedOut, runDockerCredentialHelperCommand(
        std.testing.allocator,
        std.testing.io,
        &.{
            "/bin/sh",
            "-c",
            "IFS= read -r _ || exit 7\nsleep 1\nprintf '{\"Username\":\"late\",\"Secret\":\"late\"}'\n",
            "docker-credential-secretservice",
            "get",
        },
        "ghcr.io",
        .{ .duration = .{ .raw = std.Io.Duration.fromMilliseconds(10), .clock = .awake } },
    ));

    const handle = try runDockerCredentialHelperCommand(
        std.testing.allocator,
        std.testing.io,
        &.{
            "/bin/sh",
            "-c",
            "IFS= read -r server || exit 7\n[ \"$1\" = get ] || exit 9\n[ \"$server\" = \"ghcr.io\" ] || exit 8\nprintf '{\"Username\":\"recovered\",\"Secret\":\"secret\"}'\n",
            "docker-credential-secretservice",
            "get",
        },
        "ghcr.io",
        .none,
    );
    defer handle.release();

    try std.testing.expectEqualStrings("recovered", handle.credential.username);
    try std.testing.expectEqualStrings("secret", handle.credential.secret);
}
test "runDockerCredentialHelperCommand: failed helper does not poison the next helper run" {
    if (builtin.os.tag == .windows) return;

    try std.testing.expectError(error.HelperFailed, runDockerCredentialHelperCommand(
        std.testing.allocator,
        std.testing.io,
        &.{
            "/bin/sh",
            "-c",
            "echo helper failed >&2\nexit 3\n",
            "docker-credential-secretservice",
            "get",
        },
        "ghcr.io",
        .none,
    ));

    const handle = try runDockerCredentialHelperCommand(
        std.testing.allocator,
        std.testing.io,
        &.{
            "/bin/sh",
            "-c",
            "IFS= read -r server || exit 7\n[ \"$1\" = get ] || exit 9\n[ \"$server\" = \"ghcr.io\" ] || exit 8\nprintf '{\"Username\":\"recovered\",\"Secret\":\"secret\"}'\n",
            "docker-credential-secretservice",
            "get",
        },
        "ghcr.io",
        .none,
    );
    defer handle.release();

    try std.testing.expectEqualStrings("recovered", handle.credential.username);
    try std.testing.expectEqualStrings("secret", handle.credential.secret);
}
test "AuthEngine.dockerCredentialForRegistry: helper path beats inline auth when helper context exists" {
    const State = struct {
        var calls: usize = 0;

        fn runner(allocator: std.mem.Allocator, _: std.Io, helper_suffix: []const u8, server_url: []const u8, timeout: std.Io.Timeout) AuthError!CredentialHandle {
            calls += 1;
            if (!std.mem.eql(u8, helper_suffix, "secretservice")) return error.HelperFailed;
            if (!std.mem.eql(u8, server_url, "ghcr.io")) return error.HelperFailed;
            switch (timeout) {
                .duration => |duration| {
                    if (duration.clock != .awake) return error.HelperFailed;
                    if (duration.raw.toMilliseconds() != 30_000) return error.HelperFailed;
                },
                else => return error.HelperFailed,
            }
            return try ownedCredentialHandle(allocator, "helper-user", "helper-secret");
        }
    };

    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "ghcr.io": "secretservice"
        \\  }
        \\}
    );
    defer engine.deinit();
    engine.docker_helper_config = .{
        .io = std.testing.io,
        .runner = State.runner,
    };

    const handle = (try engine.dockerCredentialForRegistry("ghcr.io")).?;
    defer handle.release();

    try std.testing.expectEqual(@as(usize, 1), State.calls);
    try std.testing.expectEqualStrings("helper-user", handle.credential.username);
    try std.testing.expectEqualStrings("helper-secret", handle.credential.secret);
}
test "AuthEngine.dockerCredentialForRegistry: Quay global helper canonicalizes mixed-case registry host" {
    const State = struct {
        var calls: usize = 0;

        fn runner(allocator: std.mem.Allocator, _: std.Io, helper_suffix: []const u8, server_url: []const u8, _: std.Io.Timeout) AuthError!CredentialHandle {
            calls += 1;
            if (!std.mem.eql(u8, helper_suffix, "pass")) return error.HelperFailed;
            if (!std.mem.eql(u8, server_url, "quay.io")) return error.HelperFailed;
            return try ownedCredentialHandle(allocator, "quay-user", "quay-secret");
        }
    };

    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "credsStore": "pass"
        \\}
    );
    defer engine.deinit();
    engine.docker_helper_config = .{ .io = std.testing.io, .runner = State.runner };

    const handle = (try engine.dockerCredentialForRegistry("QuAy.IO")).?;
    defer handle.release();

    try std.testing.expectEqual(@as(usize, 1), State.calls);
    try std.testing.expectEqualStrings("quay-user", handle.credential.username);
    try std.testing.expectEqualStrings("quay-secret", handle.credential.secret);
}
test "AuthEngine.dockerCredentialForRegistry: inline auth remains available without helper context" {
    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "ghcr.io": "secretservice"
        \\  }
        \\}
    );
    defer engine.deinit();

    const handle = (try engine.dockerCredentialForRegistry("ghcr.io")).?;

    try std.testing.expectEqualStrings("octocat", handle.credential.username);
    try std.testing.expectEqualStrings("ghp_example", handle.credential.secret);
}
test "AuthEngine.authenticate: helper-backed Docker credentials feed optional basic auth" {
    const HelperState = struct {
        fn runner(allocator: std.mem.Allocator, _: std.Io, helper_suffix: []const u8, server_url: []const u8, _: std.Io.Timeout) AuthError!CredentialHandle {
            if (!std.mem.eql(u8, helper_suffix, "secretservice")) return error.HelperFailed;
            if (!std.mem.eql(u8, server_url, "ghcr.io")) return error.HelperFailed;
            return try ownedCredentialHandle(allocator, "helper-user", "helper-secret");
        }
    };

    const ExchangeState = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Basic aGVscGVyLXVzZXI6aGVscGVyLXNlY3JldA==")) {
                return error.TokenExchangeFailed;
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "helper-token"
            \\}
            };
        }
    };

    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "credHelpers": {
        \\    "ghcr.io": "secretservice"
        \\  }
        \\}
    );
    defer engine.deinit();
    engine.docker_helper_config = .{ .io = std.testing.io, .runner = HelperState.runner };
    engine.token_http_exchanger = ExchangeState.exchange;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "ghcr.io",
        .{ .realm = "https://auth.example.test/token" },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("helper-token", response.access_token.value);
}
test "AuthEngine.authenticate: helper failure stays terminal when helper is configured" {
    const HelperState = struct {
        fn runner(_: std.mem.Allocator, _: std.Io, _: []const u8, _: []const u8, _: std.Io.Timeout) AuthError!CredentialHandle {
            return error.HelperFailed;
        }
    };

    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "ghcr.io": "secretservice"
        \\  }
        \\}
    );
    defer engine.deinit();
    engine.docker_helper_config = .{ .io = std.testing.io, .runner = HelperState.runner };
    engine.token_http_exchanger = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }
    }.exchange;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "ghcr.io",
        .{ .realm = "https://auth.example.test/token" },
    );

    try std.testing.expectError(error.HelperFailed, engine.authenticate(&client, request));
}
test "AuthEngine.authenticate: helper timeout stays terminal when helper is configured" {
    const HelperState = struct {
        fn runner(_: std.mem.Allocator, _: std.Io, _: []const u8, _: []const u8, _: std.Io.Timeout) AuthError!CredentialHandle {
            return error.HelperTimedOut;
        }
    };

    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "ghcr.io": "secretservice"
        \\  }
        \\}
    );
    defer engine.deinit();
    engine.docker_helper_config = .{ .io = std.testing.io, .runner = HelperState.runner };
    engine.token_http_exchanger = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }
    }.exchange;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "ghcr.io",
        .{ .realm = "https://auth.example.test/token" },
    );

    try std.testing.expectError(error.HelperTimedOut, engine.authenticate(&client, request));
}
test "AuthEngine.authenticate: generic self-hosted bearer registry path uses docker config auth" {
    const ExchangeState = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);

            if (request.method != .get) return error.TokenExchangeFailed;
            if (!std.mem.eql(
                u8,
                request.url,
                "https://registry.example.com/jwt/auth?service=container_registry&scope=repository%3Ateam%2Fproject%2Fimage%3Apull",
            )) return error.TokenExchangeFailed;
            if (request.body != null) return error.TokenExchangeFailed;
            if (request.authorization == null) return error.TokenExchangeFailed;
            if (!std.mem.eql(u8, request.authorization.?, "Basic aW50ZXJuYWwtdXNlcjp0b2tlbg==")) {
                return error.TokenExchangeFailed;
            }

            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "self-hosted-token"
            \\}
            };
        }
    };

    var engine = try AuthEngine.initWithDockerConfigBytes(std.testing.allocator, Config{},
        \\{
        \\  "auths": {
        \\    "registry.example.com": {
        \\      "auth": "aW50ZXJuYWwtdXNlcjp0b2tlbg=="
        \\    }
        \\  }
        \\}
    );
    defer engine.deinit();
    engine.token_http_exchanger = ExchangeState.exchange;

    const probe = ProbeHttpResponse{
        .status = .unauthorized,
        .www_authenticate_headers = &.{"Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:team/project/image:pull\""},
    };
    const classified = try probe.classify();

    try std.testing.expect(classified == .auth_required);

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init("registry.example.com", classified.auth_required.bearer);
    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("self-hosted-token", response.access_token.value);
}
test "buildTokenHttpRequest: get request includes query parameters" {
    const request = try AuthenticateRequest.init(
        "registry-1.docker.io",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:library/ubuntu:pull",
        },
    );

    var http_request = try buildTokenHttpRequest(std.testing.allocator, request, .get, null);
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqual(TokenRequestMethod.get, http_request.method);
    try std.testing.expectEqualStrings(
        "https://auth.example.test/token?service=registry.example.test&scope=repository%3Alibrary%2Fubuntu%3Apull",
        http_request.url,
    );
    try std.testing.expect(http_request.authorization == null);
    try std.testing.expect(http_request.body == null);
}
test "buildTokenHttpRequest: get request omits empty query delimiter" {
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{ .realm = "https://auth.example.test/token" },
    );

    var http_request = try buildTokenHttpRequest(std.testing.allocator, request, .get, null);
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("https://auth.example.test/token", http_request.url);
    try std.testing.expect(http_request.authorization == null);
    try std.testing.expect(http_request.body == null);
}
test "buildTokenHttpRequest: post request includes body and optional basic auth" {
    const request = try AuthenticateRequest.init(
        "ghcr.io",
        .{
            .realm = "https://auth.example.test/token",
            .service = "ghcr.io",
            .scope = "repository:owner/image:pull",
        },
    );

    var http_request = try buildTokenHttpRequest(
        std.testing.allocator,
        request,
        .post,
        .{ .username = "user", .secret = "token" },
    );
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqual(TokenRequestMethod.post, http_request.method);
    try std.testing.expectEqualStrings("https://auth.example.test/token", http_request.url);
    try std.testing.expectEqualStrings("application/x-www-form-urlencoded", http_request.content_type.?);
    try std.testing.expectEqualStrings("service=ghcr.io&scope=repository%3Aowner%2Fimage%3Apull", http_request.body.?);
    try std.testing.expectEqualStrings("Basic dXNlcjp0b2tlbg==", http_request.authorization.?);
}
test "freeOwnedOptionalSecretSlice: secureZero clears owned dupe" {
    // Documents the first step of freeOwnedOptionalSecretSlice; deinit uses that helper for auth/body.
    const secret = try std.testing.allocator.dupe(u8, "service=registry.example.test&scope=pull");
    defer std.testing.allocator.free(secret);
    try std.testing.expect(secret[0] != 0);

    std.crypto.secureZero(u8, secret);
    try std.testing.expectEqual(@as(u8, 0), secret[0]);
    try std.testing.expectEqual(@as(u8, 0), secret[secret.len - 1]);
}
test "ownedCredentialHandle.release: exercises secureZero-on-free path" {
    const handle = try ownedCredentialHandle(std.testing.allocator, "user", "secret-token");
    handle.release();
}
test "TokenHttpRequest.deinit: post teardown stays leak-free under allocation failure" {
    const State = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const request = try AuthenticateRequest.init(
                "ghcr.io",
                .{
                    .realm = "https://auth.example.test/token",
                    .service = "ghcr.io",
                    .scope = "repository:owner/image:pull",
                },
            );

            var http_request = try buildTokenHttpRequest(
                allocator,
                request,
                .post,
                .{ .username = "user", .secret = "token" },
            );

            const body = http_request.body orelse return error.TestExpectedEqual;
            try std.testing.expect(body[0] != 0);

            http_request.deinit(allocator);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "buildTokenHttpRequest: docker token auth uses repeated scope query parameters" {
    const request = try AuthenticateRequest.init(
        "registry-1.docker.io",
        .{
            .realm = "https://auth.docker.io/token",
            .service = "registry.docker.io",
            .scope = "repository:samalba/my-app:pull repository:samalba/my-app:push",
        },
    );

    var http_request = try buildTokenHttpRequest(std.testing.allocator, request, .get, null);
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Asamalba%2Fmy-app%3Apull&scope=repository%3Asamalba%2Fmy-app%3Apush",
        http_request.url,
    );
}
test "buildTokenHttpRequest: quay realm and host service stay intact" {
    const request = try AuthenticateRequest.init(
        "quay.io",
        .{
            .realm = "https://quay.io/v2/auth",
            .service = "quay.io",
            .scope = "repository:quay/listocireferrs:pull,push",
        },
    );

    var http_request = try buildTokenHttpRequest(std.testing.allocator, request, .get, null);
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "https://quay.io/v2/auth?service=quay.io&scope=repository%3Aquay%2Flistocireferrs%3Apull%2Cpush",
        http_request.url,
    );
}
test "buildTokenHttpRequest: ghcr realm and service stay intact" {
    const request = try AuthenticateRequest.init(
        "ghcr.io",
        .{
            .realm = "https://ghcr.io/token",
            .service = "ghcr.io",
            .scope = "repository:owner/image:pull",
        },
    );

    var http_request = try buildTokenHttpRequest(std.testing.allocator, request, .get, null);
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "https://ghcr.io/token?service=ghcr.io&scope=repository%3Aowner%2Fimage%3Apull",
        http_request.url,
    );
}
test "parseTokenResponse: accepts matching duplicate token fields and preserves refresh token" {
    var response = try parseTokenResponse(std.testing.allocator,
        \\{
        \\  "token": "preferred-token",
        \\  "access_token": "preferred-token",
        \\  "expires_in": 300,
        \\  "refresh_token": "ignored-for-now"
        \\}
    );
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("preferred-token", response.access_token.value);
    try std.testing.expectEqual(@as(?u64, 300), response.access_token.expires_in_seconds);
    try std.testing.expectEqualStrings("ignored-for-now", response.refresh_token.?);
}
test "parseTokenResponse: falls back to token without expires_in" {
    var response = try parseTokenResponse(std.testing.allocator,
        \\{
        \\  "token": "fallback-token"
        \\}
    );
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("fallback-token", response.access_token.value);
    try std.testing.expect(response.access_token.expires_in_seconds == null);
    try std.testing.expect(response.refresh_token == null);
}
test "parseTokenResponse: conflicting token fields are rejected" {
    try std.testing.expectError(error.InvalidTokenResponse, parseTokenResponse(std.testing.allocator,
        \\{
        \\  "token": "fallback-token",
        \\  "access_token": "preferred-token"
        \\}
    ));
}
test "parseTokenResponse: malformed payloads are rejected" {
    const cases = [_][]const u8{
        "{\"expires_in\": 60}",
        "{\"access_token\": \"\"}",
        "{\"access_token\": \"value\", \"refresh_token\": \"\"}",
        "{\"access_token\": \"value\", \"expires_in\": -1}",
        "{\"access_token\": \"value\", \"expires_in\": 0}",
        "{\"access_token\": \"value\", \"expires_in\": 4294967296}",
        "not-json",
    };

    for (cases) |case| {
        try std.testing.expectError(error.InvalidTokenResponse, parseTokenResponse(std.testing.allocator, case));
    }
}
test "parseTokenResponse: allocation failures do not leak owned token fields" {
    const State = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var response = try parseTokenResponse(allocator,
                \\{
                \\  "access_token": "preferred-token",
                \\  "refresh_token": "refresh-token",
                \\  "expires_in": 300
                \\}
            );
            defer response.deinit(allocator);

            try std.testing.expectEqualStrings("preferred-token", response.access_token.value);
            try std.testing.expectEqualStrings("refresh-token", response.refresh_token.?);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "buildTokenHttpRequest: allocation failures do not leak request-owned buffers" {
    const State = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const request = try AuthenticateRequest.init(
                "ghcr.io",
                .{
                    .realm = "https://auth.example.test/token",
                    .service = "ghcr.io",
                    .scope = "repository:owner/image:pull",
                },
            );

            var http_request = try buildTokenHttpRequest(
                allocator,
                request,
                .post,
                .{ .username = "user", .secret = "token" },
            );
            defer http_request.deinit(allocator);

            try std.testing.expectEqual(TokenRequestMethod.post, http_request.method);
            try std.testing.expectEqualStrings("https://auth.example.test/token", http_request.url);
            try std.testing.expectEqualStrings("application/x-www-form-urlencoded", http_request.content_type.?);
            try std.testing.expectEqualStrings("service=ghcr.io&scope=repository%3Aowner%2Fimage%3Apull", http_request.body.?);
            try std.testing.expectEqualStrings("Basic dXNlcjp0b2tlbg==", http_request.authorization.?);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "AuthEngine.authenticate: uses post fallback after get failure" {
    const State = struct {
        var calls: usize = 0;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;

            if (calls == 1) {
                if (request.method != .get) return error.TokenExchangeFailed;
                return .{ .status = .unauthorized, .body = "" };
            }

            if (request.method != .post) return error.TokenExchangeFailed;
            if (request.content_type == null or !std.mem.eql(u8, request.content_type.?, "application/x-www-form-urlencoded")) {
                return error.TokenExchangeFailed;
            }
            if (request.body == null or !std.mem.eql(u8, request.body.?, "service=registry.example.test&scope=repository%3Aowner%2Fimage%3Apull")) {
                return error.TokenExchangeFailed;
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "post-token",
            \\  "expires_in": 120
            \\}
            };
        }
    };

    State.calls = 0;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expectEqualStrings("post-token", response.access_token.value);
    try std.testing.expectEqual(@as(?u64, 120), response.access_token.expires_in_seconds);
}
test "AuthEngine.authenticate: retries transient 503 on token exchange then succeeds" {
    const State = struct {
        var calls: usize = 0;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;

            if (request.method != .get) return error.TokenExchangeFailed;
            if (calls == 1) return .{ .status = .service_unavailable, .body = "" };
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "retry-token",
            \\  "expires_in": 120
            \\}
            };
        }
    };

    defer State.calls = 0;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 1,
    }, State.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expectEqualStrings("retry-token", response.access_token.value);
}
test "AuthEngine.authenticate: retries connection reset on token exchange then succeeds" {
    const State = struct {
        var calls: usize = 0;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;

            if (request.method != .get) return error.TokenExchangeFailed;
            if (calls == 1) return error.ConnectionResetByPeer;
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "reset-token",
            \\  "expires_in": 120
            \\}
            };
        }
    };

    defer State.calls = 0;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 1,
    }, State.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expectEqualStrings("reset-token", response.access_token.value);
}
test "AuthEngine.authenticate: exhausts repeated 429 on token exchange" {
    const State = struct {
        var calls: usize = 0;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            return .{
                .status = .too_many_requests,
                .body = "",
                .resilience_headers = &.{
                    .{ .name = "Retry-After", .value = "1" },
                },
            };
        }
    };

    defer State.calls = 0;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_rate_limit_retries = 0,
    }, State.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    try std.testing.expectError(error.RateLimited, engine.authenticate(&client, request));
    try std.testing.expectEqual(@as(usize, 2), State.calls);
}
test "AuthEngine.authenticate: GET 429 then POST auth failure stays TokenExchangeFailed" {
    const State = struct {
        var calls: usize = 0;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            return switch (request.method) {
                .get => .{
                    .status = .too_many_requests,
                    .body = "",
                    .resilience_headers = &.{
                        .{ .name = "Retry-After", .value = "1" },
                    },
                },
                .post => .{ .status = .unauthorized, .body = "" },
            };
        }
    };

    defer State.calls = 0;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_rate_limit_retries = 0,
    }, State.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    try std.testing.expectError(error.TokenExchangeFailed, engine.authenticate(&client, request));
    try std.testing.expectEqual(@as(usize, 2), State.calls);
}
test "AuthEngine.authenticate: oversize token transport body maps to InvalidTokenResponse" {
    const custom_cap: usize = 4096;
    const State = struct {
        var seen_cap: ?usize = null;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            seen_cap = request.max_response_body_bytes;
            return mapLiveTokenTransportError(error.BodyTooLarge);
        }
    };

    State.seen_cap = null;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_token_response_bytes = custom_cap,
    }, State.exchange);
    defer engine.deinit();

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    try std.testing.expectError(error.InvalidTokenResponse, engine.authenticate(&client, request));
    try std.testing.expectEqual(custom_cap, State.seen_cap.?);
}
test "AuthEngine.authenticate: rate-limit retry path stays leak-free under DebugAllocator" {
    const State = struct {
        var calls: usize = 0;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(allocator);
            calls += 1;
            if (@rem(calls, 2) == 1) {
                return .{
                    .status = .too_many_requests,
                    .body = "",
                    .resilience_headers = &.{
                        .{ .name = "Retry-After", .value = "1" },
                    },
                };
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "retry-debug-token",
            \\  "expires_in": 3600
            \\}
            };
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var engine = AuthEngine.initWithTokenHttpExchanger(allocator, .{
        .max_rate_limit_retries = 1,
    }, State.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;

    for (0..32) |i| {
        var buf: [96]u8 = undefined;
        const scope = try std.fmt.bufPrint(&buf, "repository:owner/image{d}:pull", .{i});
        const request = try AuthenticateRequest.init(
            "registry.example.test",
            .{
                .realm = "https://auth.example.test/token",
                .service = "registry.example.test",
                .scope = scope,
            },
        );

        var response = (try engine.authenticate(&client, request)).?;
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("retry-debug-token", response.access_token.value);
    }
}
test "AuthEngine.authenticate: cache hit reuses valid token response" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            if (request.method != .get) return error.TokenExchangeFailed;
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "cached-token",
            \\  "expires_in": 90
            \\}
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var first = (try engine.authenticate(&client, request)).?;
    defer first.deinit(std.testing.allocator);
    State.fake_now = 1_002;
    var second = (try engine.authenticate(&client, request)).?;
    try std.testing.expectEqual(@as(usize, 1), State.calls);
    try std.testing.expectEqual(@as(usize, 1), engine.token_cache.count());
    try std.testing.expectEqualStrings("cached-token", first.access_token.value);
    try std.testing.expectEqualStrings("cached-token", second.access_token.value);
    try std.testing.expect(!first.owns_access_token);
    try std.testing.expect(!second.owns_access_token);
    try std.testing.expectEqual(
        engine.token_cache.getAdapted(request, TokenCacheRequestContext{}).?.token.value.ptr,
        second.access_token.value.ptr,
    );

    second.deinit(std.testing.allocator);
    var third = (try engine.authenticate(&client, request)).?;
    defer third.deinit(std.testing.allocator);
    try std.testing.expect(!third.owns_access_token);
    try std.testing.expectEqualStrings("cached-token", third.access_token.value);
}
test "AuthEngine.authenticate: cache miss borrows stored token without duplicate buffer" {
    const State = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "single-copy-token",
            \\  "expires_in": 90
            \\}
            };
        }

        fn now(_: *std.http.Client) u64 {
            return 1_000;
        }
    };

    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);
    try std.testing.expect(!response.owns_access_token);
    try std.testing.expectEqual(
        engine.token_cache.getAdapted(request, TokenCacheRequestContext{}).?.token.value.ptr,
        response.access_token.value.ptr,
    );
}
test "AuthEngine.authenticate: token without expires_in expires after default cache TTL" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "no-expiry-token"
            \\}
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var first = (try engine.authenticate(&client, request)).?;
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), State.calls);
    try std.testing.expectEqualStrings("no-expiry-token", first.access_token.value);

    State.fake_now = 1_000 + DEFAULT_TOKEN_CACHE_TTL_SECONDS - TOKEN_REFRESH_WINDOW_SECONDS - 1;
    var second = (try engine.authenticate(&client, request)).?;
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), State.calls);

    State.fake_now += 1;
    var third = (try engine.authenticate(&client, request)).?;
    defer third.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expectEqualStrings("no-expiry-token", third.access_token.value);
}
test "AuthEngine.authenticate: max_token_cache_entries evicts LRU entry" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            return switch (calls) {
                1 => .{ .status = .ok, .body = "{\"access_token\": \"token-a\", \"expires_in\": 3600}" },
                2 => .{ .status = .ok, .body = "{\"access_token\": \"token-b\", \"expires_in\": 3600}" },
                3 => .{ .status = .ok, .body = "{\"access_token\": \"token-c\", \"expires_in\": 3600}" },
                else => unreachable,
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_token_cache_entries = 2,
    }, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const request_a = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:scope=a:pull",
        },
    );
    const request_b = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:scope=b:pull",
        },
    );
    const request_c = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:scope=c:pull",
        },
    );

    var first_a = (try engine.authenticate(&client, request_a)).?;
    defer first_a.deinit(std.testing.allocator);
    State.fake_now += 1;
    var first_b = (try engine.authenticate(&client, request_b)).?;
    defer first_b.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), engine.token_cache.count());

    State.fake_now += 1;
    var first_c = (try engine.authenticate(&client, request_c)).?;
    defer first_c.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), engine.token_cache.count());
    try std.testing.expect(engine.token_cache.getAdapted(request_a, TokenCacheRequestContext{}) == null);
    try std.testing.expectEqualStrings("token-b", engine.token_cache.getAdapted(request_b, TokenCacheRequestContext{}).?.token.value);
    try std.testing.expectEqualStrings("token-c", engine.token_cache.getAdapted(request_c, TokenCacheRequestContext{}).?.token.value);

    State.fake_now += 1;
    var hit_b = (try engine.authenticate(&client, request_b)).?;
    defer hit_b.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), State.calls);
    try std.testing.expectEqualStrings("token-b", hit_b.access_token.value);
}
test "AuthEngine.authenticate: expired cached token triggers fresh exchange" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            return switch (calls) {
                1 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "first-token",
                \\  "expires_in": 10
                \\}
                },
                2 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "second-token",
                \\  "expires_in": 10
                \\}
                },
                else => unreachable,
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var first = (try engine.authenticate(&client, request)).?;
    defer first.deinit(std.testing.allocator);
    const first_token_value = try std.testing.allocator.dupe(u8, first.access_token.value);
    defer std.testing.allocator.free(first_token_value);
    State.fake_now = 1_006;
    var second = (try engine.authenticate(&client, request)).?;
    defer second.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expectEqual(@as(usize, 1), engine.token_cache.count());
    try std.testing.expectEqualStrings("second-token", engine.token_cache.getAdapted(request, TokenCacheRequestContext{}).?.token.value);
    try std.testing.expectEqualStrings("first-token", first_token_value);
    try std.testing.expectEqualStrings("second-token", second.access_token.value);
}
test "AuthEngine.cachedTokenResponseForRequest: expired entry is dropped before cache miss" {
    const State = struct {
        fn now(_: *std.http.Client) u64 {
            return 2_000;
        }
    };

    var engine = AuthEngine.init(std.testing.allocator, Config{});
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    try putCachedTokenEntryForTest(
        &engine,
        request,
        try CachedToken.initOwned(
            std.testing.allocator,
            .{ .value = "expired-token", .expires_in_seconds = 10 },
            1_995,
        ),
    );

    var client: std.http.Client = undefined;
    try std.testing.expectEqual(@as(usize, 1), engine.token_cache.count());
    try std.testing.expect((try engine.cachedTokenResponseForRequest(&client, request)) == null);
    try std.testing.expectEqual(@as(usize, 0), engine.token_cache.count());
}
test "AuthEngine.cachedTokenResponseForRequest: missing valid_until is treated as expired" {
    const State = struct {
        fn now(_: *std.http.Client) u64 {
            return 2_000;
        }
    };

    var engine = AuthEngine.init(std.testing.allocator, Config{});
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    try putCachedTokenEntryForTest(
        &engine,
        request,
        try CachedToken.initOwned(
            std.testing.allocator,
            .{ .value = "missing-ttl-token", .expires_in_seconds = 3600 },
            null,
        ),
    );

    var client: std.http.Client = undefined;
    try std.testing.expect((try engine.cachedTokenResponseForRequest(&client, request)) == null);
    try std.testing.expectEqual(@as(usize, 0), engine.token_cache.count());
}
test "AuthEngine.retryAuthenticateAfterCachedUnauthorized: invalidates exact cached entry and refetches" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            return switch (calls) {
                1 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "cached-token",
                \\  "expires_in": 90
                \\}
                },
                2 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "retried-token",
                \\  "expires_in": 90
                \\}
                },
                else => unreachable,
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var first = (try engine.authenticate(&client, request)).?;
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), engine.token_cache.count());

    var retried = (try engine.retryAuthenticateAfterCachedUnauthorized(&client, request)).?;
    defer retried.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expectEqual(@as(usize, 1), engine.token_cache.count());
    try std.testing.expectEqualStrings("retried-token", retried.access_token.value);
}
test "AuthEngine.retryAuthenticateAfterCachedUnauthorized: max_retries zero disables retry" {
    const State = struct {
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "cached-token",
            \\  "expires_in": 90
            \\}
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{ .max_retries = 0 }, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var first = (try engine.authenticate(&client, request)).?;
    defer first.deinit(std.testing.allocator);

    try std.testing.expectError(error.TokenExchangeFailed, engine.retryAuthenticateAfterCachedUnauthorized(&client, request));
    try std.testing.expectEqual(@as(usize, 1), engine.token_cache.count());
}
test "AuthEngine.authenticate: different scopes keep separate cache entries" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            if (request.url.len == 0) return error.TokenExchangeFailed;
            return switch (calls) {
                1 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "scope-one-token",
                \\  "expires_in": 90
                \\}
                },
                2 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "scope-two-token",
                \\  "expires_in": 90
                \\}
                },
                else => unreachable,
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const first_request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image-a:pull",
        },
    );
    const second_request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image-b:pull",
        },
    );

    var first = (try engine.authenticate(&client, first_request)).?;
    defer first.deinit(std.testing.allocator);
    var second = (try engine.authenticate(&client, second_request)).?;
    defer second.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expectEqual(@as(usize, 2), engine.token_cache.count());
    try std.testing.expectEqualStrings("scope-one-token", first.access_token.value);
    try std.testing.expectEqualStrings("scope-two-token", second.access_token.value);
}
test "AuthEngine.retryAuthenticateAfterCachedUnauthorized: replacement keeps one exact entry" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            return switch (calls) {
                1 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "first-cached-token",
                \\  "expires_in": 90
                \\}
                },
                2 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "replacement-token",
                \\  "expires_in": 90
                \\}
                },
                else => unreachable,
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var first = (try engine.authenticate(&client, request)).?;
    defer first.deinit(std.testing.allocator);
    var replaced = (try engine.retryAuthenticateAfterCachedUnauthorized(&client, request)).?;
    defer replaced.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.calls);
    try std.testing.expectEqual(@as(usize, 1), engine.token_cache.count());
    try std.testing.expectEqualStrings("replacement-token", engine.token_cache.getAdapted(request, TokenCacheRequestContext{}).?.token.value);
}
test "AuthEngine.authenticate: allocation failures do not leak during cache insertion" {
    const State = struct {
        fn now(_: *std.http.Client) u64 {
            return 1_000;
        }

        fn run(allocator: std.mem.Allocator) !void {
            var engine = AuthEngine.init(allocator, Config{});
            defer engine.deinit();
            engine.now_unix_seconds_fn = now;

            var client: std.http.Client = undefined;
            const request = try AuthenticateRequest.init(
                "registry.example.test",
                .{
                    .realm = "https://auth.example.test/token",
                    .service = "registry.example.test",
                    .scope = "repository:owner/image:pull",
                },
            );

            var response = TokenResponse{
                .access_token = .{
                    .value = try allocator.dupe(u8, "alloc-check-token"),
                    .expires_in_seconds = 90,
                },
            };
            defer response.deinit(allocator);

            try engine.storeTokenResponseForRequest(&client, request, &response);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, State.run, .{});
}
test "AuthEngine.authenticate: uses credential handle for optional basic auth" {
    const ProviderState = struct {
        var released = false;

        fn release(_: std.mem.Allocator, _: ConfigModule.Credential) void {
            released = true;
        }

        fn get(_: []const u8) ?CredentialHandle {
            return .{
                .credential = .{ .username = "user", .secret = "token" },
                .release_fn = release,
                .release_allocator = std.testing.allocator,
            };
        }
    };

    const ExchangeState = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Basic dXNlcjp0b2tlbg==")) {
                return error.TokenExchangeFailed;
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "credential-token"
            \\}
            };
        }
    };

    ProviderState.released = false;
    const provider = CredentialProvider{ .getCredentialFn = ProviderState.get };
    var engine = AuthEngine.initWithTokenHttpExchanger(
        std.testing.allocator,
        .{ .credential_provider = &provider },
        ExchangeState.exchange,
    );
    defer engine.deinit();
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "ghcr.io",
        .{ .realm = "https://auth.example.test/token" },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("credential-token", response.access_token.value);
    try std.testing.expect(ProviderState.released);
}
test "AuthEngine.authenticate: Docker Hub normalized reference uses env credentials for optional basic auth" {
    const ExchangeState = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            if (request.method != .get) return error.TokenExchangeFailed;
            if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Basic ZG9ja2VyLXVzZXI6ZG9ja2VyLXRva2Vu")) {
                return error.TokenExchangeFailed;
            }
            if (!std.mem.eql(u8, request.url, "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fubuntu%3Apull")) {
                return error.TokenExchangeFailed;
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "docker-hub-auth-token"
            \\}
            };
        }
    };

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "docker.io");
    try environ_map.put(ENV_REGISTRY_USER, "docker-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "docker-token");

    var ref = try Reference.parse(std.testing.allocator, "docker.io/ubuntu:latest");
    defer ref.deinit(std.testing.allocator);
    const view = referenceView(ref);

    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, ExchangeState.exchange);
    defer engine.deinit();
    engine.environ_map = &environ_map;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        view.registry,
        .{
            .realm = "https://auth.docker.io/token",
            .service = "registry.docker.io",
            .scope = "repository:library/ubuntu:pull",
        },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("docker-hub-auth-token", response.access_token.value);
}
test "AuthEngine.authenticate: env-owned credentials stay leak-free under DebugAllocator" {
    const ExchangeState = struct {
        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(allocator);
            if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Basic ZG9ja2VyLXVzZXI6ZG9ja2VyLXRva2Vu")) {
                return error.TokenExchangeFailed;
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "env-debug-token"
            \\}
            };
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "docker.io");
    try environ_map.put(ENV_REGISTRY_USER, "docker-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "docker-token");

    for (0..4) |_| {
        var engine = AuthEngine.initWithTokenHttpExchanger(allocator, Config{}, ExchangeState.exchange);
        defer engine.deinit();
        engine.environ_map = &environ_map;

        var client: std.http.Client = undefined;
        const request = try AuthenticateRequest.init(
            "registry-1.docker.io",
            .{
                .realm = "https://auth.docker.io/token",
                .service = "registry.docker.io",
                .scope = "repository:library/ubuntu:pull",
            },
        );

        var response = (try engine.authenticate(&client, request)).?;
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("env-debug-token", response.access_token.value);
    }
}
test "AuthEngine.authenticate: Docker Hub anonymous flow omits optional basic auth" {
    const ExchangeState = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            if (request.method != .get) return error.TokenExchangeFailed;
            if (request.authorization != null) return error.TokenExchangeFailed;
            if (!std.mem.eql(u8, request.url, "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fubuntu%3Apull")) {
                return error.TokenExchangeFailed;
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "docker-hub-anon-token"
            \\}
            };
        }
    };

    var ref = try Reference.parse(std.testing.allocator, "docker.io/ubuntu:latest");
    defer ref.deinit(std.testing.allocator);
    const view = referenceView(ref);

    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, ExchangeState.exchange);
    defer engine.deinit();

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        view.registry,
        .{
            .realm = "https://auth.docker.io/token",
            .service = "registry.docker.io",
            .scope = "repository:library/ubuntu:pull",
        },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("docker-hub-anon-token", response.access_token.value);
}
test "AuthEngine.authenticate: GHCR mixed-case registry still uses env credentials for optional basic auth" {
    const ExchangeState = struct {
        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            if (request.method != .get) return error.TokenExchangeFailed;
            if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Basic Z2hjci11c2VyOmdocnMtdG9rZW4=")) {
                return error.TokenExchangeFailed;
            }
            if (!std.mem.eql(u8, request.url, "https://ghcr.io/token?service=ghcr.io&scope=repository%3Astefanprodan%2Fpodinfo%3Apull")) {
                return error.TokenExchangeFailed;
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "ghcr-token"
            \\}
            };
        }
    };

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(ENV_REGISTRY_USER, "ghcr-user");
    try environ_map.put(ENV_REGISTRY_TOKEN, "ghrs-token");

    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, ExchangeState.exchange);
    defer engine.deinit();
    engine.environ_map = &environ_map;

    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "GHCR.IO",
        .{
            .realm = "https://ghcr.io/token",
            .service = "ghcr.io",
            .scope = "repository:stefanprodan/podinfo:pull",
        },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("ghcr-token", response.access_token.value);
}
test "AuthEngine.authenticate: repeated success and failure runs stay leak-free" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;

            return switch ((calls - 1) % 4) {
                0 => .{ .status = .ok, .body =
                \\{
                \\  "access_token": "steady-token",
                \\  "expires_in": 75
                \\}
                },
                1 => .{ .status = .ok, .body = "not-json" },
                2, 3 => .{ .status = .unauthorized, .body = "" },
                else => unreachable,
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{ .realm = "https://auth.example.test/token" },
    );

    var iteration: usize = 0;
    while (iteration < 6) : (iteration += 1) {
        const result = engine.authenticate(&client, request);
        switch (iteration % 3) {
            0 => {
                var response = (try result).?;
                defer response.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("steady-token", response.access_token.value);
            },
            1 => try std.testing.expectError(error.InvalidTokenResponse, result),
            else => try std.testing.expectError(error.TokenExchangeFailed, result),
        }

        State.fake_now += 100;
    }
}
test "token response: refresh window policy is fixed for short-lived cli use" {
    try std.testing.expectEqual(@as(u64, 5), TOKEN_REFRESH_WINDOW_SECONDS);
}
test "auth scaffolding: cached token owns duplicated secret bytes" {
    var cached = try CachedToken.initOwned(
        std.testing.allocator,
        .{ .value = "opaque-token", .expires_in_seconds = 300 },
        1_700_000_000,
    );
    defer cached.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("opaque-token", cached.token.value);
    try std.testing.expect(cached.token.value.ptr != "opaque-token".ptr);
}
test "auth scaffolding: token cache key owns duplicated lookup fields" {
    var key = try TokenCacheKey.initOwned(
        std.testing.allocator,
        "https://auth.example.test/token",
        "registry.example.test",
        "repository:owner/image:pull",
    );
    defer key.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("https://auth.example.test/token", key.realm);
    try std.testing.expectEqualStrings("registry.example.test", key.service.?);
    try std.testing.expectEqualStrings("repository:owner/image:pull", key.scope.?);
}
test "auth scaffolding: token cache key supports nil service and scope" {
    var key = try TokenCacheKey.initOwned(
        std.testing.allocator,
        "https://auth.example.test/token",
        null,
        null,
    );
    defer key.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("https://auth.example.test/token", key.realm);
    try std.testing.expect(key.service == null);
    try std.testing.expect(key.scope == null);
}
test "auth scaffolding: token cache key can be built from auth request" {
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    var key = try TokenCacheKey.initOwnedFromRequest(std.testing.allocator, request);
    defer key.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("https://auth.example.test/token", key.realm);
    try std.testing.expectEqualStrings("registry.example.test", key.service.?);
    try std.testing.expectEqualStrings("repository:owner/image:pull", key.scope.?);
}
test "auth scaffolding: engine deinit handles empty token cache" {
    var engine = AuthEngine.init(std.testing.allocator, Config{});
    defer engine.deinit();

    try std.testing.expectEqual(@as(usize, 0), engine.token_cache.count());
}
test "auth scaffolding: engine owns cached token entries" {
    var engine = AuthEngine.init(std.testing.allocator, Config{});
    defer engine.deinit();

    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    try putCachedTokenEntryForTest(
        &engine,
        request,
        try CachedToken.initOwned(
            std.testing.allocator,
            .{ .value = "cached-token", .expires_in_seconds = 300 },
            1_700_000_000,
        ),
    );

    try std.testing.expectEqual(@as(usize, 1), engine.token_cache.count());
    try std.testing.expectEqualStrings("cached-token", engine.token_cache.getAdapted(request, TokenCacheRequestContext{}).?.token.value);
}
test "auth scaffolding: reference view consumes normalized Reference outputs" {
    var ref = try Reference.parse(std.testing.allocator, "docker.io/ubuntu:22.04");
    defer ref.deinit(std.testing.allocator);

    const view = referenceView(ref);

    try std.testing.expectEqualStrings("registry-1.docker.io", view.registry);
    try std.testing.expectEqualStrings("library/ubuntu", view.repository_path);
    try std.testing.expectEqualStrings("22.04", view.ref_string);
}
test "auth scaffolding: probe uri uses normalized registry from reference view" {
    var ref = try Reference.parse(std.testing.allocator, "docker.io/ubuntu:22.04");
    defer ref.deinit(std.testing.allocator);

    const view = referenceView(ref);
    const probe_uri = try view.probeUriAlloc(std.testing.allocator);
    defer std.testing.allocator.free(probe_uri);

    try std.testing.expectEqualStrings("https://registry-1.docker.io/v2/", probe_uri);
    try std.testing.expectEqualStrings("library/ubuntu", view.repository_path);
    try std.testing.expectEqualStrings("22.04", view.ref_string);
}
test "parseAuthenticateHeader: parses bearer challenge" {
    const challenge = try parseAuthenticateHeader(
        "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/image:pull\"",
    );

    try std.testing.expect(challenge == .bearer);
    try std.testing.expectEqualStrings("https://auth.example.test/token", challenge.bearer.realm);
    try std.testing.expectEqualStrings("registry.example.test", challenge.bearer.service.?);
    try std.testing.expectEqualStrings("repository:owner/image:pull", challenge.bearer.scope.?);
}
test "parseAuthenticateHeader: rejects insecure bearer realm url" {
    try std.testing.expectError(
        error.InsecureRealmUrl,
        parseAuthenticateHeader("Bearer realm=\"http://auth.example.test/token\""),
    );
}
test "parseAuthenticateHeader: table-driven bearer parsing matrix" {
    const cases = [_]struct {
        raw: []const u8,
        realm: []const u8,
        service: ?[]const u8,
        scope: ?[]const u8,
    }{
        .{
            .raw = "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/image:pull\"",
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
        .{
            .raw = "bearer realm=\"https://auth.example.test/token\", foo=\"ignored\", service=registry.example.test",
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = null,
        },
        .{
            .raw = "Basic realm=\"registry.example.test\", Bearer realm=\"https://auth.example.test/token\", scope=\"repository:owner/image:pull,push\"",
            .realm = "https://auth.example.test/token",
            .service = null,
            .scope = "repository:owner/image:pull,push",
        },
    };

    for (cases) |case| {
        const challenge = try parseAuthenticateHeader(case.raw);
        try std.testing.expect(challenge == .bearer);
        try std.testing.expectEqualStrings(case.realm, challenge.bearer.realm);

        if (case.service) |service| {
            try std.testing.expectEqualStrings(service, challenge.bearer.service.?);
        } else {
            try std.testing.expect(challenge.bearer.service == null);
        }

        if (case.scope) |scope| {
            try std.testing.expectEqualStrings(scope, challenge.bearer.scope.?);
        } else {
            try std.testing.expect(challenge.bearer.scope == null);
        }
    }
}
test "parseAuthenticateHeader: bearer scheme is case-insensitive and ignores unknown params" {
    const challenge = try parseAuthenticateHeader(
        "bearer realm=\"https://auth.example.test/token\",foo=\"bar\",service=registry.example.test",
    );

    try std.testing.expect(challenge == .bearer);
    try std.testing.expectEqualStrings("https://auth.example.test/token", challenge.bearer.realm);
    try std.testing.expectEqualStrings("registry.example.test", challenge.bearer.service.?);
    try std.testing.expect(challenge.bearer.scope == null);
}
test "parseAuthenticateHeader: selects bearer from multiple challenges" {
    const challenge = try parseAuthenticateHeader(
        "Basic realm=\"registry.example.test\", Bearer realm=\"https://auth.example.test/token\", service=\"registry.example.test\", scope=\"repository:owner/image:pull,push\"",
    );

    try std.testing.expect(challenge == .bearer);
    try std.testing.expectEqualStrings("https://auth.example.test/token", challenge.bearer.realm);
    try std.testing.expectEqualStrings("registry.example.test", challenge.bearer.service.?);
    try std.testing.expectEqualStrings("repository:owner/image:pull,push", challenge.bearer.scope.?);
}
test "parseAuthenticateHeader: duplicate bearer params are invalid" {
    try std.testing.expectError(
        error.InvalidAuthenticateHeader,
        parseAuthenticateHeader(
            "Bearer realm=\"https://auth.example.test/token\", realm=\"https://duplicate.example.test/token\"",
        ),
    );
}
test "parseAuthenticateHeader: malformed quoted values are invalid" {
    try std.testing.expectError(
        error.InvalidAuthenticateHeader,
        parseAuthenticateHeader("Bearer realm=\"https://auth.example.test/token"),
    );
}
test "parseAuthenticateHeader: quoted escapes do not break bearer parsing" {
    const challenge = try parseAuthenticateHeader(
        "Bearer realm=\"https://auth.example.test/token\",service=\"registry\\\"quoted\\\".example.test\",scope=\"repository:owner/image:pull\"",
    );

    try std.testing.expect(challenge == .bearer);
    try std.testing.expectEqualStrings("https://auth.example.test/token", challenge.bearer.realm);
    try std.testing.expectEqualStrings("registry\\\"quoted\\\".example.test", challenge.bearer.service.?);
    try std.testing.expectEqualStrings("repository:owner/image:pull", challenge.bearer.scope.?);
}
test "parseAuthenticateHeader: empty optional bearer values are invalid" {
    try std.testing.expectError(
        error.InvalidAuthenticateHeader,
        parseAuthenticateHeader("Bearer realm=\"https://auth.example.test/token\",service=\"\""),
    );

    try std.testing.expectError(
        error.InvalidAuthenticateHeader,
        parseAuthenticateHeader("Bearer realm=\"https://auth.example.test/token\",scope=\"\""),
    );
}
test "parseAuthenticateHeader: missing realm is invalid" {
    try std.testing.expectError(
        error.InvalidAuthenticateHeader,
        parseAuthenticateHeader("Bearer service=registry.example.test"),
    );
}
test "parseAuthenticateHeader: unsupported scheme is rejected" {
    try std.testing.expectError(
        error.UnsupportedAuthenticateScheme,
        parseAuthenticateHeader("Basic realm=\"example\""),
    );
}
test "classifyProbeResponse: classifies ok unauthorized and not found" {
    try std.testing.expectEqual(ProbeResult.ok, try classifyProbeResponse(.ok, &.{}));

    const auth_required = try classifyProbeResponse(
        .unauthorized,
        &.{"Bearer realm=\"https://auth.example.test/token\""},
    );
    try std.testing.expect(auth_required == .auth_required);
    try std.testing.expectEqualStrings("https://auth.example.test/token", auth_required.auth_required.bearer.realm);

    try std.testing.expectEqual(ProbeResult.not_found, try classifyProbeResponse(.not_found, &.{}));
}
test "classifyProbeResponse: unauthorized without header fails explicitly" {
    try std.testing.expectError(
        error.MissingAuthenticateHeader,
        classifyProbeResponse(.unauthorized, &.{}),
    );
}
test "classifyProbeResponse: repeated headers select bearer across values" {
    const result = try classifyProbeResponse(
        .unauthorized,
        &.{
            "Basic realm=\"registry.example.test\"",
            "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\"",
        },
    );

    try std.testing.expect(result == .auth_required);
    try std.testing.expectEqualStrings("https://auth.example.test/token", result.auth_required.bearer.realm);
    try std.testing.expectEqualStrings("registry.example.test", result.auth_required.bearer.service.?);
}
test "ProbeHttpResponse: mock probe cases classify deterministically" {
    const cases = [_]struct {
        response: ProbeHttpResponse,
        expected: enum { ok, auth_required, not_found, missing_header },
    }{
        .{ .response = .{ .status = .ok }, .expected = .ok },
        .{ .response = .{ .status = .unauthorized, .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\""} }, .expected = .auth_required },
        .{ .response = .{ .status = .unauthorized }, .expected = .missing_header },
        .{ .response = .{ .status = .not_found }, .expected = .not_found },
    };

    for (cases) |case| {
        switch (case.expected) {
            .ok => try std.testing.expectEqual(ProbeResult.ok, try case.response.classify()),
            .auth_required => {
                const result = try case.response.classify();
                try std.testing.expect(result == .auth_required);
                try std.testing.expectEqualStrings("https://auth.example.test/token", result.auth_required.bearer.realm);
            },
            .not_found => try std.testing.expectEqual(ProbeResult.not_found, try case.response.classify()),
            .missing_header => try std.testing.expectError(error.MissingAuthenticateHeader, case.response.classify()),
        }
    }
}
test "AuthenticateRequest: carries parsed challenge data for token exchange" {
    const request = try AuthenticateRequest.init(
        "registry-1.docker.io",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:library/ubuntu:pull",
        },
    );

    try std.testing.expectEqualStrings("registry-1.docker.io", request.registry);
    try std.testing.expectEqualStrings("https://auth.example.test/token", request.challenge.realm);
    try std.testing.expectEqualStrings("registry.example.test", request.service().?);
    try std.testing.expectEqualStrings("repository:library/ubuntu:pull", request.scope().?);
}
test "parseAuthenticateHeader: 10000 pseudo-random headers never panic" {
    var seed: u64 = 0xde_ad_be_ef;
    var buf: [256]u8 = undefined;

    for (0..10_000) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const len: usize = @intCast(seed % (buf.len + 1));

        for (buf[0..len]) |*b| {
            seed = seed *% 6364136223846793005 +% 1;
            b.* = @truncate(seed >> 32);
        }

        const result = parseAuthenticateHeader(buf[0..len]);
        _ = result catch {};
    }
}
test "parseAuthenticateHeaders: 10000 pseudo-random multi-header inputs never panic" {
    var seed: u64 = 0xc0_ff_ee_01;
    var buf: [128]u8 = undefined;

    for (0..10_000) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const len: usize = @intCast(seed % (buf.len + 1));

        for (buf[0..len]) |*b| {
            seed = seed *% 6364136223846793005 +% 1;
            b.* = @truncate(seed >> 32);
        }

        const headers = [_][]const u8{buf[0..len]};
        const result = parseAuthenticateHeaders(&headers);
        _ = result catch {};
    }
}
test "parseChallengeChunk: 10000 pseudo-random challenge chunks never panic" {
    var seed: u64 = 0xca_fe_ba_be;
    var buf: [128]u8 = undefined;

    for (0..10_000) |_| {
        seed = seed *% 6364136223846793005 +% 1;
        const len: usize = @intCast(seed % (buf.len + 1));

        for (buf[0..len]) |*b| {
            seed = seed *% 6364136223846793005 +% 1;
            b.* = @truncate(seed >> 32);
        }

        const result = parseChallengeChunk(buf[0..len]);
        _ = result catch {};
    }
}
test "probe/authenticate: repeated success and failure runs leave no residual allocations under DebugAllocator" {
    const State = struct {
        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(allocator);
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "debug-check-token",
            \\  "expires_in": 90
            \\}
            };
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    for (0..8) |_| {
        var engine = AuthEngine.initWithTokenHttpExchanger(allocator, Config{}, State.exchange);
        defer engine.deinit();
        var client: std.http.Client = undefined;
        const request = try AuthenticateRequest.init(
            "registry.example.test",
            .{
                .realm = "https://auth.example.test/token",
                .service = "registry.example.test",
                .scope = "repository:owner/image:pull",
            },
        );

        var response = (try engine.authenticate(&client, request)).?;
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("debug-check-token", response.access_token.value);
    }
}
test "tokenCacheKeysEqual: nil service vs non-nil service returns false" {
    const a = TokenCacheKey{ .realm = "https://example.test/token" };
    const b = TokenCacheKey{ .realm = "https://example.test/token", .service = "svc" };
    try std.testing.expect(!tokenCacheKeysEqual(a, b));
}
test "tokenCacheKeysEqual: nil scope vs non-nil scope returns false" {
    const a = TokenCacheKey{ .realm = "https://example.test/token" };
    const b = TokenCacheKey{ .realm = "https://example.test/token", .scope = "repository:image:pull" };
    try std.testing.expect(!tokenCacheKeysEqual(a, b));
}
test "tokenCacheKeysEqual: both nil service and scope returns true" {
    const a = TokenCacheKey{ .realm = "https://example.test/token" };
    const b = TokenCacheKey{ .realm = "https://example.test/token" };
    try std.testing.expect(tokenCacheKeysEqual(a, b));
}
test "parseAuthenticateHeader: bare challenge without scheme is UnsupportedAuthenticateScheme" {
    try std.testing.expectError(
        error.UnsupportedAuthenticateScheme,
        parseAuthenticateHeader("realm=\"https://example.test/token\""),
    );
}
test "parseAuthenticateHeader: multiple Bearer challenges selects first valid one" {
    const challenge = try parseAuthenticateHeader(
        "Bearer realm=\"https://first.test/token\", Bearer realm=\"https://second.test/token\"",
    );
    try std.testing.expect(challenge == .bearer);
    try std.testing.expectEqualStrings("https://first.test/token", challenge.bearer.realm);
}
test "buildTokenHttpRequest: empty scope request builds url without query when no service or scope" {
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{ .realm = "https://auth.example.test/token" },
    );

    var http_request = try buildTokenHttpRequest(std.testing.allocator, request, .get, null);
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("https://auth.example.test/token", http_request.url);
    try std.testing.expect(http_request.body == null);
}
test "classifyProbeResponse: unsupported status code returns error" {
    try std.testing.expectError(
        error.UnsupportedProbeStatus,
        classifyProbeResponse(.internal_server_error, &.{}),
    );
    try std.testing.expectError(
        error.UnsupportedProbeStatus,
        classifyProbeResponse(.bad_request, &.{}),
    );
}
test "AuthEngine: 1000x repeated authenticate (cache miss then hit) under DebugAllocator" {
    const State = struct {
        var calls: usize = 0;
        var fake_now: u64 = 1_000;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(allocator);
            calls += 1;
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "stress-token",
            \\  "expires_in": 90
            \\}
            };
        }

        fn now(_: *std.http.Client) u64 {
            return fake_now;
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    State.calls = 0;
    State.fake_now = 1_000;
    var engine = AuthEngine.initWithTokenHttpExchanger(allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:owner/image:pull",
        },
    );

    for (0..1000) |_| {
        State.fake_now += 1;
        var response = (try engine.authenticate(&client, request)).?;
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("stress-token", response.access_token.value);
    }

    try std.testing.expect(State.calls >= 1);
    try std.testing.expect(engine.token_cache.count() >= 1);
}
test "AuthEngine: 1000x authenticate with short-lived tokens under DebugAllocator" {
    const State = struct {
        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(allocator);
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "steady-token",
            \\  "expires_in": 1
            \\}
            };
        }

        fn now(_: *std.http.Client) u64 {
            return 1_000;
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var engine = AuthEngine.initWithTokenHttpExchanger(allocator, Config{}, State.exchange);
    defer engine.deinit();
    engine.now_unix_seconds_fn = State.now;
    var client: std.http.Client = undefined;

    for (0..1000) |_| {
        const request = try AuthenticateRequest.init(
            "registry.example.test",
            .{ .realm = "https://auth.example.test/token" },
        );
        var response = (try engine.authenticate(&client, request)).?;
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("steady-token", response.access_token.value);
    }
}
test "AuthEngine: 1000x fresh engine per authenticate stays leak-free under DebugAllocator" {
    const State = struct {
        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(allocator);
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "fresh-engine-token",
            \\  "expires_in": 90
            \\}
            };
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    for (0..1000) |_| {
        var engine = AuthEngine.initWithTokenHttpExchanger(allocator, Config{}, State.exchange);
        defer engine.deinit();
        var client: std.http.Client = undefined;
        const request = try AuthenticateRequest.init(
            "registry.example.test",
            .{ .realm = "https://auth.example.test/token" },
        );
        var response = (try engine.authenticate(&client, request)).?;
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("fresh-engine-token", response.access_token.value);
    }
}
test "parseDockerConfig: 1000x repeated parse/deinit under DebugAllocator" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const config_json =
        \\{
        \\  "auths": {
        \\    "\u0067\u0068\u0063\u0072\u002e\u0069\u006f": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    },
        \\    "https://index.docker.io/v1/": {
        \\      "auth": "ZG9ja2VydXNlcjpzZWNyZXQ="
        \\    },
        \\    "registry.example.com": {
        \\      "auth": "aW50ZXJuYWwtdXNlcjp0b2tlbg=="
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "\u0067\u0068\u0063\u0072\u002e\u0069\u006f": "\u0073\u0065\u0063\u0072\u0065\u0074\u0073\u0065\u0072\u0076\u0069\u0063\u0065",
        \\    "gcr.io": "gcloud"
        \\  },
        \\  "credsStore": "\u0070\u0061\u0073\u0073"
        \\}
    ;
    for (0..1000) |_| {
        var docker_config = try parseDockerConfig(allocator, config_json);
        defer docker_config.deinit(allocator);

        const ghcr_auth = (try docker_config.authCredentialForRegistry(allocator, "ghcr.io")).?;
        try std.testing.expectEqualStrings("octocat", ghcr_auth.username);
        try std.testing.expectEqualStrings("ghp_example", ghcr_auth.secret);

        const ghcr_helper = (try docker_config.registrySpecificHelperLookupForRegistry(allocator, "ghcr.io")).?;
        try std.testing.expectEqualStrings("secretservice", ghcr_helper.helper_suffix);

        try docker_config.resolveCredsStore(allocator);
        try std.testing.expectEqualStrings("pass", docker_config.creds_store.?);
    }
}
