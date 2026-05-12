//! Phase 2 auth engine.
//!
//! /v2/ probe flow, Bearer challenge parsing, token exchange (GET + POST
//! fallback), credential-provider chain, and per-scope token caching.
//! AuthError stays separate from ResolveError until Phase 3 wires auth
//! through the public resolver surface.

const builtin = @import("builtin");
const std = @import("std");
const ConfigModule = @import("Config.zig");
const Config = ConfigModule.Config;
const CredentialHandle = ConfigModule.CredentialHandle;
const CredentialProvider = ConfigModule.CredentialProvider;
const Reference = @import("Reference.zig");
const json = @import("json.zig");

/// Internal Phase 2 auth-only error set.
///
/// Stays separate from `ResolveError` until Phase 3 threads auth failures
/// through real resolve/validate/getManifest behavior.
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
    HelperFailed,
    HelperTimedOut,
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

    pub fn deinit(self: TokenHttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        if (self.authorization) |authorization| allocator.free(authorization);
        if (self.body) |body| allocator.free(body);
    }
};

pub const TokenExchangeResponse = struct {
    status: std.http.Status,
    body: []const u8,
};

pub const TokenHttpExchanger = *const fn (
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: TokenHttpRequest,
) AuthError!TokenExchangeResponse;

pub const env_registry_host_var = "Z_OCI_REGISTRY_HOST";
pub const env_registry_user_var = "Z_OCI_REGISTRY_USER";
pub const env_registry_token_var = "Z_OCI_REGISTRY_TOKEN";
pub const docker_config_dir_var = "DOCKER_CONFIG";
pub const home_dir_var = "HOME";
pub const userprofile_dir_var = "USERPROFILE";
pub const docker_hub_auth_key = "https://index.docker.io/v1/";

const docker_config_file_size_limit = 1024 * 1024;
const docker_helper_stdout_limit = 64 * 1024;
const docker_helper_stderr_limit = 64 * 1024;

pub const DockerCredentialHelperRunner = *const fn (
    allocator: std.mem.Allocator,
    io: std.Io,
    helper_suffix: []const u8,
    server_url: []const u8,
) AuthError!CredentialHandle;

const ParsedDockerCredentialHelperResponse = struct {
    Username: ?[]const u8 = null,
    Secret: ?[]const u8 = null,
};

const DockerCredentialHelperLookup = struct {
    server_url: []const u8,
    helper_suffix: []const u8,

    fn commandAlloc(self: DockerCredentialHelperLookup, allocator: std.mem.Allocator) AuthError![]u8 {
        return dockerCredentialHelperCommandAlloc(allocator, self.helper_suffix);
    }
};

const DockerCredentialSource = union(enum) {
    auth: ConfigModule.Credential,
    helper: DockerCredentialHelperLookup,
};

const DockerConfigAuthEntry = struct {
    registry_key: []const u8,
    credential: ConfigModule.Credential,

    fn deinit(self: *DockerConfigAuthEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.registry_key);
        allocator.free(self.credential.username);
        std.crypto.secureZero(u8, @constCast(self.credential.secret));
        allocator.free(self.credential.secret);
    }
};

const DockerConfigHelperEntry = struct {
    registry_key: []const u8,
    helper_suffix: []const u8,

    fn deinit(self: *DockerConfigHelperEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.registry_key);
        allocator.free(self.helper_suffix);
    }
};

const DockerConfig = struct {
    auths: []DockerConfigAuthEntry = &.{},
    cred_helpers: []DockerConfigHelperEntry = &.{},
    creds_store: ?[]const u8 = null,

    fn deinit(self: *DockerConfig, allocator: std.mem.Allocator) void {
        for (self.auths) |*entry| entry.deinit(allocator);
        allocator.free(self.auths);

        for (self.cred_helpers) |*entry| entry.deinit(allocator);
        allocator.free(self.cred_helpers);

        if (self.creds_store) |creds_store| allocator.free(creds_store);
        self.* = .{};
    }

    fn credentialForRegistry(self: DockerConfig, registry: []const u8) ?CredentialHandle {
        const credential = self.authCredentialForRegistry(registry) orelse return null;
        return .{ .credential = credential };
    }

    fn authCredentialForRegistry(self: DockerConfig, registry: []const u8) ?ConfigModule.Credential {
        for (self.auths) |entry| {
            if (dockerConfigRegistryKeyMatches(entry.registry_key, registry)) {
                return entry.credential;
            }
        }
        return null;
    }

    fn credentialSourceForRegistry(self: DockerConfig, registry: []const u8) ?DockerCredentialSource {
        if (self.registrySpecificHelperLookupForRegistry(registry)) |helper_lookup| {
            return .{ .helper = helper_lookup };
        }

        if (self.authCredentialForRegistry(registry)) |credential| {
            return .{ .auth = credential };
        }

        if (self.globalHelperLookupForRegistry(registry)) |helper_lookup| {
            return .{ .helper = helper_lookup };
        }

        return null;
    }

    fn registrySpecificHelperLookupForRegistry(self: DockerConfig, registry: []const u8) ?DockerCredentialHelperLookup {
        for (self.cred_helpers) |entry| {
            if (dockerConfigRegistryKeyMatches(entry.registry_key, registry)) {
                return .{
                    .server_url = dockerCredentialHelperServer(registry),
                    .helper_suffix = entry.helper_suffix,
                };
            }
        }
        return null;
    }

    fn globalHelperLookupForRegistry(self: DockerConfig, registry: []const u8) ?DockerCredentialHelperLookup {
        const helper_suffix = self.creds_store orelse return null;
        return .{
            .server_url = dockerCredentialHelperServer(registry),
            .helper_suffix = helper_suffix,
        };
    }
};

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

pub const token_refresh_window_seconds: u64 = 5;

pub const TokenResponse = struct {
    /// Owned token-response payload.
    access_token: Token,
    /// Explicit non-goal for `v0.2.0`; parsed only so later phases can choose
    /// to ignore or surface it deliberately.
    refresh_token: ?[]const u8 = null,

    pub fn deinit(self: *TokenResponse, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, @constCast(self.access_token.value));
        allocator.free(self.access_token.value);
        if (self.refresh_token) |refresh_token| allocator.free(refresh_token);
    }
};

const ParsedTokenBody = struct {
    access_token: ?[]const u8 = null,
    token: ?[]const u8 = null,
    expires_in: ?u64 = null,
    refresh_token: ?[]const u8 = null,
};

/// Owned cache lookup key.
///
/// `realm`, `service`, and `scope` are duplicated onto the caller-owned
/// allocator when the key is constructed for cached storage.
pub const TokenCacheKey = struct {
    realm: []const u8,
    service: ?[]const u8 = null,
    scope: []const u8,

    pub fn initOwned(
        allocator: std.mem.Allocator,
        realm: []const u8,
        service: ?[]const u8,
        scope: []const u8,
    ) !TokenCacheKey {
        const owned_realm = try allocator.dupe(u8, realm);
        errdefer allocator.free(owned_realm);

        const owned_service = if (service) |s|
            try allocator.dupe(u8, s)
        else
            null;
        errdefer if (owned_service) |s| allocator.free(s);

        const owned_scope = try allocator.dupe(u8, scope);

        return .{
            .realm = owned_realm,
            .service = owned_service,
            .scope = owned_scope,
        };
    }

    pub fn deinit(self: *TokenCacheKey, allocator: std.mem.Allocator) void {
        allocator.free(self.realm);
        if (self.service) |s| allocator.free(s);
        allocator.free(self.scope);
    }
};

/// Owned cached token storage.
///
/// Unlike `Token`, this storage owns its token bytes. `deinit()` zeroes the
/// token before freeing it from the caller-owned allocator.
pub const CachedToken = struct {
    token: Token,
    valid_until_unix_seconds: ?u64 = null,

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

/// Narrow Phase 2 view of `Config`.
///
/// Relevant now: credentials, connect/read timeouts, CA bundle path
/// Deferred: `max_retries`, `rate_limit_enabled`
pub const Phase2ConfigView = struct {
    credential_provider: ?*const CredentialProvider,
    connect_timeout_ms: u32,
    read_timeout_ms: u32,
    ca_bundle_path: ?[]const u8,
    env_registry_host_var: []const u8 = env_registry_host_var,
    env_registry_user_var: []const u8 = env_registry_user_var,
    env_registry_token_var: []const u8 = env_registry_token_var,
};

/// Borrowed view of the normalized reference data auth consumes.
///
/// This codifies the Phase 1/Phase 2 boundary: auth does not re-parse raw
/// image strings. It uses the canonical registry, repository path, and ref
/// string already produced by `Reference.parse`.
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

    pub fn classify(self: ProbeHttpResponse) AuthError!ProbeResult {
        return classifyProbeResponse(self.status, self.www_authenticate_headers);
    }
};

/// Explicit process boundary for helper execution.
///
/// `std.http.Client` already owns the `std.Io` it needs for network requests in
/// Zig 0.16. Docker credential helpers are different: `std.process.spawn`,
/// `child.wait`, and `child.kill` need an explicit `std.Io` boundary. Keeping
/// that context separate lets `authenticate()` stay provisional without forcing
/// `io` through every auth call immediately.
pub const HelperProcessContext = struct {
    io: std.Io,
    runner: DockerCredentialHelperRunner = runDockerCredentialHelperBySuffix,
};

/// Phase 2 auth engine.
///
/// HTTP requests carry `io` through `std.http.Client`. Helper execution
/// passes an explicit `std.Io` boundary through `HelperProcessContext`.
pub const AuthEngine = struct {
    allocator: std.mem.Allocator,
    config: Config,
    helper_process_context: ?HelperProcessContext = null,
    token_http_exchanger: ?TokenHttpExchanger = null,
    environ_map: ?*const std.process.Environ.Map = null,
    docker_config: ?DockerConfig = null,

    pub fn init(allocator: std.mem.Allocator, config: Config) AuthEngine {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn initWithHelperProcessContext(
        allocator: std.mem.Allocator,
        config: Config,
        helper_process_context: HelperProcessContext,
    ) AuthEngine {
        return .{
            .allocator = allocator,
            .config = config,
            .helper_process_context = helper_process_context,
        };
    }

    pub fn initWithTokenHttpExchanger(
        allocator: std.mem.Allocator,
        config: Config,
        token_http_exchanger: TokenHttpExchanger,
    ) AuthEngine {
        return .{
            .allocator = allocator,
            .config = config,
            .token_http_exchanger = token_http_exchanger,
        };
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
        if (self.docker_config) |*docker_config| {
            docker_config.deinit(self.allocator);
            self.docker_config = null;
        }
    }

    pub fn setDockerConfigBytes(self: *AuthEngine, docker_config_json: []const u8) AuthError!void {
        const parsed = try parseDockerConfig(self.allocator, docker_config_json);
        if (self.docker_config) |*docker_config| docker_config.deinit(self.allocator);
        self.docker_config = parsed;
    }

    pub fn loadDockerConfigFromEnvironment(self: *AuthEngine, io: std.Io) AuthError!bool {
        const environ_map = self.environ_map orelse return false;
        const config_path = try dockerConfigPathFromEnvironmentAlloc(self.allocator, environ_map) orelse return false;
        defer self.allocator.free(config_path);

        const docker_config_json = std.Io.Dir.cwd().readFileAlloc(
            io,
            config_path,
            self.allocator,
            .limited(docker_config_file_size_limit),
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

    pub fn helperProcessContext(self: AuthEngine) ?HelperProcessContext {
        return self.helper_process_context;
    }

    pub fn phase2Config(self: AuthEngine) Phase2ConfigView {
        return phase2ConfigView(self.config);
    }

    pub fn authenticate(
        self: *AuthEngine,
        client: *std.http.Client,
        request: AuthenticateRequest,
    ) AuthError!?TokenResponse {
        const exchanger = self.token_http_exchanger orelse return error.NotYetImplemented;
        try validateRealmUrl(request.challenge.realm);

        const credential_handle = self.credentialForRegistry(request.registry);
        defer if (credential_handle) |handle| handle.release();

        const get_request = try buildTokenHttpRequest(
            self.allocator,
            request,
            .get,
            if (credential_handle) |handle| handle.credential else null,
        );
        const get_response = try exchanger(self.allocator, client, get_request);
        if (get_response.status == .ok) {
            return try parseTokenResponse(self.allocator, get_response.body);
        }

        const post_request = try buildTokenHttpRequest(
            self.allocator,
            request,
            .post,
            if (credential_handle) |handle| handle.credential else null,
        );
        const post_response = try exchanger(self.allocator, client, post_request);
        if (post_response.status != .ok) return error.TokenExchangeFailed;

        return try parseTokenResponse(self.allocator, post_response.body);
    }

    pub fn credentialForRegistry(self: AuthEngine, registry: []const u8) ?CredentialHandle {
        if (self.config.credential_provider) |provider| {
            if (provider.getCredential(registry)) |handle| return handle;
        }

        if (self.environ_map) |environ_map| {
            if (envCredentialForRegistry(environ_map, registry)) |handle| return handle;
        }

        if (self.docker_config) |docker_config| {
            if (docker_config.credentialForRegistry(registry)) |handle| return handle;
        }

        return null;
    }

    fn dockerCredentialForRegistry(self: AuthEngine, registry: []const u8) AuthError!?CredentialHandle {
        const docker_config = self.docker_config orelse return null;

        if (self.helper_process_context) |context| {
            if (docker_config.registrySpecificHelperLookupForRegistry(registry)) |helper_lookup| {
                return try context.runner(self.allocator, context.io, helper_lookup.helper_suffix, helper_lookup.server_url);
            }
        }

        if (docker_config.authCredentialForRegistry(registry)) |credential| {
            return .{ .credential = credential };
        }

        if (self.helper_process_context) |context| {
            if (docker_config.globalHelperLookupForRegistry(registry)) |helper_lookup| {
                return try context.runner(self.allocator, context.io, helper_lookup.helper_suffix, helper_lookup.server_url);
            }
        }

        return null;
    }
};

pub fn phase2ConfigView(config: Config) Phase2ConfigView {
    return .{
        .credential_provider = config.credential_provider,
        .connect_timeout_ms = config.connect_timeout_ms,
        .read_timeout_ms = config.read_timeout_ms,
        .ca_bundle_path = config.ca_bundle_path,
    };
}

pub fn envCredentialForRegistry(environ_map: *const std.process.Environ.Map, registry: []const u8) ?CredentialHandle {
    const host = environ_map.get(env_registry_host_var) orelse return null;
    if (!std.mem.eql(u8, host, registry)) return null;

    const username = environ_map.get(env_registry_user_var) orelse return null;
    const token = environ_map.get(env_registry_token_var) orelse return null;
    if (username.len == 0 or token.len == 0) return null;

    return .{ .credential = .{
        .username = username,
        .secret = token,
    } };
}

fn parseDockerConfig(allocator: std.mem.Allocator, docker_config_json: []const u8) AuthError!DockerConfig {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, docker_config_json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidDockerConfig;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidDockerConfig,
    };

    var auth_entries: std.ArrayList(DockerConfigAuthEntry) = .empty;
    defer auth_entries.deinit(allocator);

    if (root.get("auths")) |auths_value| {
        const auths_object = switch (auths_value) {
            .object => |object| object,
            else => return error.InvalidDockerConfig,
        };
        var auths_iter = auths_object.iterator();
        while (auths_iter.next()) |entry| {
            const entry_object = switch (entry.value_ptr.*) {
                .object => |object| object,
                else => return error.InvalidDockerConfig,
            };
            const encoded_auth = switch (entry_object.get("auth") orelse continue) {
                .string => |value| value,
                else => return error.InvalidDockerConfig,
            };
            try auth_entries.append(allocator, try initDockerConfigAuthEntry(allocator, entry.key_ptr.*, encoded_auth));
        }
    }

    var helper_entries: std.ArrayList(DockerConfigHelperEntry) = .empty;
    defer helper_entries.deinit(allocator);

    if (root.get("credHelpers")) |helpers_value| {
        const helpers_object = switch (helpers_value) {
            .object => |object| object,
            else => return error.InvalidDockerConfig,
        };
        var helpers_iter = helpers_object.iterator();
        while (helpers_iter.next()) |entry| {
            const helper_suffix = switch (entry.value_ptr.*) {
                .string => |value| value,
                else => return error.InvalidDockerConfig,
            };
            try helper_entries.append(allocator, .{
                .registry_key = try allocator.dupe(u8, entry.key_ptr.*),
                .helper_suffix = try allocator.dupe(u8, helper_suffix),
            });
        }
    }

    const creds_store = if (root.get("credsStore")) |creds_store_value|
        switch (creds_store_value) {
            .string => |value| try allocator.dupe(u8, value),
            else => return error.InvalidDockerConfig,
        }
    else
        null;

    return .{
        .auths = try auth_entries.toOwnedSlice(allocator),
        .cred_helpers = try helper_entries.toOwnedSlice(allocator),
        .creds_store = creds_store,
    };
}

fn initDockerConfigAuthEntry(
    allocator: std.mem.Allocator,
    registry_key: []const u8,
    encoded_auth: []const u8,
) AuthError!DockerConfigAuthEntry {
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

    return .{
        .registry_key = try allocator.dupe(u8, registry_key),
        .credential = .{
            .username = username,
            .secret = secret,
        },
    };
}

fn dockerConfigPathFromEnvironmentAlloc(
    allocator: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
) AuthError!?[]u8 {
    if (environ_map.get(docker_config_dir_var)) |docker_config_dir| {
        if (docker_config_dir.len != 0) {
            return try std.fs.path.join(allocator, &.{ docker_config_dir, "config.json" });
        }
    }

    if (environ_map.get(home_dir_var)) |home_dir| {
        if (home_dir.len != 0) {
            return try std.fs.path.join(allocator, &.{ home_dir, ".docker", "config.json" });
        }
    }

    if (environ_map.get(userprofile_dir_var)) |userprofile_dir| {
        if (userprofile_dir.len != 0) {
            return try std.fs.path.join(allocator, &.{ userprofile_dir, ".docker", "config.json" });
        }
    }

    return null;
}

fn dockerCredentialHelperServer(registry: []const u8) []const u8 {
    if (std.mem.eql(u8, registry, "registry-1.docker.io")) return docker_hub_auth_key;
    return registry;
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
) AuthError!CredentialHandle {
    const command = try dockerCredentialHelperCommandAlloc(allocator, helper_suffix);
    defer allocator.free(command);

    const argv = [_][]const u8{ command, "get" };
    return runDockerCredentialHelperCommand(allocator, io, &argv, server_url);
}

fn runDockerCredentialHelperCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    server_url: []const u8,
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

    var stderr_task = io.concurrent(readStreamAlloc, .{ allocator, io, child.stderr.?, .limited(docker_helper_stderr_limit) }) catch {
        return error.HelperFailed;
    };
    var stderr_task_completed = false;
    defer if (!stderr_task_completed) {
        if (stderr_task.cancel(io)) |stderr_contents| allocator.free(stderr_contents) else |_| {}
    };

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

    var stdout_reader = child.stdout.?.reader(io, &.{});
    const stdout_contents = stdout_reader.interface.allocRemaining(allocator, .limited(docker_helper_stdout_limit)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ReadFailed => return error.HelperFailed,
        else => return error.HelperFailed,
    };
    defer {
        std.crypto.secureZero(u8, stdout_contents);
        allocator.free(stdout_contents);
    }

    const stderr_contents = stderr_task.await(io) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.HelperFailed,
    };
    stderr_task_completed = true;
    defer allocator.free(stderr_contents);

    switch (child.wait(io) catch return error.HelperFailed) {
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

    return ownedDockerHelperCredentialHandle(username, secret);
}

fn ownedDockerHelperCredentialHandle(username: []const u8, secret: []const u8) AuthError!CredentialHandle {
    const owned_username = try std.heap.page_allocator.dupe(u8, username);
    errdefer std.heap.page_allocator.free(owned_username);

    const owned_secret = try std.heap.page_allocator.dupe(u8, secret);
    errdefer std.heap.page_allocator.free(owned_secret);

    return .{
        .credential = .{
            .username = owned_username,
            .secret = owned_secret,
        },
        .release_fn = releaseOwnedDockerHelperCredential,
    };
}

fn releaseOwnedDockerHelperCredential(credential: ConfigModule.Credential) void {
    std.heap.page_allocator.free(@constCast(credential.username));
    std.crypto.secureZero(u8, @constCast(credential.secret));
    std.heap.page_allocator.free(@constCast(credential.secret));
}

fn readStreamAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    limit: std.Io.Limit,
) ![]u8 {
    var file_reader: std.Io.File.Reader = .initStreaming(file, io, &.{});
    return file_reader.interface.allocRemaining(allocator, limit) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        else => |e| return e,
    };
}

fn dockerConfigRegistryKeyMatches(config_key: []const u8, registry: []const u8) bool {
    if (std.mem.eql(u8, config_key, registry)) return true;
    if (!std.mem.eql(u8, registry, "registry-1.docker.io")) return false;

    return std.mem.eql(u8, config_key, docker_hub_auth_key) or
        std.mem.eql(u8, config_key, "https://index.docker.io/v1") or
        std.mem.eql(u8, config_key, "index.docker.io") or
        std.mem.eql(u8, config_key, "docker.io");
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
        .get => try std.fmt.allocPrint(allocator, "{s}?{s}", .{ request.challenge.realm, query }),
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
        writeFormField(&aw.writer, &first, "scope", scope) catch return error.OutOfMemory;
    }

    return aw.toOwnedSlice() catch return error.OutOfMemory;
}

pub fn buildBasicAuthorizationAlloc(allocator: std.mem.Allocator, credential: ConfigModule.Credential) ![]u8 {
    const joined = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ credential.username, credential.secret });
    defer allocator.free(joined);

    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(joined.len);
    const buffer = try allocator.alloc(u8, "Basic ".len + encoded_len);
    errdefer allocator.free(buffer);

    @memcpy(buffer[0.."Basic ".len], "Basic ");
    _ = encoder.encode(buffer["Basic ".len..], joined);
    return buffer;
}

pub fn parseTokenResponse(allocator: std.mem.Allocator, body: []const u8) !TokenResponse {
    const parsed = json.parse(ParsedTokenBody, allocator, body) catch return error.InvalidTokenResponse;
    defer parsed.deinit();

    const token_value = parsed.value.access_token orelse parsed.value.token orelse return error.InvalidTokenResponse;
    if (token_value.len == 0) return error.InvalidTokenResponse;

    const expires_in_seconds = if (parsed.value.expires_in) |expires_in| blk: {
        if (expires_in == 0 or expires_in > std.math.maxInt(u32)) return error.InvalidTokenResponse;
        break :blk expires_in;
    } else 60;

    return .{
        .access_token = .{
            .value = try allocator.dupe(u8, token_value),
            .expires_in_seconds = expires_in_seconds,
        },
        .refresh_token = if (parsed.value.refresh_token) |refresh_token|
            try allocator.dupe(u8, refresh_token)
        else
            null,
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

// ── Tests ────────────────────────────────────────────────────────────────────

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
    const helper_process_context = HelperProcessContext{ .io = std.testing.io };

    try std.testing.expect(probe == .auth_required);
    try std.testing.expectEqualStrings("https://auth.example.test/token", bearer.realm);
    try std.testing.expectEqualStrings("opaque-token", response.access_token.value);
    try std.testing.expectEqualStrings("repository:owner/image:pull", key.scope);
    try std.testing.expectEqual(@as(?u64, 1_700_000_000), cached.valid_until_unix_seconds);
    _ = helper_process_context;
}

test "auth scaffolding: engine authenticate remains a stub without exchanger" {
    var engine = AuthEngine.init(std.testing.allocator, Config{});
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry-1.docker.io",
        .{ .realm = "https://auth.example.test/token", .scope = "repository:library/ubuntu:pull" },
    );

    try std.testing.expectError(error.NotYetImplemented, engine.authenticate(&client, request));
}

test "auth scaffolding: explicit helper process context is optional" {
    const engine = AuthEngine.initWithHelperProcessContext(
        std.testing.allocator,
        Config{},
        .{ .io = std.testing.io },
    );

    try std.testing.expect(engine.helperProcessContext() != null);
}

test "auth scaffolding: phase2 config review keeps only v0.1.1-relevant fields" {
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
    const view = phase2ConfigView(config);

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
    const engine = AuthEngine.init(std.testing.allocator, .{ .credential_provider = &provider });
    const handle = engine.credentialForRegistry("ghcr.io").?;

    try std.testing.expectEqualStrings("user", handle.credential.username);
    try std.testing.expectEqualStrings("token", handle.credential.secret);
}

test "auth scaffolding: phase2 config view records env credential variable names" {
    const view = phase2ConfigView(Config{});

    try std.testing.expectEqualStrings("Z_OCI_REGISTRY_HOST", view.env_registry_host_var);
    try std.testing.expectEqualStrings("Z_OCI_REGISTRY_USER", view.env_registry_user_var);
    try std.testing.expectEqualStrings("Z_OCI_REGISTRY_TOKEN", view.env_registry_token_var);
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
    try environ_map.put(env_registry_host_var, "ghcr.io");
    try environ_map.put(env_registry_user_var, "env-user");
    try environ_map.put(env_registry_token_var, "env-token");

    const provider = CredentialProvider{ .getCredentialFn = State.get };
    const engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, .{ .credential_provider = &provider }, &environ_map);
    const handle = engine.credentialForRegistry("ghcr.io").?;

    try std.testing.expectEqualStrings("config-user", handle.credential.username);
    try std.testing.expectEqualStrings("config-token", handle.credential.secret);
}

test "AuthEngine.credentialForRegistry: env provider supplies fallback credentials" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(env_registry_host_var, "ghcr.io");
    try environ_map.put(env_registry_user_var, "env-user");
    try environ_map.put(env_registry_token_var, "env-token");

    const engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    const handle = engine.credentialForRegistry("ghcr.io").?;

    try std.testing.expectEqualStrings("env-user", handle.credential.username);
    try std.testing.expectEqualStrings("env-token", handle.credential.secret);
}

test "AuthEngine.credentialForRegistry: env provider ignores registry mismatch and partial env" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(env_registry_host_var, "ghcr.io");
    try environ_map.put(env_registry_user_var, "env-user");

    const engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    try std.testing.expect(engine.credentialForRegistry("registry-1.docker.io") == null);
    try std.testing.expect(engine.credentialForRegistry("ghcr.io") == null);
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
    const engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, .{ .credential_provider = &provider }, &environ_map);

    try std.testing.expect(engine.credentialForRegistry("registry-1.docker.io") == null);
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

    try std.testing.expectEqual(@as(usize, 2), docker_config.auths.len);
    try std.testing.expectEqual(@as(usize, 1), docker_config.cred_helpers.len);
    try std.testing.expectEqualStrings("pass", docker_config.creds_store.?);
    try std.testing.expectEqualStrings("ghcr.io", docker_config.auths[0].registry_key);
    try std.testing.expectEqualStrings("octocat", docker_config.auths[0].credential.username);
    try std.testing.expectEqualStrings("ghp_example", docker_config.auths[0].credential.secret);
    try std.testing.expectEqualStrings(docker_hub_auth_key, docker_config.auths[1].registry_key);
    try std.testing.expectEqualStrings("dockeruser", docker_config.auths[1].credential.username);
    try std.testing.expectEqualStrings("secret", docker_config.auths[1].credential.secret);
    try std.testing.expectEqualStrings("ghcr.io", docker_config.cred_helpers[0].registry_key);
    try std.testing.expectEqualStrings("secretservice", docker_config.cred_helpers[0].helper_suffix);
}

test "parseDockerConfig: rejects malformed auth entries" {
    try std.testing.expectError(error.InvalidDockerConfig, parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "not-base64"
        \\    }
        \\  }
        \\}
    ));

    try std.testing.expectError(error.InvalidDockerConfig, parseDockerConfig(std.testing.allocator,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "bm9fY29sb24="
        \\    }
        \\  }
        \\}
    ));
}

test "dockerConfigRegistryKeyMatches: recognizes Docker Hub historical key" {
    try std.testing.expect(dockerConfigRegistryKeyMatches(docker_hub_auth_key, "registry-1.docker.io"));
    try std.testing.expect(dockerConfigRegistryKeyMatches("docker.io", "registry-1.docker.io"));
    try std.testing.expect(!dockerConfigRegistryKeyMatches("https://index.docker.io/v1/", "ghcr.io"));
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

    const handle = engine.credentialForRegistry("ghcr.io").?;

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

    const handle = engine.credentialForRegistry("registry-1.docker.io").?;

    try std.testing.expectEqualStrings("dockeruser", handle.credential.username);
    try std.testing.expectEqualStrings("secret", handle.credential.secret);
}

test "AuthEngine.credentialForRegistry: env remains ahead of docker config" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put(env_registry_host_var, "ghcr.io");
    try environ_map.put(env_registry_user_var, "env-user");
    try environ_map.put(env_registry_token_var, "env-token");

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

    const handle = engine.credentialForRegistry("ghcr.io").?;

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

    const ghcr_source = docker_config.credentialSourceForRegistry("ghcr.io").?;
    switch (ghcr_source) {
        .helper => |helper| {
            try std.testing.expectEqualStrings("ghcr.io", helper.server_url);
            try std.testing.expectEqualStrings("secretservice", helper.helper_suffix);
        },
        else => return error.TestUnexpectedResult,
    }

    const self_hosted_source = docker_config.credentialSourceForRegistry("registry.example.com").?;
    switch (self_hosted_source) {
        .auth => |credential| {
            try std.testing.expectEqualStrings("internal-user", credential.username);
            try std.testing.expectEqualStrings("token", credential.secret);
        },
        else => return error.TestUnexpectedResult,
    }

    const quay_source = docker_config.credentialSourceForRegistry("quay.io").?;
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

    const source = docker_config.credentialSourceForRegistry("registry-1.docker.io").?;
    switch (source) {
        .helper => |helper| {
            try std.testing.expectEqualStrings(docker_hub_auth_key, helper.server_url);
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
    try environ_map.put(home_dir_var, home_dir);

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    defer engine.deinit();

    try std.testing.expect(try engine.loadDockerConfigFromEnvironment(io));

    const handle = engine.credentialForRegistry("ghcr.io").?;
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
    try environ_map.put(home_dir_var, home_dir);
    try environ_map.put(docker_config_dir_var, docker_config_path);

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    defer engine.deinit();

    try std.testing.expect(try engine.loadDockerConfigFromEnvironment(io));

    const handle = engine.credentialForRegistry("ghcr.io").?;
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
    try environ_map.put(home_dir_var, home_dir);

    var engine = AuthEngine.initWithEnvironmentMap(std.testing.allocator, Config{}, &environ_map);
    defer engine.deinit();

    try std.testing.expect(!(try engine.loadDockerConfigFromEnvironment(io)));
    try std.testing.expect(engine.credentialForRegistry("ghcr.io") == null);
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
        docker_hub_auth_key,
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
    ));
}

test "AuthEngine.dockerCredentialForRegistry: helper path beats inline auth when helper context exists" {
    const State = struct {
        var calls: usize = 0;

        fn runner(_: std.mem.Allocator, _: std.Io, helper_suffix: []const u8, server_url: []const u8) AuthError!CredentialHandle {
            calls += 1;
            if (!std.mem.eql(u8, helper_suffix, "secretservice")) return error.HelperFailed;
            if (!std.mem.eql(u8, server_url, "ghcr.io")) return error.HelperFailed;
            return try ownedDockerHelperCredentialHandle("helper-user", "helper-secret");
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
    engine.helper_process_context = .{
        .io = std.testing.io,
        .runner = State.runner,
    };

    const handle = (try engine.dockerCredentialForRegistry("ghcr.io")).?;
    defer handle.release();

    try std.testing.expectEqual(@as(usize, 1), State.calls);
    try std.testing.expectEqualStrings("helper-user", handle.credential.username);
    try std.testing.expectEqualStrings("helper-secret", handle.credential.secret);
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

test "parseTokenResponse: prefers access_token and preserves refresh token" {
    var response = try parseTokenResponse(std.testing.allocator,
        \\{
        \\  "token": "fallback-token",
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

test "parseTokenResponse: falls back to token and defaults expiry" {
    var response = try parseTokenResponse(std.testing.allocator,
        \\{
        \\  "token": "fallback-token"
        \\}
    );
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("fallback-token", response.access_token.value);
    try std.testing.expectEqual(@as(?u64, 60), response.access_token.expires_in_seconds);
    try std.testing.expect(response.refresh_token == null);
}

test "parseTokenResponse: malformed payloads are rejected" {
    const cases = [_][]const u8{
        "{\"expires_in\": 60}",
        "{\"access_token\": \"\"}",
        "{\"access_token\": \"value\", \"expires_in\": -1}",
        "{\"access_token\": \"value\", \"expires_in\": 0}",
        "{\"access_token\": \"value\", \"expires_in\": 4294967296}",
        "not-json",
    };

    for (cases) |case| {
        try std.testing.expectError(error.InvalidTokenResponse, parseTokenResponse(std.testing.allocator, case));
    }
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

test "AuthEngine.authenticate: returns get response without post fallback when get succeeds" {
    const State = struct {
        var calls: usize = 0;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: TokenHttpRequest) AuthError!TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            calls += 1;
            if (request.method != .get) return error.TokenExchangeFailed;
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "get-token",
            \\  "expires_in": 90
            \\}
            };
        }
    };

    State.calls = 0;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
    var client: std.http.Client = undefined;
    const request = try AuthenticateRequest.init(
        "registry.example.test",
        .{ .realm = "https://auth.example.test/token" },
    );

    var response = (try engine.authenticate(&client, request)).?;
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), State.calls);
    try std.testing.expectEqualStrings("get-token", response.access_token.value);
    try std.testing.expectEqual(@as(?u64, 90), response.access_token.expires_in_seconds);
}

test "AuthEngine.authenticate: uses credential handle for optional basic auth" {
    const ProviderState = struct {
        var released = false;

        fn release(_: ConfigModule.Credential) void {
            released = true;
        }

        fn get(_: []const u8) ?CredentialHandle {
            return .{
                .credential = .{ .username = "user", .secret = "token" },
                .release_fn = release,
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

test "AuthEngine.authenticate: repeated success and failure runs stay leak-free" {
    const State = struct {
        var calls: usize = 0;

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
    };

    State.calls = 0;
    var engine = AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, Config{}, State.exchange);
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
    }
}

test "token response: refresh window policy is fixed for short-lived cli use" {
    try std.testing.expectEqual(@as(u64, 5), token_refresh_window_seconds);
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
    try std.testing.expectEqualStrings("repository:owner/image:pull", key.scope);
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
