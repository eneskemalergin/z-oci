//! Phase 2 auth scaffolding.
//!
//! This file provides the minimal compileable auth surface for `v0.1.1`:
//! provisional data types, a small `AuthEngine` shell, and tests that lock the
//! initial ownership story without freezing the full Phase 2 implementation.

const std = @import("std");
const ConfigModule = @import("Config.zig");
const Config = ConfigModule.Config;
const Credential = ConfigModule.Credential;
const CredentialProvider = ConfigModule.CredentialProvider;
const Reference = @import("Reference.zig");

/// Internal Phase 2 auth-only error set.
///
/// This intentionally stays separate from `ResolveError` during `v0.1.1`.
/// `ResolveError` remains the public resolver-facing error surface until Phase
/// 3 threads auth failures through real resolve/validate/getManifest behavior.
pub const AuthError = error{
    NotYetImplemented,
    MissingAuthenticateHeader,
    UnsupportedAuthenticateScheme,
    InvalidAuthenticateHeader,
    UnsupportedProbeStatus,
    InsecureRealmUrl,
    InvalidTokenResponse,
    HelperFailed,
    HelperTimedOut,
};

/// Borrowed Bearer challenge data parsed from the authenticate header.
///
/// In `v0.1.1`, these slices borrow from the header input passed to the parser.
/// Later request-building code may choose to duplicate selected fields, but the
/// parser itself performs no ownership transfer.
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

pub const TokenResponse = struct {
    /// Borrows from the parsed token-response payload.
    access_token: Token,
    /// Explicit non-goal for `v0.2.0`; parsed only so later phases can choose
    /// to ignore or surface it deliberately.
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
/// This makes the `v0.1.1` config review explicit in code:
/// - relevant now: credentials, connect/read timeouts, CA bundle path
/// - deferred: `max_retries`, `rate_limit_enabled`
pub const Phase2ConfigView = struct {
    credential_provider: ?*const CredentialProvider,
    connect_timeout_ms: u32,
    read_timeout_ms: u32,
    ca_bundle_path: ?[]const u8,
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
};

/// Provisional Phase 2 auth engine shell.
///
/// The exact process/`std.Io` boundary remains intentionally unfrozen in
/// `v0.1.1`. HTTP requests already carry `io` through `std.http.Client`, while
/// helper execution likely needs an explicit `io` boundary later.
pub const AuthEngine = struct {
    allocator: std.mem.Allocator,
    config: Config,
    helper_process_context: ?HelperProcessContext = null,

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

    pub fn helperProcessContext(self: AuthEngine) ?HelperProcessContext {
        return self.helper_process_context;
    }

    pub fn phase2Config(self: AuthEngine) Phase2ConfigView {
        return phase2ConfigView(self.config);
    }

    pub fn authenticate(
        self: *AuthEngine,
        client: *std.http.Client,
        registry: []const u8,
        scope: []const u8,
    ) AuthError!?Token {
        _ = self;
        _ = client;
        _ = registry;
        _ = scope;
        return error.NotYetImplemented;
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

pub fn referenceView(ref: Reference) AuthReferenceView {
    return .{
        .registry = ref.registry,
        .repository_path = ref.repositoryPath(),
        .ref_string = ref.refString(),
    };
}

pub fn classifyProbeResponse(
    status: std.http.Status,
    www_authenticate: ?[]const u8,
) AuthError!ProbeResult {
    return switch (status) {
        .ok => .ok,
        .unauthorized => .{ .auth_required = try parseAuthenticateHeader(www_authenticate orelse return error.MissingAuthenticateHeader) },
        .not_found => .not_found,
        else => error.UnsupportedProbeStatus,
    };
}

pub fn parseAuthenticateHeader(raw: []const u8) AuthError!AuthChallenge {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return error.MissingAuthenticateHeader;

    const space_index = std.mem.indexOfAny(u8, trimmed, " \t") orelse trimmed.len;
    const scheme = trimmed[0..space_index];
    const remainder = std.mem.trim(u8, trimmed[space_index..], " \t");

    if (!std.ascii.eqlIgnoreCase(scheme, "Bearer")) {
        return error.UnsupportedAuthenticateScheme;
    }

    return .{ .bearer = try parseBearerChallenge(remainder) };
}

fn parseBearerChallenge(params: []const u8) AuthError!BearerChallenge {
    var challenge = BearerChallenge{ .realm = "" };
    var parts = std.mem.splitScalar(u8, params, ',');
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) continue;

        const eq_index = std.mem.indexOfScalar(u8, trimmed, '=') orelse return error.InvalidAuthenticateHeader;
        const name = std.mem.trim(u8, trimmed[0..eq_index], " \t");
        const value = try parseAuthParamValue(trimmed[eq_index + 1 ..]);

        if (std.ascii.eqlIgnoreCase(name, "realm")) {
            if (challenge.realm.len != 0) return error.InvalidAuthenticateHeader;
            challenge.realm = value;
        } else if (std.ascii.eqlIgnoreCase(name, "service")) {
            if (challenge.service != null) return error.InvalidAuthenticateHeader;
            challenge.service = value;
        } else if (std.ascii.eqlIgnoreCase(name, "scope")) {
            if (challenge.scope != null) return error.InvalidAuthenticateHeader;
            challenge.scope = value;
        }
    }

    if (challenge.realm.len == 0) return error.InvalidAuthenticateHeader;
    return challenge;
}

fn parseAuthParamValue(raw: []const u8) AuthError![]const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return error.InvalidAuthenticateHeader;

    if (trimmed[0] == '"') {
        if (trimmed.len < 2 or trimmed[trimmed.len - 1] != '"') {
            return error.InvalidAuthenticateHeader;
        }
        return trimmed[1 .. trimmed.len - 1];
    }

    return trimmed;
}

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

test "auth scaffolding: engine authenticate remains a stub" {
    var engine = AuthEngine.init(std.testing.allocator, Config{});
    var client: std.http.Client = undefined;

    try std.testing.expectError(
        error.NotYetImplemented,
        engine.authenticate(&client, "registry-1.docker.io", "repository:library/ubuntu:pull"),
    );
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
            fn get(_: []const u8) ?Credential {
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

        fn get(registry: []const u8) ?Credential {
            if (!std.mem.eql(u8, registry, "ghcr.io")) return null;
            return .{
                .username = username[0..],
                .secret = secret[0..],
            };
        }
    };

    const provider = CredentialProvider{ .getCredentialFn = State.get };
    const cred = provider.getCredential("ghcr.io").?;

    try std.testing.expectEqual(@intFromPtr(cred.username.ptr), @intFromPtr(&State.username[0]));
    try std.testing.expectEqual(@intFromPtr(cred.secret.ptr), @intFromPtr(&State.secret[0]));

    State.secret[0] = 'T';
    try std.testing.expectEqual(@as(u8, 'T'), cred.secret[0]);
    State.secret[0] = 't';
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

test "parseAuthenticateHeader: parses bearer challenge" {
    const challenge = try parseAuthenticateHeader(
        "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/image:pull\"",
    );

    try std.testing.expect(challenge == .bearer);
    try std.testing.expectEqualStrings("https://auth.example.test/token", challenge.bearer.realm);
    try std.testing.expectEqualStrings("registry.example.test", challenge.bearer.service.?);
    try std.testing.expectEqualStrings("repository:owner/image:pull", challenge.bearer.scope.?);
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
    try std.testing.expectEqual(ProbeResult.ok, try classifyProbeResponse(.ok, null));

    const auth_required = try classifyProbeResponse(
        .unauthorized,
        "Bearer realm=\"https://auth.example.test/token\"",
    );
    try std.testing.expect(auth_required == .auth_required);
    try std.testing.expectEqualStrings("https://auth.example.test/token", auth_required.auth_required.bearer.realm);

    try std.testing.expectEqual(ProbeResult.not_found, try classifyProbeResponse(.not_found, null));
}

test "classifyProbeResponse: unauthorized without header fails explicitly" {
    try std.testing.expectError(
        error.MissingAuthenticateHeader,
        classifyProbeResponse(.unauthorized, null),
    );
}
