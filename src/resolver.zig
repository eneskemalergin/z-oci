//! Phase 3 resolver scaffolding.
//!
//! This module owns the first internal seam for live manifest resolution.
//! It keeps request intent, transport metadata, config review, and
//! error-mapping rules local to the resolver layer so auth and manifest
//! fetch do not collapse into one large implementation.

const std = @import("std");
const auth = @import("auth.zig");
const Config = @import("Config.zig").Config;
const Digest = @import("Digest.zig");
const DockerManifestList = @import("Index.zig").DockerManifestList;
const MediaType = @import("MediaType.zig").MediaType;
const Manifest = @import("Manifest.zig");
const OciImageIndex = @import("Index.zig").OciImageIndex;
const Platform = @import("Platform.zig");
const ResolveError = @import("ResolveError.zig").ResolveError;
const json = @import("json.zig");

pub const ManifestRequestMethod = enum {
    head,
    get,
};

pub const ResolverOperation = enum {
    resolve,
    validate,
    get_manifest,
    resolve_child_manifest,
};

/// Narrow Phase 3 view of Config.
///
/// Resolver-relevant now: transport timeouts, retry budget, CA bundle, and
/// whether later phases should honor rate-limit behavior.
pub const Phase3ConfigView = struct {
    connect_timeout_ms: u32,
    read_timeout_ms: u32,
    max_retries: u8,
    ca_bundle_path: ?[]const u8,
    rate_limit_enabled: bool,
};

/// Internal resolver context built once at the public API boundary.
///
/// The context borrows the normalized reference view and caller-owned client.
/// Later resolver milestones can add fetch helpers here without changing the
/// public `resolve`, `validate`, or `getManifest` signatures.
pub const ResolverContext = struct {
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Phase3ConfigView,
    reference: auth.AuthReferenceView,
    platform: ?Platform,
    operation: ResolverOperation,

    pub fn init(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        reference: auth.AuthReferenceView,
        platform: ?Platform,
        operation: ResolverOperation,
    ) ResolverContext {
        return .{
            .allocator = allocator,
            .client = client,
            .config = phase3ConfigView(config),
            .reference = reference,
            .platform = platform,
            .operation = operation,
        };
    }

    pub fn errorReferenceAlloc(self: ResolverContext) ![]u8 {
        return canonicalReferenceAlloc(self.allocator, self.reference);
    }
};

/// Manifest request shape for the live resolver paths that arrive next.
pub const ManifestRequest = struct {
    method: ManifestRequestMethod,
    operation: ResolverOperation,
    reference: auth.AuthReferenceView,
    platform: ?Platform = null,
    accept: []const []const u8 = &.{},
    allow_cached_auth_retry: bool = true,

    pub fn uriAlloc(self: ManifestRequest, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "https://{s}/v2/{s}/manifests/{s}",
            .{ self.reference.registry, self.reference.repository_path, self.reference.ref_string },
        );
    }
};

/// Concrete HTTP request shape for the resolver transport seam.
///
/// This keeps Phase 3 fetch tests transport-agnostic until the live std.http
/// wiring arrives in later milestones.
pub const ManifestHttpRequest = struct {
    method: ManifestRequestMethod,
    url: []u8,
    authorization: ?[]u8 = null,
    accept: []const []const u8 = &.{},

    pub fn deinit(self: ManifestHttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        if (self.authorization) |authorization| allocator.free(authorization);
    }
};

/// Concrete HTTP response shape for the resolver transport seam.
///
/// GET responses may carry an owned body buffer. Callers must release it with
/// `deinit()` after parsing or classification is complete.
pub const ManifestHttpResponse = struct {
    metadata: ManifestResponseMetadata,
    body: ?[]u8 = null,

    pub fn deinit(self: ManifestHttpResponse, allocator: std.mem.Allocator) void {
        if (self.body) |body| allocator.free(body);
    }
};

pub const ManifestExchangeError = error{
    OutOfMemory,
    TransportFailed,
};

/// Exchanges a resolver HTTP request for response metadata.
///
/// The exchanger owns request teardown and must call `request.deinit(allocator)`.
pub const ManifestHttpExchanger = *const fn (
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: ManifestHttpRequest,
) ManifestExchangeError!ManifestHttpResponse;

/// Metadata the resolver layer cares about before parsing a body.
pub const ManifestResponseMetadata = struct {
    status: std.http.Status,
    content_type: ?[]const u8 = null,
    docker_content_digest: ?[]const u8 = null,
    location: ?[]const u8 = null,
    www_authenticate_headers: []const []const u8 = &.{},

    pub fn httpStatus(self: ManifestResponseMetadata) u16 {
        return @intCast(@intFromEnum(self.status));
    }

    pub fn probeClassification(self: ManifestResponseMetadata) auth.AuthError!auth.ProbeResult {
        const response = auth.ProbeHttpResponse{
            .status = self.status,
            .www_authenticate_headers = self.www_authenticate_headers,
        };
        return response.classify();
    }
};

pub const ManifestFetchSuccess = struct {
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
    body: ?[]const u8 = null,
};

pub const ManifestFetchOutcome = union(enum) {
    success: ManifestFetchSuccess,
    redirect: ManifestResponseMetadata,
};

/// Parsed manifest document owned by a JSON arena.
pub const ParsedManifestDocument = union(enum) {
    manifest: std.json.Parsed(Manifest),
    oci_index: std.json.Parsed(OciImageIndex),
    docker_manifest_list: std.json.Parsed(DockerManifestList),

    pub fn deinit(self: *ParsedManifestDocument) void {
        switch (self.*) {
            .manifest => |parsed| parsed.deinit(),
            .oci_index => |parsed| parsed.deinit(),
            .docker_manifest_list => |parsed| parsed.deinit(),
        }
    }

    pub fn mediaType(self: ParsedManifestDocument) MediaType {
        return switch (self) {
            .manifest => |parsed| parsed.value.media_type,
            .oci_index => |parsed| parsed.value.media_type,
            .docker_manifest_list => |parsed| parsed.value.media_type,
        };
    }
};

/// Success payload for the internal GET path.
pub const ManifestGetSuccess = struct {
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
    document: ParsedManifestDocument,

    pub fn deinit(self: *ManifestGetSuccess) void {
        self.document.deinit();
    }
};

/// Resolver-visible outcome for the GET path.
pub const GetRequestOutcome = union(enum) {
    success: ManifestGetSuccess,
    not_found,
    redirect: ManifestResponseMetadata,
    failure: ResolveError,

    pub fn deinit(self: *GetRequestOutcome) void {
        switch (self.*) {
            .success => |*success| success.deinit(),
            else => {},
        }
    }
};

/// Resolver-visible outcome for the HEAD path.
pub const HeadRequestOutcome = union(enum) {
    success: ManifestResponseMetadata,
    use_get_fallback: ManifestResponseMetadata,
    not_found,
    redirect: ManifestResponseMetadata,
    failure: ResolveError,
};

pub fn phase3ConfigView(config: Config) Phase3ConfigView {
    return .{
        .connect_timeout_ms = config.connect_timeout_ms,
        .read_timeout_ms = config.read_timeout_ms,
        .max_retries = config.max_retries,
        .ca_bundle_path = config.ca_bundle_path,
        .rate_limit_enabled = config.rate_limit_enabled,
    };
}

pub fn canonicalReferenceAlloc(allocator: std.mem.Allocator, reference: auth.AuthReferenceView) ![]u8 {
    const separator: []const u8 = if (Digest.parse(reference.ref_string)) |_| "@" else |_| ":";
    return std.fmt.allocPrint(
        allocator,
        "{s}/{s}{s}{s}",
        .{ reference.registry, reference.repository_path, separator, reference.ref_string },
    );
}

/// Build a concrete transport request from resolver intent and an optional bearer token.
pub fn buildManifestHttpRequestAlloc(
    allocator: std.mem.Allocator,
    request: ManifestRequest,
    bearer_token: ?[]const u8,
) !ManifestHttpRequest {
    const url = try request.uriAlloc(allocator);
    errdefer allocator.free(url);

    const authorization = if (bearer_token) |token|
        try std.fmt.allocPrint(allocator, "Bearer {s}", .{token})
    else
        null;
    errdefer if (authorization) |header| allocator.free(header);

    return .{
        .method = request.method,
        .url = url,
        .authorization = authorization,
        .accept = request.accept,
    };
}

pub fn mapAuthError(
    err: auth.AuthError,
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16,
) error{OutOfMemory}!ResolveError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.HelperTimedOut => .{ .timeout = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
        } },
        error.UnsupportedProbeStatus => .{ .network_error = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
        } },
        else => .{ .auth_failed = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
        } },
    };
}

pub fn manifestParseFailure(registry: []const u8, reference: []const u8, http_status: ?u16) ResolveError {
    return .{ .manifest_parse_error = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}

pub fn transportFailure(registry: []const u8, reference: []const u8, http_status: ?u16) ResolveError {
    return .{ .network_error = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}

pub fn unsupportedContentType(registry: []const u8, reference: []const u8, http_status: ?u16) ResolveError {
    return .{ .content_type_mismatch = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}

/// Execute the internal Phase 3 HEAD path through a mockable transport seam.
///
/// The result stays internal for `v0.2.2`. Public resolver functions still
/// return `error.NotYetImplemented` until later milestones wire this path in.
pub fn performManifestHead(
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    accept: []const []const u8,
) error{OutOfMemory}!HeadRequestOutcome {
    const request = ManifestRequest{
        .method = .head,
        .operation = ctx.operation,
        .reference = ctx.reference,
        .platform = ctx.platform,
        .accept = accept,
    };

    const response = exchangeManifestRequest(ctx, exchanger, request, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TransportFailed => return transportFailureOutcome(ctx, null),
    };
    defer response.deinit(ctx.allocator);

    return classifyHeadResponse(ctx, engine, exchanger, request, response.metadata, true);
}

/// Execute the internal Phase 3 GET path through the resolver transport seam.
///
/// This stays internal for `v0.2.3`. Public resolver functions still return
/// `error.NotYetImplemented` until later milestones wire the live path in.
pub fn performManifestGet(
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    accept: []const []const u8,
) error{OutOfMemory}!GetRequestOutcome {
    const request = ManifestRequest{
        .method = .get,
        .operation = ctx.operation,
        .reference = ctx.reference,
        .platform = ctx.platform,
        .accept = accept,
    };

    const response = exchangeManifestRequest(ctx, exchanger, request, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TransportFailed => return transportFailureGetOutcome(ctx, null),
    };

    return classifyGetResponse(ctx, engine, exchanger, request, response, true);
}

fn exchangeManifestRequest(
    ctx: ResolverContext,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    bearer_token: ?[]const u8,
) ManifestExchangeError!ManifestHttpResponse {
    const http_request = try buildManifestHttpRequestAlloc(ctx.allocator, request, bearer_token);
    return exchanger(ctx.allocator, ctx.client, http_request);
}

fn classifyHeadResponse(
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
    allow_auth: bool,
) error{OutOfMemory}!HeadRequestOutcome {
    if (isRedirectStatus(metadata.status)) {
        if (metadata.location != null) return .{ .redirect = metadata };
        return transportFailureOutcome(ctx, metadata.httpStatus());
    }

    if (metadata.status == .unauthorized and !allow_auth) {
        return authFailureOutcome(ctx, metadata.httpStatus());
    }

    const classification = metadata.probeClassification() catch |err| {
        return mapAuthFailureOutcome(ctx, err, metadata.httpStatus());
    };

    return switch (classification) {
        .ok => classifyUsableHeadMetadata(ctx, metadata),
        .not_found => .not_found,
        .auth_required => |challenge| if (allow_auth)
            authenticateHeadRequest(ctx, engine, exchanger, request, challenge)
        else
            authFailureOutcome(ctx, metadata.httpStatus()),
    };
}

fn authenticateHeadRequest(
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    challenge: auth.AuthChallenge,
) error{OutOfMemory}!HeadRequestOutcome {
    const bearer_challenge = switch (challenge) {
        .bearer => |bearer| bearer,
        else => return authFailureOutcome(ctx, @intFromEnum(std.http.Status.unauthorized)),
    };

    const auth_request = auth.AuthenticateRequest.init(ctx.reference.registry, bearer_challenge) catch |err| {
        return mapAuthFailureOutcome(ctx, err, @intFromEnum(std.http.Status.unauthorized));
    };

    var token_response = (engine.authenticate(ctx.client, auth_request) catch |err| {
        return mapAuthFailureOutcome(ctx, err, @intFromEnum(std.http.Status.unauthorized));
    }) orelse {
        return authFailureOutcome(ctx, @intFromEnum(std.http.Status.unauthorized));
    };
    defer token_response.deinit(ctx.allocator);

    const retry_response = exchangeManifestRequest(ctx, exchanger, request, token_response.access_token.value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TransportFailed => return transportFailureOutcome(ctx, null),
    };
    defer retry_response.deinit(ctx.allocator);
    const retry_metadata = retry_response.metadata;

    if (retry_metadata.status != .unauthorized) {
        return classifyHeadResponse(ctx, engine, exchanger, request, retry_metadata, false);
    }

    if (!request.allow_cached_auth_retry) return authFailureOutcome(ctx, retry_metadata.httpStatus());

    var refreshed_token_response = (engine.retryAuthenticateAfterCachedUnauthorized(ctx.client, auth_request) catch |err| {
        return mapAuthFailureOutcome(ctx, err, retry_metadata.httpStatus());
    }) orelse {
        return authFailureOutcome(ctx, retry_metadata.httpStatus());
    };
    defer refreshed_token_response.deinit(ctx.allocator);

    var retried_request = request;
    retried_request.allow_cached_auth_retry = false;

    const refreshed_response = exchangeManifestRequest(ctx, exchanger, retried_request, refreshed_token_response.access_token.value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TransportFailed => return transportFailureOutcome(ctx, null),
    };
    defer refreshed_response.deinit(ctx.allocator);
    const refreshed_metadata = refreshed_response.metadata;

    if (refreshed_metadata.status == .unauthorized) {
        return authFailureOutcome(ctx, refreshed_metadata.httpStatus());
    }

    return classifyHeadResponse(ctx, engine, exchanger, retried_request, refreshed_metadata, false);
}

fn classifyGetResponse(
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    response: ManifestHttpResponse,
    allow_auth: bool,
) error{OutOfMemory}!GetRequestOutcome {
    defer response.deinit(ctx.allocator);
    const metadata = response.metadata;

    if (isRedirectStatus(metadata.status)) {
        if (metadata.location != null) return .{ .redirect = metadata };
        return transportFailureGetOutcome(ctx, metadata.httpStatus());
    }

    if (metadata.status == .unauthorized and !allow_auth) {
        return authFailureGetOutcome(ctx, metadata.httpStatus());
    }

    const classification = metadata.probeClassification() catch |err| {
        return mapAuthFailureGetOutcome(ctx, err, metadata.httpStatus());
    };

    return switch (classification) {
        .ok => classifyUsableGetResponse(ctx, request, metadata, response.body),
        .not_found => .not_found,
        .auth_required => |challenge| if (allow_auth)
            authenticateGetRequest(ctx, engine, exchanger, request, challenge)
        else
            authFailureGetOutcome(ctx, metadata.httpStatus()),
    };
}

fn authenticateGetRequest(
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    challenge: auth.AuthChallenge,
) error{OutOfMemory}!GetRequestOutcome {
    const bearer_challenge = switch (challenge) {
        .bearer => |bearer| bearer,
        else => return authFailureGetOutcome(ctx, @intFromEnum(std.http.Status.unauthorized)),
    };

    const auth_request = auth.AuthenticateRequest.init(ctx.reference.registry, bearer_challenge) catch |err| {
        return mapAuthFailureGetOutcome(ctx, err, @intFromEnum(std.http.Status.unauthorized));
    };

    var token_response = (engine.authenticate(ctx.client, auth_request) catch |err| {
        return mapAuthFailureGetOutcome(ctx, err, @intFromEnum(std.http.Status.unauthorized));
    }) orelse {
        return authFailureGetOutcome(ctx, @intFromEnum(std.http.Status.unauthorized));
    };
    defer token_response.deinit(ctx.allocator);

    const retry_response = exchangeManifestRequest(ctx, exchanger, request, token_response.access_token.value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TransportFailed => return transportFailureGetOutcome(ctx, null),
    };

    if (retry_response.metadata.status != .unauthorized) {
        return classifyGetResponse(ctx, engine, exchanger, request, retry_response, false);
    }

    retry_response.deinit(ctx.allocator);

    if (!request.allow_cached_auth_retry) return authFailureGetOutcome(ctx, @intFromEnum(std.http.Status.unauthorized));

    var refreshed_token_response = (engine.retryAuthenticateAfterCachedUnauthorized(ctx.client, auth_request) catch |err| {
        return mapAuthFailureGetOutcome(ctx, err, @intFromEnum(std.http.Status.unauthorized));
    }) orelse {
        return authFailureGetOutcome(ctx, @intFromEnum(std.http.Status.unauthorized));
    };
    defer refreshed_token_response.deinit(ctx.allocator);

    var retried_request = request;
    retried_request.allow_cached_auth_retry = false;

    const refreshed_response = exchangeManifestRequest(ctx, exchanger, retried_request, refreshed_token_response.access_token.value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TransportFailed => return transportFailureGetOutcome(ctx, null),
    };

    if (refreshed_response.metadata.status == .unauthorized) {
        refreshed_response.deinit(ctx.allocator);
        return authFailureGetOutcome(ctx, @intFromEnum(std.http.Status.unauthorized));
    }

    return classifyGetResponse(ctx, engine, exchanger, retried_request, refreshed_response, false);
}

fn classifyUsableHeadMetadata(ctx: ResolverContext, metadata: ManifestResponseMetadata) error{OutOfMemory}!HeadRequestOutcome {
    if (metadata.docker_content_digest == null) return .{ .use_get_fallback = metadata };
    if (Digest.parse(metadata.docker_content_digest.?)) |_| {} else |_| return .{ .use_get_fallback = metadata };

    const content_type = metadata.content_type orelse return .{ .use_get_fallback = metadata };
    const media_type = manifestDocumentMediaType(content_type) orelse {
        return unsupportedContentTypeOutcome(ctx, metadata.httpStatus());
    };
    _ = media_type;

    return .{ .success = metadata };
}

fn classifyUsableGetResponse(
    ctx: ResolverContext,
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
    body: ?[]u8,
) error{OutOfMemory}!GetRequestOutcome {
    const content_type = metadata.content_type orelse {
        return unsupportedContentTypeGetOutcome(ctx, metadata.httpStatus());
    };
    const media_type = manifestDocumentMediaType(content_type) orelse {
        return unsupportedContentTypeGetOutcome(ctx, metadata.httpStatus());
    };
    const response_body = body orelse return parseFailureGetOutcome(ctx, metadata.httpStatus());
    if (response_body.len == 0) return parseFailureGetOutcome(ctx, metadata.httpStatus());

    const document = parseManifestDocument(ctx.allocator, media_type, response_body) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return parseFailureGetOutcome(ctx, metadata.httpStatus()),
    };

    return .{ .success = .{
        .request = request,
        .metadata = metadata,
        .document = document,
    } };
}

fn manifestDocumentMediaType(content_type: []const u8) ?MediaType {
    const normalized = normalizeContentType(content_type);
    const media_type = MediaType.fromString(normalized) orelse return null;
    return switch (media_type) {
        .oci_manifest_v1,
        .docker_manifest_v2,
        .oci_index_v1,
        .docker_manifest_list_v2,
        => media_type,
        else => null,
    };
}

fn normalizeContentType(content_type: []const u8) []const u8 {
    const without_parameters = content_type[0..(std.mem.indexOfScalar(u8, content_type, ';') orelse content_type.len)];
    return std.mem.trim(u8, without_parameters, " \t\r\n");
}

fn parseManifestDocument(
    allocator: std.mem.Allocator,
    media_type: MediaType,
    body: []const u8,
) !ParsedManifestDocument {
    return switch (media_type) {
        .oci_manifest_v1, .docker_manifest_v2 => .{ .manifest = try json.parse(Manifest, allocator, body) },
        .oci_index_v1 => .{ .oci_index = try json.parse(OciImageIndex, allocator, body) },
        .docker_manifest_list_v2 => .{ .docker_manifest_list = try json.parse(DockerManifestList, allocator, body) },
        else => error.UnexpectedToken,
    };
}

fn transportFailureOutcome(ctx: ResolverContext, http_status: ?u16) error{OutOfMemory}!HeadRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = transportFailure(ctx.reference.registry, reference, http_status) };
}

fn unsupportedContentTypeOutcome(ctx: ResolverContext, http_status: ?u16) error{OutOfMemory}!HeadRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = unsupportedContentType(ctx.reference.registry, reference, http_status) };
}

fn authFailureOutcome(ctx: ResolverContext, http_status: ?u16) error{OutOfMemory}!HeadRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = .{ .auth_failed = .{
        .registry = ctx.reference.registry,
        .reference = reference,
        .http_status = http_status,
    } } };
}

fn mapAuthFailureOutcome(
    ctx: ResolverContext,
    err: auth.AuthError,
    http_status: ?u16,
) error{OutOfMemory}!HeadRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = try mapAuthError(err, ctx.reference.registry, reference, http_status) };
}

fn transportFailureGetOutcome(ctx: ResolverContext, http_status: ?u16) error{OutOfMemory}!GetRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = transportFailure(ctx.reference.registry, reference, http_status) };
}

fn unsupportedContentTypeGetOutcome(ctx: ResolverContext, http_status: ?u16) error{OutOfMemory}!GetRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = unsupportedContentType(ctx.reference.registry, reference, http_status) };
}

fn parseFailureGetOutcome(ctx: ResolverContext, http_status: ?u16) error{OutOfMemory}!GetRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = manifestParseFailure(ctx.reference.registry, reference, http_status) };
}

fn authFailureGetOutcome(ctx: ResolverContext, http_status: ?u16) error{OutOfMemory}!GetRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = .{ .auth_failed = .{
        .registry = ctx.reference.registry,
        .reference = reference,
        .http_status = http_status,
    } } };
}

fn mapAuthFailureGetOutcome(
    ctx: ResolverContext,
    err: auth.AuthError,
    http_status: ?u16,
) error{OutOfMemory}!GetRequestOutcome {
    const reference = try ctx.errorReferenceAlloc();
    return .{ .failure = try mapAuthError(err, ctx.reference.registry, reference, http_status) };
}

fn isRedirectStatus(status: std.http.Status) bool {
    const code = @intFromEnum(status);
    return code >= 300 and code < 400;
}

fn fixtureBodyAlloc(allocator: std.mem.Allocator, path: []const u8, comptime max_bytes: usize) ManifestExchangeError![]u8 {
    var buffer: [max_bytes + 1]u8 = undefined;
    const bytes = std.Io.Dir.cwd().readFile(std.testing.io, path, &buffer) catch |err| switch (err) {
        else => return error.TransportFailed,
    };
    return allocator.dupe(u8, bytes);
}

test "phase3ConfigView keeps resolver-relevant config fields" {
    const view = phase3ConfigView(.{
        .connect_timeout_ms = 1234,
        .read_timeout_ms = 5678,
        .max_retries = 2,
        .ca_bundle_path = "/tmp/ca.pem",
        .rate_limit_enabled = false,
    });

    try std.testing.expectEqual(@as(u32, 1234), view.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 5678), view.read_timeout_ms);
    try std.testing.expectEqual(@as(u8, 2), view.max_retries);
    try std.testing.expectEqualSlices(u8, "/tmp/ca.pem", view.ca_bundle_path.?);
    try std.testing.expect(!view.rate_limit_enabled);
}

test "ResolverContext init preserves normalized reference and operation" {
    var client: std.http.Client = undefined;
    const view = auth.AuthReferenceView{
        .registry = "registry-1.docker.io",
        .repository_path = "library/busybox",
        .ref_string = "latest",
    };

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        view,
        .{ .os = "linux", .architecture = "amd64" },
        .resolve,
    );

    try std.testing.expectEqualStrings("registry-1.docker.io", ctx.reference.registry);
    try std.testing.expectEqualStrings("library/busybox", ctx.reference.repository_path);
    try std.testing.expectEqualStrings("latest", ctx.reference.ref_string);
    try std.testing.expectEqual(ResolverOperation.resolve, ctx.operation);
    try std.testing.expect(ctx.platform != null);
}

test "ManifestRequest uriAlloc uses normalized repository path and ref" {
    const request = ManifestRequest{
        .method = .head,
        .operation = .resolve,
        .reference = .{
            .registry = "ghcr.io",
            .repository_path = "owner/repo",
            .ref_string = "v1.2.3",
        },
    };

    const uri = try request.uriAlloc(std.testing.allocator);
    defer std.testing.allocator.free(uri);

    try std.testing.expectEqualStrings("https://ghcr.io/v2/owner/repo/manifests/v1.2.3", uri);
}

test "canonicalReferenceAlloc uses digest separator for pinned references" {
    const reference = auth.AuthReferenceView{
        .registry = "registry-1.docker.io",
        .repository_path = "library/busybox",
        .ref_string = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
    };

    const text = try canonicalReferenceAlloc(std.testing.allocator, reference);
    defer std.testing.allocator.free(text);

    try std.testing.expectEqualStrings(
        "registry-1.docker.io/library/busybox@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        text,
    );
}

test "canonicalReferenceAlloc uses tag separator for tag references" {
    const reference = auth.AuthReferenceView{
        .registry = "registry-1.docker.io",
        .repository_path = "library/ubuntu",
        .ref_string = "22.04",
    };

    const text = try canonicalReferenceAlloc(std.testing.allocator, reference);
    defer std.testing.allocator.free(text);

    try std.testing.expectEqualStrings("registry-1.docker.io/library/ubuntu:22.04", text);
}

test "ManifestResponseMetadata probeClassification reuses auth probe rules" {
    const metadata = ManifestResponseMetadata{
        .status = .unauthorized,
        .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\""},
    };

    const result = try metadata.probeClassification();
    switch (result) {
        .auth_required => |challenge| switch (challenge) {
            .bearer => |bearer| {
                try std.testing.expectEqualStrings("https://auth.example.test/token", bearer.realm);
                try std.testing.expectEqualStrings("registry.example.test", bearer.service.?);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "mapAuthError preserves OutOfMemory and maps resolver-visible variants" {
    try std.testing.expectError(
        error.OutOfMemory,
        mapAuthError(error.OutOfMemory, "r", "ref", null),
    );

    const timed_out = try mapAuthError(error.HelperTimedOut, "r", "ref", 401);
    try std.testing.expectEqualStrings("timeout", @tagName(timed_out));

    const auth_failed = try mapAuthError(error.TokenExchangeFailed, "r", "ref", 401);
    try std.testing.expectEqualStrings("auth_failed", @tagName(auth_failed));

    const network_error = try mapAuthError(error.UnsupportedProbeStatus, "r", "ref", 500);
    try std.testing.expectEqualStrings("network_error", @tagName(network_error));
}

test "resolver error helpers keep registry, reference, and status" {
    const parse_err = manifestParseFailure("ghcr.io", "ghcr.io/owner/repo:v1", 200);
    const transport_err = transportFailure("ghcr.io", "ghcr.io/owner/repo:v1", 503);
    const content_type_err = unsupportedContentType("ghcr.io", "ghcr.io/owner/repo:v1", 415);

    try std.testing.expectEqualStrings("manifest_parse_error", @tagName(parse_err));
    try std.testing.expectEqualStrings("network_error", @tagName(transport_err));
    try std.testing.expectEqualStrings("content_type_mismatch", @tagName(content_type_err));
}

test "buildManifestHttpRequestAlloc shapes HEAD request and optional bearer header" {
    const request = ManifestRequest{
        .method = .head,
        .operation = .resolve,
        .reference = .{
            .registry = "ghcr.io",
            .repository_path = "owner/repo",
            .ref_string = "latest",
        },
        .accept = &.{"application/vnd.oci.image.manifest.v1+json"},
    };

    const http_request = try buildManifestHttpRequestAlloc(std.testing.allocator, request, "token-123");
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqual(ManifestRequestMethod.head, http_request.method);
    try std.testing.expectEqualStrings("https://ghcr.io/v2/owner/repo/manifests/latest", http_request.url);
    try std.testing.expectEqualStrings("Bearer token-123", http_request.authorization.?);
    try std.testing.expectEqual(@as(usize, 1), http_request.accept.len);
}

test "manifestDocumentMediaType normalizes parameters and rejects non-manifest types" {
    try std.testing.expectEqual(MediaType.oci_manifest_v1, manifestDocumentMediaType(" application/vnd.oci.image.manifest.v1+json; charset=utf-8 ").?);
    try std.testing.expectEqual(@as(?MediaType, null), manifestDocumentMediaType("application/vnd.oci.image.config.v1+json"));
    try std.testing.expectEqual(@as(?MediaType, null), manifestDocumentMediaType("application/vnd.docker.distribution.manifest.v1+prettyjws"));
}

test "performManifestHead returns success for anonymous usable HEAD metadata" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            if (request.authorization != null) return error.TransportFailed;
            return .{ .metadata = .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            } };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .success => |metadata| {
            try std.testing.expectEqualStrings(
                "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
                metadata.docker_content_digest.?,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead falls back to GET when usable HEAD metadata is incomplete" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
            } };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .use_get_fallback => {},
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead returns redirect outcome for redirect metadata with location" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{
                .status = .found,
                .location = "https://cdn.example.test/manifest",
            } };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "ghcr.io", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    switch (outcome) {
        .redirect => |metadata| try std.testing.expectEqualStrings("https://cdn.example.test/manifest", metadata.location.?),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead returns not_found for missing manifest" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{ .status = .not_found } };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "ghcr.io", .repository_path = "owner/repo", .ref_string = "missing" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    switch (outcome) {
        .not_found => {},
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead authenticates on challenge and retries HEAD with bearer token" {
    const State = struct {
        var manifest_call_count: usize = 0;
        const token_body = "{\"access_token\":\"head-token\",\"expires_in\":3600}";

        fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            return .{ .status = .ok, .body = token_body };
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_call_count += 1;

            if (manifest_call_count == 1) {
                if (request.authorization != null) return error.TransportFailed;
                return .{ .metadata = .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/repo:pull\""},
                } };
            }

            if (request.authorization == null) return error.TransportFailed;
            if (!std.mem.eql(u8, request.authorization.?, "Bearer head-token")) return error.TransportFailed;
            return .{ .metadata = .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            } };
        }
    };

    defer State.manifest_call_count = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .success => {},
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 2), State.manifest_call_count);
}

test "performManifestHead retries once after cached unauthorized response" {
    const State = struct {
        var manifest_call_count: usize = 0;
        var token_call_count: usize = 0;
        const stale_token_body = "{\"access_token\":\"stale-token\",\"expires_in\":3600}";
        const fresh_token_body = "{\"access_token\":\"fresh-token\",\"expires_in\":3600}";

        fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            token_call_count += 1;
            return switch (token_call_count) {
                1 => .{ .status = .ok, .body = stale_token_body },
                2 => .{ .status = .ok, .body = fresh_token_body },
                else => error.TokenExchangeFailed,
            };
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_call_count += 1;

            return switch (manifest_call_count) {
                1 => .{ .metadata = .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/repo:pull\""},
                } },
                2 => blk: {
                    if (request.authorization == null) return error.TransportFailed;
                    if (!std.mem.eql(u8, request.authorization.?, "Bearer stale-token")) return error.TransportFailed;
                    break :blk .{ .metadata = .{ .status = .unauthorized } };
                },
                3 => blk: {
                    if (request.authorization == null) return error.TransportFailed;
                    if (!std.mem.eql(u8, request.authorization.?, "Bearer fresh-token")) return error.TransportFailed;
                    break :blk .{ .metadata = .{
                        .status = .ok,
                        .content_type = "application/vnd.oci.image.manifest.v1+json",
                        .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
                    } };
                },
                else => error.TransportFailed,
            };
        }
    };

    defer {
        State.manifest_call_count = 0;
        State.token_call_count = 0;
    }

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .success => {},
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 3), State.manifest_call_count);
    try std.testing.expectEqual(@as(usize, 2), State.token_call_count);
}

test "performManifestHead maps transport failures into resolver failures" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return error.TransportFailed;
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(arena.allocator(), .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        arena.allocator(),
        &client,
        Config{},
        .{ .registry = "ghcr.io", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("network_error", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead rejects unsupported content type on HEAD success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{
                .status = .ok,
                .content_type = "application/json",
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            } };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(arena.allocator(), .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        arena.allocator(),
        &client,
        Config{},
        .{ .registry = "ghcr.io", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("content_type_mismatch", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead rejects known non-manifest content type on HEAD success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.config.v1+json",
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            } };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(arena.allocator(), .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        arena.allocator(),
        &client,
        Config{},
        .{ .registry = "ghcr.io", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("content_type_mismatch", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet parses OCI manifest fixture with normalized content type" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            if (request.method != .get) return error.TransportFailed;
            if (request.accept.len != 2) return error.TransportFailed;
            return .{
                .metadata = .{
                    .status = .ok,
                    .content_type = " application/vnd.oci.image.manifest.v1+json; charset=utf-8 ",
                    .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
                },
                .body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024),
            };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(
        ctx,
        &engine,
        State.exchange,
        &.{
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        },
    );
    defer outcome.deinit();

    switch (outcome) {
        .success => |success| {
            try std.testing.expectEqual(ManifestRequestMethod.get, success.request.method);
            try std.testing.expectEqual(MediaType.oci_manifest_v1, success.document.mediaType());
            switch (success.document) {
                .manifest => |parsed| {
                    try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
                    try std.testing.expectEqual(@as(usize, 3), parsed.value.layers.len);
                },
                else => return error.TestUnexpectedResult,
            }
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet parses Docker manifest fixture" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{
                .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.docker.distribution.manifest.v2+json",
                },
                .body = try fixtureBodyAlloc(allocator, "fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json", 32 * 1024),
            };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "quay.io", .repository_path = "prometheus/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.docker.distribution.manifest.v2+json"});
    defer outcome.deinit();

    switch (outcome) {
        .success => |success| switch (success.document) {
            .manifest => |parsed| {
                try std.testing.expectEqual(MediaType.docker_manifest_v2, parsed.value.media_type);
                try std.testing.expect(parsed.value.layers.len > 0);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet parses OCI index fixture" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{
                .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.index.v1+json",
                },
                .body = try fixtureBodyAlloc(allocator, "fixtures/indexes/oci-image-index-spec-example.json", 16 * 1024),
            };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "example.com", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.index.v1+json"});
    defer outcome.deinit();

    switch (outcome) {
        .success => |success| switch (success.document) {
            .oci_index => |parsed| {
                try std.testing.expectEqual(MediaType.oci_index_v1, parsed.value.media_type);
                try std.testing.expect(parsed.value.manifests.len > 0);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet parses Docker manifest list fixture" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{
                .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.docker.distribution.manifest.list.v2+json",
                },
                .body = try fixtureBodyAlloc(allocator, "fixtures/indexes/docker-manifest-list-spec-example.json", 16 * 1024),
            };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "example.com", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.docker.distribution.manifest.list.v2+json"});
    defer outcome.deinit();

    switch (outcome) {
        .success => |success| switch (success.document) {
            .docker_manifest_list => |parsed| {
                try std.testing.expectEqual(MediaType.docker_manifest_list_v2, parsed.value.media_type);
                try std.testing.expect(parsed.value.manifests.len > 0);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet maps unsupported content type into resolver failure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{
                .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.config.v1+json",
                },
                .body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024),
            };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(arena.allocator(), .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        arena.allocator(),
        &client,
        Config{},
        .{ .registry = "ghcr.io", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit();

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("content_type_mismatch", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet maps body and media-type mismatch into parse failure" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{
                .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                },
                .body = try fixtureBodyAlloc(allocator, "fixtures/indexes/oci-image-index-spec-example.json", 16 * 1024),
            };
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(arena.allocator(), .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        arena.allocator(),
        &client,
        Config{},
        .{ .registry = "ghcr.io", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit();

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("manifest_parse_error", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet authenticates on challenge and retries GET with bearer token" {
    const State = struct {
        var manifest_call_count: usize = 0;
        const token_body = "{\"access_token\":\"get-token\",\"expires_in\":3600}";

        fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            return .{ .status = .ok, .body = token_body };
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_call_count += 1;

            if (manifest_call_count == 1) {
                if (request.authorization != null) return error.TransportFailed;
                return .{ .metadata = .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/repo:pull\""},
                } };
            }

            if (request.authorization == null) return error.TransportFailed;
            if (!std.mem.eql(u8, request.authorization.?, "Bearer get-token")) return error.TransportFailed;
            return .{
                .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                },
                .body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024),
            };
        }
    };

    defer State.manifest_call_count = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit();

    switch (outcome) {
        .success => |success| try std.testing.expectEqual(MediaType.oci_manifest_v1, success.document.mediaType()),
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 2), State.manifest_call_count);
}
