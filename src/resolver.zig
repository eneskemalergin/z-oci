//! Manifest resolver implementation: HEAD/GET transport, response classification, and error mapping.
//!
//! Owned by the resolve/validate/get pipeline in `root.zig`; not re-exported from the
//! public package root. Integrators inject mock transports via `root.testing` exchanger
//! types that mirror the shapes defined here.
//!
//! This module keeps request intent, transport metadata, and registry outcome mapping
//! local to manifest fetch so auth token exchange stays in `auth.zig`.
const std = @import("std");
const auth = @import("auth.zig");
const config_module = @import("Config.zig");
const Config = config_module.Config;
const resilience = @import("resilience.zig");
const testing_loopback = @import("testing_loopback.zig");
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
/// Built once at the public API boundary. `config` must match the `AuthEngine` snapshot.
pub const ResolverParams = struct {
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    reference: auth.AuthReferenceView,
    platform: ?Platform,
    operation: ResolverOperation,
    transport_hooks: resilience.TransportHooks = .{},
    // Shared across HEAD/GET in one resolve session when pre-emptive throttling is on.
    manifest_throttle: ?*resilience.ManifestThrottle = null,

    pub fn init(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        reference: auth.AuthReferenceView,
        platform: ?Platform,
        operation: ResolverOperation,
    ) ResolverParams {
        return initWithTransportHooks(allocator, client, config, reference, platform, operation, .{});
    }

    pub fn initWithTransportHooks(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        reference: auth.AuthReferenceView,
        platform: ?Platform,
        operation: ResolverOperation,
        transport_hooks: resilience.TransportHooks,
    ) ResolverParams {
        return .{
            .allocator = allocator,
            .client = client,
            .config = config,
            .reference = reference,
            .platform = platform,
            .operation = operation,
            .transport_hooks = transport_hooks,
        };
    }

    pub fn initLive(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        reference: auth.AuthReferenceView,
        platform: ?Platform,
        operation: ResolverOperation,
    ) ResolverParams {
        return initWithTransportHooks(
            allocator,
            client,
            config,
            reference,
            platform,
            operation,
            resilience.liveTransportHooks(),
        );
    }

    pub fn withManifestThrottle(self: ResolverParams, throttle: *resilience.ManifestThrottle) ResolverParams {
        var copy = self;
        copy.manifest_throttle = throttle;
        return copy;
    }
};
/// `reference` and `accept` borrow for the request lifetime.
pub const ManifestRequest = struct {
    method: ManifestRequestMethod,
    operation: ResolverOperation,
    reference: auth.AuthReferenceView,
    platform: ?Platform = null,
    accept: []const []const u8 = &.{},
    allow_cached_auth_retry: bool = true,

    pub fn uriAlloc(self: ManifestRequest, allocator: std.mem.Allocator) ![]u8 {
        const registry = self.reference.registry;
        const repository_path = self.reference.repository_path;
        const ref_string = self.reference.ref_string;
        const len = "https://".len + registry.len + "/v2/".len + repository_path.len + "/manifests/".len + ref_string.len;
        const uri = try allocator.alloc(u8, len);
        const written = std.fmt.bufPrint(uri, "https://{s}/v2/{s}/manifests/{s}", .{
            registry,
            repository_path,
            ref_string,
        }) catch unreachable;
        std.debug.assert(written.len == len);
        return uri;
    }
};
pub const ManifestHttpRequest = struct {
    method: ManifestRequestMethod,
    url: []u8,
    authorization: ?[]u8 = null,
    accept: []const []const u8 = &.{},
    prebuilt_accept_headers: ?[]const std.http.Header = null,
    max_response_body_bytes: usize = config_module.DEFAULT_MAX_MANIFEST_BYTES,

    /// Zeroes bearer token bytes when present.
    pub fn deinit(self: ManifestHttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        auth.freeOwnedOptionalSecretSlice(allocator, self.authorization);
    }
};
/// GET may own a body buffer; release via `deinit` after parse/classify.
pub const ManifestHttpResponse = struct {
    metadata: ManifestResponseMetadata,
    owned_metadata: ?OwnedManifestResponseMetadata = null,
    body: ?[]u8 = null,

    pub fn deinit(self: ManifestHttpResponse, allocator: std.mem.Allocator) void {
        if (self.owned_metadata) |owned_metadata| owned_metadata.deinit(allocator);
        if (self.body) |body| allocator.free(body);
    }

    pub fn clearEphemeralMetadataHeaders(self: *ManifestHttpResponse, allocator: std.mem.Allocator) void {
        if (self.owned_metadata) |*owned_metadata| owned_metadata.dropEphemeralHeaders(allocator);
        self.metadata.www_authenticate_headers = &.{};
        self.metadata.resilience_headers = &.{};
    }

    pub fn initOwnedAlloc(
        allocator: std.mem.Allocator,
        metadata: ManifestResponseMetadata,
        body: ?[]const u8,
    ) !ManifestHttpResponse {
        const owned_metadata = try OwnedManifestResponseMetadata.initAlloc(allocator, metadata);
        errdefer owned_metadata.deinit(allocator);

        const owned_body = if (body) |bytes|
            try allocator.dupe(u8, bytes)
        else
            null;
        errdefer if (owned_body) |bytes| allocator.free(bytes);

        return .{
            .metadata = owned_metadata.view(metadata.status),
            .owned_metadata = owned_metadata,
            .body = owned_body,
        };
    }
};
pub const ManifestExchangeError = error{
    OutOfMemory,
    ResponseBodyTooLarge,
    ResponseHeadersTooLarge,
    TransportFailed,
    ConnectionResetByPeer,
    Timeout,
    NetworkUnreachable,
    ConnectionRefused,
    UnknownHostName,
};
/// Exchanger must `request.deinit` on every path; resolver does not on exchanger error.
pub const ManifestHttpExchanger = *const fn (
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: ManifestHttpRequest,
) ManifestExchangeError!ManifestHttpResponse;

pub const ManifestResponseMetadata = struct {
    status: std.http.Status,
    content_type: ?[]const u8 = null,
    docker_content_digest: ?[]const u8 = null,
    location: ?[]const u8 = null,
    www_authenticate_headers: []const []const u8 = &.{},
    resilience_headers: []const resilience.HttpHeader = &.{},

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

    pub fn cloneAlloc(self: ManifestResponseMetadata, allocator: std.mem.Allocator) !ManifestResponseMetadata {
        const owned_resilience_headers = try resilience.duplicateHttpHeadersAlloc(allocator, self.resilience_headers);
        errdefer resilience.deinitOwnedHttpHeaders(allocator, owned_resilience_headers);

        const content_type = if (self.content_type) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (content_type) |value| allocator.free(value);

        const docker_content_digest = if (self.docker_content_digest) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (docker_content_digest) |value| allocator.free(value);

        const location = if (self.location) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (location) |value| allocator.free(value);

        const www_authenticate_headers = try duplicateHeaderSlicesAlloc(allocator, self.www_authenticate_headers);
        errdefer {
            for (www_authenticate_headers) |header| allocator.free(header);
            allocator.free(www_authenticate_headers);
        }

        return .{
            .status = self.status,
            .content_type = content_type,
            .docker_content_digest = docker_content_digest,
            .location = location,
            .www_authenticate_headers = www_authenticate_headers,
            .resilience_headers = owned_resilience_headers,
        };
    }

    /// Redirect follow-up only; auth/retry headers dropped.
    pub fn cloneAllocRedirect(self: ManifestResponseMetadata, allocator: std.mem.Allocator) !ManifestResponseMetadata {
        return .{
            .status = self.status,
            .location = if (self.location) |location|
                try allocator.dupe(u8, location)
            else
                null,
        };
    }

    pub fn cloneAllocHeadSuccess(self: ManifestResponseMetadata, allocator: std.mem.Allocator) !ManifestResponseMetadata {
        const content_type = if (self.content_type) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (content_type) |value| allocator.free(value);

        const docker_content_digest = if (self.docker_content_digest) |value|
            try allocator.dupe(u8, value)
        else
            null;

        return .{
            .status = self.status,
            .content_type = content_type,
            .docker_content_digest = docker_content_digest,
        };
    }

    pub fn headFallbackMetadata(status: std.http.Status) ManifestResponseMetadata {
        return .{ .status = status };
    }

    pub fn releaseOwned(self: *ManifestResponseMetadata, allocator: std.mem.Allocator) void {
        if (self.content_type) |content_type| {
            allocator.free(content_type);
            self.content_type = null;
        }
        if (self.docker_content_digest) |digest| {
            allocator.free(digest);
            self.docker_content_digest = null;
        }
        if (self.location) |location| {
            allocator.free(location);
            self.location = null;
        }
        if (self.www_authenticate_headers.len != 0) {
            freeHeaderSlices(allocator, self.www_authenticate_headers);
            self.www_authenticate_headers = &.{};
        }
        if (self.resilience_headers.len != 0) {
            resilience.deinitOwnedHttpHeaders(allocator, @constCast(self.resilience_headers));
            self.resilience_headers = &.{};
        }
    }

    pub fn deinitOwned(self: ManifestResponseMetadata, allocator: std.mem.Allocator) void {
        var owned = self;
        owned.releaseOwned(allocator);
    }
};
pub const OwnedManifestResponseMetadata = struct {
    content_type: ?[]u8 = null,
    docker_content_digest: ?[]u8 = null,
    location: ?[]u8 = null,
    www_authenticate_headers: []const []const u8 = &.{},
    resilience_headers: []resilience.HttpHeader = &.{},

    pub fn initAlloc(allocator: std.mem.Allocator, metadata: ManifestResponseMetadata) !OwnedManifestResponseMetadata {
        const content_type = if (metadata.content_type) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (content_type) |value| allocator.free(value);

        const docker_content_digest = if (metadata.docker_content_digest) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (docker_content_digest) |value| allocator.free(value);

        const location = if (metadata.location) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (location) |value| allocator.free(value);

        const www_authenticate_headers = try duplicateHeaderSlicesAlloc(allocator, metadata.www_authenticate_headers);
        errdefer freeHeaderSlices(allocator, www_authenticate_headers);

        const resilience_headers = try resilience.duplicateHttpHeadersAlloc(allocator, metadata.resilience_headers);

        return .{
            .content_type = content_type,
            .docker_content_digest = docker_content_digest,
            .location = location,
            .www_authenticate_headers = www_authenticate_headers,
            .resilience_headers = resilience_headers,
        };
    }

    pub fn deinit(self: OwnedManifestResponseMetadata, allocator: std.mem.Allocator) void {
        if (self.content_type) |content_type| allocator.free(content_type);
        if (self.docker_content_digest) |digest| allocator.free(digest);
        if (self.location) |location| allocator.free(location);
        freeHeaderSlices(allocator, self.www_authenticate_headers);
        if (self.resilience_headers.len != 0) {
            resilience.deinitOwnedHttpHeaders(allocator, self.resilience_headers);
        }
    }

    /// Drop auth/retry headers; keep success fields for GET fallback.
    pub fn dropEphemeralHeaders(self: *OwnedManifestResponseMetadata, allocator: std.mem.Allocator) void {
        freeHeaderSlices(allocator, self.www_authenticate_headers);
        self.www_authenticate_headers = &.{};
        if (self.resilience_headers.len != 0) {
            resilience.deinitOwnedHttpHeaders(allocator, self.resilience_headers);
            self.resilience_headers = &.{};
        }
    }

    pub fn view(self: OwnedManifestResponseMetadata, status: std.http.Status) ManifestResponseMetadata {
        return .{
            .status = status,
            .content_type = self.content_type,
            .docker_content_digest = self.docker_content_digest,
            .location = self.location,
            .www_authenticate_headers = self.www_authenticate_headers,
            .resilience_headers = self.resilience_headers,
        };
    }
};
pub const ParsedManifestDocument = union(enum) {
    manifest: std.json.Parsed(Manifest),
    manifest_media_type: MediaType,
    oci_index: std.json.Parsed(OciImageIndex),
    docker_manifest_list: std.json.Parsed(DockerManifestList),

    pub fn deinit(self: *ParsedManifestDocument) void {
        switch (self.*) {
            .manifest => |parsed| parsed.deinit(),
            .manifest_media_type => {},
            .oci_index => |parsed| parsed.deinit(),
            .docker_manifest_list => |parsed| parsed.deinit(),
        }
    }

    pub fn mediaType(self: ParsedManifestDocument) MediaType {
        return switch (self) {
            .manifest => |parsed| parsed.value.media_type,
            .manifest_media_type => |media_type| media_type,
            .oci_index => |parsed| parsed.value.media_type,
            .docker_manifest_list => |parsed| parsed.value.media_type,
        };
    }
};
pub const ManifestGetSuccess = struct {
    request: ManifestRequest,
    resolved_digest: Digest,
    resolved_digest_raw: []u8,
    document: ParsedManifestDocument,
    // When set, JSON strings in `document` may borrow from this buffer.
    backing_body: ?[]u8 = null,

    pub fn deinit(self: *ManifestGetSuccess, allocator: std.mem.Allocator) void {
        allocator.free(self.resolved_digest_raw);
        self.document.deinit();
        if (self.backing_body) |body| allocator.free(body);
    }
};
pub const GetRequestOutcome = union(enum) {
    success: ManifestGetSuccess,
    not_found,
    redirect: ManifestResponseMetadata,
    failure: ResolveError,

    pub fn deinit(self: *GetRequestOutcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |*success| success.deinit(allocator),
            .redirect => |*metadata| metadata.releaseOwned(allocator),
            .failure => |*failure| failure.releaseOwnedReference(allocator),
            .not_found => {},
        }
    }
};
pub const HeadRequestOutcome = union(enum) {
    success: ManifestResponseMetadata,
    validate_manifest_ok: MediaType,
    use_get_fallback: ManifestResponseMetadata,
    not_found,
    redirect: ManifestResponseMetadata,
    failure: ResolveError,

    pub fn deinit(self: *HeadRequestOutcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |*metadata| metadata.releaseOwned(allocator),
            .use_get_fallback => |*metadata| metadata.releaseOwned(allocator),
            .redirect => |*metadata| metadata.releaseOwned(allocator),
            .failure => |*failure| failure.releaseOwnedReference(allocator),
            .validate_manifest_ok, .not_found => {},
        }
    }
};
pub const ValidateManifestHeadDecision = union(enum) {
    valid,
    not_found,
    owned_failure: ResolveError,
    inspect_multi_arch_head,
    proceed_with_get,
};
/// On `.owned_failure`, extract the failure before `head_outcome.deinit` (avoids double-free).
pub fn classifyValidateManifestHead(
    allocator: std.mem.Allocator,
    ref_view: auth.AuthReferenceView,
    head_outcome: *HeadRequestOutcome,
) error{OutOfMemory}!ValidateManifestHeadDecision {
    switch (head_outcome.*) {
        .validate_manifest_ok => return .valid,
        .not_found => return .not_found,
        .failure => |failure| {
            const extracted = failure;
            stubHeadOutcomeAfterExtract(head_outcome);
            return .{ .owned_failure = extracted };
        },
        .redirect => |*metadata| {
            return .{ .owned_failure = try headMetadataOwnedFailure(allocator, ref_view, head_outcome, metadata, .network_error) };
        },
        .use_get_fallback => return .proceed_with_get,
        .success => return .inspect_multi_arch_head,
    }
}
pub const ChildValidateHeadMappedOutcome = union(enum) {
    success_manifest_media_type: MediaType,
    not_found,
    owned_failure: ResolveError,
};
pub fn mapChildValidateHeadOutcome(
    allocator: std.mem.Allocator,
    ref_view: auth.AuthReferenceView,
    head_outcome: *HeadRequestOutcome,
) error{OutOfMemory}!ChildValidateHeadMappedOutcome {
    switch (head_outcome.*) {
        .validate_manifest_ok => |media_type| return .{ .success_manifest_media_type = media_type },
        .not_found => return .not_found,
        .failure => |failure| {
            const extracted = failure;
            stubHeadOutcomeAfterExtract(head_outcome);
            return .{ .owned_failure = extracted };
        },
        .redirect => |*metadata| {
            return .{ .owned_failure = try headMetadataOwnedFailure(allocator, ref_view, head_outcome, metadata, .network_error) };
        },
        .success => |*metadata| {
            return .{ .owned_failure = try headMetadataOwnedFailure(allocator, ref_view, head_outcome, metadata, .content_type_mismatch) };
        },
        .use_get_fallback => |*metadata| {
            return .{ .owned_failure = try headMetadataOwnedFailure(allocator, ref_view, head_outcome, metadata, .manifest_parse_error) };
        },
    }
}
pub fn ownedResolveErrorAlloc(
    allocator: std.mem.Allocator,
    ref: auth.AuthReferenceView,
    comptime tag: std.meta.Tag(ResolveError),
    http_status: ?u16,
    transport_retries_exhausted: bool,
) error{OutOfMemory}!ResolveError {
    const reference = try canonicalReferenceAlloc(allocator, ref);
    return switch (tag) {
        .rate_limited => rateLimitedError(ref.registry, reference, http_status, transport_retries_exhausted),
        .network_error => networkError(ref.registry, reference, http_status, transport_retries_exhausted),
        .timeout => timeoutError(ref.registry, reference, http_status, transport_retries_exhausted),
        inline else => |active_tag| @unionInit(ResolveError, @tagName(active_tag), .{
            .registry = ref.registry,
            .reference = reference,
            .http_status = http_status,
        }),
    };
}
pub fn canonicalReferenceAlloc(allocator: std.mem.Allocator, reference: auth.AuthReferenceView) ![]u8 {
    const separator: []const u8 = if (Digest.parse(reference.ref_string)) |_| "@" else |_| ":";
    const len = reference.registry.len + 1 + reference.repository_path.len + separator.len + reference.ref_string.len;
    const canonical = try allocator.alloc(u8, len);
    const written = std.fmt.bufPrint(canonical, "{s}/{s}{s}{s}", .{
        reference.registry,
        reference.repository_path,
        separator,
        reference.ref_string,
    }) catch unreachable;
    std.debug.assert(written.len == len);
    return canonical;
}
pub fn buildManifestHttpRequestAlloc(
    allocator: std.mem.Allocator,
    request: ManifestRequest,
    bearer_token: ?[]const u8,
) !ManifestHttpRequest {
    const url = try request.uriAlloc(allocator);
    errdefer allocator.free(url);

    const authorization = if (bearer_token) |token|
        try buildBearerAuthorizationAlloc(allocator, token)
    else
        null;
    errdefer auth.freeOwnedOptionalSecretSlice(allocator, authorization);

    return .{
        .method = request.method,
        .url = url,
        .authorization = authorization,
        .accept = request.accept,
    };
}
pub fn liveManifestHttpExchanger(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: ManifestHttpRequest,
) ManifestExchangeError!ManifestHttpResponse {
    defer request.deinit(allocator);
    const owned_accept_headers = request.prebuilt_accept_headers == null;
    const accept_headers = if (request.prebuilt_accept_headers) |headers| headers else try buildAcceptHeadersAlloc(allocator, request.accept);
    defer if (owned_accept_headers) allocator.free(accept_headers);

    const redirect_hop_limit: u8 = 2;
    var current_url = request.url;
    var current_authorization = request.authorization;
    var owned_redirect_url: ?[]u8 = null;
    defer if (owned_redirect_url) |url| allocator.free(url);

    var redirect_hops_remaining: u8 = redirect_hop_limit;
    while (true) {
        const loopback_url = testing_loopback.cleartextLoopbackUrlAlloc(allocator, current_url) catch return error.OutOfMemory;
        defer if (loopback_url) |url| allocator.free(url);
        const request_url = loopback_url orelse current_url;
        const uri = std.Uri.parse(request_url) catch return error.TransportFailed;

        var http_request = client.request(
            switch (request.method) {
                .head => .HEAD,
                .get => .GET,
            },
            uri,
            .{
                .redirect_behavior = .unhandled,
                .headers = .{
                    .authorization = if (current_authorization) |authorization|
                        .{ .override = authorization }
                    else
                        .default,
                },
                .extra_headers = accept_headers,
            },
        ) catch |err| return mapLiveManifestTransportError(err);
        defer http_request.deinit();

        http_request.sendBodiless() catch |err| return mapLiveManifestTransportError(err);

        var redirect_buffer: [8 * 1024]u8 = undefined;
        var response = http_request.receiveHead(&redirect_buffer) catch |err| return mapLiveManifestTransportError(err);

        if (isRedirectStatus(response.head.status) and response.head.location != null and redirect_hops_remaining > 0) {
            redirect_hops_remaining -= 1;

            var next_url = try resolveRedirectUrlAlloc(allocator, current_url, uri, response.head.location.?);
            errdefer allocator.free(next_url);

            // Rewrite before keep-auth so loopback https Locations match the cleartext request scheme.
            if (testing_loopback.cleartextLoopbackUrlAlloc(allocator, next_url) catch return error.OutOfMemory) |rewritten| {
                allocator.free(next_url);
                next_url = rewritten;
            }

            const keep_authorization = shouldKeepAuthorizationOnRedirect(uri, next_url) catch false;
            if (owned_redirect_url) |url| allocator.free(url);
            owned_redirect_url = next_url;
            current_url = next_url;
            current_authorization = if (keep_authorization) request.authorization else null;

            continue;
        }

        var owned_metadata = try ownedManifestResponseMetadataFromHead(allocator, response.head);
        errdefer owned_metadata.deinit(allocator);

        const body = if (request.method == .get and !resilience.isRetryableHttpStatus(response.head.status))
            resilience.readHttpResponseBodyAlloc(allocator, response.reader(&.{}), request.max_response_body_bytes) catch |err| return mapLiveManifestTransportError(err)
        else
            null;
        errdefer if (body) |bytes| allocator.free(bytes);

        return .{
            .metadata = owned_metadata.view(response.head.status),
            .owned_metadata = owned_metadata,
            .body = body,
        };
    }
}
// --- Manifest HEAD/GET paths ---

pub fn performManifestHead(
    ctx: ResolverParams,
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

    const exchange_outcome = exchangeManifestRequest(ctx, engine, exchanger, request, null);
    switch (exchange_outcome) {
        .ok => |ok| {
            defer ok.response.deinit(ctx.allocator);
            return classifyHeadResponse(ctx, engine, exchanger, request, ok.response.metadata, true, ok.budget);
        },
        .transport_failed => |failure| {
            return mapExhaustedManifestTransportError(HeadRequestOutcome, ctx, failure.err, failure.budget);
        },
    }
}
pub fn performManifestGet(
    ctx: ResolverParams,
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

    const exchange_outcome = exchangeManifestRequest(ctx, engine, exchanger, request, null);
    switch (exchange_outcome) {
        .ok => |ok| return classifyGetResponse(ctx, engine, exchanger, request, ok.response, true, ok.budget),
        .transport_failed => |failure| {
            return mapExhaustedManifestTransportError(GetRequestOutcome, ctx, failure.err, failure.budget);
        },
    }
}

// --- Private helpers ---

const MAX_WWW_AUTHENTICATE_HEADERS = 8;
const MAX_RESILIENCE_HEADERS = 16;
const MAX_MANIFEST_HEADER_VALUE_BYTES = 8 * 1024;

fn mapLiveManifestTransportError(err: anyerror) ManifestExchangeError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.BodyTooLarge => error.ResponseBodyTooLarge,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.Timeout => error.Timeout,
        error.NetworkUnreachable => error.NetworkUnreachable,
        error.ConnectionRefused => error.ConnectionRefused,
        error.UnknownHostName => error.UnknownHostName,
        else => error.TransportFailed,
    };
}
fn resolveRedirectUrlAlloc(
    allocator: std.mem.Allocator,
    _: []const u8,
    base_uri: std.Uri,
    location: []const u8,
) ManifestExchangeError![]u8 {
    var resolve_buf: [4096]u8 = undefined;
    if (location.len > resolve_buf.len) return error.OutOfMemory;
    @memcpy(resolve_buf[0..location.len], location);
    var aux_buf: []u8 = resolve_buf[0..];
    const resolved = std.Uri.resolveInPlace(base_uri, location.len, &aux_buf) catch |err| switch (err) {
        error.NoSpaceLeft => return error.OutOfMemory,
        else => return error.TransportFailed,
    };

    var out_buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buf);
    std.Uri.writeToStream(&resolved, &writer, .all) catch return error.TransportFailed;
    const formatted = writer.buffered();
    return allocator.dupe(u8, formatted) catch error.OutOfMemory;
}
fn shouldKeepAuthorizationOnRedirect(base_uri: std.Uri, next_url: []const u8) !bool {
    const next_uri = std.Uri.parse(next_url) catch return false;
    if (!std.ascii.eqlIgnoreCase(base_uri.scheme, next_uri.scheme)) return false;

    var base_host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const base_host = try base_uri.getHost(&base_host_buffer);

    var next_host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const next_host = try next_uri.getHost(&next_host_buffer);

    return base_host.eql(next_host) and effectiveUriPort(base_uri) == effectiveUriPort(next_uri);
}
fn effectiveUriPort(uri: std.Uri) ?u16 {
    return uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https"))
        443
    else if (std.ascii.eqlIgnoreCase(uri.scheme, "http"))
        80
    else
        null;
}
fn manifestHeaderValueWithinLimit(value: []const u8) bool {
    return value.len <= MAX_MANIFEST_HEADER_VALUE_BYTES;
}
fn wwwAuthenticateHeadersSufficient(headers: []const []const u8) bool {
    const challenge = auth.parseAuthenticateHeaders(headers) catch return false;
    return switch (challenge) {
        .bearer => true,
        else => false,
    };
}
fn resilienceHeaderAlreadyCollected(headers: []const resilience.HttpHeader, name: []const u8) bool {
    for (headers) |existing| {
        if (std.ascii.eqlIgnoreCase(existing.name, name)) return true;
    }
    return false;
}
fn dupeManifestHeaderValueAlloc(allocator: std.mem.Allocator, value: []const u8) ManifestExchangeError![]u8 {
    if (!manifestHeaderValueWithinLimit(value)) return error.ResponseHeadersTooLarge;
    return allocator.dupe(u8, value) catch error.OutOfMemory;
}
fn buildAcceptHeadersAlloc(
    allocator: std.mem.Allocator,
    accept: []const []const u8,
) error{OutOfMemory}![]std.http.Header {
    const headers = try allocator.alloc(std.http.Header, accept.len);
    for (accept, 0..) |value, index| {
        headers[index] = .{
            .name = "accept",
            .value = value,
        };
    }
    return headers;
}
fn buildBearerAuthorizationAlloc(allocator: std.mem.Allocator, token: []const u8) error{OutOfMemory}![]u8 {
    var stack_buf: [512]u8 = undefined;
    const written = std.fmt.bufPrint(&stack_buf, "Bearer {s}", .{token}) catch
        return std.fmt.allocPrint(allocator, "Bearer {s}", .{token}) catch error.OutOfMemory;
    return allocator.dupe(u8, written) catch error.OutOfMemory;
}
fn shouldCollectManifestAuthHeaders(status: std.http.Status) bool {
    return status == .unauthorized;
}
fn shouldCollectManifestResilienceHeader(status: std.http.Status, header_name: []const u8) bool {
    if (status == .too_many_requests or resilience.classifyHttpStatus(status) != .none) {
        return resilience.isTrackedResilienceHeaderName(header_name);
    }
    if (status == .ok) {
        return std.mem.startsWith(u8, header_name, "RateLimit-") or
            std.ascii.startsWithIgnoreCase(header_name, "X-RateLimit-");
    }
    return false;
}
fn ownedManifestResponseMetadataFromHead(
    allocator: std.mem.Allocator,
    head: std.http.Client.Response.Head,
) ManifestExchangeError!OwnedManifestResponseMetadata {
    const collect_auth_headers = shouldCollectManifestAuthHeaders(head.status);

    var www_authenticate_headers = std.ArrayList([]const u8).empty;
    errdefer {
        for (www_authenticate_headers.items) |header| allocator.free(header);
        www_authenticate_headers.deinit(allocator);
    }
    try www_authenticate_headers.ensureTotalCapacity(allocator, MAX_WWW_AUTHENTICATE_HEADERS);

    var resilience_headers = std.ArrayList(resilience.HttpHeader).empty;
    errdefer {
        resilience.deinitOwnedHttpHeaders(allocator, resilience_headers.items);
        resilience_headers.deinit(allocator);
    }
    try resilience_headers.ensureTotalCapacity(allocator, MAX_RESILIENCE_HEADERS);

    const content_type = if (head.content_type) |content_type|
        try dupeManifestHeaderValueAlloc(allocator, content_type)
    else
        null;
    errdefer if (content_type) |value| allocator.free(value);

    const location = if (head.location) |location|
        try dupeManifestHeaderValueAlloc(allocator, location)
    else
        null;
    errdefer if (location) |value| allocator.free(value);

    var docker_content_digest: ?[]u8 = null;
    errdefer if (docker_content_digest) |value| allocator.free(value);

    var www_authenticate_complete = false;
    var header_it = head.iterateHeaders();
    while (header_it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "docker-content-digest")) {
            if (docker_content_digest == null) {
                docker_content_digest = try dupeManifestHeaderValueAlloc(allocator, header.value);
            }
            continue;
        }

        if (std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) {
            if (!collect_auth_headers or www_authenticate_complete) continue;
            if (www_authenticate_headers.items.len >= MAX_WWW_AUTHENTICATE_HEADERS) {
                return error.ResponseHeadersTooLarge;
            }
            const value = try dupeManifestHeaderValueAlloc(allocator, header.value);
            errdefer allocator.free(value);
            try www_authenticate_headers.append(allocator, value);
            if (wwwAuthenticateHeadersSufficient(www_authenticate_headers.items)) {
                www_authenticate_complete = true;
            }
            continue;
        }

        if (resilience.isTrackedResilienceHeaderName(header.name)) {
            if (!shouldCollectManifestResilienceHeader(head.status, header.name)) continue;
            if (resilienceHeaderAlreadyCollected(resilience_headers.items, header.name)) continue;
            if (resilience_headers.items.len >= MAX_RESILIENCE_HEADERS) {
                return error.ResponseHeadersTooLarge;
            }
            const name = try allocator.dupe(u8, header.name);
            errdefer allocator.free(name);
            const value = try dupeManifestHeaderValueAlloc(allocator, header.value);
            errdefer allocator.free(value);
            try resilience_headers.append(allocator, .{ .name = name, .value = value });
        }
    }

    const owned_www_authenticate_headers = try www_authenticate_headers.toOwnedSlice(allocator);
    errdefer freeHeaderSlices(allocator, owned_www_authenticate_headers);
    const owned_resilience_headers = try resilience_headers.toOwnedSlice(allocator);

    return .{
        .content_type = content_type,
        .docker_content_digest = docker_content_digest,
        .location = location,
        .www_authenticate_headers = owned_www_authenticate_headers,
        .resilience_headers = owned_resilience_headers,
    };
}
fn resolveErrorFromAuthError(
    err: auth.AuthError,
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16,
    token_transport_retries_exhausted: bool,
) error{OutOfMemory}!ResolveError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.HelperTimedOut => .{ .timeout = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
            .transport_retries_exhausted = false,
        } },
        error.Timeout => .{ .timeout = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
            .transport_retries_exhausted = token_transport_retries_exhausted,
        } },
        error.UnsupportedProbeStatus => unsupportedProbeStatusResolveError(
            registry,
            reference,
            http_status,
            token_transport_retries_exhausted,
        ),
        error.TokenResponseTooLarge => .{ .response_too_large = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
        } },
        error.ConnectionResetByPeer,
        error.NetworkUnreachable,
        error.ConnectionRefused,
        error.UnknownHostName,
        => .{ .network_error = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
            .transport_retries_exhausted = token_transport_retries_exhausted,
        } },
        error.RateLimited => .{ .rate_limited = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status orelse @intFromEnum(std.http.Status.too_many_requests),
            .transport_retries_exhausted = true,
        } },
        else => .{ .auth_failed = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
        } },
    };
}
fn unsupportedProbeStatusResolveError(
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16,
    transport_retries_exhausted: bool,
) ResolveError {
    if (http_status) |status| {
        if (status == @intFromEnum(std.http.Status.too_many_requests)) {
            return rateLimitedError(registry, reference, status, transport_retries_exhausted);
        }
        if (status >= 500) {
            return networkError(registry, reference, status, transport_retries_exhausted);
        }
    }
    return .{ .auth_failed = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}
fn manifestParseError(registry: []const u8, reference: []const u8, http_status: ?u16) ResolveError {
    return .{ .manifest_parse_error = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}
fn networkError(registry: []const u8, reference: []const u8, http_status: ?u16, transport_retries_exhausted: bool) ResolveError {
    return .{ .network_error = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
        .transport_retries_exhausted = transport_retries_exhausted,
    } };
}
fn timeoutError(registry: []const u8, reference: []const u8, http_status: ?u16, transport_retries_exhausted: bool) ResolveError {
    return .{ .timeout = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
        .transport_retries_exhausted = transport_retries_exhausted,
    } };
}
fn responseTooLargeError(registry: []const u8, reference: []const u8, http_status: ?u16) ResolveError {
    return .{ .response_too_large = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}
fn rateLimitedError(registry: []const u8, reference: []const u8, http_status: ?u16, transport_retries_exhausted: bool) ResolveError {
    return .{ .rate_limited = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
        .transport_retries_exhausted = transport_retries_exhausted,
    } };
}
fn mapExhaustedManifestTransportError(
    comptime Outcome: type,
    ctx: ResolverParams,
    err: ManifestExchangeError,
    budget: resilience.RetryBudget,
) error{OutOfMemory}!Outcome {
    const transport_retries_exhausted = budget.networkRetriesExhausted();
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ResponseBodyTooLarge, error.ResponseHeadersTooLarge => mappedFailureOutcome(Outcome, ctx, null, responseTooLargeError),
        error.Timeout => mappedRetryFailureOutcome(Outcome, ctx, null, timeoutError, transport_retries_exhausted),
        else => mappedRetryFailureOutcome(Outcome, ctx, null, networkError, transport_retries_exhausted),
    };
}
fn contentTypeMismatchError(registry: []const u8, reference: []const u8, http_status: ?u16) ResolveError {
    return .{ .content_type_mismatch = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}
fn digestMismatchError(registry: []const u8, reference: []const u8, http_status: ?u16) ResolveError {
    return .{ .digest_mismatch = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}
fn unsupportedAlgorithmError(registry: []const u8, reference: []const u8, http_status: ?u16) ResolveError {
    return .{ .unsupported_algorithm = .{
        .registry = registry,
        .reference = reference,
        .http_status = http_status,
    } };
}
const ManifestExchangeLoop = struct {
    resolver_ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    bearer_token: ?[]const u8,
    cached_url: ?[]u8 = null,
    cached_authorization: ?[]u8 = null,
    cached_accept_headers: ?[]std.http.Header = null,
    exchange_attempt: usize = 0,
};
fn exchangeManifestRequestOnce(
    loop_ctx: *ManifestExchangeLoop,
    exchanger: ManifestHttpExchanger,
) ManifestExchangeError!ManifestHttpResponse {
    const allocator = loop_ctx.resolver_ctx.allocator;
    loop_ctx.exchange_attempt += 1;

    var handed_to_exchanger = false;
    const url = if (loop_ctx.cached_url) |cached|
        try allocator.dupe(u8, cached)
    else blk: {
        const built = try loop_ctx.request.uriAlloc(allocator);
        loop_ctx.cached_url = try allocator.dupe(u8, built);
        break :blk built;
    };
    errdefer if (!handed_to_exchanger) allocator.free(url);

    const authorization = if (loop_ctx.bearer_token) |token| blk: {
        if (loop_ctx.cached_authorization) |cached|
            break :blk try allocator.dupe(u8, cached);
        const built = try buildBearerAuthorizationAlloc(allocator, token);
        loop_ctx.cached_authorization = try allocator.dupe(u8, built);
        break :blk built;
    } else null;
    errdefer if (!handed_to_exchanger) auth.freeOwnedOptionalSecretSlice(allocator, authorization);

    const http_request = ManifestHttpRequest{
        .method = loop_ctx.request.method,
        .url = url,
        .authorization = authorization,
        .accept = loop_ctx.request.accept,
        .prebuilt_accept_headers = loop_ctx.cached_accept_headers,
        .max_response_body_bytes = loop_ctx.resolver_ctx.config.max_manifest_bytes,
    };
    handed_to_exchanger = true;
    return exchanger(allocator, loop_ctx.resolver_ctx.client, http_request);
}
fn exchangeManifestRequest(
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    bearer_token: ?[]const u8,
) resilience.HttpRetryLoopResult(ManifestHttpResponse, ManifestExchangeError) {
    var policy = resilience.retryPolicyFromConfig(ctx.config, ctx.transport_hooks);

    var loop_ctx = ManifestExchangeLoop{
        .resolver_ctx = ctx,
        .engine = engine,
        .exchanger = exchanger,
        .request = request,
        .bearer_token = bearer_token,
    };
    loop_ctx.cached_accept_headers = buildAcceptHeadersAlloc(ctx.allocator, request.accept) catch {
        return .{ .transport_failed = .{ .err = error.OutOfMemory, .budget = policy.budget } };
    };
    defer if (loop_ctx.cached_accept_headers) |headers| ctx.allocator.free(headers);
    defer if (loop_ctx.cached_url) |cached_url| ctx.allocator.free(cached_url);
    defer if (loop_ctx.cached_authorization) |authorization|
        auth.freeOwnedOptionalSecretSlice(ctx.allocator, authorization);

    const hooks: resilience.HttpRetryLoopHooks = if (ctx.config.rate_limit_enabled)
        .{
            .before_first_attempt = beforeManifestExchangeAttempt,
            .after_successful_exchange = afterManifestExchangeAttempt,
        }
    else
        .{};

    return resilience.runHttpRetryLoop(
        ctx.client,
        ctx.transport_hooks,
        &policy,
        hooks,
        ManifestExchangeError,
        ManifestHttpResponse,
        @ptrCast(&loop_ctx),
        manifestExchangeOnceOpaque,
        manifestResponseStatus,
        manifestResponseResilienceHeaders,
        deinitManifestHttpResponse,
        ctx.allocator,
    );
}
fn beforeManifestExchangeAttempt(ctx_ptr: *anyopaque) void {
    const loop_ctx: *const ManifestExchangeLoop = @ptrCast(@alignCast(ctx_ptr));
    const throttle = loop_ctx.resolver_ctx.manifest_throttle orelse return;
    throttle.sleepBeforeManifestRequestIfNeeded(
        loop_ctx.resolver_ctx.config,
        loop_ctx.resolver_ctx.client,
        loop_ctx.resolver_ctx.transport_hooks,
    );
}
fn afterManifestExchangeAttempt(ctx_ptr: *anyopaque, _: std.http.Status, headers: []const resilience.HttpHeader) void {
    const loop_ctx: *const ManifestExchangeLoop = @ptrCast(@alignCast(ctx_ptr));
    const throttle = loop_ctx.resolver_ctx.manifest_throttle orelse return;
    throttle.recordManifestResponseHeaders(headers);
}
fn manifestExchangeOnceOpaque(ctx_ptr: *anyopaque) ManifestExchangeError!ManifestHttpResponse {
    const loop_ctx: *ManifestExchangeLoop = @ptrCast(@alignCast(ctx_ptr));
    return exchangeManifestRequestOnce(loop_ctx, loop_ctx.exchanger);
}
fn manifestResponseStatus(response: ManifestHttpResponse) std.http.Status {
    return response.metadata.status;
}
fn manifestResponseResilienceHeaders(response: ManifestHttpResponse) []const resilience.HttpHeader {
    return response.metadata.resilience_headers;
}
fn deinitManifestHttpResponse(allocator: std.mem.Allocator, response: ManifestHttpResponse) void {
    var owned = response;
    owned.deinit(allocator);
}
fn mapRetryableManifestStatusFailure(
    comptime Outcome: type,
    ctx: ResolverParams,
    http_status: ?u16,
    status: std.http.Status,
    budget: resilience.RetryBudget,
) error{OutOfMemory}!?Outcome {
    if (status == .too_many_requests) {
        return try mappedRetryFailureOutcome(
            Outcome,
            ctx,
            http_status,
            rateLimitedError,
            budget.rateLimitRetriesExhausted(),
        );
    }

    if (resilience.classifyHttpStatus(status) == .network) {
        return try mappedRetryFailureOutcome(
            Outcome,
            ctx,
            http_status,
            networkError,
            budget.networkRetriesExhausted(),
        );
    }

    return null;
}
fn classifyHeadResponse(
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
    allow_auth: bool,
    retry_budget: resilience.RetryBudget,
) error{OutOfMemory}!HeadRequestOutcome {
    if (isRedirectStatus(metadata.status)) {
        if (metadata.location != null) return .{ .redirect = try metadata.cloneAllocRedirect(ctx.allocator) };
        return mappedRetryFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), networkError, retry_budget.networkRetriesExhausted());
    }

    if (try mapRetryableManifestStatusFailure(HeadRequestOutcome, ctx, metadata.httpStatus(), metadata.status, retry_budget)) |failure| {
        return failure;
    }

    if (metadata.status == .unauthorized and !allow_auth) {
        return authFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus());
    }

    const classification = metadata.probeClassification() catch |err| {
        return mappedAuthFailureOutcome(HeadRequestOutcome, ctx, engine, err, metadata.httpStatus());
    };

    return switch (classification) {
        .ok => classifyUsableHeadMetadata(ctx, request, metadata),
        .not_found => .not_found,
        .auth_required => |challenge| if (allow_auth)
            authenticateHeadRequest(ctx, engine, exchanger, request, challenge)
        else
            authFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus()),
    };
}
fn authenticateHeadRequest(
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    challenge: auth.AuthChallenge,
) error{OutOfMemory}!HeadRequestOutcome {
    return authenticateManifestRequest(
        HeadRequestOutcome,
        ctx,
        engine,
        exchanger,
        request,
        challenge,
        classifyAuthenticatedHeadResponse,
    );
}
fn classifyGetResponse(
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    response: ManifestHttpResponse,
    allow_auth: bool,
    retry_budget: resilience.RetryBudget,
) error{OutOfMemory}!GetRequestOutcome {
    var owned_response = response;
    defer owned_response.deinit(ctx.allocator);
    const metadata = owned_response.metadata;

    if (isRedirectStatus(metadata.status)) {
        if (metadata.location != null) return .{ .redirect = try metadata.cloneAllocRedirect(ctx.allocator) };
        return mappedRetryFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), networkError, retry_budget.networkRetriesExhausted());
    }

    if (try mapRetryableManifestStatusFailure(GetRequestOutcome, ctx, metadata.httpStatus(), metadata.status, retry_budget)) |failure| {
        return failure;
    }

    if (metadata.status == .unauthorized and !allow_auth) {
        return authFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus());
    }

    const classification = metadata.probeClassification() catch |err| {
        return mappedAuthFailureOutcome(GetRequestOutcome, ctx, engine, err, metadata.httpStatus());
    };

    return switch (classification) {
        .ok => blk: {
            owned_response.clearEphemeralMetadataHeaders(ctx.allocator);
            const stolen_body = owned_response.body;
            owned_response.body = null;
            break :blk classifyUsableGetResponse(ctx, request, metadata, stolen_body);
        },
        .not_found => .not_found,
        .auth_required => |challenge| if (allow_auth)
            authenticateGetRequest(ctx, engine, exchanger, request, challenge)
        else
            authFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus()),
    };
}
fn authenticateGetRequest(
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    challenge: auth.AuthChallenge,
) error{OutOfMemory}!GetRequestOutcome {
    return authenticateManifestRequest(
        GetRequestOutcome,
        ctx,
        engine,
        exchanger,
        request,
        challenge,
        classifyAuthenticatedGetResponse,
    );
}
fn authenticateManifestRequest(
    comptime Outcome: type,
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    challenge: auth.AuthChallenge,
    comptime classify_authenticated_response_fn: fn (ResolverParams, *auth.AuthEngine, ManifestHttpExchanger, ManifestRequest, ManifestHttpResponse, resilience.RetryBudget) error{OutOfMemory}!Outcome,
) error{OutOfMemory}!Outcome {
    const unauthorized_status = @intFromEnum(std.http.Status.unauthorized);
    const bearer_challenge = switch (challenge) {
        .bearer => |bearer| bearer,
        else => return authFailureOutcome(Outcome, ctx, unauthorized_status),
    };

    const auth_request = auth.AuthenticateRequest.init(ctx.reference.registry, bearer_challenge) catch |err| {
        return mappedAuthFailureOutcome(Outcome, ctx, engine, err, unauthorized_status);
    };

    var token_response = (engine.authenticate(ctx.client, auth_request) catch |err| {
        return mappedAuthFailureOutcome(Outcome, ctx, engine, err, unauthorized_status);
    }) orelse {
        return authFailureOutcome(Outcome, ctx, unauthorized_status);
    };
    defer token_response.deinit(ctx.allocator);

    const retry_exchange_outcome = exchangeManifestRequest(ctx, engine, exchanger, request, token_response.access_token.value);
    const retry_response = switch (retry_exchange_outcome) {
        .ok => |ok| ok,
        .transport_failed => |failure| {
            return mapExhaustedManifestTransportError(Outcome, ctx, failure.err, failure.budget);
        },
    };

    if (retry_response.response.metadata.status != .unauthorized) {
        return classify_authenticated_response_fn(ctx, engine, exchanger, request, retry_response.response, retry_response.budget);
    }

    retry_response.response.deinit(ctx.allocator);

    if (!request.allow_cached_auth_retry) return authFailureOutcome(Outcome, ctx, unauthorized_status);

    var refreshed_token_response = (engine.retryAuthenticateAfterCachedUnauthorized(ctx.client, auth_request) catch |err| {
        return mappedAuthFailureOutcome(Outcome, ctx, engine, err, unauthorized_status);
    }) orelse {
        return authFailureOutcome(Outcome, ctx, unauthorized_status);
    };
    defer refreshed_token_response.deinit(ctx.allocator);

    var retried_request = request;
    retried_request.allow_cached_auth_retry = false;

    const refreshed_exchange_outcome = exchangeManifestRequest(ctx, engine, exchanger, retried_request, refreshed_token_response.access_token.value);
    const refreshed_response = switch (refreshed_exchange_outcome) {
        .ok => |ok| ok,
        .transport_failed => |failure| {
            return mapExhaustedManifestTransportError(Outcome, ctx, failure.err, failure.budget);
        },
    };

    if (refreshed_response.response.metadata.status == .unauthorized) {
        refreshed_response.response.deinit(ctx.allocator);
        return authFailureOutcome(Outcome, ctx, unauthorized_status);
    }

    return classify_authenticated_response_fn(ctx, engine, exchanger, retried_request, refreshed_response.response, refreshed_response.budget);
}
fn classifyAuthenticatedHeadResponse(
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    response: ManifestHttpResponse,
    retry_budget: resilience.RetryBudget,
) error{OutOfMemory}!HeadRequestOutcome {
    defer response.deinit(ctx.allocator);
    return classifyHeadResponse(ctx, engine, exchanger, request, response.metadata, false, retry_budget);
}
fn classifyAuthenticatedGetResponse(
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    response: ManifestHttpResponse,
    retry_budget: resilience.RetryBudget,
) error{OutOfMemory}!GetRequestOutcome {
    return classifyGetResponse(ctx, engine, exchanger, request, response, false, retry_budget);
}
fn classifyUsableHeadMetadata(
    ctx: ResolverParams,
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
) error{OutOfMemory}!HeadRequestOutcome {
    if (metadata.docker_content_digest == null) return .{ .use_get_fallback = ManifestResponseMetadata.headFallbackMetadata(metadata.status) };
    if (Digest.parse(metadata.docker_content_digest.?)) |_| {} else |_| {
        return .{ .use_get_fallback = ManifestResponseMetadata.headFallbackMetadata(metadata.status) };
    }

    const content_type = metadata.content_type orelse return .{ .use_get_fallback = ManifestResponseMetadata.headFallbackMetadata(metadata.status) };
    const media_type = manifestDocumentMediaType(content_type) orelse {
        return mappedFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    };
    if (!acceptsManifestMediaType(request.accept, media_type)) {
        return mappedFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    }

    if (ctx.operation == .validate and !media_type.isMultiArch()) {
        if (Digest.parse(ctx.reference.ref_string)) |expected_digest| {
            const header_digest = Digest.parse(metadata.docker_content_digest.?) catch unreachable;
            if (!digestMatchesSha256Hex(expected_digest, header_digest.hex)) {
                return mappedFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), digestMismatchError);
            }
        } else |err| switch (err) {
            error.MissingColon => {},
            error.UnsupportedAlgorithm => return mappedFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), unsupportedAlgorithmError),
            else => return mappedFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), digestMismatchError),
        }
        return .{ .validate_manifest_ok = media_type };
    }

    if (ctx.operation == .validate and ctx.platform != null) {
        return .{ .use_get_fallback = ManifestResponseMetadata.headFallbackMetadata(metadata.status) };
    }

    return .{ .success = try metadata.cloneAllocHeadSuccess(ctx.allocator) };
}
fn classifyUsableGetResponse(
    ctx: ResolverParams,
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
    body: ?[]u8,
) error{OutOfMemory}!GetRequestOutcome {
    var owned_body = body;
    defer if (owned_body) |b| ctx.allocator.free(b);

    const content_type = metadata.content_type orelse {
        return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    };
    const media_type = manifestDocumentMediaType(content_type) orelse {
        return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    };
    if (!acceptsManifestMediaType(request.accept, media_type)) {
        return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    }
    const response_body = owned_body orelse return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), manifestParseError);
    if (response_body.len == 0) return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), manifestParseError);

    // Hash and parse the owned response body in place. `json.parse` uses
    // alloc_always; shallow resolve probes return only a MediaType enum. Neither
    // retains pointers into `response_body`, so the nested arena copy is unnecessary.
    const resolved_digest = verifyManifestBodyIntegrityAlloc(ctx, metadata, response_body) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.DigestMismatch => return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), digestMismatchError),
        error.UnsupportedAlgorithm => return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), unsupportedAlgorithmError),
    };
    var resolved_digest_raw: ?[]u8 = resolved_digest.raw;
    defer if (resolved_digest_raw) |raw| ctx.allocator.free(raw);

    var document = parseManifestDocument(ctx.allocator, ctx.operation, media_type, response_body) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), manifestParseError),
    };
    var keep_document = false;
    defer if (!keep_document) document.deinit();

    if (document.mediaType() != media_type) {
        return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    }

    ctx.allocator.free(response_body);
    owned_body = null;

    keep_document = true;
    const owned_digest_raw = resolved_digest_raw.?;
    resolved_digest_raw = null;

    return .{ .success = .{
        .request = request,
        .resolved_digest = resolved_digest.digest,
        .resolved_digest_raw = owned_digest_raw,
        .document = document,
        .backing_body = null,
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
fn acceptsManifestMediaType(accept: []const []const u8, media_type: MediaType) bool {
    if (accept.len == 0) return true;

    for (accept) |entry| {
        const normalized = normalizeContentType(entry);
        if (std.mem.eql(u8, normalized, "*/*")) return true;

        const accepted_media_type = MediaType.fromString(normalized) orelse continue;
        if (accepted_media_type == media_type) return true;
    }

    return false;
}
fn parseManifestDocument(
    allocator: std.mem.Allocator,
    operation: ResolverOperation,
    media_type: MediaType,
    body: []const u8,
) !ParsedManifestDocument {
    const shallow_single_manifest = operation == .resolve or operation == .resolve_child_manifest;
    return switch (media_type) {
        .oci_manifest_v1, .docker_manifest_v2 => if (shallow_single_manifest)
            .{ .manifest_media_type = try Manifest.parseMediaTypeShallow(allocator, body) }
        else
            .{ .manifest = try json.parse(Manifest, allocator, body) },
        .oci_index_v1 => .{ .oci_index = try json.parse(OciImageIndex, allocator, body) },
        .docker_manifest_list_v2 => .{ .docker_manifest_list = try json.parse(DockerManifestList, allocator, body) },
        else => error.UnexpectedToken,
    };
}
const ManifestIntegrityError = error{
    OutOfMemory,
    DigestMismatch,
    UnsupportedAlgorithm,
};
const VerifiedManifestDigest = struct {
    digest: Digest,
    raw: []u8,
};
fn verifyManifestBodyIntegrityAlloc(
    ctx: ResolverParams,
    metadata: ManifestResponseMetadata,
    body: []const u8,
) ManifestIntegrityError!VerifiedManifestDigest {
    const digest_hex = bodySha256DigestHex(body);

    if (try expectedReferenceDigest(ctx.reference.ref_string)) |expected_digest| {
        if (!digestMatchesSha256Hex(expected_digest, digest_hex[0..])) return error.DigestMismatch;
    }

    if (metadata.docker_content_digest) |header_digest_text| {
        const header_digest = parseExpectedDigest(header_digest_text) catch |err| switch (err) {
            error.UnsupportedAlgorithm => return error.UnsupportedAlgorithm,
            else => return error.DigestMismatch,
        };

        if (!digestMatchesSha256Hex(header_digest, digest_hex[0..])) return error.DigestMismatch;
    }

    const digest_prefix = "sha256:";
    const body_digest_raw = try ctx.allocator.alloc(u8, digest_prefix.len + digest_hex.len);
    errdefer ctx.allocator.free(body_digest_raw);
    @memcpy(body_digest_raw[0..digest_prefix.len], digest_prefix);
    @memcpy(body_digest_raw[digest_prefix.len..], digest_hex[0..]);

    return .{
        .digest = .{
            .algorithm = .sha256,
            .hex = body_digest_raw[digest_prefix.len..],
        },
        .raw = body_digest_raw,
    };
}
fn expectedReferenceDigest(ref_string: []const u8) ManifestIntegrityError!?Digest {
    return Digest.parse(ref_string) catch |err| switch (err) {
        error.MissingColon => null,
        error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
        else => error.DigestMismatch,
    };
}
fn parseExpectedDigest(text: []const u8) Digest.ParseError!Digest {
    return Digest.parse(text);
}
fn bodySha256DigestHex(body: []const u8) [Digest.Algorithm.sha256.hexLen()]u8 {
    var digest_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest_bytes, .{});
    return std.fmt.bytesToHex(digest_bytes, .lower);
}
fn digestMatchesSha256Hex(expected_digest: Digest, actual_hex: []const u8) bool {
    return expected_digest.algorithm == .sha256 and std.ascii.eqlIgnoreCase(expected_digest.hex, actual_hex);
}
fn failureOutcome(comptime Outcome: type, failure: ResolveError) Outcome {
    return .{ .failure = failure };
}
fn mappedFailureOutcome(
    comptime Outcome: type,
    ctx: ResolverParams,
    http_status: ?u16,
    comptime failure_factory: *const fn ([]const u8, []const u8, ?u16) ResolveError,
) error{OutOfMemory}!Outcome {
    const reference = try canonicalReferenceAlloc(ctx.allocator, ctx.reference);
    return failureOutcome(Outcome, failure_factory(ctx.reference.registry, reference, http_status));
}
fn mappedRetryFailureOutcome(
    comptime Outcome: type,
    ctx: ResolverParams,
    http_status: ?u16,
    comptime failure_factory: *const fn ([]const u8, []const u8, ?u16, bool) ResolveError,
    transport_retries_exhausted: bool,
) error{OutOfMemory}!Outcome {
    const reference = try canonicalReferenceAlloc(ctx.allocator, ctx.reference);
    return failureOutcome(Outcome, failure_factory(ctx.reference.registry, reference, http_status, transport_retries_exhausted));
}
fn authFailureOutcome(
    comptime Outcome: type,
    ctx: ResolverParams,
    http_status: ?u16,
) error{OutOfMemory}!Outcome {
    const reference = try canonicalReferenceAlloc(ctx.allocator, ctx.reference);
    return failureOutcome(Outcome, .{ .auth_failed = .{
        .registry = ctx.reference.registry,
        .reference = reference,
        .http_status = http_status,
    } });
}
fn mappedAuthFailureOutcome(
    comptime Outcome: type,
    ctx: ResolverParams,
    engine: *auth.AuthEngine,
    err: auth.AuthError,
    http_status: ?u16,
) error{OutOfMemory}!Outcome {
    const reference = try canonicalReferenceAlloc(ctx.allocator, ctx.reference);
    errdefer ctx.allocator.free(reference);
    const token_transport_retries_exhausted = engine.takeTokenTransportRetriesExhausted();
    return failureOutcome(Outcome, try resolveErrorFromAuthError(
        err,
        ctx.reference.registry,
        reference,
        http_status,
        token_transport_retries_exhausted,
    ));
}
fn isRedirectStatus(status: std.http.Status) bool {
    const code = @intFromEnum(status);
    return code >= 300 and code < 400;
}
fn stubHeadOutcomeAfterExtract(head_outcome: *HeadRequestOutcome) void {
    head_outcome.* = .not_found;
}
fn headMetadataOwnedFailure(
    allocator: std.mem.Allocator,
    ref_view: auth.AuthReferenceView,
    head_outcome: *HeadRequestOutcome,
    metadata: *ManifestResponseMetadata,
    comptime tag: std.meta.Tag(ResolveError),
) error{OutOfMemory}!ResolveError {
    const http_status = metadata.httpStatus();
    metadata.releaseOwned(allocator);
    stubHeadOutcomeAfterExtract(head_outcome);
    return try ownedResolveErrorAlloc(allocator, ref_view, tag, http_status, false);
}
fn fixtureBodyAlloc(allocator: std.mem.Allocator, path: []const u8, comptime max_bytes: usize) ManifestExchangeError![]u8 {
    var buffer: [max_bytes + 1]u8 = undefined;
    const bytes = std.Io.Dir.cwd().readFile(std.testing.io, path, &buffer) catch |err| switch (err) {
        else => return error.TransportFailed,
    };
    return allocator.dupe(u8, bytes);
}
fn duplicateHeaderSlicesAlloc(allocator: std.mem.Allocator, headers: []const []const u8) ![]const []const u8 {
    const owned_headers = try allocator.alloc([]const u8, headers.len);
    errdefer allocator.free(owned_headers);

    var initialized: usize = 0;
    errdefer {
        for (owned_headers[0..initialized]) |header| allocator.free(header);
    }

    for (headers, 0..) |header, index| {
        owned_headers[index] = try allocator.dupe(u8, header);
        initialized += 1;
    }

    return owned_headers;
}
fn freeHeaderSlices(allocator: std.mem.Allocator, headers: []const []const u8) void {
    for (headers) |header| allocator.free(header);
    allocator.free(headers);
}
fn testHttpHeadFromLines(allocator: std.mem.Allocator, status_line: []const u8, header_lines: []const []const u8) !std.http.Client.Response.Head {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, status_line);
    try buf.appendSlice(allocator, "\r\n");
    for (header_lines) |line| {
        try buf.appendSlice(allocator, line);
        try buf.appendSlice(allocator, "\r\n");
    }
    try buf.appendSlice(allocator, "\r\n");
    const raw = try allocator.dupe(u8, buf.items);
    errdefer allocator.free(raw);
    return try std.http.Client.Response.Head.parse(raw);
}

// --- Tests ---

const test_matrix = @import("test_matrix.zig");
const sha256DigestStringAlloc = test_matrix.sha256DigestStringAlloc;

const ResolverTestHarness = struct {
    const busybox_ref = auth.AuthReferenceView{
        .registry = "registry-1.docker.io",
        .repository_path = "library/busybox",
        .ref_string = "latest",
    };

    fn refuseTokenExchange(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        request: auth.TokenHttpRequest,
    ) auth.AuthError!auth.TokenExchangeResponse {
        return test_matrix.refuseTokenExchange(allocator, client, request);
    }
};

test "resolveRedirectUrlAlloc: relative Location resolves against manifest URL" {
    const base_url = "https://registry.example.test/v2/library/ubuntu/manifests/latest";
    const base_uri = try std.Uri.parse(base_url);

    const resolved = try resolveRedirectUrlAlloc(
        std.testing.allocator,
        base_url,
        base_uri,
        "../blobs/sha256:abc123",
    );
    defer std.testing.allocator.free(resolved);

    try std.testing.expectEqualStrings(
        "https://registry.example.test/v2/library/ubuntu/blobs/sha256:abc123",
        resolved,
    );
}
test "shouldKeepAuthorizationOnRedirect: same-origin and rejection matrix" {
    const docker_base = try std.Uri.parse("https://registry-1.docker.io/v2/library/ubuntu/manifests/22.04");
    const example_base = try std.Uri.parse("https://registry.example.test/v2/owner/repo/manifests/latest");

    const cases = [_]struct {
        base: std.Uri,
        redirect: []const u8,
        keep: bool,
    }{
        .{ .base = docker_base, .redirect = "https://registry-1.docker.io/v2/library/ubuntu/manifests/22.04", .keep = true },
        .{ .base = docker_base, .redirect = "https://registry-1.docker.io:443/v2/library/ubuntu/manifests/22.04", .keep = true },
        .{ .base = docker_base, .redirect = "https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/abc/data", .keep = false },
        .{ .base = docker_base, .redirect = "http://registry-1.docker.io/v2/library/ubuntu/manifests/22.04", .keep = false },
        .{ .base = example_base, .redirect = "https://cdn.registry.example.test/v2/owner/repo/manifests/latest", .keep = false },
        .{ .base = example_base, .redirect = "https://registry.example.test:8443/v2/owner/repo/manifests/latest", .keep = false },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.keep, try shouldKeepAuthorizationOnRedirect(case.base, case.redirect));
    }
}
test "ResolverParams.init: preserves normalized reference and operation" {
    var client: std.http.Client = undefined;
    const view = auth.AuthReferenceView{
        .registry = "registry-1.docker.io",
        .repository_path = "library/busybox",
        .ref_string = "latest",
    };

    const ctx = ResolverParams.init(
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
test "ManifestRequest.uriAlloc: builds HEAD resolve manifest URL" {
    const head_request = ManifestRequest{
        .method = .head,
        .operation = .resolve,
        .reference = .{
            .registry = "ghcr.io",
            .repository_path = "owner/repo",
            .ref_string = "v1.2.3",
        },
    };

    const head_uri = try head_request.uriAlloc(std.testing.allocator);
    defer std.testing.allocator.free(head_uri);

    try std.testing.expectEqualStrings("https://ghcr.io/v2/owner/repo/manifests/v1.2.3", head_uri);
}

test "canonicalReferenceAlloc: formats tag- and digest-pinned references" {
    const digest_ref = auth.AuthReferenceView{
        .registry = "registry-1.docker.io",
        .repository_path = "library/busybox",
        .ref_string = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
    };
    const digest_text = try canonicalReferenceAlloc(std.testing.allocator, digest_ref);
    defer std.testing.allocator.free(digest_text);

    try std.testing.expectEqualStrings(
        "registry-1.docker.io/library/busybox@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        digest_text,
    );

    const tag_ref = auth.AuthReferenceView{
        .registry = "registry-1.docker.io",
        .repository_path = "library/ubuntu",
        .ref_string = "22.04",
    };
    const tag_text = try canonicalReferenceAlloc(std.testing.allocator, tag_ref);
    defer std.testing.allocator.free(tag_text);

    try std.testing.expectEqualStrings("registry-1.docker.io/library/ubuntu:22.04", tag_text);
}

test "buildManifestHttpRequestAlloc: sets method, URL, Authorization, and Accept" {
    const http_request = try buildManifestHttpRequestAlloc(
        std.testing.allocator,
        .{
            .method = .head,
            .operation = .resolve,
            .reference = .{
                .registry = "ghcr.io",
                .repository_path = "owner/repo",
                .ref_string = "v1.2.3",
            },
            .accept = &.{"application/vnd.oci.image.manifest.v1+json"},
        },
        "token-123",
    );
    defer http_request.deinit(std.testing.allocator);

    try std.testing.expectEqual(ManifestRequestMethod.head, http_request.method);
    try std.testing.expectEqualStrings("https://ghcr.io/v2/owner/repo/manifests/v1.2.3", http_request.url);
    try std.testing.expectEqualStrings("Bearer token-123", http_request.authorization.?);
    try std.testing.expectEqual(@as(usize, 1), http_request.accept.len);
}

test "ManifestResponseMetadata.probeClassification: bearer challenge matrix" {
    const cases = [_]ManifestResponseMetadata{
        .{
            .status = .unauthorized,
            .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\""},
        },
        .{
            .status = .unauthorized,
            .www_authenticate_headers = &.{
                "Basic realm=\"example\"",
                "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\"",
            },
        },
    };

    for (cases) |metadata| {
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
}
test "ownedManifestResponseMetadataFromHead: header collection matrix" {
    // Exceeds MAX_WWW_AUTHENTICATE_HEADERS (8).
    var flood_lines: [9][]const u8 = undefined;
    for (&flood_lines, 0..) |*line, index| {
        line.* = try std.fmt.allocPrint(
            std.testing.allocator,
            "WWW-Authenticate: Basic realm=\"bogus-{d}\"",
            .{index},
        );
    }
    defer for (flood_lines) |line| std.testing.allocator.free(line);
    const flood_head = try testHttpHeadFromLines(
        std.testing.allocator,
        "HTTP/1.1 401 Unauthorized",
        &flood_lines,
    );
    defer std.testing.allocator.free(flood_head.bytes);
    try std.testing.expectError(
        error.ResponseHeadersTooLarge,
        ownedManifestResponseMetadataFromHead(std.testing.allocator, flood_head),
    );

    const bearer = "WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/repo:pull\"";
    const stop_after_bearer_head = try testHttpHeadFromLines(
        std.testing.allocator,
        "HTTP/1.1 401 Unauthorized",
        &.{ bearer, "WWW-Authenticate: Bearer realm=\"trailing\",service=\"registry.example.test\"" },
    );
    defer std.testing.allocator.free(stop_after_bearer_head.bytes);
    var stop_after_bearer = try ownedManifestResponseMetadataFromHead(std.testing.allocator, stop_after_bearer_head);
    defer stop_after_bearer.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), stop_after_bearer.www_authenticate_headers.len);

    const mixed_auth_head = try testHttpHeadFromLines(std.testing.allocator, "HTTP/1.1 401 Unauthorized", &.{
        "WWW-Authenticate: Basic realm=\"example\"",
        "WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\"",
    });
    defer std.testing.allocator.free(mixed_auth_head.bytes);
    var mixed_auth = try ownedManifestResponseMetadataFromHead(std.testing.allocator, mixed_auth_head);
    defer mixed_auth.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), mixed_auth.www_authenticate_headers.len);

    const oversized = try std.testing.allocator.alloc(u8, MAX_MANIFEST_HEADER_VALUE_BYTES + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 'a');
    const oversized_line = try std.fmt.allocPrint(
        std.testing.allocator,
        "WWW-Authenticate: Bearer realm=\"{s}\",service=\"registry.example.test\"",
        .{oversized},
    );
    defer std.testing.allocator.free(oversized_line);
    const oversized_head = try testHttpHeadFromLines(std.testing.allocator, "HTTP/1.1 401 Unauthorized", &.{oversized_line});
    defer std.testing.allocator.free(oversized_head.bytes);
    try std.testing.expectError(
        error.ResponseHeadersTooLarge,
        ownedManifestResponseMetadataFromHead(std.testing.allocator, oversized_head),
    );

    const rate_limit_head = try testHttpHeadFromLines(std.testing.allocator, "HTTP/1.1 429 Too Many Requests", &.{
        "Retry-After: 30",
        "Retry-After: 60",
        "Date: Sun, 06 Nov 1994 08:49:37 GMT",
    });
    defer std.testing.allocator.free(rate_limit_head.bytes);
    var rate_limit_owned = try ownedManifestResponseMetadataFromHead(std.testing.allocator, rate_limit_head);
    defer rate_limit_owned.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), rate_limit_owned.resilience_headers.len);
    try std.testing.expectEqualStrings("Retry-After", rate_limit_owned.resilience_headers[0].name);
    try std.testing.expectEqualStrings("30", rate_limit_owned.resilience_headers[0].value);

    const ok_rate_limit_head = try testHttpHeadFromLines(std.testing.allocator, "HTTP/1.1 200 OK", &.{
        "WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\"",
        "Retry-After: 30",
        "RateLimit-Limit: 100;w=21600",
        "RateLimit-Remaining: 99;w=21600",
        "RateLimit-Reset: 1746136938;w=21600",
    });
    defer std.testing.allocator.free(ok_rate_limit_head.bytes);
    var ok_rate_limit = try ownedManifestResponseMetadataFromHead(std.testing.allocator, ok_rate_limit_head);
    defer ok_rate_limit.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), ok_rate_limit.www_authenticate_headers.len);
    try std.testing.expectEqual(@as(usize, 3), ok_rate_limit.resilience_headers.len);

    const ok_no_resilience_head = try testHttpHeadFromLines(std.testing.allocator, "HTTP/1.1 200 OK", &.{
        "Retry-After: 30",
        "Date: Sun, 06 Nov 1994 08:49:37 GMT",
    });
    defer std.testing.allocator.free(ok_no_resilience_head.bytes);
    var ok_no_resilience = try ownedManifestResponseMetadataFromHead(std.testing.allocator, ok_no_resilience_head);
    defer ok_no_resilience.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), ok_no_resilience.resilience_headers.len);

    const forbidden_head = try testHttpHeadFromLines(std.testing.allocator, "HTTP/1.1 403 Forbidden", &.{
        "WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\"",
    });
    defer std.testing.allocator.free(forbidden_head.bytes);
    var forbidden_owned = try ownedManifestResponseMetadataFromHead(std.testing.allocator, forbidden_head);
    defer forbidden_owned.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), forbidden_owned.www_authenticate_headers.len);
    try std.testing.expectError(error.UnsupportedProbeStatus, forbidden_owned.view(.forbidden).probeClassification());

    const unauthorized_head = try testHttpHeadFromLines(std.testing.allocator, "HTTP/1.1 401 Unauthorized", &.{
        "WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\"",
    });
    defer std.testing.allocator.free(unauthorized_head.bytes);
    var unauthorized_owned = try ownedManifestResponseMetadataFromHead(std.testing.allocator, unauthorized_head);
    defer unauthorized_owned.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), unauthorized_owned.www_authenticate_headers.len);
    try std.testing.expect((try unauthorized_owned.view(.unauthorized).probeClassification()) == .auth_required);

    const retryable_head = try testHttpHeadFromLines(std.testing.allocator, "HTTP/1.1 502 Bad Gateway", &.{
        "WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\"",
        "Retry-After: 15",
        "Date: Sun, 06 Nov 1994 08:49:37 GMT",
    });
    defer std.testing.allocator.free(retryable_head.bytes);
    var retryable_owned = try ownedManifestResponseMetadataFromHead(std.testing.allocator, retryable_head);
    defer retryable_owned.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), retryable_owned.www_authenticate_headers.len);
    try std.testing.expectEqual(@as(usize, 2), retryable_owned.resilience_headers.len);
}
test "ownedManifestResponseMetadataFromHead: allocation failure paths" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const head = try testHttpHeadFromLines(allocator, "HTTP/1.1 401 Unauthorized", &.{
                "WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\"",
            });
            defer allocator.free(head.bytes);
            var owned = try ownedManifestResponseMetadataFromHead(allocator, head);
            owned.deinit(allocator);
        }
    }.run, .{});
}
test "ManifestResponseMetadata.cloneAllocHeadSuccess: omits auth and retry headers" {
    const metadata = ManifestResponseMetadata{
        .status = .ok,
        .content_type = "application/vnd.oci.image.manifest.v1+json",
        .docker_content_digest = "sha256:abc",
        .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\""},
        .resilience_headers = &.{.{ .name = "Retry-After", .value = "30" }},
    };

    var cloned = try metadata.cloneAllocHeadSuccess(std.testing.allocator);
    defer cloned.deinitOwned(std.testing.allocator);

    try std.testing.expect(cloned.www_authenticate_headers.len == 0);
    try std.testing.expect(cloned.resilience_headers.len == 0);
    try std.testing.expectEqualStrings("sha256:abc", cloned.docker_content_digest.?);
}
test "resolveErrorFromAuthError: preserves OutOfMemory and maps resolver-visible variants" {
    try std.testing.expectError(
        error.OutOfMemory,
        resolveErrorFromAuthError(error.OutOfMemory, "r", "ref", null, false),
    );

    const timed_out = try resolveErrorFromAuthError(error.HelperTimedOut, "r", "ref", 401, false);
    try std.testing.expectEqualStrings("timeout", @tagName(timed_out));
    try std.testing.expect(!timed_out.timeout.transport_retries_exhausted);

    const auth_failed = try resolveErrorFromAuthError(error.TokenExchangeFailed, "r", "ref", 401, false);
    try std.testing.expectEqualStrings("auth_failed", @tagName(auth_failed));

    const rate_limited = try resolveErrorFromAuthError(error.RateLimited, "r", "ref", 429, false);
    try std.testing.expectEqualStrings("rate_limited", @tagName(rate_limited));
    try std.testing.expect(rate_limited.rate_limited.transport_retries_exhausted);

    const transport_timeout = try resolveErrorFromAuthError(error.Timeout, "r", "ref", null, true);
    try std.testing.expectEqualStrings("timeout", @tagName(transport_timeout));
    try std.testing.expect(transport_timeout.timeout.transport_retries_exhausted);

    const network_error = try resolveErrorFromAuthError(error.UnsupportedProbeStatus, "r", "ref", 500, false);
    try std.testing.expectEqualStrings("network_error", @tagName(network_error));

    const forbidden = try resolveErrorFromAuthError(error.UnsupportedProbeStatus, "r", "ref", 403, false);
    try std.testing.expectEqualStrings("auth_failed", @tagName(forbidden));

    const token_body_too_large = try resolveErrorFromAuthError(error.TokenResponseTooLarge, "r", "ref", null, false);
    try std.testing.expectEqualStrings("response_too_large", @tagName(token_body_too_large));

    const reset = try resolveErrorFromAuthError(error.ConnectionResetByPeer, "r", "ref", null, true);
    try std.testing.expectEqualStrings("network_error", @tagName(reset));
    try std.testing.expect(reset.network_error.transport_retries_exhausted);

    const unreachable_err = try resolveErrorFromAuthError(error.NetworkUnreachable, "r", "ref", null, true);
    try std.testing.expectEqualStrings("network_error", @tagName(unreachable_err));

    const refused = try resolveErrorFromAuthError(error.ConnectionRefused, "r", "ref", null, false);
    try std.testing.expectEqualStrings("network_error", @tagName(refused));
    try std.testing.expect(!refused.network_error.transport_retries_exhausted);

    const unknown_host = try resolveErrorFromAuthError(error.UnknownHostName, "r", "ref", null, true);
    try std.testing.expectEqualStrings("network_error", @tagName(unknown_host));
    try std.testing.expect(unknown_host.network_error.transport_retries_exhausted);

    const invalid_token = try resolveErrorFromAuthError(error.InvalidTokenResponse, "r", "ref", 401, false);
    try std.testing.expectEqualStrings("auth_failed", @tagName(invalid_token));

    const not_implemented = try resolveErrorFromAuthError(error.NotYetImplemented, "r", "ref", null, false);
    try std.testing.expectEqualStrings("auth_failed", @tagName(not_implemented));
}
test "classifyValidateManifestHead: maps all validate HEAD outcome arms" {
    const ref_view = auth.AuthReferenceView{
        .registry = "registry.example.test",
        .repository_path = "owner/repo",
        .ref_string = "latest",
    };

    var valid_outcome: HeadRequestOutcome = .{ .validate_manifest_ok = MediaType.oci_manifest_v1 };
    try std.testing.expectEqual(ValidateManifestHeadDecision.valid, try classifyValidateManifestHead(
        std.testing.allocator,
        ref_view,
        &valid_outcome,
    ));

    var not_found_outcome: HeadRequestOutcome = .not_found;
    try std.testing.expectEqual(ValidateManifestHeadDecision.not_found, try classifyValidateManifestHead(
        std.testing.allocator,
        ref_view,
        &not_found_outcome,
    ));

    const reference = try canonicalReferenceAlloc(std.testing.allocator, ref_view);
    var failure_outcome: HeadRequestOutcome = .{
        .failure = .{ .auth_failed = .{
            .registry = ref_view.registry,
            .reference = reference,
            .http_status = 401,
        } },
    };
    const owned_failure = try classifyValidateManifestHead(std.testing.allocator, ref_view, &failure_outcome);
    try std.testing.expect(owned_failure == .owned_failure);
    try std.testing.expectEqualStrings("auth_failed", @tagName(owned_failure.owned_failure));
    try std.testing.expect(failure_outcome == .not_found);
    owned_failure.owned_failure.deinitOwned(std.testing.allocator);

    const redirect_location = try std.testing.allocator.dupe(u8, "https://cdn.example.test/manifest");
    const redirect_metadata = ManifestResponseMetadata{
        .status = .temporary_redirect,
        .location = redirect_location,
    };
    var redirect_outcome: HeadRequestOutcome = .{ .redirect = redirect_metadata };
    const redirect_decision = try classifyValidateManifestHead(std.testing.allocator, ref_view, &redirect_outcome);
    try std.testing.expect(redirect_decision == .owned_failure);
    try std.testing.expectEqualStrings("network_error", @tagName(redirect_decision.owned_failure));
    redirect_decision.owned_failure.deinitOwned(std.testing.allocator);

    var fallback_outcome: HeadRequestOutcome = .{ .use_get_fallback = ManifestResponseMetadata.headFallbackMetadata(.ok) };
    try std.testing.expectEqual(ValidateManifestHeadDecision.proceed_with_get, try classifyValidateManifestHead(
        std.testing.allocator,
        ref_view,
        &fallback_outcome,
    ));

    const multi_arch_source = ManifestResponseMetadata{
        .status = .ok,
        .content_type = MediaType.oci_index_v1.toString(),
        .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
    };
    var multi_arch_metadata = try multi_arch_source.cloneAllocHeadSuccess(std.testing.allocator);
    defer multi_arch_metadata.releaseOwned(std.testing.allocator);
    var inspect_outcome: HeadRequestOutcome = .{ .success = multi_arch_metadata };
    try std.testing.expectEqual(ValidateManifestHeadDecision.inspect_multi_arch_head, try classifyValidateManifestHead(
        std.testing.allocator,
        ref_view,
        &inspect_outcome,
    ));
}
test "mapChildValidateHeadOutcome: maps all child validate HEAD outcome arms" {
    const ref_view = auth.AuthReferenceView{
        .registry = "registry.example.test",
        .repository_path = "owner/repo",
        .ref_string = "latest",
    };

    var media_type_outcome: HeadRequestOutcome = .{ .validate_manifest_ok = MediaType.oci_manifest_v1 };
    const media_type_mapped = try mapChildValidateHeadOutcome(std.testing.allocator, ref_view, &media_type_outcome);
    try std.testing.expectEqual(MediaType.oci_manifest_v1, media_type_mapped.success_manifest_media_type);

    var not_found_outcome: HeadRequestOutcome = .not_found;
    try std.testing.expectEqual(ChildValidateHeadMappedOutcome.not_found, try mapChildValidateHeadOutcome(
        std.testing.allocator,
        ref_view,
        &not_found_outcome,
    ));

    const reference = try canonicalReferenceAlloc(std.testing.allocator, ref_view);
    var failure_outcome: HeadRequestOutcome = .{
        .failure = .{ .digest_mismatch = .{
            .registry = ref_view.registry,
            .reference = reference,
            .http_status = 412,
        } },
    };
    const failure_mapped = try mapChildValidateHeadOutcome(std.testing.allocator, ref_view, &failure_outcome);
    try std.testing.expect(failure_mapped == .owned_failure);
    try std.testing.expectEqualStrings("digest_mismatch", @tagName(failure_mapped.owned_failure));
    failure_mapped.owned_failure.deinitOwned(std.testing.allocator);

    const child_redirect_location = try std.testing.allocator.dupe(u8, "https://cdn.example.test/manifest");
    var redirect_outcome: HeadRequestOutcome = .{ .redirect = .{
        .status = .temporary_redirect,
        .location = child_redirect_location,
    } };
    const redirect_mapped = try mapChildValidateHeadOutcome(std.testing.allocator, ref_view, &redirect_outcome);
    try std.testing.expect(redirect_mapped == .owned_failure);
    try std.testing.expectEqualStrings("network_error", @tagName(redirect_mapped.owned_failure));
    redirect_mapped.owned_failure.deinitOwned(std.testing.allocator);

    const success_source = ManifestResponseMetadata{
        .status = .ok,
        .content_type = MediaType.oci_index_v1.toString(),
        .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
    };
    const success_metadata = try success_source.cloneAllocHeadSuccess(std.testing.allocator);
    var success_outcome: HeadRequestOutcome = .{ .success = success_metadata };
    const success_mapped = try mapChildValidateHeadOutcome(std.testing.allocator, ref_view, &success_outcome);
    try std.testing.expect(success_mapped == .owned_failure);
    try std.testing.expectEqualStrings("content_type_mismatch", @tagName(success_mapped.owned_failure));
    success_mapped.owned_failure.deinitOwned(std.testing.allocator);

    var fallback_outcome: HeadRequestOutcome = .{ .use_get_fallback = ManifestResponseMetadata.headFallbackMetadata(.ok) };
    const fallback_mapped = try mapChildValidateHeadOutcome(std.testing.allocator, ref_view, &fallback_outcome);
    try std.testing.expect(fallback_mapped == .owned_failure);
    try std.testing.expectEqualStrings("manifest_parse_error", @tagName(fallback_mapped.owned_failure));
    fallback_mapped.owned_failure.deinitOwned(std.testing.allocator);
}
test "liveManifestHttpExchanger: invalid URL maps to TransportFailed" {
    const request = ManifestHttpRequest{
        .method = .head,
        .url = try std.testing.allocator.dupe(u8, "not-a-valid-uri"),
    };
    var client: std.http.Client = undefined;
    try std.testing.expectError(error.TransportFailed, liveManifestHttpExchanger(std.testing.allocator, &client, request));
}

test "liveManifestHttpExchanger: valid URL reaches transport layer" {
    const request = ManifestHttpRequest{
        .method = .head,
        .url = try std.testing.allocator.dupe(u8, "http://127.0.0.1:1/"),
        .accept = &.{},
    };
    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const result = liveManifestHttpExchanger(std.testing.allocator, &client, request);
    try std.testing.expectError(error.ConnectionRefused, result);
}

test "mapLiveManifestTransportError: maps transport and oversize errors without erasure" {
    const cases = [_]struct { err: anyerror, expected: ManifestExchangeError }{
        .{ .err = error.OutOfMemory, .expected = error.OutOfMemory },
        .{ .err = error.BodyTooLarge, .expected = error.ResponseBodyTooLarge },
        .{ .err = error.ConnectionResetByPeer, .expected = error.ConnectionResetByPeer },
        .{ .err = error.Timeout, .expected = error.Timeout },
        .{ .err = error.NetworkUnreachable, .expected = error.NetworkUnreachable },
        .{ .err = error.ConnectionRefused, .expected = error.ConnectionRefused },
        .{ .err = error.UnknownHostName, .expected = error.UnknownHostName },
        .{ .err = error.UnexpectedToken, .expected = error.TransportFailed },
    };
    for (cases) |tc| {
        try std.testing.expectEqual(tc.expected, mapLiveManifestTransportError(tc.err));
    }
}
test "manifestParseError and helpers: error tags match ResolveError variants" {
    const parse_err = manifestParseError("ghcr.io", "ghcr.io/owner/repo:v1", 200);
    const network_err = networkError("ghcr.io", "ghcr.io/owner/repo:v1", 503, false);
    const content_type_err = contentTypeMismatchError("ghcr.io", "ghcr.io/owner/repo:v1", 415);
    const digest_mismatch_err = digestMismatchError("ghcr.io", "ghcr.io/owner/repo:v1", 412);
    const unsupported_algorithm_err = unsupportedAlgorithmError("ghcr.io", "ghcr.io/owner/repo:v1", 400);

    try std.testing.expectEqualStrings("manifest_parse_error", @tagName(parse_err));
    try std.testing.expectEqualStrings("network_error", @tagName(network_err));
    try std.testing.expectEqualStrings("content_type_mismatch", @tagName(content_type_err));
    try std.testing.expectEqualStrings("digest_mismatch", @tagName(digest_mismatch_err));
    try std.testing.expectEqualStrings("unsupported_algorithm", @tagName(unsupported_algorithm_err));
}
test "performManifestGet: exhausted 504 maps to network_error" {
    const MockHarness = struct {
        var attempts: usize = 0;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .gateway_timeout,
            }, "not-a-manifest");
        }
    };

    defer MockHarness.attempts = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 1,
    }, MockHarness.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverParams.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestGet(ctx, &engine, MockHarness.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("network_error", @tagName(failure));
            try std.testing.expectEqual(true, failure.network_error.transport_retries_exhausted);
            try std.testing.expectEqual(@as(usize, 2), MockHarness.attempts);
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
}
test "ManifestResponseMetadata.releaseOwned: clears owned slices in place" {
    const content_type = try std.testing.allocator.dupe(u8, "application/vnd.oci.image.manifest.v1+json");
    const digest = try std.testing.allocator.dupe(u8, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const location = try std.testing.allocator.dupe(u8, "https://registry.example.test/v2/library/alpine/manifests/latest");

    var metadata = ManifestResponseMetadata{
        .status = .ok,
        .content_type = content_type,
        .docker_content_digest = digest,
        .location = location,
    };

    metadata.releaseOwned(std.testing.allocator);

    try std.testing.expect(metadata.content_type == null);
    try std.testing.expect(metadata.docker_content_digest == null);
    try std.testing.expect(metadata.location == null);
    try std.testing.expect(metadata.www_authenticate_headers.len == 0);
    try std.testing.expect(metadata.resilience_headers.len == 0);
}
test "performManifestHead: marks transport_retries_exhausted after rate-limit retries" {
    const MockHarness = struct {
        var attempts: usize = 0;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .too_many_requests,
                .resilience_headers = &.{
                    .{ .name = "Retry-After", .value = "1" },
                },
            }, null);
        }
    };

    defer MockHarness.attempts = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_rate_limit_retries = 1,
    }, MockHarness.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverParams.init(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, MockHarness.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("rate_limited", @tagName(failure));
            try std.testing.expectEqual(true, failure.rate_limited.transport_retries_exhausted);
            try std.testing.expectEqual(@as(usize, 2), MockHarness.attempts);
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
}
test "performManifestGet: preemptive sleep when engine carries exhausted registry rate limit" {
    const MockHarness = struct {
        var attempts: usize = 0;
        var preemptive_sleep_ms: u32 = 0;
        var now_unix_seconds: i64 = 1_700_000_000;

        fn now() i64 {
            return now_unix_seconds;
        }

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = digest,
            }, body);
        }

        fn sleeper(delay_ms: u32) void {
            preemptive_sleep_ms = delay_ms;
        }
    };
    defer {
        MockHarness.attempts = 0;
        MockHarness.preemptive_sleep_ms = 0;
        MockHarness.now_unix_seconds = 1_700_000_000;
    }

    const hooks = resilience.TransportHooks{
        .sleeper = MockHarness.sleeper,
        .clock = .{ .now_unix_seconds = MockHarness.now },
    };

    var client: std.http.Client = undefined;
    var manifest_throttle: resilience.ManifestThrottle = .{
        .prior = .{
            .source = .registry_rate_limit,
            .limit = 100,
            .remaining = 0,
            .reset_unix_seconds = 1_700_000_030,
        },
    };
    var engine = auth.AuthEngine.initWithTokenHttpExchangerAndHooks(std.testing.allocator, .{
        .rate_limit_enabled = true,
    }, MockHarness.tokenExchange, hooks);
    defer engine.deinit();

    const ctx = ResolverParams.initWithTransportHooks(
        std.testing.allocator,
        &client,
        .{ .rate_limit_enabled = true },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
        hooks,
    ).withManifestThrottle(&manifest_throttle);

    var outcome = try performManifestGet(ctx, &engine, MockHarness.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), MockHarness.attempts);
    try std.testing.expectEqual(@as(u32, 30_000), MockHarness.preemptive_sleep_ms);
    switch (outcome) {
        .success => {},
        else => return error.TestUnexpectedResult,
    }
}
test "manifestMediaTypeClassifiers: normalize, accept, and reject matrix" {
    try std.testing.expectEqual(MediaType.oci_manifest_v1, manifestDocumentMediaType(" application/vnd.oci.image.manifest.v1+json; charset=utf-8 ").?);
    try std.testing.expectEqual(@as(?MediaType, null), manifestDocumentMediaType("application/vnd.oci.image.config.v1+json"));
    try std.testing.expectEqual(@as(?MediaType, null), manifestDocumentMediaType("application/vnd.docker.distribution.manifest.v1+prettyjws"));

    try std.testing.expect(acceptsManifestMediaType(&.{" application/vnd.oci.image.manifest.v1+json; q=1.0 "}, .oci_manifest_v1));
    try std.testing.expect(acceptsManifestMediaType(&.{"*/*"}, .docker_manifest_list_v2));
    try std.testing.expect(!acceptsManifestMediaType(&.{"application/vnd.oci.image.index.v1+json"}, .docker_manifest_v2));
}
test "performManifestHead: outcome and validation matrix" {
    const Case = enum {
        validate_manifest_ok,
        validate_digest_mismatch,
        anonymous_success,
        incomplete_metadata_fallback,
        not_found_no_retry,
        transport_failure,
        content_type_unknown,
        content_type_non_manifest,
    };

    const digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65";
    const pinned_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    const HeadMock = struct {
        var case: Case = undefined;
        var attempts: usize = 0;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            return switch (case) {
                .validate_manifest_ok, .validate_digest_mismatch => .{ .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                    .docker_content_digest = if (case == .validate_digest_mismatch)
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    else
                        digest,
                } },
                .anonymous_success => blk: {
                    if (request.authorization != null) return error.TransportFailed;
                    break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                        .status = .ok,
                        .content_type = "application/vnd.oci.image.manifest.v1+json",
                        .docker_content_digest = digest,
                    }, null);
                },
                .incomplete_metadata_fallback => .{ .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                } },
                .not_found_no_retry => .{ .metadata = .{ .status = .not_found } },
                .transport_failure => error.TransportFailed,
                .content_type_unknown => .{ .metadata = .{
                    .status = .ok,
                    .content_type = "application/json",
                    .docker_content_digest = digest,
                } },
                .content_type_non_manifest => .{ .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.config.v1+json",
                    .docker_content_digest = digest,
                } },
            };
        }
    };

    const cases = [_]struct {
        case: Case,
        ref_string: []const u8,
        operation: ResolverOperation,
        config: Config,
        expected_tag: []const u8,
        check_attempts: ?usize,
    }{
        .{ .case = .validate_manifest_ok, .ref_string = "latest", .operation = .validate, .config = .{}, .expected_tag = "validate_manifest_ok", .check_attempts = null },
        .{ .case = .validate_digest_mismatch, .ref_string = pinned_digest, .operation = .validate, .config = .{}, .expected_tag = "digest_mismatch", .check_attempts = null },
        .{ .case = .anonymous_success, .ref_string = "latest", .operation = .resolve, .config = .{}, .expected_tag = "success", .check_attempts = null },
        .{ .case = .incomplete_metadata_fallback, .ref_string = "latest", .operation = .resolve, .config = .{}, .expected_tag = "use_get_fallback", .check_attempts = null },
        .{ .case = .not_found_no_retry, .ref_string = "latest", .operation = .resolve, .config = .{ .max_network_retries = 2 }, .expected_tag = "not_found", .check_attempts = 1 },
        .{ .case = .transport_failure, .ref_string = "latest", .operation = .resolve, .config = .{}, .expected_tag = "network_error", .check_attempts = null },
        .{ .case = .content_type_unknown, .ref_string = "latest", .operation = .resolve, .config = .{}, .expected_tag = "content_type_mismatch", .check_attempts = null },
        .{ .case = .content_type_non_manifest, .ref_string = "latest", .operation = .resolve, .config = .{}, .expected_tag = "content_type_mismatch", .check_attempts = null },
    };

    for (cases) |c| {
        HeadMock.case = c.case;
        HeadMock.attempts = 0;

        var client: std.http.Client = undefined;
        var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, c.config, ResolverTestHarness.refuseTokenExchange);
        defer engine.deinit();

        const ctx = ResolverParams.init(
            std.testing.allocator,
            &client,
            c.config,
            .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = c.ref_string },
            null,
            c.operation,
        );

        var outcome = try performManifestHead(ctx, &engine, HeadMock.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
        defer outcome.deinit(std.testing.allocator);

        if (std.mem.eql(u8, c.expected_tag, "validate_manifest_ok")) {
            try std.testing.expectEqual(HeadRequestOutcome{ .validate_manifest_ok = MediaType.oci_manifest_v1 }, outcome);
        } else if (std.mem.eql(u8, c.expected_tag, "success")) {
            switch (outcome) {
                .success => |metadata| {
                    try std.testing.expectEqualStrings("application/vnd.oci.image.manifest.v1+json", metadata.content_type.?);
                    try std.testing.expectEqualStrings(digest, metadata.docker_content_digest.?);
                },
                else => return error.TestUnexpectedResult,
            }
        } else if (std.mem.eql(u8, c.expected_tag, "use_get_fallback")) {
            try std.testing.expect(outcome == .use_get_fallback);
        } else if (std.mem.eql(u8, c.expected_tag, "not_found")) {
            try std.testing.expect(outcome == .not_found);
        } else {
            switch (outcome) {
                .failure => |failure| try std.testing.expectEqualStrings(c.expected_tag, @tagName(failure)),
                else => return error.TestUnexpectedResult,
            }
        }

        if (c.check_attempts) |expected| {
            try std.testing.expectEqual(expected, HeadMock.attempts);
        }
    }
}
test "performManifestGet: fixture document parsing matrix" {
    const DocumentKind = enum { oci_manifest, docker_manifest, oci_index, docker_list };

    const FixtureMock = struct {
        var fixture_path: []const u8 = undefined;
        var content_type: []const u8 = undefined;
        var normalize_whitespace: bool = false;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            const body = try fixtureBodyAlloc(allocator, fixture_path, 32 * 1024);
            if (normalize_whitespace) {
                errdefer allocator.free(body);
                const digest = try sha256DigestStringAlloc(allocator, body);
                defer allocator.free(digest);
                const response = try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = content_type,
                    .docker_content_digest = digest,
                }, body);
                allocator.free(body);
                return response;
            }
            return .{
                .metadata = .{ .status = .ok, .content_type = content_type },
                .body = body,
            };
        }
    };

    const cases = [_]struct {
        fixture_path: []const u8,
        content_type: []const u8,
        normalize_whitespace: bool,
        accept: []const []const u8,
        operation: ResolverOperation,
        kind: DocumentKind,
        expected_media_type: MediaType,
    }{
        .{
            .fixture_path = "fixtures/manifests/oci-image-manifest-spec-example.json",
            .content_type = " application/vnd.oci.image.manifest.v1+json; charset=utf-8 ",
            .normalize_whitespace = true,
            .accept = &.{
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            },
            .operation = .get_manifest,
            .kind = .oci_manifest,
            .expected_media_type = .oci_manifest_v1,
        },
        .{
            .fixture_path = "fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json",
            .content_type = "application/vnd.docker.distribution.manifest.v2+json",
            .normalize_whitespace = false,
            .accept = &.{"application/vnd.docker.distribution.manifest.v2+json"},
            .operation = .get_manifest,
            .kind = .docker_manifest,
            .expected_media_type = .docker_manifest_v2,
        },
        .{
            .fixture_path = "fixtures/indexes/oci-image-index-spec-example.json",
            .content_type = "application/vnd.oci.image.index.v1+json",
            .normalize_whitespace = false,
            .accept = &.{"application/vnd.oci.image.index.v1+json"},
            .operation = .resolve,
            .kind = .oci_index,
            .expected_media_type = .oci_index_v1,
        },
        .{
            .fixture_path = "fixtures/indexes/docker-manifest-list-spec-example.json",
            .content_type = "application/vnd.docker.distribution.manifest.list.v2+json",
            .normalize_whitespace = false,
            .accept = &.{"application/vnd.docker.distribution.manifest.list.v2+json"},
            .operation = .resolve,
            .kind = .docker_list,
            .expected_media_type = .docker_manifest_list_v2,
        },
    };

    for (cases) |c| {
        FixtureMock.fixture_path = c.fixture_path;
        FixtureMock.content_type = c.content_type;
        FixtureMock.normalize_whitespace = c.normalize_whitespace;

        var client: std.http.Client = undefined;
        var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, ResolverTestHarness.refuseTokenExchange);
        defer engine.deinit();
        const ctx = ResolverParams.init(
            std.testing.allocator,
            &client,
            Config{},
            ResolverTestHarness.busybox_ref,
            null,
            c.operation,
        );

        var outcome = try performManifestGet(ctx, &engine, FixtureMock.exchange, c.accept);
        defer outcome.deinit(std.testing.allocator);

        switch (outcome) {
            .success => |success| {
                try std.testing.expect(success.backing_body == null);
                try std.testing.expectEqual(c.expected_media_type, success.document.mediaType());
                switch (c.kind) {
                    .oci_manifest => switch (success.document) {
                        .manifest => |parsed| {
                            try std.testing.expectEqual(@as(u8, 2), parsed.value.schema_version);
                            try std.testing.expect(parsed.value.layers.len > 0);
                        },
                        else => return error.TestUnexpectedResult,
                    },
                    .docker_manifest => switch (success.document) {
                        .manifest => |parsed| try std.testing.expect(parsed.value.layers.len > 0),
                        else => return error.TestUnexpectedResult,
                    },
                    .oci_index => switch (success.document) {
                        .oci_index => |parsed| try std.testing.expect(parsed.value.manifests.len > 0),
                        else => return error.TestUnexpectedResult,
                    },
                    .docker_list => switch (success.document) {
                        .docker_manifest_list => |parsed| try std.testing.expect(parsed.value.manifests.len > 0),
                        else => return error.TestUnexpectedResult,
                    },
                }
            },
            else => return error.TestUnexpectedResult,
        }
    }
}
test "performManifestGet: body and content-type failure matrix" {
    const FailureCase = enum {
        missing_body,
        empty_body,
        invalid_json,
        unsupported_content_type,
        body_media_type_disagrees,
    };

    const FailureMock = struct {
        var case: FailureCase = undefined;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return switch (case) {
                .missing_body => .{ .metadata = .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                } },
                .empty_body => blk: {
                    const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/invalid-empty-manifest.json", 1024);
                    errdefer allocator.free(body);
                    const response = try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                        .status = .ok,
                        .content_type = "application/vnd.oci.image.manifest.v1+json",
                    }, body);
                    allocator.free(body);
                    break :blk response;
                },
                .invalid_json => try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                }, "{not-json"),
                .unsupported_content_type => .{
                    .metadata = .{
                        .status = .ok,
                        .content_type = "application/vnd.oci.image.config.v1+json",
                    },
                    .body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024),
                },
                .body_media_type_disagrees => .{
                    .metadata = .{
                        .status = .ok,
                        .content_type = "application/vnd.oci.image.manifest.v1+json",
                    },
                    .body = try fixtureBodyAlloc(allocator, "fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json", 32 * 1024),
                },
            };
        }
    };

    const cases = [_]struct { failure: FailureCase, expected_tag: []const u8 }{
        .{ .failure = .missing_body, .expected_tag = "manifest_parse_error" },
        .{ .failure = .empty_body, .expected_tag = "manifest_parse_error" },
        .{ .failure = .invalid_json, .expected_tag = "manifest_parse_error" },
        .{ .failure = .unsupported_content_type, .expected_tag = "content_type_mismatch" },
        .{ .failure = .body_media_type_disagrees, .expected_tag = "content_type_mismatch" },
    };

    for (cases) |c| {
        FailureMock.case = c.failure;

        var client: std.http.Client = undefined;
        var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, ResolverTestHarness.refuseTokenExchange);
        defer engine.deinit();
        const ctx = ResolverParams.init(
            std.testing.allocator,
            &client,
            Config{},
            ResolverTestHarness.busybox_ref,
            null,
            .resolve,
        );

        var outcome = try performManifestGet(ctx, &engine, FailureMock.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
        defer outcome.deinit(std.testing.allocator);

        switch (outcome) {
            .failure => |failure| try std.testing.expectEqualStrings(c.expected_tag, @tagName(failure)),
            else => return error.TestUnexpectedResult,
        }
    }
}
test "performManifestGet: digest verification matrix" {
    const DigestCase = enum {
        matching_pinned,
        header_mismatch,
        pinned_mismatch,
        unsupported_algorithm,
    };

    const wrong_sha256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const wrong_sha512 = "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    const fixture_body = try fixtureBodyAlloc(std.testing.allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
    defer std.testing.allocator.free(fixture_body);
    const matching_digest = try sha256DigestStringAlloc(std.testing.allocator, fixture_body);
    defer std.testing.allocator.free(matching_digest);

    const DigestMock = struct {
        var case: DigestCase = undefined;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            errdefer allocator.free(body);
            const response = switch (case) {
                .matching_pinned, .pinned_mismatch => try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                }, body),
                .header_mismatch => try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                    .docker_content_digest = wrong_sha256,
                }, body),
                .unsupported_algorithm => try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                    .docker_content_digest = wrong_sha512,
                }, body),
            };
            allocator.free(body);
            return response;
        }
    };

    const cases = [_]struct {
        case: DigestCase,
        ref_string: []const u8,
        expected_tag: []const u8,
    }{
        .{ .case = .matching_pinned, .ref_string = matching_digest, .expected_tag = "success" },
        .{ .case = .header_mismatch, .ref_string = "latest", .expected_tag = "digest_mismatch" },
        .{ .case = .pinned_mismatch, .ref_string = wrong_sha256, .expected_tag = "digest_mismatch" },
        .{ .case = .unsupported_algorithm, .ref_string = "latest", .expected_tag = "unsupported_algorithm" },
    };

    for (cases) |c| {
        DigestMock.case = c.case;

        var client: std.http.Client = undefined;
        var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, ResolverTestHarness.refuseTokenExchange);
        defer engine.deinit();
        const ctx = ResolverParams.init(
            std.testing.allocator,
            &client,
            Config{},
            .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = c.ref_string },
            null,
            .resolve,
        );

        var outcome = try performManifestGet(ctx, &engine, DigestMock.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
        defer outcome.deinit(std.testing.allocator);

        if (std.mem.eql(u8, c.expected_tag, "success")) {
            switch (outcome) {
                .success => |success| try std.testing.expectEqual(MediaType.oci_manifest_v1, success.document.mediaType()),
                else => return error.TestUnexpectedResult,
            }
        } else {
            switch (outcome) {
                .failure => |failure| try std.testing.expectEqualStrings(c.expected_tag, @tagName(failure)),
                else => return error.TestUnexpectedResult,
            }
        }
    }
}
test "performManifestGet: oversize transport maps to response_too_large" {
    const OversizeCase = enum { body, headers };

    const OversizeMock = struct {
        var case: OversizeCase = undefined;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(std.testing.allocator);
            return switch (case) {
                .body => error.ResponseBodyTooLarge,
                .headers => error.ResponseHeadersTooLarge,
            };
        }
    };

    for ([_]OversizeCase{ .body, .headers }) |c| {
        OversizeMock.case = c;

        var client: std.http.Client = undefined;
        var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, ResolverTestHarness.refuseTokenExchange);
        defer engine.deinit();
        const ctx = ResolverParams.init(
            std.testing.allocator,
            &client,
            Config{},
            ResolverTestHarness.busybox_ref,
            null,
            .resolve,
        );

        const outcome = try performManifestGet(ctx, &engine, OversizeMock.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
        switch (outcome) {
            .failure => |failure| {
                defer failure.deinitOwned(std.testing.allocator);
                try std.testing.expectEqualStrings("response_too_large", @tagName(failure));
            },
            else => return error.TestUnexpectedResult,
        }
    }
}
test "performManifestGet: oversize token response maps to auth_failed" {
    const custom_cap: usize = 4096;
    const MockHarness = struct {
        var seen_cap: ?usize = null;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            seen_cap = request.max_response_body_bytes;
            return error.InvalidTokenResponse;
        }

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(std.testing.allocator);
            return .{ .metadata = .{
                .status = .unauthorized,
                .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/repo:pull\""},
            } };
        }
    };

    MockHarness.seen_cap = null;
    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_token_response_bytes = custom_cap,
    }, MockHarness.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverParams.init(
        std.testing.allocator,
        &client,
        Config{ .max_token_response_bytes = custom_cap },
        .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestGet(ctx, &engine, MockHarness.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            defer failure.deinitOwned(std.testing.allocator);
            try std.testing.expectEqualStrings("auth_failed", @tagName(failure));
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(custom_cap, MockHarness.seen_cap.?);
}
test "performManifestHead: validate with platform falls back to GET" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            return test_matrix.refuseTokenExchange(allocator, client, request);
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{
                .status = .ok,
                .content_type = MediaType.oci_index_v1.toString(),
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            } };
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, MockHarness.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverParams.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        .{ .os = "linux", .architecture = "amd64" },
        .validate,
    );

    const outcome = try performManifestHead(ctx, &engine, MockHarness.exchange, &.{
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
    });
    switch (outcome) {
        .use_get_fallback => |metadata| {
            try std.testing.expectEqual(std.http.Status.ok, metadata.status);
            var owned = metadata;
            owned.releaseOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
}
test "performManifestHead: second 401 after cached retry maps to auth_failed" {
    const MockHarness = struct {
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
                2 => .{ .metadata = .{ .status = .unauthorized } },
                3 => .{ .metadata = .{ .status = .unauthorized } },
                else => error.TransportFailed,
            };
        }
    };

    defer {
        MockHarness.manifest_call_count = 0;
        MockHarness.token_call_count = 0;
    }

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, MockHarness.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverParams.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, MockHarness.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("auth_failed", @tagName(failure));
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 3), MockHarness.manifest_call_count);
    try std.testing.expectEqual(@as(usize, 2), MockHarness.token_call_count);
}
test "performManifestHead: allow_cached_auth_retry false skips token refresh" {
    const MockHarness = struct {
        var manifest_call_count: usize = 0;
        var token_call_count: usize = 0;
        const stale_token_body = "{\"access_token\":\"stale-token\",\"expires_in\":3600}";

        fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            token_call_count += 1;
            return .{ .status = .ok, .body = stale_token_body };
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_call_count += 1;

            return switch (manifest_call_count) {
                1 => .{ .metadata = .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/repo:pull\""},
                } },
                2 => .{ .metadata = .{ .status = .unauthorized } },
                else => error.TransportFailed,
            };
        }
    };

    defer {
        MockHarness.manifest_call_count = 0;
        MockHarness.token_call_count = 0;
    }

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, MockHarness.tokenExchange);
    defer engine.deinit();

    const request = ManifestRequest{
        .method = .head,
        .operation = .resolve,
        .reference = .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        .accept = &.{"application/vnd.oci.image.manifest.v1+json"},
        .allow_cached_auth_retry = false,
    };
    const ctx = ResolverParams.init(
        std.testing.allocator,
        &client,
        Config{},
        request.reference,
        null,
        request.operation,
    );

    const exchange_outcome = exchangeManifestRequest(ctx, &engine, MockHarness.exchange, request, null);
    const ok = switch (exchange_outcome) {
        .ok => |value| value,
        .transport_failed => return error.TestUnexpectedResult,
    };
    defer ok.response.deinit(std.testing.allocator);

    const outcome = try classifyHeadResponse(ctx, &engine, MockHarness.exchange, request, ok.response.metadata, true, ok.budget);
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("auth_failed", @tagName(failure));
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_call_count);
    try std.testing.expectEqual(@as(usize, 1), MockHarness.token_call_count);
}
test "performManifestHead/Get: shared transport and classification matrix" {
    const Scenario = enum {
        retry_503_then_success,
        exhausted_429,
        connection_reset_then_success,
        transport_timeout,
        redirect_with_location,
        redirect_without_location,
        auth_challenge_success,
        malformed_auth_header,
        cached_unauthorized_retry,
        accept_media_type_mismatch,
    };

    const bearer_challenge = "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/repo:pull\"";
    const stale_token_body = "{\"access_token\":\"stale-token\",\"expires_in\":3600}";
    const fresh_token_body = "{\"access_token\":\"fresh-token\",\"expires_in\":3600}";
    const matrix_token_body = "{\"access_token\":\"matrix-token\",\"expires_in\":3600}";
    const digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65";

    const scenario_defs = [_]struct {
        scenario: Scenario,
        config: Config,
        expected_tag: []const u8,
        expected_attempts: usize,
        expect_token_calls: ?usize,
    }{
        .{ .scenario = .retry_503_then_success, .config = .{ .max_network_retries = 1 }, .expected_tag = "success", .expected_attempts = 2, .expect_token_calls = null },
        .{ .scenario = .exhausted_429, .config = .{ .max_rate_limit_retries = 0 }, .expected_tag = "rate_limited", .expected_attempts = 1, .expect_token_calls = null },
        .{ .scenario = .connection_reset_then_success, .config = .{ .max_network_retries = 1 }, .expected_tag = "success", .expected_attempts = 2, .expect_token_calls = null },
        .{ .scenario = .transport_timeout, .config = .{ .max_network_retries = 1 }, .expected_tag = "timeout", .expected_attempts = 2, .expect_token_calls = null },
        .{ .scenario = .redirect_with_location, .config = .{}, .expected_tag = "redirect", .expected_attempts = 1, .expect_token_calls = null },
        .{ .scenario = .redirect_without_location, .config = .{}, .expected_tag = "network_error", .expected_attempts = 1, .expect_token_calls = null },
        .{ .scenario = .auth_challenge_success, .config = .{}, .expected_tag = "success", .expected_attempts = 2, .expect_token_calls = null },
        .{ .scenario = .malformed_auth_header, .config = .{}, .expected_tag = "auth_failed", .expected_attempts = 1, .expect_token_calls = null },
        .{ .scenario = .cached_unauthorized_retry, .config = .{}, .expected_tag = "success", .expected_attempts = 3, .expect_token_calls = 2 },
        .{ .scenario = .accept_media_type_mismatch, .config = .{}, .expected_tag = "content_type_mismatch", .expected_attempts = 1, .expect_token_calls = null },
    };

    for (scenario_defs) |def| {
        for ([_]ManifestRequestMethod{ .head, .get }) |method| {
            const MatrixMock = struct {
                var scenario: Scenario = undefined;
                var attempts: usize = 0;
                var manifest_call_count: usize = 0;
                var token_call_count: usize = 0;

                fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
                    defer request.deinit(allocator);
                    token_call_count += 1;
                    return switch (scenario) {
                        .auth_challenge_success => .{ .status = .ok, .body = matrix_token_body },
                        .cached_unauthorized_retry => switch (token_call_count) {
                            1 => .{ .status = .ok, .body = stale_token_body },
                            2 => .{ .status = .ok, .body = fresh_token_body },
                            else => error.TokenExchangeFailed,
                        },
                        else => error.TokenExchangeFailed,
                    };
                }

                fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
                    defer request.deinit(allocator);
                    attempts += 1;
                    manifest_call_count += 1;

                    return switch (scenario) {
                        .retry_503_then_success => blk: {
                            if (attempts == 1) {
                                break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{ .status = .service_unavailable }, null);
                            }
                            if (request.method == .get) {
                                const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
                                defer allocator.free(body);
                                break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                                    .status = .ok,
                                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                                }, body);
                            }
                            break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                                .status = .ok,
                                .content_type = "application/vnd.oci.image.manifest.v1+json",
                                .docker_content_digest = digest,
                            }, null);
                        },
                        .exhausted_429 => ManifestHttpResponse.initOwnedAlloc(allocator, .{
                            .status = .too_many_requests,
                            .resilience_headers = &.{
                                .{ .name = "Retry-After", .value = "1" },
                            },
                        }, null),
                        .connection_reset_then_success => blk: {
                            if (attempts == 1) return error.ConnectionResetByPeer;
                            if (request.method == .get) {
                                const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
                                defer allocator.free(body);
                                break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                                    .status = .ok,
                                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                                }, body);
                            }
                            break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                                .status = .ok,
                                .content_type = "application/vnd.oci.image.manifest.v1+json",
                                .docker_content_digest = digest,
                            }, null);
                        },
                        .transport_timeout => error.Timeout,
                        .redirect_with_location => .{ .metadata = .{
                            .status = .temporary_redirect,
                            .location = "https://cdn.example.test/manifest",
                        } },
                        .redirect_without_location => .{ .metadata = .{ .status = .temporary_redirect } },
                        .auth_challenge_success => blk: {
                            if (manifest_call_count == 1) {
                                if (request.authorization != null) return error.TransportFailed;
                                break :blk .{ .metadata = .{
                                    .status = .unauthorized,
                                    .www_authenticate_headers = &.{bearer_challenge},
                                } };
                            }
                            if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Bearer matrix-token")) {
                                return error.TransportFailed;
                            }
                            if (request.method == .get) {
                                const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
                                defer allocator.free(body);
                                break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                                    .status = .ok,
                                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                                }, body);
                            }
                            break :blk .{ .metadata = .{
                                .status = .ok,
                                .content_type = "application/vnd.oci.image.manifest.v1+json",
                                .docker_content_digest = digest,
                            } };
                        },
                        .malformed_auth_header => .{ .metadata = .{
                            .status = .unauthorized,
                            .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token"},
                        } },
                        .cached_unauthorized_retry => switch (manifest_call_count) {
                            1 => .{ .metadata = .{
                                .status = .unauthorized,
                                .www_authenticate_headers = &.{bearer_challenge},
                            } },
                            2 => .{ .metadata = .{ .status = .unauthorized } },
                            3 => blk: {
                                if (request.authorization == null or !std.mem.eql(u8, request.authorization.?, "Bearer fresh-token")) {
                                    return error.TransportFailed;
                                }
                                if (request.method == .get) {
                                    const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
                                    defer allocator.free(body);
                                    break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                                        .status = .ok,
                                        .content_type = "application/vnd.oci.image.manifest.v1+json",
                                    }, body);
                                }
                                break :blk .{ .metadata = .{
                                    .status = .ok,
                                    .content_type = "application/vnd.oci.image.manifest.v1+json",
                                    .docker_content_digest = digest,
                                } };
                            },
                            else => error.TransportFailed,
                        },
                        .accept_media_type_mismatch => .{ .metadata = .{
                            .status = .ok,
                            .content_type = "application/vnd.docker.distribution.manifest.v2+json",
                            .docker_content_digest = digest,
                        } },
                    };
                }
            };

            MatrixMock.scenario = def.scenario;
            MatrixMock.attempts = 0;
            MatrixMock.manifest_call_count = 0;
            MatrixMock.token_call_count = 0;

            var client: std.http.Client = undefined;
            var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, def.config, MatrixMock.tokenExchange);
            defer engine.deinit();
            const ctx = ResolverParams.init(
                std.testing.allocator,
                &client,
                def.config,
                .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
                null,
                .resolve,
            );

            const accept = &.{"application/vnd.oci.image.manifest.v1+json"};
            if (method == .head) {
                var outcome = try performManifestHead(ctx, &engine, MatrixMock.exchange, accept);
                defer outcome.deinit(std.testing.allocator);
                switch (outcome) {
                    .success => try std.testing.expectEqualStrings("success", def.expected_tag),
                    .redirect => |metadata| {
                        try std.testing.expectEqualStrings("redirect", def.expected_tag);
                        try std.testing.expectEqualStrings("https://cdn.example.test/manifest", metadata.location.?);
                    },
                    .failure => |failure| try std.testing.expectEqualStrings(def.expected_tag, @tagName(failure)),
                    else => return error.TestUnexpectedResult,
                }
            } else {
                var outcome = try performManifestGet(ctx, &engine, MatrixMock.exchange, accept);
                defer outcome.deinit(std.testing.allocator);
                switch (outcome) {
                    .success => try std.testing.expectEqualStrings("success", def.expected_tag),
                    .redirect => |metadata| {
                        try std.testing.expectEqualStrings("redirect", def.expected_tag);
                        try std.testing.expectEqualStrings("https://cdn.example.test/manifest", metadata.location.?);
                    },
                    .failure => |failure| try std.testing.expectEqualStrings(def.expected_tag, @tagName(failure)),
                    else => return error.TestUnexpectedResult,
                }
            }

            try std.testing.expectEqual(def.expected_attempts, MatrixMock.attempts);
            if (def.expect_token_calls) |expected_token_calls| {
                try std.testing.expectEqual(expected_token_calls, MatrixMock.token_call_count);
            }
        }
    }
}
