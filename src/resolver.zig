//! Internal manifest resolver helpers.
//!
//! This module keeps request intent, transport metadata, and error-mapping
//! rules local to the resolver layer so auth and manifest fetch
//! do not collapse into one large implementation.

const std = @import("std");
const auth = @import("auth.zig");
const Config = @import("Config.zig").Config;
const resilience = @import("resilience.zig");
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

/// Internal resolver context built once at the public API boundary.
///
/// `config` must match the `Config` snapshot passed to `AuthEngine` on the same
/// resolve/validate/get call so transport retry budgets stay aligned across
/// manifest and token traffic.
pub const ResolverContext = struct {
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    config: Config,
    reference: auth.AuthReferenceView,
    platform: ?Platform,
    operation: ResolverOperation,
    transport_hooks: resilience.TransportHooks = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        config: Config,
        reference: auth.AuthReferenceView,
        platform: ?Platform,
        operation: ResolverOperation,
    ) ResolverContext {
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
    ) ResolverContext {
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
    ) ResolverContext {
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
};

/// Manifest request shape for resolver transport operations.
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
pub const ManifestHttpRequest = struct {
    method: ManifestRequestMethod,
    url: []u8,
    authorization: ?[]u8 = null,
    accept: []const []const u8 = &.{},

    pub fn deinit(self: ManifestHttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        if (self.authorization) |authorization| {
            std.crypto.secureZero(u8, authorization);
            allocator.free(authorization);
        }
    }
};

/// Concrete HTTP response shape for the resolver transport seam.
///
/// GET responses may carry an owned body buffer. Callers must release it with
/// `deinit()` after parsing or classification is complete.
pub const ManifestHttpResponse = struct {
    metadata: ManifestResponseMetadata,
    owned_metadata: ?OwnedManifestResponseMetadata = null,
    body: ?[]u8 = null,

    pub fn deinit(self: ManifestHttpResponse, allocator: std.mem.Allocator) void {
        if (self.owned_metadata) |owned_metadata| owned_metadata.deinit(allocator);
        if (self.body) |body| allocator.free(body);
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
    TransportFailed,
    ConnectionResetByPeer,
    Timeout,
    NetworkUnreachable,
    ConnectionRefused,
    UnknownHostName,
};

/// Exchanges a resolver HTTP request for response metadata.
///
/// The exchanger owns request teardown and must call `request.deinit(allocator)`
/// on every return path, including errors. The resolver does not deinit built
/// requests when the exchanger returns an error.
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

        return .{
            .status = self.status,
            .content_type = if (self.content_type) |content_type|
                try allocator.dupe(u8, content_type)
            else
                null,
            .docker_content_digest = if (self.docker_content_digest) |digest|
                try allocator.dupe(u8, digest)
            else
                null,
            .location = if (self.location) |location|
                try allocator.dupe(u8, location)
            else
                null,
            .www_authenticate_headers = try duplicateHeaderSlicesAlloc(allocator, self.www_authenticate_headers),
            .resilience_headers = owned_resilience_headers,
        };
    }

    pub fn deinitOwned(self: ManifestResponseMetadata, allocator: std.mem.Allocator) void {
        if (self.content_type) |content_type| allocator.free(content_type);
        if (self.docker_content_digest) |digest| allocator.free(digest);
        if (self.location) |location| allocator.free(location);
        freeHeaderSlices(allocator, self.www_authenticate_headers);
        if (self.resilience_headers.len != 0) {
            resilience.deinitOwnedHttpHeaders(allocator, @constCast(self.resilience_headers));
        }
    }
};

pub const OwnedManifestResponseMetadata = struct {
    content_type: ?[]u8 = null,
    docker_content_digest: ?[]u8 = null,
    location: ?[]u8 = null,
    www_authenticate_headers: []const []const u8 = &.{},
    resilience_headers: []resilience.HttpHeader = &.{},

    pub fn initAlloc(allocator: std.mem.Allocator, metadata: ManifestResponseMetadata) !OwnedManifestResponseMetadata {
        return .{
            .content_type = if (metadata.content_type) |content_type|
                try allocator.dupe(u8, content_type)
            else
                null,
            .docker_content_digest = if (metadata.docker_content_digest) |digest|
                try allocator.dupe(u8, digest)
            else
                null,
            .location = if (metadata.location) |location|
                try allocator.dupe(u8, location)
            else
                null,
            .www_authenticate_headers = try duplicateHeaderSlicesAlloc(allocator, metadata.www_authenticate_headers),
            .resilience_headers = try resilience.duplicateHttpHeadersAlloc(allocator, metadata.resilience_headers),
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

/// Parsed manifest document owned by a JSON arena, or a resolve-depth media type tag.
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

/// Success payload for the internal GET path.
pub const ManifestGetSuccess = struct {
    request: ManifestRequest,
    resolved_digest: Digest,
    resolved_digest_raw: []u8,
    document: ParsedManifestDocument,

    pub fn deinit(self: *ManifestGetSuccess, allocator: std.mem.Allocator) void {
        allocator.free(self.resolved_digest_raw);
        self.document.deinit();
    }
};

/// Resolver-visible outcome for the GET path.
pub const GetRequestOutcome = union(enum) {
    success: ManifestGetSuccess,
    not_found,
    redirect: ManifestResponseMetadata,
    failure: ResolveError,

    pub fn deinit(self: *GetRequestOutcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |*success| success.deinit(allocator),
            .redirect => |metadata| metadata.deinitOwned(allocator),
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

    pub fn deinit(self: *HeadRequestOutcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |metadata| metadata.deinitOwned(allocator),
            .use_get_fallback => |metadata| metadata.deinitOwned(allocator),
            .redirect => |metadata| metadata.deinitOwned(allocator),
            else => {},
        }
    }
};

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

/// Live HTTP exchanger for manifest HEAD and GET requests.
pub fn liveManifestHttpExchanger(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: ManifestHttpRequest,
) ManifestExchangeError!ManifestHttpResponse {
    defer request.deinit(allocator);
    const accept_headers = try buildAcceptHeadersAlloc(allocator, request.accept);
    defer allocator.free(accept_headers);

    const redirect_hop_limit: u8 = 2;
    var current_url = request.url;
    var current_authorization = request.authorization;
    var owned_redirect_url: ?[]u8 = null;
    defer if (owned_redirect_url) |url| allocator.free(url);

    var redirect_hops_remaining: u8 = redirect_hop_limit;
    while (true) {
        const uri = std.Uri.parse(current_url) catch return error.TransportFailed;

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
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ConnectionResetByPeer,
            error.Timeout,
            error.NetworkUnreachable,
            error.ConnectionRefused,
            error.UnknownHostName,
            => return err,
            else => return error.TransportFailed,
        };
        defer http_request.deinit();

        http_request.sendBodiless() catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ConnectionResetByPeer,
            error.Timeout,
            error.NetworkUnreachable,
            error.ConnectionRefused,
            error.UnknownHostName,
            => return err,
            else => return error.TransportFailed,
        };

        var redirect_buffer: [8 * 1024]u8 = undefined;
        var response = http_request.receiveHead(&redirect_buffer) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ConnectionResetByPeer,
            error.Timeout,
            error.NetworkUnreachable,
            error.ConnectionRefused,
            error.UnknownHostName,
            => return err,
            else => return error.TransportFailed,
        };

        if (isRedirectStatus(response.head.status) and response.head.location != null and redirect_hops_remaining > 0) {
            redirect_hops_remaining -= 1;

            const next_url = try resolveRedirectUrlAlloc(allocator, current_url, uri, response.head.location.?);
            errdefer allocator.free(next_url);

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
            response.reader(&.{}).allocRemaining(allocator, .unlimited) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.ConnectionResetByPeer,
                error.Timeout,
                error.NetworkUnreachable,
                error.ConnectionRefused,
                error.UnknownHostName,
                => return err,
                else => return error.TransportFailed,
            }
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

fn resolveRedirectUrlAlloc(
    allocator: std.mem.Allocator,
    base_url: []const u8,
    base_uri: std.Uri,
    location: []const u8,
) ManifestExchangeError![]u8 {
    var buffer = try allocator.alloc(u8, base_url.len + location.len + 16);
    defer allocator.free(buffer);

    @memcpy(buffer[0..location.len], location);
    var aux_buf = buffer;
    const resolved = std.Uri.resolveInPlace(base_uri, location.len, &aux_buf) catch |err| switch (err) {
        error.NoSpaceLeft => return error.OutOfMemory,
        else => return error.TransportFailed,
    };
    return std.fmt.allocPrint(allocator, "{f}", .{std.Uri.fmt(&resolved, .all)}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
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

test "resolveRedirectUrlAlloc resolves relative redirect against manifest URL" {
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

test "shouldKeepAuthorizationOnRedirect only keeps same-origin authorization" {
    const base_uri = try std.Uri.parse("https://registry-1.docker.io/v2/library/ubuntu/manifests/22.04");

    try std.testing.expect(try shouldKeepAuthorizationOnRedirect(
        base_uri,
        "https://registry-1.docker.io/v2/library/ubuntu/manifests/22.04",
    ));
    try std.testing.expect(try shouldKeepAuthorizationOnRedirect(
        base_uri,
        "https://registry-1.docker.io:443/v2/library/ubuntu/manifests/22.04",
    ));
    try std.testing.expect(!(try shouldKeepAuthorizationOnRedirect(
        base_uri,
        "https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/abc/data",
    )));
    try std.testing.expect(!(try shouldKeepAuthorizationOnRedirect(
        base_uri,
        "http://registry-1.docker.io/v2/library/ubuntu/manifests/22.04",
    )));
}

test "shouldKeepAuthorizationOnRedirect rejects subdomain redirects" {
    const base_uri = try std.Uri.parse("https://registry.example.test/v2/owner/repo/manifests/latest");

    try std.testing.expect(!(try shouldKeepAuthorizationOnRedirect(
        base_uri,
        "https://cdn.registry.example.test/v2/owner/repo/manifests/latest",
    )));
}

test "shouldKeepAuthorizationOnRedirect rejects port changes" {
    const base_uri = try std.Uri.parse("https://registry.example.test/v2/owner/repo/manifests/latest");

    try std.testing.expect(!(try shouldKeepAuthorizationOnRedirect(
        base_uri,
        "https://registry.example.test:8443/v2/owner/repo/manifests/latest",
    )));
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

fn ownedManifestResponseMetadataFromHead(
    allocator: std.mem.Allocator,
    head: std.http.Client.Response.Head,
) error{OutOfMemory}!OwnedManifestResponseMetadata {
    var www_authenticate_headers = std.ArrayList([]const u8).empty;
    errdefer {
        for (www_authenticate_headers.items) |header| allocator.free(header);
        www_authenticate_headers.deinit(allocator);
    }

    var resilience_headers = std.ArrayList(resilience.HttpHeader).empty;
    errdefer {
        resilience.deinitOwnedHttpHeaders(allocator, resilience_headers.items);
        resilience_headers.deinit(allocator);
    }

    const content_type = if (head.content_type) |content_type|
        try allocator.dupe(u8, content_type)
    else
        null;
    errdefer if (content_type) |value| allocator.free(value);

    const location = if (head.location) |location|
        try allocator.dupe(u8, location)
    else
        null;
    errdefer if (location) |value| allocator.free(value);

    var docker_content_digest: ?[]u8 = null;
    errdefer if (docker_content_digest) |value| allocator.free(value);

    var header_it = head.iterateHeaders();
    while (header_it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "docker-content-digest")) {
            if (docker_content_digest == null) {
                docker_content_digest = try allocator.dupe(u8, header.value);
            }
            continue;
        }

        if (std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) {
            try www_authenticate_headers.append(allocator, try allocator.dupe(u8, header.value));
            continue;
        }

        if (resilience.isTrackedResilienceHeaderName(header.name)) {
            try resilience_headers.append(allocator, .{
                .name = try allocator.dupe(u8, header.name),
                .value = try allocator.dupe(u8, header.value),
            });
        }
    }

    return .{
        .content_type = content_type,
        .docker_content_digest = docker_content_digest,
        .location = location,
        .www_authenticate_headers = try www_authenticate_headers.toOwnedSlice(allocator),
        .resilience_headers = try resilience_headers.toOwnedSlice(allocator),
    };
}

fn resolveErrorFromAuthError(
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
        error.Timeout => .{ .timeout = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
        } },
        error.UnsupportedProbeStatus => .{ .network_error = .{
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
        } },
        else => .{ .auth_failed = .{
            .registry = registry,
            .reference = reference,
            .http_status = http_status,
        } },
    };
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
    ctx: ResolverContext,
    err: ManifestExchangeError,
    budget: resilience.RetryBudget,
) error{OutOfMemory}!Outcome {
    const transport_retries_exhausted = budget.networkRetriesExhausted();
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
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

/// Execute the internal HEAD path through a mockable transport seam.
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

/// Execute the internal GET path through the resolver transport seam.
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

    const exchange_outcome = exchangeManifestRequest(ctx, engine, exchanger, request, null);
    switch (exchange_outcome) {
        .ok => |ok| return classifyGetResponse(ctx, engine, exchanger, request, ok.response, true, ok.budget),
        .transport_failed => |failure| {
            return mapExhaustedManifestTransportError(GetRequestOutcome, ctx, failure.err, failure.budget);
        },
    }
}

const ManifestExchangeLoopContext = struct {
    resolver_ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    bearer_token: ?[]const u8,
    cached_url: ?[]u8 = null,
    exchange_attempt: usize = 0,
};

fn exchangeManifestRequestOnce(
    loop_ctx: *ManifestExchangeLoopContext,
    exchanger: ManifestHttpExchanger,
) ManifestExchangeError!ManifestHttpResponse {
    const allocator = loop_ctx.resolver_ctx.allocator;
    loop_ctx.exchange_attempt += 1;

    const url = if (loop_ctx.cached_url) |cached|
        try allocator.dupe(u8, cached)
    else
        try loop_ctx.request.uriAlloc(allocator);

    if (loop_ctx.cached_url == null and loop_ctx.exchange_attempt > 1) {
        loop_ctx.cached_url = try allocator.dupe(u8, url);
    }

    const authorization = if (loop_ctx.bearer_token) |token|
        try std.fmt.allocPrint(allocator, "Bearer {s}", .{token})
    else
        null;

    const http_request = ManifestHttpRequest{
        .method = loop_ctx.request.method,
        .url = url,
        .authorization = authorization,
        .accept = loop_ctx.request.accept,
    };
    return exchanger(allocator, loop_ctx.resolver_ctx.client, http_request);
}

fn exchangeManifestRequest(
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    bearer_token: ?[]const u8,
) resilience.HttpRetryLoopResult(ManifestHttpResponse, ManifestExchangeError) {
    var policy = resilience.retryPolicyFromConfig(ctx.config, ctx.transport_hooks);

    var loop_ctx = ManifestExchangeLoopContext{
        .resolver_ctx = ctx,
        .engine = engine,
        .exchanger = exchanger,
        .request = request,
        .bearer_token = bearer_token,
    };
    defer if (loop_ctx.cached_url) |cached_url| ctx.allocator.free(cached_url);

    const hooks = resilience.HttpRetryLoopHooks{
        .before_first_attempt = beforeManifestExchangeAttempt,
        .after_successful_exchange = afterManifestExchangeAttempt,
    };

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
    const loop_ctx: *const ManifestExchangeLoopContext = @ptrCast(@alignCast(ctx_ptr));
    loop_ctx.engine.manifest_rate_limit_state.sleepBeforeManifestRequestIfNeeded(
        loop_ctx.resolver_ctx.config,
        loop_ctx.resolver_ctx.client,
        loop_ctx.resolver_ctx.transport_hooks,
    );
}

fn afterManifestExchangeAttempt(ctx_ptr: *anyopaque, _: std.http.Status, headers: []const resilience.HttpHeader) void {
    const loop_ctx: *const ManifestExchangeLoopContext = @ptrCast(@alignCast(ctx_ptr));
    loop_ctx.engine.manifest_rate_limit_state.recordManifestResponseHeaders(headers);
}

fn manifestExchangeOnceOpaque(ctx_ptr: *anyopaque) ManifestExchangeError!ManifestHttpResponse {
    const loop_ctx: *ManifestExchangeLoopContext = @ptrCast(@alignCast(ctx_ptr));
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
    ctx: ResolverContext,
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
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
    allow_auth: bool,
    retry_budget: resilience.RetryBudget,
) error{OutOfMemory}!HeadRequestOutcome {
    if (isRedirectStatus(metadata.status)) {
        if (metadata.location != null) return .{ .redirect = try metadata.cloneAlloc(ctx.allocator) };
        return mappedRetryFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), networkError, retry_budget.networkRetriesExhausted());
    }

    if (try mapRetryableManifestStatusFailure(HeadRequestOutcome, ctx, metadata.httpStatus(), metadata.status, retry_budget)) |failure| {
        return failure;
    }

    if (metadata.status == .unauthorized and !allow_auth) {
        return authFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus());
    }

    const classification = metadata.probeClassification() catch |err| {
        return mappedAuthFailureOutcome(HeadRequestOutcome, ctx, err, metadata.httpStatus());
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
    ctx: ResolverContext,
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
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    response: ManifestHttpResponse,
    allow_auth: bool,
    retry_budget: resilience.RetryBudget,
) error{OutOfMemory}!GetRequestOutcome {
    defer response.deinit(ctx.allocator);
    const metadata = response.metadata;

    if (isRedirectStatus(metadata.status)) {
        if (metadata.location != null) return .{ .redirect = try metadata.cloneAlloc(ctx.allocator) };
        return mappedRetryFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), networkError, retry_budget.networkRetriesExhausted());
    }

    if (try mapRetryableManifestStatusFailure(GetRequestOutcome, ctx, metadata.httpStatus(), metadata.status, retry_budget)) |failure| {
        return failure;
    }

    if (metadata.status == .unauthorized and !allow_auth) {
        return authFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus());
    }

    const classification = metadata.probeClassification() catch |err| {
        return mappedAuthFailureOutcome(GetRequestOutcome, ctx, err, metadata.httpStatus());
    };

    return switch (classification) {
        .ok => classifyUsableGetResponse(ctx, request, metadata, response.body),
        .not_found => .not_found,
        .auth_required => |challenge| if (allow_auth)
            authenticateGetRequest(ctx, engine, exchanger, request, challenge)
        else
            authFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus()),
    };
}

fn authenticateGetRequest(
    ctx: ResolverContext,
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
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    challenge: auth.AuthChallenge,
    comptime classify_authenticated_response_fn: fn (ResolverContext, *auth.AuthEngine, ManifestHttpExchanger, ManifestRequest, ManifestHttpResponse, resilience.RetryBudget) error{OutOfMemory}!Outcome,
) error{OutOfMemory}!Outcome {
    const unauthorized_status = @intFromEnum(std.http.Status.unauthorized);
    const bearer_challenge = switch (challenge) {
        .bearer => |bearer| bearer,
        else => return authFailureOutcome(Outcome, ctx, unauthorized_status),
    };

    const auth_request = auth.AuthenticateRequest.init(ctx.reference.registry, bearer_challenge) catch |err| {
        return mappedAuthFailureOutcome(Outcome, ctx, err, unauthorized_status);
    };

    var token_response = (engine.authenticate(ctx.client, auth_request) catch |err| {
        return mappedAuthFailureOutcome(Outcome, ctx, err, unauthorized_status);
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
        return mappedAuthFailureOutcome(Outcome, ctx, err, unauthorized_status);
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
    ctx: ResolverContext,
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
    ctx: ResolverContext,
    engine: *auth.AuthEngine,
    exchanger: ManifestHttpExchanger,
    request: ManifestRequest,
    response: ManifestHttpResponse,
    retry_budget: resilience.RetryBudget,
) error{OutOfMemory}!GetRequestOutcome {
    return classifyGetResponse(ctx, engine, exchanger, request, response, false, retry_budget);
}

fn classifyUsableHeadMetadata(
    ctx: ResolverContext,
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
) error{OutOfMemory}!HeadRequestOutcome {
    if (metadata.docker_content_digest == null) return .{ .use_get_fallback = try metadata.cloneAlloc(ctx.allocator) };
    if (Digest.parse(metadata.docker_content_digest.?)) |_| {} else |_| {
        return .{ .use_get_fallback = try metadata.cloneAlloc(ctx.allocator) };
    }

    const content_type = metadata.content_type orelse return .{ .use_get_fallback = try metadata.cloneAlloc(ctx.allocator) };
    const media_type = manifestDocumentMediaType(content_type) orelse {
        return mappedFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    };
    if (!acceptsManifestMediaType(request.accept, media_type)) {
        return mappedFailureOutcome(HeadRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    }

    return .{ .success = try metadata.cloneAlloc(ctx.allocator) };
}

fn classifyUsableGetResponse(
    ctx: ResolverContext,
    request: ManifestRequest,
    metadata: ManifestResponseMetadata,
    body: ?[]u8,
) error{OutOfMemory}!GetRequestOutcome {
    const content_type = metadata.content_type orelse {
        return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    };
    const media_type = manifestDocumentMediaType(content_type) orelse {
        return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    };
    if (!acceptsManifestMediaType(request.accept, media_type)) {
        return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), contentTypeMismatchError);
    }
    const response_body = body orelse return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), manifestParseError);
    if (response_body.len == 0) return mappedFailureOutcome(GetRequestOutcome, ctx, metadata.httpStatus(), manifestParseError);

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

    keep_document = true;
    const owned_digest_raw = resolved_digest_raw.?;
    resolved_digest_raw = null;

    return .{ .success = .{
        .request = request,
        .resolved_digest = resolved_digest.digest,
        .resolved_digest_raw = owned_digest_raw,
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
    ctx: ResolverContext,
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

    const body_digest_raw = try std.fmt.allocPrint(ctx.allocator, "sha256:{s}", .{digest_hex[0..]});
    errdefer ctx.allocator.free(body_digest_raw);

    return .{
        .digest = .{
            .algorithm = .sha256,
            .hex = body_digest_raw["sha256:".len..],
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

fn sha256DigestStringAlloc(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const digest_hex = bodySha256DigestHex(body);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{digest_hex[0..]});
}

fn failureOutcome(comptime Outcome: type, failure: ResolveError) Outcome {
    return .{ .failure = failure };
}

fn mappedFailureOutcome(
    comptime Outcome: type,
    ctx: ResolverContext,
    http_status: ?u16,
    comptime failure_factory: *const fn ([]const u8, []const u8, ?u16) ResolveError,
) error{OutOfMemory}!Outcome {
    const reference = try canonicalReferenceAlloc(ctx.allocator, ctx.reference);
    return failureOutcome(Outcome, failure_factory(ctx.reference.registry, reference, http_status));
}

fn mappedRetryFailureOutcome(
    comptime Outcome: type,
    ctx: ResolverContext,
    http_status: ?u16,
    comptime failure_factory: *const fn ([]const u8, []const u8, ?u16, bool) ResolveError,
    transport_retries_exhausted: bool,
) error{OutOfMemory}!Outcome {
    const reference = try canonicalReferenceAlloc(ctx.allocator, ctx.reference);
    return failureOutcome(Outcome, failure_factory(ctx.reference.registry, reference, http_status, transport_retries_exhausted));
}

fn authFailureOutcome(
    comptime Outcome: type,
    ctx: ResolverContext,
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
    ctx: ResolverContext,
    err: auth.AuthError,
    http_status: ?u16,
) error{OutOfMemory}!Outcome {
    const reference = try canonicalReferenceAlloc(ctx.allocator, ctx.reference);
    return failureOutcome(Outcome, try resolveErrorFromAuthError(err, ctx.reference.registry, reference, http_status));
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

test "ManifestResponseMetadata probeClassification selects bearer from repeated headers" {
    const metadata = ManifestResponseMetadata{
        .status = .unauthorized,
        .www_authenticate_headers = &.{
            "Basic realm=\"example\"",
            "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\"",
        },
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

test "resolveErrorFromAuthError preserves OutOfMemory and maps resolver-visible variants" {
    try std.testing.expectError(
        error.OutOfMemory,
        resolveErrorFromAuthError(error.OutOfMemory, "r", "ref", null),
    );

    const timed_out = try resolveErrorFromAuthError(error.HelperTimedOut, "r", "ref", 401);
    try std.testing.expectEqualStrings("timeout", @tagName(timed_out));

    const auth_failed = try resolveErrorFromAuthError(error.TokenExchangeFailed, "r", "ref", 401);
    try std.testing.expectEqualStrings("auth_failed", @tagName(auth_failed));

    const transport_timeout = try resolveErrorFromAuthError(error.Timeout, "r", "ref", null);
    try std.testing.expectEqualStrings("timeout", @tagName(transport_timeout));

    const network_error = try resolveErrorFromAuthError(error.UnsupportedProbeStatus, "r", "ref", 500);
    try std.testing.expectEqualStrings("network_error", @tagName(network_error));

    const reset = try resolveErrorFromAuthError(error.ConnectionResetByPeer, "r", "ref", null);
    try std.testing.expectEqualStrings("network_error", @tagName(reset));
}

test "resolver error helpers keep registry, reference, and status" {
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

test "performManifestHead retries transient 503 then succeeds" {
    const State = struct {
        var attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            if (attempts == 1) {
                return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .service_unavailable,
                }, null);
            }

            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 1,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestHead(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.attempts);
    switch (outcome) {
        .success => |metadata| {
            try std.testing.expectEqualStrings("application/vnd.oci.image.manifest.v1+json", metadata.content_type.?);
            try std.testing.expectEqualStrings("sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65", metadata.docker_content_digest.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead retry path leaves no residual allocations under DebugAllocator" {
    const State = struct {
        var attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            if (@rem(attempts, 2) == 1) {
                return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .service_unavailable,
                }, null);
            }

            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            }, null);
        }
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(allocator, .{
        .max_network_retries = 1,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        allocator,
        &client,
        .{ .max_network_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    for (0..32) |_| {
        var outcome = try performManifestHead(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
        defer outcome.deinit(allocator);

        switch (outcome) {
            .success => {},
            else => return error.TestUnexpectedResult,
        }
    }
}

test "performManifestHead maps exhausted 429 to rate_limited" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .too_many_requests,
                .resilience_headers = &.{
                    .{ .name = "Retry-After", .value = "1" },
                },
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_rate_limit_retries = 0,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 0 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("rate_limited", @tagName(failure));
            try std.testing.expectEqual(false, failure.rate_limited.transport_retries_exhausted);
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead marks transport_retries_exhausted after rate-limit retries" {
    const State = struct {
        var attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
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

    defer State.attempts = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_rate_limit_retries = 1,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("rate_limited", @tagName(failure));
            try std.testing.expectEqual(true, failure.rate_limited.transport_retries_exhausted);
            try std.testing.expectEqual(@as(usize, 2), State.attempts);
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead maps exhausted transport timeout to timeout failure" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return error.Timeout;
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 0,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 0 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("timeout", @tagName(failure));
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet preemptive sleep before request when engine carries exhausted registry rate limit" {
    const State = struct {
        var attempts: usize = 0;
        var preemptive_sleep_ms: u32 = 0;
        var now_unix_seconds: i64 = 1_700_000_000;

        fn now() i64 {
            return now_unix_seconds;
        }

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
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
        State.attempts = 0;
        State.preemptive_sleep_ms = 0;
        State.now_unix_seconds = 1_700_000_000;
    }

    const hooks = resilience.TransportHooks{
        .sleeper = State.sleeper,
        .clock = .{ .now_unix_seconds = State.now },
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchangerAndHooks(std.testing.allocator, .{
        .rate_limit_enabled = true,
    }, State.tokenExchange, hooks);
    defer engine.deinit();

    engine.manifest_rate_limit_state.prior = .{
        .source = .registry_rate_limit,
        .limit = 100,
        .remaining = 0,
        .reset_unix_seconds = 1_700_000_030,
    };

    const ctx = ResolverContext.initWithTransportHooks(
        std.testing.allocator,
        &client,
        .{ .rate_limit_enabled = true },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
        hooks,
    );

    var outcome = try performManifestGet(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), State.attempts);
    try std.testing.expectEqual(@as(u32, 30_000), State.preemptive_sleep_ms);
    switch (outcome) {
        .success => {},
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead retries connection reset then succeeds" {
    const State = struct {
        var attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            if (attempts == 1) return error.ConnectionResetByPeer;

            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            }, null);
        }
    };

    defer State.attempts = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 1,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestHead(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.attempts);
    switch (outcome) {
        .success => {},
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead does not retry not found" {
    const State = struct {
        var attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .not_found,
            }, null);
        }
    };

    defer State.attempts = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 2,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 2 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .not_found => {
            try std.testing.expectEqual(@as(usize, 1), State.attempts);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead exhausts repeated 429 on rate limit budget" {
    const State = struct {
        var attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
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

    defer State.attempts = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_rate_limit_retries = 1,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestHead(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqual(@as(usize, 2), State.attempts);
            try std.testing.expectEqualStrings("rate_limited", @tagName(failure));
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
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

test "acceptsManifestMediaType matches normalized exact entries and wildcard" {
    try std.testing.expect(acceptsManifestMediaType(&.{" application/vnd.oci.image.manifest.v1+json; q=1.0 "}, .oci_manifest_v1));
    try std.testing.expect(acceptsManifestMediaType(&.{"*/*"}, .docker_manifest_list_v2));
    try std.testing.expect(!acceptsManifestMediaType(&.{"application/vnd.oci.image.index.v1+json"}, .docker_manifest_v2));
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
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            }, null);
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);
    switch (outcome) {
        .success => |metadata| {
            try std.testing.expectEqualStrings("application/vnd.oci.image.manifest.v1+json", metadata.content_type.?);
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(std.testing.allocator);
    switch (outcome) {
        .redirect => |metadata| try std.testing.expectEqualStrings("https://cdn.example.test/manifest", metadata.location.?),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead maps redirect without location into network error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{ .status = .found } };
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(arena.allocator());
    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("network_error", @tagName(err)),
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(std.testing.allocator);
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);
    switch (outcome) {
        .success => {},
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 2), State.manifest_call_count);
}

test "performManifestHead maps malformed authenticate header into auth failure" {
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
                .status = .unauthorized,
                .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token"},
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
        .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(arena.allocator());
    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("auth_failed", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
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
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 2,
        .max_rate_limit_retries = 2,
    }, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 2, .max_rate_limit_retries = 2 },
        .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(arena.allocator());
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(arena.allocator());
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(arena.allocator());
    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("content_type_mismatch", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestHead rejects recognized media type outside Accept list" {
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
                .content_type = "application/vnd.docker.distribution.manifest.v2+json",
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

    var outcome = try performManifestHead(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(arena.allocator());
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
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = " application/vnd.oci.image.manifest.v1+json; charset=utf-8 ",
                .docker_content_digest = digest,
            }, body);
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
        .get_manifest,
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
    defer outcome.deinit(std.testing.allocator);

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
        .get_manifest,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.docker.distribution.manifest.v2+json"});
    defer outcome.deinit(std.testing.allocator);

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
    defer outcome.deinit(std.testing.allocator);

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
    defer outcome.deinit(std.testing.allocator);

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

test "performManifestGet returns redirect outcome for redirect metadata with location" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{
                .status = .temporary_redirect,
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

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(std.testing.allocator);
    switch (outcome) {
        .redirect => |metadata| try std.testing.expectEqualStrings("https://cdn.example.test/manifest", metadata.location.?),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet maps redirect without location into network error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return .{ .metadata = .{ .status = .temporary_redirect } };
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

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(arena.allocator());
    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("network_error", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet maps missing body into manifest parse error" {
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
                .content_type = "application/vnd.oci.image.manifest.v1+json",
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

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(arena.allocator());

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("manifest_parse_error", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet maps empty body into manifest parse error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/invalid-empty-manifest.json", 1024);
            defer allocator.free(body);
            return try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
            }, body);
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
    defer outcome.deinit(arena.allocator());

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("manifest_parse_error", @tagName(err)),
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
    defer outcome.deinit(arena.allocator());

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("content_type_mismatch", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet rejects body whose declared mediaType disagrees with Content-Type" {
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
                .body = try fixtureBodyAlloc(allocator, "fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json", 32 * 1024),
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
    defer outcome.deinit(arena.allocator());

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("content_type_mismatch", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet rejects recognized media type outside Accept list" {
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
                    .content_type = "application/vnd.docker.distribution.manifest.v2+json",
                },
                .body = try fixtureBodyAlloc(allocator, "fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json", 32 * 1024),
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
    defer outcome.deinit(arena.allocator());

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("content_type_mismatch", @tagName(err)),
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
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
            }, body);
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
    defer outcome.deinit(std.testing.allocator);

    switch (outcome) {
        .success => |success| try std.testing.expectEqual(MediaType.oci_manifest_v1, success.document.mediaType()),
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 2), State.manifest_call_count);
}

test "performManifestGet retries transient 503 then succeeds" {
    const State = struct {
        var attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            if (attempts == 1) {
                return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .service_unavailable,
                }, null);
            }

            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
            }, body);
        }
    };

    defer State.attempts = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 1,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.attempts);
    switch (outcome) {
        .success => |success| try std.testing.expectEqual(MediaType.oci_manifest_v1, success.document.mediaType()),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet maps exhausted 429 to rate_limited" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .too_many_requests,
                .resilience_headers = &.{
                    .{ .name = "Retry-After", .value = "1" },
                },
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_rate_limit_retries = 0,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 0 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestGet(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("rate_limited", @tagName(failure));
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet retries connection reset then succeeds" {
    const State = struct {
        var attempts: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            attempts += 1;
            if (attempts == 1) return error.ConnectionResetByPeer;

            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
            }, body);
        }
    };

    defer State.attempts = 0;

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 1,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 1 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), State.attempts);
    switch (outcome) {
        .success => |success| try std.testing.expectEqual(MediaType.oci_manifest_v1, success.document.mediaType()),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet maps exhausted transport timeout to timeout failure" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            return error.Timeout;
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{
        .max_network_retries = 0,
    }, State.tokenExchange);
    defer engine.deinit();

    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 0 },
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = "latest" },
        null,
        .resolve,
    );

    const outcome = try performManifestGet(ctx, &engine, State.manifestExchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    switch (outcome) {
        .failure => |failure| {
            try std.testing.expectEqualStrings("timeout", @tagName(failure));
            failure.deinitOwned(std.testing.allocator);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet maps malformed authenticate header into auth failure" {
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
                .status = .unauthorized,
                .www_authenticate_headers = &.{"Bearer realm=\"https://auth.example.test/token"},
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
        .{ .registry = "registry.example.test", .repository_path = "owner/repo", .ref_string = "latest" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{});
    defer outcome.deinit(arena.allocator());
    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("auth_failed", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet retries once after cached unauthorized response" {
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
                    const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
                    defer allocator.free(body);
                    break :blk try ManifestHttpResponse.initOwnedAlloc(allocator, .{
                        .status = .ok,
                        .content_type = "application/vnd.oci.image.manifest.v1+json",
                    }, body);
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

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);

    switch (outcome) {
        .success => |success| try std.testing.expectEqual(MediaType.oci_manifest_v1, success.document.mediaType()),
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 3), State.manifest_call_count);
    try std.testing.expectEqual(@as(usize, 2), State.token_call_count);
}

test "performManifestGet verifies matching pinned digest reference" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
            }, body);
        }
    };

    const fixture_body = try fixtureBodyAlloc(std.testing.allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
    defer std.testing.allocator.free(fixture_body);
    const pinned_digest = try sha256DigestStringAlloc(std.testing.allocator, fixture_body);
    defer std.testing.allocator.free(pinned_digest);

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(std.testing.allocator, .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        std.testing.allocator,
        &client,
        Config{},
        .{ .registry = "registry-1.docker.io", .repository_path = "library/busybox", .ref_string = pinned_digest },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(std.testing.allocator);

    switch (outcome) {
        .success => |success| try std.testing.expectEqual(MediaType.oci_manifest_v1, success.document.mediaType()),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet rejects mismatched response digest header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }, body);
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
    defer outcome.deinit(arena.allocator());

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("digest_mismatch", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet rejects mismatched pinned digest reference" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
            }, body);
        }
    };

    var client: std.http.Client = undefined;
    var engine = auth.AuthEngine.initWithTokenHttpExchanger(arena.allocator(), .{}, State.tokenExchange);
    defer engine.deinit();
    const ctx = ResolverContext.init(
        arena.allocator(),
        &client,
        Config{},
        .{ .registry = "ghcr.io", .repository_path = "owner/repo", .ref_string = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
        null,
        .resolve,
    );

    var outcome = try performManifestGet(ctx, &engine, State.exchange, &.{"application/vnd.oci.image.manifest.v1+json"});
    defer outcome.deinit(arena.allocator());

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("digest_mismatch", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}

test "performManifestGet rejects unsupported digest algorithm in response header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: auth.TokenHttpRequest) auth.AuthError!auth.TokenExchangeResponse {
            request.deinit(std.testing.allocator);
            return error.TokenExchangeFailed;
        }

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: ManifestHttpRequest) ManifestExchangeError!ManifestHttpResponse {
            defer request.deinit(allocator);
            const body = try fixtureBodyAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024);
            defer allocator.free(body);
            return ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = "application/vnd.oci.image.manifest.v1+json",
                .docker_content_digest = "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }, body);
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
    defer outcome.deinit(arena.allocator());

    switch (outcome) {
        .failure => |err| try std.testing.expectEqualStrings("unsupported_algorithm", @tagName(err)),
        else => return error.TestUnexpectedResult,
    }
}
