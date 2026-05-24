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
const Platform = @import("Platform.zig");
const ResolveError = @import("ResolveError.zig").ResolveError;

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
