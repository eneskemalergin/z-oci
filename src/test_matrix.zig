//! Shared failure-matrix fixtures and mock transport plans for resolver tests.
//!
//! Used by `root.zig` and `workflow_smoke.zig` so scenario wiring stays
//! in one place.
//!
//! Test conventions (Q10): per-test mock structs are named `MockHarness`;
//! scenario tests use AAA spacing (blank lines between arrange, act, assert).

const std = @import("std");
const MediaType = @import("MediaType.zig").MediaType;
const Platform = @import("Platform.zig");
const Config = @import("Config.zig").Config;
const ResolveError = @import("ResolveError.zig").ResolveError;
const auth = @import("auth.zig");
const resolver = @import("resolver.zig");

pub const max_child_manifest_depth: usize = 4;
pub const index_child_digest = "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

const depth_levels: usize = max_child_manifest_depth + 1;

pub const Scenario = enum {
    auth_failed,
    content_type_mismatch,
    depth_limit_exceeded,
    digest_mismatch,
    manifest_parse_error,
    network_error,
    not_found,
    platform_not_found,
    platform_required,
    rate_limited,
    response_too_large,
    timeout,
    unsupported_algorithm,
};

pub const resolve_failure_scenarios = [_]Scenario{
    .auth_failed,
    .content_type_mismatch,
    .depth_limit_exceeded,
    .digest_mismatch,
    .manifest_parse_error,
    .network_error,
    .not_found,
    .platform_not_found,
    .platform_required,
    .rate_limited,
    .response_too_large,
    .timeout,
    .unsupported_algorithm,
};

pub const validate_failure_scenarios = [_]Scenario{
    .auth_failed,
    .content_type_mismatch,
    .manifest_parse_error,
    .network_error,
    .not_found,
    .platform_not_found,
    .platform_required,
    .rate_limited,
    .response_too_large,
    .timeout,
    .unsupported_algorithm,
};

/// Paired with `validate_failure_scenarios`; shared tag-ref plans cannot produce these tags.
pub const validate_failure_scenario_skips = [_]Scenario{
    .digest_mismatch,
    .depth_limit_exceeded,
};

pub const get_manifest_failure_scenarios = [_]Scenario{
    .auth_failed,
    .content_type_mismatch,
    .depth_limit_exceeded,
    .digest_mismatch,
    .manifest_parse_error,
    .network_error,
    .not_found,
    .platform_not_found,
    .platform_required,
    .rate_limited,
    .response_too_large,
    .timeout,
    .unsupported_algorithm,
};

pub const PublicApi = enum { resolve, validate, get_manifest };

pub const C4Surface = enum {
    success,
    resolve_error,
    validate_valid,
    validate_not_found,
    manifest_success,
    public_api_error,
};

pub const C4Entry = struct {
    api: PublicApi,
    surface: C4Surface,
    tier: []const u8,
    owner_test: []const u8,
    scenario: ?Scenario = null,
};

pub const c4_success_entries = [_]C4Entry{
    .{ .api = .resolve, .surface = .success, .tier = "T2", .owner_test = "resolveWithExchangers returns pinned single-arch result for tag reference" },
    .{ .api = .resolve, .surface = .success, .tier = "T2", .owner_test = "resolveWithExchangers resolves multi-arch index to selected child manifest" },
    .{ .api = .resolve, .surface = .success, .tier = "T2", .owner_test = "resolveWithExchangers authenticates on challenge and resolves manifest" },
    .{ .api = .validate, .surface = .validate_valid, .tier = "T2", .owner_test = "validateWithExchangers returns valid from HEAD for single-arch manifest" },
    .{ .api = .validate, .surface = .validate_valid, .tier = "T2", .owner_test = "validateWithExchangers returns valid for selected multi-arch child manifest" },
    .{ .api = .validate, .surface = .validate_valid, .tier = "T3", .owner_test = "workflow smoke: public validate follows selected multi-arch child" },
    .{ .api = .get_manifest, .surface = .manifest_success, .tier = "T2", .owner_test = "getManifestWithExchangers returns parsed single-arch manifest" },
    .{ .api = .get_manifest, .surface = .manifest_success, .tier = "T2", .owner_test = "getManifestWithExchangers resolves nested index to leaf manifest" },
};

pub const c4_public_api_error_entries = [_]C4Entry{
    .{ .api = .resolve, .surface = .public_api_error, .tier = "T3", .owner_test = "workflow smoke: public resolve returns CaBundleFileNotFound for missing ca bundle path" },
    .{ .api = .resolve, .surface = .public_api_error, .tier = "T2", .owner_test = "resolveWithEngine per-resolve arena promotes failures without leaking" },
    .{ .api = .validate, .surface = .public_api_error, .tier = "T2", .owner_test = "validateWithEngine per-resolve arena promotes failures without leaking" },
    .{ .api = .get_manifest, .surface = .public_api_error, .tier = "T2", .owner_test = "getManifestWithEngine per-resolve arena promotes failures without leaking" },
};

pub fn c4ResolveErrorEntries(out: []C4Entry) usize {
    var count: usize = 0;
    for (resolve_failure_scenarios) |scenario| {
        out[count] = .{
            .api = .resolve,
            .surface = .resolve_error,
            .tier = "T2",
            .owner_test = "resolveWithExchangers propagates resolver failure matrix with full context",
            .scenario = scenario,
        };
        count += 1;
    }
    return count;
}

pub fn c4ValidateFailureEntries(out: []C4Entry, offset: usize) usize {
    var count: usize = 0;
    for (validate_failure_scenarios) |scenario| {
        const surface: C4Surface = if (scenario == .not_found) .validate_not_found else .resolve_error;
        out[offset + count] = .{
            .api = .validate,
            .surface = surface,
            .tier = "T2",
            .owner_test = "validateWithExchangers propagates representative failure matrix with full context",
            .scenario = scenario,
        };
        count += 1;
    }
    return count;
}

pub fn c4GetManifestFailureEntries(out: []C4Entry, offset: usize) usize {
    var count: usize = 0;
    for (get_manifest_failure_scenarios) |scenario| {
        out[offset + count] = .{
            .api = .get_manifest,
            .surface = .resolve_error,
            .tier = "T2",
            .owner_test = "getManifestWithExchangers propagates representative failure matrix with full context",
            .scenario = scenario,
        };
        count += 1;
    }
    return count;
}

const BodyKind = enum {
    none,
    malformed_manifest_fixture,
    manifest_fixture,
    index_fixture,
};

const ResponsePlan = struct {
    status: std.http.Status,
    content_type: ?[]const u8 = null,
    docker_content_digest: ?[]const u8 = null,
    body_kind: BodyKind = .none,
    malformed_auth_header: bool = false,
    manifest_exchange_error: ?resolver.ManifestExchangeError = null,
};

pub const Fixtures = struct {
    var index_body: ?[]u8 = null;
    var index_digest: ?[]u8 = null;
    var depth_bodies: [depth_levels][]u8 = undefined;
    var depth_digests: [depth_levels][]u8 = undefined;
    var depth_ready: bool = false;

    pub fn reset(allocator: std.mem.Allocator) void {
        if (index_body) |body| allocator.free(body);
        if (index_digest) |digest| allocator.free(digest);
        index_body = null;
        index_digest = null;
        if (depth_ready) {
            for (depth_bodies) |body| allocator.free(body);
            for (depth_digests) |digest| allocator.free(digest);
            depth_ready = false;
        }
    }

    fn ensureIndex(allocator: std.mem.Allocator) !void {
        if (index_body != null) return;
        index_body = try buildIndexBodyAlloc(
            allocator,
            MediaType.oci_index_v1.toString(),
            MediaType.oci_manifest_v1.toString(),
            index_child_digest,
            "linux",
            "arm64",
        );
        index_digest = try sha256DigestStringAlloc(allocator, index_body.?);
    }

    fn ensureDepthChain(allocator: std.mem.Allocator) !void {
        if (depth_ready) return;
        var next_digest: []const u8 = index_child_digest;
        var reverse_index: usize = depth_bodies.len;
        while (reverse_index > 0) {
            reverse_index -= 1;
            depth_bodies[reverse_index] = try buildIndexBodyAlloc(
                allocator,
                MediaType.oci_index_v1.toString(),
                MediaType.oci_index_v1.toString(),
                next_digest,
                "linux",
                "arm64",
            );
            depth_digests[reverse_index] = try sha256DigestStringAlloc(allocator, depth_bodies[reverse_index]);
            next_digest = depth_digests[reverse_index];
        }
        depth_ready = true;
    }
};

pub fn readFixtureAlloc(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(max_bytes),
    );
}

pub fn sha256DigestStringAlloc(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var digest_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest_bytes, .{});
    const digest_hex = std.fmt.bytesToHex(digest_bytes, .lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{digest_hex[0..]});
}

pub fn buildIndexBodyAlloc(
    allocator: std.mem.Allocator,
    index_media_type: []const u8,
    child_media_type: []const u8,
    child_digest: []const u8,
    os: []const u8,
    architecture: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "schemaVersion": 2,
        \\  "mediaType": "{s}",
        \\  "manifests": [
        \\    {{
        \\      "mediaType": "{s}",
        \\      "digest": "{s}",
        \\      "size": 610,
        \\      "platform": {{
        \\        "os": "{s}",
        \\        "architecture": "{s}"
        \\      }}
        \\    }}
        \\  ]
        \\}}
    ,
        .{ index_media_type, child_media_type, child_digest, os, architecture },
    );
}

pub fn refuseTokenExchange(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    request: auth.TokenHttpRequest,
) auth.AuthError!auth.TokenExchangeResponse {
    request.deinit(allocator);
    return error.TokenExchangeFailed;
}

fn responsePlan(scenario: Scenario) ResponsePlan {
    return switch (scenario) {
        .network_error => .{ .status = .temporary_redirect },
        .auth_failed => .{
            .status = .unauthorized,
            .malformed_auth_header = true,
        },
        .content_type_mismatch => .{
            .status = .ok,
            .content_type = "application/vnd.oci.image.config.v1+json",
            .body_kind = .manifest_fixture,
        },
        .manifest_parse_error => .{
            .status = .ok,
            .content_type = "application/vnd.oci.image.manifest.v1+json",
            .body_kind = .malformed_manifest_fixture,
        },
        .digest_mismatch => .{
            .status = .ok,
            .content_type = "application/vnd.oci.image.manifest.v1+json",
            .docker_content_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .body_kind = .manifest_fixture,
        },
        .unsupported_algorithm => .{
            .status = .ok,
            .content_type = "application/vnd.oci.image.manifest.v1+json",
            .docker_content_digest = "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .body_kind = .manifest_fixture,
        },
        .not_found => .{ .status = .not_found },
        .rate_limited => .{ .status = .too_many_requests },
        .platform_required => .{
            .status = .ok,
            .content_type = MediaType.oci_index_v1.toString(),
            .body_kind = .index_fixture,
        },
        .platform_not_found => .{
            .status = .ok,
            .content_type = MediaType.oci_index_v1.toString(),
            .body_kind = .index_fixture,
        },
        .timeout => .{
            .status = .ok,
            .manifest_exchange_error = error.Timeout,
        },
        .response_too_large => .{
            .status = .ok,
            .manifest_exchange_error = error.ResponseBodyTooLarge,
        },
        .depth_limit_exceeded => .{
            .status = .ok,
            .content_type = MediaType.oci_index_v1.toString(),
            .body_kind = .index_fixture,
        },
    };
}

pub fn scenarioConfig(scenario: Scenario) Config {
    return switch (scenario) {
        .rate_limited => .{ .max_rate_limit_retries = 0 },
        else => .{},
    };
}

pub fn scenarioPlatform(scenario: Scenario) ?Platform {
    return switch (scenario) {
        .platform_not_found => .{ .os = "linux", .architecture = "ppc64" },
        .depth_limit_exceeded => .{ .os = "linux", .architecture = "arm64" },
        else => null,
    };
}

pub fn expectedHttpStatus(scenario: Scenario) ?u16 {
    return switch (scenario) {
        .timeout, .response_too_large, .depth_limit_exceeded, .not_found, .platform_not_found, .platform_required => null,
        else => @intCast(@intFromEnum(responsePlan(scenario).status)),
    };
}

pub fn expectedReference(scenario: Scenario) []const u8 {
    return switch (scenario) {
        .depth_limit_exceeded => "registry-1.docker.io/library/busybox@" ++ index_child_digest,
        else => "registry-1.docker.io/library/busybox:latest",
    };
}

pub fn prepareScenario(scenario: Scenario, allocator: std.mem.Allocator) !void {
    switch (scenario) {
        .platform_required, .platform_not_found => try Fixtures.ensureIndex(allocator),
        .depth_limit_exceeded => try Fixtures.ensureDepthChain(allocator),
        else => {},
    }
}

pub fn manifestExchange(
    scenario: Scenario,
    allocator: std.mem.Allocator,
    request: resolver.ManifestHttpRequest,
) resolver.ManifestExchangeError!resolver.ManifestHttpResponse {
    defer request.deinit(allocator);

    const plan = responsePlan(scenario);
    if (plan.manifest_exchange_error) |exchange_error| return exchange_error;

    if (scenario == .depth_limit_exceeded) {
        if (std.mem.endsWith(u8, request.url, "/manifests/latest")) {
            return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = MediaType.oci_index_v1.toString(),
                .docker_content_digest = Fixtures.depth_digests[0],
            }, Fixtures.depth_bodies[0]);
        }
        for (Fixtures.depth_digests, Fixtures.depth_bodies) |digest, body| {
            if (std.mem.endsWith(u8, request.url, digest)) {
                return resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = MediaType.oci_index_v1.toString(),
                    .docker_content_digest = digest,
                }, body);
            }
        }
        return error.TransportFailed;
    }

    const headers: []const []const u8 = if (plan.malformed_auth_header)
        &.{"Bearer realm=\"https://auth.example.test/token"}
    else
        &.{};

    return switch (plan.body_kind) {
        .none => resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
            .status = plan.status,
            .content_type = plan.content_type,
            .docker_content_digest = plan.docker_content_digest,
            .www_authenticate_headers = headers,
        }, null),
        .index_fixture => resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
            .status = plan.status,
            .content_type = plan.content_type,
            .docker_content_digest = Fixtures.index_digest,
            .www_authenticate_headers = headers,
        }, Fixtures.index_body.?),
        .malformed_manifest_fixture => blk: {
            const body = readFixtureAlloc(allocator, "fixtures/manifests/invalid-truncated-oci-manifest.json", 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            break :blk resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = plan.status,
                .content_type = plan.content_type,
                .docker_content_digest = plan.docker_content_digest,
                .www_authenticate_headers = headers,
            }, body);
        },
        .manifest_fixture => blk: {
            const body = readFixtureAlloc(allocator, "fixtures/manifests/oci-image-manifest-spec-example.json", 16 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            break :blk resolver.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = plan.status,
                .content_type = plan.content_type,
                .docker_content_digest = plan.docker_content_digest,
                .www_authenticate_headers = headers,
            }, body);
        },
    };
}

pub fn expectResolveFailure(
    failure: ResolveError,
    expected_tag_name: []const u8,
    expected_registry: []const u8,
    expected_reference: []const u8,
    expected_http_status: ?u16,
    expected_transport_retries_exhausted: ?bool,
) !void {
    try std.testing.expectEqualStrings(expected_tag_name, @tagName(std.meta.activeTag(failure)));
    switch (failure) {
        inline else => |value| {
            try std.testing.expectEqualSlices(u8, expected_registry, value.registry);
            try std.testing.expectEqualSlices(u8, expected_reference, value.reference);
            try std.testing.expectEqual(expected_http_status, value.http_status);
        },
    }
    if (expected_transport_retries_exhausted) |expected| {
        switch (failure) {
            .rate_limited => |value| try std.testing.expectEqual(expected, value.transport_retries_exhausted),
            .network_error => |value| try std.testing.expectEqual(expected, value.transport_retries_exhausted),
            .timeout => |value| try std.testing.expectEqual(expected, value.transport_retries_exhausted),
            else => try std.testing.expect(!expected),
        }
    }
}

// --- Test helpers ---

fn allocManifestGet(allocator: std.mem.Allocator, url: []const u8) !resolver.ManifestHttpRequest {
    return .{
        .method = .get,
        .url = try allocator.dupe(u8, url),
    };
}

fn scenarioInList(scenario: Scenario, list: []const Scenario) bool {
    for (list) |entry| {
        if (entry == scenario) return true;
    }
    return false;
}

fn expectScenarioTagMatchesResolveError(scenario: Scenario) !void {
    const name = @tagName(scenario);
    inline for (std.meta.fields(ResolveError)) |field| {
        if (std.mem.eql(u8, name, field.name)) return;
    }
    return error.TestUnexpectedResult;
}

// --- Tests ---

test "test_matrix: failure scenario tables align with ResolveError tags and C4 builders" {
    try std.testing.expectEqual(@typeInfo(ResolveError).@"union".fields.len, resolve_failure_scenarios.len);

    var resolve_errors: [resolve_failure_scenarios.len]C4Entry = undefined;
    try std.testing.expectEqual(resolve_failure_scenarios.len, c4ResolveErrorEntries(&resolve_errors));

    var validate_errors: [validate_failure_scenarios.len]C4Entry = undefined;
    try std.testing.expectEqual(validate_failure_scenarios.len, c4ValidateFailureEntries(&validate_errors, 0));

    var get_manifest_errors: [get_manifest_failure_scenarios.len]C4Entry = undefined;
    try std.testing.expectEqual(get_manifest_failure_scenarios.len, c4GetManifestFailureEntries(&get_manifest_errors, 0));

    for (resolve_failure_scenarios) |scenario| {
        try expectScenarioTagMatchesResolveError(scenario);

        var listed = false;
        for (resolve_errors) |entry| {
            if (entry.scenario == scenario) listed = true;
        }
        try std.testing.expect(listed);
        try std.testing.expectEqual(PublicApi.resolve, resolve_errors[0].api);
    }

    for (validate_failure_scenarios) |scenario| {
        try std.testing.expect(scenarioInList(scenario, &resolve_failure_scenarios));
        const expected_surface: C4Surface = if (scenario == .not_found) .validate_not_found else .resolve_error;
        var listed = false;
        for (validate_errors) |entry| {
            if (entry.scenario == scenario) {
                listed = true;
                try std.testing.expectEqual(PublicApi.validate, entry.api);
                try std.testing.expectEqual(expected_surface, entry.surface);
            }
        }
        try std.testing.expect(listed);
    }

    for (get_manifest_failure_scenarios) |scenario| {
        try std.testing.expect(scenarioInList(scenario, &resolve_failure_scenarios));
        var listed = false;
        for (get_manifest_errors) |entry| {
            if (entry.scenario == scenario) {
                listed = true;
                try std.testing.expectEqual(PublicApi.get_manifest, entry.api);
                try std.testing.expectEqual(C4Surface.resolve_error, entry.surface);
            }
        }
        try std.testing.expect(listed);
    }

    try std.testing.expectEqual(
        resolve_failure_scenarios.len,
        validate_failure_scenarios.len + validate_failure_scenario_skips.len,
    );
    for (validate_failure_scenario_skips) |skipped| {
        try std.testing.expect(!scenarioInList(skipped, &validate_failure_scenarios));
        try std.testing.expect(scenarioInList(skipped, &resolve_failure_scenarios));
    }
    for (resolve_failure_scenarios) |scenario| {
        const in_validate = scenarioInList(scenario, &validate_failure_scenarios);
        const in_skips = scenarioInList(scenario, &validate_failure_scenario_skips);
        try std.testing.expect(in_validate != in_skips);
    }
    try std.testing.expectEqual(resolve_failure_scenarios.len, get_manifest_failure_scenarios.len);
}

test "test_matrix: scenario metadata helpers match expected HTTP status, reference, platform, and config" {
    const metadata_cases = [_]struct {
        scenario: Scenario,
        http_status: ?u16,
        reference: []const u8,
        platform: ?Platform,
        rate_limit_retries: u8,
    }{
        .{
            .scenario = .not_found,
            .http_status = null,
            .reference = "registry-1.docker.io/library/busybox:latest",
            .platform = null,
            .rate_limit_retries = 1,
        },
        .{
            .scenario = .rate_limited,
            .http_status = 429,
            .reference = "registry-1.docker.io/library/busybox:latest",
            .platform = null,
            .rate_limit_retries = 0,
        },
        .{
            .scenario = .depth_limit_exceeded,
            .http_status = null,
            .reference = "registry-1.docker.io/library/busybox@" ++ index_child_digest,
            .platform = .{ .os = "linux", .architecture = "arm64" },
            .rate_limit_retries = 1,
        },
        .{
            .scenario = .platform_not_found,
            .http_status = null,
            .reference = "registry-1.docker.io/library/busybox:latest",
            .platform = .{ .os = "linux", .architecture = "ppc64" },
            .rate_limit_retries = 1,
        },
    };

    for (metadata_cases) |tc| {
        try std.testing.expectEqual(tc.http_status, expectedHttpStatus(tc.scenario));
        try std.testing.expectEqualStrings(tc.reference, expectedReference(tc.scenario));
        try std.testing.expectEqual(tc.rate_limit_retries, scenarioConfig(tc.scenario).max_rate_limit_retries);
        const platform = scenarioPlatform(tc.scenario);
        if (tc.platform) |expected| {
            try std.testing.expect(platform != null);
            try std.testing.expect(expected.match(platform.?));
        } else {
            try std.testing.expect(platform == null);
        }
    }
}

test "test_matrix.sha256DigestStringAlloc: prefixes sha256 and sizes digest string" {
    const body = "fixture-bytes";

    const digest = try sha256DigestStringAlloc(std.testing.allocator, body);
    defer std.testing.allocator.free(digest);

    try std.testing.expect(std.mem.startsWith(u8, digest, "sha256:"));
    try std.testing.expectEqual(@as(usize, 71), digest.len);
}

test "test_matrix.buildIndexBodyAlloc: embeds child digest and platform fields" {
    const index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        MediaType.oci_index_v1.toString(),
        MediaType.oci_manifest_v1.toString(),
        index_child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(index_body);

    try std.testing.expect(std.mem.indexOf(u8, index_body, index_child_digest) != null);
    try std.testing.expect(std.mem.indexOf(u8, index_body, "\"architecture\": \"arm64\"") != null);
}

test "test_matrix.expectResolveFailure: asserts tag, registry, reference, and HTTP status" {
    const failure = ResolveError{ .not_found = .{
        .registry = "registry-1.docker.io",
        .reference = "registry-1.docker.io/library/busybox:latest",
        .http_status = 404,
    } };

    try expectResolveFailure(
        failure,
        "not_found",
        "registry-1.docker.io",
        "registry-1.docker.io/library/busybox:latest",
        404,
        null,
    );
}

test "test_matrix: manifestExchange and refuseTokenExchange implement scenario plans" {
    defer Fixtures.reset(std.testing.allocator);
    const alloc = std.testing.allocator;

    var client: std.http.Client = undefined;
    const token_request = auth.TokenHttpRequest{
        .method = .get,
        .url = try alloc.dupe(u8, "https://auth.example.test/token"),
    };
    try std.testing.expectError(error.TokenExchangeFailed, refuseTokenExchange(alloc, &client, token_request));

    const manifest_url = "https://registry-1.docker.io/v2/library/busybox/manifests/latest";
    const exchange_cases = [_]struct {
        scenario: Scenario,
        status: ?std.http.Status,
        err: ?resolver.ManifestExchangeError,
    }{
        .{ .scenario = .network_error, .status = .temporary_redirect, .err = null },
        .{ .scenario = .auth_failed, .status = .unauthorized, .err = null },
        .{ .scenario = .not_found, .status = .not_found, .err = null },
        .{ .scenario = .rate_limited, .status = .too_many_requests, .err = null },
        .{ .scenario = .timeout, .status = null, .err = error.Timeout },
        .{ .scenario = .response_too_large, .status = null, .err = error.ResponseBodyTooLarge },
        .{ .scenario = .content_type_mismatch, .status = .ok, .err = null },
        .{ .scenario = .digest_mismatch, .status = .ok, .err = null },
        .{ .scenario = .unsupported_algorithm, .status = .ok, .err = null },
        .{ .scenario = .manifest_parse_error, .status = .ok, .err = null },
        .{ .scenario = .platform_required, .status = .ok, .err = null },
        .{ .scenario = .platform_not_found, .status = .ok, .err = null },
        .{ .scenario = .depth_limit_exceeded, .status = .ok, .err = null },
    };

    for (exchange_cases) |tc| {
        try prepareScenario(tc.scenario, alloc);
        const request = try allocManifestGet(alloc, manifest_url);
        const result = manifestExchange(tc.scenario, alloc, request);
        if (tc.err) |expected_err| {
            try std.testing.expectError(expected_err, result);
        } else {
            const response = try result;
            defer response.deinit(alloc);
            try std.testing.expectEqual(tc.status.?, response.metadata.status);
            if (tc.scenario == .auth_failed) {
                try std.testing.expectEqual(@as(usize, 1), response.metadata.www_authenticate_headers.len);
            }
            if (tc.scenario == .digest_mismatch) {
                try std.testing.expectEqualStrings(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    response.metadata.docker_content_digest.?,
                );
            }
            if (tc.scenario == .unsupported_algorithm) {
                try std.testing.expect(std.mem.startsWith(u8, response.metadata.docker_content_digest.?, "sha512:"));
            }
        }
    }
}
