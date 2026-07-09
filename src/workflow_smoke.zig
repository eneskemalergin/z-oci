//! Small workflow smoke matrix.
//!
//! These tests sit above the owning unit tests and below any future integration
//! layer. They exercise the public resolver surface through `z_oci.testing` with
//! injected transports.

const std = @import("std");
const z_oci = @import("z_oci");

const tm = z_oci.test_matrix;

const busybox_ref = z_oci.Reference{
    .registry = "registry-1.docker.io",
    .repository = "library/busybox",
    .tag = "latest",
    .digest = null,
    .digest_raw = null,
};

const child_manifest_json =
    \\{
    \\  "schemaVersion": 2,
    \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
    \\  "config": {
    \\    "mediaType": "application/vnd.oci.image.config.v1+json",
    \\    "digest": "sha256:abababababababababababababababababababababababababababababababab",
    \\    "size": 111
    \\  },
    \\  "layers": []
    \\}
;

const ChildArtifacts = struct {
    body: []u8,
    digest: []u8,

    fn alloc(allocator: std.mem.Allocator) !ChildArtifacts {
        const body = try allocator.dupe(u8, child_manifest_json);
        errdefer allocator.free(body);
        const digest = try tm.sha256DigestStringAlloc(allocator, body);
        errdefer allocator.free(digest);
        return .{ .body = body, .digest = digest };
    }

    fn deinit(self: ChildArtifacts, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        allocator.free(self.digest);
    }
};

fn expectWorkflowValidateFailure(outcome: z_oci.ValidateOutcome, scenario: tm.Scenario) !void {
    switch (scenario) {
        .not_found => try std.testing.expectEqual(z_oci.ValidateOutcome.not_found, outcome),
        else => switch (outcome) {
            .valid, .not_found => return error.TestUnexpectedResult,
            .failure => |failure| try tm.expectResolveFailure(
                failure,
                @tagName(scenario),
                "registry-1.docker.io",
                tm.expectedReference(scenario),
                tm.expectedHttpStatus(scenario),
                null,
            ),
        },
    }
}

fn expectWorkflowGetManifestFailure(outcome: z_oci.ManifestOutcome, scenario: tm.Scenario) !void {
    switch (outcome) {
        .success => return error.TestUnexpectedResult,
        .failure => |failure| try tm.expectResolveFailure(
            failure,
            @tagName(scenario),
            "registry-1.docker.io",
            tm.expectedReference(scenario),
            tm.expectedHttpStatus(scenario),
            null,
        ),
    }
}

const ScenarioHarness = struct {
    var scenario: tm.Scenario = .not_found;

    fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
        return tm.refuseTokenExchange(allocator, client, request);
    }

    fn manifestExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.testing.ManifestHttpRequest,
    ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
        return tm.manifestExchange(scenario, allocator, request);
    }
};

fn deinitResolveOutcome(outcome: z_oci.ResolveOutcome, allocator: std.mem.Allocator) void {
    switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, allocator),
        else => {},
    }
}

fn deinitValidateOutcome(outcome: z_oci.ValidateOutcome, allocator: std.mem.Allocator) void {
    switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, allocator),
        else => {},
    }
}

fn deinitManifestOutcome(outcome: z_oci.ManifestOutcome, allocator: std.mem.Allocator) void {
    switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, allocator),
        .success => |parsed| parsed.deinit(),
    }
}

// --- Tests ---

test "workflow smoke: ResolveResult clone survives arena teardown" {
    var cloned: z_oci.ResolveResult = undefined;

    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        const original = z_oci.ResolveResult{
            .reference = busybox_ref,
            .digest = .{ .algorithm = .sha256, .hex = "b8d1827e38a1d49cd17217efd7b07d689e4ea174e39c7dcbb95533d175bea65" },
            .media_type = z_oci.MediaType.oci_manifest_v1,
            .platform = .{ .os = "linux", .architecture = "arm64", .variant = "v8" },
        };

        cloned = try original.clone(std.testing.allocator);
    }
    defer cloned.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", cloned.reference.registry);
    try std.testing.expectEqualSlices(u8, "library/busybox", cloned.reference.repository);
    try std.testing.expectEqualSlices(u8, "latest", cloned.reference.refString());
    try std.testing.expectEqualSlices(u8, "linux", cloned.platform.?.os);
    try std.testing.expectEqualSlices(u8, "arm64", cloned.platform.?.architecture);
    try std.testing.expectEqualSlices(u8, "v8", cloned.platform.?.variant.?);
}

test "workflow smoke: public validate follows selected multi-arch child" {
    const MockHarness = struct {
        var child: ChildArtifacts = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return tm.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (std.mem.endsWith(u8, request.url, "/manifests/latest")) {
                const index_body = try tm.buildIndexBodyAlloc(
                    allocator,
                    z_oci.MediaType.oci_index_v1.toString(),
                    z_oci.MediaType.oci_manifest_v1.toString(),
                    child.digest,
                    "linux",
                    "arm64",
                );
                defer allocator.free(index_body);
                const index_digest = try tm.sha256DigestStringAlloc(allocator, index_body);
                defer allocator.free(index_digest);
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = z_oci.MediaType.oci_index_v1.toString(),
                    .docker_content_digest = index_digest,
                }, index_body);
            }

            if (std.mem.endsWith(u8, request.url, child.digest)) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                    .docker_content_digest = child.digest,
                }, child.body);
            }

            return error.TransportFailed;
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(std.testing.allocator);
    defer MockHarness.child.deinit(std.testing.allocator);

    var client: std.http.Client = undefined;
    const outcome = try z_oci.testing.validateWithExchangers(
        std.testing.allocator,
        &client,
        z_oci.Config{},
        busybox_ref,
        .{ .os = "linux", .architecture = "arm64" },
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    try std.testing.expectEqual(z_oci.ValidateOutcome.valid, outcome);
}

test "workflow smoke: z_oci.testing public APIs propagate representative failures" {
    defer tm.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;
    const allocator = std.testing.allocator;

    const resolve_outcome = try z_oci.testing.resolveWithExchangers(
        allocator,
        &client,
        z_oci.Config{},
        busybox_ref,
        null,
        ScenarioHarness.tokenExchange,
        struct {
            fn call(allocator_arg: std.mem.Allocator, _: *std.http.Client, request: z_oci.testing.ManifestHttpRequest) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
                return tm.manifestExchange(.network_error, allocator_arg, request);
            }
        }.call,
        .{},
    );
    defer deinitResolveOutcome(resolve_outcome, allocator);
    switch (resolve_outcome) {
        .failure => |failure| try tm.expectResolveFailure(
            failure,
            "network_error",
            "registry-1.docker.io",
            tm.expectedReference(.network_error),
            tm.expectedHttpStatus(.network_error),
            null,
        ),
        else => return error.TestUnexpectedResult,
    }

    for (tm.validate_failure_scenarios) |scenario| {
        ScenarioHarness.scenario = scenario;
        try tm.prepareScenario(scenario, allocator);

        const outcome = try z_oci.testing.validateWithExchangers(
            allocator,
            &client,
            tm.scenarioConfig(scenario),
            busybox_ref,
            tm.scenarioPlatform(scenario),
            ScenarioHarness.tokenExchange,
            ScenarioHarness.manifestExchange,
            .{},
        );
        defer deinitValidateOutcome(outcome, allocator);
        try expectWorkflowValidateFailure(outcome, scenario);
    }

    for (tm.get_manifest_failure_scenarios) |scenario| {
        ScenarioHarness.scenario = scenario;
        try tm.prepareScenario(scenario, allocator);

        const outcome = try z_oci.testing.getManifestWithExchangers(
            allocator,
            &client,
            tm.scenarioConfig(scenario),
            busybox_ref,
            tm.scenarioPlatform(scenario),
            ScenarioHarness.tokenExchange,
            ScenarioHarness.manifestExchange,
            .{},
        );
        defer deinitManifestOutcome(outcome, allocator);
        try expectWorkflowGetManifestFailure(outcome, scenario);
    }
}

test "workflow smoke: public resolve maps token 429 exhaustion and missing CA bundle" {
    const RateLimitHarness = struct {
        var manifest_calls: usize = 0;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(std.testing.allocator);
            return .{
                .status = .too_many_requests,
                .body = "",
                .resilience_headers = &.{
                    .{ .name = "Retry-After", .value = "1" },
                },
            };
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_calls += 1;
            if (manifest_calls == 1) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:library/busybox:pull\"",
                    },
                }, null);
            }
            return error.TransportFailed;
        }
    };

    defer RateLimitHarness.manifest_calls = 0;

    var client: std.http.Client = undefined;
    const rate_limited = try z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 0 },
        busybox_ref,
        null,
        RateLimitHarness.tokenExchange,
        RateLimitHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(rate_limited, std.testing.allocator);
    switch (rate_limited) {
        .failure => |failure| try tm.expectResolveFailure(
            failure,
            "rate_limited",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            401,
            true,
        ),
        else => return error.TestUnexpectedResult,
    }

    if (comptime std.http.Client.disable_tls) return;

    const CaHarness = struct {
        var manifest_calls: usize = 0;

        fn tokenExchange(allocator: std.mem.Allocator, http_client: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return tm.refuseTokenExchange(allocator, http_client, request);
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_calls += 1;
            unreachable;
        }
    };

    defer CaHarness.manifest_calls = 0;

    var tls_client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer tls_client.deinit();

    try std.testing.expectError(
        error.CaBundleFileNotFound,
        z_oci.testing.resolveWithExchangers(
            std.testing.allocator,
            &tls_client,
            .{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" },
            busybox_ref,
            null,
            CaHarness.tokenExchange,
            CaHarness.manifestExchange,
            .{},
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), CaHarness.manifest_calls);
}

test "workflow smoke: public resolve preemptively sleeps before child fetch when rate limit exhausted" {
    const MockHarness = struct {
        var manifest_calls: usize = 0;
        var preemptive_sleep_ms: u32 = 0;
        var now_unix_seconds: i64 = 1_700_000_000;
        var child: ChildArtifacts = undefined;

        fn now() i64 {
            return now_unix_seconds;
        }

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return tm.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_calls += 1;

            if (manifest_calls == 1) {
                const index_body = try tm.buildIndexBodyAlloc(
                    allocator,
                    z_oci.MediaType.oci_index_v1.toString(),
                    z_oci.MediaType.oci_manifest_v1.toString(),
                    child.digest,
                    "linux",
                    "arm64",
                );
                defer allocator.free(index_body);
                const index_digest = try tm.sha256DigestStringAlloc(allocator, index_body);
                defer allocator.free(index_digest);

                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = z_oci.MediaType.oci_index_v1.toString(),
                    .docker_content_digest = index_digest,
                    .resilience_headers = &.{
                        .{ .name = "RateLimit-Limit", .value = "100;w=21600" },
                        .{ .name = "RateLimit-Remaining", .value = "0" },
                        .{ .name = "RateLimit-Reset", .value = "1700000030" },
                    },
                }, index_body);
            }

            if (preemptive_sleep_ms == 0) return error.TransportFailed;
            if (!std.mem.endsWith(u8, request.url, child.digest)) return error.TransportFailed;

            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }

        fn sleeper(delay_ms: u32) void {
            preemptive_sleep_ms = delay_ms;
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(std.testing.allocator);
    defer MockHarness.child.deinit(std.testing.allocator);
    defer {
        MockHarness.manifest_calls = 0;
        MockHarness.preemptive_sleep_ms = 0;
        MockHarness.now_unix_seconds = 1_700_000_000;
    }

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var client: std.http.Client = undefined;
    const outcome = try z_oci.testing.resolveWithExchangers(
        arena.allocator(),
        &client,
        .{ .rate_limit_enabled = true },
        busybox_ref,
        .{ .os = "linux", .architecture = "arm64" },
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{
            .sleeper = MockHarness.sleeper,
            .clock = .{ .now_unix_seconds = MockHarness.now },
        },
    );

    switch (outcome) {
        .success => |result| {
            try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_calls);
            try std.testing.expectEqual(@as(u32, 30_000), MockHarness.preemptive_sleep_ms);
            try std.testing.expectEqual(z_oci.MediaType.oci_manifest_v1, result.media_type);
        },
        .failure => |failure| {
            z_oci.testing.deinitResolveError(failure, std.testing.allocator);
            return error.TestUnexpectedResult;
        },
    }
}

test "workflow smoke: resolveMany caches implicit latest and preserves partial failures" {
    const MockHarness = struct {
        var manifest_calls: usize = 0;
        var child: ChildArtifacts = undefined;

        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return tm.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            manifest_calls += 1;

            if (std.mem.endsWith(u8, request.url, "/manifests/missing")) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .not_found,
                }, null);
            }

            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(std.testing.allocator);
    defer MockHarness.child.deinit(std.testing.allocator);
    defer MockHarness.manifest_calls = 0;

    const allocator = std.testing.allocator;
    var refs = [_]z_oci.Reference{
        try z_oci.Reference.parse(allocator, "registry-1.docker.io/library/busybox"),
        try z_oci.Reference.parse(allocator, "registry-1.docker.io/library/busybox"),
        try z_oci.Reference.parse(allocator, "registry-1.docker.io/library/busybox:missing"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try z_oci.testing.resolveManyWithExchangers(
        allocator,
        &client,
        z_oci.Config{},
        refs[0..],
        .{},
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), result.items.len);
    try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_calls);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[2]));
    try std.testing.expectEqualStrings(result.items[0].success.digest.hex, result.items[1].success.digest.hex);
    try std.testing.expect(result.items[0].success.digest.hex.ptr != result.items[1].success.digest.hex.ptr);
    try tm.expectResolveFailure(
        result.items[2].failure,
        "not_found",
        "registry-1.docker.io",
        "registry-1.docker.io/library/busybox:missing",
        null,
        null,
    );
}
