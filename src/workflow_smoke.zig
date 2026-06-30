//! Small workflow smoke matrix.
//!
//! These tests sit above the owning unit tests and below any future integration
//! layer. They exercise the public resolver surface through `z_oci.testing` with
//! injected transports.

const std = @import("std");
const z_oci = @import("z_oci");

const tm = z_oci.test_matrix;

fn parseWorkflowFixture(comptime T: type, path: []const u8, comptime max_bytes: usize) !std.json.Parsed(T) {
    var bytes_buffer: [max_bytes + 1]u8 = undefined;
    const bytes = try std.Io.Dir.cwd().readFile(std.testing.io, path, &bytes_buffer);
    if (bytes.len > max_bytes) return error.StreamTooLong;

    return z_oci.json.parse(T, std.testing.allocator, bytes);
}

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

const busybox_ref = z_oci.Reference{
    .registry = "registry-1.docker.io",
    .repository = "library/busybox",
    .tag = "latest",
    .digest = null,
    .digest_raw = null,
};

// --- Tests ---

test "workflow smoke: parse manifest fixture and stringify round-trips core fields" {
    const parsed = try parseWorkflowFixture(
        z_oci.Manifest,
        "fixtures/manifests/busybox-amd64-live-oci-manifest.json",
        32 * 1024,
    );
    defer parsed.deinit();

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(parsed.value);
    const out = aw.written();

    const reparsed = try z_oci.json.parse(z_oci.Manifest, std.testing.allocator, out);
    defer reparsed.deinit();

    try std.testing.expectEqual(parsed.value.schema_version, reparsed.value.schema_version);
    try std.testing.expectEqual(parsed.value.media_type, reparsed.value.media_type);
    try std.testing.expectEqualSlices(u8, parsed.value.config.digest.hex, reparsed.value.config.digest.hex);
    try std.testing.expectEqual(parsed.value.layers.len, reparsed.value.layers.len);

    const truncated_result = parseWorkflowFixture(
        z_oci.Manifest,
        "fixtures/manifests/invalid-truncated-oci-manifest.json",
        32 * 1024,
    );
    if (truncated_result) |_| return error.TestUnexpectedResult else |_| {}
}

test "workflow smoke: ResolveResult clone survives arena teardown" {
    var cloned: z_oci.ResolveResult = undefined;

    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        const original = z_oci.ResolveResult{
            .reference = .{
                .registry = "registry-1.docker.io",
                .repository = "library/busybox",
                .tag = "latest",
                .digest = null,
                .digest_raw = null,
            },
            .digest = .{ .algorithm = .sha256, .hex = "b8d1827e38a1d49cd17217efd7b07d689e4ea174e39c7dcbb95533d175bea65" },
            .media_type = z_oci.MediaType.oci_manifest_v1,
            .platform = .{
                .os = "linux",
                .architecture = "arm64",
                .variant = "v8",
            },
        };

        cloned = try original.clone(std.testing.allocator);
    }
    defer cloned.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "registry-1.docker.io", cloned.reference.registry);
    try std.testing.expectEqualSlices(u8, "library/busybox", cloned.reference.repository);
    try std.testing.expectEqualSlices(u8, "latest", cloned.reference.refString());
    try std.testing.expect(cloned.platform != null);
    try std.testing.expectEqualSlices(u8, "linux", cloned.platform.?.os);
    try std.testing.expectEqualSlices(u8, "arm64", cloned.platform.?.architecture);
    try std.testing.expectEqualSlices(u8, "v8", cloned.platform.?.variant.?);
}

test "workflow smoke: public validate follows selected multi-arch child" {
    const MockHarness = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

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
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = z_oci.MediaType.oci_index_v1.toString(),
                    .docker_content_digest = index_digest,
                }, index_body);
            }

            if (std.mem.endsWith(u8, request.url, child_digest)) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                    .docker_content_digest = child_digest,
                }, child_body);
            }

            return error.TransportFailed;
        }
    };

    MockHarness.child_body = try std.testing.allocator.dupe(
        u8,
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
        ,
    );
    defer std.testing.allocator.free(MockHarness.child_body);

    MockHarness.child_digest = try tm.sha256DigestStringAlloc(std.testing.allocator, MockHarness.child_body);
    defer std.testing.allocator.free(MockHarness.child_digest);

    MockHarness.index_body = try tm.buildIndexBodyAlloc(
        std.testing.allocator,
        z_oci.MediaType.oci_index_v1.toString(),
        z_oci.MediaType.oci_manifest_v1.toString(),
        MockHarness.child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(MockHarness.index_body);

    MockHarness.index_digest = try tm.sha256DigestStringAlloc(std.testing.allocator, MockHarness.index_body);
    defer std.testing.allocator.free(MockHarness.index_digest);

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

test "workflow smoke: z_oci.testing resolve propagates failure context through public seam" {
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return tm.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            return tm.manifestExchange(.network_error, allocator, request);
        }
    };

    var client: std.http.Client = undefined;

    const outcome = try z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        z_oci.Config{},
        busybox_ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .success => return error.TestUnexpectedResult,
        .failure => |failure| try tm.expectResolveFailure(
            failure,
            "network_error",
            "registry-1.docker.io",
            tm.expectedReference(.network_error),
            tm.expectedHttpStatus(.network_error),
            null,
        ),
    }
}

test "workflow smoke: public validate maps representative failures with full context" {
    const MockHarness = struct {
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

    defer tm.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;

    for (tm.validate_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try tm.prepareScenario(scenario, std.testing.allocator);

        const outcome = try z_oci.testing.validateWithExchangers(
            std.testing.allocator,
            &client,
            tm.scenarioConfig(scenario),
            busybox_ref,
            tm.scenarioPlatform(scenario),
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );
        defer switch (outcome) {
            .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
            else => {},
        };

        try expectWorkflowValidateFailure(outcome, scenario);
    }
}

test "workflow smoke: public getManifest maps representative failures with full context" {
    const MockHarness = struct {
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

    defer tm.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;

    for (tm.get_manifest_failure_scenarios) |scenario| {
        MockHarness.scenario = scenario;
        try tm.prepareScenario(scenario, std.testing.allocator);

        const outcome = try z_oci.testing.getManifestWithExchangers(
            std.testing.allocator,
            &client,
            tm.scenarioConfig(scenario),
            busybox_ref,
            tm.scenarioPlatform(scenario),
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );
        defer switch (outcome) {
            .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
            .success => |parsed| parsed.deinit(),
        };

        try expectWorkflowGetManifestFailure(outcome, scenario);
    }
}

test "workflow smoke: public resolve maps exhausted token 429 to rate_limited" {
    const MockHarness = struct {
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

    defer MockHarness.manifest_calls = 0;

    var client: std.http.Client = undefined;

    const outcome = try z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 0 },
        busybox_ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
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
}

test "workflow smoke: public resolve returns CaBundleFileNotFound for missing ca bundle path" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    const MockHarness = struct {
        var manifest_calls: usize = 0;

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
            unreachable;
        }
    };

    defer MockHarness.manifest_calls = 0;

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const outcome = z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" },
        busybox_ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );

    try std.testing.expectError(error.CaBundleFileNotFound, outcome);
    try std.testing.expectEqual(@as(usize, 0), MockHarness.manifest_calls);
}

test "workflow smoke: public resolve preemptively sleeps before child fetch when rate limit exhausted" {
    const MockHarness = struct {
        var manifest_calls: usize = 0;
        var preemptive_sleep_ms: u32 = 0;
        var now_unix_seconds: i64 = 1_700_000_000;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

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
                    child_digest,
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
            if (!std.mem.endsWith(u8, request.url, child_digest)) return error.TransportFailed;

            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child_digest,
            }, child_body);
        }

        fn sleeper(delay_ms: u32) void {
            preemptive_sleep_ms = delay_ms;
        }
    };

    MockHarness.child_body = try std.testing.allocator.dupe(
        u8,
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
        ,
    );
    defer std.testing.allocator.free(MockHarness.child_body);
    MockHarness.child_digest = try tm.sha256DigestStringAlloc(std.testing.allocator, MockHarness.child_body);
    defer std.testing.allocator.free(MockHarness.child_digest);

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
