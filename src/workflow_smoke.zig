//! Small workflow smoke matrix.
//!
//! These tests sit above the owning unit tests and below any future integration
//! layer. They exercise the public resolver surface through `z_oci.testing` with
//! injected transports, and app-shaped public API flows against the in-process mock
//! peer are covered in `root.zig` mock integration tests.

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
                switch (scenario) {
                    .rate_limited => false,
                    .timeout => true,
                    else => null,
                },
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
            switch (scenario) {
                .rate_limited => false,
                .timeout => true,
                else => null,
            },
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

const ResolveOutcomeTeardown = struct {
    owned_input: ?*z_oci.Reference = null,
    // Success payload lives in an arena; skip `ResolveResult.deinit` (arena teardown owns it).
    success_owned_by_arena: bool = false,
};

fn deinitResolveOutcome(
    outcome: *z_oci.ResolveOutcome,
    allocator: std.mem.Allocator,
    teardown: ResolveOutcomeTeardown,
) void {
    switch (outcome.*) {
        .success => |*result| {
            if (!teardown.success_owned_by_arena) result.deinit(allocator);
        },
        .failure => |failure| {
            if (teardown.owned_input) |ref| ref.deinit(allocator);
            z_oci.testing.deinitResolveError(failure, allocator);
        },
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

test "workflow smoke: z_oci.testing resolveWithExchangers propagates network_error" {
    defer tm.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;
    const allocator = std.testing.allocator;

    var resolve_outcome = try z_oci.testing.resolveWithExchangers(
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
    defer deinitResolveOutcome(&resolve_outcome, allocator, .{});

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
}

test "workflow smoke: resolveWithExchangers never probes registry /v2/ root" {
    const MockHarness = struct {
        var saw_v2_root: bool = false;

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            if (std.mem.endsWith(u8, request.url, "/v2/") or std.mem.eql(u8, request.url, "https://registry-1.docker.io/v2")) {
                saw_v2_root = true;
            }
            const body = try allocator.dupe(u8, child_manifest_json);
            errdefer allocator.free(body);
            const digest = try tm.sha256DigestStringAlloc(allocator, body);
            errdefer allocator.free(digest);
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = digest,
            }, body);
        }
    };
    defer MockHarness.saw_v2_root = false;

    var ref = try z_oci.Reference.parse(std.testing.allocator, "registry-1.docker.io/library/busybox:latest");

    var client: std.http.Client = undefined;
    var owned_outcome = try z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        z_oci.Config{},
        ref,
        null,
        tm.refuseTokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&owned_outcome, std.testing.allocator, .{ .owned_input = &ref });

    switch (owned_outcome) {
        .success => try std.testing.expect(!MockHarness.saw_v2_root),
        .failure => return error.TestUnexpectedResult,
    }
}

test "workflow smoke: pingRegistryWithExchanger requests only /v2/ root" {
    const MockHarness = struct {
        var saw_manifest_path: bool = false;
        var saw_v2_root: bool = false;

        fn exchange(_: std.mem.Allocator, _: *std.http.Client, request: z_oci.testing.PingHttpRequest) z_oci.testing.PingExchangeError!z_oci.testing.PingHttpResponse {
            if (std.mem.indexOf(u8, request.url, "/manifests/") != null) saw_manifest_path = true;
            if (std.mem.endsWith(u8, request.url, "/v2/")) saw_v2_root = true;
            return .{ .status = .unauthorized };
        }
    };
    defer {
        MockHarness.saw_manifest_path = false;
        MockHarness.saw_v2_root = false;
    }

    var client: std.http.Client = undefined;
    try std.testing.expectEqual(
        z_oci.RegistryPingStatus.reachable_auth_required,
        (try z_oci.testing.pingRegistryWithExchanger(
            std.testing.allocator,
            &client,
            z_oci.Config{},
            "registry.example.test",
            MockHarness.exchange,
        )).ok,
    );
    try std.testing.expect(!MockHarness.saw_manifest_path);
    try std.testing.expect(MockHarness.saw_v2_root);
}

test "workflow smoke: z_oci.testing validateWithExchangers propagates scenario failures" {
    defer tm.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;
    const allocator = std.testing.allocator;

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
}

test "workflow smoke: z_oci.testing getManifestWithExchangers propagates scenario failures" {
    defer tm.Fixtures.reset(std.testing.allocator);

    var client: std.http.Client = undefined;
    const allocator = std.testing.allocator;

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

test "workflow smoke: public resolve maps exhausted token 429 to rate_limited" {
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
    var rate_limited = try z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 0 },
        busybox_ref,
        null,
        RateLimitHarness.tokenExchange,
        RateLimitHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&rate_limited, std.testing.allocator, .{});

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
}

test "workflow smoke: public resolve maps missing CA bundle before manifest fetch" {
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
    var outcome = try z_oci.testing.resolveWithExchangers(
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
    defer deinitResolveOutcome(&outcome, arena.allocator(), .{ .success_owned_by_arena = true });

    switch (outcome) {
        .success => |result| {
            try std.testing.expectEqual(@as(usize, 2), MockHarness.manifest_calls);
            try std.testing.expectEqual(@as(u32, 30_000), MockHarness.preemptive_sleep_ms);
            try std.testing.expectEqual(z_oci.MediaType.oci_manifest_v1, result.media_type);
        },
        .failure => return error.TestUnexpectedResult,
    }
}

test "workflow smoke: resolveMany caches implicit latest and preserves partial failures" {
    defer tm.Fixtures.reset(std.testing.allocator);

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

test "workflow smoke: Zencelot-style pin flow formats pinned refs across mixed registries" {
    defer tm.Fixtures.reset(std.testing.allocator);

    // Multi-arch, auth isolation, digest verify, cache, lockfile metadata.
    const MockHarness = struct {
        const RecordedEvent = struct {
            event: z_oci.ResolveManyProgress.Event,
            index: usize,
            total: usize,
            registry: []u8,
            repository: []u8,
            ref_string: []u8,
        };

        const Recorder = struct {
            allocator: std.mem.Allocator,
            events: [24]RecordedEvent = undefined,
            event_count: usize = 0,

            fn deinit(self: *Recorder) void {
                for (self.events[0..self.event_count]) |event| {
                    self.allocator.free(event.registry);
                    self.allocator.free(event.repository);
                    self.allocator.free(event.ref_string);
                }
                self.event_count = 0;
            }
        };

        var docker_fetches: usize = 0;
        var ghcr_fetches: usize = 0;
        var docker_token_exchanges: usize = 0;
        var ghcr_token_exchanges: usize = 0;
        var child: ChildArtifacts = undefined;
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn progress(event: z_oci.ResolveManyProgress, user_data: ?*anyopaque) void {
            const recorder: *Recorder = @ptrCast(@alignCast(user_data.?));
            std.debug.assert(recorder.event_count < recorder.events.len);
            // Progress views are callback-duration only.
            const registry = recorder.allocator.dupe(u8, event.reference.registry) catch unreachable;
            const repository = recorder.allocator.dupe(u8, event.reference.repository) catch unreachable;
            const ref_string = recorder.allocator.dupe(u8, event.reference.ref_string) catch unreachable;
            recorder.events[recorder.event_count] = .{
                .event = event.event,
                .index = event.index,
                .total = event.total,
                .registry = registry,
                .repository = repository,
                .ref_string = ref_string,
            };
            recorder.event_count += 1;
        }

        fn tokenExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            if (std.mem.indexOf(u8, request.url, "auth.docker.test") != null) {
                docker_token_exchanges += 1;
                return .{ .status = .ok, .body = "{\"access_token\":\"docker-token\",\"expires_in\":3600}" };
            }
            if (std.mem.indexOf(u8, request.url, "auth.ghcr.test") != null) {
                ghcr_token_exchanges += 1;
                return .{ .status = .ok, .body = "{\"access_token\":\"ghcr-token\",\"expires_in\":3600}" };
            }
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);

            const is_docker = std.mem.indexOf(u8, request.url, "://registry-1.docker.io/") != null;
            const is_ghcr = std.mem.indexOf(u8, request.url, "://ghcr.io/") != null;
            if (is_docker) {
                docker_fetches += 1;
            } else if (is_ghcr) {
                ghcr_fetches += 1;
            } else {
                return error.TransportFailed;
            }

            if (request.authorization == null) {
                const challenge = if (is_docker)
                    "Bearer realm=\"https://auth.docker.test/token\",service=\"registry-1.docker.io\",scope=\"repository:library/busybox:pull\""
                else
                    "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/busybox:pull\"";
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{challenge},
                }, null);
            }

            const expected_token = if (is_docker) "Bearer docker-token" else "Bearer ghcr-token";
            if (!std.mem.eql(u8, request.authorization.?, expected_token)) {
                return error.TransportFailed;
            }

            if (std.mem.endsWith(u8, request.url, "/manifests/missing")) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .not_found,
                }, null);
            }

            if (std.mem.endsWith(u8, request.url, "/manifests/rate-limited")) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .too_many_requests,
                    .resilience_headers = &.{
                        .{ .name = "Retry-After", .value = "1" },
                    },
                }, null);
            }

            if (std.mem.endsWith(u8, request.url, "/manifests/latest") or
                std.mem.endsWith(u8, request.url, "/manifests/stable"))
            {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = z_oci.MediaType.oci_index_v1.toString(),
                    .docker_content_digest = index_digest,
                }, index_body);
            }

            if (std.mem.endsWith(u8, request.url, child.digest) or
                std.mem.indexOf(u8, request.url, "/manifests/sha256:") != null)
            {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .ok,
                    .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                    .docker_content_digest = child.digest,
                }, child.body);
            }

            return error.TransportFailed;
        }
    };

    const allocator = std.testing.allocator;
    MockHarness.child = try ChildArtifacts.alloc(allocator);
    defer MockHarness.child.deinit(allocator);

    MockHarness.index_body = try tm.buildIndexBodyAlloc(
        allocator,
        z_oci.MediaType.oci_index_v1.toString(),
        z_oci.MediaType.oci_manifest_v1.toString(),
        MockHarness.child.digest,
        "linux",
        "amd64",
    );
    defer allocator.free(MockHarness.index_body);

    MockHarness.index_digest = try tm.sha256DigestStringAlloc(allocator, MockHarness.index_body);
    defer allocator.free(MockHarness.index_digest);

    defer {
        MockHarness.docker_fetches = 0;
        MockHarness.ghcr_fetches = 0;
        MockHarness.docker_token_exchanges = 0;
        MockHarness.ghcr_token_exchanges = 0;
    }

    const wrong_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    var digest_image_buf: [128]u8 = undefined;
    const digest_image = try std.fmt.bufPrint(
        &digest_image_buf,
        "registry-1.docker.io/library/busybox@{s}",
        .{MockHarness.child.digest},
    );
    var wrong_digest_image_buf: [128]u8 = undefined;
    const wrong_digest_image = try std.fmt.bufPrint(
        &wrong_digest_image_buf,
        "registry-1.docker.io/library/busybox@{s}",
        .{wrong_digest},
    );

    // Mixed tag/digest/failure list shaped like a pipeline pin set.
    const image_strings = [_][]const u8{
        "registry-1.docker.io/library/busybox",
        "registry-1.docker.io/library/busybox:latest",
        "registry-1.docker.io/library/busybox:stable",
        "ghcr.io/owner/busybox:latest",
        digest_image,
        wrong_digest_image,
        "registry-1.docker.io/library/busybox:missing",
        "registry-1.docker.io/library/busybox:rate-limited",
    };

    var refs: [image_strings.len]z_oci.Reference = undefined;
    var parsed_count: usize = 0;
    defer for (refs[0..parsed_count]) |*ref| ref.deinit(allocator);
    for (image_strings, 0..) |image, index| {
        refs[index] = try z_oci.Reference.parse(allocator, image);
        parsed_count += 1;
    }

    var recorder: MockHarness.Recorder = .{ .allocator = allocator };
    defer recorder.deinit();

    var client: std.http.Client = undefined;
    var result = try z_oci.testing.resolveManyWithExchangers(
        allocator,
        &client,
        // One reactive retry so rate_limited surfaces transport_retries_exhausted.
        .{ .max_rate_limit_retries = 1 },
        refs[0..],
        .{
            // Batch-wide platform only.
            .platform = .{ .os = "linux", .architecture = "amd64" },
            .progress_fn = MockHarness.progress,
            .progress_user_data = @ptrCast(&recorder),
        },
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 8), result.items.len);
    // Unauthenticated probe then cached token retry. docker=17, ghcr=4 exchanges.
    try std.testing.expectEqual(@as(usize, 17), MockHarness.docker_fetches);
    try std.testing.expectEqual(@as(usize, 4), MockHarness.ghcr_fetches);
    try std.testing.expectEqual(@as(usize, 1), MockHarness.docker_token_exchanges);
    try std.testing.expectEqual(@as(usize, 1), MockHarness.ghcr_token_exchanges);

    // Input refs stay valid after success, cache hit, and failure.
    try std.testing.expectEqualStrings("registry-1.docker.io", refs[0].registry);
    try std.testing.expectEqualStrings("latest", refs[1].refString());
    try std.testing.expectEqualStrings("ghcr.io", refs[3].registry);
    try std.testing.expectEqualStrings(MockHarness.child.digest, refs[4].refString());
    try std.testing.expectEqualStrings(wrong_digest, refs[5].refString());

    const expected_events = [_]struct {
        event: z_oci.ResolveManyProgress.Event,
        index: usize,
        registry: []const u8,
        repository: []const u8,
        ref_string: []const u8,
    }{
        .{ .event = .item_started, .index = 0, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "latest" },
        .{ .event = .item_succeeded, .index = 0, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "latest" },
        .{ .event = .item_started, .index = 1, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "latest" },
        .{ .event = .cache_hit, .index = 1, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "latest" },
        .{ .event = .item_succeeded, .index = 1, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "latest" },
        .{ .event = .item_started, .index = 2, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "stable" },
        .{ .event = .item_succeeded, .index = 2, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "stable" },
        .{ .event = .item_started, .index = 3, .registry = "ghcr.io", .repository = "owner/busybox", .ref_string = "latest" },
        .{ .event = .item_succeeded, .index = 3, .registry = "ghcr.io", .repository = "owner/busybox", .ref_string = "latest" },
        .{ .event = .item_started, .index = 4, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = MockHarness.child.digest },
        .{ .event = .item_succeeded, .index = 4, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = MockHarness.child.digest },
        .{ .event = .item_started, .index = 5, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = wrong_digest },
        .{ .event = .item_failed, .index = 5, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = wrong_digest },
        .{ .event = .item_started, .index = 6, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "missing" },
        .{ .event = .item_failed, .index = 6, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "missing" },
        .{ .event = .item_started, .index = 7, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "rate-limited" },
        .{ .event = .item_failed, .index = 7, .registry = "registry-1.docker.io", .repository = "library/busybox", .ref_string = "rate-limited" },
    };
    try std.testing.expectEqual(@as(usize, expected_events.len), recorder.event_count);
    for (expected_events, recorder.events[0..recorder.event_count]) |want, got| {
        try std.testing.expectEqual(want.event, got.event);
        try std.testing.expectEqual(want.index, got.index);
        try std.testing.expectEqual(@as(usize, 8), got.total);
        try std.testing.expectEqualStrings(want.registry, got.registry);
        try std.testing.expectEqualStrings(want.repository, got.repository);
        try std.testing.expectEqualStrings(want.ref_string, got.ref_string);
    }

    var pinned_count: usize = 0;
    for (result.items, 0..) |item, index| {
        switch (item) {
            .success => |resolved| {
                pinned_count += 1;
                try std.testing.expectEqual(z_oci.MediaType.oci_manifest_v1, resolved.media_type);
                try std.testing.expectEqualStrings("linux", resolved.platform.?.os);
                try std.testing.expectEqualStrings("amd64", resolved.platform.?.architecture);
                try std.testing.expectEqualStrings(
                    MockHarness.child.digest["sha256:".len..],
                    resolved.digest.hex,
                );

                var pinned_buf: [256]u8 = undefined;
                const pinned = try std.fmt.bufPrint(
                    &pinned_buf,
                    "{s}/{s}@{f}",
                    .{ resolved.reference.registry, resolved.reference.repository, resolved.digest },
                );
                const expected_pinned = try std.fmt.allocPrint(
                    allocator,
                    "{s}/{s}@{s}",
                    .{ resolved.reference.registry, resolved.reference.repository, MockHarness.child.digest },
                );
                defer allocator.free(expected_pinned);
                try std.testing.expectEqualStrings(expected_pinned, pinned);

                if (index == 1) {
                    try std.testing.expect(result.items[0].success.digest.hex.ptr != resolved.digest.hex.ptr);
                }
            },
            .failure => |failure| {
                var message_buf: [512]u8 = undefined;
                var message_writer = std.Io.Writer.fixed(&message_buf);
                try failure.format(&message_writer);
                const message = message_writer.buffered();

                switch (index) {
                    5 => {
                        const expected_ref = try std.fmt.allocPrint(
                            allocator,
                            "registry-1.docker.io/library/busybox@{s}",
                            .{wrong_digest},
                        );
                        defer allocator.free(expected_ref);
                        try tm.expectResolveFailure(
                            failure,
                            "digest_mismatch",
                            "registry-1.docker.io",
                            expected_ref,
                            200,
                            null,
                        );
                        try std.testing.expect(std.mem.indexOf(u8, message, "digest mismatch") != null);
                    },
                    6 => {
                        try tm.expectResolveFailure(
                            failure,
                            "not_found",
                            "registry-1.docker.io",
                            "registry-1.docker.io/library/busybox:missing",
                            null,
                            null,
                        );
                        try std.testing.expect(std.mem.indexOf(u8, message, "registry-1.docker.io") != null);
                        try std.testing.expect(std.mem.indexOf(u8, message, "busybox:missing") != null);
                    },
                    7 => {
                        try tm.expectResolveFailure(
                            failure,
                            "rate_limited",
                            "registry-1.docker.io",
                            "registry-1.docker.io/library/busybox:rate-limited",
                            429,
                            true,
                        );
                        try std.testing.expect(std.mem.indexOf(u8, message, "HTTP 429") != null);
                        try std.testing.expect(std.mem.indexOf(u8, message, "transport retries exhausted") != null);
                    },
                    else => return error.TestUnexpectedResult,
                }
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 5), pinned_count);
}

test "workflow smoke: public resolveMany empty batch requires a live Client" {
    // Public resolveMany + real Client on the empty-batch path (no network).
    const allocator = std.testing.allocator;
    var client = std.http.Client{
        .allocator = allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    var result = try z_oci.resolveMany(allocator, &client, .{}, &.{}, .{});
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "workflow smoke: batch failure registry outlives input Reference deinit" {
    defer tm.Fixtures.reset(std.testing.allocator);
    // Batch failures own registry; safe to deinit inputs then format failures.
    const MockHarness = struct {
        fn tokenExchange(allocator: std.mem.Allocator, client: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return tm.refuseTokenExchange(allocator, client, request);
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .not_found,
            }, null);
        }
    };

    const allocator = std.testing.allocator;
    var ref = try z_oci.Reference.parse(allocator, "registry-1.docker.io/library/busybox:missing");
    const input_registry_ptr = ref.registry.ptr;

    var client: std.http.Client = undefined;
    var result = try z_oci.testing.resolveManyWithExchangers(
        allocator,
        &client,
        .{},
        &.{ref},
        .{},
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), result.items.len);
    try std.testing.expectEqual(.failure, std.meta.activeTag(result.items[0]));
    const failure_registry = switch (result.items[0].failure) {
        inline else => |value| value.registry,
    };
    try std.testing.expect(failure_registry.ptr != input_registry_ptr);

    ref.deinit(allocator);

    var message_buf: [256]u8 = undefined;
    var message_writer = std.Io.Writer.fixed(&message_buf);
    try result.items[0].failure.format(&message_writer);
    const message = message_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, message, "registry-1.docker.io") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "busybox:missing") != null);
}

test "workflow smoke: warm token cache still probes without Authorization first" {
    defer tm.Fixtures.reset(std.testing.allocator);

    // Warm token does not skip the unauthenticated probe (still pays 401).
    const MockHarness = struct {
        var unauthorized_probes: usize = 0;
        var authorized_gets: usize = 0;
        var token_exchanges: usize = 0;
        var child: ChildArtifacts = undefined;
        const token_body = "{\"access_token\":\"warm-token\",\"expires_in\":3600}";

        fn tokenExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            token_exchanges += 1;
            return .{ .status = .ok, .body = token_body };
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);

            if (request.authorization == null) {
                unauthorized_probes += 1;
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.example.test/token\",service=\"registry-1.docker.io\",scope=\"repository:library/busybox:pull\"",
                    },
                }, null);
            }

            if (!std.mem.eql(u8, request.authorization.?, "Bearer warm-token")) {
                return error.TransportFailed;
            }
            authorized_gets += 1;
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(std.testing.allocator);
    defer MockHarness.child.deinit(std.testing.allocator);
    defer {
        MockHarness.unauthorized_probes = 0;
        MockHarness.authorized_gets = 0;
        MockHarness.token_exchanges = 0;
    }

    const allocator = std.testing.allocator;
    var refs = [_]z_oci.Reference{
        try z_oci.Reference.parse(allocator, "registry-1.docker.io/library/busybox:one"),
        try z_oci.Reference.parse(allocator, "registry-1.docker.io/library/busybox:two"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try z_oci.testing.resolveManyWithExchangers(
        allocator,
        &client,
        .{},
        refs[0..],
        .{},
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expectEqual(@as(usize, 1), MockHarness.token_exchanges);
    try std.testing.expectEqual(@as(usize, 2), MockHarness.unauthorized_probes);
    try std.testing.expectEqual(@as(usize, 2), MockHarness.authorized_gets);
}

test "workflow smoke: CredentialProvider supplies Basic auth on per-registry token exchange" {
    defer tm.Fixtures.reset(std.testing.allocator);

    // credential_provider is on the live batch path, not storage-only.
    const MockHarness = struct {
        var docker_basic_seen: bool = false;
        var ghcr_basic_seen: bool = false;
        var child: ChildArtifacts = undefined;

        fn getCredential(registry: []const u8) ?z_oci.CredentialHandle {
            if (std.mem.eql(u8, registry, "registry-1.docker.io")) {
                return .{ .credential = .{ .username = "docker-user", .secret = "docker-secret" } };
            }
            if (std.mem.eql(u8, registry, "ghcr.io")) {
                return .{ .credential = .{ .username = "ghcr-user", .secret = "ghcr-secret" } };
            }
            return null;
        }

        fn tokenExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            const authorization = request.authorization orelse return error.TokenExchangeFailed;
            if (!std.mem.startsWith(u8, authorization, "Basic ")) return error.TokenExchangeFailed;

            if (std.mem.indexOf(u8, request.url, "auth.docker.test") != null) {
                docker_basic_seen = true;
                return .{ .status = .ok, .body = "{\"access_token\":\"docker-token\",\"expires_in\":3600}" };
            }
            if (std.mem.indexOf(u8, request.url, "auth.ghcr.test") != null) {
                ghcr_basic_seen = true;
                return .{ .status = .ok, .body = "{\"access_token\":\"ghcr-token\",\"expires_in\":3600}" };
            }
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);

            const is_docker = std.mem.indexOf(u8, request.url, "://registry-1.docker.io/") != null;
            const is_ghcr = std.mem.indexOf(u8, request.url, "://ghcr.io/") != null;
            if (!is_docker and !is_ghcr) return error.TransportFailed;

            if (request.authorization == null) {
                const challenge = if (is_docker)
                    "Bearer realm=\"https://auth.docker.test/token\",service=\"registry-1.docker.io\",scope=\"repository:library/busybox:pull\""
                else
                    "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/busybox:pull\"";
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{challenge},
                }, null);
            }

            const expected = if (is_docker) "Bearer docker-token" else "Bearer ghcr-token";
            if (!std.mem.eql(u8, request.authorization.?, expected)) return error.TransportFailed;

            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(std.testing.allocator);
    defer MockHarness.child.deinit(std.testing.allocator);
    defer {
        MockHarness.docker_basic_seen = false;
        MockHarness.ghcr_basic_seen = false;
    }

    const provider = z_oci.CredentialProvider{ .getCredentialFn = MockHarness.getCredential };
    const allocator = std.testing.allocator;
    var refs = [_]z_oci.Reference{
        try z_oci.Reference.parse(allocator, "registry-1.docker.io/library/busybox:latest"),
        try z_oci.Reference.parse(allocator, "ghcr.io/owner/busybox:latest"),
    };
    defer for (&refs) |*ref| ref.deinit(allocator);

    var client: std.http.Client = undefined;
    var result = try z_oci.testing.resolveManyWithExchangers(
        allocator,
        &client,
        .{ .credential_provider = &provider },
        refs[0..],
        .{},
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[0]));
    try std.testing.expectEqual(.success, std.meta.activeTag(result.items[1]));
    try std.testing.expect(MockHarness.docker_basic_seen);
    try std.testing.expect(MockHarness.ghcr_basic_seen);
}

test "workflow smoke: public path ignores env credentials unless credential_sources injects them" {
    defer tm.Fixtures.reset(std.testing.allocator);
    const allocator = std.testing.allocator;

    const MockHarness = struct {
        var saw_basic: bool = false;
        var child: ChildArtifacts = undefined;

        fn tokenExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(alloc);
            if (request.authorization) |authorization| {
                if (std.mem.startsWith(u8, authorization, "Basic ")) saw_basic = true;
            }
            return .{ .status = .ok, .body = "{\"access_token\":\"anon-token\",\"expires_in\":3600}" };
        }

        fn manifestExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(alloc);
            if (request.authorization == null) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/app:pull\"",
                    },
                }, null);
            }
            if (!std.mem.eql(u8, request.authorization.?, "Bearer anon-token")) return error.TransportFailed;
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(allocator);
    defer MockHarness.child.deinit(allocator);
    defer {
        MockHarness.saw_basic = false;
    }

    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    try environ_map.put(z_oci.auth.ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(z_oci.auth.ENV_REGISTRY_USER, "env-user");
    try environ_map.put(z_oci.auth.ENV_REGISTRY_TOKEN, "env-token");

    var client: std.http.Client = undefined;

    var anonymous_ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    var anonymous_outcome = try z_oci.testing.resolveWithExchangers(
        allocator,
        &client,
        .{},
        anonymous_ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&anonymous_outcome, allocator, .{ .owned_input = &anonymous_ref });
    try std.testing.expectEqual(.success, std.meta.activeTag(anonymous_outcome));
    try std.testing.expect(!MockHarness.saw_basic);

    MockHarness.saw_basic = false;
    var injected_ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    var injected_outcome = try z_oci.testing.resolveWithExchangers(
        allocator,
        &client,
        .{
            .credential_sources = .{ .environ_map = &environ_map },
        },
        injected_ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&injected_outcome, allocator, .{ .owned_input = &injected_ref });
    try std.testing.expectEqual(.success, std.meta.activeTag(injected_outcome));
    try std.testing.expect(MockHarness.saw_basic);
}

test "workflow smoke: public path uses injected docker_config_json Basic auth" {
    defer tm.Fixtures.reset(std.testing.allocator);
    const allocator = std.testing.allocator;

    const docker_config_json =
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  }
        \\}
    ;

    const MockHarness = struct {
        var saw_expected_basic: bool = false;
        var child: ChildArtifacts = undefined;

        fn tokenExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(alloc);
            const authorization = request.authorization orelse return error.TokenExchangeFailed;
            if (std.mem.eql(u8, authorization, "Basic b2N0b2NhdDpnaHBfZXhhbXBsZQ==")) {
                saw_expected_basic = true;
            }
            return .{ .status = .ok, .body = "{\"access_token\":\"docker-token\",\"expires_in\":3600}" };
        }

        fn manifestExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(alloc);
            if (request.authorization == null) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/app:pull\"",
                    },
                }, null);
            }
            if (!std.mem.eql(u8, request.authorization.?, "Bearer docker-token")) return error.TransportFailed;
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(allocator);
    defer MockHarness.child.deinit(allocator);
    defer {
        MockHarness.saw_expected_basic = false;
    }

    var client: std.http.Client = undefined;
    var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    var outcome = try z_oci.testing.resolveWithExchangers(
        allocator,
        &client,
        .{
            .credential_sources = .{ .docker_config_json = docker_config_json },
        },
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&outcome, allocator, .{ .owned_input = &ref });
    try std.testing.expectEqual(.success, std.meta.activeTag(outcome));
    try std.testing.expect(MockHarness.saw_expected_basic);
}

test "workflow smoke: credential_provider wins over injected environ on public path" {
    defer tm.Fixtures.reset(std.testing.allocator);
    const allocator = std.testing.allocator;

    const MockHarness = struct {
        var saw_provider_basic: bool = false;
        var saw_env_basic: bool = false;
        var child: ChildArtifacts = undefined;

        fn getCredential(registry: []const u8) ?z_oci.CredentialHandle {
            if (!std.mem.eql(u8, registry, "ghcr.io")) return null;
            return .{ .credential = .{ .username = "provider-user", .secret = "provider-secret" } };
        }

        fn tokenExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(alloc);
            const authorization = request.authorization orelse return error.TokenExchangeFailed;
            if (std.mem.eql(u8, authorization, "Basic cHJvdmlkZXItdXNlcjpwcm92aWRlci1zZWNyZXQ=")) {
                saw_provider_basic = true;
            }
            if (std.mem.eql(u8, authorization, "Basic ZW52LXVzZXI6ZW52LXRva2Vu")) {
                saw_env_basic = true;
            }
            return .{ .status = .ok, .body = "{\"access_token\":\"provider-token\",\"expires_in\":3600}" };
        }

        fn manifestExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(alloc);
            if (request.authorization == null) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/app:pull\"",
                    },
                }, null);
            }
            if (!std.mem.eql(u8, request.authorization.?, "Bearer provider-token")) return error.TransportFailed;
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(allocator);
    defer MockHarness.child.deinit(allocator);
    defer {
        MockHarness.saw_provider_basic = false;
        MockHarness.saw_env_basic = false;
    }

    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    try environ_map.put(z_oci.auth.ENV_REGISTRY_HOST, "ghcr.io");
    try environ_map.put(z_oci.auth.ENV_REGISTRY_USER, "env-user");
    try environ_map.put(z_oci.auth.ENV_REGISTRY_TOKEN, "env-token");

    const provider = z_oci.CredentialProvider{ .getCredentialFn = MockHarness.getCredential };

    var client: std.http.Client = undefined;
    var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    var outcome = try z_oci.testing.resolveWithExchangers(
        allocator,
        &client,
        .{
            .credential_provider = &provider,
            .credential_sources = .{ .environ_map = &environ_map },
        },
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&outcome, allocator, .{ .owned_input = &ref });
    try std.testing.expectEqual(.success, std.meta.activeTag(outcome));
    try std.testing.expect(MockHarness.saw_provider_basic);
    try std.testing.expect(!MockHarness.saw_env_basic);
}

test "workflow smoke: invalid docker_config_json is PublicApiError on public path" {
    const allocator = std.testing.allocator;

    var client: std.http.Client = undefined;
    var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    defer ref.deinit(allocator);

    try std.testing.expectError(
        error.InvalidDockerConfig,
        z_oci.testing.resolveWithExchangers(
            allocator,
            &client,
            .{
                .credential_sources = .{ .docker_config_json = "{not-json" },
            },
            ref,
            null,
            tm.refuseTokenExchange,
            struct {
                fn exchange(
                    alloc: std.mem.Allocator,
                    _: *std.http.Client,
                    request: z_oci.testing.ManifestHttpRequest,
                ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
                    defer request.deinit(alloc);
                    return error.TransportFailed;
                }
            }.exchange,
            .{},
        ),
    );
}

test "workflow smoke: load_docker_config_from_environ without Io is CredentialSourcesIncomplete" {
    const allocator = std.testing.allocator;

    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    try environ_map.put(z_oci.auth.HOME_DIR_VAR, "/tmp");

    var client: std.http.Client = undefined;
    var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    defer ref.deinit(allocator);

    try std.testing.expectError(
        error.CredentialSourcesIncomplete,
        z_oci.testing.resolveWithExchangers(
            allocator,
            &client,
            .{
                .credential_sources = .{
                    .environ_map = &environ_map,
                    .load_docker_config_from_environ = true,
                },
            },
            ref,
            null,
            tm.refuseTokenExchange,
            struct {
                fn exchange(
                    alloc: std.mem.Allocator,
                    _: *std.http.Client,
                    request: z_oci.testing.ManifestHttpRequest,
                ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
                    defer request.deinit(alloc);
                    return error.TransportFailed;
                }
            }.exchange,
            .{},
        ),
    );
}

test "workflow smoke: public path helper_runner failure stays terminal on resolveWithExchangers" {
    defer tm.Fixtures.reset(std.testing.allocator);
    const allocator = std.testing.allocator;

    const docker_config_json =
        \\{
        \\  "credHelpers": {
        \\    "ghcr.io": "mock-helper"
        \\  }
        \\}
    ;

    const MockHarness = struct {
        fn failingHelper(
            _: std.mem.Allocator,
            _: std.Io,
            _: []const u8,
            _: []const u8,
            _: std.Io.Timeout,
        ) anyerror!z_oci.CredentialHandle {
            return error.HelperFailed;
        }

        fn tokenExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(alloc);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(alloc);
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                .status = .unauthorized,
                .www_authenticate_headers = &.{
                    "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/app:pull\"",
                },
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    var outcome = try z_oci.testing.resolveWithExchangers(
        allocator,
        &client,
        .{
            .credential_sources = .{
                .docker_config_json = docker_config_json,
                .process_io = std.testing.io,
                .helper_runner = MockHarness.failingHelper,
            },
        },
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&outcome, allocator, .{ .owned_input = &ref });
    try std.testing.expectEqual(.failure, std.meta.activeTag(outcome));
    try std.testing.expectEqual(.auth_failed, std.meta.activeTag(outcome.failure));
}

test "workflow smoke: public path helper_runner timeout maps to ResolveError.timeout" {
    defer tm.Fixtures.reset(std.testing.allocator);
    const allocator = std.testing.allocator;

    const docker_config_json =
        \\{
        \\  "credHelpers": {
        \\    "ghcr.io": "mock-helper"
        \\  }
        \\}
    ;

    const MockHarness = struct {
        fn timeoutHelper(
            _: std.mem.Allocator,
            _: std.Io,
            _: []const u8,
            _: []const u8,
            _: std.Io.Timeout,
        ) anyerror!z_oci.CredentialHandle {
            return error.HelperTimedOut;
        }

        fn tokenExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(alloc);
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(alloc);
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                .status = .unauthorized,
                .www_authenticate_headers = &.{
                    "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/app:pull\"",
                },
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    var outcome = try z_oci.testing.resolveWithExchangers(
        allocator,
        &client,
        .{
            .credential_sources = .{
                .docker_config_json = docker_config_json,
                .process_io = std.testing.io,
                .helper_runner = MockHarness.timeoutHelper,
            },
        },
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&outcome, allocator, .{ .owned_input = &ref });
    try std.testing.expectEqual(.failure, std.meta.activeTag(outcome));
    try std.testing.expectEqual(.timeout, std.meta.activeTag(outcome.failure));
}

test "workflow smoke: public path load_docker_config_from_environ supplies Basic auth" {
    defer tm.Fixtures.reset(std.testing.allocator);
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const ghcr_config_json =
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  }
        \\}
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    {
        var config_dir = try tmp_dir.dir.createDirPathOpen(io, ".docker", .{});
        defer config_dir.close(io);
        const file = try config_dir.createFile(io, "config.json", .{ .read = true });
        defer file.close(io);
        var file_buffer: [512]u8 = undefined;
        var file_writer = file.writer(io, &file_buffer);
        try file_writer.interface.writeAll(ghcr_config_json);
        try file_writer.interface.flush();
    }
    const home_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp_dir.sub_path[0..] });
    defer allocator.free(home_dir);

    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    try environ_map.put(z_oci.auth.HOME_DIR_VAR, home_dir);

    const MockHarness = struct {
        var saw_expected_basic: bool = false;
        var child: ChildArtifacts = undefined;

        fn tokenExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(alloc);
            const authorization = request.authorization orelse return error.TokenExchangeFailed;
            if (std.mem.eql(u8, authorization, "Basic b2N0b2NhdDpnaHBfZXhhbXBsZQ==")) {
                saw_expected_basic = true;
            }
            return .{ .status = .ok, .body = "{\"access_token\":\"docker-token\",\"expires_in\":3600}" };
        }

        fn manifestExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(alloc);
            if (request.authorization == null) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/app:pull\"",
                    },
                }, null);
            }
            if (!std.mem.eql(u8, request.authorization.?, "Bearer docker-token")) return error.TransportFailed;
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(allocator);
    defer MockHarness.child.deinit(allocator);
    defer {
        MockHarness.saw_expected_basic = false;
    }

    var client: std.http.Client = undefined;
    var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
    var outcome = try z_oci.testing.resolveWithExchangers(
        allocator,
        &client,
        .{
            .credential_sources = .{
                .environ_map = &environ_map,
                .load_docker_config_from_environ = true,
                .process_io = io,
            },
        },
        ref,
        null,
        MockHarness.tokenExchange,
        MockHarness.manifestExchange,
        .{},
    );
    defer deinitResolveOutcome(&outcome, allocator, .{ .owned_input = &ref });
    try std.testing.expectEqual(.success, std.meta.activeTag(outcome));
    try std.testing.expect(MockHarness.saw_expected_basic);
}

test "workflow smoke: credential_sources Basic auth works on validate, getManifest, and resolveMany" {
    defer tm.Fixtures.reset(std.testing.allocator);
    const allocator = std.testing.allocator;

    const docker_config_json =
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2N0b2NhdDpnaHBfZXhhbXBsZQ=="
        \\    }
        \\  }
        \\}
    ;

    const MockHarness = struct {
        var basic_token_calls: usize = 0;
        var child: ChildArtifacts = undefined;

        fn tokenExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.auth.TokenHttpRequest,
        ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(alloc);
            const authorization = request.authorization orelse return error.TokenExchangeFailed;
            if (!std.mem.eql(u8, authorization, "Basic b2N0b2NhdDpnaHBfZXhhbXBsZQ==")) {
                return error.TokenExchangeFailed;
            }
            basic_token_calls += 1;
            return .{ .status = .ok, .body = "{\"access_token\":\"docker-token\",\"expires_in\":3600}" };
        }

        fn manifestExchange(
            alloc: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(alloc);
            if (request.authorization == null) {
                return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                    .status = .unauthorized,
                    .www_authenticate_headers = &.{
                        "Bearer realm=\"https://auth.ghcr.test/token\",service=\"ghcr.io\",scope=\"repository:owner/app:pull\"",
                    },
                }, null);
            }
            if (!std.mem.eql(u8, request.authorization.?, "Bearer docker-token")) return error.TransportFailed;
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(alloc, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = child.digest,
            }, child.body);
        }
    };

    MockHarness.child = try ChildArtifacts.alloc(allocator);
    defer MockHarness.child.deinit(allocator);
    defer {
        MockHarness.basic_token_calls = 0;
    }

    const config = z_oci.Config{
        .credential_sources = .{ .docker_config_json = docker_config_json },
    };
    var client: std.http.Client = undefined;

    {
        var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
        defer ref.deinit(allocator);
        const validity = try z_oci.testing.validateWithExchangers(
            allocator,
            &client,
            config,
            ref,
            null,
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );
        defer deinitValidateOutcome(validity, allocator);
        try std.testing.expectEqual(.valid, validity);
    }

    {
        var ref = try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest");
        defer ref.deinit(allocator);
        const manifest_outcome = try z_oci.testing.getManifestWithExchangers(
            allocator,
            &client,
            config,
            ref,
            null,
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );
        defer deinitManifestOutcome(manifest_outcome, allocator);
        try std.testing.expectEqual(.success, std.meta.activeTag(manifest_outcome));
    }

    {
        var refs = [_]z_oci.Reference{
            try z_oci.Reference.parse(allocator, "ghcr.io/owner/app:latest"),
        };
        defer for (&refs) |*ref| ref.deinit(allocator);
        var batch = try z_oci.testing.resolveManyWithExchangers(
            allocator,
            &client,
            config,
            refs[0..],
            .{},
            MockHarness.tokenExchange,
            MockHarness.manifestExchange,
            .{},
        );
        defer batch.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), batch.items.len);
        try std.testing.expectEqual(.success, std.meta.activeTag(batch.items[0]));
    }

    try std.testing.expect(MockHarness.basic_token_calls >= 3);
}
