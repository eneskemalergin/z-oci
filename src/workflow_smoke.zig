//! Small workflow smoke matrix.
//!
//! These tests sit above the owning unit tests and below any future integration
//! layer. They exercise the current toolkit the way a real user would: parse a
//! fixture, derive a reference URL component, select a platform, call the
//! public resolver surface with injected transports, and keep a cloned result
//! alive past arena teardown.

const std = @import("std");
const z_oci = @import("z_oci");

const WorkflowFailureScenario = enum {
    network_error,
    auth_failed,
    content_type_mismatch,
    manifest_parse_error,
    digest_mismatch,
    unsupported_algorithm,
};

const WorkflowResponseBodyKind = enum {
    none,
    malformed_manifest_fixture,
    manifest_fixture,
};

const WorkflowResponsePlan = struct {
    status: std.http.Status,
    content_type: ?[]const u8 = null,
    docker_content_digest: ?[]const u8 = null,
    body_kind: WorkflowResponseBodyKind = .none,
    malformed_auth_header: bool = false,
};

const WORKFLOW_PUBLIC_RESOLVE_FAILURE_SCENARIOS = [_]WorkflowFailureScenario{
    .network_error,
    .auth_failed,
    .content_type_mismatch,
    .manifest_parse_error,
    .digest_mismatch,
    .unsupported_algorithm,
};

// Kept local on purpose: workflow_smoke builds as its own root module under
// `zig build test`, so importing test_support.zig here would make that file
// belong to two modules at once.
fn parseWorkflowFixture(comptime T: type, path: []const u8, comptime max_bytes: usize) !std.json.Parsed(T) {
    var bytes_buffer: [max_bytes + 1]u8 = undefined;
    const bytes = try std.Io.Dir.cwd().readFile(std.testing.io, path, &bytes_buffer);
    if (bytes.len > max_bytes) return error.StreamTooLong;

    return z_oci.json.parse(T, std.testing.allocator, bytes);
}

fn readWorkflowFixtureAlloc(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(max_bytes));
}

fn sha256DigestStringAlloc(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var digest_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest_bytes, .{});
    const digest_hex = std.fmt.bytesToHex(digest_bytes, .lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{digest_hex[0..]});
}

fn workflowResponsePlan(scenario: WorkflowFailureScenario) WorkflowResponsePlan {
    return switch (scenario) {
        .network_error => .{
            .status = .temporary_redirect,
        },
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
    };
}

fn workflowExpectedTagName(scenario: WorkflowFailureScenario) []const u8 {
    return @tagName(scenario);
}

fn workflowExpectedHttpStatus(scenario: WorkflowFailureScenario) ?u16 {
    return @intCast(@intFromEnum(workflowResponsePlan(scenario).status));
}

fn expectWorkflowResolveFailure(
    failure: z_oci.ResolveError,
    expected_tag_name: []const u8,
    expected_registry: []const u8,
    expected_reference: []const u8,
    expected_http_status: ?u16,
) !void {
    try std.testing.expectEqualStrings(expected_tag_name, @tagName(std.meta.activeTag(failure)));
    switch (failure) {
        inline else => |value| {
            try std.testing.expectEqualSlices(u8, expected_registry, value.registry);
            try std.testing.expectEqualSlices(u8, expected_reference, value.reference);
            try std.testing.expectEqual(expected_http_status, value.http_status);
        },
    }
}

fn buildIndexBodyAlloc(
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

// --- Tests ---

test "workflow smoke: parse manifest fixture and stringify summary fields" {
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

    try std.testing.expect(std.mem.indexOf(u8, out, "\"schemaVersion\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"config\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, parsed.value.config.digest.hex) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"layers\"") != null);
}

test "workflow smoke: parse image reference and derive repository path and ref string" {
    const cases = [_]struct {
        input: []const u8,
        repository_path: []const u8,
        ref_string: []const u8,
    }{
        .{
            .input = "ubuntu:22.04",
            .repository_path = "library/ubuntu",
            .ref_string = "22.04",
        },
        .{
            .input = "registry-1.docker.io/library/busybox@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
            .repository_path = "library/busybox",
            .ref_string = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65",
        },
    };

    for (cases) |case| {
        var ref = try z_oci.Reference.parse(std.testing.allocator, case.input);
        defer ref.deinit(std.testing.allocator);

        try std.testing.expectEqualSlices(u8, case.repository_path, ref.repositoryPath());
        try std.testing.expectEqualSlices(u8, case.ref_string, ref.refString());
    }
}

test "workflow smoke: parse index fixture, select platform, and assert descriptor digest" {
    const parsed = try parseWorkflowFixture(
        z_oci.OciImageIndex,
        "fixtures/indexes/busybox-latest-live-oci-index.json",
        32 * 1024,
    );
    defer parsed.deinit();

    const multi = z_oci.MultiArchManifest{ .oci = parsed.value };
    const selected = multi.filterByPlatform(.{ .os = "linux", .architecture = "arm64", .variant = "v8" });
    try std.testing.expect(selected != null);
    try std.testing.expectEqualSlices(u8, "c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6", selected.?.digest.hex);
}

test "workflow smoke: ResolveResult clone survives arena teardown" {
    var cloned: z_oci.ResolveResult = undefined;
    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        const original = z_oci.ResolveResult{
            .digest = .{
                .algorithm = .sha256,
                .hex = try arena_alloc.dupe(u8, "f" ** 64),
            },
            .media_type = .oci_manifest_v1,
            .platform = .{
                .os = try arena_alloc.dupe(u8, "linux"),
                .architecture = try arena_alloc.dupe(u8, "arm64"),
                .variant = try arena_alloc.dupe(u8, "v8"),
            },
            .reference = .{
                .registry = try arena_alloc.dupe(u8, "registry-1.docker.io"),
                .repository = try arena_alloc.dupe(u8, "library/busybox"),
                .tag = try arena_alloc.dupe(u8, "latest"),
                .digest = null,
                .digest_raw = null,
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

test "workflow smoke: public resolve pins a single-arch manifest" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);

            const body = readWorkflowFixtureAlloc(
                allocator,
                "fixtures/manifests/busybox-amd64-live-oci-manifest.json",
                32 * 1024,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.TransportFailed,
            };
            defer allocator.free(body);

            const digest = try sha256DigestStringAlloc(allocator, body);
            defer allocator.free(digest);

            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_manifest_v1.toString(),
                .docker_content_digest = digest,
            }, body);
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try z_oci.testing.resolveWithExchangers(
        arena.allocator(),
        &client,
        z_oci.Config{},
        ref,
        null,
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );

    switch (outcome) {
        .success => |result| {
            try std.testing.expectEqual(z_oci.MediaType.oci_manifest_v1, result.media_type);
            try std.testing.expect(result.platform == null);
            try std.testing.expectEqualSlices(u8, "registry-1.docker.io", result.reference.registry);
            try std.testing.expectEqualSlices(u8, "library/busybox", result.reference.repository);
            try std.testing.expectEqualSlices(u8, "latest", result.reference.tag.?);
            try std.testing.expect(result.reference.digest != null);
            try std.testing.expect(result.reference.digest_raw != null);
            try std.testing.expectEqualSlices(u8, result.digest.hex, result.reference.digest.?.hex);
            try std.testing.expectEqualSlices(u8, result.reference.digest_raw.?[("sha256:").len..], result.digest.hex);
        },
        .failure => return error.TestUnexpectedResult,
    }
}

test "workflow smoke: public validate follows selected multi-arch child" {
    const State = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;
        var child_body: []u8 = undefined;
        var child_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
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

    State.child_body = try std.testing.allocator.dupe(
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
    defer std.testing.allocator.free(State.child_body);

    State.child_digest = try sha256DigestStringAlloc(std.testing.allocator, State.child_body);
    defer std.testing.allocator.free(State.child_digest);

    State.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        z_oci.MediaType.oci_index_v1.toString(),
        z_oci.MediaType.oci_manifest_v1.toString(),
        State.child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.index_body);

    State.index_digest = try sha256DigestStringAlloc(std.testing.allocator, State.index_body);
    defer std.testing.allocator.free(State.index_digest);

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try z_oci.testing.validateWithExchangers(
        std.testing.allocator,
        &client,
        z_oci.Config{},
        ref,
        .{ .os = "linux", .architecture = "arm64" },
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );

    try std.testing.expectEqual(z_oci.ValidateOutcome.valid, outcome);
}

test "workflow smoke: public getManifest reports platform_required for multi-arch request without platform" {
    const State = struct {
        var index_body: []u8 = undefined;
        var index_digest: []u8 = undefined;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            if (!std.mem.endsWith(u8, request.url, "/manifests/latest")) return error.TransportFailed;

            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .ok,
                .content_type = z_oci.MediaType.oci_index_v1.toString(),
                .docker_content_digest = index_digest,
            }, index_body);
        }
    };

    const child_digest = "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    State.index_body = try buildIndexBodyAlloc(
        std.testing.allocator,
        z_oci.MediaType.oci_index_v1.toString(),
        z_oci.MediaType.oci_manifest_v1.toString(),
        child_digest,
        "linux",
        "arm64",
    );
    defer std.testing.allocator.free(State.index_body);

    State.index_digest = try sha256DigestStringAlloc(std.testing.allocator, State.index_body);
    defer std.testing.allocator.free(State.index_digest);

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try z_oci.testing.getManifestWithExchangers(
        std.testing.allocator,
        &client,
        z_oci.Config{},
        ref,
        null,
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .success => |parsed| {
            parsed.deinit();
            return error.TestUnexpectedResult;
        },
        .failure => |failure| switch (failure) {
            .platform_required => {},
            else => return error.TestUnexpectedResult,
        },
    }
}

test "workflow smoke: public resolve failure matrix preserves full error context" {
    const State = struct {
        var scenario: WorkflowFailureScenario = .network_error;

        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);

            const plan = workflowResponsePlan(scenario);
            const headers: []const []const u8 = if (plan.malformed_auth_header)
                &.{"Bearer realm=\"https://auth.example.test/token"}
            else
                &.{};

            return switch (plan.body_kind) {
                .none => z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                    .status = plan.status,
                    .content_type = plan.content_type,
                    .docker_content_digest = plan.docker_content_digest,
                    .www_authenticate_headers = headers,
                }, null),
                .malformed_manifest_fixture => blk: {
                    const body = readWorkflowFixtureAlloc(
                        allocator,
                        "fixtures/manifests/invalid-truncated-oci-manifest.json",
                        16 * 1024,
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.TransportFailed,
                    };
                    defer allocator.free(body);

                    break :blk z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                        .status = plan.status,
                        .content_type = plan.content_type,
                        .docker_content_digest = plan.docker_content_digest,
                        .www_authenticate_headers = headers,
                    }, body);
                },
                .manifest_fixture => blk: {
                    const body = readWorkflowFixtureAlloc(
                        allocator,
                        "fixtures/manifests/oci-image-manifest-spec-example.json",
                        16 * 1024,
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.TransportFailed,
                    };
                    defer allocator.free(body);

                    break :blk z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                        .status = plan.status,
                        .content_type = plan.content_type,
                        .docker_content_digest = plan.docker_content_digest,
                        .www_authenticate_headers = headers,
                    }, body);
                },
            };
        }
    };

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    for (WORKFLOW_PUBLIC_RESOLVE_FAILURE_SCENARIOS) |scenario| {
        State.scenario = scenario;

        const outcome = try z_oci.testing.resolveWithExchangers(
            std.testing.allocator,
            &client,
            z_oci.Config{},
            ref,
            null,
            State.tokenExchange,
            State.manifestExchange,
            .{},
        );
        defer switch (outcome) {
            .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
            else => {},
        };

        switch (outcome) {
            .success => return error.TestUnexpectedResult,
            .failure => |failure| try expectWorkflowResolveFailure(
                failure,
                workflowExpectedTagName(scenario),
                "registry-1.docker.io",
                "registry-1.docker.io/library/busybox:latest",
                workflowExpectedHttpStatus(scenario),
            ),
        }
    }
}

test "workflow smoke: public resolve maps exhausted token 429 to rate_limited" {
    const State = struct {
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

    defer State.manifest_calls = 0;

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 0 },
        ref,
        null,
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .failure => |failure| try expectWorkflowResolveFailure(
            failure,
            "rate_limited",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            401,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "workflow smoke: public resolve maps exhausted manifest 429 to rate_limited" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .too_many_requests,
                .resilience_headers = &.{
                    .{ .name = "Retry-After", .value = "1" },
                },
            }, null);
        }
    };

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_rate_limit_retries = 0 },
        ref,
        null,
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .failure => |failure| try expectWorkflowResolveFailure(
            failure,
            "rate_limited",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            429,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "workflow smoke: public resolve maps exhausted transport timeout to timeout" {
    const State = struct {
        fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
            return error.TokenExchangeFailed;
        }

        fn manifestExchange(
            allocator: std.mem.Allocator,
            _: *std.http.Client,
            request: z_oci.testing.ManifestHttpRequest,
        ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
            defer request.deinit(allocator);
            return error.Timeout;
        }
    };

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = try z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .max_network_retries = 0 },
        ref,
        null,
        State.tokenExchange,
        State.manifestExchange,
        .{},
    );
    defer switch (outcome) {
        .failure => |failure| z_oci.testing.deinitResolveError(failure, std.testing.allocator),
        else => {},
    };

    switch (outcome) {
        .failure => |failure| try expectWorkflowResolveFailure(
            failure,
            "timeout",
            "registry-1.docker.io",
            "registry-1.docker.io/library/busybox:latest",
            null,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "workflow smoke: public resolve returns CaBundleFileNotFound for missing ca bundle path" {
    if (comptime std.http.Client.disable_tls) return error.SkipZigTest;

    var client = std.http.Client{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer client.deinit();

    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    const outcome = z_oci.testing.resolveWithExchangers(
        std.testing.allocator,
        &client,
        .{ .ca_bundle_path = "/nonexistent/z-oci-ca-bundle.pem" },
        ref,
        null,
        struct {
            fn tokenExchange(_: std.mem.Allocator, _: *std.http.Client, _: z_oci.auth.TokenHttpRequest) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
                return error.TokenExchangeFailed;
            }
        }.tokenExchange,
        struct {
            fn manifestExchange(
                allocator: std.mem.Allocator,
                _: *std.http.Client,
                request: z_oci.testing.ManifestHttpRequest,
            ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
                defer request.deinit(allocator);
                unreachable;
            }
        }.manifestExchange,
        .{},
    );

    try std.testing.expectError(error.CaBundleFileNotFound, outcome);
}
