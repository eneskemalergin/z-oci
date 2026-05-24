const std = @import("std");

pub const Scenario = enum {
    network_error,
    auth_failed,
    content_type_mismatch,
    manifest_parse_error,
    digest_mismatch,
    unsupported_algorithm,
};

pub const BodyKind = enum {
    none,
    empty_manifest,
    manifest_fixture,
};

pub const ResponsePlan = struct {
    status: std.http.Status,
    content_type: ?[]const u8 = null,
    docker_content_digest: ?[]const u8 = null,
    body_kind: BodyKind = .none,
    malformed_auth_header: bool = false,
};

pub const public_resolve_failure_scenarios = [_]Scenario{
    .network_error,
    .auth_failed,
    .content_type_mismatch,
    .manifest_parse_error,
    .digest_mismatch,
    .unsupported_algorithm,
};

pub fn responsePlan(scenario: Scenario) ResponsePlan {
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
            .body_kind = .empty_manifest,
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

pub fn expectedTagName(scenario: Scenario) []const u8 {
    return @tagName(scenario);
}

pub fn expectedHttpStatus(scenario: Scenario) ?u16 {
    return @intCast(@intFromEnum(responsePlan(scenario).status));
}
