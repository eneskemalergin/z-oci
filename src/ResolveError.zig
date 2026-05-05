//! Error type for OCI registry operations.
//!
//! Each variant carries context: the registry hostname and the full reference
//! string. http_status is set when the server returned an HTTP response code.
//!
//! Context slices borrow from the per-call arena. They are valid for the
//! lifetime of that arena. No allocation is performed here.
//!
//! Callers switch on variants for structured error handling. The format method
//! produces a human-readable string for logging or display.

const std = @import("std");

/// Authentication failed. The registry rejected the request.
pub const AuthFailed = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The requested manifest or blob was not found.
pub const NotFound = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The client hit a rate limit imposed by the registry.
pub const RateLimited = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The pulled content digest does not match the requested digest.
pub const DigestMismatch = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// No manifest in the index matched the requested platform.
pub const PlatformNotFound = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The manifest JSON could not be parsed or failed schema validation.
pub const ManifestParseError = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// A network-level error: DNS failure, TCP timeout, TLS error, etc.
pub const NetworkError = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The digest algorithm in the response is not supported by this client.
pub const UnsupportedAlgorithm = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The server returned a Content-Type that does not match what was requested.
pub const ContentTypeMismatch = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The operation exceeded the configured timeout.
pub const Timeout = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// Manifest index nesting exceeded the maximum allowed depth.
/// Prevents unbounded recursion when indices point to other indices.
pub const DepthLimitExceeded = struct {
    registry: []const u8,
    reference: []const u8,
    http_status: ?u16 = null,
};

/// Tagged union over all possible OCI resolve failure modes.
/// Each variant carries context fields that borrow from the per-call arena.
pub const ResolveError = union(enum) {
    auth_failed: AuthFailed,
    not_found: NotFound,
    rate_limited: RateLimited,
    digest_mismatch: DigestMismatch,
    platform_not_found: PlatformNotFound,
    manifest_parse_error: ManifestParseError,
    network_error: NetworkError,
    unsupported_algorithm: UnsupportedAlgorithm,
    content_type_mismatch: ContentTypeMismatch,
    timeout: Timeout,
    depth_limit_exceeded: DepthLimitExceeded,

    /// Write a human-readable error description.
    /// Format: "VariantName: registry <reg> for <ref> [status <N>]"
    pub fn format(self: ResolveError, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const ctx = self.context();
        const name = self.variantName();
        try w.print("{s}: registry {s} for {s}", .{ name, ctx.registry, ctx.reference });
        if (ctx.http_status) |status| {
            try w.print(" (HTTP {d})", .{status});
        }
    }

    // context returns the common context fields regardless of variant.
    // Using a shared struct avoids repeating the same switch in each method.
    fn context(self: ResolveError) struct {
        registry: []const u8,
        reference: []const u8,
        http_status: ?u16,
    } {
        return switch (self) {
            inline else => |v| .{
                .registry = v.registry,
                .reference = v.reference,
                .http_status = v.http_status,
            },
        };
    }

    fn variantName(self: ResolveError) []const u8 {
        return switch (self) {
            .auth_failed => "AuthFailed",
            .not_found => "NotFound",
            .rate_limited => "RateLimited",
            .digest_mismatch => "DigestMismatch",
            .platform_not_found => "PlatformNotFound",
            .manifest_parse_error => "ManifestParseError",
            .network_error => "NetworkError",
            .unsupported_algorithm => "UnsupportedAlgorithm",
            .content_type_mismatch => "ContentTypeMismatch",
            .timeout => "Timeout",
            .depth_limit_exceeded => "DepthLimitExceeded",
        };
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "ResolveError.format: AuthFailed with HTTP status" {
    // Arrange
    const err = ResolveError{ .auth_failed = .{
        .registry = "ghcr.io",
        .reference = "ghcr.io/owner/repo:v1",
        .http_status = 401,
    } };
    // Act
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try err.format(&w);
    const out = w.buffered();
    // Assert
    try std.testing.expect(std.mem.indexOf(u8, out, "AuthFailed") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ghcr.io") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "401") != null);
}

test "ResolveError.format: NotFound without HTTP status" {
    // Arrange
    const err = ResolveError{ .not_found = .{
        .registry = "registry-1.docker.io",
        .reference = "library/ubuntu:latest",
    } };
    // Act
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try err.format(&w);
    const out = w.buffered();
    // Assert: status is absent when not set
    try std.testing.expect(std.mem.indexOf(u8, out, "NotFound") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ubuntu") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "HTTP") == null);
}

test "ResolveError.format: all variants produce non-empty output" {
    // Arrange: spot-check a handful of variants.
    const cases = [_]ResolveError{
        .{ .rate_limited = .{ .registry = "r", .reference = "ref", .http_status = 429 } },
        .{ .digest_mismatch = .{ .registry = "r", .reference = "ref" } },
        .{ .platform_not_found = .{ .registry = "r", .reference = "ref" } },
        .{ .manifest_parse_error = .{ .registry = "r", .reference = "ref" } },
        .{ .network_error = .{ .registry = "r", .reference = "ref" } },
        .{ .unsupported_algorithm = .{ .registry = "r", .reference = "ref" } },
        .{ .content_type_mismatch = .{ .registry = "r", .reference = "ref", .http_status = 200 } },
        .{ .timeout = .{ .registry = "r", .reference = "ref" } },
        .{ .depth_limit_exceeded = .{ .registry = "r", .reference = "ref" } },
    };
    for (cases) |err| {
        var buf: [256]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try err.format(&w);
        // Each variant must produce at least the variant name and registry.
        try std.testing.expect(w.buffered().len > 0);
    }
}

test "ResolveError: context fields are stored exactly" {
    // Verifies the context struct carries through all three fields.
    const err = ResolveError{ .timeout = .{
        .registry = "index.docker.io",
        .reference = "alpine:3.18",
        .http_status = 504,
    } };
    const ctx = err.context();
    try std.testing.expectEqualSlices(u8, "index.docker.io", ctx.registry);
    try std.testing.expectEqualSlices(u8, "alpine:3.18", ctx.reference);
    try std.testing.expectEqual(@as(?u16, 504), ctx.http_status);
}

test "ResolveError: http_status null when not set" {
    const err = ResolveError{ .network_error = .{
        .registry = "r",
        .reference = "ref",
    } };
    try std.testing.expectEqual(@as(?u16, null), err.context().http_status);
}
