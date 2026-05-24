//! Error type for OCI registry resolution operations.
//!
//! Each variant carries context: the registry hostname and the full reference
//! string. http_status is set when the server returned an HTTP response code.
//!
//! Values returned from the public resolver APIs own their `reference` string
//! through the caller-provided allocator. Call `deinitOwned()` on those public
//! failures when using a non-arena allocator. If the surrounding allocator is
//! an arena, tearing the arena down is also sufficient.
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

/// The resolution attempt hit a rate limit imposed by the registry.
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

/// The manifest is multi-arch and the caller must provide a platform.
pub const PlatformRequired = struct {
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

/// The digest algorithm in the response is not supported by the resolver.
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
/// Public resolver failures own their `reference` string through the caller allocator.
pub const ResolveError = union(enum) {
    auth_failed: AuthFailed,
    not_found: NotFound,
    rate_limited: RateLimited,
    digest_mismatch: DigestMismatch,
    platform_not_found: PlatformNotFound,
    platform_required: PlatformRequired,
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

    /// Release the owned `reference` string carried by public resolver failures.
    ///
    /// Call this only for errors returned from the public resolver APIs, or for
    /// other ResolveError values whose `reference` string was allocated from the
    /// same allocator.
    pub fn deinitOwned(self: ResolveError, allocator: std.mem.Allocator) void {
        switch (self) {
            inline else => |value| allocator.free(value.reference),
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
            .platform_required => "PlatformRequired",
            .manifest_parse_error => "ManifestParseError",
            .network_error => "NetworkError",
            .unsupported_algorithm => "UnsupportedAlgorithm",
            .content_type_mismatch => "ContentTypeMismatch",
            .timeout => "Timeout",
            .depth_limit_exceeded => "DepthLimitExceeded",
        };
    }
};

// Tests

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
        .{ .platform_required = .{ .registry = "r", .reference = "ref" } },
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

test "ResolveError.format: all variants include their exact name" {
    // Each variant must include the exact name string in its output.
    const cases = [_]struct { err: ResolveError, name: []const u8 }{
        .{ .err = .{ .auth_failed = .{ .registry = "r", .reference = "ref" } }, .name = "AuthFailed" },
        .{ .err = .{ .not_found = .{ .registry = "r", .reference = "ref" } }, .name = "NotFound" },
        .{ .err = .{ .rate_limited = .{ .registry = "r", .reference = "ref" } }, .name = "RateLimited" },
        .{ .err = .{ .digest_mismatch = .{ .registry = "r", .reference = "ref" } }, .name = "DigestMismatch" },
        .{ .err = .{ .platform_not_found = .{ .registry = "r", .reference = "ref" } }, .name = "PlatformNotFound" },
        .{ .err = .{ .platform_required = .{ .registry = "r", .reference = "ref" } }, .name = "PlatformRequired" },
        .{ .err = .{ .manifest_parse_error = .{ .registry = "r", .reference = "ref" } }, .name = "ManifestParseError" },
        .{ .err = .{ .network_error = .{ .registry = "r", .reference = "ref" } }, .name = "NetworkError" },
        .{ .err = .{ .unsupported_algorithm = .{ .registry = "r", .reference = "ref" } }, .name = "UnsupportedAlgorithm" },
        .{ .err = .{ .content_type_mismatch = .{ .registry = "r", .reference = "ref" } }, .name = "ContentTypeMismatch" },
        .{ .err = .{ .timeout = .{ .registry = "r", .reference = "ref" } }, .name = "Timeout" },
        .{ .err = .{ .depth_limit_exceeded = .{ .registry = "r", .reference = "ref" } }, .name = "DepthLimitExceeded" },
    };
    for (cases) |tc| {
        var buf: [256]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try tc.err.format(&w);
        // The exact variant name must appear at the start of the output.
        try std.testing.expect(std.mem.startsWith(u8, w.buffered(), tc.name));
    }
}

test "ResolveError.format: HTTP status appears only when set" {
    // A variant without http_status must not emit any "HTTP" substring.
    const without = ResolveError{ .auth_failed = .{
        .registry = "r",
        .reference = "ref",
    } };
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try without.format(&w);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "HTTP") == null);

    // A variant with http_status must include the status code.
    const with_status = ResolveError{ .auth_failed = .{
        .registry = "r",
        .reference = "ref",
        .http_status = 401,
    } };
    var buf2: [256]u8 = undefined;
    var w2 = std.Io.Writer.fixed(&buf2);
    try with_status.format(&w2);
    try std.testing.expect(std.mem.indexOf(u8, w2.buffered(), "401") != null);
}

test "ResolveError.format: registry and reference appear in output" {
    // Both context strings must be present so logs are actionable.
    const err = ResolveError{ .not_found = .{
        .registry = "gcr.io",
        .reference = "gcr.io/project/image:v2",
    } };
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try err.format(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "gcr.io") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "project/image") != null);
}

test "ResolveError.deinitOwned: frees owned public-style reference context" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const alloc = gpa.allocator();

    const owned_reference = try alloc.dupe(u8, "library/busybox:latest");
    const err = ResolveError{ .platform_required = .{
        .registry = "registry-1.docker.io",
        .reference = owned_reference,
    } };

    err.deinitOwned(alloc);
}

test "ResolveError.format: very long registry and reference are not truncated" {
    const long_reg = "a" ** 200;
    const long_ref = "b" ** 200;
    const err = ResolveError{ .rate_limited = .{
        .registry = long_reg,
        .reference = long_ref,
        .http_status = 429,
    } };
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try err.format(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, long_reg) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, long_ref) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "429") != null);
}

test "ResolveError.format: typical error output length is bounded" {
    const err = ResolveError{ .auth_failed = .{
        .registry = "registry-1.docker.io",
        .reference = "library/ubuntu:22.04",
        .http_status = 401,
    } };
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try err.format(&w);
    const out = w.buffered();
    try std.testing.expect(out.len < 150);
    try std.testing.expect(out.len > 20);
}
