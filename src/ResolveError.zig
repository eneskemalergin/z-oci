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
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The requested manifest or blob was not found.
pub const NotFound = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The resolution attempt hit a rate limit imposed by the registry.
pub const RateLimited = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
    /// True when reactive transport retries were consumed before this `429`.
    transport_retries_exhausted: bool = false,
};

/// The pulled content digest does not match the requested digest.
pub const DigestMismatch = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// No manifest in the index matched the requested platform.
pub const PlatformNotFound = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The manifest is multi-arch and the caller must provide a platform.
pub const PlatformRequired = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The manifest JSON could not be parsed or failed schema validation.
pub const ManifestParseError = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// A network-level error: DNS failure, TCP timeout, TLS error, etc.
pub const NetworkError = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
    /// True when reactive transport retries were consumed before this failure.
    transport_retries_exhausted: bool = false,
};

/// The digest algorithm in the response is not supported by the resolver.
pub const UnsupportedAlgorithm = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The server returned a Content-Type that does not match what was requested.
pub const ContentTypeMismatch = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The operation exceeded the configured timeout.
pub const Timeout = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
    /// True when reactive transport retries were consumed before this timeout.
    transport_retries_exhausted: bool = false,
};

/// Manifest index nesting exceeded the maximum allowed depth.
/// Prevents unbounded recursion when indices point to other indices.
pub const DepthLimitExceeded = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
    reference: []const u8,
    http_status: ?u16 = null,
};

/// The server response exceeded configured size limits.
pub const ResponseTooLarge = struct {
    /// Registry hostname; borrows from the caller's reference.
    registry: []const u8,
    /// Canonical reference string; caller-owned on public API outcomes.
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
    response_too_large: ResponseTooLarge,

    /// Write a human-readable error description.
    /// Format: "summary: registry <reg> for <ref> [status <N>]"
    pub fn format(self: ResolveError, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const ctx = self.context();
        try w.print("{s}: registry {s} for {s}", .{ self.summary(), ctx.registry, ctx.reference });
        if (ctx.http_status) |status| {
            try w.print(" (HTTP {d})", .{status});
        }
        if (self.transportRetriesExhausted()) {
            try w.writeAll(" after transport retries exhausted");
        }
    }

    fn transportRetriesExhausted(self: ResolveError) bool {
        return switch (self) {
            .rate_limited => |v| v.transport_retries_exhausted,
            .network_error => |v| v.transport_retries_exhausted,
            .timeout => |v| v.transport_retries_exhausted,
            else => false,
        };
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

    /// Free the owned `reference` and clear it in place so the error value cannot
    /// retain a dangling pointer (for storage still live after release).
    pub fn releaseOwnedReference(self: *ResolveError, allocator: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*value| {
                if (value.reference.len != 0) {
                    allocator.free(value.reference);
                    value.reference = "";
                }
            },
        }
    }

    /// Rebuild the error with a caller-owned `reference` string.
    pub fn withOwnedReference(self: ResolveError, owned_reference: []const u8) ResolveError {
        return switch (self) {
            .auth_failed => |value| .{ .auth_failed = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .not_found => |value| .{ .not_found = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .rate_limited => |value| .{ .rate_limited = .{
                .registry = value.registry,
                .reference = owned_reference,
                .http_status = value.http_status,
                .transport_retries_exhausted = value.transport_retries_exhausted,
            } },
            .digest_mismatch => |value| .{ .digest_mismatch = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .platform_not_found => |value| .{ .platform_not_found = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .platform_required => |value| .{ .platform_required = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .manifest_parse_error => |value| .{ .manifest_parse_error = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .network_error => |value| .{ .network_error = .{
                .registry = value.registry,
                .reference = owned_reference,
                .http_status = value.http_status,
                .transport_retries_exhausted = value.transport_retries_exhausted,
            } },
            .unsupported_algorithm => |value| .{ .unsupported_algorithm = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .content_type_mismatch => |value| .{ .content_type_mismatch = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .timeout => |value| .{ .timeout = .{
                .registry = value.registry,
                .reference = owned_reference,
                .http_status = value.http_status,
                .transport_retries_exhausted = value.transport_retries_exhausted,
            } },
            .depth_limit_exceeded => |value| .{ .depth_limit_exceeded = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
            .response_too_large => |value| .{ .response_too_large = .{ .registry = value.registry, .reference = owned_reference, .http_status = value.http_status } },
        };
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

    fn summary(self: ResolveError) []const u8 {
        return switch (self) {
            .auth_failed => "authentication failed",
            .not_found => "manifest not found",
            .rate_limited => "rate limited",
            .digest_mismatch => "digest mismatch",
            .platform_not_found => "platform not found",
            .platform_required => "platform required",
            .manifest_parse_error => "manifest parse error",
            .network_error => "network error",
            .unsupported_algorithm => "unsupported digest algorithm",
            .content_type_mismatch => "content type mismatch",
            .timeout => "timeout",
            .depth_limit_exceeded => "depth limit exceeded",
            .response_too_large => "response too large",
        };
    }
};

// Tests

test "ResolveError.format: spot-checks summary, context, and HTTP status" {
    const cases = [_]struct {
        err: ResolveError,
        summary: []const u8,
        expect_http: bool,
        expect_registry: []const u8,
        expect_ref_fragment: []const u8,
    }{
        .{
            .err = .{ .auth_failed = .{
                .registry = "ghcr.io",
                .reference = "ghcr.io/owner/repo:v1",
                .http_status = 401,
            } },
            .summary = "authentication failed",
            .expect_http = true,
            .expect_registry = "ghcr.io",
            .expect_ref_fragment = "owner/repo",
        },
        .{
            .err = .{ .not_found = .{
                .registry = "registry-1.docker.io",
                .reference = "library/ubuntu:latest",
            } },
            .summary = "manifest not found",
            .expect_http = false,
            .expect_registry = "registry-1.docker.io",
            .expect_ref_fragment = "ubuntu",
        },
        .{
            .err = .{ .auth_failed = .{
                .registry = "r",
                .reference = "ref",
            } },
            .summary = "authentication failed",
            .expect_http = false,
            .expect_registry = "r",
            .expect_ref_fragment = "ref",
        },
        .{
            .err = .{ .auth_failed = .{
                .registry = "r",
                .reference = "ref",
                .http_status = 401,
            } },
            .summary = "authentication failed",
            .expect_http = true,
            .expect_registry = "r",
            .expect_ref_fragment = "ref",
        },
    };
    for (cases) |tc| {
        var buf: [256]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try tc.err.format(&w);
        const out = w.buffered();
        try std.testing.expect(std.mem.startsWith(u8, out, tc.summary));
        try std.testing.expect(std.mem.indexOf(u8, out, tc.expect_registry) != null);
        try std.testing.expect(std.mem.indexOf(u8, out, tc.expect_ref_fragment) != null);
        if (tc.expect_http) {
            try std.testing.expect(std.mem.indexOf(u8, out, "HTTP") != null);
        } else {
            try std.testing.expect(std.mem.indexOf(u8, out, "HTTP") == null);
        }
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

test "ResolveError.format: all variants include a plain summary" {
    const cases = [_]struct { err: ResolveError, summary: []const u8 }{
        .{ .err = .{ .auth_failed = .{ .registry = "r", .reference = "ref" } }, .summary = "authentication failed" },
        .{ .err = .{ .not_found = .{ .registry = "r", .reference = "ref" } }, .summary = "manifest not found" },
        .{ .err = .{ .rate_limited = .{ .registry = "r", .reference = "ref" } }, .summary = "rate limited" },
        .{ .err = .{ .digest_mismatch = .{ .registry = "r", .reference = "ref" } }, .summary = "digest mismatch" },
        .{ .err = .{ .platform_not_found = .{ .registry = "r", .reference = "ref" } }, .summary = "platform not found" },
        .{ .err = .{ .platform_required = .{ .registry = "r", .reference = "ref" } }, .summary = "platform required" },
        .{ .err = .{ .manifest_parse_error = .{ .registry = "r", .reference = "ref" } }, .summary = "manifest parse error" },
        .{ .err = .{ .network_error = .{ .registry = "r", .reference = "ref" } }, .summary = "network error" },
        .{ .err = .{ .unsupported_algorithm = .{ .registry = "r", .reference = "ref" } }, .summary = "unsupported digest algorithm" },
        .{ .err = .{ .content_type_mismatch = .{ .registry = "r", .reference = "ref" } }, .summary = "content type mismatch" },
        .{ .err = .{ .timeout = .{ .registry = "r", .reference = "ref" } }, .summary = "timeout" },
        .{ .err = .{ .depth_limit_exceeded = .{ .registry = "r", .reference = "ref" } }, .summary = "depth limit exceeded" },
        .{ .err = .{ .response_too_large = .{ .registry = "r", .reference = "ref" } }, .summary = "response too large" },
    };
    for (cases) |tc| {
        var buf: [256]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try tc.err.format(&w);
        try std.testing.expect(std.mem.startsWith(u8, w.buffered(), tc.summary));
    }
}

test "ResolveError.format: HTTP status appears only when set" {
    const without = ResolveError{ .auth_failed = .{
        .registry = "r",
        .reference = "ref",
    } };
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try without.format(&w);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "HTTP") == null);

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

test "ResolveError.withOwnedReference: preserves registry, status, and transport flags" {
    const owned = "library/busybox:latest";
    const cases = [_]struct { input: ResolveError, tag: std.meta.Tag(ResolveError) }{
        .{ .input = .{ .auth_failed = .{ .registry = "ghcr.io", .reference = "old", .http_status = 401 } }, .tag = .auth_failed },
        .{ .input = .{ .rate_limited = .{ .registry = "r", .reference = "old", .http_status = 429, .transport_retries_exhausted = true } }, .tag = .rate_limited },
        .{ .input = .{ .network_error = .{ .registry = "r", .reference = "old", .transport_retries_exhausted = true } }, .tag = .network_error },
        .{ .input = .{ .timeout = .{ .registry = "r", .reference = "old", .http_status = 504, .transport_retries_exhausted = false } }, .tag = .timeout },
    };
    for (cases) |tc| {
        const rebuilt = tc.input.withOwnedReference(owned);
        try std.testing.expectEqual(tc.tag, std.meta.activeTag(rebuilt));
        const ctx = rebuilt.context();
        try std.testing.expectEqualSlices(u8, tc.input.context().registry, ctx.registry);
        try std.testing.expectEqualSlices(u8, owned, ctx.reference);
        try std.testing.expectEqual(tc.input.context().http_status, ctx.http_status);
        switch (rebuilt) {
            .rate_limited => |v| try std.testing.expectEqual(tc.input.rate_limited.transport_retries_exhausted, v.transport_retries_exhausted),
            .network_error => |v| try std.testing.expectEqual(tc.input.network_error.transport_retries_exhausted, v.transport_retries_exhausted),
            .timeout => |v| try std.testing.expectEqual(tc.input.timeout.transport_retries_exhausted, v.transport_retries_exhausted),
            else => {},
        }
    }
}

test "ResolveError lifecycle: deinitOwned and releaseOwnedReference on transport variants" {
    const variants = [_]ResolveError{
        .{ .rate_limited = .{ .registry = "registry-1.docker.io", .reference = "" } },
        .{ .network_error = .{ .registry = "registry-1.docker.io", .reference = "" } },
        .{ .timeout = .{ .registry = "registry-1.docker.io", .reference = "" } },
        .{ .platform_required = .{ .registry = "registry-1.docker.io", .reference = "" } },
    };
    for (variants) |template| {
        var gpa = std.heap.DebugAllocator(.{}){};
        defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
        const alloc = gpa.allocator();

        const owned_reference = try alloc.dupe(u8, "library/busybox:latest");
        var err = template.withOwnedReference(owned_reference);
        err.deinitOwned(alloc);

        const owned_reference2 = try alloc.dupe(u8, "library/alpine:latest");
        var err2 = template.withOwnedReference(owned_reference2);
        err2.releaseOwnedReference(alloc);
        const ctx = err2.context();
        try std.testing.expect(ctx.reference.len == 0);
    }
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

test "ResolveError.format: transport retry exhaustion suffix on retry-related failures" {
    const cases = [_]struct { err: ResolveError, expect_suffix: bool }{
        .{ .err = .{ .rate_limited = .{
            .registry = "registry-1.docker.io",
            .reference = "library/busybox:latest",
            .http_status = 429,
            .transport_retries_exhausted = true,
        } }, .expect_suffix = true },
        .{ .err = .{ .network_error = .{
            .registry = "registry-1.docker.io",
            .reference = "library/busybox:latest",
            .transport_retries_exhausted = true,
        } }, .expect_suffix = true },
        .{ .err = .{ .timeout = .{
            .registry = "registry-1.docker.io",
            .reference = "library/busybox:latest",
            .transport_retries_exhausted = true,
        } }, .expect_suffix = true },
        .{ .err = .{ .network_error = .{
            .registry = "registry-1.docker.io",
            .reference = "library/busybox:latest",
            .transport_retries_exhausted = false,
        } }, .expect_suffix = false },
        .{ .err = .{ .timeout = .{
            .registry = "registry-1.docker.io",
            .reference = "library/busybox:latest",
            .transport_retries_exhausted = false,
        } }, .expect_suffix = false },
    };
    for (cases) |tc| {
        var buf: [256]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try tc.err.format(&w);
        const out = w.buffered();
        const has_suffix = std.mem.indexOf(u8, out, "after transport retries exhausted") != null;
        try std.testing.expectEqual(tc.expect_suffix, has_suffix);
    }
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
