//! Error type for OCI registry resolution operations.
//!
//! Each variant carries context: the registry hostname and the full reference
//! string. http_status is set when the server returned an HTTP response code.
//!
//! Ownership (single-resolve / `validate` / `getManifest` failures):
//! - `reference` is owned by the caller allocator. Free it with `deinitOwned()`
//!   (or `z_oci.deinitResolveFailure`).
//! - `registry` **borrows** the input `Reference.registry`. Keep that input
//!   `Reference` alive until after you finish reading or formatting the error.
//!   Do not `Reference.deinit` the input before logging the failure.
//!
//! Ownership (batch / `resolveMany` item failures):
//! - Both `registry` and `reference` are owned. Free them only through
//!   `ResolveManyItem.deinit` or `ResolveManyResult.deinit`.
//! - Do **not** call `deinitOwned` / `z_oci.deinitResolveFailure` on a batch
//!   failure: that frees `reference` only and leaks the owned `registry`.
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

    /// Release the owned `reference` string carried by **single-resolve** public
    /// failures (`resolve` / `validate` / `getManifest`).
    ///
    /// Does **not** free `registry` (borrowed from the input `Reference` on those
    /// APIs). Do not use this on `resolveMany` item failures: those own `registry`
    /// as well; use `ResolveManyItem.deinit` / `ResolveManyResult.deinit` instead.
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

// --- Test helpers ---

fn formatBuffered(err: ResolveError, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try err.format(&w);
    return w.buffered();
}

fn testErr(
    tag: std.meta.Tag(ResolveError),
    ctx: struct {
        registry: []const u8 = "ghcr.io",
        reference: []const u8 = "ghcr.io/owner/repo:v1",
        http_status: ?u16 = null,
        transport_retries_exhausted: bool = false,
    },
) ResolveError {
    return switch (tag) {
        .auth_failed => .{ .auth_failed = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .not_found => .{ .not_found = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .rate_limited => .{ .rate_limited = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
            .transport_retries_exhausted = ctx.transport_retries_exhausted,
        } },
        .digest_mismatch => .{ .digest_mismatch = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .platform_not_found => .{ .platform_not_found = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .platform_required => .{ .platform_required = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .manifest_parse_error => .{ .manifest_parse_error = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .network_error => .{ .network_error = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
            .transport_retries_exhausted = ctx.transport_retries_exhausted,
        } },
        .unsupported_algorithm => .{ .unsupported_algorithm = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .content_type_mismatch => .{ .content_type_mismatch = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .timeout => .{ .timeout = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
            .transport_retries_exhausted = ctx.transport_retries_exhausted,
        } },
        .depth_limit_exceeded => .{ .depth_limit_exceeded = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
        .response_too_large => .{ .response_too_large = .{
            .registry = ctx.registry,
            .reference = ctx.reference,
            .http_status = ctx.http_status,
        } },
    };
}

const all_tags = [_]std.meta.Tag(ResolveError){
    .auth_failed,
    .not_found,
    .rate_limited,
    .digest_mismatch,
    .platform_not_found,
    .platform_required,
    .manifest_parse_error,
    .network_error,
    .unsupported_algorithm,
    .content_type_mismatch,
    .timeout,
    .depth_limit_exceeded,
    .response_too_large,
};

// --- Tests ---

test "ResolveError.format: every variant summary, HTTP status, transport suffix, and long context" {
    const summaries = [_]struct { tag: std.meta.Tag(ResolveError), summary: []const u8 }{
        .{ .tag = .auth_failed, .summary = "authentication failed" },
        .{ .tag = .not_found, .summary = "manifest not found" },
        .{ .tag = .rate_limited, .summary = "rate limited" },
        .{ .tag = .digest_mismatch, .summary = "digest mismatch" },
        .{ .tag = .platform_not_found, .summary = "platform not found" },
        .{ .tag = .platform_required, .summary = "platform required" },
        .{ .tag = .manifest_parse_error, .summary = "manifest parse error" },
        .{ .tag = .network_error, .summary = "network error" },
        .{ .tag = .unsupported_algorithm, .summary = "unsupported digest algorithm" },
        .{ .tag = .content_type_mismatch, .summary = "content type mismatch" },
        .{ .tag = .timeout, .summary = "timeout" },
        .{ .tag = .depth_limit_exceeded, .summary = "depth limit exceeded" },
        .{ .tag = .response_too_large, .summary = "response too large" },
    };
    var buf: [1024]u8 = undefined;
    for (summaries) |row| {
        const err = testErr(row.tag, .{ .registry = "registry-1.docker.io", .reference = "library/ubuntu:latest" });
        const out = try formatBuffered(err, &buf);
        try std.testing.expect(std.mem.startsWith(u8, out, row.summary));
        try std.testing.expect(std.mem.indexOf(u8, out, "registry-1.docker.io") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "library/ubuntu:latest") != null);
    }

    const without_http = try formatBuffered(testErr(.auth_failed, .{}), &buf);
    try std.testing.expect(std.mem.indexOf(u8, without_http, "HTTP") == null);

    const with_http = try formatBuffered(testErr(.auth_failed, .{ .http_status = 401 }), &buf);
    try std.testing.expect(std.mem.indexOf(u8, with_http, "HTTP 401") != null);

    const transport_cases = [_]struct { tag: std.meta.Tag(ResolveError), exhausted: bool }{
        .{ .tag = .rate_limited, .exhausted = true },
        .{ .tag = .network_error, .exhausted = true },
        .{ .tag = .timeout, .exhausted = true },
        .{ .tag = .network_error, .exhausted = false },
        .{ .tag = .timeout, .exhausted = false },
    };
    for (transport_cases) |tc| {
        const err = testErr(tc.tag, .{ .transport_retries_exhausted = tc.exhausted });
        const out = try formatBuffered(err, &buf);
        const has_suffix = std.mem.indexOf(u8, out, "after transport retries exhausted") != null;
        try std.testing.expectEqual(tc.exhausted, has_suffix);
    }

    const long_reg = "a" ** 200;
    const long_ref = "b" ** 200;
    const long_out = try formatBuffered(testErr(.rate_limited, .{
        .registry = long_reg,
        .reference = long_ref,
        .http_status = 429,
    }), &buf);
    try std.testing.expect(std.mem.indexOf(u8, long_out, long_reg) != null);
    try std.testing.expect(std.mem.indexOf(u8, long_out, long_ref) != null);
}

test "ResolveError.withOwnedReference: swaps reference on every variant preserving other fields" {
    const owned = "library/busybox:latest";
    for (all_tags) |tag| {
        const input = testErr(tag, .{
            .registry = "index.docker.io",
            .reference = "old",
            .http_status = 503,
            .transport_retries_exhausted = true,
        });
        const rebuilt = input.withOwnedReference(owned);
        try std.testing.expectEqual(tag, std.meta.activeTag(rebuilt));
        const ctx = rebuilt.context();
        try std.testing.expectEqualSlices(u8, "index.docker.io", ctx.registry);
        try std.testing.expectEqualSlices(u8, owned, ctx.reference);
        try std.testing.expectEqual(@as(?u16, 503), ctx.http_status);
        switch (rebuilt) {
            .rate_limited => |v| try std.testing.expect(v.transport_retries_exhausted),
            .network_error => |v| try std.testing.expect(v.transport_retries_exhausted),
            .timeout => |v| try std.testing.expect(v.transport_retries_exhausted),
            else => {},
        }
    }
}

test "ResolveError lifecycle: deinitOwned frees and releaseOwnedReference clears reference" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const alloc = gpa.allocator();

    const owned = try alloc.dupe(u8, "library/busybox:latest");
    var freed = testErr(.not_found, .{ .reference = "old" }).withOwnedReference(owned);
    freed.deinitOwned(alloc);

    const owned2 = try alloc.dupe(u8, "library/alpine:latest");
    var cleared = testErr(.rate_limited, .{
        .transport_retries_exhausted = true,
    }).withOwnedReference(owned2);
    cleared.releaseOwnedReference(alloc);
    try std.testing.expectEqual(@as(usize, 0), cleared.rate_limited.reference.len);
}
