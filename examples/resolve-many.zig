//! Offline Zencelot-style pin flow through injected exchangers.
//!
//! Simulates what a caller does with a list of image strings from a pipeline:
//! parse references, resolve the batch with progress and a batch-wide platform,
//! format pinned `registry/repo@sha256:...` lines for successes, and print
//! actionable failure context for partial failures.
//!
//! This is an offline demo, not a production template:
//! - It calls `z_oci.testing.resolveManyWithExchangers`, not public `resolveMany`.
//! - The `std.http.Client` value is intentionally unused because exchangers never
//!   touch it. Live callers must construct a real client with `allocator` and `io`,
//!   then call public `resolveMany` (with credentials/TLS as needed).
//! - Progress callbacks must stay cheap; borrowed reference views are valid only
//!   for the callback duration.
//!
//! Ownership notes:
//! - Parsed input references use `init.gpa` and are deinitialized explicitly.
//! - The returned `ResolveManyResult` is owned; this example calls
//!   `result.deinit(init.gpa)` once after printing every item.
//! - Platform is batch-wide. Callers that need per-item platforms must issue
//!   separate `resolveMany` calls.
//! - The manifest body comes from a checked-in fixture, so the example does not
//!   perform network I/O.

const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const MANIFEST_PATH = "fixtures/manifests/busybox-amd64-live-oci-manifest.json";
const MANIFEST_DIGEST = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65";

const MockRegistry = struct {
    var manifest_body: []const u8 = "";
    var manifest_calls: usize = 0;

    fn tokenExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.auth.TokenHttpRequest,
    ) z_oci.auth.AuthError!z_oci.auth.TokenExchangeResponse {
        request.deinit(allocator);
        return error.TokenExchangeFailed;
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
            .docker_content_digest = MANIFEST_DIGEST,
        }, manifest_body);
    }
};

const ProgressPrinter = struct {
    stdout: *Io.Writer,

    fn progress(event: z_oci.ResolveManyProgress, user_data: ?*anyopaque) void {
        const self: *ProgressPrinter = @ptrCast(@alignCast(user_data.?));
        self.stdout.print(
            "progress[{d}/{d}] {s} registry={s} repository={s} ref={s}\n",
            .{
                event.index + 1,
                event.total,
                @tagName(event.event),
                event.reference.registry,
                event.reference.repository,
                event.reference.ref_string,
            },
        ) catch {};
    }
};

/// Offline batch pin example; see file header for ownership and platform limits.
pub fn main(init: std.process.Init) !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(init.io, &stdout_buffer);
    defer stdout_writer.end() catch {};
    const stdout = &stdout_writer.interface;

    var manifest_buffer: [32 * 1024 + 1]u8 = undefined;
    const manifest_body = try Io.Dir.cwd().readFile(init.io, MANIFEST_PATH, &manifest_buffer);
    if (manifest_body.len > 32 * 1024) return error.StreamTooLong;

    MockRegistry.manifest_body = manifest_body;
    MockRegistry.manifest_calls = 0;

    // Image strings shaped like pipeline.toml [[tasks]] image fields.
    const image_strings = [_][]const u8{
        "registry-1.docker.io/library/busybox",
        "registry-1.docker.io/library/busybox:latest",
        "registry-1.docker.io/library/busybox@" ++ MANIFEST_DIGEST,
        "ghcr.io/owner/busybox:stable",
        "registry-1.docker.io/library/busybox:missing",
    };

    var refs: [image_strings.len]z_oci.Reference = undefined;
    var parsed_count: usize = 0;
    defer for (refs[0..parsed_count]) |*ref| ref.deinit(init.gpa);
    for (image_strings, 0..) |image, index| {
        refs[index] = try z_oci.Reference.parse(init.gpa, image);
        parsed_count += 1;
    }

    var progress_printer = ProgressPrinter{ .stdout = stdout };
    // Offline only: exchangers never use this client. Live callers need a real Client.
    var client: std.http.Client = undefined;
    var result = try z_oci.testing.resolveManyWithExchangers(
        init.gpa,
        &client,
        z_oci.Config{},
        refs[0..],
        .{
            .platform = .{ .os = "linux", .architecture = "amd64" },
            .progress_fn = ProgressPrinter.progress,
            .progress_user_data = @ptrCast(&progress_printer),
        },
        MockRegistry.tokenExchange,
        MockRegistry.manifestExchange,
        .{},
    );
    defer result.deinit(init.gpa);

    try stdout.print("items: {d}\n", .{result.items.len});
    try stdout.print("manifestCalls: {d}\n", .{MockRegistry.manifest_calls});

    var pinned_count: usize = 0;
    var failed_count: usize = 0;
    for (result.items, 0..) |item, index| {
        switch (item) {
            .success => |resolved| {
                pinned_count += 1;
                try stdout.print(
                    "pinned[{d}]: {s}/{s}@{f}\n",
                    .{ index, resolved.reference.registry, resolved.reference.repository, resolved.digest },
                );
            },
            .failure => |failure| {
                failed_count += 1;
                try stdout.print("failed[{d}]: {f}\n", .{ index, failure });
            },
        }
    }

    try stdout.print("pinnedCount: {d}\n", .{pinned_count});
    try stdout.print("failedCount: {d}\n", .{failed_count});
    try stdout.flush();

    // Fail closed so examples-smoke catches silent regressions in the pin demo.
    if (result.items.len != 5 or pinned_count != 4 or failed_count != 1 or MockRegistry.manifest_calls != 4) {
        return error.UnexpectedPinFlowCounts;
    }
}
