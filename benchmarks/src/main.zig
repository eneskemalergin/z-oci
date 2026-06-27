const std = @import("std");
const Io = std.Io;
const z_oci = @import("z_oci");

const usage =
    \\usage: z-oci-bench <operation> [options]
    \\
    \\Operations:
    \\  reference-parse   Reference.parse throughput
    \\  digest-parse      Digest.parse throughput
    \\  manifest-parse    json.parse(Manifest) throughput
    \\  challenge-parse   parseAuthenticateHeader throughput
    \\  platform-match    Platform.match throughput
    \\  authenticate-miss AuthEngine.authenticate (cache miss per iteration)
    \\  authenticate-hit  AuthEngine.authenticate (cached token, second call)
    \\  authenticate-rate-limit AuthEngine.authenticate (429 then success per call)
    \\  resolve-single    public resolve() single-arch path via injected transports
    \\  resolve-session   resolve() reusing one AuthEngine across iterations
    \\  resolve-single-retry public resolve() with one transient 503 retry per call
    \\  resolve-multi     public resolve() multi-arch child-selection path via injected transports
    \\  validate-single   public validate() single-arch path via injected transports
    \\  get-manifest      public getManifest() single-arch path via injected transports
    \\  all               run every operation sequentially
    \\
    \\Options:
    \\  --iterations <n>   iterations per run (default: 10000)
    \\  --counting          enable counting allocator (default: off)
    \\
;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) {
        var sbuf: [1024]u8 = undefined;
        var sw = Io.File.stderr().writer(io, &sbuf);
        defer sw.end() catch {};
        try sw.interface.writeAll(usage);
        return error.InvalidArguments;
    }

    const operation = args[1];
    var iterations: usize = 10_000;
    var counting = false;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--iterations") and i + 1 < args.len) {
            iterations = try std.fmt.parseInt(usize, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--counting")) {
            counting = true;
        }
    }

    if (std.mem.eql(u8, operation, "all")) {
        try benchReferenceParse(io, iterations, counting);
        try benchDigestParse(io, iterations, counting);
        try benchManifestParse(io, iterations, counting);
        try benchChallengeParse(io, iterations, counting);
        try benchPlatformMatch(io, iterations, counting);
        try benchAuthenticateMiss(io, iterations, counting);
        try benchAuthenticateHit(io, iterations, counting);
        try benchAuthenticateRateLimit(io, iterations, counting);
        try benchResolveSingle(io, iterations, counting);
        try benchResolveSession(io, iterations, counting);
        try benchResolveSingleRetry(io, iterations, counting);
        try benchResolveMulti(io, iterations, counting);
        try benchValidateSingle(io, iterations, counting);
        try benchGetManifest(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "reference-parse")) {
        try benchReferenceParse(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "digest-parse")) {
        try benchDigestParse(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "manifest-parse")) {
        try benchManifestParse(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "challenge-parse")) {
        try benchChallengeParse(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "platform-match")) {
        try benchPlatformMatch(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "authenticate-miss")) {
        try benchAuthenticateMiss(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "authenticate-hit")) {
        try benchAuthenticateHit(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "authenticate-rate-limit")) {
        try benchAuthenticateRateLimit(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "resolve-single")) {
        try benchResolveSingle(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "resolve-session")) {
        try benchResolveSession(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "resolve-single-retry")) {
        try benchResolveSingleRetry(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "resolve-multi")) {
        try benchResolveMulti(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "validate-single")) {
        try benchValidateSingle(io, iterations, counting);
    } else if (std.mem.eql(u8, operation, "get-manifest")) {
        try benchGetManifest(io, iterations, counting);
    } else {
        var ebuf: [1024]u8 = undefined;
        var ew = Io.File.stderr().writer(io, &ebuf);
        defer ew.end() catch {};
        try ew.interface.print("unknown operation: {s}\n", .{operation});
        return error.InvalidArguments;
    }
}

fn nanoTime() i128 {
    var ts: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts))) {
        .SUCCESS => {},
        else => return 0,
    }
    return @as(i128, ts.sec) * 1_000_000_000 + @as(i128, ts.nsec);
}

fn printReport(name: []const u8, detail: []const u8, io: Io, iterations: usize, wall_ns: i128, alloc_count: usize, alloc_bytes: usize) void {
    var buf: [4096]u8 = undefined;
    var w = Io.File.stdout().writer(io, &buf);
    defer w.end() catch {};
    const out = &w.interface;
    out.print("{s}: {s}\n", .{ name, detail }) catch {};
    out.print("  iterations  {d}\n", .{iterations}) catch {};
    out.print("  wall_ns     {d}\n", .{wall_ns}) catch {};
    const mean = @divFloor(wall_ns, @as(i128, @intCast(iterations)));
    out.print("  mean_ns     {d}\n", .{mean}) catch {};
    if (alloc_count > 0) {
        out.print("  allocs      {d}\n", .{alloc_count}) catch {};
        out.print("  alloc_bytes {d}\n", .{alloc_bytes}) catch {};
    }
}

const CountingAllocator = struct {
    inner: std.mem.Allocator,
    bytes_allocated: usize = 0,
    bytes_freed: usize = 0,
    peak_bytes: usize = 0,
    allocation_count: usize = 0,
    current_bytes: usize = 0,

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .remap = remapFn,
                .free = freeFn,
            },
        };
    }

    fn reset(self: *CountingAllocator) void {
        self.bytes_allocated = 0;
        self.bytes_freed = 0;
        self.peak_bytes = 0;
        self.allocation_count = 0;
        self.current_bytes = 0;
    }

    fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.inner.rawAlloc(len, alignment, ra);
        if (result != null) {
            self.bytes_allocated += len;
            self.allocation_count += 1;
            self.current_bytes += len;
            if (self.current_bytes > self.peak_bytes) self.peak_bytes = self.current_bytes;
        }
        return result;
    }

    fn resizeFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const old_len = buf.len;
        if (self.inner.rawResize(buf, alignment, new_len, ra)) {
            if (new_len > old_len) {
                self.bytes_allocated += new_len - old_len;
                self.current_bytes += new_len - old_len;
                if (self.current_bytes > self.peak_bytes) self.peak_bytes = self.current_bytes;
            } else {
                self.bytes_freed += old_len - new_len;
                self.current_bytes -= old_len - new_len;
            }
            return true;
        }
        return false;
    }

    fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (self.inner.rawResize(memory, alignment, new_len, ra)) {
            const old_len = memory.len;
            if (new_len > old_len) {
                self.bytes_allocated += new_len - old_len;
                self.current_bytes += new_len - old_len;
                if (self.current_bytes > self.peak_bytes) self.peak_bytes = self.current_bytes;
            } else {
                self.bytes_freed += old_len - new_len;
                self.current_bytes -= old_len - new_len;
            }
            return memory.ptr;
        }
        const new_mem = self.inner.rawAlloc(new_len, alignment, ra) orelse return null;
        self.bytes_allocated += new_len;
        self.allocation_count += 1;
        self.current_bytes += new_len;
        if (self.current_bytes > self.peak_bytes) self.peak_bytes = self.current_bytes;
        @memcpy(new_mem[0..memory.len], memory);
        self.inner.rawFree(memory, alignment, ra);
        self.bytes_freed += memory.len;
        self.current_bytes -|= memory.len;
        return new_mem;
    }

    fn freeFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(buf, alignment, ra);
        self.bytes_freed += buf.len;
        self.current_bytes -|= buf.len;
    }
};

const oci_manifest_media_type = "application/vnd.oci.image.manifest.v1+json";
const oci_index_media_type = "application/vnd.oci.image.index.v1+json";
const busybox_manifest_digest = "sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65";
const busybox_index_digest = "sha256:924ad1d57c2cb496c959c157fd3562d2abb87e98efd9f62912fb8ff975bbafc3";
const bench_busybox_ref = "registry-1.docker.io/library/busybox:latest";

fn parseBusyboxBenchRef(alloc: std.mem.Allocator) !z_oci.Reference {
    return z_oci.Reference.parse(alloc, bench_busybox_ref);
}

fn benchReferenceParse(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const input = "ghcr.io/owner/repo:v1.0@sha256:" ++ "a" ** 64;

    {
        var ref = try z_oci.Reference.parse(alloc, input);
        ref.deinit(alloc);
    }

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        var ref = try z_oci.Reference.parse(alloc, input);
        ref.deinit(alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("reference-parse", input, io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchDigestParse(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;
    _ = alloc; // Digest.parse does not take an allocator

    const input = "sha256:" ++ "a" ** 64;

    _ = z_oci.Digest.parse(input) catch unreachable;

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        _ = z_oci.Digest.parse(input) catch unreachable;
    }
    const elapsed = nanoTime() - start;

    printReport("digest-parse", input, io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchManifestParse(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const fixture_path = "fixtures/manifests/busybox-amd64-live-oci-manifest.json";
    var fixture_buf: [32 * 1024]u8 = undefined;
    const fixture_bytes = try Io.Dir.cwd().readFile(io, fixture_path, &fixture_buf);

    {
        var parsed = try z_oci.json.parse(z_oci.Manifest, alloc, fixture_bytes);
        parsed.deinit();
    }

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        var parsed = try z_oci.json.parse(z_oci.Manifest, alloc, fixture_bytes);
        parsed.deinit();
    }
    const elapsed = nanoTime() - start;

    printReport("manifest-parse", fixture_path, io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchChallengeParse(io: Io, iterations: usize, counting: bool) !void {
    _ = counting;
    const input = "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:owner/image:pull\"";

    _ = z_oci.auth.parseAuthenticateHeader(input) catch unreachable;

    const start = nanoTime();
    for (0..iterations) |_| {
        _ = z_oci.auth.parseAuthenticateHeader(input) catch unreachable;
    }
    const elapsed = nanoTime() - start;

    printReport("challenge-parse", input, io, iterations, elapsed, 0, 0);
}

fn benchPlatformMatch(io: Io, iterations: usize, counting: bool) !void {
    _ = counting;
    const candidate = z_oci.Platform{ .os = "linux", .architecture = "arm64", .variant = "v8" };
    const filter = z_oci.Platform{ .os = "linux", .architecture = "arm64" };

    _ = z_oci.Platform.match(candidate, filter);

    const start = nanoTime();
    for (0..iterations) |_| {
        _ = z_oci.Platform.match(candidate, filter);
    }
    const elapsed = nanoTime() - start;

    printReport("platform-match", "candidate linux/arm64/v8 vs filter linux/arm64", io, iterations, elapsed, 0, 0);
}

fn benchAuthenticateMiss(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const ExchangeState = struct {
        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "bench-token",
            \\  "expires_in": 3600
            \\}
            };
        }
    };

    var engine = z_oci.AuthEngine.initWithTokenHttpExchanger(alloc, .{}, ExchangeState.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;

    {
        const request = try z_oci.AuthenticateRequest.init("registry.example.test", .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:bench/image:pull",
        });
        var response = (try engine.authenticate(&client, request)).?;
        response.deinit(alloc);
    }

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |i| {
        var buf: [128]u8 = undefined;
        const scope = try std.fmt.bufPrint(&buf, "repository:bench/image{d}:pull", .{i});
        const request = try z_oci.AuthenticateRequest.init("registry.example.test", .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = scope,
        });
        var response = (try engine.authenticate(&client, request)).?;
        response.deinit(alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("authenticate-miss", "unique scope per call", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchAuthenticateHit(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const ExchangeState = struct {
        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "bench-token",
            \\  "expires_in": 3600
            \\}
            };
        }
    };

    var engine = z_oci.AuthEngine.initWithTokenHttpExchanger(alloc, .{}, ExchangeState.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;

    const request = try z_oci.AuthenticateRequest.init("registry.example.test", .{
        .realm = "https://auth.example.test/token",
        .service = "registry.example.test",
        .scope = "repository:bench/image:pull",
    });

    // First call: populate cache
    {
        var response = (try engine.authenticate(&client, request)).?;
        response.deinit(alloc);
    }

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        var response = (try engine.authenticate(&client, request)).?;
        response.deinit(alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("authenticate-hit", "same scope, cached", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchAuthenticateRateLimit(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const ExchangeState = struct {
        var calls: usize = 0;

        fn exchange(allocator: std.mem.Allocator, _: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.AuthError!z_oci.auth.TokenExchangeResponse {
            defer request.deinit(allocator);
            calls += 1;
            if (@rem(calls, 2) == 1) {
                return .{
                    .status = .too_many_requests,
                    .body = "",
                    .resilience_headers = &.{
                        .{ .name = "Retry-After", .value = "1" },
                    },
                };
            }
            return .{ .status = .ok, .body =
            \\{
            \\  "access_token": "bench-retry-token",
            \\  "expires_in": 3600
            \\}
            };
        }
    };

    var engine = z_oci.AuthEngine.initWithTokenHttpExchanger(alloc, .{
        .max_rate_limit_retries = 1,
    }, ExchangeState.exchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;

    {
        const request = try z_oci.AuthenticateRequest.init("registry.example.test", .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = "repository:bench/retry:pull",
        });
        var response = (try engine.authenticate(&client, request)).?;
        response.deinit(alloc);
    }

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |i| {
        var buf: [128]u8 = undefined;
        const scope = try std.fmt.bufPrint(&buf, "repository:bench/retry{d}:pull", .{i});
        const request = try z_oci.AuthenticateRequest.init("registry.example.test", .{
            .realm = "https://auth.example.test/token",
            .service = "registry.example.test",
            .scope = scope,
        });
        var response = (try engine.authenticate(&client, request)).?;
        response.deinit(alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("authenticate-rate-limit", "429 then success via injected token transport", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

const ResolverBenchFixture = struct {
    index_body: []u8,
    index_digest: []u8,
    child_body: []u8,
    child_digest: []u8,

    fn init(allocator: std.mem.Allocator, io: Io) !ResolverBenchFixture {
        const index_body = try readFixtureAlloc(allocator, io, "fixtures/indexes/busybox-latest-live-oci-index.json", 32 * 1024);
        errdefer allocator.free(index_body);

        const index_digest = try allocator.dupe(u8, busybox_index_digest);
        errdefer allocator.free(index_digest);

        const child_body = try readFixtureAlloc(allocator, io, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 32 * 1024);
        errdefer allocator.free(child_body);

        const child_digest = try allocator.dupe(u8, busybox_manifest_digest);
        errdefer allocator.free(child_digest);

        return .{
            .index_body = index_body,
            .index_digest = index_digest,
            .child_body = child_body,
            .child_digest = child_digest,
        };
    }

    fn deinit(self: *ResolverBenchFixture, allocator: std.mem.Allocator) void {
        allocator.free(self.index_body);
        allocator.free(self.index_digest);
        allocator.free(self.child_body);
        allocator.free(self.child_digest);
    }
};

const SingleManifestBenchState = struct {
    var body: []const u8 = undefined;

    fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.AuthError!z_oci.auth.TokenExchangeResponse {
        request.deinit(allocator);
        return error.TokenExchangeFailed;
    }

    fn manifestExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.testing.ManifestHttpRequest,
    ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
        defer request.deinit(allocator);
        return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
            .status = .ok,
            .content_type = oci_manifest_media_type,
            .docker_content_digest = busybox_manifest_digest,
        }, body);
    }
};

const SingleManifestRetryBenchState = struct {
    var body: []const u8 = undefined;
    var attempts: usize = 0;

    fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.AuthError!z_oci.auth.TokenExchangeResponse {
        request.deinit(allocator);
        return error.TokenExchangeFailed;
    }

    fn manifestExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.testing.ManifestHttpRequest,
    ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
        defer request.deinit(allocator);
        attempts += 1;
        if (@rem(attempts, 2) == 1) {
            return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
                .status = .service_unavailable,
            }, null);
        }

        return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
            .status = .ok,
            .content_type = oci_manifest_media_type,
            .docker_content_digest = busybox_manifest_digest,
        }, body);
    }
};

const MultiManifestBenchState = struct {
    var fixture_ref: *const ResolverBenchFixture = undefined;

    fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.AuthError!z_oci.auth.TokenExchangeResponse {
        request.deinit(allocator);
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
                .content_type = oci_index_media_type,
                .docker_content_digest = fixture_ref.index_digest,
            }, fixture_ref.index_body);
        }

        return z_oci.testing.ManifestHttpResponse.initOwnedAlloc(allocator, .{
            .status = .ok,
            .content_type = oci_manifest_media_type,
            .docker_content_digest = fixture_ref.child_digest,
        }, fixture_ref.child_body);
    }
};

const ValidateBenchState = struct {
    fn tokenExchange(allocator: std.mem.Allocator, _: *std.http.Client, request: z_oci.auth.TokenHttpRequest) z_oci.AuthError!z_oci.auth.TokenExchangeResponse {
        request.deinit(allocator);
        return error.TokenExchangeFailed;
    }

    fn manifestExchange(
        allocator: std.mem.Allocator,
        _: *std.http.Client,
        request: z_oci.testing.ManifestHttpRequest,
    ) z_oci.testing.ManifestExchangeError!z_oci.testing.ManifestHttpResponse {
        defer request.deinit(allocator);
        return .{ .metadata = .{
            .status = .ok,
            .content_type = oci_manifest_media_type,
            .docker_content_digest = busybox_manifest_digest,
        } };
    }
};

fn benchResolveSingle(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const manifest_body = try readFixtureAlloc(alloc, io, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 32 * 1024);
    defer alloc.free(manifest_body);

    SingleManifestBenchState.body = manifest_body;

    var client: std.http.Client = undefined;

    try deinitResolveSuccess(try z_oci.testing.resolveWithExchangers(
        alloc,
        &client,
        z_oci.Config{},
        try parseBusyboxBenchRef(alloc),
        null,
        SingleManifestBenchState.tokenExchange,
        SingleManifestBenchState.manifestExchange,
        .{},
    ), alloc);

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        try deinitResolveSuccess(try z_oci.testing.resolveWithExchangers(
            alloc,
            &client,
            z_oci.Config{},
            try parseBusyboxBenchRef(alloc),
            null,
            SingleManifestBenchState.tokenExchange,
            SingleManifestBenchState.manifestExchange,
            .{},
        ), alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("resolve-single", "single-arch resolve via injected manifest fixture", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchResolveSession(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const manifest_body = try readFixtureAlloc(alloc, io, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 32 * 1024);
    defer alloc.free(manifest_body);

    SingleManifestBenchState.body = manifest_body;

    var engine = z_oci.AuthEngine.initWithTokenHttpExchanger(alloc, .{}, SingleManifestBenchState.tokenExchange);
    defer engine.deinit();
    var client: std.http.Client = undefined;

    try deinitResolveSuccess(try z_oci.testing.resolveWithEngine(
        alloc,
        &client,
        z_oci.Config{},
        &engine,
        try parseBusyboxBenchRef(alloc),
        null,
        SingleManifestBenchState.tokenExchange,
        SingleManifestBenchState.manifestExchange,
        .{},
    ), alloc);

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        try deinitResolveSuccess(try z_oci.testing.resolveWithEngine(
            alloc,
            &client,
            z_oci.Config{},
            &engine,
            try parseBusyboxBenchRef(alloc),
            null,
            SingleManifestBenchState.tokenExchange,
            SingleManifestBenchState.manifestExchange,
            .{},
        ), alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("resolve-session", "single-arch resolve with reused AuthEngine", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchResolveSingleRetry(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const manifest_body = try readFixtureAlloc(alloc, io, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 32 * 1024);
    defer alloc.free(manifest_body);

    SingleManifestRetryBenchState.body = manifest_body;
    SingleManifestRetryBenchState.attempts = 0;

    var client: std.http.Client = undefined;
    const config = z_oci.Config{ .max_network_retries = 1 };

    try deinitResolveSuccess(try z_oci.testing.resolveWithExchangers(
        alloc,
        &client,
        config,
        try parseBusyboxBenchRef(alloc),
        null,
        SingleManifestRetryBenchState.tokenExchange,
        SingleManifestRetryBenchState.manifestExchange,
        .{},
    ), alloc);

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        try deinitResolveSuccess(try z_oci.testing.resolveWithExchangers(
            alloc,
            &client,
            config,
            try parseBusyboxBenchRef(alloc),
            null,
            SingleManifestRetryBenchState.tokenExchange,
            SingleManifestRetryBenchState.manifestExchange,
            .{},
        ), alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("resolve-single-retry", "503 then success via injected manifest transport", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchResolveMulti(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    var fixture = try ResolverBenchFixture.init(alloc, io);
    defer fixture.deinit(alloc);

    MultiManifestBenchState.fixture_ref = &fixture;

    var client: std.http.Client = undefined;
    const platform = z_oci.Platform{ .os = "linux", .architecture = "amd64" };

    try deinitResolveSuccess(try z_oci.testing.resolveWithExchangers(
        alloc,
        &client,
        z_oci.Config{},
        try parseBusyboxBenchRef(alloc),
        platform,
        MultiManifestBenchState.tokenExchange,
        MultiManifestBenchState.manifestExchange,
        .{},
    ), alloc);

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        try deinitResolveSuccess(try z_oci.testing.resolveWithExchangers(
            alloc,
            &client,
            z_oci.Config{},
            try parseBusyboxBenchRef(alloc),
            platform,
            MultiManifestBenchState.tokenExchange,
            MultiManifestBenchState.manifestExchange,
            .{},
        ), alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("resolve-multi", "multi-arch resolve with child selection via injected fixtures", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchValidateSingle(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    try expectValidOutcome(try z_oci.testing.validateWithExchangers(
        alloc,
        &client,
        z_oci.Config{},
        ref,
        null,
        ValidateBenchState.tokenExchange,
        ValidateBenchState.manifestExchange,
        .{},
    ), alloc);

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        try expectValidOutcome(try z_oci.testing.validateWithExchangers(
            alloc,
            &client,
            z_oci.Config{},
            ref,
            null,
            ValidateBenchState.tokenExchange,
            ValidateBenchState.manifestExchange,
            .{},
        ), alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("validate-single", "single-arch validate HEAD path via injected metadata", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn benchGetManifest(io: Io, iterations: usize, counting: bool) !void {
    var ca = CountingAllocator{ .inner = std.heap.page_allocator };
    const alloc = if (counting) ca.allocator() else std.heap.page_allocator;

    const manifest_body = try readFixtureAlloc(alloc, io, "fixtures/manifests/busybox-amd64-live-oci-manifest.json", 32 * 1024);
    defer alloc.free(manifest_body);

    SingleManifestBenchState.body = manifest_body;

    var client: std.http.Client = undefined;
    const ref = z_oci.Reference{
        .registry = "registry-1.docker.io",
        .repository = "library/busybox",
        .tag = "latest",
        .digest = null,
        .digest_raw = null,
    };

    try deinitManifestSuccess(try z_oci.testing.getManifestWithExchangers(
        alloc,
        &client,
        z_oci.Config{},
        ref,
        null,
        SingleManifestBenchState.tokenExchange,
        SingleManifestBenchState.manifestExchange,
        .{},
    ), alloc);

    ca.reset();
    const start = nanoTime();
    for (0..iterations) |_| {
        try deinitManifestSuccess(try z_oci.testing.getManifestWithExchangers(
            alloc,
            &client,
            z_oci.Config{},
            ref,
            null,
            SingleManifestBenchState.tokenExchange,
            SingleManifestBenchState.manifestExchange,
            .{},
        ), alloc);
    }
    const elapsed = nanoTime() - start;

    printReport("get-manifest", "single-arch getManifest via injected manifest fixture", io, iterations, elapsed, ca.allocation_count, ca.bytes_allocated);
}

fn deinitResolveSuccess(outcome: z_oci.ResolveOutcome, allocator: std.mem.Allocator) !void {
    switch (outcome) {
        .success => |result| {
            var owned = result;
            owned.deinit(allocator);
        },
        .failure => |failure| {
            var owned = failure;
            std.debug.print("resolve benchmark failure: {f}\n", .{owned});
            owned.deinitOwned(allocator);
            return error.UnexpectedBenchmarkFailure;
        },
    }
}

fn expectValidOutcome(outcome: z_oci.ValidateOutcome, allocator: std.mem.Allocator) !void {
    switch (outcome) {
        .valid => {},
        .not_found => return error.UnexpectedBenchmarkFailure,
        .failure => |failure| {
            var owned = failure;
            std.debug.print("validate benchmark failure: {f}\n", .{owned});
            owned.deinitOwned(allocator);
            return error.UnexpectedBenchmarkFailure;
        },
    }
}

fn deinitManifestSuccess(outcome: z_oci.ManifestOutcome, allocator: std.mem.Allocator) !void {
    switch (outcome) {
        .success => |parsed| {
            var owned = parsed;
            owned.deinit();
        },
        .failure => |failure| {
            var owned = failure;
            std.debug.print("getManifest benchmark failure: {f}\n", .{owned});
            owned.deinitOwned(allocator);
            return error.UnexpectedBenchmarkFailure;
        },
    }
}

fn readFixtureAlloc(allocator: std.mem.Allocator, io: Io, path: []const u8, max_bytes: usize) ![]u8 {
    return try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_bytes));
}
