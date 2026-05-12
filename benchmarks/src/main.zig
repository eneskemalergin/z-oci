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
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
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
        self.current_bytes -= memory.len;
        return new_mem;
    }

    fn freeFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(buf, alignment, ra);
        self.bytes_freed += buf.len;
        self.current_bytes -= buf.len;
    }
};

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
