//! In-process mock OCI Distribution peer for offline tests.
//!
//! Not a product API. Listens on `127.0.0.1:0`. Use `start` for a single
//! anonymous manifest script, or `startWithHandler` for scripted auth, redirect,
//! and error responses. Pair with live exchangers (loopback cleartext rewrite).
//!
//! Serve exits after `request_budget` accepts. Teardown cancels the serve task
//! then closes the listener so a blocked `accept` cannot hang (and so cancel
//! does not race a closed fd). Handlers must respond with `keep_alive = false`
//! so each client request consumes one accept.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const http = std.http;

const testing_loopback = @import("testing_loopback.zig");

pub const ManifestScript = struct {
    repository: []const u8,
    tag: []const u8,
    body: []const u8,
    content_type: []const u8,
};

pub const ServeHandler = *const fn (*MockRegistry, *http.Server.Request) anyerror!void;

pub const MockRegistry = struct {
    allocator: std.mem.Allocator,
    io: Io,
    tcp: net.Server,
    port: u16,
    /// Owned `127.0.0.1:{port}` for `Reference.parse`.
    registry_host: []u8,
    script: ?ManifestScript,
    digest_header: ?[]u8,
    /// Remaining accepts; caps the serve loop so teardown need not rely on cancel alone.
    request_budget: std.atomic.Value(usize),
    serve_future: Io.Future(anyerror!void),
    handler: ServeHandler,
    user_data: ?*anyopaque,

    /// Anonymous scripted peer. `request_budget` bounds accepts for teardown.
    pub fn start(
        allocator: std.mem.Allocator,
        io: Io,
        script: ManifestScript,
        request_budget: usize,
    ) !*MockRegistry {
        const digest_header = try sha256DigestHeaderAlloc(allocator, script.body);
        errdefer allocator.free(digest_header);

        const self = try initListening(allocator, io, request_budget, anonymousManifestHandler, null);
        errdefer self.destroyListening();

        self.script = script;
        self.digest_header = digest_header;
        try self.beginServe();
        return self;
    }

    /// Scripted peer with a caller handler. `user_data` is passed through `self.user_data`.
    pub fn startWithHandler(
        allocator: std.mem.Allocator,
        io: Io,
        request_budget: usize,
        handler: ServeHandler,
        user_data: ?*anyopaque,
    ) !*MockRegistry {
        const self = try initListening(allocator, io, request_budget, handler, user_data);
        errdefer self.destroyListening();
        try self.beginServe();
        return self;
    }

    fn initListening(
        allocator: std.mem.Allocator,
        io: Io,
        request_budget: usize,
        handler: ServeHandler,
        user_data: ?*anyopaque,
    ) !*MockRegistry {
        std.debug.assert(request_budget > 0);

        const self = try allocator.create(MockRegistry);
        errdefer allocator.destroy(self);

        const listen_addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        var tcp = try listen_addr.listen(io, .{ .reuse_address = true });
        errdefer tcp.deinit(io);

        const port = tcp.socket.address.getPort();
        const registry_host = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
        errdefer allocator.free(registry_host);

        self.* = .{
            .allocator = allocator,
            .io = io,
            .tcp = tcp,
            .port = port,
            .registry_host = registry_host,
            .script = null,
            .digest_header = null,
            .request_budget = .init(request_budget),
            .serve_future = undefined,
            .handler = handler,
            .user_data = user_data,
        };
        return self;
    }

    fn beginServe(self: *MockRegistry) !void {
        self.serve_future = try self.io.concurrent(serveLoop, .{self});
    }

    fn destroyListening(self: *MockRegistry) void {
        self.tcp.deinit(self.io);
        self.allocator.free(self.registry_host);
        if (self.digest_header) |digest| self.allocator.free(digest);
        self.allocator.destroy(self);
    }

    /// Cancel the serve task before closing the listener (close-then-cancel can ABRT on a closed fd).
    pub fn deinit(self: *MockRegistry) void {
        const result = self.serve_future.cancel(self.io);
        _ = result catch {};
        self.tcp.deinit(self.io);
        self.allocator.free(self.registry_host);
        if (self.digest_header) |digest| self.allocator.free(digest);
        self.allocator.destroy(self);
    }

    /// Owned `{host}/{repository}:{tag}` for anonymous `start` peers only (`script` set).
    pub fn imageReferenceAlloc(self: *const MockRegistry, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
        const script = self.script orelse return error.OutOfMemory;
        return std.fmt.allocPrint(allocator, "{s}/{s}:{s}", .{
            self.registry_host,
            script.repository,
            script.tag,
        });
    }

    fn serveLoop(self: *MockRegistry) anyerror!void {
        while (self.request_budget.load(.acquire) > 0) {
            var stream = self.tcp.accept(self.io) catch |err| switch (err) {
                error.SocketNotListening, error.Canceled => return,
                else => return err,
            };
            defer stream.close(self.io);
            // Failed serves must not consume budget; the peer may still finish later.
            self.handleConnection(&stream) catch continue;
            _ = self.request_budget.fetchSub(1, .acq_rel);
        }
    }

    fn handleConnection(self: *MockRegistry, stream: *net.Stream) !void {
        var send_buffer: [8 * 1024]u8 = undefined;
        var recv_buffer: [8 * 1024]u8 = undefined;
        var connection_reader = stream.reader(self.io, &recv_buffer);
        var connection_writer = stream.writer(self.io, &send_buffer);
        var http_server: http.Server = .init(&connection_reader.interface, &connection_writer.interface);

        var request = try http_server.receiveHead();
        try self.handler(self, &request);
    }
};

/// Borrowed `Authorization` header value when present.
pub fn requestAuthorization(request: *const http.Server.Request) ?[]const u8 {
    var header_it = request.iterateHeaders();
    while (header_it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Authorization")) return header.value;
    }
    return null;
}

/// Owned `Docker-Content-Digest` value (`sha256:` + hex) for `body`.
pub fn sha256DigestHeaderAlloc(allocator: std.mem.Allocator, body: []const u8) error{OutOfMemory}![]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{hex[0..]});
}

fn anonymousManifestHandler(self: *MockRegistry, request: *http.Server.Request) !void {
    const script = self.script.?;
    const digest_header = self.digest_header.?;
    const method = request.head.method;
    const target = request.head.target;

    if (std.mem.eql(u8, target, "/v2/") or std.mem.eql(u8, target, "/v2")) {
        try request.respond("{}", .{
            .status = .ok,
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Docker-Distribution-Api-Version", .value = "registry/2.0" },
                .{ .name = "Content-Type", .value = "application/json" },
            },
        });
        return;
    }

    const manifest_path = try std.fmt.allocPrint(self.allocator, "/v2/{s}/manifests/{s}", .{
        script.repository,
        script.tag,
    });
    defer self.allocator.free(manifest_path);

    if (!std.mem.eql(u8, target, manifest_path)) {
        try request.respond("not found", .{ .status = .not_found, .keep_alive = false });
        return;
    }

    const headers = [_]http.Header{
        .{ .name = "Content-Type", .value = script.content_type },
        .{ .name = "Docker-Content-Digest", .value = digest_header },
        .{ .name = "Docker-Distribution-Api-Version", .value = "registry/2.0" },
    };

    switch (method) {
        .HEAD => try request.respond("", .{
            .status = .ok,
            .keep_alive = false,
            .extra_headers = &headers,
        }),
        .GET => try request.respond(script.body, .{
            .status = .ok,
            .keep_alive = false,
            .extra_headers = &headers,
        }),
        else => try request.respond("method not allowed", .{ .status = .method_not_allowed, .keep_alive = false }),
    }
}

test "sha256DigestHeaderAlloc: stable for known body" {
    const body = "{\"schemaVersion\":2}\n";
    const digest = try sha256DigestHeaderAlloc(std.testing.allocator, body);
    defer std.testing.allocator.free(digest);

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    const expected = try std.fmt.allocPrint(std.testing.allocator, "sha256:{s}", .{hex[0..]});
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, digest);
}

test "MockRegistry: anonymous HEAD over loopback" {
    try std.testing.expect(testing_loopback.isLoopbackHost("127.0.0.1"));

    const io = std.testing.io;
    const body =
        \\{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}
    ;

    const mock = try MockRegistry.start(std.testing.allocator, io, .{
        .repository = "library/alpine",
        .tag = "latest",
        .body = body,
        .content_type = "application/vnd.oci.image.manifest.v1+json",
    }, 1);
    defer mock.deinit();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://{s}/v2/{s}/manifests/{s}", .{
        mock.registry_host,
        mock.script.?.repository,
        mock.script.?.tag,
    });

    var client: http.Client = .{ .allocator = std.testing.allocator, .io = io };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var http_request = try client.request(.HEAD, uri, .{});
    defer http_request.deinit();
    try http_request.sendBodiless();

    var redirect_buffer: [4 * 1024]u8 = undefined;
    var response = try http_request.receiveHead(&redirect_buffer);
    try std.testing.expectEqual(http.Status.ok, response.head.status);

    var saw_digest = false;
    var header_it = response.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Docker-Content-Digest")) {
            try std.testing.expectEqualStrings(mock.digest_header.?, header.value);
            saw_digest = true;
        }
    }
    try std.testing.expect(saw_digest);
}

test "MockRegistry: GET /v2/ returns distribution api version" {
    const io = std.testing.io;
    const mock = try MockRegistry.start(std.testing.allocator, io, .{
        .repository = "library/alpine",
        .tag = "latest",
        .body = "{}",
        .content_type = "application/json",
    }, 1);
    defer mock.deinit();

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://{s}/v2/", .{mock.registry_host});

    var client: http.Client = .{ .allocator = std.testing.allocator, .io = io };
    defer client.deinit();

    var response_body: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer response_body.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &response_body.writer,
    });
    try std.testing.expectEqual(http.Status.ok, result.status);
    try std.testing.expectEqualStrings("{}", response_body.written());
}

test "MockRegistry: deinit without accepts does not hang" {
    const mock = try MockRegistry.startWithHandler(
        std.testing.allocator,
        std.testing.io,
        4,
        struct {
            fn handle(_: *MockRegistry, request: *http.Server.Request) anyerror!void {
                try request.respond("unused", .{ .status = .ok, .keep_alive = false });
            }
        }.handle,
        null,
    );
    mock.deinit();
}
