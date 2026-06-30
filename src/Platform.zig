//! OCI platform descriptor with partial matching for multi-arch resolution.
//!
//! Slice fields borrow from their source unless copied with `clonePlatformAlloc`
//! in `root.zig`. Values produced by `jsonParse` borrow from the parse arena.
//! Caller literals and stack buffers remain valid for the caller's lifetime.
//! match() does partial matching. The filter only needs to specify what it cares about.
//! Omitting variant accepts any variant (e.g. arm64 matches arm64/v8).
//! os_version uses dot-segment prefix matching for Windows builds.
//!
//! eql() is strict. Every field must match exactly.

const std = @import("std");

/// Operating system. Borrows from the parse arena, caller input, or a clone.
os: []const u8,
/// CPU architecture. Borrows from the parse arena, caller input, or a clone.
architecture: []const u8,
/// Optional CPU variant. Borrows from the parse arena, caller input, or a clone.
variant: ?[]const u8 = null,
/// Optional OS version string. Borrows from the parse arena, caller input, or a clone.
os_version: ?[]const u8 = null,
/// Optional OS feature list. Outer and inner slices borrow from the parse arena or a clone.
os_features: ?[]const []const u8 = null,

const Platform = @This();

/// match returns true if candidate satisfies all constraints in filter.
///
/// Rules:
///   - os and architecture: case-insensitive exact match (required).
///   - variant: if filter specifies one, candidate must match. Omitting accepts any.
///   - os_version: dot-segment prefix match. filter "10.0" matches candidate "10.0.17763.1234"
///     but not "10.01".
///   - os_features: not checked by match. Use eql for strict comparison.
pub fn match(candidate: Platform, filter: Platform) bool {
    if (!std.ascii.eqlIgnoreCase(candidate.os, filter.os)) return false;
    if (!std.ascii.eqlIgnoreCase(candidate.architecture, filter.architecture)) return false;

    if (filter.variant) |fv| {
        const cv = candidate.variant orelse return false;
        if (!std.ascii.eqlIgnoreCase(cv, fv)) return false;
    }

    if (filter.os_version) |fv| {
        const cv = candidate.os_version orelse return false;
        if (!osVersionMatches(cv, fv)) return false;
    }

    return true;
}

fn osVersionMatches(candidate: []const u8, filter: []const u8) bool {
    if (!std.mem.startsWith(u8, candidate, filter)) return false;
    return candidate.len == filter.len or candidate[filter.len] == '.';
}

/// eql returns true only when every non-null field matches exactly (case-sensitive).
pub fn eql(a: Platform, b: Platform) bool {
    if (!std.mem.eql(u8, a.os, b.os)) return false;
    if (!std.mem.eql(u8, a.architecture, b.architecture)) return false;
    if (!sliceEql(a.variant, b.variant)) return false;
    if (!sliceEql(a.os_version, b.os_version)) return false;
    if (!featuresEql(a.os_features, b.os_features)) return false;
    return true;
}

/// Parse a JSON platform object.
/// OCI spec uses dot-named fields ("os.version", "os.features"); these map to
/// the underscore Zig fields (os_version, os_features).
pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Platform {
    if (.object_begin != try source.next()) return error.UnexpectedToken;
    var result = Platform{ .os = "", .architecture = "" };
    var seen_os = false;
    var seen_arch = false;
    while (true) {
        const tok = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
        const field_name: []const u8 = switch (tok) {
            inline .string, .allocated_string => |s| s,
            .object_end => break,
            else => return error.UnexpectedToken,
        };
        defer switch (tok) {
            .allocated_string => |s| allocator.free(s),
            else => {},
        };
        if (std.mem.eql(u8, field_name, "os")) {
            result.os = try std.json.innerParse([]const u8, allocator, source, options);
            seen_os = true;
        } else if (std.mem.eql(u8, field_name, "architecture")) {
            result.architecture = try std.json.innerParse([]const u8, allocator, source, options);
            seen_arch = true;
        } else if (std.mem.eql(u8, field_name, "variant")) {
            result.variant = try std.json.innerParse(?[]const u8, allocator, source, options);
        } else if (std.mem.eql(u8, field_name, "os.version")) {
            result.os_version = try std.json.innerParse(?[]const u8, allocator, source, options);
        } else if (std.mem.eql(u8, field_name, "os.features")) {
            result.os_features = try std.json.innerParse(?[]const []const u8, allocator, source, options);
        } else {
            if (!options.ignore_unknown_fields) return error.UnknownField;
            try source.skipValue();
        }
    }
    if (!seen_os or !seen_arch) return error.MissingField;
    return result;
}

/// Stringify to a JSON platform object using OCI spec field names.
pub fn jsonStringify(self: Platform, jw: anytype) !void {
    try jw.beginObject();
    try jw.objectField("os");
    try jw.write(self.os);
    try jw.objectField("architecture");
    try jw.write(self.architecture);
    if (self.variant) |v| {
        try jw.objectField("variant");
        try jw.write(v);
    }
    if (self.os_version) |v| {
        // OCI spec uses the dot form for these fields.
        try jw.objectField("os.version");
        try jw.write(v);
    }
    if (self.os_features) |v| {
        try jw.objectField("os.features");
        try jw.write(v);
    }
    try jw.endObject();
}

fn sliceEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

fn featuresEql(a: ?[]const []const u8, b: ?[]const []const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    if (a.?.len != b.?.len) return false;
    for (a.?, b.?) |af, bf| {
        if (!std.mem.eql(u8, af, bf)) return false;
    }
    return true;
}

// --- Tests ---

const minimal_platform_json = "{\"os\": \"linux\", \"architecture\": \"amd64\"}";

const full_platform_json =
    \\{
    \\  "os": "windows",
    \\  "architecture": "amd64",
    \\  "variant": "v1",
    \\  "os.version": "10.0.17763",
    \\  "os.features": ["win32k", "hyperv"]
    \\}
;

fn parsePlatformJson(json: []const u8, options: std.json.ParseOptions) !std.json.Parsed(Platform) {
    return std.json.parseFromSlice(Platform, std.testing.allocator, json, options);
}

test "Platform.match: partial matching matrix" {
    const long_variant = "v" ++ "x" ** 255;
    const filter_features = [_][]const u8{"feature-a"};

    const cases = [_]struct {
        candidate: Platform,
        filter: Platform,
        expected: bool,
    }{
        .{
            .candidate = .{ .os = "linux", .architecture = "amd64" },
            .filter = .{ .os = "linux", .architecture = "amd64" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "Linux", .architecture = "AMD64" },
            .filter = .{ .os = "linux", .architecture = "amd64" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "windows", .architecture = "amd64" },
            .filter = .{ .os = "linux", .architecture = "amd64" },
            .expected = false,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "arm64" },
            .filter = .{ .os = "linux", .architecture = "amd64" },
            .expected = false,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "arm64", .variant = "v8" },
            .filter = .{ .os = "linux", .architecture = "arm64" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "arm64" },
            .filter = .{ .os = "linux", .architecture = "arm64" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "arm", .variant = "v7" },
            .filter = .{ .os = "linux", .architecture = "arm", .variant = "v7" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "arm", .variant = "v7" },
            .filter = .{ .os = "linux", .architecture = "arm", .variant = "v6" },
            .expected = false,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "arm64", .variant = "v8" },
            .filter = .{ .os = "linux", .architecture = "arm64", .variant = "V8" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "arm64" },
            .filter = .{ .os = "linux", .architecture = "arm64", .variant = "v8" },
            .expected = false,
        },
        .{
            .candidate = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0.17763.1234" },
            .filter = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0" },
            .filter = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "windows", .architecture = "amd64", .os_version = "10" },
            .filter = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0" },
            .expected = false,
        },
        .{
            .candidate = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0.17763" },
            .filter = .{ .os = "windows", .architecture = "amd64", .os_version = "11.0" },
            .expected = false,
        },
        .{
            .candidate = .{ .os = "windows", .architecture = "amd64", .os_version = "10.01" },
            .filter = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0" },
            .expected = false,
        },
        .{
            .candidate = .{ .os = "windows", .architecture = "amd64" },
            .filter = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0" },
            .expected = false,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "amd64" },
            .filter = .{ .os = "linux", .architecture = "amd64", .os_features = &filter_features },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "", .architecture = "" },
            .filter = .{ .os = "", .architecture = "" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0.βeta" },
            .filter = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0" },
            .expected = true,
        },
        .{
            .candidate = .{ .os = "linux", .architecture = "arm64", .variant = long_variant },
            .filter = .{ .os = "linux", .architecture = "arm64", .variant = long_variant },
            .expected = true,
        },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expected, match(case.candidate, case.filter));
    }
}

test "Platform.eql: strict equality matrix" {
    const seccomp_only = [_][]const u8{"seccomp"};
    const seccomp_apparmor_a = [_][]const u8{ "seccomp", "apparmor" };
    const seccomp_apparmor_b = [_][]const u8{ "seccomp", "apparmor" };
    const apparmor_seccomp = [_][]const u8{ "apparmor", "seccomp" };

    const cases = [_]struct {
        a: Platform,
        b: Platform,
        expected: bool,
    }{
        .{
            .a = .{ .os = "linux", .architecture = "amd64" },
            .b = .{ .os = "linux", .architecture = "amd64" },
            .expected = true,
        },
        .{
            .a = .{ .os = "Linux", .architecture = "amd64" },
            .b = .{ .os = "linux", .architecture = "amd64" },
            .expected = false,
        },
        .{
            .a = .{ .os = "linux", .architecture = "arm", .variant = "v7" },
            .b = .{ .os = "linux", .architecture = "arm", .variant = "v8" },
            .expected = false,
        },
        .{
            .a = .{ .os = "linux", .architecture = "arm64", .variant = "v8" },
            .b = .{ .os = "linux", .architecture = "arm64" },
            .expected = false,
        },
        .{
            .a = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0.17763" },
            .b = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0.19041" },
            .expected = false,
        },
        .{
            .a = .{ .os = "windows", .architecture = "amd64", .os_version = "10.0" },
            .b = .{ .os = "windows", .architecture = "amd64" },
            .expected = false,
        },
        .{
            .a = .{ .os = "linux", .architecture = "amd64", .os_features = &seccomp_only },
            .b = .{ .os = "linux", .architecture = "amd64" },
            .expected = false,
        },
        .{
            .a = .{ .os = "linux", .architecture = "amd64", .os_features = &seccomp_apparmor_a },
            .b = .{ .os = "linux", .architecture = "amd64", .os_features = &seccomp_apparmor_b },
            .expected = true,
        },
        .{
            .a = .{ .os = "linux", .architecture = "amd64", .os_features = &seccomp_only },
            .b = .{ .os = "linux", .architecture = "amd64", .os_features = &[_][]const u8{"apparmor"} },
            .expected = false,
        },
        .{
            .a = .{ .os = "linux", .architecture = "amd64", .os_features = &seccomp_apparmor_a },
            .b = .{ .os = "linux", .architecture = "amd64", .os_features = &apparmor_seccomp },
            .expected = false,
        },
        .{
            .a = .{ .os = "linux", .architecture = "amd64", .os_features = &seccomp_only },
            .b = .{ .os = "linux", .architecture = "amd64", .os_features = &seccomp_apparmor_a },
            .expected = false,
        },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expected, eql(case.a, case.b));
    }
}

test "Platform jsonParse: parses required and optional OCI fields" {
    const minimal = try parsePlatformJson(minimal_platform_json, .{ .ignore_unknown_fields = true });
    defer minimal.deinit();
    try std.testing.expectEqualSlices(u8, "linux", minimal.value.os);
    try std.testing.expectEqualSlices(u8, "amd64", minimal.value.architecture);
    try std.testing.expect(minimal.value.variant == null);
    try std.testing.expect(minimal.value.os_version == null);
    try std.testing.expect(minimal.value.os_features == null);

    const full = try parsePlatformJson(full_platform_json, .{ .ignore_unknown_fields = true });
    defer full.deinit();
    try std.testing.expectEqualSlices(u8, "windows", full.value.os);
    try std.testing.expectEqualSlices(u8, "amd64", full.value.architecture);
    try std.testing.expectEqualSlices(u8, "v1", full.value.variant.?);
    try std.testing.expectEqualSlices(u8, "10.0.17763", full.value.os_version.?);
    try std.testing.expectEqual(@as(usize, 2), full.value.os_features.?.len);
    try std.testing.expectEqualSlices(u8, "win32k", full.value.os_features.?[0]);
    try std.testing.expectEqualSlices(u8, "hyperv", full.value.os_features.?[1]);

    const with_unknown =
        "{\"os\": \"linux\", \"architecture\": \"amd64\", \"customField\": \"value\"}";
    const ignored = try parsePlatformJson(with_unknown, .{ .ignore_unknown_fields = true });
    defer ignored.deinit();
    try std.testing.expectEqualSlices(u8, "linux", ignored.value.os);
    try std.testing.expectEqualSlices(u8, "amd64", ignored.value.architecture);
}

test "Platform jsonParse: exact errors for malformed input" {
    const missing_field_cases = [_][]const u8{
        "{\"architecture\": \"amd64\"}",
        "{\"os\": \"linux\"}",
        "{}",
    };
    for (missing_field_cases) |json| {
        try std.testing.expectError(error.MissingField, parsePlatformJson(json, .{ .ignore_unknown_fields = true }));
    }

    const unexpected_token_cases = [_][]const u8{
        "null",
        "[]",
        "{\"os\": 1, \"architecture\": \"amd64\"}",
    };
    for (unexpected_token_cases) |json| {
        try std.testing.expectError(error.UnexpectedToken, parsePlatformJson(json, .{ .ignore_unknown_fields = true }));
    }

    const unknown_field_json = "{\"os\": \"linux\", \"architecture\": \"amd64\", \"customField\": \"value\"}";
    try std.testing.expectError(error.UnknownField, parsePlatformJson(unknown_field_json, .{ .ignore_unknown_fields = false }));
}

test "Platform jsonParse: allocation failures do not leak" {
    const json_bytes = "{\"os\": \"linux\", \"architecture\": \"amd64\", \"variant\": \"v8\", \"os.version\": \"10.0\"}";
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const parsed = try std.json.parseFromSlice(Platform, allocator, json_bytes, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            try std.testing.expectEqualSlices(u8, "linux", parsed.value.os);
            try std.testing.expectEqualSlices(u8, "v8", parsed.value.variant.?);
        }
    }.run, .{});
}

test "Platform jsonStringify: round-trip preserves fields via eql" {
    const features = [_][]const u8{ "seccomp", "apparmor" };
    const original = Platform{
        .os = "windows",
        .architecture = "amd64",
        .variant = "v1",
        .os_version = "10.0.17763",
        .os_features = &features,
    };

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    var ws: std.json.Stringify = .{ .writer = &aw.writer };
    try ws.write(original);

    const reparsed = try parsePlatformJson(aw.written(), .{ .ignore_unknown_fields = true });
    defer reparsed.deinit();
    try std.testing.expect(eql(original, reparsed.value));

    var minimal_aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer minimal_aw.deinit();
    var minimal_ws: std.json.Stringify = .{ .writer = &minimal_aw.writer };
    const minimal_platform = Platform{ .os = "linux", .architecture = "amd64" };
    try minimal_ws.write(minimal_platform);

    const minimal_reparsed = try parsePlatformJson(minimal_aw.written(), .{ .ignore_unknown_fields = true });
    defer minimal_reparsed.deinit();
    try std.testing.expect(eql(minimal_platform, minimal_reparsed.value));
}
