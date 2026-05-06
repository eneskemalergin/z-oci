//! OCI platform descriptor with partial matching for multi-arch resolution.
//!
//! match() does partial matching. The filter only needs to specify what it cares about.
//! Omitting variant accepts any variant (e.g. arm64 matches arm64/v8).
//! os_version uses prefix matching for Windows builds.
//!
//! eql() is strict. Every field must match exactly.

const std = @import("std");

os: []const u8,
architecture: []const u8,
variant: ?[]const u8 = null,
os_version: ?[]const u8 = null,
os_features: ?[]const []const u8 = null,

const Platform = @This();

/// match returns true if candidate satisfies all constraints in filter.
///
/// Rules:
///   - os and architecture: case-insensitive exact match (required).
///   - variant: if filter specifies one, candidate must match. Omitting accepts any.
///   - os_version: prefix match. filter "10.0" matches candidate "10.0.17763.1234".
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
        if (!std.mem.startsWith(u8, cv, fv)) return false;
    }

    return true;
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

// ── Tests ────────────────────────────────────────────────────────────────────
//
// match -----------------------------------------------------------------------

test "match: os and architecture exact match returns true" {
    // Arrange
    const candidate = Platform{ .os = "linux", .architecture = "amd64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    // Act + Assert
    try std.testing.expect(match(candidate, filter));
}

test "match: os and architecture are case-insensitive" {
    // Guards against switching from eqlIgnoreCase to eql on required fields.
    const candidate = Platform{ .os = "Linux", .architecture = "AMD64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(match(candidate, filter));
}

test "match: os mismatch returns false" {
    const candidate = Platform{ .os = "windows", .architecture = "amd64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: architecture mismatch returns false" {
    const candidate = Platform{ .os = "linux", .architecture = "arm64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: filter omits variant, candidate with variant still matches" {
    // Verifies the partial match rule: omitting variant accepts any.
    const candidate = Platform{ .os = "linux", .architecture = "arm64", .variant = "v8" };
    const filter = Platform{ .os = "linux", .architecture = "arm64" };
    try std.testing.expect(match(candidate, filter));
}

test "match: filter omits variant, candidate without variant also matches" {
    const candidate = Platform{ .os = "linux", .architecture = "arm64" };
    const filter = Platform{ .os = "linux", .architecture = "arm64" };
    try std.testing.expect(match(candidate, filter));
}

test "match: filter specifies variant, candidate variant must match" {
    const candidate = Platform{ .os = "linux", .architecture = "arm", .variant = "v7" };
    const filter = Platform{ .os = "linux", .architecture = "arm", .variant = "v7" };
    try std.testing.expect(match(candidate, filter));
}

test "match: filter specifies variant, different candidate variant returns false" {
    const candidate = Platform{ .os = "linux", .architecture = "arm", .variant = "v7" };
    const filter = Platform{ .os = "linux", .architecture = "arm", .variant = "v6" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: variant comparison is case-insensitive" {
    // "V8" in filter must match "v8" in candidate.
    const candidate = Platform{ .os = "linux", .architecture = "arm64", .variant = "v8" };
    const filter = Platform{ .os = "linux", .architecture = "arm64", .variant = "V8" };
    try std.testing.expect(match(candidate, filter));
}

test "match: filter specifies variant, candidate has no variant returns false" {
    const candidate = Platform{ .os = "linux", .architecture = "arm64" };
    const filter = Platform{ .os = "linux", .architecture = "arm64", .variant = "v8" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: os_version prefix match returns true" {
    // Windows-style build strings: filter "10.0" matches "10.0.17763.1234".
    const candidate = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0.17763.1234" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0" };
    try std.testing.expect(match(candidate, filter));
}

test "match: os_version exact equality is a valid prefix match" {
    // Filter "10.0" must match candidate "10.0" exactly (prefix of itself).
    const candidate = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0" };
    try std.testing.expect(match(candidate, filter));
}

test "match: os_version candidate shorter than filter returns false" {
    // "10" is not a prefix of filter "10.0"; the comparison goes the wrong way.
    const candidate = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: os_version prefix mismatch returns false" {
    const candidate = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0.17763" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "11.0" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: filter specifies os_version, candidate missing it returns false" {
    const candidate = Platform{ .os = "windows", .architecture = "amd64" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: os_features in filter are not checked" {
    // Per OCI spec, os_features is not a filter criterion in match().
    // A filter with os_features must still match a candidate without them.
    const features = [_][]const u8{"feature-a"};
    const candidate = Platform{ .os = "linux", .architecture = "amd64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64", .os_features = &features };
    try std.testing.expect(match(candidate, filter));
}

// eql -------------------------------------------------------------------------

test "eql: identical platforms with no optional fields return true" {
    const a = Platform{ .os = "linux", .architecture = "amd64" };
    const b = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(eql(a, b));
}

test "eql: comparison is case-sensitive, different casing returns false" {
    // Guards against accidentally using eqlIgnoreCase in eql().
    const a = Platform{ .os = "Linux", .architecture = "amd64" };
    const b = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(!eql(a, b));
}

test "eql: both variants null returns true" {
    const a = Platform{ .os = "linux", .architecture = "arm64" };
    const b = Platform{ .os = "linux", .architecture = "arm64" };
    try std.testing.expect(eql(a, b));
}

test "eql: variant differs returns false" {
    const a = Platform{ .os = "linux", .architecture = "arm", .variant = "v7" };
    const b = Platform{ .os = "linux", .architecture = "arm", .variant = "v8" };
    try std.testing.expect(!eql(a, b));
}

test "eql: one variant null, one set returns false" {
    const a = Platform{ .os = "linux", .architecture = "arm64", .variant = "v8" };
    const b = Platform{ .os = "linux", .architecture = "arm64" };
    try std.testing.expect(!eql(a, b));
}

test "eql: os_version differs returns false" {
    const a = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0.17763" };
    const b = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0.19041" };
    try std.testing.expect(!eql(a, b));
}

test "eql: os_version one null, one set returns false" {
    const a = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0" };
    const b = Platform{ .os = "windows", .architecture = "amd64" };
    try std.testing.expect(!eql(a, b));
}

test "eql: os_features both null returns true" {
    const a = Platform{ .os = "linux", .architecture = "amd64" };
    const b = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(eql(a, b));
}

test "eql: os_features one null, one non-null returns false" {
    const features = [_][]const u8{"seccomp"};
    const a = Platform{ .os = "linux", .architecture = "amd64", .os_features = &features };
    const b = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(!eql(a, b));
}

test "eql: os_features same content returns true" {
    const fa = [_][]const u8{ "seccomp", "apparmor" };
    const fb = [_][]const u8{ "seccomp", "apparmor" };
    const a = Platform{ .os = "linux", .architecture = "amd64", .os_features = &fa };
    const b = Platform{ .os = "linux", .architecture = "amd64", .os_features = &fb };
    try std.testing.expect(eql(a, b));
}

test "eql: os_features different content returns false" {
    const fa = [_][]const u8{"seccomp"};
    const fb = [_][]const u8{"apparmor"};
    const a = Platform{ .os = "linux", .architecture = "amd64", .os_features = &fa };
    const b = Platform{ .os = "linux", .architecture = "amd64", .os_features = &fb };
    try std.testing.expect(!eql(a, b));
}

test "eql: os_features different order returns false" {
    // eql checks element order; ["a","b"] != ["b","a"].
    const fa = [_][]const u8{ "seccomp", "apparmor" };
    const fb = [_][]const u8{ "apparmor", "seccomp" };
    const a = Platform{ .os = "linux", .architecture = "amd64", .os_features = &fa };
    const b = Platform{ .os = "linux", .architecture = "amd64", .os_features = &fb };
    try std.testing.expect(!eql(a, b));
}

test "match: empty os and architecture still compare deterministically" {
    // The type does not forbid empty strings. match() should still behave predictably.
    const candidate = Platform{ .os = "", .architecture = "" };
    const filter = Platform{ .os = "", .architecture = "" };
    try std.testing.expect(match(candidate, filter));
}

test "match: unicode os_version uses byte-prefix semantics" {
    // os_version is byte-oriented. UTF-8 content must still respect prefix matching.
    const candidate = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0-βeta" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0-" };
    try std.testing.expect(match(candidate, filter));
}

test "match: very long variant string still matches exactly" {
    // Guards against fixed-size assumptions in variant handling.
    const long_variant = "v" ++ "x" ** 255;
    const candidate = Platform{ .os = "linux", .architecture = "arm64", .variant = long_variant };
    const filter = Platform{ .os = "linux", .architecture = "arm64", .variant = long_variant };
    try std.testing.expect(match(candidate, filter));
}
