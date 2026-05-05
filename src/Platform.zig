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

test "match: exact os and arch" {
    const candidate = Platform{ .os = "linux", .architecture = "amd64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(match(candidate, filter));
}

test "match: case-insensitive os and arch" {
    const candidate = Platform{ .os = "Linux", .architecture = "AMD64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(match(candidate, filter));
}

test "match: os mismatch" {
    const candidate = Platform{ .os = "windows", .architecture = "amd64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: arch mismatch" {
    const candidate = Platform{ .os = "linux", .architecture = "arm64" };
    const filter = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: variant omitted in filter accepts any" {
    const candidate = Platform{ .os = "linux", .architecture = "arm64", .variant = "v8" };
    const filter = Platform{ .os = "linux", .architecture = "arm64" };
    try std.testing.expect(match(candidate, filter));
}

test "match: variant specified must match" {
    const candidate = Platform{ .os = "linux", .architecture = "arm", .variant = "v7" };
    const filter_match = Platform{ .os = "linux", .architecture = "arm", .variant = "v7" };
    const filter_miss = Platform{ .os = "linux", .architecture = "arm", .variant = "v6" };
    try std.testing.expect(match(candidate, filter_match));
    try std.testing.expect(!match(candidate, filter_miss));
}

test "match: variant specified but candidate has none" {
    const candidate = Platform{ .os = "linux", .architecture = "arm64" };
    const filter = Platform{ .os = "linux", .architecture = "arm64", .variant = "v8" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: os_version prefix" {
    const candidate = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0.17763.1234" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0" };
    try std.testing.expect(match(candidate, filter));
}

test "match: os_version prefix mismatch" {
    const candidate = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0.17763" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "11.0" };
    try std.testing.expect(!match(candidate, filter));
}

test "match: os_version in filter but candidate missing it" {
    const candidate = Platform{ .os = "windows", .architecture = "amd64" };
    const filter = Platform{ .os = "windows", .architecture = "amd64", .os_version = "10.0" };
    try std.testing.expect(!match(candidate, filter));
}

test "eql: identical platforms" {
    const a = Platform{ .os = "linux", .architecture = "amd64" };
    const b = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(eql(a, b));
}

test "eql: case-sensitive, different case is not equal" {
    const a = Platform{ .os = "Linux", .architecture = "amd64" };
    const b = Platform{ .os = "linux", .architecture = "amd64" };
    try std.testing.expect(!eql(a, b));
}

test "eql: variant differs" {
    const a = Platform{ .os = "linux", .architecture = "arm", .variant = "v7" };
    const b = Platform{ .os = "linux", .architecture = "arm", .variant = "v8" };
    try std.testing.expect(!eql(a, b));
}

test "eql: one variant null" {
    const a = Platform{ .os = "linux", .architecture = "arm64", .variant = "v8" };
    const b = Platform{ .os = "linux", .architecture = "arm64" };
    try std.testing.expect(!eql(a, b));
}
