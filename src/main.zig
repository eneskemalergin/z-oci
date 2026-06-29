//! Current `z-oci` executable entrypoint.
//!
//! The default build still installs a `z-oci` binary so the package keeps a
//! stable executable shape while the library surface matures, but the real
//! user-facing CLI commands are still deferred to the later CLI phase.
//!
//! Today the packaged examples provide the practical command-line entrypoints
//! for live resolver and offline fixture workflows.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    var stderr_buffer: [512]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    defer stderr_writer.end() catch {};
    try stderr_writer.interface.writeAll(
        \\z-oci: CLI scaffold (Phase 7 deferred).
        \\
        \\Use packaged examples instead:
        \\  zig build example-resolve-reference -- ubuntu:22.04
        \\  zig build example-normalize-reference -- ubuntu:22.04
        \\  zig build example-inspect-manifest
        \\  zig build example-select-platform
        \\
    );
}
