//! Minimal external-consumer build used to verify the published module boundary.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const z_oci = b.dependency("z_oci", .{
        .target = target,
        .optimize = optimize,
    });

    const consumer_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = z_oci.module("z_oci") },
            },
        }),
    });
    const run_consumer_tests = b.addRunArtifact(consumer_tests);

    const test_step = b.step("test", "Compile and run the external consumer smoke test");
    test_step.dependOn(&run_consumer_tests.step);
}
