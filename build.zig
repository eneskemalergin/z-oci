const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module — the importable z-oci package
    const mod = b.addModule("z_oci", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // CLI executable (Phase 6)
    const exe = b.addExecutable(.{
        .name = "z-oci",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    // zig build run
    const run_step = b.step("run", "Run the CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    // Tests
    const lib_tests = b.addTest(.{ .root_module = mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // Offline example programs
    const normalize_reference_example = b.addExecutable(.{
        .name = "normalize-reference",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/normalize-reference.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });

    const inspect_manifest_example = b.addExecutable(.{
        .name = "inspect-manifest",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/inspect-manifest.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });

    const select_platform_example = b.addExecutable(.{
        .name = "select-platform",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/select-platform.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });

    const examples_step = b.step("examples", "Build all offline example programs");
    examples_step.dependOn(&normalize_reference_example.step);
    examples_step.dependOn(&inspect_manifest_example.step);
    examples_step.dependOn(&select_platform_example.step);

    const run_normalize_reference_step = b.step("example-normalize-reference", "Run the normalize-reference example");
    const run_normalize_reference = b.addRunArtifact(normalize_reference_example);
    run_normalize_reference_step.dependOn(&run_normalize_reference.step);
    if (b.args) |args| run_normalize_reference.addArgs(args);

    const run_inspect_manifest_step = b.step("example-inspect-manifest", "Run the inspect-manifest example");
    const run_inspect_manifest = b.addRunArtifact(inspect_manifest_example);
    run_inspect_manifest_step.dependOn(&run_inspect_manifest.step);
    if (b.args) |args| run_inspect_manifest.addArgs(args);

    const run_select_platform_step = b.step("example-select-platform", "Run the select-platform example");
    const run_select_platform = b.addRunArtifact(select_platform_example);
    run_select_platform_step.dependOn(&run_select_platform.step);
    if (b.args) |args| run_select_platform.addArgs(args);

    const smoke_examples_step = b.step("examples-smoke", "Run a minimal smoke pass over the offline examples");

    const smoke_normalize_reference = b.addRunArtifact(normalize_reference_example);
    smoke_normalize_reference.addArg("ubuntu:22.04");
    smoke_examples_step.dependOn(&smoke_normalize_reference.step);

    const smoke_inspect_manifest = b.addRunArtifact(inspect_manifest_example);
    smoke_examples_step.dependOn(&smoke_inspect_manifest.step);

    const smoke_select_platform = b.addRunArtifact(select_platform_example);
    smoke_examples_step.dependOn(&smoke_select_platform.step);

    test_step.dependOn(smoke_examples_step);
}
