//! Build graph for z-oci: library module, CLI scaffold, tests, examples, and bench.
//!
//! Primary steps: `test`, `run`, `workflow-smoke`, `examples`, `bench`, `security-check`.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module: the importable z-oci package
    const mod = b.addModule("z_oci", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Current CLI scaffold. Real user-facing commands land in the later CLI implementation.
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

    const workflow_smoke_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/workflow_smoke.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "z_oci", .module = mod },
        },
    }) });
    const run_workflow_smoke_tests = b.addRunArtifact(workflow_smoke_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_workflow_smoke_tests.step);

    const security_check = b.addExecutable(.{
        .name = "check-repo-security",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/check_repo_security.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });
    const run_security_check = b.addRunArtifact(security_check);

    const security_check_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tools/check_repo_security.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    const run_security_check_tests = b.addRunArtifact(security_check_tests);

    const security_check_step = b.step("security-check", "Reject private keys in tracked PEM material");
    security_check_step.dependOn(&run_security_check.step);
    test_step.dependOn(security_check_step);
    test_step.dependOn(&run_security_check_tests.step);

    const workflow_smoke_step = b.step("workflow-smoke", "Run offline workflow smoke tests");
    workflow_smoke_step.dependOn(&run_workflow_smoke_tests.step);

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

    const resolve_reference_example = b.addExecutable(.{
        .name = "resolve-reference",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/resolve-reference.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });

    const examples_step = b.step("examples", "Build all packaged example programs");
    examples_step.dependOn(&normalize_reference_example.step);
    examples_step.dependOn(&inspect_manifest_example.step);
    examples_step.dependOn(&select_platform_example.step);
    examples_step.dependOn(&resolve_reference_example.step);
    b.installArtifact(normalize_reference_example);
    b.installArtifact(inspect_manifest_example);
    b.installArtifact(select_platform_example);
    b.installArtifact(resolve_reference_example);

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

    const run_resolve_reference_step = b.step("example-resolve-reference", "Run the live resolve-reference example");
    const run_resolve_reference = b.addRunArtifact(resolve_reference_example);
    run_resolve_reference_step.dependOn(&run_resolve_reference.step);
    if (b.args) |args| run_resolve_reference.addArgs(args);

    // Benchmark CLI
    const bench = b.addExecutable(.{
        .name = "z-oci-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });
    b.installArtifact(bench);

    const bench_step = b.step("bench", "Build the benchmark CLI");
    bench_step.dependOn(&bench.step);

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
