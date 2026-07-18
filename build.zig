//! Build graph for z-oci: library, executable, tests, examples, and benchmarks.
//!
//! Primary steps:
//! - `test`: library, executable, workflow, CLI smoke, example smoke, and security
//!   checks (offline examples only; live `resolve-reference` is excluded).
//! - `run`: installed `z-oci` executable with forwarded build arguments.
//! - `cli-smoke`: installed `z-oci` help, version, usage, and stream checks.
//! - `workflow-smoke`: offline workflow smoke tests only.
//! - `examples`: build all packaged example programs.
//! - `example-normalize-reference`, `example-inspect-manifest`, `example-select-platform`,
//!   `example-resolve-many`, `example-validate-reference`, `example-resolve-authenticated`,
//!   and `example-resolve-reference`: run one example with forwarded CLI args.
//! - `examples-smoke`: run offline examples with fixed fixture inputs.
//! - `bench`: build and install the benchmark CLI to `zig-out/bin/z-oci-bench`.
//! - `security-check`: reject private-key PEM blocks, high-confidence credential
//!   material, and development-only visibility leaks in public repo paths.
//! - `integration-registry`: opt-in local `registry:2` checks (requires Docker;
//!   clear-fails if absent; never part of `test`).

const std = @import("std");
const builtin = @import("builtin");
const package = @import("build.zig.zon");

const minimum_zig_version = std.SemanticVersion{ .major = 0, .minor = 16, .patch = 0 };

pub fn build(b: *std.Build) void {
    if (comptime builtin.zig_version.order(minimum_zig_version) == .lt) {
        @compileError("z-oci requires Zig 0.16.0 or later");
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("z_oci", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cli_options = b.addOptions();
    cli_options.addOption([]const u8, "package_version", package.version);

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
    exe.root_module.addOptions("build_options", cli_options);
    const install_exe = b.addInstallArtifact(exe, .{});
    b.getInstallStep().dependOn(&install_exe.step);

    const run_step = b.step("run", "Run installed z-oci with forwarded arguments");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const cli_smoke_step = b.step("cli-smoke", "Check installed z-oci process behavior");
    addCliSmokeCase(cli_smoke_step, exe, &.{"--help"}, "Usage:\n  z-oci [global-options]", null, "", 0);
    addCliSmokeCase(cli_smoke_step, exe, &.{"--version"}, null, b.fmt("z-oci {s}\n", .{package.version}), "", 0);
    addCliSmokeCase(cli_smoke_step, exe, &.{ "resolve", "--help" }, "Usage:\n  z-oci resolve", null, "", 0);
    addCliSmokeCase(cli_smoke_step, exe, &.{ "validate", "--help" }, "Usage:\n  z-oci validate", null, "", 0);
    addCliSmokeCase(cli_smoke_step, exe, &.{ "inspect", "--help" }, "Usage:\n  z-oci inspect", null, "", 0);
    addCliSmokeCase(cli_smoke_step, exe, &.{ "resolve", "--version" }, null, b.fmt("z-oci {s}\n", .{package.version}), "", 0);
    addCliSmokeCase(cli_smoke_step, exe, &.{ "validate", "--version" }, null, b.fmt("z-oci {s}\n", .{package.version}), "", 0);
    addCliSmokeCase(cli_smoke_step, exe, &.{ "inspect", "--version" }, null, b.fmt("z-oci {s}\n", .{package.version}), "", 0);
    addCliSmokeCase(
        cli_smoke_step,
        exe,
        &.{ "unknown", "ubuntu" },
        "",
        null,
        "z-oci: usage error: code=unknown_command\nRun \"z-oci --help\" for help.\n",
        5,
    );
    cli_smoke_step.dependOn(&install_exe.step);
    addCliSmokeCase(
        cli_smoke_step,
        exe,
        &.{ "resolve", "--format", "json" },
        "",
        null,
        "z-oci: usage error: code=missing_argument\nRun \"z-oci resolve --help\" for help.\n",
        5,
    );

    // --- Tests ---

    const lib_tests = b.addTest(.{ .root_module = mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const cli_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "z_oci", .module = mod },
        },
    }) });
    const run_cli_tests = b.addRunArtifact(cli_tests);

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
    test_step.dependOn(&run_cli_tests.step);
    test_step.dependOn(&run_workflow_smoke_tests.step);
    test_step.dependOn(cli_smoke_step);

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

    const security_check_step = b.step("security-check", "Reject secrets and development-only references in public paths");
    security_check_step.dependOn(&run_security_check.step);
    test_step.dependOn(security_check_step);
    test_step.dependOn(&run_security_check_tests.step);

    const workflow_smoke_step = b.step("workflow-smoke", "Run offline workflow smoke tests");
    workflow_smoke_step.dependOn(&run_workflow_smoke_tests.step);

    // --- Offline example programs ---

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

    const resolve_many_example = b.addExecutable(.{
        .name = "resolve-many",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/resolve-many.zig"),
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

    const validate_reference_example = b.addExecutable(.{
        .name = "validate-reference",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/validate-reference.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });

    const resolve_authenticated_example = b.addExecutable(.{
        .name = "resolve-authenticated",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/resolve-authenticated.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });

    const examples_step = b.step("examples", "Build all packaged example programs");
    const normalize_reference_install = b.addInstallArtifact(normalize_reference_example, .{});
    const inspect_manifest_install = b.addInstallArtifact(inspect_manifest_example, .{});
    const select_platform_install = b.addInstallArtifact(select_platform_example, .{});
    const resolve_many_install = b.addInstallArtifact(resolve_many_example, .{});
    const resolve_reference_install = b.addInstallArtifact(resolve_reference_example, .{});
    const validate_reference_install = b.addInstallArtifact(validate_reference_example, .{});
    const resolve_authenticated_install = b.addInstallArtifact(resolve_authenticated_example, .{});
    examples_step.dependOn(&normalize_reference_install.step);
    examples_step.dependOn(&inspect_manifest_install.step);
    examples_step.dependOn(&select_platform_install.step);
    examples_step.dependOn(&resolve_many_install.step);
    examples_step.dependOn(&resolve_reference_install.step);
    examples_step.dependOn(&validate_reference_install.step);
    examples_step.dependOn(&resolve_authenticated_install.step);

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

    const run_resolve_many_step = b.step("example-resolve-many", "Run the offline resolve-many example");
    const run_resolve_many = b.addRunArtifact(resolve_many_example);
    run_resolve_many_step.dependOn(&run_resolve_many.step);
    if (b.args) |args| run_resolve_many.addArgs(args);

    const run_resolve_reference_step = b.step("example-resolve-reference", "Run the live resolve-reference example");
    const run_resolve_reference = b.addRunArtifact(resolve_reference_example);
    run_resolve_reference_step.dependOn(&run_resolve_reference.step);
    if (b.args) |args| run_resolve_reference.addArgs(args);

    const run_validate_reference_step = b.step("example-validate-reference", "Run the offline digest-validation example");
    const run_validate_reference = b.addRunArtifact(validate_reference_example);
    run_validate_reference_step.dependOn(&run_validate_reference.step);
    if (b.args) |args| run_validate_reference.addArgs(args);

    const run_resolve_authenticated_step = b.step("example-resolve-authenticated", "Run the offline authenticated-resolution example");
    const run_resolve_authenticated = b.addRunArtifact(resolve_authenticated_example);
    run_resolve_authenticated_step.dependOn(&run_resolve_authenticated.step);
    if (b.args) |args| run_resolve_authenticated.addArgs(args);

    // --- Benchmark CLI ---

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
    const bench_install = b.addInstallArtifact(bench, .{});

    const bench_step = b.step("bench", "Build and install the benchmark CLI");
    bench_step.dependOn(&bench_install.step);

    const smoke_examples_step = b.step("examples-smoke", "Run a minimal smoke pass over the offline examples");
    // resolve-reference hits live registries, so it stays out of the offline smoke gate.

    const smoke_normalize_reference = b.addRunArtifact(normalize_reference_example);
    smoke_normalize_reference.addArg("ubuntu:22.04");
    smoke_examples_step.dependOn(&smoke_normalize_reference.step);

    const smoke_inspect_manifest = b.addRunArtifact(inspect_manifest_example);
    smoke_examples_step.dependOn(&smoke_inspect_manifest.step);

    const smoke_select_platform = b.addRunArtifact(select_platform_example);
    smoke_examples_step.dependOn(&smoke_select_platform.step);

    const smoke_resolve_many = b.addRunArtifact(resolve_many_example);
    smoke_examples_step.dependOn(&smoke_resolve_many.step);

    const smoke_validate_reference = b.addRunArtifact(validate_reference_example);
    smoke_examples_step.dependOn(&smoke_validate_reference.step);

    const smoke_resolve_authenticated = b.addRunArtifact(resolve_authenticated_example);
    smoke_examples_step.dependOn(&smoke_resolve_authenticated.step);

    test_step.dependOn(smoke_examples_step);

    // --- Opt-in local registry:2 interoperability (never part of `test`) ---

    const registry2_harness = b.addExecutable(.{
        .name = "registry2-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("integration/registry2/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z_oci", .module = mod },
            },
        }),
    });

    const run_registry2 = b.addSystemCommand(&.{"bash"});
    run_registry2.addFileArg(b.path("integration/registry2/run.sh"));
    run_registry2.addArtifactArg(registry2_harness);

    const integration_registry_step = b.step(
        "integration-registry",
        "Opt-in registry:2 interoperability (requires Docker; clear-fails if absent)",
    );
    integration_registry_step.dependOn(&run_registry2.step);
}

fn addCliSmokeCase(
    step: *std.Build.Step,
    exe: *std.Build.Step.Compile,
    args: []const []const u8,
    stdout_match: ?[]const u8,
    stdout_exact: ?[]const u8,
    stderr: []const u8,
    exit_code: u8,
) void {
    const run = std.Build.Step.Run.create(step.owner, "run cli-smoke case");
    run.producer = exe;
    run.addArtifactArg(exe);
    run.addArgs(args);
    run.expectExitCode(exit_code);
    if (stdout_match) |match| run.expectStdOutMatch(match);
    if (stdout_exact) |exact| run.expectStdOutEqual(exact);
    run.expectStdErrEqual(stderr);
    step.dependOn(&run.step);
}
