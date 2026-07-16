<!-- markdownlint-disable MD033 MD036 MD041 -->
<p align="center">
  <img src="assets/z-oci-icon.svg" alt="z-oci logo" width="90">
</p>

<h1 align="center">z-oci</h1>

<p align="center">
    Pure Zig OCI/Docker Registry API v2 toolkit. Reference parsing, live manifest resolution, auth engine. Zero external dependencies.
</p>

<p align="center">
    <img src="https://img.shields.io/badge/version-v0.7.0-8B5CF6?style=flat-square" alt="v0.7.0">
    <img src="https://img.shields.io/badge/status-compat%20testing-2D7D46?style=flat-square" alt="Status: compat testing">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/OCI-Distribution%20Spec-0066CC?style=flat-square" alt="OCI Distribution Spec">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

## What is z-oci?

z-oci is a read-only OCI and Docker Registry client for Zig. It parses image references, authenticates when configured, fetches manifests, verifies digests, and selects a platform from multi-arch images. It does not pull image layers.

The current package metadata is `0.7.0` and remains unreleased. The latest tagged package is `v0.6.0`.

## Why z-oci?

- Library-first: the CLI is a thin process adapter over the same public resolver API.
- Explicit ownership: callers provide allocators and clients, and owned results have explicit teardown.
- No hidden process state: environment variables, Docker configuration, and credential helpers are opt-in.
- OCI-aware: references, manifests, indexes, platform selection, and digest verification share one resolver path.
- Small dependency surface: Zig 0.16 and the standard library, with no external runtime dependencies.
- Testable by design: injected HTTP, process I/O, clocks, and offline registry fixtures keep core behavior deterministic.

## Install

Requirements: Zig **0.16.0** or later.

### Use as a dependency

The latest tagged release can be fetched with:

```sh
zig fetch --save git+https://github.com/eneskemalergin/z-oci#v0.6.0
```

Then import the module from `build.zig`:

```zig
const z_oci = b.dependency("z_oci", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("z_oci", z_oci.module("z_oci"));
```

### Build the current checkout

The repository includes the Zig toolchain used by its checks:

```sh
./zig-0.16.0/zig build
./zig-out/bin/z-oci --help
```

## Choose an interface

GitHub Markdown does not provide native tabs. These collapsible panels keep the library and CLI quick starts together without making either path dominate the page.

<details open>
<summary>Library API</summary>

The public API covers reference parsing, manifest resolution, exact digest validation, manifest inspection, batch resolution, and registry reachability checks.

```zig
const outcome = try z_oci.resolve(
    allocator,
    &client,
    config,
    reference,
    .{ .os = "linux", .architecture = "amd64" },
);

switch (outcome) {
    .success => |result| {
        var owned = result;
        defer owned.deinit(allocator);
    },
    .failure => |failure| {
        defer z_oci.deinitResolveFailure(failure, allocator);
    },
}
```

Main entry points:

- `Reference.parse` normalizes Docker and OCI image references.
- `resolve` resolves a tag or digest and returns a verified pinned result.
- `validate` checks whether an exact digest exists.
- `getManifest` returns a parsed manifest document.
- `inspect` returns top-level manifest or index metadata, with an optional selected leaf.
- `resolveMany` resolves references sequentially with one client and auth session.
- `pingRegistry` checks `/v2/` reachability independently of resolution.

Results use the caller's allocator. Single-resolve successes and failures have dedicated teardown paths; `ResolveManyResult.deinit` owns the complete batch. `Config{}` is anonymous and does not read process state. Callers that want environment, Docker config, or helper credentials inject them through `Config.credential_sources`.

</details>

<details>
<summary>CLI</summary>

Build the executable, then run one of the three commands:

```sh
./zig-0.16.0/zig build

./zig-out/bin/z-oci resolve ubuntu:22.04 --platform linux/amd64
./zig-out/bin/z-oci validate ubuntu@sha256:<64-hex-digest>
./zig-out/bin/z-oci inspect ubuntu:22.04 --format json
```

The CLI also supports:

- `--format text|json` for shell-friendly or structured output.
- `--verbose` for a safe elapsed-time summary on stderr.
- `--ca-bundle <path>` for a certificate-only HTTPS trust bundle.
- `--helper-timeout-ms <ms>` for credential-helper I/O only.
- `--platform os/arch[/variant]` on `resolve` and `inspect`.
- `--help` and `--version` on the top level and each command.

Text resolve output is a pinned reference:

```text
registry-1.docker.io/library/ubuntu@sha256:<64-hex-digest>
```

JSON output contains the command, input, pinned reference, digest, media type, and selected platform. Diagnostics use stable exit codes and never print credentials, authorization values, helper data, raw headers, or response bodies.

The executable explicitly wires process credentials into the library. It does not create a second authentication or registry implementation. Live HTTPS registry traffic is supported on Linux and macOS; Windows is currently limited to non-network behavior because of Zig 0.16 TLS support.

</details>

## Documentation

This README is the quick orientation and first-run guide. Detailed API contracts, ownership rules, credential configuration, output schemas, platform behavior, troubleshooting, and design notes will live in the [z-oci GitHub Wiki](https://github.com/eneskemalergin/z-oci/wiki).

## Examples

The repository includes small programs for common library paths:

```sh
./zig-0.16.0/zig build example-normalize-reference -- ubuntu:22.04
./zig-0.16.0/zig build example-inspect-manifest
./zig-0.16.0/zig build example-select-platform
./zig-0.16.0/zig build example-resolve-many
./zig-0.16.0/zig build example-resolve-reference -- ubuntu:22.04
```

The first four examples are offline. `example-resolve-reference` may contact a live registry. Source is in [examples](examples).

## Build and test

The default gate is deterministic and offline:

```sh
./zig-0.16.0/zig build test --summary all --zig-lib-dir ./zig-0.16.0/lib
```

It covers library and CLI tests, workflow and example smoke checks, and the repository security scan. The opt-in `integration-registry` step uses Docker and is separate from the default gate.

## References

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec): the registry API this client implements
- [OCI Image Layout Specification](https://github.com/opencontainers/image-spec): manifest and descriptor formats
- [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/): Docker Hub compatibility layer

## License

MIT. See [LICENSE](LICENSE).

---

<p align="center"><em>
Names fade with the sun,<br>
One seal binds the ancient root -<br>
The ghost finds its frame.
</em></p>
