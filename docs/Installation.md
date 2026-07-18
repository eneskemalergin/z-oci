# Installation

z-oci requires Zig 0.16.0 or later. Use it as a package dependency or build it from a checkout.

## Use as a dependency

Fetch the current tagged release:

```sh
zig fetch --save git+https://github.com/eneskemalergin/z-oci#v0.7.2
```

Import the module from `build.zig`:

```zig
const z_oci = b.dependency("z_oci", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("z_oci", z_oci.module("z_oci"));
```

The package declares no external dependencies. `zig fetch --save` records the fetched package in `build.zig.zon`.

The published package is distributed from the `v0.7.2` git tag. Its package name is `.z_oci`, its importable module is `z_oci`, its fingerprint is `0xdf1b7d025f2687bf`, and it requires Zig `0.16.0` or later. Zig 0.16 records the fetched source hash in the consumer's `build.zig.zon`, so consumers do not need to clone or vendor the repository manually.

## Install the CLI

The `v0.7.2` [GitHub Release](https://github.com/eneskemalergin/z-oci/releases/tag/v0.7.2) includes native CLI archives and checksums. Download the archive for your system, unpack `z-oci`, and place it on your `PATH`. Windows is not a supported target; the published CLI archives target Linux and macOS.

## Build the checkout

From the repository root, with `zig` available on `PATH`:

```sh
zig build
./zig-out/bin/z-oci --help
```

The build installs the `z-oci` executable. The library is exposed as the `z_oci` package module for dependency builds.

## Verify the checkout

The default test step is deterministic and offline:

```sh
zig build test --summary all
```

It runs the library and CLI tests, workflow and CLI smoke checks, offline example smoke checks, and repository security checks.

For formatting checks, run:

```sh
zig fmt --check src/ examples/ benchmarks/ build.zig tools/ integration/
```

The optional registry interoperability check uses Docker and network access:

```sh
zig build integration-registry
```

It is separate from `zig build test`.

## Next steps

- [Library](Library.md) shows the caller-owned API path.
- [CLI](CLI.md) documents commands, output, and exit codes.
- [Examples](Examples.md) separates offline fixtures from live registry access.
- [Troubleshooting](Troubleshooting.md) covers common setup and request failures.
