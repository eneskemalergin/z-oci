# Installation

z-oci requires Zig 0.16.0 or later. Use it as a package dependency or build it from a checkout.

## Use as a dependency

Fetch the current tagged release:

```sh
zig fetch --save git+https://github.com/eneskemalergin/z-oci#v0.7.0
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
