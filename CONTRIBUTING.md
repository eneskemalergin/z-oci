# Contributing

## Test types

The current release gate covers the codebase from a few complementary angles:

- unit tests colocated with the owning modules
- fixture-backed JSON and parser tests against checked-in OCI/Docker payloads
- deterministic fuzz-style parser and JSON smoke tests
- allocator, leak, and allocation-failure tests on owned-lifetime paths
- example smoke coverage and workflow smoke coverage for offline usage paths

## Running tests

Prefer the bundled toolchain and lib dir so builds match the documented offline gate:

```sh
./zig-0.16.0/zig fmt --check src/ examples/ benchmarks/ build.zig tools/ integration/
./zig-0.16.0/zig build test --summary all --zig-lib-dir ./zig-0.16.0/lib
./zig-0.16.0/zig build security-check --zig-lib-dir ./zig-0.16.0/lib
./zig-0.16.0/zig build examples-smoke --zig-lib-dir ./zig-0.16.0/lib
./zig-0.16.0/zig build workflow-smoke --zig-lib-dir ./zig-0.16.0/lib
```

`zig build test` already runs `security-check`, `workflow-smoke`, and `examples-smoke`. The standalone steps above are for narrower iteration.

Opt-in interoperability (requires Docker; never part of `zig build test`):

```sh
./zig-0.16.0/zig build integration-registry --zig-lib-dir ./zig-0.16.0/lib
```

## Requirements

Zig **0.16.0** (bundled under `./zig-0.16.0/` in this repository).
