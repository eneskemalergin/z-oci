# Contributing

## Test types

The current release gate covers the codebase from a few complementary angles:

- unit tests colocated with the owning modules
- fixture-backed JSON and parser tests against checked-in OCI/Docker payloads
- deterministic fuzz-style parser and JSON smoke tests
- allocator, leak, and allocation-failure tests on owned-lifetime paths
- example smoke coverage and workflow smoke coverage for offline usage paths

## Running tests

```sh
zig fmt --check src/ examples/ benchmarks/ build.zig tools/ integration/
zig build test            # Run all unit tests (includes security-check, workflow-smoke, examples-smoke)
zig build examples-smoke  # Smoke pass over offline example programs
zig build workflow-smoke  # Offline workflow smoke-test matrix
```

## Requirements

Zig **0.16.0** or later.
