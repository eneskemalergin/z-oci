# Contributing

First of all, thank you for considering contributing to this small but mighty project of mine, and for reading the contributing guide first. I want to give you a few things to keep in mind before opening a PR. They should help us avoid unnecessary work for both of us and make review easier.

Note: Changes should follow the existing ownership boundaries. Library behavior belongs in the owning `src/` module, the process adapter belongs in `src/main.zig`, and examples should call the public API instead of creating a second resolver path. Start from the source and its tests, then update public documentation after the behavior is verified.

## Before you change code

- Use Zig 0.16.0 or later and run commands from the repository root.
- Read the public contract in the source before changing caller-visible behavior.
- Keep tests beside the implementation unless the case crosses modules and belongs in workflow or smoke coverage.
- Give every owned result, parsed document, client, reference, and helper resource an explicit cleanup path.
- Keep the default test path offline and deterministic. Live registry and Docker checks are opt-in.

Please keep a PR focused on one logical change where possible. If the behavior changes, explain what changed, why it belongs in that layer, and how you verified it. If something could not be verified, please say so directly.

## Test types

The current release gate covers the codebase from a few complementary angles:

- unit tests colocated with the owning modules
- fixture-backed JSON and parser tests against checked-in OCI/Docker payloads
- deterministic fuzz-style parser and JSON smoke tests
- allocator, leak, and allocation-failure tests on owned-lifetime paths
- example smoke coverage and workflow smoke coverage for offline usage paths

## Running tests

Use Zig 0.16.0 or later with `zig` available on `PATH`:

```sh
zig fmt --check src/ examples/ benchmarks/ build.zig tools/ integration/
zig build test --summary all
zig build security-check
zig build examples-smoke
zig build workflow-smoke
```

`zig build test` already runs `security-check`, `workflow-smoke`, and `examples-smoke`. The standalone steps above are useful for narrower iteration.

For the broader local release check, also run:

```sh
zig build -Doptimize=ReleaseFast
zig build -Doptimize=ReleaseSmall
zig build bench
```

## GitHub Actions

The required CI workflow runs the complete offline gate on Ubuntu 24.04 and macOS 15 Intel, checks the package through a clean consumer project, verifies ReleaseFast and ReleaseSmall builds, compiles the benchmark CLI, and cross-compiles the public library for selected Linux, macOS, and Windows targets. Release binaries distinguish x86_64 (Intel/AMD 64-bit, or x64) from aarch64 (64-bit ARM); macOS release builds cover both Intel Macs and Apple Silicon. Windows runtime support is not claimed by that compile-only check.

Workflow files are audited separately when `.github/workflows/` changes. GitHub Actions dependencies are pinned to commits and maintained by the weekly Dependabot configuration. Docker and live-registry checks remain opt-in and are not required for ordinary pull requests.

## Publishing a release

Update the version in `build.zig.zon` and add the matching version section to `CHANGELOG.md`, then push an annotated `v<major>.<minor>.<patch>` tag. The release workflow reruns the complete CI graph against that tag, builds the supported Linux and macOS binaries, creates checksums and attestations, and publishes the changelog section as the GitHub Release notes. Any failed CI, build, upload, or attestation job prevents publication; an interrupted publish leaves a draft release that can be safely resumed by rerunning the workflow.

When a change affects public API or cross-module behavior, run `workflow-smoke` and `examples-smoke` directly while iterating. When it affects credentials, fixtures, or registry integration, run `security-check` and keep the Docker integration opt-in.

## Opt-in interoperability (requires Docker; never part of `zig build test`)

```sh
zig build integration-registry
```

This check needs Docker and network access. It is separate from the offline release gate and should not be treated as a replacement for the default tests.

## Documentation and examples

Public examples must state whether they use fixtures, injected exchanges, or live network access. Use placeholders for registry credentials and never commit real tokens, Docker auth values, private keys, copied authorization headers, or response bodies. Examples that allocate through the caller must show the matching `deinit` or arena lifetime.

Public documentation describes observable behavior and user ownership. It must not expose ignored local paths, internal work labels, or local-only commands. Source comments should explain non-obvious ownership, security, compatibility, or failure decisions. Keep prose direct and use fenced code blocks for commands and examples.

## Security

Run `zig build security-check` before handing off changes. Do not broaden cleartext HTTP, log credentials or authorization headers, or add process credential lookup to the bare library `Config{}` path. Use the existing injected credential and loopback test seams when coverage needs them.

## Requirements

Zig **0.16.0** or later.
