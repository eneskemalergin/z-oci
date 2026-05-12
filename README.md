<!-- markdownlint-disable MD033 MD036 MD041 -->
<p align="center">
  <img src="assets/z-oci-icon.svg" alt="z-oci logo" width="90">
</p>

<h1 align="center">z-oci</h1>

<p align="center">
        Pure Zig OCI/Docker Registry API v2 toolkit. Reference parsing, OCI JSON handling, and a Phase 2 auth engine on top of Zig 0.16 std only.
</p>

<p align="center">
    <img src="https://img.shields.io/badge/version-phase2--auth-8B5CF6?style=flat-square" alt="phase2-auth branch">
    <img src="https://img.shields.io/badge/status-phase%202%20auth%20in%20progress-2D7D46?style=flat-square" alt="Status: Phase 2 auth in progress">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/OCI-Distribution%20Spec-0066CC?style=flat-square" alt="OCI Distribution Spec">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

## Overview

z-oci currently provides:

- Docker and OCI reference parsing and normalization through `Reference`
- OCI manifest, index, descriptor, digest, media-type, and platform types
- `json.parse(T, allocator, bytes)` as a thin OCI-friendly wrapper over `std.json`
- offline fixture-driven manifest and index inspection
- a Phase 2 auth engine for `/v2/` probe classification, bearer challenge parsing, token exchange, credential lookup, and token caching
- public resolver-surface stubs with documented ownership and auth handoff contracts

For release-by-release detail, see [CHANGELOG.md](CHANGELOG.md). For milestone planning, see [plan/phase2-plan.md](plan/phase2-plan.md).

## What Works Today

- Parse and normalize image references, including Docker Hub canonicalization.
- Parse digests, manifests, indices, and descriptors from local JSON payloads.
- Select platforms from parsed multi-arch indices and manifest lists.
- Run offline example programs and workflow smoke coverage from checked-in fixtures.
- Use the Phase 2 auth engine to classify registry challenges, build token requests, exchange tokens, resolve credentials, and reuse cached bearer tokens.

The current code does not yet perform live manifest fetch, digest verification over registry responses, or real `resolve`, `validate`, and `getManifest` behavior.

## Auth Scope

The auth engine is implemented and tested, but it is still a library slice rather than a fully wired resolver. The public seam that Phase 3 will consume is already exported through `AuthReferenceView`, `referenceView(...)`, `ProbeHttpResponse.classify()`, `AuthenticateRequest`, `AuthEngine.authenticate(...)`, and `AuthEngine.retryAuthenticateAfterCachedUnauthorized(...)`.

Named registry hardening in `v0.1.7` is intentionally narrow:

- explicitly registry-hardened: Docker Hub, GHCR, and Quay
- explicitly covered through a generic self-hosted bearer-registry test path: GitLab Container Registry and Harbor
- deferred or documentation-only: other registries that either follow the generic bearer flow without dedicated fixtures yet, or depend on cloud IAM and provider-specific helpers

If you need the detailed support matrix or the exact auth hardening changes in this release, use [CHANGELOG.md](CHANGELOG.md) instead of this README.

## Requirements

Zig **0.16.0** or later.

## Example use today

In `build.zig`, import the package into your executable module:

```zig
const z_oci = b.dependency("z_oci", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("z_oci", z_oci.module("z_oci"));
```

### Normalize an image reference

```zig
const std = @import("std");
const z_oci = @import("z_oci");

pub fn main() !void {
    var ref = try z_oci.Reference.parse(std.heap.page_allocator, "ubuntu:22.04");
    defer ref.deinit(std.heap.page_allocator);

    std.debug.print("registry: {s}\n", .{ref.registry});
    std.debug.print("repository: {s}\n", .{ref.repository});
    std.debug.print("ref: {s}\n", .{ref.refString()});
}
```

### Parse a manifest JSON payload offline

```zig
const std = @import("std");
const z_oci = @import("z_oci");

pub fn main() !void {
    const json_bytes =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "size": 256
        \\  },
        \\  "layers": []
        \\}
    ;

    const parsed = try z_oci.json.parse(z_oci.Manifest, std.heap.page_allocator, json_bytes);
    defer parsed.deinit();

    std.debug.print("schemaVersion: {d}\n", .{parsed.value.schema_version});
    std.debug.print("mediaType: {s}\n", .{parsed.value.media_type.toString()});
}
```

## Build steps

- `zig build`: build and install the current stub CLI plus the package module
- `zig build test`: run all unit tests
- `zig build examples`: build the offline example programs
- `zig build examples-smoke`: run a small smoke pass over the example programs
- `zig build workflow-smoke`: run the offline workflow smoke-test matrix

Fixtures under `fixtures/` are checked-in snapshots, not live fetches. Their provenance and refresh notes live in [fixtures/SOURCES.md](fixtures/SOURCES.md).

The published Zig package bundles `src/`, `examples/`, `fixtures/`, `assets/`, and the build files, so the documented examples and tests work from a dependency fetch.

## Offline examples

- `zig build example-normalize-reference -- ubuntu:22.04`
- `zig build example-inspect-manifest`
- `zig build example-select-platform`

See [examples](examples) for the source of the packaged examples.

## Roadmap

Planned implementation areas:

- manifest resolution with HEAD/GET and multi-arch selection
- rate limiting and backoff behavior
- broader transport and registry testing
- CLI commands for resolve, validate, and inspect
- packaging, API docs, and stabilization

Detailed milestone notes live in [plan/phase2-plan.md](plan/phase2-plan.md).

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
