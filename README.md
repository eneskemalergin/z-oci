<!-- markdownlint-disable MD033 MD036 MD041 -->
<p align="center">
  <img src="assets/z-oci-icon.svg" alt="z-oci logo" width="90">
</p>

<h1 align="center">z-oci</h1>

<p align="center">
    Pure Zig OCI/Docker Registry API v2 toolkit. Offline reference parsing, OCI JSON handling, and resolver API contracts. Zero dependencies, Zig 0.16 std only.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-8B5CF6?style=flat-square" alt="v0.1.0">
  <img src="https://img.shields.io/badge/status-public%20offline%20release-2D7D46?style=flat-square" alt="Status: public offline release">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/OCI-Distribution%20Spec-0066CC?style=flat-square" alt="OCI Distribution Spec">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

**What ships in v0.1.0:**

- `Digest`, `MediaType`, and `Platform`: leaf types with parser, matching, and formatting behavior
- `Reference`: full Docker/OCI reference parser with owned-lifetime semantics
- `Descriptor`, `Manifest`, `OciImageIndex`, and `DockerManifestList`: OCI/Docker data model types
- `MultiArchManifest`: platform selection over multi-arch indices and manifest lists
- `json.parse(T, allocator, bytes)`: OCI-friendly JSON wrapper over `std.json.Parsed(T)`
- `ResolveError`, `ResolveResult`, and `Config`: public contract types for the future resolver surface
- `resolve`, `validate`, and `getManifest`: public API stubs with documented ownership contracts
- real offline OCI/Docker fixture set with provenance in `fixtures/SOURCES.md`
- three offline example programs plus `examples-smoke` build coverage
- explicit offline workflow smoke matrix via `zig build workflow-smoke`

**What works now:**

- normalize and validate image references offline
- parse, inspect, and re-stringify OCI manifests and indexes offline
- select platform-matching descriptors from parsed multi-arch data
- run small end-to-end offline workflows through checked-in examples and fixture-backed smoke coverage
- exercise the intended resolver memory model without any network code

## Supported Offline Workflows

`v0.1.0` treats the current library as an offline toolkit, not a partial network client. The supported workflows are intentionally narrow:

- reference normalization and decomposition through `Reference.parse`, `repositoryPath()`, and `refString()`
- digest parsing and syntactic validation through `Digest.parse` and digest-pinned references
- offline manifest and index inspection from checked-in OCI/Docker JSON fixtures
- platform selection from parsed multi-arch indices and manifest lists
- ownership-aware cloning of `ResolveResult` values that outlive a short-lived arena

**What does not work yet:**

- registry HTTP transport
- auth and token exchange
- real tag-to-digest resolution
- manifest fetching from registries
- batch resolve and caching behavior

## What Phase 2 Adds

Phase 2 starts when the public resolver stubs stop returning `error.NotYetImplemented`. That phase adds:

- registry HTTP transport
- auth and token exchange
- real `resolve`, `validate`, and `getManifest` behavior
- tag-to-digest resolution, manifest fetching, and transport-level retry or rate-limit handling

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

| Command | What it does |
| ------- | ------------ |
| `zig build` | Build and install the current stub CLI plus the package module |
| `zig build test` | Run all unit tests |
| `zig build examples` | Build all offline example programs |
| `zig build examples-smoke` | Run a small smoke pass over the offline example programs |
| `zig build workflow-smoke` | Run the offline workflow smoke-test matrix |
| `zig build run` | Run the CLI (once implemented) |

Live registry fixtures under `fixtures/` are intentional snapshots, not always-current network fetches. `zig build test` validates them in CI because they stay fast; when refreshing them, recapture from the exact URLs and `Accept` headers recorded in `fixtures/SOURCES.md`.

The published Zig package includes `src/`, `examples/`, `fixtures/`, `assets/`, `README.md`, `CHANGELOG.md`, and the build files so the documented offline examples and fixture-backed tests remain usable from the packaged release.

## Included test types

The current release gate covers the codebase from a few complementary angles:

- unit tests colocated with the owning modules
- fixture-backed JSON and parser tests against checked-in OCI/Docker payloads
- deterministic fuzz-style parser and JSON smoke tests
- allocator, leak, and allocation-failure tests on owned-lifetime paths
- example smoke coverage and workflow smoke coverage for offline usage paths

## Offline examples

The current offline example programs are small usage paths over the shipped parser and fixture surface:

- `zig build example-normalize-reference -- ubuntu:22.04`
- `zig build example-inspect-manifest`
- `zig build example-select-platform`

## Roadmap

Public roadmap summary:

| Version | Status | Description |
| ------- | ------ | ----------- |
| v0.0.1 | done | Leaf types: `Digest`, `MediaType`, `Platform` |
| v0.0.2 | done | OCI types: `Reference`, `Descriptor`, `Manifest`, `Index` |
| v0.0.3 | done | JSON infrastructure, `ResolveError`, `ResolveResult`, `Config` skeleton |
| v0.0.4 | done | Public function signatures, arena lifetime contract, fuzz tests |
| v0.0.5 | done | Public-surface tightening, docs cleanup, ownership notes, and test colocation |
| v0.0.6 | done | Real OCI/Docker fixtures, offline examples, and fixture-backed smoke coverage |
| v0.0.7 | done | Explicit offline workflow contract, workflow smoke matrix, and release-readiness docs pass |
| v0.1.0 | done | Public offline release: hardening audit, allocator checks, artifact review, package review, and docs alignment |
| Phase 2 | planned | Registry HTTP transport, auth flows, and real resolver behavior |

**Later phases**

| Version | Description |
| ------- | ----------- |
| v0.1.0 | Public offline release: quality audit, leak checks, artifact review, binary-size investigation, package review, and docs health |
| v0.2.0 | Auth engine: Bearer token flow, credential helpers |
| v0.3.0 | Manifest resolution: HEAD/GET, multi-arch, nested index |
| v0.4.0 | Rate limiting: backoff, batch API, session cache |
| v0.5.0 | Testing: mock server, local registry, CI |
| v0.6.0 | CLI: `z-oci resolve`, `validate`, `inspect` |
| v1.0.0 | Package release: Zig package index, API docs |

## References

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec): the registry API this client implements
- [OCI Image Layout Specification](https://github.com/opencontainers/image-spec): manifest and descriptor formats
- [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/): Docker Hub compatibility layer
- [zig.pkg index](https://pkg.ziglang.org): the Zig community package index where this library will be listed

## License

MIT. See [LICENSE](LICENSE).

---

<p align="center"><em>
Names fade with the sun,<br>
One seal binds the ancient root -<br>
The ghost finds its frame.
</em></p>
