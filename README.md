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

**Current scope on `phase2-auth`:**

- `Digest`, `MediaType`, and `Platform`: leaf types with parser, matching, and formatting behavior
- `Reference`: full Docker/OCI reference parser with owned-lifetime semantics
- `Descriptor`, `Manifest`, `OciImageIndex`, and `DockerManifestList`: OCI/Docker data model types
- `MultiArchManifest`: platform selection over multi-arch indices and manifest lists
- `json.parse(T, allocator, bytes)`: OCI-friendly JSON wrapper over `std.json.Parsed(T)`
- `ResolveError`, `ResolveResult`, and `Config`: public contract types for the future resolver surface
- Phase 2 auth engine exports: `/v2/` probe classification, `WWW-Authenticate` parsing, token-request construction, token-response parsing, and credential-provider plumbing
- `resolve`, `validate`, and `getManifest`: public API stubs with documented ownership contracts; real manifest HTTP fetch is still not implemented
- real offline OCI/Docker fixture set with provenance in `fixtures/SOURCES.md`
- three offline example programs plus `examples-smoke` build coverage
- explicit offline workflow smoke matrix via `zig build workflow-smoke`

## Current Supported Workflows

The current codebase handles:

- reference normalization and decomposition through `Reference.parse`, `repositoryPath()`, and `refString()`
- digest parsing and syntactic validation through `Digest.parse` and digest-pinned references
- offline manifest and index inspection from checked-in OCI/Docker JSON fixtures
- platform selection from parsed multi-arch indices and manifest lists
- clone `ResolveResult` values out of a short-lived arena
- auth-only Phase 2 flows: `/v2/` probe classification, Bearer challenge parsing, GET plus POST-fallback token exchange, and deterministic credential lookup ordering

It does not yet implement live manifest fetch, digest verification over registry responses, or real `resolve`, `validate`, and `getManifest` behavior.

## Auth Engine Status

The auth subsystem is now a real Phase 2 slice rather than a placeholder. Current auth coverage includes:

- `/v2/` probe response classification and repeated `WWW-Authenticate` header handling
- Bearer challenge parsing with HTTPS realm validation
- token request building from parsed challenge data, including GET-first and POST fallback shapes
- optional Basic auth header construction for credentialed token exchange
- deterministic credential lookup: explicit config provider -> injected environment map -> anonymous fallback
- fixed environment variable names for the env-backed path: `Z_OCI_REGISTRY_HOST`, `Z_OCI_REGISTRY_USER`, and `Z_OCI_REGISTRY_TOKEN`

Docker config parsing, credential helpers, token caching, and live registry manifest fetch remain future Phase 2 and Phase 3 work.

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

Fixtures under `fixtures/` are checked-in snapshots, not live fetches. `zig build test` validates them in CI. To refresh, recapture from the URLs and `Accept` headers in `fixtures/SOURCES.md`.

The published Zig package bundles `src/`, `examples/`, `fixtures/`, `assets/`, and build files. Documented examples and tests work from a dependency fetch.

## Offline examples

- `zig build example-normalize-reference -- ubuntu:22.04`
- `zig build example-inspect-manifest`
- `zig build example-select-platform`

## Roadmap

- Done on `main`: v0.0.1 -> v0.1.0: offline toolkit baseline
- Done on `phase2-auth` so far:
    - v0.1.1: auth surface and type scaffolding
    - v0.1.2: `/v2/` probe and Bearer challenge parsing
    - v0.1.3: token exchange with GET-first and POST fallback
    - v0.1.4: basic credential chain with config, env, and anonymous lookup

Next up:

- Docker credential sources and helper integration (v0.1.5)
- token cache and auth retry policy (v0.1.6)
- auth hardening, docs, and release gate (v0.1.7 / v0.2.0)
- Manifest resolution: HEAD/GET, multi-arch, nested index (v0.3.0)
- Rate limiting: backoff, batch API, session cache (v0.4.0)
- Testing: mock server, local registry, CI (v0.5.0)
- CLI: `z-oci resolve`, `validate`, `inspect` (v0.6.0)
- Zencelot (v0.7.0)
- Zencelot Integration (v0.8.0)
- Stabilization (v0.9.0)
- Package release: Zig package index, API docs (v1.0.0)
- Registry HTTP transport, auth flows, and real resolver behavior (Phase 2)

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
