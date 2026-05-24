<!-- markdownlint-disable MD033 MD036 MD041 -->
<p align="center">
  <img src="assets/z-oci-icon.svg" alt="z-oci logo" width="90">
</p>

<h1 align="center">z-oci</h1>

<p align="center">
        Pure Zig OCI/Docker Registry API v2 toolkit. Reference parsing, OCI types, auth engine. Zero external dependencies.
</p>

<p align="center">
    <img src="https://img.shields.io/badge/version-v0.2.0-8B5CF6?style=flat-square" alt="v0.2.0">
        <img src="https://img.shields.io/badge/status-phase--3%20resolver-2D7D46?style=flat-square" alt="Status: Phase 3 resolver">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/OCI-Distribution%20Spec-0066CC?style=flat-square" alt="OCI Distribution Spec">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

## What z-oci does

z-oci is a read-only OCI registry client. It parses image references, handles the types needed for manifest resolution, and authenticates against registries. Everything is built on Zig 0.16 std -- no external dependencies.

### Capabilities

- **Reference parsing**: normalize `ubuntu:22.04`, `ghcr.io/owner/repo@sha256:...`, `localhost:5000/myimage:dev`, and every other Docker/OCI reference form.
- **OCI types**: `Digest`, `MediaType`, `Platform`, `Descriptor`, `Manifest`, `OciImageIndex`, `DockerManifestList`, `MultiArchManifest` -- all with JSON round-trip support.
- **Auth engine** (v0.2.0): Bearer token flow compatible with Docker Hub, GHCR, Quay, and self-hosted registries. Probes `/v2/`, parses `WWW-Authenticate` challenges, exchanges tokens (GET with POST fallback), resolves credentials from config, environment variables, or Docker config/helpers, and caches tokens per scope with TTL expiry (in-memory, per-scope). 299 tests. The auth engine is transport-agnostic logic -- it produces token headers but does not perform live HTTP. Callers provide a `*std.http.Client` and an allocator; the library handles everything else.
- **Public resolver path** (v0.2.6): `resolve` and `getManifest` now perform live manifest fetches through Zig 0.16 `std.http.Client`, reuse the shipped auth engine, verify manifest digests against pinned references and `Docker-Content-Digest`, follow OCI indexes and Docker manifest lists to a selected child manifest when a platform is provided, preserve the selected platform in `ResolveResult`, and enforce a bounded nested-index recursion limit.
- **Benchmarking**: `z-oci-bench` measures per-call timing and allocation counts using a counting allocator and [zebrac](https://github.com/eneskemalergin/zebrac) for statistical sampling.

### Current limitations

- Multi-arch public calls without an explicit platform still return `error.NotYetImplemented` instead of guessing a default child.
- `validate` still has no platform-aware multi-arch path, so multi-arch validation remains explicitly unsupported at the public boundary.
- Retry and rate-limit policy beyond the current correctness-first fetch path.
- CLI commands built on top of the live resolver surface.

### Registry support

| Registries             | Status                                    |
| ---------------------- | ----------------------------------------- |
| Docker Hub, GHCR, Quay | Tested with auth engine                   |
| GitLab, Harbor         | Covered by generic bearer mock tests      |
| ECR, GCR, ACR          | Deferred; use the credential helper chain |

### Performance

| Operation                 | Time    | Allocations |
| ------------------------- | ------- | ----------- |
| `Reference.parse`         | 33 μs   | 4           |
| `Digest.parse`            | 0.4 μs  | 0           |
| `json.parse(Manifest)`    | 46 μs   | ~3          |
| `parseAuthenticateHeader` | 5.6 μs  | 0           |
| `Platform.match`          | 0.15 μs | 0           |
| `authenticate` (miss)     | 145 μs  | ~13         |
| `authenticate` (hit)      | 31 μs   | 4           |

Full zebrac baseline at `benchmarks/baselines/`. CHANGELOG at [CHANGELOG.md](CHANGELOG.md).

## Getting started

**Requirements:** Zig **0.16.0** or later.

### Add as a dependency

```sh
zig fetch --save git+https://github.com/eneskemalergin/z-oci#v0.2.0
```

Then in `build.zig`, import the package:

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

- `zig build`: build and install the stub CLI plus the package module
- `zig build test`: run all unit tests and smoke checks
- `zig build examples`: build the offline example programs
- `zig build examples-smoke`: run a small smoke pass over the example programs
- `zig build workflow-smoke`: run the offline workflow smoke-test matrix
- `zig build bench`: build the benchmark CLI (`z-oci-bench`)

Fixtures under `fixtures/` are checked-in snapshots, not live fetches. Their provenance and refresh notes live in [fixtures/SOURCES.md](fixtures/SOURCES.md).

The published Zig package bundles `src/`, `examples/`, `fixtures/`, `assets/`, `benchmarks/`, and the build files, so the documented examples and tests work from a dependency fetch.

## Offline examples

- `zig build example-normalize-reference -- ubuntu:22.04`
- `zig build example-inspect-manifest`
- `zig build example-select-platform`

See [examples](examples) for the source of the packaged examples.

## What is next

- Public API semantic cleanup around multi-arch `validate` and the remaining explicit `NotYetImplemented` cases
- Rate limiting and retry logic
- CLI for resolve, validate, and inspect
- More registry compatibility testing

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
