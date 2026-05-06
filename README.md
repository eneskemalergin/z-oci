<!-- markdownlint-disable MD033 MD036 MD041 -->
<p align="center">
  <img src="assets/z-oci-icon.svg" alt="z-oci logo" width="90">
</p>

<h1 align="center">z-oci</h1>

<p align="center">
    Pure Zig OCI/Docker Registry API v2 toolkit. Offline reference parsing, OCI JSON handling, and resolver API contracts. Zero dependencies, Zig 0.16 std only.
</p>

<p align="center">
  <!-- <a href="https://github.com/eneskemalergin/z-oci/actions/workflows/ci.yml">
    <img src="https://github.com/eneskemalergin/z-oci/actions/workflows/ci.yml/badge.svg?style=flat-square" alt="CI">
  </a> -->
  <img src="https://img.shields.io/badge/version-0.0.5-8B5CF6?style=flat-square" alt="v0.0.5">
  <img src="https://img.shields.io/badge/status-early%20development-E57C23?style=flat-square" alt="Status: early development">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/OCI-Distribution%20Spec-0066CC?style=flat-square" alt="OCI Distribution Spec">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

**What ships in v0.0.5:**

- `Digest`, `MediaType`, and `Platform`: leaf types with parser, matching, and formatting behavior
- `Reference`: full Docker/OCI reference parser with owned-lifetime semantics
- `Descriptor`, `Manifest`, `OciImageIndex`, and `DockerManifestList`: OCI/Docker data model types
- `MultiArchManifest`: platform selection over multi-arch indices and manifest lists
- `json.parse(T, allocator, bytes)`: OCI-friendly JSON wrapper over `std.json.Parsed(T)`
- `ResolveError`, `ResolveResult`, and `Config`: public contract types for the future resolver surface
- `resolve`, `validate`, and `getManifest`: public API stubs with documented ownership contracts

**What works now:**

- normalize and validate image references offline
- parse, inspect, and re-stringify OCI manifests and indexes offline
- select platform-matching descriptors from parsed multi-arch data
- exercise the intended resolver memory model without any network code

**What does not work yet:**

- registry HTTP transport
- auth and token exchange
- real tag-to-digest resolution
- manifest fetching from registries
- batch resolve and caching behavior

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
| `zig build` | Compile the library |
| `zig build test` | Run all unit tests |
| `zig build run` | Run the CLI (once implemented) |

Live registry fixtures under `fixtures/` are intentional snapshots, not always-current network fetches. `zig build test` validates them in CI because they stay fast; when refreshing them, recapture from the exact URLs and `Accept` headers recorded in `fixtures/SOURCES.md`.

## Roadmap

Public roadmap summary:

| Version | Status | Description |
| ------- | ------ | ----------- |
| v0.0.1 | done | Leaf types: `Digest`, `MediaType`, `Platform` |
| v0.0.2 | done | OCI types: `Reference`, `Descriptor`, `Manifest`, `Index` |
| v0.0.3 | done | JSON infrastructure, `ResolveError`, `ResolveResult`, `Config` skeleton |
| v0.0.4 | done | Public function signatures, arena lifetime contract, fuzz tests |
| v0.0.5 | done | Public-surface tightening, docs cleanup, ownership notes, and test colocation |
| v0.0.6 | next | Offline examples and real OCI-shaped fixtures |
| v0.0.7 | planned | Polished offline workflows ahead of `v0.1.0` |
| Phase 2 | planned | Registry HTTP transport, auth flows, and real resolver behavior |

**Later phases**

| Version | Description |
| ------- | ----------- |
| v0.1.0 | Auth engine: Bearer token flow, credential helpers |
| v0.2.0 | Manifest resolution: HEAD/GET, multi-arch, nested index |
| v0.3.0 | Rate limiting: backoff, batch API, session cache |
| v0.4.0 | Testing: mock server, local registry, CI |
| v0.5.0 | CLI: `z-oci resolve`, `validate`, `inspect` |
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
