<!-- markdownlint-disable MD033 MD036 MD041 -->
<p align="center">
  <img src="assets/z-oci-icon.svg" alt="z-oci logo" width="90">
</p>

<h1 align="center">z-oci</h1>

<p align="center">
  Pure Zig OCI/Docker Registry API v2 client. Resolves image references to pinned SHA256 digests. Zero dependencies, Zig 0.16 std only.
</p>

<p align="center">
  <!-- <a href="https://github.com/eneskemalergin/z-oci/actions/workflows/ci.yml">
    <img src="https://github.com/eneskemalergin/z-oci/actions/workflows/ci.yml/badge.svg?style=flat-square" alt="CI">
  </a> -->
  <img src="https://img.shields.io/badge/version-0.0.2-8B5CF6?style=flat-square" alt="v0.0.2">
  <img src="https://img.shields.io/badge/status-early%20development-E57C23?style=flat-square" alt="Status: early development">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/OCI-Distribution%20Spec-0066CC?style=flat-square" alt="OCI Distribution Spec">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

**What ships in v0.0.2:**

- `Reference` parser: handles bare names, tags, digests, registries with ports, nested paths, Docker Hub aliases, and tag+digest refs
- `Digest`: SHA-256 parse and validation, hex borrowing from caller input, no allocation
- `MediaType`: OCI and Docker MIME type enum with `fromString`, `isMultiArch`, `isLegacy`
- `Platform`: os/arch/variant struct with partial match (variant optional, os_version prefix) and strict `eql`
- `Descriptor`, `Manifest`, `OciImageIndex`, `DockerManifestList`: full OCI type system
- `MultiArchManifest`: tagged union over both index types with `filterByPlatform`

**Coming later:**

- JSON parse/stringify with camelCase mapping for OCI spec fields
- `resolve`: tag-to-digest resolution over HTTP, HEAD-first with GET fallback
- Multi-arch resolution with platform fallback and nested index recursion
- Bearer token auth with pluggable credential providers
- Rate-limit handling: 429 backoff, `Retry-After`, exponential jitter
- Batch resolve with shared token and digest cache

## Requirements

Zig **0.16.0** or later.

<!--
## Installation

Add z-oci as a dependency in your `build.zig.zon`:

```zig
.dependencies = .{
    .z_oci = .{
        .url = "https://github.com/eneskemalergin/z-oci/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "<run zig fetch to get the hash>",
    },
},
```

Or use `zig fetch` to add it automatically:

```sh
zig fetch --save https://github.com/eneskemalergin/z-oci/archive/refs/tags/v0.1.0.tar.gz
```

Then wire it up in your `build.zig`:

```zig
const z_oci = b.dependency("z_oci", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("z_oci", z_oci.module("z_oci"));
```
-->

<!--
## Quick start

### Resolve a tag to a pinned digest

```zig
const std = @import("std");
const z_oci = @import("z_oci");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var http_client = std.http.Client{ .allocator = arena.allocator() };
    defer http_client.deinit();

    const config = z_oci.client.Config{
        .credential_provider = .anonymous,
    };

    const result = try z_oci.client.resolve(
        arena.allocator(),
        &http_client,
        config,
        "library/alpine:latest",
        null, // platform: null uses host platform
    );

    // result.digest     → "sha256:a856..."
    // result.media_type → "application/vnd.oci.image.manifest.v1+json"
    // result.platform   → null (single-arch) or Platform{...}
    std.debug.print("digest: {s}\n", .{result.digest});
}
```

### Validate a pinned digest

```zig
const exists = try z_oci.client.validate(
    arena.allocator(),
    &http_client,
    config,
    "library/alpine@sha256:a856...",
);
```

### Inspect full manifest metadata

```zig
const parsed = try z_oci.client.getManifest(
    arena.allocator(),
    &http_client,
    config,
    "library/alpine:latest",
    null,
);
// parsed.value is a z_oci.types.Manifest
```

### Batch resolve

```zig
const refs = &[_][]const u8{
    "library/alpine:latest",
    "library/ubuntu:22.04",
    "library/debian:bookworm",
};

const results = try z_oci.client.resolveMany(
    arena.allocator(),
    &http_client,
    config,
    refs,
    null,
);
```
-->

<!--
## API

### `resolve`

```zig
pub fn resolve(
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    config: Config,
    ref: []const u8,
    platform: ?types.Platform,
) ResolveError!ResolveResult
```

Resolves `registry/repo:tag` or `registry/repo@sha256:...` to a pinned digest. Uses HEAD for fast extraction, falls back to GET for body verification. For multi-arch images, selects the manifest matching `platform` (defaults to host platform when `null`).

### `validate`

```zig
pub fn validate(
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    config: Config,
    ref: []const u8,
) ResolveError!bool
```

HEAD-checks whether a pinned digest reference still exists in the registry. Returns `true` if present, `false` on 404.

### `getManifest`

```zig
pub fn getManifest(
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    config: Config,
    ref: []const u8,
    platform: ?types.Platform,
) ResolveError!types.Parsed(types.Manifest)
```

Fetches and returns the full manifest for inspection. `Parsed(T)` is an arena-backed wrapper; free with `parsed.deinit()` or deinit the arena.

### `resolveMany`

```zig
pub fn resolveMany(
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    config: Config,
    refs: []const []const u8,
    platform: ?types.Platform,
) ResolveError![]ResolveResult
```

Batch resolve with a shared `TokenCache` and session digest cache. Amortizes token requests across all refs in the batch.

### `ResolveResult`

```zig
pub const ResolveResult = struct {
    digest:     []const u8,   // "sha256:<hex>"
    media_type: []const u8,   // normalized Content-Type
    platform:   ?types.Platform, // null for single-arch manifests
};
```

### `Config`

```zig
pub const Config = struct {
    credential_provider: auth.CredentialProvider,
    max_retries:         u32 = 3,
    connect_timeout_ms:  u64 = 5_000,
    read_timeout_ms:     u64 = 30_000,
};
```

### `ResolveError`

| Error | Cause |
| ----- | ----- |
| `Unauthorized` | Auth challenge failed or credentials rejected |
| `NotFound` | Image reference does not exist |
| `ContentTypeMismatch` | Legacy schema 1 or unexpected media type |
| `ManifestParseError` | JSON decode failed or nesting depth exceeded |
| `PlatformNotFound` | No manifest in the index matches the requested platform |
| `RateLimitExceeded` | 429 persisted after all retries with backoff |
| `NetworkError` | `std.http.Client` connection or read failure |
| `OutOfMemory` | Allocator exhausted |

### Core types

| Type | Description |
| ---- | ----------- |
| `types.Digest` | Algorithm + raw bytes. Parses/formats `"sha256:<hex>"`. |
| `types.MediaType` | Known OCI and Docker media type constants with detection helpers. |
| `types.Platform` | `os`, `arch`, `variant`, `os.version`, `os.features`. Partial match. |
| `types.Descriptor` | OCI content descriptor: `mediaType`, `digest`, `size`, `platform`, `annotations`. |
| `types.Manifest` | OCI Image Manifest + Docker V2 Schema 2. |
| `types.OciImageIndex` | OCI Image Index for multi-arch. |
| `types.DockerManifestList` | Docker Manifest List for multi-arch. |
| `auth.CredentialProvider` | Pluggable interface: anonymous, env vars, Docker config, process helpers. |

### Memory model

All allocation goes through the `allocator` you pass. Two options:

1. **Arena**: pass `arena.allocator()` and call `arena.deinit()` when done. No per-object cleanup needed.
2. **GPA**: call `parsed.deinit()` on `Parsed(T)` values and free `ResolveResult` slices manually.
-->

## Build steps

| Command | What it does |
| ------- | ------------ |
| `zig build` | Compile the library |
| `zig build test` | Run all unit tests |
| `zig build run` | Run the CLI (once implemented) |

## Roadmap

**Phase 1: Types, parsers, API contracts (v0.0.1 to v0.0.4)**

| Version | Status | Description |
| ------- | ------ | ----------- |
| v0.0.1 | done | Leaf types: `Digest`, `MediaType`, `Platform` |
| v0.0.2 | done | OCI types: `Reference`, `Descriptor`, `Manifest`, `Index` |
| v0.0.3 | next | JSON infrastructure, `ResolveError`, `ResolveResult`, `Config` skeleton |
| v0.0.4 | | Public function signatures, arena lifetime contract, fuzz tests |

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
