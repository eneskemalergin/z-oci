<!-- markdownlint-disable MD033 MD036 MD041 -->
<p align="center">
  <img src="assets/z-oci-icon.svg" alt="z-oci logo" width="90">
</p>

<h1 align="center">z-oci</h1>

<p align="center">
    Pure Zig OCI/Docker Registry API v2 toolkit. Reference parsing, live manifest resolution, auth engine. Zero external dependencies.
</p>

<p align="center">
    <img src="https://img.shields.io/badge/version-v0.6.0-8B5CF6?style=flat-square" alt="v0.6.0">
    <img src="https://img.shields.io/badge/status-compat%20testing-2D7D46?style=flat-square" alt="Status: compat testing">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/OCI-Distribution%20Spec-0066CC?style=flat-square" alt="OCI Distribution Spec">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

## What z-oci does

z-oci is a read-only OCI registry client for Zig. Give it an image reference, and it can normalize the name, authenticate with the registry, fetch the manifest, verify the digest, and pick the right child manifest for a platform when the image is multi-arch. Everything is built on Zig 0.16 std with no external dependencies.

## What you can do today

- Parse and normalize Docker and OCI image references, including tags, digests, Docker Hub defaults, and host-plus-port registries.
- Resolve a tag to a pinned digest with `resolve`.
- Resolve many references in one call with `resolveMany` (sequential, partial success, in-call tag cache).
- Check whether a registry answers `/v2/` with `pingRegistry` (anonymous OK or auth required). Independent of resolve: resolve never calls ping.
- Check whether a manifest exists with `validate`.
- Fetch and parse a manifest with `getManifest`.
- Follow OCI indexes and Docker manifest lists when you provide a target platform.
- Run packaged examples for offline parsing, offline batch pinning, and live resolution.
- Measure parser, auth, resolver, and batch costs with `z-oci-bench`.

### Capabilities

- **Reference parsing**: normalize `ubuntu:22.04`, `ghcr.io/owner/repo@sha256:...`, `localhost:5000/myimage:dev`, and every other Docker/OCI reference form.
- **OCI types**: `Digest`, `MediaType`, `Platform`, `Descriptor`, `Manifest`, `OciImageIndex`, `DockerManifestList`, and `MultiArchManifest`, all with JSON round-trip support.
- **Auth engine**: Bearer token flow compatible with Docker Hub, GHCR, Quay, and self-hosted registries. Live auth starts from manifest `HEAD`/`GET` challenges (not a separate `/v2/` probe). It parses `WWW-Authenticate` headers, exchanges tokens, resolves credentials from config, environment variables, or Docker config/helpers, and caches tokens per scope with TTL expiry.
- **Public resolver path**: `resolve`, `validate`, `getManifest`, and `resolveMany` perform live manifest fetches through Zig 0.16 `std.http.Client`, reuse the auth engine, verify manifest digests against pinned references and `Docker-Content-Digest`, follow OCI indexes and Docker manifest lists to a selected child manifest when a platform is provided, preserve the selected platform in `ResolveResult`, and enforce a bounded nested-index recursion limit. `resolveMany` is sequential over one shared client and auth engine; it does not parallelize registry traffic.
- **Benchmarking**: `z-oci-bench` measures per-call timing and allocation counts using a counting allocator and [zebrac](https://github.com/eneskemalergin/zebrac) for statistical sampling.

### Current limitations

- Multi-arch public calls without an explicit platform fail explicitly with `ResolveError.platform_required` instead of guessing a default child.
- Per-request HTTP read/connect timeouts are not wired through `std.http.Client.request` on Zig 0.16 yet (`connect_timeout_ms` is exposed for caller-owned `connectTcpOptions` recipes; see `Config` docs and zig#31305).
- Windows is not a supported host for live HTTPS registry traffic. Offline parsing works cross-platform; TLS to registries is validated on Linux and macOS only.
- `pingRegistry` is a status probe. `200` reports anonymous reachability, `401` reports auth required, and everything else maps to `unexpected_status`. Redirects are not followed.
- `resolve` does not call ping, and ping does not call resolve.
- Live exchangers rewrite `https://` to cleartext `http://` only for loopback registry hosts (`127.0.0.1`, `localhost`, `::1`) so offline mock / local `registry:2` tests can use a real `std.http.Client`. Public hostnames stay HTTPS. There is no public Config switch for cleartext.
- User-facing CLI commands built on top of the live resolver surface are still future work.

### Resilience

Reactive transport retries are live on manifest `HEAD`/`GET` and token HTTP paths:

- `Config.max_network_retries` retries transient `5xx` responses and socket-level transport errors.
- `Config.max_rate_limit_retries` retries `429` responses using `Retry-After` / `X-Retry-After` (and response `Date` when present).
- `Config.max_retries` stays auth-only: cached-token invalidation after a manifest `401`.
- `Config.rate_limit_enabled` (default `false`) opts into pre-emptive manifest throttling when trustworthy registry `RateLimit-*` headers show `remaining == 0`.
- `Config.ca_bundle_path` loads a PEM CA trust bundle at the public API boundary (`resolve`, `validate`, `getManifest`, `resolveMany`, `pingRegistry`).
- `ResolveError.rate_limited`, `network_error`, and `timeout` carry `transport_retries_exhausted` so callers can distinguish immediate hard failures from post-retry exhaustion.

See [CHANGELOG.md](CHANGELOG.md) and `src/resilience.zig` for registry header assumptions (Docker Hub epoch `Retry-After`, `X-RateLimit-Reset`, and related parser behavior).

### Registry coverage

Docker Hub, Quay, and GHCR are the main named targets in the current code and tests.

- Docker Hub: covered in auth tests and exercised on the live resolver path.
- Quay: covered in auth tests and fixture-backed resolver coverage.
- GHCR: covered in auth and challenge-flow tests.
- GitLab and Harbor: covered through generic bearer-registry mock tests.
- Distribution `registry:2` on loopback: opt-in `zig build integration-registry` (see [integration/registry2/README.md](integration/registry2/README.md)).
- ECR, GCR, and ACR: not first-class targets yet. Use the credential helper chain where it fits your setup.

Checked-in fixtures and in-process mocks cover most paths in `zig build test`. Live registry checks use packaged examples and are not part of the default gate.

### Performance

ReleaseFast baseline for this version is `benchmarks/baselines/v0.6.0.json`:

| Operation                 | Mean per iteration | Mean RSS | Samples |
| ------------------------- | ------------------ | -------- | ------- |
| `reference-parse`         | 306847.4 us        | 1.05 MB  | 14      |
| `digest-parse`            | 1331.9 us          | 1.05 MB  | 2985    |
| `manifest-parse`          | 262327.0 us        | 1.07 MB  | 16      |
| `challenge-parse`         | 5318.3 us          | 1.10 MB  | 751     |
| `platform-match`          | 1319.3 us          | 1.29 MB  | 3013    |
| `authenticate-miss`       | 69191.6 us         | 3.05 MB  | 58      |
| `authenticate-hit`        | 1589.2 us          | 1.70 MB  | 2505    |
| `authenticate-rate-limit` | 83847.2 us         | 3.05 MB  | 48      |
| `resolve-single`          | 42199.9 us         | 1.97 MB  | 95      |
| `resolve-single-retry`    | 42154.7 us         | 1.99 MB  | 95      |
| `resolve-session`         | 43309.9 us         | 2.01 MB  | 93      |
| `resolve-many`            | 199525.9 us        | 2.02 MB  | 21      |
| `resolve-many-unique`     | 385818.8 us        | 2.03 MB  | 11      |
| `resolve-multi`           | 175768.9 us        | 2.03 MB  | 23      |
| `validate-single`         | 25160.7 us         | 2.04 MB  | 159     |
| `get-manifest`            | 54015.5 us         | 2.07 MB  | 75      |

v0.6.0 Debug `--counting` snapshot for core resolve ops (100 iterations; see `benchmarks/baselines/v0.6.0-debug-counting.txt`): `resolve-single` 500 allocs/call, `resolve-session` 500 allocs/call, `resolve-many` 2700 allocs/batch, `resolve-many-unique` 5000 allocs/batch.

## Getting started

**Requirements:** Zig **0.16.0** or later.

### Add as a dependency

```sh
zig fetch --save git+https://github.com/eneskemalergin/z-oci#v0.6.0
```

Then in `build.zig`, import the package:

```zig
const z_oci = b.dependency("z_oci", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("z_oci", z_oci.module("z_oci"));
```

### Live resolver entry points

```zig
const outcome = try z_oci.resolve(allocator, &client, config, ref, .{ .os = "linux", .architecture = "amd64" });
switch (outcome) {
    .success => |result| {
        defer result.deinit(allocator);
        // use result.digest, result.reference, ...
    },
    .failure => |failure| {
        defer z_oci.deinitResolveFailure(failure, allocator);
        // handle failure
    },
}
const validity = try z_oci.validate(allocator, &client, config, ref, null);
switch (validity) {
    .valid, .not_found => {},
    .failure => |failure| {
        defer z_oci.deinitResolveFailure(failure, allocator);
        // handle failure
    },
}
const manifest_outcome = try z_oci.getManifest(allocator, &client, config, ref, .{ .os = "linux", .architecture = "amd64" });
switch (manifest_outcome) {
    .success => |manifest| {
        defer manifest.deinit();
        // use manifest
    },
    .failure => |failure| {
        defer z_oci.deinitResolveFailure(failure, allocator);
        // handle failure
    },
}
```

`resolve`, `validate`, and `getManifest` all use a caller-owned `std.http.Client` and the same auth-backed resolver flow.

On single-resolve `.failure`, keep the input `Reference` alive until after you finish reading or formatting the error: `registry` borrows that input. Then call `deinitResolveFailure` (or `ResolveError.deinitOwned`) and `Reference.deinit`.

### Batch resolve (`resolveMany`)

`resolveMany` resolves a slice of references in order and returns one outcome per input. One item failure does not abort the rest. There is no parallel registry traffic in this API: one caller-owned `std.http.Client` and one shared `AuthEngine` serve the whole batch.

```zig
var result = try z_oci.resolveMany(allocator, &client, config, refs[0..], .{
    .platform = .{ .os = "linux", .architecture = "amd64" },
});
defer result.deinit(allocator); // tears down every item; do not use deinitResolveFailure here

for (result.items) |item| {
    switch (item) {
        .success => |resolved| {
            // use resolved.digest / resolved.reference
        },
        .failure => |failure| {
            // batch failures own both registry and reference; result.deinit frees them
            _ = failure;
        },
    }
}
```

Ownership:

- Input `refs` are borrowed. Callers keep and free their own `Reference` values.
- `ResolveManyResult` owns the item slice and every item. Call `result.deinit(allocator)` once.
- Successful items own a `ResolveResult` (same teardown as single-resolve success).
- Failed items own both `registry` and `reference`. Do not call `deinitResolveFailure` on them; that helper is single-resolve only and would leak `registry`.

Platform is batch-wide via `ResolveManyOptions.platform`. Per-item platforms need separate batches.

Session cache (in-call only):

- Within one `resolveMany` call, successful tag pins and implicit `latest` pins can be reused for later duplicate inputs.
- Digest-addressed references never hit the session cache.
- The cache does not survive past the call. A second `resolveMany` starts empty.

Progress callbacks (optional `ResolveManyOptions.progress_fn`):

- Events are `item_started`, `cache_hit`, `item_succeeded`, and `item_failed`.
- `event.reference` borrows input slices for the callback duration only. Copy any strings you need to keep.
- Callbacks are `void`: they cannot fail or cancel the batch.

Offline demo (injected exchangers, no live network):

```sh
zig build example-resolve-many
```

See [examples/resolve-many.zig](examples/resolve-many.zig). Live callers should use public `resolveMany` with a real `std.http.Client`.

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

This repository vendors Zig 0.16 under `./zig-0.16.0/`. Prefer the bundled compiler and pass `--zig-lib-dir ./zig-0.16.0/lib` so builds match the documented offline gate:

```sh
./zig-0.16.0/zig build test --summary all --zig-lib-dir ./zig-0.16.0/lib
```

- `zig build`: build and install the current `z-oci` CLI scaffold and `z-oci-bench` executable
- `zig build test`: run all unit tests, smoke checks, and the `security-check` PEM scan (`tools/check_repo_security.zig`)
- `zig build security-check`: standalone credential and private-key scan (same tool as inside `test`)
- `zig build examples`: build all packaged example programs
- `zig build examples-smoke`: run a small smoke pass over the offline example programs
- `zig build workflow-smoke`: run the offline workflow smoke-test matrix
- `zig build bench`: build the benchmark CLI (`z-oci-bench`)
- `zig build integration-registry`: opt-in local `registry:2` checks (requires Docker; clear-fails if absent)

Fixtures under `fixtures/` include checked-in live registry snapshots plus synthetic malformed payloads for deterministic negative-path tests. Their provenance and refresh notes live in [fixtures/SOURCES.md](fixtures/SOURCES.md).

Offline tests can drive a real `std.http.Client` against an in-process loopback mock peer. That peer is test infrastructure only, not part of the public library API.

For Distribution `registry:2` interoperability, use the opt-in step (requires a Docker daemon; clear-fails if absent):

```sh
./zig-0.16.0/zig build integration-registry --zig-lib-dir ./zig-0.16.0/lib
```

See `integration/registry2/README.md`. This step is never part of `zig build test`.

The Zig package contents in this repository bundle `src/`, `examples/`, `fixtures/`, `assets/`, `benchmarks/`, and the build files, so the documented examples and tests work from a dependency fetch.

## Examples

Live example:

- `zig build example-resolve-reference -- ubuntu:22.04`
- `zig build example-resolve-reference -- ubuntu:22.04 linux/amd64`

This example uses the live public `resolve` API and may make network requests or trigger registry auth.

Offline examples:

- `zig build example-normalize-reference -- ubuntu:22.04`
- `zig build example-inspect-manifest`
- `zig build example-select-platform`
- `zig build example-resolve-many` (offline batch pin flow; see Batch resolve above)

See [examples](examples) for the source of the packaged examples.

## Next

- CLI for resolve, validate, and inspect

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
