# Examples

If you want to see how the library is used before writing your own program, start with the offline examples. They use checked-in fixtures or injected exchanges, so they do not need a registry.

## Quick start

Run the offline smoke pass from the repository root:

```sh
zig build examples-smoke
```

To build all five packaged examples without running them:

```sh
zig build examples
```

The individual `example-*` steps build and run one program. Arguments after `--` are passed to that example.

## Offline examples

### Normalize a reference

[`normalize-reference.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/normalize-reference.zig) parses an image reference and prints its normalized registry, repository, tag or digest, and reference form:

```sh
zig build example-normalize-reference -- ubuntu:22.04
```

The example uses the process arena because the parsed reference is printed and then discarded when the process exits.

### Inspect a manifest fixture

[`inspect-manifest.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/inspect-manifest.zig) reads a bounded manifest fixture, prints its media types, digests, layer sizes, and annotations, then calls `parsed.deinit()`:

```sh
zig build example-inspect-manifest
zig build example-inspect-manifest -- fixtures/manifests/busybox-amd64-live-oci-manifest.json
```

The first command uses the checked-in fixture default. The second accepts another manifest JSON path, subject to the example's 32 KiB input limit.

### Select a platform

[`select-platform.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/select-platform.zig) parses an OCI image index or Docker manifest list and selects one descriptor:

```sh
zig build example-select-platform
zig build example-select-platform -- linux arm64
zig build example-select-platform -- fixtures/indexes/busybox-latest-live-oci-index.json linux arm64 v8
```

With no arguments it reads the checked-in index and selects `linux/amd64`. The two-argument form keeps the default index and changes the `os` and `architecture`. The path form accepts an optional variant. The parsed document owns the selected descriptor's borrowed strings until it is released.

### Resolve a batch with injected exchanges

[`resolve-many.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/resolve-many.zig) demonstrates sequential batch resolution with injected manifest and token exchanges. It reads one fixture, processes five references, and expects four pinned results plus one missing-reference failure:

```sh
zig build example-resolve-many
```

This is an offline demonstration of the `z_oci.testing.resolveManyWithExchangers` seam, not a live registry example. The result owns every batch item and is released with `ResolveManyResult.deinit`.

## Live example

[`resolve-reference.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/resolve-reference.zig) calls the public `resolve` API against a registry:

```sh
zig build example-resolve-reference -- ubuntu:22.04
zig build example-resolve-reference -- ubuntu:22.04 linux/amd64
```

These commands may need network access and registry credentials. The example uses `Config{}`, so it starts with anonymous access. It creates a caller-owned HTTP client, releases the successful `ResolveResult`, and cleans up the parsed reference on failure.

The live example is excluded from `examples-smoke`. If you adapt it for a private registry, inject credentials through `Config.credential_sources` as described in [Credentials](Credentials.md). Do not put credentials in command arguments or source files.

## Ownership and next steps

The examples use the process allocator for short-lived command input and caller-owned allocators for parsed documents, clients, references, and results where those values must outlive a step. Follow the cleanup in the source when adapting an example to a longer-lived program.

For a complete library quick start, see [Library](Library.md). For CLI usage, see [CLI](CLI.md). For platform selection details, see [Platform and limits](Platform.md).
