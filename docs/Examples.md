# Examples

The repository contains seven executable examples. Six are deterministic and offline; the live resolver example is separate and may contact a registry.

## Run them

Run the offline smoke set:

```sh
zig build examples-smoke
```

Build all seven examples without running them:

```sh
zig build examples
```

Arguments after `--` are passed to an individual example.

| Example | Demonstrates | Command |
| --- | --- | --- |
| [`normalize-reference.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/normalize-reference.zig) | Docker/OCI reference parsing and normalization | `zig build example-normalize-reference -- ubuntu:22.04` |
| [`inspect-manifest.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/inspect-manifest.zig) | Bounded manifest-fixture parsing and cleanup | `zig build example-inspect-manifest` |
| [`select-platform.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/select-platform.zig) | OCI index and Docker manifest-list selection | `zig build example-select-platform -- linux arm64` |
| [`resolve-many.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/resolve-many.zig) | Batch resolution with injected exchanges | `zig build example-resolve-many` |
| [`validate-reference.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/validate-reference.zig) | Digest validation through an injected HEAD response | `zig build example-validate-reference` |
| [`resolve-authenticated.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/resolve-authenticated.zig) | Bearer challenge, token exchange, and authenticated retry | `zig build example-resolve-authenticated` |
| [`resolve-reference.zig`](https://github.com/eneskemalergin/z-oci/blob/main/examples/resolve-reference.zig) | Live public `resolve` usage | `zig build example-resolve-reference -- ubuntu:22.04` |

The first six examples use fixtures or injected exchanges and do not require a registry. The batch and authenticated examples exercise the public testing seams; they are deterministic demonstrations, not credential configuration recipes.

The live example uses anonymous `Config{}` by default and is excluded from `examples-smoke`:

```sh
zig build example-resolve-reference -- ubuntu:22.04 linux/amd64
```

For authenticated applications, inject `Config.credential_sources` as described in [Credentials](Credentials.md). Never put credentials in command arguments or source files.

Examples use short-lived process or caller-owned allocations. Follow the cleanup shown in the source when adapting one to a longer-lived program. The complete library ownership model is in [Library](Library.md).
