<!-- markdownlint-disable MD033 MD036 MD041 -->
<p align="center">
  <img src="assets/z-oci-icon.svg" alt="z-oci logo" width="90">
</p>

<h1 align="center">z-oci</h1>

<p align="center">
    Pure Zig OCI/Docker Registry API v2 toolkit. Reference parsing, live manifest resolution, auth engine. Zero external dependencies.
</p>

<p align="center">
    <img src="https://img.shields.io/badge/version-v0.7.2-8B5CF6?style=flat-square" alt="v0.7.2">
    <img src="https://img.shields.io/badge/status-release--ready-2D7D46?style=flat-square" alt="Status: release-ready">
  <img src="https://img.shields.io/badge/zig-0.16.0-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig 0.16.0">
  <img src="https://img.shields.io/badge/OCI-Distribution%20Spec-0066CC?style=flat-square" alt="OCI Distribution Spec">
  <img src="https://img.shields.io/badge/license-MIT-4B9D6E?style=flat-square" alt="MIT">
</p>

---

## What is z-oci?

z-oci is a read-only OCI and Docker Registry client for Zig. It parses image references, authenticates when configured, fetches manifests, verifies digests, and selects platforms from multi-arch images. It does not pull layers or push images.

## What it provides

- A library API with caller-owned allocators, HTTP clients, I/O, and results. The CLI uses the same public resolver API.
- Reference parsing for Docker and OCI image references.
- `resolve` for verified digest-pinned results.
- `validate` for checking an exact digest without returning a manifest.
- `getManifest` and `inspect` for manifest and index metadata.
- `resolveMany` for sequential batch resolution with in-call caching for repeated tag pins.
- `pingRegistry` for independent `/v2/` reachability checks.
- OCI Bearer authentication and explicitly injected credential sources.
- OCI image index and Docker manifest list platform selection.

The library uses Zig 0.16.0 or later and has no third-party runtime dependencies. It is read-only by design: blob, layer, push, build, and container-runtime operations are outside its scope.

## Install

### Use as a dependency

Fetch the current tagged release:

```sh
zig fetch --save git+https://github.com/eneskemalergin/z-oci#v0.7.2
```

Import the module from `build.zig`:

```zig
const z_oci = b.dependency("z_oci", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("z_oci", z_oci.module("z_oci"));
```

### Build the current checkout

With Zig 0.16.0 installed and available as `zig`:

```sh
zig build
./zig-out/bin/z-oci --help
```

For prebuilt v0.7.2 CLI archives and checksums, see the [installation guide](docs/Installation.md).

## Library usage

Use the library when your application should own process setup, credentials, HTTP clients, allocators, and result lifetime. Start with the [library quick start](docs/Library.md), which shows a `resolve` call and both result cleanup paths.

The default `Config{}` is anonymous. It does not read environment variables, Docker configuration, or credential helpers. Applications that need them inject `Config.credential_sources` explicitly. See [Credentials](docs/Credentials.md) for the supported sources and precedence.

## CLI usage

The executable provides `resolve`, `validate`, and `inspect` through the public resolver API:

```sh
zig build

./zig-out/bin/z-oci resolve --platform linux/amd64 ubuntu:22.04
./zig-out/bin/z-oci validate ubuntu@sha256:<64-hex-digest>
./zig-out/bin/z-oci inspect --format json ubuntu:22.04
```

Use `--format text|json` for output selection, `--verbose` for elapsed time and outcome on stderr, `--ca-bundle <path>` for a certificate-only trust bundle, and `--helper-timeout-ms <ms>` for credential-helper I/O only. `--platform os/arch[/variant]` is available on `resolve` and `inspect`.

Command options go before the image argument. The [CLI guide](docs/CLI.md) has the complete grammar, output examples, stream routing, and exit-code mapping.

## Limits and credentials

Credentials are never accepted as CLI arguments. The CLI wires process credential sources explicitly; the library remains anonymous unless its caller injects credentials.

Live HTTPS registry traffic is verified on Linux and macOS. Windows is not a verified supported build target for this repository. Per-request network timeout control is also limited by the Zig 0.16 HTTP client. The helper timeout applies to credential-helper I/O, not registry requests.

See [Credentials](docs/Credentials.md), [Platform and limits](docs/Platform.md), [Registry compatibility](docs/RegistryCompatibility.md), and [Troubleshooting](docs/Troubleshooting.md) for the detailed boundaries.

## Examples

Run the deterministic offline examples with `zig build examples-smoke`. See the [examples guide](docs/Examples.md) for the individual programs and the separate live-registry example.

## Documentation

The [documentation home](docs/Home.md) links to installation, library, CLI, credentials, platform, troubleshooting, compatibility, and examples pages. The repository pages are the current documentation source. The same content is intended for the [z-oci GitHub Wiki](https://github.com/eneskemalergin/z-oci/wiki) when it is published.

## Development

The default gate is deterministic and offline:

```sh
zig build test --summary all
```

It covers library and CLI tests, workflow and example smoke checks, and the repository security scan. Formatting, release builds, benchmark compilation, contributor workflow, and opt-in Docker checks are described in [CONTRIBUTING.md](CONTRIBUTING.md).

## References

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec): the registry API this client implements
- [OCI Image Layout Specification](https://github.com/opencontainers/image-spec): manifest and descriptor formats
- [Docker Registry HTTP API V2](https://docs.docker.com/reference/api/registry/latest/): Docker Registry compatibility

## License

MIT. See [LICENSE](LICENSE).

---

<p align="center"><em>
Names fade with the sun,<br>
One seal binds the ancient root -<br>
The ghost finds its frame.
</em></p>
