# Platform and limits

z-oci selects image platforms from OCI indexes and Docker manifest lists. A platform has a required `os` and `architecture`, plus optional `variant`, `os_version`, and `os_features` fields.

## Select a platform

The CLI accepts `os/arch[/variant]`:

```sh
./zig-out/bin/z-oci resolve --platform linux/amd64 ubuntu:22.04
./zig-out/bin/z-oci inspect --platform linux/amd64 --format json ubuntu:22.04
```

The library accepts a `Platform` value:

```zig
const platform = z_oci.Platform{
    .os = "linux",
    .architecture = "amd64",
};
```

Matching follows these rules:

- `os` and `architecture` are required and compared case-insensitively.
- An omitted `variant` accepts any candidate variant. A supplied variant must match case-insensitively.
- A library filter with `os_version` uses dot-segment prefix matching. `10.0` matches `10.0.17763`, but not `10.01`.
- `os_features` is parsed and preserved as metadata; `Platform.match` does not use it as a selection constraint.
- Nested indexes are followed through at most four child levels. A deeper chain returns `depth_limit_exceeded`.

For `resolve`, `validate`, and `getManifest`, a multi-arch reference without a platform returns `platform_required`. `inspect` can return the top-level index without selecting a leaf. If no descriptor matches, the selecting operation returns `platform_not_found`. The CLI does not accept `--platform` for `validate` because that command requires an exact digest reference.

## HTTPS and trust

Registry request builders use HTTPS. The live manifest, token, and `/v2/` ping exchangers rewrite URLs to cleartext HTTP only for `127.0.0.1`, `localhost`, and `::1`, which supports local registry tests. Other hosts remain HTTPS.

The repository verifies live HTTPS behavior on Linux and macOS. Windows is not a verified supported build target for this repository. The Zig standard library has Windows TLS support, but this project also uses POSIX clock APIs in retry and authentication policy. A custom CA bundle does not establish Windows support.

`Config.ca_bundle_path` loads a certificate-only PEM trust bundle and replaces the client's OS trust bundle rather than merging with it. The file must not contain private-key PEM blocks, and POSIX files that are writable by other users are rejected. See [Credentials](Credentials.md) for CLI and library trust-bundle setup.

## Configuration defaults

These are the defaults in the public `Config` type:

- `max_manifest_bytes`: 8 MiB per manifest response.
- `max_token_response_bytes`: 64 KiB per token response.
- `max_token_cache_entries`: 128 cached token scopes per `AuthEngine`; `0` disables the entry limit.
- `max_retries`: 1 retry after invalidating a cached token that received `401`.
- `max_network_retries`: 1 retry for retryable transport errors and `502`, `503`, or `504` responses.
- `max_rate_limit_retries`: 1 retry for `429` responses.
- `rate_limit_enabled`: `false`; when enabled, pre-emptive sleeping uses complete trusted `RateLimit-*` metadata.
- `read_timeout_ms`: 30,000 ms for Docker credential-helper I/O; `0` disables that helper timeout.
- `connect_timeout_ms`: `0`. The live resolver path does not apply this value to `std.http.Client.request`; it is available to caller-owned connection recipes through `Config.connectIoTimeout()`.

Public resolve calls create a call-scoped auth engine. Code that creates an `AuthEngine` directly owns it and must call `deinit()`.

## Scope boundaries

z-oci reads registry metadata. It does not pull layers, push images, build images, or act as a container runtime.
