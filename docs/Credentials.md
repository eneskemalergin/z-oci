# Credentials and trust

If you are here because a registry needs credentials, start by choosing the path you are using. The library keeps credential discovery explicit. The CLI wires the process sources for its own invocation.

## Library mode

`Config{}` uses anonymous access. It does not read the process environment, Docker configuration, or credential helpers unless the caller injects those sources through `Config.credential_sources`.

For a program that owns `std.process.Init`, pass the environment map and process I/O explicitly:

```zig
const z_oci = @import("z_oci");

// Inside a function that receives `std.process.Init` as `init`:
const config = z_oci.Config{
    .credential_sources = .{
        .environ_map = init.environ_map,
        .load_docker_config_from_environ = true,
        .process_io = init.io,
    },
};
```

When the application owns Docker JSON directly, provide it instead:

```zig
const config = z_oci.Config{
    .credential_sources = .{
        .docker_config_json = docker_config_json,
        .process_io = init.io,
    },
};
```

The JSON slice, environment map, and process I/O are borrowed for the resolve call. Keep them valid for that call and do not log them. Use `Config.credential_provider` when the application already has a credential callback; it takes precedence over the injected sources. Provider credential slices must remain valid for the resolve call, and the auth engine invokes a supplied `CredentialHandle.release_fn` after using the credential.

## CLI mode

The executable injects its process environment map, process I/O, and Docker configuration discovery automatically. It accepts no username, password, token, Docker config, or helper name as a command-line argument.

Set the supported environment or Docker configuration source, then run the command:

```sh
z-oci resolve --platform linux/amd64 ubuntu:22.04
```

Global options must come before the command. In particular, `--ca-bundle <path>` and `--helper-timeout-ms <ms>` go before `resolve`, `validate`, or `inspect`. See [CLI](CLI.md) for the complete command grammar.

## Source precedence

For each registry lookup, credentials are considered in this order:

1. A caller-provided `credential_provider`.
2. An injected environment map.
3. Explicit Docker JSON and its configured helpers.
4. Anonymous access when no credential is available.

Within Docker configuration, a registry-specific `credHelpers` entry wins first, followed by an inline `auths` entry, then the global `credsStore` helper. If both `credential_sources.docker_config_json` and `credential_sources.load_docker_config_from_environ` are set, the directly supplied JSON is used.

A configured helper failure maps to an authentication failure, and a helper timeout maps to the timeout path. z-oci does not silently fall back to anonymous access after a helper failure. A malformed inline Docker auth entry is treated as unavailable for that registry lookup.

## Environment and Docker configuration

The environment source is one complete credential selected by these variables:

- `Z_OCI_REGISTRY_HOST`
- `Z_OCI_REGISTRY_USER`
- `Z_OCI_REGISTRY_TOKEN`

All three values must be present and non-empty. The configured host must match the requested registry, ignoring case. Docker Hub aliases such as `docker.io`, `index.docker.io`, and `registry-1.docker.io` are treated as the same registry.

When Docker configuration discovery is enabled, a non-empty `DOCKER_CONFIG` value selects `<DOCKER_CONFIG>/config.json`. If it is absent or empty, the resolver checks `HOME/.docker/config.json`, then `USERPROFILE/.docker/config.json`.

The Docker file can contain:

- inline base64 `auths` entries;
- registry-specific `credHelpers` entries;
- a global `credsStore` helper.

Helpers run as `docker-credential-<suffix> get`. Helper suffixes are validated before spawning a process, and path separators and whitespace are rejected. Loading Docker configuration from the environment requires both an injected environment map and process I/O.

## CA bundles and helper timeout

`--ca-bundle <path>` accepts a certificate-only PEM trust bundle. When supplied, it replaces the client OS trust bundle rather than merging with it. The same behavior is available through `Config.ca_bundle_path`.

The bundle must be no larger than 10 MiB, must not contain private-key PEM blocks, and must not be world-writable on POSIX systems. Use one PEM file containing both the system certificates and any additional corporate roots when both are required. Relative paths are resolved from the current working directory; an absolute path is preferable for services.

`--helper-timeout-ms <ms>` controls credential-helper I/O only. `Config.read_timeout_ms` defaults to 30,000 ms for helper I/O, and `0` means no helper timeout. Neither setting controls manifest, token, or general registry reads.

## Security boundaries

Do not log environment values, Docker configuration, helper output, authorization headers, or resolve failures expecting embedded secrets. Diagnostics contain registry, reference, and HTTP status information, not credentials or response bodies. Owned Docker configuration, helper output, authorization data, and token buffers are cleared before release.

Bearer token endpoints must use HTTPS. Authorization is removed when a manifest redirect changes the scheme, host, or port.

For platform and HTTPS limits, see [Platform and limits](Platform.md). For command failures, see [Troubleshooting](Troubleshooting.md). For the complete library ownership and cleanup model, see [Library](Library.md).
