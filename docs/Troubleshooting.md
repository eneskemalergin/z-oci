# Troubleshooting

Start by separating local command errors from registry failures. The CLI keeps usage, configuration, and resolver failures distinct, writes diagnostics without credentials, and returns a stable exit code for each category.

## The command is rejected

Run the relevant help command:

```sh
./zig-out/bin/z-oci --help
./zig-out/bin/z-oci resolve --help
```

Put global options before the command:

```sh
./zig-out/bin/z-oci --ca-bundle ./ca-bundle.pem resolve ubuntu:22.04
```

Put command options after the command and before the image. `--platform` is available for `resolve` and `inspect`, not `validate`. `validate` also requires an exact `image@sha256:<64-hex-digest>` reference.

Usage errors return exit code `5`. Help and version output return exit code `0`.

## Authentication fails

The bare library `Config{}` is anonymous. Inject `credential_provider` or `credential_sources` for a library call. The CLI process adapter injects its environment map, Docker configuration discovery, and helper I/O for that invocation; credentials are not accepted as command-line arguments.

For environment credentials, verify `Z_OCI_REGISTRY_HOST`, `Z_OCI_REGISTRY_USER`, and `Z_OCI_REGISTRY_TOKEN`. The configured host must match the requested registry. For Docker credentials, check `DOCKER_CONFIG`, `HOME`, or `USERPROFILE`, then check the registry-specific helper, inline `auths`, and global `credsStore` in the documented order. See [Credentials](Credentials.md) for the exact source rules.

A helper error is terminal for that configured helper path. It does not silently fall back to anonymous access. In library code, keep borrowed environment maps, Docker JSON, and helper I/O alive until the call returns.

Authentication failures return exit code `2`. A `401` from a registry may also mean that credentials are required, not that the registry is unreachable.

## HTTPS or certificates fail

Confirm that `--ca-bundle` or `Config.ca_bundle_path` points to a readable certificate-only PEM bundle. A custom bundle replaces the OS trust bundle rather than merging with it. Private-key PEM blocks are rejected, and POSIX bundles writable by other users are rejected.

The helper timeout controls credential-helper I/O only. It does not set a timeout for manifest, token, or general registry requests. See [Platform and limits](Platform.md) for timeout scope and platform boundaries.

Certificate and other local configuration failures return exit code `6`. The JSON error code identifies the specific configuration failure, such as `ca_bundle_file_not_found` or `ca_bundle_invalid`.

## The registry request fails

Use the text error or request JSON to distinguish the failure:

- Exit `1`, `not_found`: the requested manifest or tag was not found.
- Exit `2`, `auth_failed`: authentication or token exchange failed.
- Exit `3`, `rate_limited`: the registry rejected the request for rate limits after the configured retries.
- Exit `4`, `network_error`: a transport or retryable registry failure remained.
- Exit `7`, `digest_mismatch` or `unsupported_algorithm`: digest verification failed.
- Exit `8`, `content_type_mismatch`: the response was not an accepted manifest type.
- Exit `9`, `manifest_parse_error`, `response_too_large`, or `depth_limit_exceeded`: the manifest content could not be processed.
- Exit `10`, `timeout`: a configured operation timed out.
- Exit `12`, `unexpected`: an unclassified process failure occurred.

The complete code list and output shapes are in [CLI](CLI.md). The library returns these resolver failures as tagged `ResolveError` values instead of process exit codes.

## A platform cannot be selected

Use `inspect` to view top-level manifest or index metadata, then pass an exact `os/arch[/variant]` filter to `resolve` or `inspect`:

```sh
./zig-out/bin/z-oci inspect --format json ubuntu:22.04
./zig-out/bin/z-oci inspect --platform linux/amd64 --format json ubuntu:22.04
```

Omitting a variant accepts any candidate variant. Supplying one requires a case-insensitive match. A missing platform is different from a missing reference:

- `platform_required` means a multi-arch document needs a platform selection.
- `platform_not_found` means the requested platform is absent.
- `depth_limit_exceeded` means nested index traversal exceeded four child levels.

Library filters can also use `os_version`; it uses dot-segment prefix matching. `os_features` is preserved metadata and is not a selector constraint. Platform failures return exit code `11` in the CLI.

## Output goes to the wrong stream

Successful output, help, and version go to standard output. Text diagnostics and `--verbose` timing go to standard error. JSON failures go to standard output so a script can parse them. Use `--format json` when a caller needs structured failure data.
