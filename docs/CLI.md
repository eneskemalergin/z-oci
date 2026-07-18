# CLI

If you want to resolve or inspect an image from a shell, script, or CI job, the CLI gives you that path without requiring application code. It provides `resolve`, `validate`, and `inspect` over the same public resolver used by the library.

## Quick start

Build the executable, then put command options before the image argument:

```sh
zig build

./zig-out/bin/z-oci resolve --platform linux/amd64 ubuntu:22.04
./zig-out/bin/z-oci validate ubuntu@sha256:<64-hex-digest>
./zig-out/bin/z-oci inspect --format json ubuntu:22.04
```

Registry commands may contact a live HTTPS registry. Credentials are configured through the process adapter; they are not command-line arguments. See [Credentials](Credentials.md) for the supported process sources.

`z-oci --version` prints `z-oci 0.7.2`. Use `z-oci --help` or `z-oci <command> --help` for the complete option text.

## Commands and options

The top-level form is:

```text
z-oci [global-options] <command> [command-options] <image>
```

Commands:

- `resolve <image>` resolves an image reference to a verified digest-pinned reference.
- `validate <image@sha256:...>` checks whether an exact `sha256` digest exists in the registry.
- `inspect <image>` shows the top-level manifest or index and optional selected-leaf metadata.

Options that configure the process adapter must come before the command:

- `--ca-bundle <path>` uses a public CA bundle for registry HTTPS.
- `--helper-timeout-ms <ms>` sets the credential-helper I/O timeout.

`--help` and `--version` can be used at the top level or as the sole option after a command.

Command options must come after the command and before the image:

- `--format text|json` selects the output format. The default is `text`.
- `--platform <os/arch[/variant]>` selects a platform for multi-arch images. It is available for `resolve` and `inspect`.
- `--verbose` writes elapsed time and the outcome to standard error.

The library `Config` fields for retries, response limits, token-cache capacity, and connect timeout are not CLI options. The CLI exposes the process-facing CA-bundle and credential-helper timeout settings listed above.

## Output

Text output is compact and suitable for terminal use or shell pipelines. JSON output is command-specific and intended for programmatic consumers.

Successful `resolve` output contains a pinned reference in text mode:

```text
registry-1.docker.io/library/ubuntu@sha256:<64-hex-digest>
```

In JSON mode, `resolve` returns the input, pinned reference, digest, media type, and selected platform:

```json
{"command":"resolve","input":"ubuntu:22.04","reference":"registry-1.docker.io/library/ubuntu@sha256:<64-hex-digest>","digest":"sha256:<64-hex-digest>","media_type":"application/vnd.oci.image.manifest.v1+json","platform":{"os":"linux","architecture":"amd64","variant":null,"os_version":null,"os_features":null}}
```

`validate` reports its result in text mode:

```text
validate success: valid
validate not found: not-found
```

Its JSON form contains the reference and a boolean result:

```json
{"command":"validate","reference":"registry-1.docker.io/library/ubuntu@sha256:<64-hex-digest>","valid":true}
```

`inspect` text lists top-level metadata and, when requested, the selected leaf. A single-manifest result looks like this:

```text
inspect:
  reference: registry-1.docker.io/library/ubuntu:22.04
  top_level.kind: manifest
  top_level.media_type: application/vnd.oci.image.manifest.v1+json
  top_level.config_digest: sha256:<64-hex-digest>
  top_level.layers.count: 0
```

`inspect --format json` returns `command`, `reference`, `top_level`, and `selected_leaf`. `top_level` contains the manifest or index kind, media type, config digest, and layer count; for an index, it also contains platform descriptors. `selected_leaf` is an object containing the requested platform and selected manifest metadata, or `null` when no leaf was selected. For an index, use `--platform os/arch[/variant]` when you need a selected leaf.

## Streams and failures

Successful results, help, and version output go to standard output. Text failures and verbose timing go to standard error. JSON failures remain on standard output so callers can parse the error object.

A verbose line has this form, with the measured value varying by run:

```text
z-oci verbose: command=resolve outcome=success elapsed_ms=37
```

Numeric exit codes are:

```text
0   success
1   not found
2   authentication failure
3   rate limited
4   network failure
5   usage failure
6   local configuration failure
7   digest failure
8   content type failure
9   manifest content failure
10  timeout
11  platform selection failure
12  unexpected failure
```

Diagnostics do not include credentials, authorization values, credential-helper data, raw headers, or response bodies.

For credential setup and trust-bundle behavior, see [Credentials](Credentials.md). For platform matching and configured limits, see [Platform and limits](Platform.md). [Troubleshooting](Troubleshooting.md) covers common command and registry failures.
