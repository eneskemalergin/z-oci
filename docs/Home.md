# z-oci

If you need registry metadata from Zig, start here. z-oci reads OCI and Docker image references, resolves manifests to verified digests, and keeps the choice between library and CLI use clear.

z-oci is read-only. It can parse references, authenticate through the OCI Bearer flow when configured, fetch and verify manifests, validate exact digests, inspect metadata, and select platforms from multi-arch indexes. It does not pull layers, push images, build images, or run containers.

## Choose a path

- Use the [library](Library.md) when your program should own its allocator, I/O, HTTP client, credentials, and result lifetime.
- Use the [CLI](CLI.md) when you want `resolve`, `validate`, or `inspect` from a shell, script, or CI job.

Both paths use the same public resolver implementation. The library keeps process credential discovery opt-in. The CLI wires process sources for its own invocation. See [Credentials](Credentials.md) before adding authenticated access.

## Start here

- [Installation](Installation.md) explains dependency and checkout builds.
- [Library](Library.md) shows a complete `resolve` call and cleanup paths.
- [CLI](CLI.md) covers command grammar, output, streams, and exit codes.
- [Examples](Examples.md) separates offline fixture flows from the live resolver example.
- [Troubleshooting](Troubleshooting.md) covers command, credential, HTTPS, and platform failures.

## Public API at a glance

- `Reference` parses and normalizes Docker and OCI image references.
- `resolve` returns a verified digest-pinned result.
- `validate` checks whether an exact digest exists without returning a manifest.
- `getManifest` returns a parsed manifest document.
- `inspect` returns top-level manifest or index metadata and an optional selected leaf.
- `resolveMany` resolves references sequentially with caller-owned results.
- `pingRegistry` checks registry `/v2/` reachability independently of resolution.

The platform selector handles OCI image indexes and Docker manifest lists. The [Platform and limits](Platform.md) page describes matching rules, nested-index limits, HTTPS boundaries, and `Config` defaults.

## Project facts

The package requires Zig 0.16.0 or later, has no external package dependencies, and is released under the MIT License. The current package and latest tagged release are `v0.7.0`.

For registry evidence and known boundaries, see [Registry compatibility](RegistryCompatibility.md). The [documentation pages](Installation.md) are the maintained starting point for using the package.
