<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to z-oci are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows [Semantic Versioning](https://semver.org/).

Versions listed here are not yet tagged in git. Tags will follow once the library reaches a stable public API.

## [Unreleased]

Nothing yet.

---

## [0.0.5] - 2026-05-05

### Changed

- `README.md` now reflects the current offline Phase 1 toolkit instead of the old `v0.0.2` shape and outdated `client`/`types` examples.
- `root.zig` module docs now describe the current package surface and ownership model without embedding milestone history.
- Ownership notes in `Reference.zig` and `ResolveResult.zig` were tightened so owned vs borrowed fields are clearer.
- Type-specific JSON contract tests were moved out of `json.zig` and back into `Descriptor.zig`, `Manifest.zig`, and `Index.zig`.

### Fixed

- Public documentation no longer implies the registry client already exists.
- JSON behavior tests are now colocated with the types that own that behavior.

### Verified

- Focused file-scoped tests for moved JSON slices passed during the `v0.0.5` cleanup.
- `zig build test --summary all` passes after the full cleanup pass.

## [0.0.4] - 2026-05-05

### Added

- `root.zig`: public `resolve`, `validate`, and `getManifest` stubs. Each is callable and returns `error.NotYetImplemented` until the transport layer lands.
- Ownership doc comments on the new public API surface. They explain the intended arena lifetime for single-shot calls, batch clone flows, and `std.json.Parsed(Manifest)` values.
- Deterministic fuzz-style smoke tests for `Digest.parse`, `Reference.parse`, and `json.parse(Manifest, ...)`, each covering 10,000 pseudo-random inputs.
- New `Platform.match` edge-case tests for empty strings, UTF-8 `os_version` prefixes, and very long variant strings.
- A fuller `ResolveResult.clone` smoke test that tears the source arena down before validating the clone.

### Fixed

- `root.zig` test discovery now imports all sub-modules during `zig test`, so the full suite is actually executed.
- `Reference.parse` now rejects `ubuntu:` and `myorg/` with `error.InvalidReference` instead of accepting an empty tag or trailing slash path.

### Verified

- `zig test src/root.zig --zig-lib-dir zig-0.16.0/lib/` passes with 161 tests.
- `zig build test --summary all` passes and reports the same suite.
- `zig build -Doptimize=ReleaseSmall` produces a 4.8 KB artifact at `zig-out/bin/z-oci`.

## [0.0.3] - 2026-05-06

### Added

- `json.zig`: `parse(T, allocator, bytes)` wrapper around `std.json.parseFromSlice` with `ignore_unknown_fields: true` for OCI extension field tolerance. Returns `std.json.Parsed(T)` for arena lifecycle management.
- `jsonParse` and `jsonStringify` methods on `Descriptor`, `Manifest`, `OciImageIndex`, and `DockerManifestList`. Map camelCase JSON field names (`mediaType`, `schemaVersion`, `artifactType`) to snake_case Zig fields.
- `jsonParse` and `jsonStringify` on `MediaType`, `Digest`, and `Platform`. Platform handles OCI dot-named fields (`os.version`, `os.features`).
- `annotations` field type changed from `?[]const u8` placeholder to `?std.json.Value` on `Descriptor`, `Manifest`, and `OciImageIndex`.
- `ResolveError.zig`: tagged union with 11 variants (`AuthFailed`, `NotFound`, `RateLimited`, `DigestMismatch`, `PlatformNotFound`, `ManifestParseError`, `NetworkError`, `UnsupportedAlgorithm`, `ContentTypeMismatch`, `Timeout`, `DepthLimitExceeded`). Each variant carries `registry`, `reference`, and `http_status` context fields borrowed from the per-call arena. `format` produces a human-readable description.
- `ResolveResult.zig`: result struct with `digest`, `media_type`, `platform`, and `reference` fields. `clone(allocator)` deep-copies all slices for use after arena teardown. `deinit(allocator)` frees cloned slices.
- `Config.zig`: configuration skeleton with `CredentialProvider` interface, `Credential` struct, and all fields defaulted. `Config{}` works for anonymous public registry access.
- All new and updated types exported from `root.zig`.
- JSON round-trip tests for `Descriptor`, `Manifest`, `OciImageIndex`, and `DockerManifestList`.
- `ResolveError.format` tests for all variants.
- `ResolveResult.clone` tests: independence after arena teardown, platform field copy, null platform.
- `Config` defaults and `CredentialProvider` slot tests.

---

## [0.0.2] - 2026-05-05

### Added

- `Reference.zig`: full Docker/OCI reference parser. Handles bare names, tags, digests, registries with ports, nested paths, Docker Hub aliases (`docker.io`, `index.docker.io`), and tag+digest refs. Allocates into caller-provided allocator. `deinit` frees all fields.
- `Descriptor.zig`: OCI content descriptor struct. Fields: `media_type`, `digest`, `size`, `platform`, `urls`, `annotations` (placeholder), `artifact_type`.
- `Manifest.zig`: OCI Image Manifest and Docker V2 Schema 2 (same shape, different `media_type`).
- `Index.zig`: `OciImageIndex`, `DockerManifestList`, and `MultiArchManifest` tagged union with `filterByPlatform`.
- All v0.0.2 types exported from `root.zig`.
- Reworked unit tests across all source files: AAA structure, one assertion per concern, boundary and mutation-catching cases, and memory lifecycle tests using the testing allocator.

---

## [0.0.1] - 2026-04-01

### Added

- `build.zig` and `build.zig.zon` for Zig 0.16 package manager. Module name: `z_oci`.
- `Digest.zig`: SHA-256 algorithm enum, hex string parser, `eql`, and `format`.
- `MediaType.zig`: OCI/Docker MIME type enum with `fromString`, `toString`, `isMultiArch`, `isLegacy`.
- `Platform.zig`: os/arch/variant struct with `match` (partial, case-insensitive) and `eql` (strict).
- `root.zig`: public API entry point re-exporting all leaf types.
