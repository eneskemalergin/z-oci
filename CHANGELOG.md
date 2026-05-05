<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to z-oci are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows [Semantic Versioning](https://semver.org/).

Versions listed here are not yet tagged in git. Tags will follow once the library reaches a stable public API.

## [Unreleased]

Nothing yet.

---

## [0.0.2] - 2026-05-05

### Added

- `Reference.zig`: full Docker/OCI reference parser. Handles bare names, tags, digests, registries with ports, nested paths, Docker Hub aliases (`docker.io`, `index.docker.io`), and tag+digest refs. Allocates into caller-provided allocator. `deinit` frees all fields.
- `Descriptor.zig`: OCI content descriptor struct. Fields: `media_type`, `digest`, `size`, `platform`, `urls`, `annotations` (placeholder), `artifact_type`.
- `Manifest.zig`: OCI Image Manifest and Docker V2 Schema 2 (same shape, different `media_type`).
- `Index.zig`: `OciImageIndex`, `DockerManifestList`, and `MultiArchManifest` tagged union with `filterByPlatform`.
- All v0.0.2 types exported from `root.zig`.

---

## [0.0.1] - 2026-04-01

### Added

- `build.zig` and `build.zig.zon` for Zig 0.16 package manager. Module name: `z_oci`.
- `Digest.zig`: SHA-256 algorithm enum, hex string parser, `eql`, and `format`.
- `MediaType.zig`: OCI/Docker MIME type enum with `fromString`, `toString`, `isMultiArch`, `isLegacy`.
- `Platform.zig`: os/arch/variant struct with `match` (partial, case-insensitive) and `eql` (strict).
- `root.zig`: public API entry point re-exporting all leaf types.
