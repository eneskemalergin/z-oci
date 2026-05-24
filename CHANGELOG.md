<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to z-oci are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows [Semantic Versioning](https://semver.org/).

Versions listed here may be prepared ahead of the matching git tag. Tags follow once the release is cut.

## [Unreleased]

### Added

- Phase 3 resolver scaffolding in `src/resolver.zig`: resolver context, Phase 3 config view, manifest request and response metadata types, canonical reference helpers, and initial resolver-side error mapping.
- Internal resolver HEAD flow in `src/resolver.zig`: manifest transport request type, mockable manifest HTTP exchanger seam, HEAD outcome classification, header-based GET fallback rules, redirect handling, and auth-on-demand retry coverage.
- Internal resolver GET flow in `src/resolver.zig`: owned manifest response bodies, normalized content-type routing, parser integration for OCI and Docker single-arch and multi-arch documents, and focused transport-plus-parser coverage.

### Changed

- `src/root.zig` now builds a resolver context at the public API boundary before returning `error.NotYetImplemented`, which locks the Phase 2 to Phase 3 handoff into code without changing public behavior yet.
- The Phase 3 resolver layer now performs real internal HEAD request control flow, including bearer-token retry and cached-unauthorized retry, while public resolver APIs remain intentionally stubbed.
- Resolver media-type validation now accepts only actual manifest document types on the internal HEAD and GET paths, so config, layer, and legacy manifest content types fail before parse instead of slipping through as usable metadata.

### Verified

- `zig test src/resolver.zig --zig-lib-dir ./zig-0.16.0/lib` passes.
- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes.
- `zig fmt --check src/root.zig src/resolver.zig` passes.
- `zig build example-select-platform -- fixtures/indexes/busybox-latest-live-oci-index.json linux arm64 v8` passes.
- `zig build example-inspect-manifest -- fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json` passes.
- `zig build example-select-platform -- fixtures/indexes/quay-prometheus-busybox-latest-live-docker-manifest-list.json linux arm64` passes.
- `zig build test --summary all` passes.

## [0.2.0] - 2026-05-12 - [Tagged]

### Added

- Phase 2 auth engine: `/v2/` probe, Bearer challenge parsing, token exchange (GET + POST fallback), credential-provider chain (config → env → Docker config → anonymous), per-scope token cache with TTL expiry, 401 invalidation retry. Full mock-transport test suite with 299 auth tests covering Docker Hub, GHCR, Quay, and generic self-hosted registries.
- `benchmarks/` directory with `z-oci-bench` CLI (7 subcommands: `reference-parse`, `digest-parse`, `manifest-parse`, `challenge-parse`, `platform-match`, `authenticate-miss`, `authenticate-hit`), `CountingAllocator`, and `tools/zebrac` integration for statistical sampling.
- Memory stress tests: 7 DebugAllocator tests at 1000x iterations each (auth engine 3 variants, Reference.parse 2 variants, all JSON types, parseDockerConfig). 358 total tests.
- Token cache sizing documented in `AuthEngine` doc comment (unbounded by design for CLI use).
- Arena lifecycle conventions documented in `root.zig` module docs.
- CI workflow with zig build test, zig fmt --check, cached Zig 0.16 installation.
- v0.2.0 baseline at `benchmarks/baselines/v0.2.0.json`.
- `authenticate-miss` bench: ~145μs/iter, ~13 allocs/call.
- `authenticate-hit` bench: ~31μs/iter, 4 allocs/call.

### Changed

- Auth engine is now the Phase 2 deliverable, ready for Phase 3 resolver integration.
- `build.zig` builds and installs `z-oci-bench`.
- `build.zig.zon` version bumped to `0.2.0`.

### Verified

- `zig build test --summary all` passes (358/358 tests, examples-smoke, workflow-smoke).
- `zig build -Doptimize=ReleaseSmall` passes.
- `zig fmt --check src/ examples/ build.zig benchmarks/` passes.
- `zig build bench` compiles and runs all 7 operations.
- Zero-allocation confirmed: `Digest.parse`, `Platform.match`, `parseAuthenticateHeader`, `classifyProbeResponse`, `tokenCacheKeysEqual`, `referenceView`.

## [0.1.8] - 2026-05-12

### Added

- CI workflow (`.github/workflows/ci.yml`) now runs `zig build test`, `examples-smoke`, and `zig fmt --check` on every push and PR to `main` and `phase2-auth`.
- 59 new tests across all modules: JSON round-trip, allocation-failure, DebugAllocator leak detection, fuzz coverage for auth header parsers, edge-case tests for Config and ResolveError formats, and allocation-failure safety for every JSON-backed type.
- Fuzz coverage now spans 40,000 pseudo-random inputs across Digest parse, Reference parse, JSON manifest parse, and auth header/challenge parser paths.
- Allocation-failure coverage (`checkAllAllocationFailures`) now covers Digest, MediaType, Platform, Descriptor, Manifest, OciImageIndex, DockerManifestList, json.parse, auth token response, auth token request, and auth cache insertion.

### Changed

- `MediaType.toString()` now derives from `mime_table` instead of duplicating every MIME string in a second switch. Adding a new media type now requires touching exactly one table.
- `stringifyForTest` extracted from 3 files to `json.zig` as a shared test helper.
- `dockerConfigRegistryKeyMatches` now reuses the shared `isDockerHubRegistryAlias` helper instead of duplicating the alias list inline.
- Doc comments stripped of em-dashes throughout (`Reference.zig`, `ResolveResult.zig`, `Config.zig`, `Index.zig`, `json.zig`).
- Section headers normalized from `// ----` box-drawing characters to plain `//` comments across all source files.
- `zig fmt` formatting pass applied across `src/`, `examples/`, and `build.zig`.
- `build.zig.zon` version bumped to `0.1.8`.

### Removed

- 6 redundant tests removed: 4 simple leak checks in `Reference.zig` (covered by DebugAllocator test), 2 happy-path parse checks in `Digest.zig` (covered by 10k fuzz test and mixed-case test).
- 1 duplicate null-release-fn test in `Config.zig`.
- 1 O(n**2) redundant variant-prefix test in `ResolveError.zig`.

### Verified

- `zig build test --summary all` passes with 344/344 tests (up from 297 at v0.1.7), plus examples-smoke and workflow-smoke.
- `zig build -Doptimize=ReleaseSmall` produces a working artifact.
- `zig fmt --check src/ examples/ build.zig` passes with zero formatting changes.
- `zig build examples-smoke` passes (3 offline example programs parse fixtures and print correct output).

## [0.1.7] - 2026-05-11

### Added

- Auth token request building now expands space-delimited bearer challenge scopes into repeated `scope=` query parameters, matching the Docker registry token-auth contract instead of collapsing them into a single encoded value.
- Auth request-builder coverage now includes documented Docker Hub, GHCR, and Quay token endpoint examples so registry-specific realm and service values stay pinned in tests.
- Docker Hub env-backed auth now composes with Phase 1 reference normalization, so `docker.io/...` references that normalize to `registry-1.docker.io` still pick up configured Docker Hub credentials.
- Docker Hub auth coverage now explicitly distinguishes authenticated and anonymous token requests, proving optional basic auth is attached only when a Docker Hub credential source matches.
- Plain-host credential matching is now case-insensitive for registry auth inputs, which hardens GHCR and Quay flows against mixed-case registry hosts.
- Helper-backed credential lookup now canonicalizes registry server names before invoking Docker helpers, so GHCR and Quay helper flows no longer depend on caller casing.
- The Phase 3 auth-resolver handoff is now explicit in the public code docs and exports: resolver code consumes `AuthReferenceView`, `referenceView(...)`, `ProbeHttpResponse.classify()`, `AuthenticateRequest`, `AuthEngine.authenticate(...)`, and the one-shot cached-401 retry hook `AuthEngine.retryAuthenticateAfterCachedUnauthorized(...)` with documented ownership and retry guarantees.
- Public docs now distinguish shipped Phase 2 auth-engine behavior from still-unimplemented Phase 3 resolver work, so `resolve`, `validate`, and `getManifest` are not presented as live manifest-fetch APIs yet.
- The `v0.1.7` registry scope is now explicit: Docker Hub, GHCR, and Quay remain the named registry-hardened targets, GitLab and Harbor now have explicit mock coverage through a generic self-hosted bearer-registry validation target, other standards-based registries like Artifactory, `registry.k8s.io`, `mcr.microsoft.com`, and BioContainers distribution paths remain documentation-only, and cloud-provider registries such as Google Artifact Registry, ECR, ACR, OCIR, IBM Cloud Container Registry, Alibaba ACR, and DigitalOcean Container Registry are deferred to later support work.
- Auth bug-hunt coverage now includes empty-query token requests, conflicting duplicate token fields, empty refresh tokens, and eager eviction of expired cached tokens before cache misses.
- Release-gate allocation-failure coverage now extends beyond cache insertion to token-response ownership and token-request construction, so owned auth paths fail cleanly without leaks when allocations are denied.

### Fixed

- Token-response parsing now rejects conflicting `access_token` vs `token` payloads and empty `refresh_token` values instead of silently accepting ambiguous or malformed token bodies.
- Token-response parsing now preserves `OutOfMemory` instead of collapsing allocator failures into `InvalidTokenResponse`.
- Owned `refresh_token` bytes are now zeroed before free during `TokenResponse.deinit()`, bringing refresh-token teardown in line with access-token teardown.
- Token-response construction no longer leaks the already-owned access token if refresh-token duplication fails mid-parse.
- GET token requests built from bearer challenges without `service` or `scope` no longer emit a trailing `?` on the auth realm URL.
- Expired cached tokens are now dropped eagerly on lookup, and the cache path no longer carries dead single-use invalidation helpers.

### Verified

- Live `GET /v2/` challenge checks confirm Docker Hub returns `realm="https://auth.docker.io/token",service="registry.docker.io"`, GHCR returns `realm="https://ghcr.io/token",service="ghcr.io"`, and Quay returns `realm="https://quay.io/v2/auth",service="quay.io"`.
- Live repository challenge checks confirm GHCR returns a repository-scoped bearer challenge for public manifests, while public Quay manifests can still succeed anonymously without forcing auth.
- `zig test src/auth.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 246 tests.
- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 293 tests.
- `zig build test --summary all --zig-lib-dir ./zig-0.16.0/lib` passes with 297/297 tests.

---

## [0.1.6] - 2026-05-11

### Added

- `AuthEngine` now owns token-cache storage built on `TokenCacheKey` and `CachedToken`, with explicit cached-entry teardown during engine deinitialization.
- Token cache keys now preserve the full auth identity as `realm + service + scope`, including nil-vs-explicit field separation where appropriate.
- Auth tests now cover cache-hit reuse, expiry refresh, exact-key invalidation retry, multi-scope coexistence, repeated mixed success/failure runs, and allocation-failure cleanup around cache insertion.

### Changed

- `AuthEngine.authenticate(...)` now checks the token cache before issuing token exchange and returns an owned response clone when a cached token is still valid.
- Successful token exchange now stores expiry-aware cached tokens using the fixed refresh-window policy already defined in the auth layer.
- The auth engine now exposes a narrow cached-token invalidation retry helper for the future upstream-`401` path without widening the public resolver surface prematurely.

### Fixed

- Cached token teardown now zeroes and frees owned token bytes correctly on engine shutdown, entry replacement, and explicit invalidation paths.
- Cache replacement and repeated-run flows no longer collapse different scopes into one slot or leave stale cached entries behind.

### Verified

- `zig test src/auth.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 231 tests.
- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 278 tests.
- `zig build test --summary all` passes with 282/282 tests.

## [0.1.5] - 2026-05-11

### Added

- Docker credential source support now covers Docker config discovery via `DOCKER_CONFIG`, `HOME`, and `USERPROFILE`, plus owned parsing of `auths`, `credHelpers`, and `credsStore`.
- Inline Docker `auths` decoding now handles real registry entries including Docker Hub historical keys, normal host keys such as `ghcr.io`, and host-plus-port self-hosted registries.
- Docker helper execution now runs through `std.process.spawn` with stdin-driven helper protocol support, bounded stdout/stderr handling, helper JSON parsing, and teardown-safe owned credential handles.
- Additional auth tests now cover Docker-source precedence, helper protocol behavior, timeout handling, helper failure propagation, and repeated-run recovery after helper timeout or failure.

### Changed

- `AuthEngine` now extends the credential chain from explicit config -> environment map -> anonymous to explicit config -> environment map -> Docker sources -> anonymous.
- Docker-source lookup now uses explicit precedence of registry-specific helper -> inline auth -> global `credsStore`, while preserving Docker Hub normalization to `https://index.docker.io/v1/` where required.
- `authenticate(...)` now consumes helper-backed Docker credentials in the real auth path, and configured helper failures or timeouts remain terminal for that Docker credential source instead of degrading silently.

### Fixed

- Docker helper timeout handling now enforces deterministic child termination and repeated-run safety rather than allowing a hung helper to stall the auth path indefinitely.
- Docker-derived copied secrets now consistently flow through `CredentialHandle` teardown hooks so helper-owned bytes are zeroed and freed after use.

### Verified

- `zig test src/auth.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 220 tests.
- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 267 tests.
- `zig build test --summary all` passes with 271/271 tests.

## [0.1.4] - 2026-05-11

### Added

- The auth credential chain now supports an environment-backed provider through an injected `std.process.Environ.Map`, keeping env-based auth std-only and testable.
- Phase 2 environment variable names are now fixed in code as `Z_OCI_REGISTRY_HOST`, `Z_OCI_REGISTRY_USER`, and `Z_OCI_REGISTRY_TOKEN`.
- Additional zero-network auth tests now cover explicit-config precedence, env fallback, registry mismatch, partial env state, and anonymous behavior.

### Changed

- `AuthEngine.credentialForRegistry(...)` now resolves credentials in deterministic order: explicit config provider -> environment map -> anonymous fallback.
- Provider composition remains local to the auth layer, so later Docker config and helper-backed credential sources can extend the chain without reinterpreting precedence.
- Anonymous registry access is now an explicit credential-chain outcome instead of an implicit null-path side effect.

### Verified

- `zig test src/auth.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 196 tests.
- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 243 tests.
- `zig build test --summary all` passes with 247/247 tests.

## [0.1.3] - 2026-05-11

### Added

- Token exchange now builds authenticated Bearer-token requests from `AuthenticateRequest`, including `GET` query construction and `POST` body construction from parsed challenge fields.
- Optional Basic auth header construction landed for credentialed token requests using provider-supplied credentials.
- `TokenResponse` now returns owned token data with explicit teardown, preserving `refresh_token` as parsed-but-deferred data for later phases.

### Changed

- The auth engine now performs GET-first token exchange with POST fallback through an injected token HTTP exchanger, keeping the transport seam mockable before live HTTP wiring lands.
- Token-response parsing now prefers `access_token`, falls back to `token`, and defaults missing expiry to a short-lived CLI-friendly value.
- HTTPS realm validation now gates token exchange before credentials are sent to the challenge realm.

### Fixed

- Malformed token payloads, zero or invalid expiry values, and non-JSON token responses are now rejected deterministically as auth-layer failures.
- Repeated auth success and failure runs now tear down owned token bytes correctly without leaking on retry and fallback paths.

### Verified

- `zig test src/auth.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 191 tests.
- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 238 tests.
- `zig build test --summary all` passes with 242/242 tests.

## [0.1.2] - 2026-05-11

### Added

- `auth.zig` now models repeated `WWW-Authenticate` header values explicitly through `ProbeHttpResponse.www_authenticate_headers` and `parseAuthenticateHeaders(...)`, so Bearer selection works across both comma-separated challenge lists and repeated header fields.
- `AuthenticateRequest` now carries the parsed Bearer challenge context needed for real token exchange instead of relying on a lossy registry-plus-scope stub shape.
- Additional parser and probe tests now cover repeated-header selection, insecure Bearer realms, escaped quoted values, and empty optional Bearer parameter rejection.

### Changed

- The auth probe/parser layer now consumes the canonical `Reference` outputs directly for `/v2/` probing and challenge handling, keeping Docker Hub normalization and repository-path ownership in Phase 1.
- `WWW-Authenticate` parsing now handles mixed-case schemes, spacing normalization, unknown parameters, duplicate parameters, malformed quoting, and escaped quoted content deterministically.
- The credential-provider seam now returns a `CredentialHandle` with an optional release hook, so provider-owned secrets can be torn down deliberately after auth uses them.

### Fixed

- Bearer challenge parsing now rejects insecure non-HTTPS realm URLs instead of accepting them for later token exchange.
- Parser bug-hunt regressions were fixed around escaped quotes inside quoted parameter values and ambiguous empty `service` / `scope` values.
- Probe classification no longer assumes only a single `WWW-Authenticate` value exists on `401` responses.

### Verified

- `zig test src/auth.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 92 tests.
- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 228 tests.
- `zig build test --summary all` passes with 232/232 tests.

## [0.1.1] - 2026-05-11

### Added

- `src/auth.zig`: initial Phase 2 auth scaffolding with `AuthError`, `AuthChallenge`, `BearerChallenge`, `ProbeResult`, `Token`, `TokenResponse`, `TokenCacheKey`, `CachedToken`, `HelperProcessContext`, and `AuthEngine`.
- `Phase2ConfigView` and `AuthReferenceView` to make the Phase 1/Phase 2 boundary explicit in code.
- Root exports for the new auth surface in `src/root.zig`.
- Initial auth-focused tests covering type compilation, helper-process context wiring, provider borrow semantics, cache/key ownership, config review, and normalized `Reference` consumption.

### Changed

- The auth subsystem now keeps auth-specific errors internal to Phase 2 instead of extending the public `ResolveError` surface prematurely.
- Ownership rules for transient tokens versus owned cached tokens are now encoded directly in code and doc comments.
- The Zig 0.16 helper/process boundary is now explicit: HTTP continues through `std.http.Client`, while helper execution is modeled through a dedicated `std.Io`-backed process context.

### Verified

- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes with 215 tests.
- `zig build test --summary all` passes with 219/219 tests.

## [0.1.0] - 2026-05-05 - [Tagged]

### Changed

- Release-facing docs, package metadata, examples, and plan notes now consistently describe `z-oci` as a public offline toolkit release rather than a pre-release milestone snapshot.
- `build.zig.zon` now packages `examples/`, `fixtures/`, and `assets/` alongside `src/` so the documented offline examples, fixture-backed tests, and README asset references remain valid for package consumers.
- The JSON-heavy tests in `Descriptor.zig`, `Manifest.zig`, and `Index.zig` now use clearer names that distinguish parse-only coverage from real stringify/reparse coverage.

### Fixed

- Bounded JSON reads in examples, workflow smoke, and shared fixture helpers no longer allocate temporary whole-file buffers on the heap.
- The Docker Hub `library/` prefix path in `Reference.parse` no longer goes through `std.fmt.allocPrint`, avoiding unnecessary formatter overhead on a hot normalization path.
- A partial-construction cleanup bug in `ResolveResult.clone` that leaked optional platform fields on later allocation failure has been fixed and covered by allocation-failure tests.

### Verified

- `zig build test --summary all` passes with unit tests, workflow smoke coverage, and example smoke coverage.
- `zig build -Doptimize=ReleaseSmall` passes.
- Artifact-size measurements were recorded for the stub CLI, example binaries, and root test binary in Debug and `ReleaseSmall` modes.

## [0.0.7] - 2026-05-05

### Added

- `src/workflow_smoke.zig` now defines a small offline workflow smoke matrix covering:
    - manifest fixture parse -> stringify summary fields
    - reference parse -> `repositoryPath()` and `refString()`
    - index fixture parse -> platform selection -> descriptor digest assertion
    - `ResolveResult.clone()` surviving arena teardown
- `build.zig` now exposes `zig build workflow-smoke` and includes that workflow-smoke layer in `zig build test`.

### Changed

- `README.md` now explicitly documents the supported offline workflows and adds a dedicated `What Phase 2 Adds` section.
- Public roadmap and shipped-surface language now treat `v0.0.7` as the offline usefulness and release-readiness pass ahead of `v0.1.0`.

### Verified

- `zig build workflow-smoke --summary all` passes.
- `zig build test --summary all` passes with unit tests, example smoke coverage, and the workflow smoke matrix.

## [0.0.6] - 2026-05-05

### Added

- `fixtures/` now contains a typed offline fixture set spanning spec-derived OCI/Docker examples plus live public-registry snapshots from Docker Hub and Quay.
- `fixtures/SOURCES.md` now records provenance, exact capture URLs, and exact `Accept` headers for the live snapshots.
- Three offline example programs were added under `examples/`:
    - `normalize-reference.zig`
    - `inspect-manifest.zig`
    - `select-platform.zig`
- `build.zig` now exposes explicit example steps plus `examples-smoke` for a minimal usage-path pass.
- `Reference.zig` now includes a real-world parser corpus covering Docker Hub, GHCR, Quay, MCR, `registry.k8s.io`, localhost with port, nested paths, and digest-pinned inputs.
- `Index.zig` now includes additional fixture-driven platform-selection tests for real `arm64`, variant-bearing selection, and a dedicated no-match regression.

### Changed

- README examples and build-step documentation now reflect the current offline toolkit and example entrypoints.
- The `inspect-manifest` example now prints a compact manifest summary with type-family distinctions and total compressed layer size.
- The `select-platform` example now reports available platforms when no exact match exists, making the failure path useful as an offline inspection flow.

### Fixed

- `MediaType.zig` now recognizes real OCI and Docker config/layer media types used by live manifests, which previously caused legitimate upstream payloads to fail parsing.
- Example build and run wiring was updated to match Zig 0.16 build and stdlib APIs.

### Verified

- `zig test src/root.zig --zig-lib-dir ./zig-0.16.0/lib` passes with the real fixture and parser corpus coverage.
- `zig build examples-smoke --summary all` passes and exercises the three offline example programs.
- `zig build test --summary all` passes deterministically offline with fixture-backed tests and example smoke coverage.

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

## [0.0.3] - 2026-05-05

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

[0.1.0]: https://github.com/eneskemalergin/z-oci/releases/tag/v0.1.0
[0.2.0]: https://github.com/eneskemalergin/z-oci/releases/tag/v0.2.0
