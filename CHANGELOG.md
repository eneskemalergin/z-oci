<!-- markdownlint-disable MD024 MD036 -->
# Changelog

All notable changes to z-oci are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows [Semantic Versioning](https://semver.org/).

Versions listed here may be prepared ahead of the matching git tag. Tags follow once the release is cut.

## [0.6.0] - [Unreleased]

Integration and compatibility verification on top of the v0.5.0 client: deeper offline coverage, a local mock registry peer for the real HTTP client path, optional `registry:2`, and documented registry compatibility coverage. Resolve and auth stay on the shipped seams unless compat testing finds a defect.

Nothing under this version is released yet. Add, change, fix, and verified notes land here only after the matching work is on the branch and gated.

### Added

- Offline parser coverage: Manifest empty/truncated exact-error cases and fixed-seed fuzz; Index empty-list and empty/truncated exact-error cases plus Docker manifest-list fuzz; resilience conflicting `Retry-After` fixture wired; auth empty/trailing-junk authenticate-header cases.
- Public-path `ResolveError` matrix: `getManifest` covers all 13 variants; `validate` covers 11/13 with documented skips plus a digest-pinned `digest_mismatch` proof.
- Credential-helper hang timeout keyed from `Config.read_timeout_ms`; helper failure stays terminal when `credHelpers` is set; `max_retries` does not gate token rate-limit retries.
- `pingRegistry` probes `https://{registry}/v2/` for anonymous reachability or auth-required; independent of resolve.
- In-process loopback mock registry peer for offline tests that drive a real `std.http.Client` (not a public product API).
- Mock hard-case coverage against a real `std.http.Client`: bearer auth, redirect keep/strip, content-type/digest/size errors, multi-arch, depth limit, 429/503 retry, and ping status classification.
- Opt-in local `registry:2` harness (`zig build integration-registry`): resolve by tag and digest, validate missing -> `not_found`. Clear-fails when Docker is absent; never part of `zig build test`.
- `security-check` scans `integration/` and flags non-placeholder Docker `auths` embedded in `.zig` sources.
- Registry compatibility coverage in README (Hub, GHCR, Quay, generic bearer, loopback `registry:2`; fixtures, mocks, opt-in harness, and live commands).
- Offline test coverage for mock/ping/loopback edge cases and ownership invariants.
- Integration-style offline checks: public `resolveMany` pin-list, ping-then-resolve caller flow, and batch failure ownership on a loopback mock peer; recorded `registry:2` recipe in `integration/registry2/README.md`.

### Changed

- The `testing` namespace re-exports the in-process mock peer for callers writing integration tests.
- Ping URL ownership is centralized in `pingRegistryWithExchanger`; exchangers borrow the probe URL only.
- README and CONTRIBUTING list the same build steps as the repository gate (`security-check`, `integration-registry`, bundled toolchain, `fmt --check`).
- v0.6.0 documentation now points at `benchmarks/baselines/v0.6.0.json` and `benchmarks/baselines/v0.6.0-debug-counting.txt` as current comparison snapshots.

### Fixed

- Live manifest redirect follow rewrites loopback `https://` Locations to cleartext before the keep-authorization origin compare, so same-origin bearer auth is not stripped on local mock peers.
- Cross-module workflow tests: `deinitResolveOutcome` tears down success and failure paths; arena-backed preemptive rate-limit smoke skips double-free on success.
- `pingRegistryWithExchanger` owns the probe URL buffer; ping exchangers borrow only (prevents double-free when mock exchangers also freed the URL).
- Docker credential-helper timeout path relies on `defer child.kill` for reap (removed redundant kill on timeout).

### Verified

- `./zig-0.16.0/zig build test --summary all --zig-lib-dir ./zig-0.16.0/lib` passes (350/350 tests, examples-smoke, workflow-smoke, security-check).
- `./zig-0.16.0/zig fmt --check src/ examples/ benchmarks/ build.zig tools/ integration/` passes on `src/`, `examples/`, `benchmarks/`, `build.zig`, `tools/`, `integration/`.
- `./zig-0.16.0/zig build security-check` passes on tracked roots including `integration/`.
- Debug `--counting` for core resolve bench ops matches `benchmarks/baselines/v0.6.0-debug-counting.txt` allocation counts (`resolve-single` 500, `resolve-session` 500, `resolve-many` 2700, `resolve-many-unique` 5000). ReleaseFast baseline is `benchmarks/baselines/v0.6.0.json`.

## [0.5.0] - 2026-07-10 - [Tagged]

Session-oriented batch resolution for multi-image workflows: public `resolveMany`, in-call tag session cache, progress callbacks, an offline batch example, and matching `z-oci-bench` operations. Builds on the v0.4.0 single-call path (shared client and `AuthEngine`, reactive retries) without parallel registry traffic.

### Added

- **Batch resolve**
    - Public `resolveMany(allocator, client, config, refs, options)` resolves references sequentially and returns one `ResolveManyItem` per input. One item failure does not abort the batch.
    - `ResolveManyResult` owns the item slice and every item; call `deinit` once. Successful items own `ResolveResult`. Failed items own both `registry` and `reference` (unlike single-resolve failures, where `registry` still borrows the input).
    - `ResolveManyOptions.platform` is batch-wide. Per-item platforms need separate batches.
    - Input `Reference` values are borrowed; the batch path deep-clones per item so callers keep uniform ownership of the input slice.
- **Session digest cache**
    - Within one `resolveMany` call, successful tag pins and implicit `latest` pins can be reused for later duplicate inputs.
    - Digest-addressed references bypass the session cache.
    - The cache lives only for that call.
- **Progress reporting**
    - Optional `ResolveManyOptions.progress_fn` receives `item_started`, `cache_hit`, `item_succeeded`, and `item_failed`.
    - Progress reference views borrow for the callback duration only. Callbacks are `void` and cannot cancel the batch.
- **Examples and benchmarks**
    - Offline `examples/resolve-many.zig` pin-flow demo, wired as `zig build example-resolve-many` and included in `examples-smoke`.
    - New `z-oci-bench` operations: `resolve-many` (duplicate-heavy batch) and `resolve-many-unique` (unique-reference batch).

### Changed

- **Docs**
    - README documents `resolveMany` ownership, sequential behavior, session-cache rules, progress semantics, and the offline batch example build step.
    - Benchmark baseline docs list every current `z-oci-bench` operation name and record `benchmarks/baselines/v0.5.0.json` plus the Debug counting snapshot for batch ops.
- **Public API clarity**
    - `deinitResolveFailure` is documented as single-resolve only. Batch failures must tear down through `ResolveManyResult.deinit` or `ResolveManyItem.deinit`.
- **Hot-path allocation**
    - Manifest URI and canonical reference builders use exact-size allocation instead of `allocPrint` where the final length is known.
    - Live token and manifest header collection paths add `errdefer` cleanup between multi-step dupes so OOM cannot leak partial header or body buffers.

### Fixed

- **Example ownership**
    - Live `resolve-reference` success path no longer double-frees moved reference fields; failure path keeps input `registry` alive until after error formatting.
- **Batch teardown**
    - Partial batch construction and per-item failure promotion free owned registry/reference pairs without leaking or double-freeing under allocation failure.

### Verified

- `zig build test --summary all` passes (288/288 tests, examples-smoke, workflow-smoke, security-check).
- Explicit `workflow-smoke`, `examples-smoke`, and `security-check` steps pass.
- `zig fmt --check src/ examples/ benchmarks/ build.zig tools/` passes.
- `zig build -Doptimize=ReleaseFast` and `zig build bench` pass.
- `benchmarks/baselines/v0.5.0.json` records the ReleaseFast zebrac baseline (includes `resolve-many` and `resolve-many-unique`).
- `benchmarks/baselines/v0.5.0-debug-counting.txt` records Debug `--counting` for `resolve-single`, `resolve-session`, `resolve-many`, and `resolve-many-unique`.

## [0.4.0] - 2026-06-30 - [Tagged]

Production resilience for live registry traffic: reactive retries and rate-limit handling, custom CA trust bundles, tighter HTTP and cache limits, resolver performance improvements, and memory-ownership hardening across `resolve`, `validate`, and `getManifest`.

### Added

- **Retries and rate limits**
    - Reactive transport retries on manifest `HEAD`/`GET` and token HTTP exchangers, with separate `max_network_retries` and `max_rate_limit_retries` budgets.
    - Opt-in pre-emptive manifest throttling when `Config.rate_limit_enabled` is true and registry `RateLimit-*` headers are trustworthy (`remaining == 0`).
    - `ResolveError.rate_limited`, `network_error`, and `timeout` expose `transport_retries_exhausted` so callers can tell immediate failures from post-retry exhaustion.
- **TLS and request limits**
    - `Config.ca_bundle_path` to load a PEM CA trust bundle at `resolve`, `validate`, and `getManifest` for enterprise and self-hosted registries.
    - `Config.max_manifest_bytes`, `max_token_response_bytes`, and `max_token_cache_entries` to cap live HTTP bodies and token-cache growth.
- **Parsing helpers**
    - `Manifest.parseMediaTypeShallow` for workloads that need only manifest media type, not a full document parse.
    - `json.parseBorrowing` and `json.promoteParsed` to borrow input bytes or move a parsed value onto the caller allocator.
- **Tooling**
    - Build-time PEM private-key scan via `zig build security-check` (also runs as part of `zig build test`).
    - New `z-oci-bench` operations: `resolve-single-retry`, `authenticate-rate-limit`, and `resolve-session` (reused `AuthEngine`).

### Changed

- **Transport**
    - Manifest and token HTTP wrappers share one reactive retry loop in `resilience.zig` instead of duplicating sleep/retry logic in `auth.zig` and `resolver.zig`.
    - Manifest and token retry loops cache built request fields lazily (attempt 2+) so single-shot paths pay no cache overhead.
    - Single-attempt paths no longer allocate retry caches up front; retryable GET failures keep the downloaded body for the next attempt.
- **Docs**
    - Comment and docstring pass across library, examples, and tools: removed internal roadmap language from public docs, fixed scrambled auth API docs, and filled missing public API doc comments.
    - Public docs (`README.md`, `Config.zig`, `resilience.zig`) describe live retry budgets, CA bundle behavior, and registry header assumptions.
    - `examples/resolve-reference` documents default `Config` behavior and when to set `ca_bundle_path`, credentials, and rate-limit flags.
- **TLS**
    - `Config.applyToClient` rejects world-writable CA bundle files on POSIX, reads the bundle in one pass, rejects private-key PEM markers in CA bundles, and skips reload when path and mtime are unchanged for the same client.
- **Auth and credentials**
    - Docker config loading builds a registry index at parse time and decodes credentials lazily per registry instead of materializing the full auth tree up front.
    - Token cache uses a bounded `HashMap` with LRU eviction, borrowed key lookup on hits, remembered GET/POST method per realm, default 60s TTL when `expires_in` is absent, and single-owner token storage on cache miss.
    - `AuthEngine.credentialForRegistry` returns `AuthError!?CredentialHandle`: allocation failures propagate as `OutOfMemory` instead of anonymous fallback; malformed docker-config auth for the requested registry still yields `null`.
- **Resolver performance and memory model**
    - `resolve`, `validate`, and `getManifest` run transient work in a per-call arena and promote caller-owned success values (`Parsed(Manifest)`, references, errors) onto the caller allocator.
    - Resolve hot path avoids full manifest JSON parse when only `media_type` is needed; uses stack SHA-256 hex before digest string allocation; drops wasted GET metadata clones.
    - Live manifest GET uses a bounded transient workspace during digest verification and JSON parse, copies only response headers needed per HTTP status, and enforces caps on `WWW-Authenticate` count and header value size.
    - Multi-arch child fetches forward caller `operation` correctly; parent index document is torn down before child GET.
- **Testing**
    - Duplicate resolver, auth, and workflow tests now run through scenario loops in `test_matrix.zig`, shared by `root.zig` and `workflow_smoke.zig`. The release gate reports 204/204 tests (down from 535); the same `ResolveError` arms, validate/get-manifest failure paths, and C4 public API entries are still covered.

### Fixed

- **Credentials and secrets**
    - Owned credential and token HTTP POST secret buffers are zeroed before release.
    - Docker config parse and teardown under allocation failure no longer double-free registry index keys.
- **Ownership and promotion**
    - Resolve, validate, and getManifest preserve caller-owned reference strings on failure and clear transient storage after promotion.
    - Manifest promotion detaches digest and parsed-document fields from the transient resolve shell before teardown, avoiding digest alias use-after-free.
    - `json.promoteParsed` destroys the source parse tree only after a successful promotion onto the caller allocator.
    - Validate manifest HEAD path releases owned response metadata through one outcome teardown (including GET-fallback and redirect arms).
- **Transport errors**
    - Redirect-without-`Location` and exhausted reactive failures preserve HTTP status and retry-budget context on the public resolver error path.
- **Multi-arch**
    - `recurseIntoMultiArchDocument` tears down the parent index document correctly on `platform_required` and `platform_not_found` early returns.
- **Token cache**
    - LRU eviction now runs before inserting a new cache entry, so a freshly stored token is never selected as the eviction victim when many entries share the same `last_used` timestamp (fixes `authenticate-miss` and `authenticate-rate-limit` benches at high iteration counts).

### Verified

- `zig build test --summary all` passes (204/204 tests, examples-smoke, workflow-smoke, security-check).
- `zig build -Doptimize=ReleaseFast` and `-Doptimize=ReleaseSmall` pass.
- `zig fmt --check src/ examples/ benchmarks/ build.zig tools/` passes.
- `benchmarks/baselines/v0.4.0.json` records the post-optimization bench snapshot (zebrac 0.6.0, `./tools/zebrac`).

## [0.3.0] - 2026-05-24 - [Tagged]

### Added

- Live manifest resolution for `resolve`, `validate`, and `getManifest`, including HEAD and GET fetch paths, manifest media routing, digest verification, and allocator-owned public results built on the shipped auth engine.
- Platform-aware multi-arch resolution for OCI indexes and Docker manifest lists, including recursive child selection, auxiliary-descriptor skipping, selected-platform preservation in `ResolveResult`, and explicit depth-limit failures.
- A live `resolve-reference` packaged example for end-to-end resolver usage, while the existing offline examples remain fixture-backed.
- Synthetic malformed manifest fixtures with explicit provenance (`invalid-empty-manifest.json`, `invalid-truncated-oci-manifest.json`) for deterministic malformed-body coverage in parser and resolver tests.
- Resolver benchmark coverage now exists in `z-oci-bench` through deterministic `resolve-single`, `resolve-multi`, `validate-single`, and `get-manifest` operations, and the repo now carries a `benchmarks/baselines/v0.3.0.json` Phase 3 baseline alongside the older auth-only snapshot.

### Changed

- No-platform multi-arch calls now fail with the structured `platform_required` resolver error instead of surfacing `error.NotYetImplemented` or guessing a default child manifest.
- `validate` now accepts an optional platform and follows the selected child manifest on supported multi-arch inputs, matching `resolve` and `getManifest` semantics.
- `validate` now uses the internal HEAD path first for top-level existence checks, returning early for single-arch manifests and no-platform multi-arch failures before falling back to GET only when child selection still requires parsing.
- Public resolver ownership contracts are now explicit: public failures support owned teardown, and `ResolveResult.deinit()` is valid for live resolver results as well as cloned results.
- Resolver result shaping now reuses owned verified digest strings, and multi-arch child selection formats digest references on the stack instead of allocating them per child fetch, trimming the current ReleaseFast counting snapshot to roughly `95us / 13 allocs` for `resolve-single` and `284us / 28 allocs` for `resolve-multi`.
- Packaged example builds are now distinct from the offline `examples-smoke` step, allowing a live resolver example without making the smoke gate network-dependent.
- Public negative-path coverage was tightened around full error context (`tag`, `registry`, canonical `reference`, and `http_status`) and fixture-backed malformed payloads rather than repeated inline body literals.
- The public config contract is now explicit about what the caller-owned client path really supports today: cached-401 auth retry is live, Docker credential helper timeout uses `read_timeout_ms`, and wider HTTP timeout, custom CA bundle, and rate-limit controls remain deferred instead of being described as already wired.

### Fixed

- Live manifest requests now follow a bounded redirect chain while preserving bearer authorization on the authenticated retry and stripping it when the redirect crosses origin, fixing the Docker Hub live auth path without reopening cross-domain header leakage.
- Recursive multi-arch child fetches now reuse the same auth, media validation, and digest-verification path as single-arch resolution instead of diverging on the child-manifest path.
- Resolver transport teardown now clones returned metadata, zeroes authorization buffers before free, and rejects mismatched manifest headers earlier.
- Resolver GET classification now releases verified digest buffers and parsed-document allocations correctly on non-error failure outcomes, eliminating leak paths exposed by malformed non-empty fixture bodies.
- The public resolver Accept list now lives in stable top-level storage instead of an anonymous temporary slice, fixing a ReleaseFast-only regression where optimized `resolve` and `getManifest` paths could misclassify valid manifest responses as `content_type_mismatch`.

## [0.2.0] - 2026-05-12 - [Tagged]

### Added

- Phase 2 auth engine: `/v2/` probe, Bearer challenge parsing, token exchange (GET + POST fallback), credential-provider chain (config -> env -> Docker config -> anonymous), per-scope token cache with TTL expiry, 401 invalidation retry. Full mock-transport test suite with 299 auth tests covering Docker Hub, GHCR, Quay, and generic self-hosted registries.
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
- Doc comment wording and section-header style were normalized across `Reference.zig`, `ResolveResult.zig`, `Config.zig`, `Index.zig`, and `json.zig`.
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
[0.3.0]: https://github.com/eneskemalergin/z-oci/releases/tag/v0.3.0
[0.4.0]: https://github.com/eneskemalergin/z-oci/releases/tag/v0.4.0
[0.5.0]: https://github.com/eneskemalergin/z-oci/releases/tag/v0.5.0
