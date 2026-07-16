# Registry compatibility

z-oci follows the OCI Distribution API for read-only manifest operations. The table below describes the evidence available in this repository. It is a compatibility guide, not a promise that every registry uses the same authentication or rate-limit behavior.

## Evidence labels

- `fixture`: checked-in data used by deterministic tests. Some fixtures are captured from live public registries.
- `mock`: injected HTTP exchanges or the in-process test peer used by the offline test suite.
- `registry:2 harness`: an opt-in local Docker check that must be run separately.
- `live run`: a manual network check. It is not part of `zig build test` and is not implied by a fixture.

## Current coverage

| Registry or family | Evidence | Covered behavior | Boundary |
| --- | --- | --- | --- |
| Docker Hub (`registry-1.docker.io`) | fixture, mock | Captured OCI index and manifest parsing, Docker Hub reference normalization, injected Bearer flows, digest verification, platform selection, and modeled rate-limit headers | The snapshots are pinned and are not refreshed during tests. No current live-network pass is part of the default gate. |
| GitHub Container Registry (`ghcr.io`) | mock | Injected Bearer challenges, credential-source selection, resolve-shaped batch workflows, and `/v2/` ping classification | No GHCR manifest fixture or provider-specific live check is included. |
| Quay (`quay.io`) | fixture, mock | Captured Docker manifest-list and child-manifest parsing, platform selection, and generic Bearer flows | The captured payloads are pinned; no current Quay network check is part of the default gate. |
| Generic OCI Distribution Bearer registries | mock | Bearer challenge parsing, token exchange, credential injection, manifest resolution, digest verification, and common retry responses | GitLab, Harbor, Artifactory, and other products do not have separate registry-specific checks. |
| Distribution `registry:2` on loopback | registry:2 harness | Optional anonymous tag resolve, digest resolve, digest consistency, and missing-tag validation | Requires Docker, Docker Compose, `curl`, and network access on first run. It does not test `pingRegistry`. |
| ECR, GCR, Artifact Registry, and ACR | none | No provider-specific login or token acquisition path is proven here | A caller-supplied credential and a registry-compatible Bearer or Basic flow may work, but this repository does not claim cloud-provider integration. |

The captured registry snapshots and their source URLs are listed in [`fixtures/SOURCES.md`](../fixtures/SOURCES.md). They are test inputs, not a promise that the referenced tags or digests still exist upstream.

## Local `registry:2` check

The optional harness starts an anonymous `registry:2` peer on `127.0.0.1:5000`, loads `busybox:1.36.1`, and checks tag and digest resolution plus missing-tag validation. The harness is separate from the offline test gate:

```sh
zig build integration-registry
```

The check requires Docker Engine, Docker Compose, `curl`, and network access to pull `registry:2` and `busybox:1.36.1` on first run. The peer uses HTTP on loopback only and has no authentication. Do not expose it beyond loopback or reuse its compose file for real images.

## HTTPS, credentials, and ping

Public registry URLs use HTTPS. The live exchangers rewrite URLs to HTTP only for the explicit loopback hosts `127.0.0.1`, `localhost`, and `::1` used by local tests. See [Platform and limits](Platform.md) for the trust-bundle and platform boundary.

The library starts anonymously with `Config{}`. The CLI process adapter can inject environment, Docker config, or credential-helper sources; the library requires the caller to inject those sources. See [Credentials](Credentials.md).

`pingRegistry` probes `https://<registry>/v2/` without fetching a manifest. A `200` response is anonymous reachability, `401` means authentication is required, and other statuses are classified as failures. The ping path does not follow redirects, and `resolve` does not call it first.

## Default verification

The default gate is deterministic and does not require Docker or live registry access:

```sh
zig build test --summary all
zig fmt --check src/ examples/ benchmarks/ build.zig tools/ integration/
```

Run the `registry:2` harness or a live example separately when you need network evidence for a particular registry.
