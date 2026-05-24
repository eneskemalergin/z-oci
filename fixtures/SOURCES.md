# Fixture Sources

This directory contains two kinds of fixtures:

- spec-derived examples copied from OCI or Docker documentation
- live registry snapshots captured from public registries and checked into git

All fixtures are intentionally small, human-reviewable, and covered by tests.

## Synthetic Negative Fixtures

These fixtures are intentionally malformed and are checked in to keep negative-path parser and resolver behavior deterministic without inline payload literals spread across test files.

- `fixtures/manifests/invalid-empty-manifest.json`
    - Source: repository-authored synthetic fixture
    - Created: 2026-05-24
    - Shape: zero-byte body
    - Purpose: assert manifest-parse failure on empty GET bodies
- `fixtures/manifests/invalid-truncated-oci-manifest.json`
    - Source: repository-authored synthetic fixture
    - Created: 2026-05-24
    - Shape: truncated OCI manifest JSON (missing closing delimiters)
    - Purpose: assert manifest-parse failure on malformed-but-manifest-shaped payloads

## Spec-Derived Examples

These were copied from upstream specifications on 2026-05-05. The JSON stays semantically faithful to the source examples, although formatting may differ.

- `fixtures/manifests/oci-image-manifest-spec-example.json`
    - Source: <https://github.com/opencontainers/image-spec/blob/main/manifest.md>
    - Section: `Example Image Manifest`
- `fixtures/indexes/oci-image-index-spec-example.json`
    - Source: <https://github.com/opencontainers/image-spec/blob/main/image-index.md>
    - Section: `Example Image Index`
- `fixtures/indexes/docker-manifest-list-spec-example.json`
    - Source: <https://github.com/distribution/distribution/blob/main/docs/content/spec/manifest-v2-2.md>
    - Section: `Example Manifest List`
- `fixtures/descriptors/oci-descriptor-artifact-spec-example.json`
    - Source: <https://github.com/opencontainers/image-spec/blob/main/descriptor.md>
    - Section: `Examples`
    - Example: descriptor with `artifactType`

## Live Registry Snapshots

These are request/response snapshots from public registries. They are intentionally pinned to the captured payloads, not refreshed automatically during tests.

When refreshing one of these fixtures, use the exact URL and `Accept` header recorded below, then update the recorded response metadata if the payload changes.

### Docker Hub

- `fixtures/indexes/busybox-latest-live-oci-index.json`
    - Source: Docker Hub registry API
    - Captured from: `https://registry-1.docker.io/v2/library/busybox/manifests/latest`
    - Accept: `application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json`
    - Response content-type: `application/vnd.oci.image.index.v1+json`
    - Response docker-content-digest: `sha256:1487d0af5f52b4ba31c7e465126ee2123fe3f2305d638e7827681e7cf6c83d5e`
    - Notes: anonymous bearer token flow against `library/busybox`; captured live to preserve current registry behavior including attestation entries.
- `fixtures/manifests/busybox-amd64-live-oci-manifest.json`
    - Source: Docker Hub registry API
    - Captured from: `https://registry-1.docker.io/v2/library/busybox/manifests/sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65`
    - Accept: `application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json`
    - Response content-type: `application/vnd.oci.image.manifest.v1+json`
    - Response docker-content-digest: `sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65`
    - Notes: child manifest selected from the live `linux/amd64` descriptor in `busybox:latest`.

### Quay

- `fixtures/indexes/quay-prometheus-busybox-latest-live-docker-manifest-list.json`
    - Source: Quay registry API
    - Captured from: `https://quay.io/v2/prometheus/busybox/manifests/latest`
    - Accept: `application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json`
    - Response content-type: `application/vnd.docker.distribution.manifest.list.v2+json`
    - Response docker-content-digest: `sha256:cbfd893bf86113dbe6b36c2106365f08acb8ee9223167d6dc5e07a3493a24544`
    - Notes: live Docker schema-2 manifest list snapshot from a non-Docker-Hub registry, kept to cover registry behavior drift.
- `fixtures/manifests/quay-prometheus-busybox-amd64-live-docker-manifest.json`
    - Source: Quay registry API
    - Captured from: `https://quay.io/v2/prometheus/busybox/manifests/sha256:35e7e430350711653810b2b3cc889fec2a6e0175c078e4114964c7252c411209`
    - Accept: `application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json`
    - Response content-type: `application/vnd.docker.distribution.manifest.v2+json`
    - Response docker-content-digest: `sha256:35e7e430350711653810b2b3cc889fec2a6e0175c078e4114964c7252c411209`
    - Notes: child manifest selected from the live `linux/amd64` descriptor in the Quay manifest list snapshot above.
