# Local `registry:2` harness (opt-in)

Interoperability checks against Distribution `registry:2` on loopback HTTP. Not part of `zig build test`.

## Policy

Clear-fail when Docker is absent. Running `zig build integration-registry` without a Docker CLI or daemon exits non-zero with an explicit message. This step is opt-in. A silent skip would look like a green pass with no proof.

## Run

```sh
./zig-0.16.0/zig build integration-registry --zig-lib-dir ./zig-0.16.0/lib
```

Requires Docker Engine, the Docker Compose plugin, `curl`, and network access to pull `registry:2` and `busybox:1.36.1` on first run.

Docker must allow insecure HTTP pushes to loopback. Many Linux installs include `127.0.0.0/8` by default. Docker Desktop may need `insecure-registries` in daemon config.

## What it proves

1. `resolve` by tag against `127.0.0.1:5000/...` (loopback cleartext rewrite).
2. `resolve` by digest matches the tag pin.
3. `validate` of a missing tag returns `not_found`.

## Security (local harness only)

This compose file is a throwaway test peer, not a production registry.

- Bind: `127.0.0.1:5000` only. Not reachable from other hosts on the LAN.
- Auth: none (anonymous pull and push). Anyone who can reach the port can read or write images.
- TLS: HTTP only. Cleartext on loopback; z-oci rewrites `https://127.0.0.1` for tests.
- Deletes: `REGISTRY_STORAGE_DELETE_ENABLED=true` allows manifest and layer deletes.
- Data: ephemeral compose volume. `compose down -v` tears down storage.

Do not reuse this compose file for real images, credentials, or internet-facing registry workloads. Do not bind to `0.0.0.0` or expose port 5000 publicly.

## Quirks

- Live URL builders emit `https://`; loopback exchangers rewrite to `http://` for `127.0.0.1` only (`testing_loopback.zig`).
- The default peer is anonymous. This harness does not exercise ping.
- Named registry coverage and proof levels are summarized in the root README Registry coverage section.
