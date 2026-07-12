# Local `registry:2` harness (opt-in)

Interoperability checks against Distribution `registry:2` on loopback HTTP.
Not part of `zig build test`.

## Policy

**Clear-fail when Docker is absent.** Running
`zig build integration-registry` without a Docker CLI/daemon exits non-zero with
an explicit message. This step is opt-in; a silent skip would look like a green
pass with no proof.

## Run

```sh
./zig-0.16.0/zig build integration-registry --zig-lib-dir ./zig-0.16.0/lib
```

Requires: Docker Engine, Docker Compose plugin, `curl`, network to pull
`registry:2` and `busybox:1.36.1` on first run.

Docker must allow **insecure HTTP pushes** to loopback (many Linux installs
include `127.0.0.0/8` by default; Docker Desktop may need
`insecure-registries` in daemon config).

## What it proves

1. `resolve` by tag against `127.0.0.1:5000/...` (loopback cleartext rewrite).
2. `resolve` by digest matches the tag pin.
3. `validate` of a missing tag returns `not_found`.

## Security (local harness only)

This compose file is a **throwaway test peer**, not a production registry.

| Property | Setting | Implication |
| --- | --- | --- |
| Bind | `127.0.0.1:5000` only | Not reachable from other hosts on the LAN. |
| Auth | None (anonymous pull/push) | Anyone who can reach the port can read/write images. |
| TLS | HTTP only | Cleartext on loopback; z-oci rewrites `https://127.0.0.1` for tests. |
| Deletes | `REGISTRY_STORAGE_DELETE_ENABLED=true` | Manifest/layer deletes are allowed. |
| Data | Ephemeral compose volume | `compose down -v` tears down storage. |

Do not reuse this compose file for real images, credentials, or internet-facing
registry workloads. Do not point it at `0.0.0.0` or expose port 5000 publicly.

## Quirks (compat-matrix draft)

| Quirk | Observation |
| --- | --- |
| Scheme | Stock `registry:2` speaks HTTP; z-oci live builders emit `https://` and rewrite only for loopback hosts. |
| Auth | Default compose is anonymous; no Bearer challenge on pull. |
| Bind | Compose binds `127.0.0.1:5000` only (not `0.0.0.0`). |
| Image shape | `docker pull` + `docker push` of `busybox` typically yields a single-arch manifest for the host platform (not a multi-arch index). |
| Port conflict | Fails if something else already owns `127.0.0.1:5000`. |
| Docker required | Host daemon + Compose; never required by the default offline gate. |
| Insecure registry | `docker push` to `http://127.0.0.1:5000` requires daemon insecure-registry policy for loopback. |
