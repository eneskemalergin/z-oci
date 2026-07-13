# Benchmark Baselines

JSON files in this directory are zebrac output snapshots from milestone releases. Each file captures wall-clock time, peak RSS, and CPU performance counter statistics for every benchmark operation sampled in that release.

Baselines are generated with `./tools/zebrac` (currently **0.6.0**, tracked in-repo). zebrac 0.6.0 adds `branch_misses`, `minor_faults`, `major_faults`, and `failed_sample_count` per benchmark, and accepts `-i/--min-samples` (default 5) and `-a/--max-samples` (default 10000) alongside `-d/--duration-ms` and `-w/--warmup`.

## Operation names

`z-oci-bench` operation names are kebab-case and must match across:

- CLI dispatch / `USAGE` in `benchmarks/src/main.zig`
- `printReport(...)` labels
- zebrac command lines in this file
- README performance tables

Current operations (run `./zig-out/bin/z-oci-bench` with no args for the same list):

| Operation | Measures |
| --- | --- |
| `reference-parse` | `Reference.parse` |
| `digest-parse` | `Digest.parse` |
| `manifest-parse` | `json.parse(Manifest)` |
| `challenge-parse` | `parseAuthenticateHeader` |
| `platform-match` | `Platform.match` |
| `authenticate-miss` | `AuthEngine.authenticate` cache miss |
| `authenticate-hit` | `AuthEngine.authenticate` cache hit |
| `authenticate-rate-limit` | `AuthEngine.authenticate` with 429 then success |
| `resolve-single` | public `resolve()` single-arch |
| `resolve-session` | `resolve()` with reused `AuthEngine` |
| `resolve-many` | public `resolveMany()` duplicate-heavy batch |
| `resolve-many-unique` | public `resolveMany()` unique-reference batch |
| `resolve-single-retry` | public `resolve()` with one transient 503 retry |
| `resolve-multi` | public `resolve()` multi-arch child selection |
| `validate-single` | public `validate()` single-arch |
| `get-manifest` | public `getManifest()` single-arch |
| `all` | every operation above, sequentially |

## Available Baselines

- `v0.2.0.json` is the tagged Phase 2 auth-engine release baseline.
- `v0.3.0.json` is the Phase 3 resolver baseline generated after the public resolver and packaged benchmark CLI gained deterministic resolver operations.
- `v0.4.0.json` is the Phase 4 pre-release baseline: reactive transport retries (wave 1) plus v0.3.9 performance hot-path work (wave 2). Includes `resolve-single-retry`, `authenticate-rate-limit`, and `resolve-session`. Regenerated with zebrac 0.6.0 after the token-cache LRU pre-insert eviction fix.
- `v0.5.0.json` is the Phase 5 batch-resolve baseline. Adds `resolve-many` and `resolve-many-unique` to the full operation set. Captured 2026-07-10 with zebrac 0.6.0.
- `v0.5.0-debug-counting.txt` is the Debug `--counting` snapshot for `resolve-single`, `resolve-session`, `resolve-many`, and `resolve-many-unique` (100 iterations each).
- `v0.6.0.json` is the current release-baseline snapshot for v0.6.0. It includes all 16 operations and was captured with zebrac 0.6.0.
- `v0.6.0-debug-counting.txt` is the current release-debug snapshot for core resolve batch behavior: `resolve-single`, `resolve-session`, `resolve-many`, and `resolve-many-unique` (100 iterations each).

### `v0.6.0-debug-counting.txt`: Debug `--counting` (per call / per batch)

Captured with `zig build -Doptimize=Debug install`, 100 iterations each.

| Operation | Mean per iteration | Allocs per call |
| --- | --- | --- |
| `resolve-single` | 70 us | 500 |
| `resolve-session` | 66 us | 500 |
| `resolve-many` | 242 us | 2700 |
| `resolve-many-unique` | 514 us | 5000 |

`resolve-many` is a 4-item duplicate-heavy batch (1 manifest exchange per batch). `resolve-many-unique` is a 4-item unique-reference batch (4 exchanges per batch).

### `v0.6.0.json`: ReleaseFast zebrac (per iteration)

Captured with `zig build -Doptimize=ReleaseFast install`, `./tools/zebrac -d 4000 -w 1`.

| Operation | Mean per iteration | Mean RSS | Samples |
| --- | --- | --- | --- |
| `reference-parse` | 306847.4 us | 1.05 MB | 14 |
| `digest-parse` | 1331.9 us | 1.05 MB | 2985 |
| `manifest-parse` | 262327.0 us | 1.07 MB | 16 |
| `challenge-parse` | 5318.3 us | 1.10 MB | 751 |
| `platform-match` | 1319.3 us | 1.29 MB | 3013 |
| `authenticate-miss` | 69191.6 us | 3.05 MB | 58 |
| `authenticate-hit` | 1589.2 us | 1.70 MB | 2505 |
| `authenticate-rate-limit` | 83847.2 us | 3.05 MB | 48 |
| `resolve-single` | 42199.9 us | 1.97 MB | 95 |
| `resolve-single-retry` | 42154.7 us | 1.99 MB | 95 |
| `resolve-session` | 43309.9 us | 2.01 MB | 93 |
| `resolve-many` | 199525.9 us | 2.02 MB | 21 |
| `resolve-many-unique` | 385818.8 us | 2.03 MB | 11 |
| `resolve-multi` | 175768.9 us | 2.03 MB | 23 |
| `validate-single` | 25160.7 us | 2.04 MB | 159 |
| `get-manifest` | 54015.5 us | 2.07 MB | 75 |

### `v0.5.0.json`: ReleaseFast zebrac (per iteration)

Captured with `zig build -Doptimize=ReleaseFast install`, `./tools/zebrac -d 4000 -w 1`.

| Operation | Mean per iteration | Mean RSS | Samples |
| --- | --- | --- | --- |
| `reference-parse` | 29.0 us | 1.05 MB | 14 |
| `digest-parse` | 0.1 us | 1.05 MB | 2995 |
| `manifest-parse` | 25.3 us | 1.09 MB | 16 |
| `challenge-parse` | 0.5 us | 1.12 MB | 761 |
| `platform-match` | 0.1 us | 1.30 MB | 3014 |
| `authenticate-miss` | 65.8 us | 3.05 MB | 61 |
| `authenticate-hit` | 1.6 us | 1.71 MB | 2488 |
| `authenticate-rate-limit` | 80.3 us | 3.05 MB | 50 |
| `resolve-single` | 40.2 us | 1.98 MB | 100 |
| `resolve-single-retry` | 40.3 us | 2.00 MB | 100 |
| `resolve-session` | 40.0 us | 2.02 MB | 100 |
| `resolve-many` | 187.8 us | 2.04 MB | 22 |
| `resolve-many-unique` | 368.0 us | 2.04 MB | 11 |
| `resolve-multi` | 167.2 us | 2.04 MB | 24 |
| `validate-single` | 24.0 us | 2.05 MB | 167 |
| `get-manifest` | 52.0 us | 2.08 MB | 77 |

### `v0.5.0-debug-counting.txt`: Debug `--counting` (per call / per batch)

Captured with `zig build -Doptimize=Debug install`, 100 iterations each.

| Operation | Mean per iteration | Allocs per call |
| --- | --- | --- |
| `resolve-single` | 67.6 us | 5 |
| `resolve-session` | 68.6 us | 5 |
| `resolve-many` | 236.9 us | 27 |
| `resolve-many-unique` | 544.2 us | 50 |

`resolve-many` is a 4-item duplicate-heavy batch (1 manifest exchange per batch). `resolve-many-unique` is a 4-item unique-reference batch (4 exchanges per batch).

### `v0.4.0.json`: ReleaseFast zebrac (per iteration)

Captured with `zig build -Doptimize=ReleaseFast install`, `./tools/zebrac -d 4000 -w 1`.

| Operation | Mean per iteration | Mean RSS | Samples |
| --- | --- | --- | --- |
| `reference-parse` | 30.0 us | 1.04 MB | 14 |
| `digest-parse` | 0.1 us | 1.04 MB | 2867 |
| `manifest-parse` | 25.5 us | 1.09 MB | 16 |
| `challenge-parse` | 0.5 us | 1.12 MB | 800 |
| `platform-match` | 0.1 us | 1.31 MB | 2911 |
| `authenticate-miss` | 74.7 us | 3.04 MB | 54 |
| `authenticate-hit` | 1.7 us | 1.71 MB | 2397 |
| `authenticate-rate-limit` | 82.5 us | 3.04 MB | 49 |
| `resolve-single` | 48.3 us | 1.97 MB | 83 |
| `resolve-single-retry` | 48.2 us | 1.99 MB | 83 |
| `resolve-session` | 48.2 us | 2.01 MB | 84 |
| `resolve-multi` | 177.1 us | 2.02 MB | 23 |
| `validate-single` | 24.4 us | 2.04 MB | 164 |
| `get-manifest` | 55.6 us | 2.06 MB | 73 |

### `v0.4.0.json`: Debug `--counting` (per call)

| Operation | Mean per iteration | Allocs per call |
| --- | --- | --- |
| `reference-parse` | 32.6 us | 4 |
| `digest-parse` | 0.4 us | 0 |
| `manifest-parse` | 46.4 us | 3 |
| `challenge-parse` | 5.3 us | 0 |
| `platform-match` | 0.1 us | 0 |
| `authenticate-miss` | 108.9 us | 10 |
| `authenticate-hit` | 2.7 us | 0 |
| `authenticate-rate-limit` | 114.5 us | 11 |
| `resolve-single` | 77.6 us | 6 |
| `resolve-single-retry` | 78.4 us | 6 |
| `resolve-session` | 76.6 us | 6 |
| `resolve-multi` | 664.4 us | 10 |
| `validate-single` | 28.0 us | 3 |
| `get-manifest` | 125.3 us | 6 |

## Regenerating

Run ReleaseFast install to completion before starting zebrac. Do not run `install` with another `-Doptimize` mode (for example Debug) while zebrac is sampling: a concurrent install can overwrite `zig-out/bin/z-oci-bench` mid-run and poison the baseline with the wrong optimization mode.

`zig build bench` installs `z-oci-bench` to `zig-out/bin/` for the active `-Doptimize` mode, matching the `install` artifact path zebrac expects.

```sh
zig build -Doptimize=ReleaseFast install
./tools/zebrac -d 4000 -w 1 --json benchmarks/baselines/v0.6.0.json \
  './zig-out/bin/z-oci-bench reference-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench digest-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench manifest-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench challenge-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench platform-match --iterations 10000' \
  './zig-out/bin/z-oci-bench authenticate-miss --iterations 1000' \
  './zig-out/bin/z-oci-bench authenticate-hit --iterations 1000' \
  './zig-out/bin/z-oci-bench authenticate-rate-limit --iterations 1000' \
  './zig-out/bin/z-oci-bench resolve-single --iterations 1000' \
  './zig-out/bin/z-oci-bench resolve-single-retry --iterations 1000' \
  './zig-out/bin/z-oci-bench resolve-session --iterations 1000' \
  './zig-out/bin/z-oci-bench resolve-many --iterations 1000' \
  './zig-out/bin/z-oci-bench resolve-many-unique --iterations 1000' \
  './zig-out/bin/z-oci-bench resolve-multi --iterations 1000' \
  './zig-out/bin/z-oci-bench validate-single --iterations 1000' \
  './zig-out/bin/z-oci-bench get-manifest --iterations 1000'
```

Debug allocation snapshots use `zig build -Doptimize=Debug install` and `./zig-out/bin/z-oci-bench <operation> --iterations <n> --counting`.

On-the-fly comparison snapshots (not committed) can go under `benchmarks/tmp/`.
