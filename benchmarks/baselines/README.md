# Benchmark Baselines

JSON files in this directory are zebrac output snapshots from milestone releases. Each file captures wall-clock time, peak RSS, and CPU performance counter statistics for every benchmark operation.

Baselines are generated with `./tools/zebrac` (currently **0.6.0**, tracked in-repo). zebrac 0.6.0 adds `branch_misses`, `minor_faults`, `major_faults`, and `failed_sample_count` per benchmark, and accepts `-i/--min-samples` (default 5) and `-a/--max-samples` (default 10000) alongside `-d/--duration-ms` and `-w/--warmup`.

## Available Baselines

- `v0.2.0.json` is the tagged Phase 2 auth-engine release baseline.
- `v0.3.0.json` is the Phase 3 resolver baseline generated after the public resolver and packaged benchmark CLI gained deterministic resolver operations.
- `v0.4.0.json` is the Phase 4 pre-release baseline: reactive transport retries (wave 1) plus v0.3.9 performance hot-path work (wave 2). Includes `resolve-single-retry` and `authenticate-rate-limit`. Regenerated with zebrac 0.6.0 after the token-cache LRU pre-insert eviction fix.

### `v0.4.0.json`: ReleaseFast zebrac (per iteration)

Captured with `zig build -Doptimize=ReleaseFast install`, `./tools/zebrac -d 4000 -w 1`.

| Operation               | Mean per iteration | Mean RSS | Samples |
| ----------------------- | ------------------ | -------- | ------- |
| reference-parse         | 30.0 us            | 1.04 MB  | 14      |
| digest-parse            | 0.1 us             | 1.04 MB  | 2867    |
| manifest-parse          | 25.5 us            | 1.09 MB  | 16      |
| challenge-parse         | 0.5 us             | 1.12 MB  | 800     |
| platform-match          | 0.1 us             | 1.31 MB  | 2911    |
| authenticate-miss       | 74.7 us            | 3.04 MB  | 54      |
| authenticate-hit        | 1.7 us             | 1.71 MB  | 2397    |
| authenticate-rate-limit | 82.5 us            | 3.04 MB  | 49      |
| resolve-single          | 48.3 us            | 1.97 MB  | 83      |
| resolve-single-retry    | 48.2 us            | 1.99 MB  | 83      |
| resolve-session         | 48.2 us            | 2.01 MB  | 84      |
| resolve-multi           | 177.1 us           | 2.02 MB  | 23      |
| validate-single         | 24.4 us            | 2.04 MB  | 164     |
| get-manifest            | 55.6 us            | 2.06 MB  | 73      |

### `v0.4.0.json`: Debug `--counting` (per call)

| Operation               | Mean per iteration | Allocs per call |
| ----------------------- | ------------------ | --------------- |
| reference-parse         | 32.6 us            | 4               |
| digest-parse            | 0.4 us             | 0               |
| manifest-parse          | 46.4 us            | 3               |
| challenge-parse         | 5.3 us             | 0               |
| platform-match          | 0.1 us             | 0               |
| authenticate-miss       | 108.9 us           | 10              |
| authenticate-hit        | 2.7 us             | 0               |
| authenticate-rate-limit | 114.5 us           | 11              |
| resolve-single          | 77.6 us            | 6               |
| resolve-single-retry    | 78.4 us            | 6               |
| resolve-session         | 76.6 us            | 6               |
| resolve-multi           | 664.4 us           | 10              |
| validate-single         | 28.0 us            | 3               |
| get-manifest            | 125.3 us           | 6               |

## Regenerating

Run ReleaseFast install to completion before starting zebrac. Do not run `install` with another `-Doptimize` mode (for example Debug) while zebrac is sampling: a concurrent install can overwrite `zig-out/bin/z-oci-bench` mid-run and poison the baseline with the wrong optimization mode.

`zig build bench` now installs `z-oci-bench` to `zig-out/bin/` for the active `-Doptimize` mode, matching the `install` artifact path zebrac expects.

```sh
zig build -Doptimize=ReleaseFast install
./tools/zebrac -d 4000 -w 1 --json benchmarks/baselines/v0.4.0.json \
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
  './zig-out/bin/z-oci-bench resolve-multi --iterations 1000' \
  './zig-out/bin/z-oci-bench validate-single --iterations 1000' \
  './zig-out/bin/z-oci-bench get-manifest --iterations 1000'
```

Debug allocation snapshots use `zig build -Doptimize=Debug install` and `./zig-out/bin/z-oci-bench <operation> --iterations <n> --counting`.

On-the-fly comparison snapshots (not committed) can go under `benchmarks/tmp/`.
