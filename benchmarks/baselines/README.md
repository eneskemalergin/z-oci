# Benchmark Baselines

JSON files in this directory are zebrac output snapshots from milestone releases. Each file captures wall-clock time, peak RSS, and CPU performance counter statistics for every benchmark operation.

## Available Baselines

- `v0.2.0.json` is the tagged Phase 2 auth-engine release baseline.
- `v0.3.0.json` is the Phase 3 resolver baseline generated after the public resolver and packaged benchmark CLI gained deterministic resolver operations.
- `v0.4.0.json` is the Phase 4 pre-release baseline: reactive transport retries (wave 1) plus v0.3.9 performance hot-path work (wave 2). Includes `resolve-single-retry` and `authenticate-rate-limit`.

### `v0.4.0.json`: ReleaseFast zebrac (per iteration)

Captured with `zig build -Doptimize=ReleaseFast`, `zebrac -d 4000 -w 1`.

| Operation               | Mean per iteration | Mean RSS | Samples |
| ----------------------- | ------------------ | -------- | ------- |
| reference-parse         | 29.8 us            | 0.77 MB  | 14      |
| digest-parse            | 0.2 us             | 0.77 MB  | 1931    |
| manifest-parse          | 26.6 us            | 0.77 MB  | 16      |
| challenge-parse         | 1.0 us             | 0.77 MB  | 384     |
| platform-match          | 0.1 us             | 0.77 MB  | 2612    |
| authenticate-miss       | 118.6 us           | 16.5 MB  | 34      |
| authenticate-hit        | 9.9 us             | 0.77 MB  | 401     |
| authenticate-rate-limit | 129.8 us           | 16.5 MB  | 31      |
| resolve-single          | 91.4 us            | 0.77 MB  | 44      |
| resolve-single-retry    | 98.6 us            | 0.77 MB  | 41      |
| resolve-session         | 48.4 us            | 1.04 MB  | 83      |
| resolve-multi           | 300.0 us           | 1.02 MB  | 14      |
| validate-single         | 41.1 us            | 0.77 MB  | 98      |
| get-manifest            | 79.6 us            | 0.77 MB  | 51      |

### `v0.4.0.json`: Debug `--counting` (per call)

| Operation               | Mean per iteration | Allocs per call |
| ----------------------- | ------------------ | --------------- |
| reference-parse         | 30.8 us            | 4               |
| digest-parse            | 0.1 us             | 0               |
| manifest-parse          | 28.1 us            | 3               |
| challenge-parse         | 0.9 us             | 0               |
| platform-match          | 0.02 us            | 0               |
| authenticate-miss       | 107.8 us           | 11              |
| authenticate-hit        | 8.0 us             | 1               |
| authenticate-rate-limit | 112.0 us           | 12              |
| resolve-single          | 89.1 us            | 12              |
| resolve-single-retry    | 94.7 us            | 13              |
| resolve-session         | 47.6 us            | 6               |
| resolve-multi           | 304.4 us           | 27              |
| validate-single         | 42.7 us            | 5               |
| get-manifest            | 76.1 us            | 10              |

## Regenerating

```sh
zig build -Doptimize=ReleaseFast
zebrac -d 4000 -w 1 --json benchmarks/baselines/v0.4.0.json \
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

On-the-fly comparison snapshots (not committed) can go under `benchmarks/tmp/`.
