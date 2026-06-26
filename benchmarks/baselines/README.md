# Benchmark Baselines

JSON files in this directory are zebrac output snapshots from milestone releases. Each file captures wall-clock time, peak RSS, and CPU performance counter statistics for every benchmark operation.

## Available Baselines

- `v0.2.0.json` is the tagged Phase 2 auth-engine release baseline.
- `v0.3.0.json` is the Phase 3 resolver baseline generated after the public resolver and packaged benchmark CLI gained deterministic resolver operations.
- `v0.4.0.json` is the Phase 4 pre-release baseline after reactive transport retries landed; it adds `resolve-single-retry` and `authenticate-rate-limit` alongside the Phase 3 operations.

| Operation                    | Mean wall time | Mean RSS | Samples |
| ---------------------------- | -------------- | -------- | ------- |
| reference-parse (10k iters)  | ~338ms         | 4.69 MB  | 12      |
| digest-parse (10k iters)     | ~13ms          | 4.69 MB  | 314     |
| manifest-parse (10k iters)   | ~478ms         | 4.69 MB  | 9       |
| challenge-parse (10k iters)  | ~63ms          | 4.70 MB  | 64      |
| platform-match (10k iters)   | ~10ms          | 4.70 MB  | 388     |
| authenticate-miss (1k iters) | ~584ms         | 4.73 MB  | 7       |
| authenticate-hit (1k iters)  | ~43ms          | 4.70 MB  | 94      |

Retry-path wall-time summary from `v0.4.0.json` (ReleaseFast, 1k iters):

| Operation               | Mean wall time | Mean per iteration | Mean RSS |
| ----------------------- | -------------- | ------------------ | -------- |
| resolve-single-retry    | ~110ms         | ~110 us            | ~1.1 MB  |
| authenticate-rate-limit | ~152ms         | ~152 us            | ~4.7 MB  |

Resolver wall-time summary from the refreshed `v0.3.0` baseline:

| Operation       | Mean wall time | Mean per iteration | Mean RSS |
| --------------- | -------------- | ------------------ | -------- |
| resolve-single  | ~99ms          | ~99 us             | 1.10 MB  |
| resolve-multi   | ~286ms         | ~286 us            | 1.12 MB  |
| validate-single | ~26ms          | ~26 us             | 799 KB   |
| get-manifest    | ~78ms          | ~78 us             | 1.10 MB  |

Per-operation internal timing (from `z-oci-bench --counting`):

| Operation         | Mean per iteration | Allocs per call |
| ----------------- | ------------------ | --------------- |
| reference-parse   | 33 us              | 4               |
| digest-parse      | 0.4 us             | 0               |
| manifest-parse    | 46 us              | 3               |
| challenge-parse   | 5.6 us             | 0               |
| platform-match    | 0.15 us            | 0               |
| authenticate-miss | 145 us             | 13              |
| authenticate-hit  | 31 us              | 4               |

Resolver-surface counting snapshot from the current `v0.3.0` baseline pass after the repeated-allocation audit:

| Operation               | Mean per iteration | Allocs per call |
| ----------------------- | ------------------ | --------------- |
| resolve-single          | 95 us              | 13              |
| resolve-multi           | 284 us             | 28              |
| validate-single         | 24 us              | 3               |
| get-manifest            | 74 us              | 10              |
| resolve-single-retry    | 105 us             | 14              |
| authenticate-rate-limit | 128 us             | 15              |

## Regenerating

```sh
zig build -Doptimize=ReleaseFast
./tools/zebrac -d 4000 -w 1 --json benchmarks/baselines/v0.3.0.json \
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
  './zig-out/bin/z-oci-bench resolve-multi --iterations 1000' \
  './zig-out/bin/z-oci-bench validate-single --iterations 1000' \
  './zig-out/bin/z-oci-bench get-manifest --iterations 1000'
```

For `v0.4.0.json`, use the same command list with output path `benchmarks/baselines/v0.4.0.json`.
