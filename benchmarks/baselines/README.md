# Benchmark Baselines

JSON files in this directory are zebrac output snapshots from milestone releases. Each file captures wall-clock time, peak RSS, and CPU performance counter statistics for every benchmark operation.

## Current Baseline: v0.2.0

| Operation | Mean wall time | Mean RSS | Samples |
|---|---|---|---|---|
| reference-parse (10k iters) | ~338ms | 4.69 MB | 12 |
| digest-parse (10k iters) | ~13ms | 4.69 MB | 314 |
| manifest-parse (10k iters) | ~478ms | 4.69 MB | 9 |
| challenge-parse (10k iters) | ~63ms | 4.70 MB | 64 |
| platform-match (10k iters) | ~10ms | 4.70 MB | 388 |
| authenticate-miss (1k iters) | ~584ms | 4.73 MB | 7 |
| authenticate-hit (1k iters) | ~43ms | 4.70 MB | 94 |

Per-operation internal timing (from `z-oci-bench --counting`):

| Operation | Mean per iteration | Allocs per call |
|---|---|---|
| reference-parse | 33 us | 4 |
| digest-parse | 0.4 us | 0 |
| manifest-parse | 46 us | 3 |
| challenge-parse | 5.6 us | 0 |
| platform-match | 0.15 us | 0 |
| authenticate-miss | 145 us | 13 |
| authenticate-hit | 31 us | 4 |

## Regenerating

```sh
zig build -Doptimize=ReleaseFast
./tools/zebrac -d 4000 -w 1 --json benchmarks/baselines/v0.2.0.json \
  './zig-out/bin/z-oci-bench reference-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench digest-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench manifest-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench challenge-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench platform-match --iterations 10000' \
  './zig-out/bin/z-oci-bench authenticate-miss --iterations 1000' \
  './zig-out/bin/z-oci-bench authenticate-hit --iterations 1000'
```
