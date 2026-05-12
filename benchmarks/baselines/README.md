# Benchmark Baselines

JSON files in this directory are zebrac output snapshots from milestone releases. Each file captures wall-clock time, peak RSS, and CPU performance counter statistics for every benchmark operation.

## Current Baseline: v0.1.9

| Operation | Mean wall time | Mean RSS | Samples |
|---|---|---|---|
| reference-parse (10k iters) | ~341ms | 4.69 MB | 12 |
| digest-parse (10k iters) | ~1.2ms | 4.69 MB | 1705 |
| manifest-parse (10k iters) | ~343ms | 4.69 MB | 12 |
| challenge-parse (10k iters) | ~62ms | 4.70 MB | 65 |
| platform-match (10k iters) | ~8.8ms | 4.70 MB | 450 |

Per-operation internal timing (from `z-oci-bench --counting`):

| Operation | Mean per iteration | Allocs per call |
|---|---|---|
| reference-parse | 33.4 us | 4 |
| digest-parse | 0.4 us | 0 |
| manifest-parse | 46.2 us | 3 |
| challenge-parse | 5.6 us | 0 |
| platform-match | 0.15 us | 0 |

## Regenerating

```sh
zig build -Doptimize=ReleaseFast
./tools/zebrac -d 5000 --json benchmarks/baselines/v0.X.Y.json \
  './zig-out/bin/z-oci-bench reference-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench digest-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench manifest-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench challenge-parse --iterations 10000' \
  './zig-out/bin/z-oci-bench platform-match --iterations 10000'
```
