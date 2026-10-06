# DriftWarden Reproducible Benchmark Report (2026-10)

**Execution Timestamp**: `2026-10-06T12:38:44Z`  
**Operating System**: `windows/amd64`  
**Go Compiler Version**: `go1.27.0`  
**CPU Cores Available**: `4`  

---

## Measured Benchmark Results

| Benchmark Name | Scale (Resources) | Iterations | Median (ms) | P95 (ms) | P99 (ms) | Heap Alloc (MB) | Target SLA (ms) | Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `BenchmarkStateParsing` | **1000** | 15 | **7.53 ms** | 10.47 ms | 10.47 ms | 2.34 MB | < 50.0 ms | **PASS** |
| `BenchmarkStateParsing` | **10000** | 15 | **66.68 ms** | 75.57 ms | 75.57 ms | 28.48 MB | < 500.0 ms | **PASS** |
| `BenchmarkSemanticDiffing` | **1000** | 15 | **1.59 ms** | 3.55 ms | 3.55 ms | 0.27 MB | < 10.0 ms | **PASS** |
| `BenchmarkSemanticDiffing` | **10000** | 15 | **20.60 ms** | 29.99 ms | 29.99 ms | 2.53 MB | < 100.0 ms | **PASS** |

---

## Methodology & Verification

1. **Deterministic Datasets**: Generated using `benchmarks/datasets/generator.go` with pinned pseudorandom seed (seed=42).
2. **Garbage Collection Isolation**: Explicit `runtime.GC()` invoked prior to each sample run to eliminate GC pause jitter.
3. **Reproducibility**: Run `make benchmark` or `go run ./benchmarks/scripts/runner.go` on any compatible host.
