# DriftWarden Benchmark Harness & Verification Suite

This directory contains the reproducible benchmark suite, dataset generators, and historical performance results for DriftWarden across multi-scale infrastructure graphs.

---

## 1. Directory Structure

```
benchmarks/
├── README.md               # Methodology, hardware context, and execution guide
├── datasets/
│   └── generator.go        # Deterministic synthetic state & 3-source triple generator
├── results/
│   ├── benchmark-2026-10.json # Machine-readable performance report
│   └── benchmark-2026-10.md   # Published markdown benchmark tables
└── scripts/
    └── runner.go           # Automated benchmark runner (Median, P95, P99, Allocations)
```

---

## 2. Reproducing Benchmarks

Run the benchmark runner directly via `make`:

```bash
make benchmark
```

Or using the Go toolchain:

```bash
go run ./benchmarks/scripts/runner.go
```

To run standard Go microbenchmarks:

```bash
go test -bench=. ./pkg/terraform/... ./pkg/diff/...
```

---

## 3. SLA Targets & Guarantees

| Engine Component | Dataset Scale | Hard Limit SLA | Typical Performance | Margin |
|:---|:---:|:---:|:---:|:---:|
| **Terraform State Parser** | 1,000 resources | $< 50.0\text{ ms}$ | **$7.53\text{ ms}$** | **$6.6\times\text{ faster}$** |
| **Terraform State Parser** | 10,000 resources | $< 500.0\text{ ms}$ | **$66.68\text{ ms}$** | **$7.5\times\text{ faster}$** |
| **Three-Source Diff Engine** | 1,000 resources | $< 10.0\text{ ms}$ | **$1.59\text{ ms}$** | **$6.3\times\text{ faster}$** |
| **Three-Source Diff Engine** | 10,000 resources | $< 100.0\text{ ms}$ | **$20.60\text{ ms}$** | **$4.8\times\text{ faster}$** |
| **Peak Heap Allocation** | 1,000 resources | $< 30.0\text{ MB}$ | **$2.03\text{ MB}$** | **$14.7\times\text{ lower}$** |
