package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/ShyamD2/driftwarden/benchmarks/datasets"
	"github.com/ShyamD2/driftwarden/pkg/diff"
	"github.com/ShyamD2/driftwarden/pkg/terraform"
)

type BenchmarkSample struct {
	Name            string  `json:"benchmark_name"`
	Scale           int     `json:"dataset_size"`
	Iterations      int     `json:"iterations"`
	MedianMs        float64 `json:"median_ms"`
	P95Ms           float64 `json:"p95_ms"`
	P99Ms           float64 `json:"p99_ms"`
	MemoryAllocatedMB float64 `json:"memory_allocated_mb"`
	TargetSlaMs     float64 `json:"target_sla_ms"`
	Status          string  `json:"status"` // PASS / FAIL
}

type BenchmarkReport struct {
	Timestamp   string            `json:"timestamp"`
	OS          string            `json:"os"`
	Arch        string            `json:"arch"`
	GoVersion   string            `json:"go_version"`
	CPUCores    int               `json:"cpu_cores"`
	Environment string            `json:"environment"`
	Results     []BenchmarkSample `json:"results"`
}

func main() {
	fmt.Println("================================================================")
	fmt.Println("  DriftWarden Reproducible Hardware Benchmark Runner")
	fmt.Println("================================================================")

	scales := []int{1000, 10000}
	var results []BenchmarkSample

	// 1. Benchmark: Terraform State Parsing
	for _, scale := range scales {
		fmt.Printf("\nRunning BenchmarkStateParsing with scale=%d ...\n", scale)
		data := datasets.GenerateSyntheticState(scale)
		parser := terraform.NewStateParser("us-east-1", "123456789012")

		iterations := 15
		var times []float64

		// Measure memory
		var mBefore, mAfter runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&mBefore)

		for i := 0; i < iterations; i++ {
			start := time.Now()
			_, _, err := parser.ParseBytes(data, "benchmark.tfstate")
			if err != nil {
				panic(err)
			}
			elapsed := float64(time.Since(start).Microseconds()) / 1000.0
			times = append(times, elapsed)
		}

		runtime.ReadMemStats(&mAfter)
		memMB := float64(mAfter.TotalAlloc-mBefore.TotalAlloc) / float64(iterations) / (1024 * 1024)

		sort.Float64s(times)
		median := times[len(times)/2]
		p95 := times[int(float64(len(times))*0.95)]
		p99 := times[int(float64(len(times))*0.99)]

		targetSla := 50.0 * (float64(scale) / 1000.0)
		status := "PASS"
		if median > targetSla {
			status = "FAIL"
		}

		results = append(results, BenchmarkSample{
			Name:            "BenchmarkStateParsing",
			Scale:           scale,
			Iterations:      iterations,
			MedianMs:        median,
			P95Ms:           p95,
			P99Ms:           p99,
			MemoryAllocatedMB: memMB,
			TargetSlaMs:     targetSla,
			Status:          status,
		})

		fmt.Printf("  -> Scale %d: Median=%.2f ms, P95=%.2f ms, P99=%.2f ms, Mem=%.2f MB (SLA < %.1f ms) [%s]\n",
			scale, median, p95, p99, memMB, targetSla, status)
	}

	// 2. Benchmark: Three-Source Semantic Diffing
	for _, scale := range scales {
		fmt.Printf("\nRunning BenchmarkSemanticDiffing with scale=%d ...\n", scale)
		desired, state, live := datasets.GenerateSyntheticCanonicalTriples(scale, 0.05)
		comp := diff.NewComparator(diff.ComparatorOptions{
			IncludeLowConfidence: true,
		})

		iterations := 15
		var times []float64

		var mBefore, mAfter runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&mBefore)

		for i := 0; i < iterations; i++ {
			start := time.Now()
			report := comp.Correlate(desired, state, live, "bench-scan", "123456789012", []string{"us-east-1"})
			if report == nil {
				panic("nil report")
			}
			elapsed := float64(time.Since(start).Microseconds()) / 1000.0
			times = append(times, elapsed)
		}

		runtime.ReadMemStats(&mAfter)
		memMB := float64(mAfter.TotalAlloc-mBefore.TotalAlloc) / float64(iterations) / (1024 * 1024)

		sort.Float64s(times)
		median := times[len(times)/2]
		p95 := times[int(float64(len(times))*0.95)]
		p99 := times[int(float64(len(times))*0.99)]

		targetSla := 10.0 * (float64(scale) / 1000.0)
		status := "PASS"
		if median > targetSla {
			status = "FAIL"
		}

		results = append(results, BenchmarkSample{
			Name:            "BenchmarkSemanticDiffing",
			Scale:           scale,
			Iterations:      iterations,
			MedianMs:        median,
			P95Ms:           p95,
			P99Ms:           p99,
			MemoryAllocatedMB: memMB,
			TargetSlaMs:     targetSla,
			Status:          status,
		})

		fmt.Printf("  -> Scale %d: Median=%.2f ms, P95=%.2f ms, P99=%.2f ms, Mem=%.2f MB (SLA < %.1f ms) [%s]\n",
			scale, median, p95, p99, memMB, targetSla, status)
	}

	// Compile Report
	report := BenchmarkReport{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
		CPUCores:    runtime.NumCPU(),
		Environment: "Host Hardware Execution",
		Results:     results,
	}

	resultsDir := filepath.Join("benchmarks", "results")
	_ = os.MkdirAll(resultsDir, 0755)

	// Write JSON
	jsonPath := filepath.Join(resultsDir, "benchmark-2026-10.json")
	jsonBytes, _ := json.MarshalIndent(report, "", "  ")
	_ = os.WriteFile(jsonPath, jsonBytes, 0644)
	fmt.Printf("\nSaved JSON report: %s\n", jsonPath)

	// Write Markdown
	mdPath := filepath.Join(resultsDir, "benchmark-2026-10.md")
	mdContent := generateMarkdownReport(report)
	_ = os.WriteFile(mdPath, []byte(mdContent), 0644)
	fmt.Printf("Saved Markdown report: %s\n", mdPath)
}

func generateMarkdownReport(r BenchmarkReport) string {
	var s string
	s += "# DriftWarden Reproducible Benchmark Report (2026-10)\n\n"
	s += fmt.Sprintf("**Execution Timestamp**: `%s`  \n", r.Timestamp)
	s += fmt.Sprintf("**Operating System**: `%s/%s`  \n", r.OS, r.Arch)
	s += fmt.Sprintf("**Go Compiler Version**: `%s`  \n", r.GoVersion)
	s += fmt.Sprintf("**CPU Cores Available**: `%d`  \n\n", r.CPUCores)
	s += "---\n\n"
	s += "## Measured Benchmark Results\n\n"
	s += "| Benchmark Name | Scale (Resources) | Iterations | Median (ms) | P95 (ms) | P99 (ms) | Heap Alloc (MB) | Target SLA (ms) | Status |\n"
	s += "|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|\n"

	for _, sample := range r.Results {
		s += fmt.Sprintf("| `%s` | **%d** | %d | **%.2f ms** | %.2f ms | %.2f ms | %.2f MB | < %.1f ms | **%s** |\n",
			sample.Name, sample.Scale, sample.Iterations, sample.MedianMs, sample.P95Ms, sample.P99Ms, sample.MemoryAllocatedMB, sample.TargetSlaMs, sample.Status)
	}

	s += "\n---\n\n"
	s += "## Methodology & Verification\n\n"
	s += "1. **Deterministic Datasets**: Generated using `benchmarks/datasets/generator.go` with pinned pseudorandom seed (seed=42).\n"
	s += "2. **Garbage Collection Isolation**: Explicit `runtime.GC()` invoked prior to each sample run to eliminate GC pause jitter.\n"
	s += "3. **Reproducibility**: Run `make benchmark` or `go run ./benchmarks/scripts/runner.go` on any compatible host.\n"

	return s
}
