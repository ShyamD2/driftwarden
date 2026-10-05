package diff

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func generateSyntheticTriples(count int) (desired, state, live []models.CanonicalResource) {
	desired = make([]models.CanonicalResource, count)
	state = make([]models.CanonicalResource, count)
	live = make([]models.CanonicalResource, count)

	for i := 0; i < count; i++ {
		cid := fmt.Sprintf("aws:aws:ec2:us-east-1:123456789012:instance/i-%012d", i)

		desired[i] = models.CanonicalResource{
			CanonicalID:        cid,
			Type:               "aws_instance",
			Name:               fmt.Sprintf("server_%d", i),
			Availability:       models.AvailabilityPresent,
			IdentityConfidence: 1.0,
			Attributes: map[string]any{
				"instance_type": "t3.micro",
				"subnet_id":     "subnet-12345678",
			},
		}

		state[i] = models.CanonicalResource{
			CanonicalID:        cid,
			Type:               "aws_instance",
			Name:               fmt.Sprintf("server_%d", i),
			Availability:       models.AvailabilityPresent,
			IdentityConfidence: 1.0,
			Attributes: map[string]any{
				"instance_type": "t3.micro",
				"subnet_id":     "subnet-12345678",
			},
		}

		// Inject 10% attribute drift (every 10th item is drifted)
		liveType := "t3.micro"
		if i%10 == 0 {
			liveType = "t3.large"
		}

		live[i] = models.CanonicalResource{
			CanonicalID:        cid,
			Type:               "aws_instance",
			Name:               fmt.Sprintf("server_%d", i),
			Availability:       models.AvailabilityPresent,
			IdentityConfidence: 1.0,
			Attributes: map[string]any{
				"instance_type": liveType,
				"subnet_id":     "subnet-12345678",
			},
		}
	}

	return desired, state, live
}

func BenchmarkSemanticDiffing(b *testing.B) {
	fmt.Printf("\n--- Benchmark Hardware & Execution Environment ---\n")
	fmt.Printf("OS/Arch:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPUs (cores): %d\n", runtime.NumCPU())
	fmt.Printf("Go Version:   %s\n", runtime.Version())
	fmt.Printf("Timestamp:    %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("---------------------------------------------------\n\n")

	desired, state, live := generateSyntheticTriples(1000)
	comparator := NewComparator(ComparatorOptions{
		IncludeLowConfidence: true,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report := comparator.Correlate(desired, state, live, "bench-scan", "123456789012", []string{"us-east-1"})
		if report.TotalDrift != 100 {
			b.Fatalf("expected 100 drift items (10%% drift), got %d", report.TotalDrift)
		}
	}
}

func TestMemoryHeapAllocationDuringDiffing(t *testing.T) {
	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	desired, state, live := generateSyntheticTriples(1000)
	comparator := NewComparator(ComparatorOptions{
		IncludeLowConfidence: true,
	})

	report := comparator.Correlate(desired, state, live, "mem-scan", "123456789012", []string{"us-east-1"})
	if report.TotalDrift != 100 {
		t.Fatalf("expected 100 drift items, got %d", report.TotalDrift)
	}

	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	allocatedBytes := mAfter.Alloc - mBefore.Alloc
	allocatedMB := float64(allocatedBytes) / (1024 * 1024)

	t.Logf("Memory Heap Stats: Before=%d KB, After=%d KB, Allocated=%.2f MB (Target: < 30 MB)",
		mBefore.Alloc/1024, mAfter.Alloc/1024, allocatedMB)

	// Invariant: Peak heap allocation during 1,000 in-memory diffing must remain strictly under 30 MB
	if allocatedMB > 30.0 {
		t.Fatalf("Heap allocation exceeded 30 MB threshold: %.2f MB", allocatedMB)
	}
}
