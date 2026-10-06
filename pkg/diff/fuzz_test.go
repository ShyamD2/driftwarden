package diff

import (
	"reflect"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// FuzzDriftCorrelationDeterminism tests the invariant that correlating 3-source inputs
// always produces deterministic, reproducible drift findings regardless of run order.
func FuzzDriftCorrelationDeterminism(f *testing.F) {
	comp := NewComparator(ComparatorOptions{
		IncludeLowConfidence: true,
	})

	f.Add("aws_instance", "i-123", "t3.micro", "t3.micro", "t3.small")
	f.Add("aws_security_group", "sg-web", "443", "443", "22")
	f.Add("aws_s3_bucket", "data-bucket", "private", "private", "public-read")

	f.Fuzz(func(t *testing.T, resType, resID, dVal, sVal, lVal string) {
		canonicalID := "aws:aws:ec2:us-east-1:123456789012:" + resType + "/" + resID

		desired := []models.CanonicalResource{
			{
				CanonicalID:  canonicalID,
				Type:         resType,
				ProviderID:   resID,
				Source:       models.SourceDesired,
				Availability: models.AvailabilityPresent,
				Attributes:   map[string]any{"config_field": dVal},
			},
		}

		state := []models.CanonicalResource{
			{
				CanonicalID:  canonicalID,
				Type:         resType,
				ProviderID:   resID,
				Source:       models.SourceState,
				Availability: models.AvailabilityPresent,
				Attributes:   map[string]any{"config_field": sVal},
			},
		}

		live := []models.CanonicalResource{
			{
				CanonicalID:  canonicalID,
				Type:         resType,
				ProviderID:   resID,
				Source:       models.SourceLive,
				Availability: models.AvailabilityPresent,
				Attributes:   map[string]any{"config_field": lVal},
			},
		}

		// Run 1
		report1 := comp.Correlate(desired, state, live, "scan-fuzz-1", "123456789012", []string{"us-east-1"})

		// Run 2
		report2 := comp.Correlate(desired, state, live, "scan-fuzz-2", "123456789012", []string{"us-east-1"})

		// Invariant 1: Total drift count must match
		if report1.TotalDrift != report2.TotalDrift {
			t.Fatalf("Drift count non-deterministic: run1=%d, run2=%d", report1.TotalDrift, report2.TotalDrift)
		}

		// Invariant 2: Drift types must match
		if len(report1.Items) != len(report2.Items) {
			t.Fatalf("Item count mismatch: %d != %d", len(report1.Items), len(report2.Items))
		}

		for i := range report1.Items {
			if report1.Items[i].Type != report2.Items[i].Type {
				t.Fatalf("Item drift type non-deterministic at index %d: %v != %v",
					i, report1.Items[i].Type, report2.Items[i].Type)
			}
			if report1.Items[i].FindingConfidence != report2.Items[i].FindingConfidence {
				t.Fatalf("Item confidence non-deterministic at index %d: %v != %v",
					i, report1.Items[i].FindingConfidence, report2.Items[i].FindingConfidence)
			}
			if !reflect.DeepEqual(report1.Items[i].Diffs, report2.Items[i].Diffs) {
				t.Fatalf("Item diff non-deterministic at index %d", i)
			}
		}
	})
}
