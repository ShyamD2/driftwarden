package diff

import (
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestComparator_NonLiteralAttribute_ResolutionStatus(t *testing.T) {
	// Desired has AttributeReference on subnet_id: aws_subnet.main.id
	desired := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:instance/i-123",
			Type:         "aws_instance",
			Name:         "web",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"instance_type": "t3.micro",
				"subnet_id":     "aws_subnet.main.id", // Reference
				"_attribute_kinds": map[string]models.AttributeValueKind{
					"instance_type": models.AttributeLiteral,
					"subnet_id":     models.AttributeReference,
				},
			},
		},
	}

	state := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:instance/i-123",
			Type:         "aws_instance",
			Name:         "web",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"instance_type": "t3.micro",
				"subnet_id":     "subnet-0123456789",
			},
		},
	}

	live := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:instance/i-123",
			Type:         "aws_instance",
			Name:         "web",
			Availability: models.AvailabilityPresent,
			Attributes: map[string]any{
				"instance_type": "t3.micro",
				"subnet_id":     "subnet-0123456789",
			},
		},
	}

	comparator := NewComparator(ComparatorOptions{
		IncludeLowConfidence: true,
	})

	report := comparator.Correlate(desired, state, live, "scan-1", "123456789012", []string{"us-east-1"})

	// Because subnet_id is an AttributeReference and instance_type matches,
	// NO false attribute drift should be emitted!
	if report.TotalDrift != 0 {
		t.Fatalf("expected 0 drift items (no false attribute drift for reference), got %d items", report.TotalDrift)
	}
}

func TestComparator_LiveUnavailable_PartialScan_NoGhost(t *testing.T) {
	// State has resource, but Live reading was AccessDenied (UNAVAILABLE)
	state := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:instance/i-secret",
			Type:         "aws_instance",
			Name:         "secret-server",
			Availability: models.AvailabilityPresent,
		},
	}

	live := []models.CanonicalResource{
		{
			CanonicalID:  "aws:aws:ec2:us-east-1:123456789012:instance/i-secret",
			Type:         "aws_instance",
			Name:         "secret-server",
			Availability: models.AvailabilityUnavailable, // AccessDenied!
		},
	}

	comparator := NewComparator(ComparatorOptions{})
	report := comparator.Correlate(nil, state, live, "scan-2", "123456789012", []string{"us-east-1"})

	// CRITICAL INVARIANT:
	// Live UNAVAILABLE must NOT emit DriftGhost, and must mark status PARTIAL_SCAN
	if report.Status != "PARTIAL_SCAN" {
		t.Errorf("expected report status PARTIAL_SCAN, got %q", report.Status)
	}
	if report.AccessDeniedCount != 1 {
		t.Errorf("expected AccessDeniedCount 1, got %d", report.AccessDeniedCount)
	}
	if report.TotalDrift != 0 {
		t.Errorf("CRITICAL INVARIANT VIOLATION: AccessDenied emitted a false DriftGhost: %v", report.Items)
	}
}

func TestComparator_DriftGhost_WhenAbsent(t *testing.T) {
	state := []models.CanonicalResource{
		{
			CanonicalID:        "aws:aws:ec2:us-east-1:123456789012:instance/i-deleted",
			Type:               "aws_instance",
			Name:               "deleted-server",
			Availability:       models.AvailabilityPresent,
			IdentityConfidence: 1.0,
		},
	}

	comparator := NewComparator(ComparatorOptions{
		IncludeLowConfidence: true,
	})
	report := comparator.Correlate(nil, state, nil, "scan-3", "123456789012", []string{"us-east-1"})

	if report.TotalDrift != 1 {
		t.Fatalf("expected 1 drift item, got %d", report.TotalDrift)
	}
	if report.Items[0].Type != models.DriftGhost {
		t.Errorf("expected DriftGhost, got %v", report.Items[0].Type)
	}
}

func TestComparator_DriftShadow(t *testing.T) {
	live := []models.CanonicalResource{
		{
			CanonicalID:        "aws:aws:ec2:us-east-1:123456789012:instance/i-rogue",
			Type:               "aws_instance",
			Name:               "rogue-server",
			Availability:       models.AvailabilityPresent,
			IdentityConfidence: 1.0,
		},
	}

	comparator := NewComparator(ComparatorOptions{
		IncludeLowConfidence: true,
	})
	report := comparator.Correlate(nil, nil, live, "scan-4", "123456789012", []string{"us-east-1"})

	if report.TotalDrift != 1 {
		t.Fatalf("expected 1 drift item, got %d", report.TotalDrift)
	}
	if report.Items[0].Type != models.DriftShadow {
		t.Errorf("expected DriftShadow, got %v", report.Items[0].Type)
	}
}

func TestComparator_DivergenceMatrix(t *testing.T) {
	cid := "aws:aws:ec2:us-east-1:123456789012:instance/i-matrix"

	// 1. D == S && S != L -> DriftAttribute
	d1 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.micro"}}}
	s1 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.micro"}}}
	l1 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.large"}}}

	comparator := NewComparator(ComparatorOptions{IncludeLowConfidence: true})
	r1 := comparator.Correlate(d1, s1, l1, "scan", "acc", []string{"us-east-1"})
	if r1.TotalDrift != 1 || r1.Items[0].Type != models.DriftAttribute {
		t.Errorf("expected DriftAttribute, got: %v", r1.Items)
	}

	// 2. D != S && S == L -> DriftUnappliedConfig
	d2 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.xlarge"}}}
	s2 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.micro"}}}
	l2 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.micro"}}}

	r2 := comparator.Correlate(d2, s2, l2, "scan", "acc", []string{"us-east-1"})
	if r2.TotalDrift != 1 || r2.Items[0].Type != models.DriftUnappliedConfig {
		t.Errorf("expected DriftUnappliedConfig, got: %v", r2.Items)
	}

	// 3. D != S && S != L -> DriftSplitBrain
	d3 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.nano"}}}
	s3 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.micro"}}}
	l3 := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.2xlarge"}}}

	r3 := comparator.Correlate(d3, s3, l3, "scan", "acc", []string{"us-east-1"})
	if r3.TotalDrift != 1 || r3.Items[0].Type != models.DriftSplitBrain {
		t.Errorf("expected DriftSplitBrain, got: %v", r3.Items)
	}
}

func TestComparator_LowConfidenceSuppression(t *testing.T) {
	cid := "aws:aws:ec2:us-east-1:123456789012:instance/i-lowconf"
	d := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.micro"}}}
	s := []models.CanonicalResource{{CanonicalID: cid, Type: "aws_instance", Availability: models.AvailabilityPresent, Attributes: map[string]any{"instance_type": "t3.micro"}}}
	// Live has low identity confidence 0.4 -> FindingConfidence = 0.4 * 0.8 * 1.0 = 0.32 < 0.5
	l := []models.CanonicalResource{{
		CanonicalID:        cid,
		Type:               "aws_instance",
		Availability:       models.AvailabilityPresent,
		IdentityConfidence: 0.4,
		Attributes:         map[string]any{"instance_type": "t3.large"},
	}}

	// Suppressed when IncludeLowConfidence is false
	compSuppressed := NewComparator(ComparatorOptions{IncludeLowConfidence: false})
	repSuppressed := compSuppressed.Correlate(d, s, l, "scan", "acc", []string{"us-east-1"})
	if repSuppressed.TotalDrift != 0 {
		t.Errorf("expected low confidence item to be suppressed, got %d items", repSuppressed.TotalDrift)
	}

	// Included when IncludeLowConfidence is true
	compIncluded := NewComparator(ComparatorOptions{IncludeLowConfidence: true})
	repIncluded := compIncluded.Correlate(d, s, l, "scan", "acc", []string{"us-east-1"})
	if repIncluded.TotalDrift != 1 {
		t.Errorf("expected low confidence item to be included when opted in, got %d items", repIncluded.TotalDrift)
	}
}
