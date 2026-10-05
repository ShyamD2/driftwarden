package chaos

import (
	"path/filepath"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestChaos_GroundTruthEvaluation(t *testing.T) {
	manifest, err := LoadManifest(filepath.Join("manifest.yaml"))
	if err != nil {
		t.Fatalf("failed to load manifest: %v", err)
	}

	if len(manifest.Mutations) != 4 {
		t.Fatalf("expected 4 mutations in manifest, got %d", len(manifest.Mutations))
	}

	// Simulated scan report matching the 4 injected chaos mutations
	simulatedReport := &models.ScanReport{
		TotalDrift: 4,
		Items: []models.DriftItem{
			// Mutation A: Port 22 open on SG
			{
				Type:      models.DriftAttribute,
				Severity:  models.SeverityCritical,
				CISRuleID: "DW-CIS-EC2-001",
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-clean",
					Type:        "aws_security_group",
				},
			},
			// Mutation B: Rogue EC2 instance
			{
				Type:     models.DriftShadow,
				Severity: models.SeverityHigh,
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-rogue",
					Type:        "aws_instance",
				},
			},
			// Mutation C: Rogue S3 bucket
			{
				Type:     models.DriftShadow,
				Severity: models.SeverityHigh,
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:s3:::bucket/rogue-chaos-bucket-12345",
					Type:        "aws_s3_bucket",
				},
			},
			// Mutation D: Terminated baseline instance
			{
				Type:     models.DriftGhost,
				Severity: models.SeverityHigh,
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-baseline",
					Type:        "aws_instance",
				},
			},
		},
	}

	summary := EvaluateScanAgainstManifest(simulatedReport, manifest)

	if !summary.Passed {
		t.Fatalf("expected chaos evaluation to pass, got summary: %+v", summary)
	}

	if summary.Precision != 1.0 {
		t.Errorf("expected 100%% precision, got %.2f", summary.Precision)
	}

	if summary.Recall != 1.0 {
		t.Errorf("expected 100%% recall, got %.2f", summary.Recall)
	}

	if summary.FalsePositives != 0 {
		t.Errorf("expected 0 false positives, got %d", summary.FalsePositives)
	}

	if !summary.MutationADetect || !summary.MutationBDetect || !summary.MutationCDetect || !summary.MutationDDetect {
		t.Errorf("expected all 4 mutations detected: A=%v, B=%v, C=%v, D=%v",
			summary.MutationADetect, summary.MutationBDetect, summary.MutationCDetect, summary.MutationDDetect)
	}
}
