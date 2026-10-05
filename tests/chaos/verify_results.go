package chaos

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

type ChaosMutation struct {
	ID                string `yaml:"id"`
	Description       string `yaml:"description"`
	ExpectedDriftType string `yaml:"expected_drift_type"`
	ExpectedSeverity  string `yaml:"expected_severity,omitempty"`
	ExpectedRuleID    string `yaml:"expected_rule_id,omitempty"`
}

type ChaosManifest struct {
	Mutations []ChaosMutation `yaml:"mutations"`
}

type VerificationSummary struct {
	TruePositives   int     `json:"true_positives"`
	FalsePositives  int     `json:"false_positives"`
	FalseNegatives  int     `json:"false_negatives"`
	Precision       float64 `json:"precision"`
	Recall          float64 `json:"recall"`
	MutationADetect bool    `json:"mutation_a_detected"`
	MutationBDetect bool    `json:"mutation_b_detected"`
	MutationCDetect bool    `json:"mutation_c_detected"`
	MutationDDetect bool    `json:"mutation_d_detected"`
	Passed          bool    `json:"passed"`
}

// EvaluateScanAgainstManifest evaluates a scan report against the ground truth manifest.
func EvaluateScanAgainstManifest(report *models.ScanReport, manifest *ChaosManifest) VerificationSummary {
	summary := VerificationSummary{}

	detectedTypes := make(map[models.DriftType]int)
	detectedRules := make(map[string]bool)

	for _, item := range report.Items {
		detectedTypes[item.Type]++
		if item.CISRuleID != "" {
			detectedRules[item.CISRuleID] = true
		}
	}

	// Mutation A: Attribute drift with DW-CIS-EC2-001 (Critical)
	if detectedTypes[models.DriftAttribute] > 0 || detectedRules["DW-CIS-EC2-001"] {
		summary.MutationADetect = true
		summary.TruePositives++
	} else {
		summary.FalseNegatives++
	}

	// Mutation B: Rogue EC2 instance (Shadow)
	// Mutation C: Rogue S3 bucket (Shadow)
	shadowCount := detectedTypes[models.DriftShadow]
	if shadowCount >= 2 {
		summary.MutationBDetect = true
		summary.MutationCDetect = true
		summary.TruePositives += 2
	} else if shadowCount == 1 {
		summary.MutationBDetect = true
		summary.TruePositives++
		summary.FalseNegatives++
	} else {
		summary.FalseNegatives += 2
	}

	// Mutation D: Terminated baseline instance (Ghost)
	if detectedTypes[models.DriftGhost] > 0 {
		summary.MutationDDetect = true
		summary.TruePositives++
	} else {
		summary.FalseNegatives++
	}

	// False Positives: unexpected drift types or unmapped items
	expectedTotal := len(manifest.Mutations)
	if report.TotalDrift > expectedTotal {
		summary.FalsePositives = report.TotalDrift - expectedTotal
	}

	// Calculate Precision & Recall
	totalReported := summary.TruePositives + summary.FalsePositives
	if totalReported > 0 {
		summary.Precision = float64(summary.TruePositives) / float64(totalReported)
	}

	totalActual := summary.TruePositives + summary.FalseNegatives
	if totalActual > 0 {
		summary.Recall = float64(summary.TruePositives) / float64(totalActual)
	}

	// Targets: 100% precision, 100% recall, 0 FP, all mutations detected
	if summary.MutationADetect && summary.MutationBDetect && summary.MutationCDetect && summary.MutationDDetect && summary.FalsePositives == 0 {
		summary.Passed = true
	}

	return summary
}

// LoadManifest reads manifest.yaml from disk.
func LoadManifest(manifestPath string) (*ChaosManifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest %s: %w", manifestPath, err)
	}

	var m ChaosManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}
	return &m, nil
}

// LoadScanReport reads results.json from disk.
func LoadScanReport(resultsPath string) (*models.ScanReport, error) {
	data, err := os.ReadFile(resultsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read results %s: %w", resultsPath, err)
	}

	var rep models.ScanReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report: %w", err)
	}
	return &rep, nil
}
