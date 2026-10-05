package analyzer

import "github.com/ShyamD2/driftwarden/pkg/models"

// RuleResult represents the evaluation result of a single security or governance rule.
type RuleResult struct {
	RuleID           string          `json:"rule_id"`
	BenchmarkVersion string          `json:"benchmark_version"`
	Description      string          `json:"description"`
	Severity         models.Severity `json:"severity"`
	Passed           bool            `json:"passed"`
	Evidence         string          `json:"evidence"`
	Remediation      string          `json:"remediation,omitempty"`
}

// SecurityRule defines the interface that all CIS benchmark and governance rules must implement.
type SecurityRule interface {
	ID() string
	BenchmarkVersion() string
	Description() string
	EvaluateResource(res models.CanonicalResource) (violation bool, severity models.Severity, evidence string, remediation string, err error)
}
