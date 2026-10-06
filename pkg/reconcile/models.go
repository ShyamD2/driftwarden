package reconcile

import (
	"fmt"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// Confidence represents the safety confidence rating of a reconciliation mutation.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Safeguards defines validation guardrails against accidental mutations on unintended environments or resources.
type Safeguards struct {
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Validated    bool   `json:"validated"`
}

// Validate asserts that target execution environment coordinates match the safeguarded resource identity.
func (s *Safeguards) Validate(accountID, region, resourceType string) error {
	if s.AccountID != "" && accountID != "" && s.AccountID != accountID {
		return fmt.Errorf("safeguard violation: account ID mismatch (expected %s, got %s)", s.AccountID, accountID)
	}
	if s.Region != "" && region != "" && s.Region != region {
		return fmt.Errorf("safeguard violation: region mismatch (expected %s, got %s)", s.Region, region)
	}
	if s.ResourceType != "" && resourceType != "" && s.ResourceType != resourceType {
		return fmt.Errorf("safeguard violation: resource type mismatch (expected %s, got %s)", s.ResourceType, resourceType)
	}
	return nil
}

// RevertAction defines a structured mutation to revert drift or remediate a security violation.
type RevertAction struct {
	RuleID               string          `json:"rule_id,omitempty"`
	ResourceID           string          `json:"resource_id"`
	CanonicalID          string          `json:"canonical_id"`
	Severity             models.Severity `json:"severity"`
	Confidence           Confidence      `json:"confidence"`
	Safeguards           Safeguards      `json:"safeguards"`
	AutomatedPREligible  bool            `json:"automated_pr_eligible"`
	RequiresManualReview bool            `json:"requires_manual_review"`
	RiskWarning          string          `json:"risk_warning,omitempty"`
	Command              []string        `json:"command"`
	Description          string          `json:"description"`
}

// RevertPlan is the machine-readable plan of target mutations.
type RevertPlan struct {
	SchemaVersion string         `json:"schema_version"`
	Timestamp     string         `json:"timestamp"`
	TotalActions  int            `json:"total_actions"`
	Actions       []RevertAction `json:"actions"`
}

// ReconcileAction is an alias for RevertAction to support reconciliation terminology.
type ReconcileAction = RevertAction

// ReconcilePlan is an alias for RevertPlan to support reconciliation terminology.
type ReconcilePlan = RevertPlan
