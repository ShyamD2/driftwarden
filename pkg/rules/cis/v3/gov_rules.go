package v3

import (
	"fmt"
	"strings"

	"github.com/ShyamD2/driftwarden/pkg/analyzer"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWGOV_TAG_001 verifies that resources have the mandatory governance tags (Environment, Owner, CostCenter).
type DWGOV_TAG_001 struct {
	RequiredTags []string
}

func NewDWGOV_TAG_001(requiredTags ...string) analyzer.SecurityRule {
	if len(requiredTags) == 0 {
		requiredTags = []string{"Environment", "Owner", "CostCenter"}
	}
	return &DWGOV_TAG_001{
		RequiredTags: requiredTags,
	}
}

func (r *DWGOV_TAG_001) ID() string {
	return "DW-GOV-TAG-001"
}

func (r *DWGOV_TAG_001) BenchmarkVersion() string {
	return "Cloud Governance Tagging Standards v1.0"
}

func (r *DWGOV_TAG_001) Description() string {
	return "Ensure cloud resources comply with mandatory governance tags (Environment, Owner, CostCenter)"
}

func (r *DWGOV_TAG_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	// Skip system defaults like default VPCs / default SGs from governance tagging
	if res.IsDefault {
		return false, "", "", "", nil
	}

	lowerTags := make(map[string]string)
	for k, v := range res.Tags {
		lowerTags[strings.ToLower(k)] = v
	}

	var missing []string
	for _, req := range r.RequiredTags {
		val, exists := lowerTags[strings.ToLower(req)]
		if !exists || strings.TrimSpace(val) == "" {
			missing = append(missing, req)
		}
	}

	if len(missing) > 0 {
		evidence := fmt.Sprintf("Resource %s is missing mandatory governance tags: %s", res.CanonicalID, strings.Join(missing, ", "))
		remediation := fmt.Sprintf("Apply missing governance tags (%s) to resource %s", strings.Join(missing, ", "), res.ProviderID)
		return true, models.SeverityMedium, evidence, remediation, nil
	}

	return false, "", "", "", nil
}
