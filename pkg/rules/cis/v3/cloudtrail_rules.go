package v3

import (
	"fmt"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWCIS_CT_001 verifies that CloudTrail trails have multi-region logging enabled.
// Benchmark: CIS AWS Foundations Benchmark v3.0.0 (Section 3.1)
type DWCIS_CT_001 struct{}

func NewDWCIS_CT_001() *DWCIS_CT_001 {
	return &DWCIS_CT_001{}
}

func (r *DWCIS_CT_001) ID() string {
	return "DW-CIS-CT-001"
}

func (r *DWCIS_CT_001) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 3.1)"
}

func (r *DWCIS_CT_001) Description() string {
	return "Ensure CloudTrail is enabled across all regions to detect anomalous activity"
}

func (r *DWCIS_CT_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_cloudtrail" && res.Type != "AWS::CloudTrail::Trail" {
		return false, "", "", "", nil
	}

	attrs := res.Attributes
	if attrs == nil {
		return false, "", "", "", nil
	}

	trailName := res.ProviderID
	if trailName == "" {
		trailName = res.Name
	}

	remediation := fmt.Sprintf("aws cloudtrail update-trail --name %s --is-multi-region-trail", trailName)

	if isMulti, ok := attrs["is_multi_region_trail"].(bool); ok && !isMulti {
		evidence := fmt.Sprintf("CloudTrail trail %s has is_multi_region_trail=false; logging is restricted to single region", trailName)
		return true, models.SeverityHigh, evidence, remediation, nil
	}

	return false, "", "", "", nil
}
