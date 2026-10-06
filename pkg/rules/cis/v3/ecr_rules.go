package v3

import (
	"fmt"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWCIS_ECR_001 verifies that ECR repositories have image scanning configured on push.
// Benchmark: CIS AWS Foundations Benchmark v3.0.0 (Section 2.10)
type DWCIS_ECR_001 struct{}

func NewDWCIS_ECR_001() *DWCIS_ECR_001 {
	return &DWCIS_ECR_001{}
}

func (r *DWCIS_ECR_001) ID() string {
	return "DW-CIS-ECR-001"
}

func (r *DWCIS_ECR_001) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 2.10)"
}

func (r *DWCIS_ECR_001) Description() string {
	return "Ensure ECR image scanning on push is enabled"
}

func (r *DWCIS_ECR_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_ecr_repository" && res.Type != "AWS::ECR::Repository" {
		return false, "", "", "", nil
	}

	attrs := res.Attributes
	repoName := res.ProviderID
	if repoName == "" {
		repoName = res.Name
	}
	if repoName == "" {
		repoName = "<repo>"
	}

	remediation := fmt.Sprintf("aws ecr put-image-scanning-configuration --repository-name %s --image-scanning-configuration scanOnPush=true", repoName)

	if attrs == nil {
		return true, models.SeverityMedium, fmt.Sprintf("ECR repository %s has no attributes; scan on push is not enabled", repoName), remediation, nil
	}

	scanOnPush := false
	if isc, ok := attrs["image_scanning_configuration"].(map[string]any); ok {
		if sop, ok := isc["scan_on_push"].(bool); ok {
			scanOnPush = sop
		}
	} else if iscs, ok := attrs["image_scanning_configuration"].([]any); ok && len(iscs) > 0 {
		if first, ok := iscs[0].(map[string]any); ok {
			if sop, ok := first["scan_on_push"].(bool); ok {
				scanOnPush = sop
			}
		}
	} else if sop, ok := attrs["image_scanning_configuration.scan_on_push"].(bool); ok {
		scanOnPush = sop
	} else if sop, ok := attrs["scan_on_push"].(bool); ok {
		scanOnPush = sop
	}

	if !scanOnPush {
		evidence := fmt.Sprintf("ECR repository %s does not have image scan on push enabled (scan_on_push=false)", repoName)
		return true, models.SeverityMedium, evidence, remediation, nil
	}

	return false, "", "", "", nil
}
