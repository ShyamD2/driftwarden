package v3

import (
	"fmt"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWCIS_KMS_001 verifies that KMS customer master keys have key rotation enabled.
// Benchmark: CIS AWS Foundations Benchmark v3.0.0 (Section 2.8)
type DWCIS_KMS_001 struct{}

func NewDWCIS_KMS_001() *DWCIS_KMS_001 {
	return &DWCIS_KMS_001{}
}

func (r *DWCIS_KMS_001) ID() string {
	return "DW-CIS-KMS-001"
}

func (r *DWCIS_KMS_001) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 2.8)"
}

func (r *DWCIS_KMS_001) Description() string {
	return "Ensure rotation for customer created KMS keys is enabled"
}

func (r *DWCIS_KMS_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_kms_key" && res.Type != "AWS::KMS::Key" {
		return false, "", "", "", nil
	}

	attrs := res.Attributes
	keyID := res.ProviderID
	if keyID == "" {
		keyID = res.Name
	}
	if keyID == "" {
		keyID = "<key-id>"
	}

	remediation := fmt.Sprintf("aws kms enable-key-rotation --key-id %s", keyID)

	if attrs == nil {
		return true, models.SeverityHigh, fmt.Sprintf("KMS key %s has no attributes; key rotation is not enabled", keyID), remediation, nil
	}

	enabled := false
	if val, ok := attrs["key_rotation_enabled"].(bool); ok {
		enabled = val
	} else if val, ok := attrs["enable_key_rotation"].(bool); ok {
		enabled = val
	}

	if !enabled {
		evidence := fmt.Sprintf("KMS key %s does not have key rotation enabled (key_rotation_enabled=false)", keyID)
		return true, models.SeverityHigh, evidence, remediation, nil
	}

	return false, "", "", "", nil
}
