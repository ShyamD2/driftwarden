package v3

import (
	"fmt"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWCIS_VPC_001 verifies that the default security group of every VPC drops all traffic.
// Benchmark: CIS AWS Foundations Benchmark v3.0.0 (Section 4.3)
type DWCIS_VPC_001 struct{}

func NewDWCIS_VPC_001() *DWCIS_VPC_001 {
	return &DWCIS_VPC_001{}
}

func (r *DWCIS_VPC_001) ID() string {
	return "DW-CIS-VPC-001"
}

func (r *DWCIS_VPC_001) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 4.3)"
}

func (r *DWCIS_VPC_001) Description() string {
	return "Ensure the default security group of every VPC restricts all inbound and outbound traffic"
}

func (r *DWCIS_VPC_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_security_group" {
		return false, "", "", "", nil
	}

	attrs := res.Attributes
	if attrs == nil {
		return false, "", "", "", nil
	}

	name := res.Name
	if n, ok := attrs["name"].(string); ok && n != "" {
		name = n
	}

	if name != "default" && !res.IsDefault {
		return false, "", "", "", nil
	}

	sgID := res.ProviderID
	if sgID == "" {
		sgID = res.Name
	}

	remediation := fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol all", sgID)

	// Check if default SG has any ingress or egress rules
	if ingress, ok := attrs["ingress"].([]any); ok && len(ingress) > 0 {
		evidence := fmt.Sprintf("Default security group %s has %d ingress rule(s) configured instead of dropping all traffic", sgID, len(ingress))
		return true, models.SeverityHigh, evidence, remediation, nil
	}
	if egress, ok := attrs["egress"].([]any); ok && len(egress) > 0 {
		evidence := fmt.Sprintf("Default security group %s has %d egress rule(s) configured instead of dropping all traffic", sgID, len(egress))
		return true, models.SeverityHigh, evidence, remediation, nil
	}

	return false, "", "", "", nil
}
