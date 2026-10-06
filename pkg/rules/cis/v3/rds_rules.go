package v3

import (
	"fmt"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWCIS_RDS_001 verifies that RDS database instances are not publicly accessible.
// Benchmark: CIS AWS Foundations Benchmark v3.0.0 (Section 2.3.1)
type DWCIS_RDS_001 struct{}

func NewDWCIS_RDS_001() *DWCIS_RDS_001 {
	return &DWCIS_RDS_001{}
}

func (r *DWCIS_RDS_001) ID() string {
	return "DW-CIS-RDS-001"
}

func (r *DWCIS_RDS_001) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 2.3.1)"
}

func (r *DWCIS_RDS_001) Description() string {
	return "Ensure RDS database instances are not publicly accessible from the internet"
}

func (r *DWCIS_RDS_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_db_instance" && res.Type != "AWS::RDS::DBInstance" {
		return false, "", "", "", nil
	}

	attrs := res.Attributes
	if attrs == nil {
		return false, "", "", "", nil
	}

	dbID := res.ProviderID
	if dbID == "" {
		dbID = res.Name
	}

	remediation := fmt.Sprintf("aws rds modify-db-instance --db-instance-identifier %s --no-publicly-accessible --apply-immediately", dbID)

	if isPublic, ok := attrs["publicly_accessible"].(bool); ok && isPublic {
		evidence := fmt.Sprintf("RDS DB instance %s has publicly_accessible=true exposing endpoints to public internet", dbID)
		return true, models.SeverityCritical, evidence, remediation, nil
	}

	return false, "", "", "", nil
}
