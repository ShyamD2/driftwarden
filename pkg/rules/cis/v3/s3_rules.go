package v3

import (
	"fmt"

	"github.com/ShyamD2/driftwarden/pkg/analyzer"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// DWCIS_S3_001 verifies that S3 bucket Public Access Block is fully enabled.
type DWCIS_S3_001 struct{}

func NewDWCIS_S3_001() analyzer.SecurityRule {
	return &DWCIS_S3_001{}
}

func (r *DWCIS_S3_001) ID() string {
	return "DW-CIS-S3-001"
}

func (r *DWCIS_S3_001) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 2.1.5)"
}

func (r *DWCIS_S3_001) Description() string {
	return "Ensure S3 bucket has Public Access Block enabled for all public access settings"
}

func (r *DWCIS_S3_001) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_s3_bucket" {
		return false, "", "", "", nil
	}

	attrs := res.Attributes
	remediation := fmt.Sprintf("aws s3control put-public-access-block --account-id %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", res.AccountID)

	if attrs == nil {
		return true, models.SeverityCritical, "S3 bucket attributes are empty; Public Access Block configuration missing", remediation, nil
	}

	if enabled, ok := attrs["public_access_block_enabled"].(bool); ok && !enabled {
		return true, models.SeverityCritical, "S3 bucket Public Access Block is explicitly disabled", remediation, nil
	}

	flags := []string{
		"block_public_acls",
		"ignore_public_acls",
		"block_public_policy",
		"restrict_public_buckets",
	}

	for _, flag := range flags {
		val, exists := attrs[flag]
		if !exists {
			if overall, ok := attrs["public_access_block_enabled"].(bool); !ok || !overall {
				return true, models.SeverityCritical, "S3 bucket is missing Public Access Block setting: " + flag, remediation, nil
			}
		}
		if b, ok := val.(bool); ok && !b {
			return true, models.SeverityCritical, "S3 bucket Public Access Block setting " + flag + " is disabled", remediation, nil
		}
	}

	return false, "", "", "", nil
}

// DWCIS_S3_002 verifies that S3 bucket default server-side encryption is enabled.
type DWCIS_S3_002 struct{}

func NewDWCIS_S3_002() analyzer.SecurityRule {
	return &DWCIS_S3_002{}
}

func (r *DWCIS_S3_002) ID() string {
	return "DW-CIS-S3-002"
}

func (r *DWCIS_S3_002) BenchmarkVersion() string {
	return "CIS AWS Foundations Benchmark v3.0.0 (Section 2.1.1)"
}

func (r *DWCIS_S3_002) Description() string {
	return "Ensure S3 bucket default server-side encryption is enabled"
}

func (r *DWCIS_S3_002) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if res.Type != "aws_s3_bucket" {
		return false, "", "", "", nil
	}

	attrs := res.Attributes
	bucketName := res.ProviderID
	if bucketName == "" {
		bucketName = res.Name
	}
	remediation := fmt.Sprintf("aws s3api put-bucket-encryption --bucket %s --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'", bucketName)

	if attrs == nil {
		return true, models.SeverityHigh, "S3 bucket attributes are empty; default server-side encryption missing", remediation, nil
	}

	if enabled, ok := attrs["encryption_enabled"].(bool); ok && !enabled {
		return true, models.SeverityHigh, "S3 bucket default server-side encryption is explicitly disabled", remediation, nil
	}

	sseConfig, hasSSE := attrs["server_side_encryption_configuration"]
	sseAlgo, hasAlgo := attrs["sse_algorithm"]
	sseRules, hasRules := attrs["server_side_encryption_rules"]

	if !hasSSE && !hasAlgo && !hasRules {
		if enabled, ok := attrs["encryption_enabled"].(bool); !ok || !enabled {
			return true, models.SeverityHigh, "S3 bucket has no server-side encryption configuration configured", remediation, nil
		}
	}

	if sseConfig == nil && sseAlgo == nil && sseRules == nil {
		return true, models.SeverityHigh, "S3 bucket server-side encryption configuration is nil", remediation, nil
	}

	return false, "", "", "", nil
}
