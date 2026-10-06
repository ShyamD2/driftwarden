package v3

import (
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestCIS_EC2_SSH_Rule(t *testing.T) {
	rule := NewDWCIS_EC2_001()

	// 1. Violation: 0.0.0.0/0 on port 22
	badSG := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-bad",
		Type:        "aws_security_group",
		Attributes: map[string]any{
			"ingress": []any{
				map[string]any{
					"protocol":    "tcp",
					"from_port":   22,
					"to_port":     22,
					"cidr_blocks": []any{"0.0.0.0/0"},
				},
			},
		},
	}
	violation, sev, ev, _, err := rule.EvaluateResource(badSG)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !violation {
		t.Fatalf("expected DW-CIS-EC2-001 violation for SG with 0.0.0.0/0:22")
	}
	if sev != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", sev)
	}
	if ev == "" {
		t.Errorf("expected non-empty evidence")
	}

	// 2. Safe: restricted CIDR
	safeSG := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-safe",
		Type:        "aws_security_group",
		Attributes: map[string]any{
			"ingress": []any{
				map[string]any{
					"protocol":    "tcp",
					"from_port":   22,
					"to_port":     22,
					"cidr_blocks": []any{"10.0.0.0/8"},
				},
			},
		},
	}
	violation, _, _, _, _ = rule.EvaluateResource(safeSG)
	if violation {
		t.Fatalf("expected safe SG to pass DW-CIS-EC2-001")
	}
}

func TestCIS_EC2_RDP_Rule(t *testing.T) {
	rule := NewDWCIS_EC2_002()

	badSG := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-bad-rdp",
		Type:        "aws_security_group",
		Attributes: map[string]any{
			"ingress": []any{
				map[string]any{
					"protocol":    "tcp",
					"from_port":   3389,
					"to_port":     3389,
					"cidr_blocks": []any{"0.0.0.0/0"},
				},
			},
		},
	}
	violation, sev, _, _, _ := rule.EvaluateResource(badSG)
	if !violation {
		t.Fatalf("expected DW-CIS-EC2-002 violation for SG with 0.0.0.0/0:3389")
	}
	if sev != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", sev)
	}
}

func TestCIS_S3_PAB_Rule(t *testing.T) {
	rule := NewDWCIS_S3_001()

	// 1. Violation: disabled PAB -> must be CRITICAL
	badBucket := models.CanonicalResource{
		CanonicalID: "aws:aws:s3:::bucket/unprotected-bucket",
		Type:        "aws_s3_bucket",
		Attributes: map[string]any{
			"public_access_block_enabled": false,
		},
	}
	violation, sev, _, _, _ := rule.EvaluateResource(badBucket)
	if !violation {
		t.Fatalf("expected DW-CIS-S3-001 violation for disabled PAB")
	}
	if sev != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", sev)
	}

	// 2. Safe: fully enabled
	safeBucket := models.CanonicalResource{
		CanonicalID: "aws:aws:s3:::bucket/protected-bucket",
		Type:        "aws_s3_bucket",
		Attributes: map[string]any{
			"public_access_block_enabled": true,
			"block_public_acls":           true,
			"ignore_public_acls":          true,
			"block_public_policy":         true,
			"restrict_public_buckets":     true,
		},
	}
	violation, _, _, _, _ = rule.EvaluateResource(safeBucket)
	if violation {
		t.Fatalf("expected protected bucket to pass DW-CIS-S3-001")
	}
}

func TestCIS_S3_Encryption_Rule(t *testing.T) {
	rule := NewDWCIS_S3_002()

	// 1. Violation: missing encryption
	badBucket := models.CanonicalResource{
		CanonicalID: "aws:aws:s3:::bucket/unencrypted-bucket",
		Type:        "aws_s3_bucket",
		Attributes:  map[string]any{},
	}
	violation, sev, _, _, _ := rule.EvaluateResource(badBucket)
	if !violation {
		t.Fatalf("expected DW-CIS-S3-002 violation for missing encryption")
	}
	if sev != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %v", sev)
	}

	// 2. Safe: enabled encryption
	safeBucket := models.CanonicalResource{
		CanonicalID: "aws:aws:s3:::bucket/encrypted-bucket",
		Type:        "aws_s3_bucket",
		Attributes: map[string]any{
			"encryption_enabled": true,
			"sse_algorithm":      "aws:kms",
		},
	}
	violation, _, _, _, _ = rule.EvaluateResource(safeBucket)
	if violation {
		t.Fatalf("expected encrypted bucket to pass DW-CIS-S3-002")
	}
}

func TestCIS_IAM_Wildcard_Distinctions(t *testing.T) {
	rule := NewDWCIS_IAM_001()

	// 1. Action: "*" and Resource: "*" -> CRITICAL
	criticalRole := models.CanonicalResource{
		CanonicalID: "aws:aws:iam::123456789012:role/SuperAdmin",
		Type:        "aws_iam_role",
		Attributes: map[string]any{
			"policy": `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "*",
					"Resource": "*"
				}]
			}`,
		},
	}
	v, sev, _, _, _ := rule.EvaluateResource(criticalRole)
	if !v || sev != models.SeverityCritical {
		t.Fatalf("expected CRITICAL for Action:* and Resource:*, got %v / %v", v, sev)
	}

	// 2. Action: "*" on specific resource -> HIGH
	highRole := models.CanonicalResource{
		CanonicalID: "aws:aws:iam::123456789012:role/BucketAdmin",
		Type:        "aws_iam_role",
		Attributes: map[string]any{
			"policy": `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "*",
					"Resource": "arn:aws:s3:::my-special-bucket/*"
				}]
			}`,
		},
	}
	v, sev, _, _, _ = rule.EvaluateResource(highRole)
	if !v || sev != models.SeverityHigh {
		t.Fatalf("expected HIGH for Action:* on specific resource, got %v / %v", v, sev)
	}

	// 3. Action: "ec2:*" -> MEDIUM
	medRole := models.CanonicalResource{
		CanonicalID: "aws:aws:iam::123456789012:role/EC2Manager",
		Type:        "aws_iam_role",
		Attributes: map[string]any{
			"policy": `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "ec2:*",
					"Resource": "*"
				}]
			}`,
		},
	}
	v, sev, _, _, _ = rule.EvaluateResource(medRole)
	if !v || sev != models.SeverityMedium {
		t.Fatalf("expected MEDIUM for Action:ec2:*, got %v / %v", v, sev)
	}

	// 4. Granular Action: "s3:GetObject" -> Safe (No violation)
	safeRole := models.CanonicalResource{
		CanonicalID: "aws:aws:iam::123456789012:role/Reader",
		Type:        "aws_iam_role",
		Attributes: map[string]any{
			"policy": `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::my-special-bucket/*"
				}]
			}`,
		},
	}
	v, _, _, _, _ = rule.EvaluateResource(safeRole)
	if v {
		t.Fatalf("expected safe granular role to have no violation")
	}
}

func TestGOV_Tagging_Rule(t *testing.T) {
	rule := NewDWGOV_TAG_001()

	// 1. Violation: missing CostCenter tag -> MEDIUM
	badRes := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-partial-tags",
		Type:        "aws_instance",
		Tags: map[string]string{
			"Environment": "production",
			"Owner":       "platform-engineering",
		},
	}
	v, sev, _, _, _ := rule.EvaluateResource(badRes)
	if !v {
		t.Fatalf("expected DW-GOV-TAG-001 violation for missing CostCenter")
	}
	if sev != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity for tag violation, got %v", sev)
	}

	// 2. Safe: Environment, Owner, CostCenter all present
	safeRes := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-tagged",
		Type:        "aws_instance",
		Tags: map[string]string{
			"Environment": "production",
			"Owner":       "platform-engineering",
			"CostCenter":  "CC-1014",
		},
	}
	v, _, _, _, _ = rule.EvaluateResource(safeRes)
	if v {
		t.Fatalf("expected fully tagged resource to pass DW-GOV-TAG-001")
	}
}

func TestCIS_RDS_PubliclyAccessible(t *testing.T) {
	rule := NewDWCIS_RDS_001()

	// 1. Violation: publicly accessible RDS instance -> CRITICAL
	badDB := models.CanonicalResource{
		CanonicalID: "aws:aws:rds:us-east-1:123456789012:db/prod-db",
		Type:        "aws_db_instance",
		ProviderID:  "prod-db",
		Attributes: map[string]any{
			"publicly_accessible": true,
		},
	}
	violation, sev, ev, rem, err := rule.EvaluateResource(badDB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !violation {
		t.Fatalf("expected DW-CIS-RDS-001 violation for publicly accessible RDS")
	}
	if sev != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", sev)
	}
	if ev == "" || rem == "" {
		t.Errorf("expected non-empty evidence and remediation")
	}

	// 2. Safe: private RDS instance
	safeDB := models.CanonicalResource{
		CanonicalID: "aws:aws:rds:us-east-1:123456789012:db/private-db",
		Type:        "aws_db_instance",
		ProviderID:  "private-db",
		Attributes: map[string]any{
			"publicly_accessible": false,
		},
	}
	violation, _, _, _, _ = rule.EvaluateResource(safeDB)
	if violation {
		t.Fatalf("expected private RDS to pass DW-CIS-RDS-001")
	}

	// 3. Irrelevant resource
	otherRes := models.CanonicalResource{
		Type: "aws_s3_bucket",
	}
	v, _, _, _, _ := rule.EvaluateResource(otherRes)
	if v {
		t.Fatalf("expected other resource to be skipped")
	}
}

func TestCIS_CloudTrail_MultiRegion(t *testing.T) {
	rule := NewDWCIS_CT_001()

	// 1. Violation: is_multi_region_trail=false -> HIGH
	badTrail := models.CanonicalResource{
		CanonicalID: "aws:aws:cloudtrail:us-east-1:123456789012:trail/local-trail",
		Type:        "aws_cloudtrail",
		ProviderID:  "local-trail",
		Attributes: map[string]any{
			"is_multi_region_trail": false,
		},
	}
	violation, sev, ev, rem, err := rule.EvaluateResource(badTrail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !violation {
		t.Fatalf("expected DW-CIS-CT-001 violation for single-region trail")
	}
	if sev != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %v", sev)
	}
	if ev == "" || rem == "" {
		t.Errorf("expected non-empty evidence and remediation")
	}

	// 2. Safe: multi-region trail
	safeTrail := models.CanonicalResource{
		CanonicalID: "aws:aws:cloudtrail:us-east-1:123456789012:trail/global-trail",
		Type:        "aws_cloudtrail",
		ProviderID:  "global-trail",
		Attributes: map[string]any{
			"is_multi_region_trail": true,
		},
	}
	violation, _, _, _, _ = rule.EvaluateResource(safeTrail)
	if violation {
		t.Fatalf("expected multi-region trail to pass DW-CIS-CT-001")
	}
}

func TestCIS_VPC_DefaultSecurityGroup(t *testing.T) {
	rule := NewDWCIS_VPC_001()

	// 1. Violation: default SG with ingress rules -> HIGH
	badSG := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-default",
		Type:        "aws_security_group",
		Name:        "default",
		ProviderID:  "sg-default",
		Attributes: map[string]any{
			"name": "default",
			"ingress": []any{
				map[string]any{"protocol": "-1", "from_port": 0, "to_port": 0},
			},
		},
	}
	violation, sev, ev, rem, err := rule.EvaluateResource(badSG)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !violation {
		t.Fatalf("expected DW-CIS-VPC-001 violation for default SG with ingress")
	}
	if sev != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %v", sev)
	}
	if ev == "" || rem == "" {
		t.Errorf("expected non-empty evidence and remediation")
	}

	// 2. Safe: default SG with no ingress/egress
	safeSG := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-empty-default",
		Type:        "aws_security_group",
		Name:        "default",
		ProviderID:  "sg-empty-default",
		Attributes: map[string]any{
			"name":    "default",
			"ingress": []any{},
			"egress":  []any{},
		},
	}
	violation, _, _, _, _ = rule.EvaluateResource(safeSG)
	if violation {
		t.Fatalf("expected empty default SG to pass DW-CIS-VPC-001")
	}

	// 3. Non-default SG should be ignored by this rule
	customSG := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-custom",
		Type:        "aws_security_group",
		Name:        "my-web-sg",
		Attributes: map[string]any{
			"name": "my-web-sg",
			"ingress": []any{
				map[string]any{"protocol": "tcp", "from_port": 80, "to_port": 80},
			},
		},
	}
	violation, _, _, _, _ = rule.EvaluateResource(customSG)
	if violation {
		t.Fatalf("expected non-default SG to be ignored by DW-CIS-VPC-001")
	}
}
