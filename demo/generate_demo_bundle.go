package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ShyamD2/driftwarden/pkg/analyzer"
	"github.com/ShyamD2/driftwarden/pkg/evidence"
	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/rules"
)

func main() {
	evidenceDir := filepath.Join("demo", "evidence")
	_ = os.MkdirAll(evidenceDir, 0755)

	sgCanonicalID := "aws:aws:ec2:us-east-1:123456789012:security_group/sg-demo-web"
	s3CanonicalID := "aws:aws:s3:::bucket/prod-assets-corp-bucket-12345"
	ec2CanonicalID := "aws:aws:ec2:us-east-1:123456789012:instance/i-rogue-shadow-99"

	report := &models.ScanReport{
		ReportSchemaVersion: "1.0.0",
		ToolVersion:         "1.0.0",
		ScanID:              "scan-golden-demo-2026",
		Timestamp:           "2026-10-06T12:00:00Z",
		AccountID:           "123456789012",
		Regions:             []string{"us-east-1"},
		SnapshotMode:        "CURRENT",
		Status:              "COMPLETE",
		TotalScanned:        3,
		TotalDrift:          3,
		AccessDeniedCount:   0,
		Items: []models.DriftItem{
			// 1. Security Group Port 22 SSH Exposure
			{
				Type:               models.DriftAttribute,
				Severity:           models.SeverityCritical,
				CISRuleID:          "DW-CIS-EC2-001",
				DoubleReadVerified: true,
				FindingConfidence:  1.0,
				FindingEvidence:    []string{"live_ingress_contains_0.0.0.0/0:22", "state_specifies_443_only"},
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: true,
				},
				Resource: models.CanonicalResource{
					CanonicalID: sgCanonicalID,
					Type:        "aws_security_group",
					ProviderID:  "sg-demo-web",
					Name:        "web-prod-sg",
					AccountID:   "123456789012",
					Region:      "us-east-1",
					Source:      models.SourceLive,
					Attributes: map[string]any{
						"description": "Production web security group",
						"name":        "web-prod-sg",
						"ingress": []any{
							map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": []any{"0.0.0.0/0"}},
							map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": []any{"0.0.0.0/0"}},
						},
					},
				},
				Diffs: map[string]models.DiffDetail{
					"ingress": {
						DesiredValue:  []any{map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": []any{"0.0.0.0/0"}}},
						StateValue:    []any{map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": []any{"0.0.0.0/0"}}},
						LiveValue:     []any{map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": []any{"0.0.0.0/0"}}, map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": []any{"0.0.0.0/0"}}},
						AttributeKind: models.AttributeLiteral,
					},
				},
			},
			// 2. S3 Public Access Block Disabled
			{
				Type:               models.DriftAttribute,
				Severity:           models.SeverityCritical,
				CISRuleID:          "DW-CIS-S3-001",
				DoubleReadVerified: true,
				FindingConfidence:  1.0,
				FindingEvidence:    []string{"live_public_access_block_disabled"},
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: true,
				},
				Resource: models.CanonicalResource{
					CanonicalID: s3CanonicalID,
					Type:        "aws_s3_bucket",
					ProviderID:  "prod-assets-corp-bucket-12345",
					Name:        "prod_assets",
					AccountID:   "123456789012",
					Region:      "us-east-1",
					Source:      models.SourceLive,
					Attributes: map[string]any{
						"bucket":                      "prod-assets-corp-bucket-12345",
						"public_access_block_enabled": false,
					},
				},
				Diffs: map[string]models.DiffDetail{
					"public_access_block_enabled": {
						DesiredValue:  true,
						StateValue:    true,
						LiveValue:     false,
						AttributeKind: models.AttributeLiteral,
					},
				},
			},
			// 3. Rogue Unmanaged EC2 Instance (Shadow Resource)
			{
				Type:               models.DriftShadow,
				Severity:           models.SeverityHigh,
				CISRuleID:          "DW-GOV-TAG-001",
				DoubleReadVerified: true,
				FindingConfidence:  1.0,
				FindingEvidence:    []string{"resource_present_in_live_absent_from_state"},
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: true,
				},
				Resource: models.CanonicalResource{
					CanonicalID: ec2CanonicalID,
					Type:        "aws_instance",
					ProviderID:  "i-rogue-shadow-99",
					Name:        "unmanaged-shadow-host",
					AccountID:   "123456789012",
					Region:      "us-east-1",
					Source:      models.SourceLive,
					Attributes: map[string]any{
						"id":            "i-rogue-shadow-99",
						"instance_type": "t3.medium",
					},
					Tags: map[string]string{
						"CreatedBy": "unknown-console-user",
					},
				},
				Cost: &models.CostEstimate{
					AmountMonthly: 60.74,
					Currency:      "USD",
					Region:        "us-east-1",
					PricingSource: "AWS Pricing On-Demand us-east-1 (v1)",
					PricingModel:  "t3.medium hourly ($0.0416 * 730h)",
					Confidence:    1.0,
				},
			},
		},
	}

	allResources := []models.CanonicalResource{
		report.Items[0].Resource,
		report.Items[1].Resource,
		report.Items[2].Resource,
	}

	costProvider, _ := analyzer.NewStaticCostProvider("us-east-1", nil)
	engine := rules.NewDefaultEngine()
	engine.AnalyzeReport(report, allResources, costProvider)

	if err := evidence.SaveEvidenceBundle(evidenceDir, report, allResources); err != nil {
		panic(err)
	}

	fmt.Printf("Golden demo evidence bundle generated successfully at: %s\n", evidenceDir)
}
