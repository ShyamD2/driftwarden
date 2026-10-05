package analyzer

import (
	"math"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestStaticCostProvider_EC2_EBS_EIP(t *testing.T) {
	provider, err := NewStaticCostProvider("us-east-1", nil)
	if err != nil {
		t.Fatalf("failed to create static cost provider: %v", err)
	}

	// 1. EC2 Instance
	ec2Res := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-cost",
		Type:        "aws_instance",
		Region:      "us-east-1",
		Attributes: map[string]any{
			"instance_type": "t3.micro", // 0.0104 * 730 = 7.592
		},
	}
	ec2Cost := provider.Estimate(ec2Res)
	if ec2Cost == nil {
		t.Fatalf("expected cost estimate for t3.micro")
	}
	expectedEC2 := 0.0104 * 730.0
	if math.Abs(ec2Cost.AmountMonthly-expectedEC2) > 0.01 {
		t.Errorf("expected monthly cost ~$%.2f, got $%.2f", expectedEC2, ec2Cost.AmountMonthly)
	}

	// 2. EBS Volume
	ebsRes := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:volume/vol-cost",
		Type:        "aws_ebs_volume",
		Region:      "us-east-1",
		Attributes: map[string]any{
			"size":        100,   // 100 GB
			"volume_type": "gp3", // 0.08 $/GB/mo -> $8.00
		},
	}
	ebsCost := provider.Estimate(ebsRes)
	if ebsCost == nil {
		t.Fatalf("expected cost estimate for gp3 volume")
	}
	if math.Abs(ebsCost.AmountMonthly-8.0) > 0.01 {
		t.Errorf("expected monthly cost $8.00, got $%.2f", ebsCost.AmountMonthly)
	}

	// 3. Unassociated EIP
	eipRes := models.CanonicalResource{
		CanonicalID: "aws:aws:ec2:us-east-1:123456789012:eip/eipalloc-idle",
		Type:        "aws_eip",
		Region:      "us-east-1",
		Attributes: map[string]any{
			"instance_id": "",
		},
	}
	eipCost := provider.Estimate(eipRes)
	if eipCost == nil {
		t.Fatalf("expected cost estimate for idle EIP")
	}
	expectedEIP := 0.005 * 730.0
	if math.Abs(eipCost.AmountMonthly-expectedEIP) > 0.01 {
		t.Errorf("expected monthly cost ~$%.2f, got $%.2f", expectedEIP, eipCost.AmountMonthly)
	}
}

func TestStaticCostProvider_DriftWaste(t *testing.T) {
	provider, err := NewStaticCostProvider("us-east-1", nil)
	if err != nil {
		t.Fatalf("failed to create static cost provider: %v", err)
	}

	// Shadow resource waste (100% waste)
	shadowItem := &models.DriftItem{
		Type: models.DriftShadow,
		Resource: models.CanonicalResource{
			CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-rogue",
			Type:        "aws_instance",
			Region:      "us-east-1",
			Attributes:  map[string]any{"instance_type": "t3.large"}, // 0.0832 * 730 = 60.736
		},
	}
	shadowCost := provider.EstimateDriftWaste(shadowItem)
	if shadowCost == nil {
		t.Fatalf("expected drift waste for shadow instance")
	}
	expectedShadow := 0.0832 * 730.0
	if math.Abs(shadowCost.AmountMonthly-expectedShadow) > 0.01 {
		t.Errorf("expected shadow waste ~$%.2f, got $%.2f", expectedShadow, shadowCost.AmountMonthly)
	}

	// Ghost resource waste ($0.00)
	ghostItem := &models.DriftItem{
		Type: models.DriftGhost,
		Resource: models.CanonicalResource{
			CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-deleted",
			Type:        "aws_instance",
			Region:      "us-east-1",
		},
	}
	ghostCost := provider.EstimateDriftWaste(ghostItem)
	if ghostCost == nil || ghostCost.AmountMonthly != 0.0 {
		t.Errorf("expected ghost resource waste to be $0.00, got: %v", ghostCost)
	}
}

func TestDisabledCostProvider(t *testing.T) {
	provider := &DisabledCostProvider{}
	res := models.CanonicalResource{Type: "aws_instance"}
	if provider.Estimate(res) != nil {
		t.Errorf("expected nil from DisabledCostProvider")
	}
	item := &models.DriftItem{Type: models.DriftShadow}
	if provider.EstimateDriftWaste(item) != nil {
		t.Errorf("expected nil from DisabledCostProvider for drift waste")
	}
}

type mockTestRule struct {
	id          string
	targetType  string
	severity    models.Severity
	shouldFail  func(res models.CanonicalResource) bool
	evidenceMsg string
}

func (m *mockTestRule) ID() string               { return m.id }
func (m *mockTestRule) BenchmarkVersion() string { return "Benchmark v1.0" }
func (m *mockTestRule) Description() string      { return "Mock Test Rule" }
func (m *mockTestRule) EvaluateResource(res models.CanonicalResource) (bool, models.Severity, string, string, error) {
	if m.targetType != "" && res.Type != m.targetType {
		return false, "", "", "", nil
	}
	if m.shouldFail != nil && m.shouldFail(res) {
		return true, m.severity, m.evidenceMsg, "remediation", nil
	}
	return false, "", "", "", nil
}

func TestSecurityEngine_AnalyzeReport(t *testing.T) {
	engine := NewSecurityEngine()
	engine.RegisterRules(
		&mockTestRule{
			id:         "DW-CIS-EC2-001",
			targetType: "aws_security_group",
			severity:   models.SeverityCritical,
			shouldFail: func(res models.CanonicalResource) bool {
				return res.Attributes["open_ssh"] == true
			},
			evidenceMsg: "Security group allows unrestricted SSH ingress",
		},
		&mockTestRule{
			id:         "DW-CIS-S3-001",
			targetType: "aws_s3_bucket",
			severity:   models.SeverityHigh,
			shouldFail: func(res models.CanonicalResource) bool {
				return res.Attributes["public_access_block_enabled"] == false
			},
			evidenceMsg: "S3 bucket Public Access Block is disabled",
		},
	)

	costProvider, _ := NewStaticCostProvider("us-east-1", nil)

	// An existing drift item with open SSH
	report := &models.ScanReport{
		Items: []models.DriftItem{
			{
				Type:     models.DriftShadow,
				Severity: models.SeverityLow,
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-open",
					Type:        "aws_security_group",
					Region:      "us-east-1",
					Attributes: map[string]any{
						"open_ssh": true,
					},
				},
			},
		},
	}

	// A live S3 bucket without Public Access Block (not in report.Items initially)
	allLive := []models.CanonicalResource{
		{
			CanonicalID: "aws:aws:s3:::bucket/unprotected-bucket",
			Type:        "aws_s3_bucket",
			Region:      "us-east-1",
			Attributes: map[string]any{
				"public_access_block_enabled": false,
			},
		},
	}

	engine.AnalyzeReport(report, allLive, costProvider)

	// 1. First item should have CISRuleID = "DW-CIS-EC2-001" and escalated to CRITICAL
	if report.Items[0].CISRuleID != "DW-CIS-EC2-001" {
		t.Errorf("expected DW-CIS-EC2-001, got %s", report.Items[0].CISRuleID)
	}
	if report.Items[0].Severity != models.SeverityCritical {
		t.Errorf("expected escalated CRITICAL severity, got %v", report.Items[0].Severity)
	}

	// 2. Second item should have been added for S3 PAB violation
	if len(report.Items) != 2 {
		t.Fatalf("expected 2 items after security analysis, got %d", len(report.Items))
	}
	if report.Items[1].CISRuleID != "DW-CIS-S3-001" {
		t.Errorf("expected DW-CIS-S3-001, got %s", report.Items[1].CISRuleID)
	}
}
