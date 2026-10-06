package reconcile

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/models"
)

func TestReconcile_HCLCapabilityEnforcement(t *testing.T) {
	report := &models.ScanReport{
		Items: []models.DriftItem{
			// 1. Supported resource (Reconcile: true)
			{
				Type: models.DriftShadow,
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: true,
				},
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-012345",
					Type:        "aws_security_group",
					ProviderID:  "sg-012345",
					Name:        "unmanaged_web_sg",
					Attributes: map[string]any{
						"description": "Unmanaged SG",
					},
				},
			},
			// 2. Unsupported resource (Reconcile: false)
			{
				Type: models.DriftShadow,
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: false, // Unsupported!
				},
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:rds:us-east-1:123456789012:db/db-prod-replica",
					Type:        "AWS::RDS::DBInstance",
					ProviderID:  "db-prod-replica",
					Name:        "db-prod-replica",
				},
			},
		},
	}

	hclBytes, err := GenerateHCLReconciliation(report, "")
	if err != nil {
		t.Fatalf("GenerateHCLReconciliation failed: %v", err)
	}

	hclStr := string(hclBytes)

	// Invariant: Unsupported resource produces explicit warning comment, NOT invalid HCL
	if !strings.Contains(hclStr, "Reconciliation: UNSUPPORTED") {
		t.Errorf("expected warning comment for unsupported resource")
	}
	if !strings.Contains(hclStr, "Manual import required for CloudControl-discovered resources") {
		t.Errorf("expected manual import warning message")
	}
	if strings.Contains(hclStr, "resource \"AWS::RDS::DBInstance\"") {
		t.Errorf("should NOT synthesize resource block for unsupported resource")
	}

	// Invariant: Supported resource synthesizes modern import {} block
	if !strings.Contains(hclStr, "import {") {
		t.Errorf("expected modern import block for supported resource")
	}
	if !strings.Contains(hclStr, "id = \"sg-012345\"") {
		t.Errorf("expected correct import ID sg-012345")
	}
	if !strings.Contains(hclStr, "resource \"aws_security_group\" \"unmanaged_web_sg\"") {
		t.Errorf("expected resource block for supported SG")
	}
}

func TestReconcile_RevertPlanSafety(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dw-revert-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	report := &models.ScanReport{
		Items: []models.DriftItem{
			{
				Type:      models.DriftAttribute,
				Severity:  models.SeverityCritical,
				CISRuleID: "DW-CIS-EC2-001",
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-test-ssh",
					Type:        "aws_security_group",
					ProviderID:  "sg-test-ssh",
				},
			},
		},
	}

	plan, err := GenerateRevertArtifacts(report, tmpDir)
	if err != nil {
		t.Fatalf("GenerateRevertArtifacts failed: %v", err)
	}

	if plan.TotalActions != 1 {
		t.Errorf("expected 1 action, got %d", plan.TotalActions)
	}

	shBytes, err := os.ReadFile(filepath.Join(tmpDir, "revert.sh"))
	if err != nil {
		t.Fatalf("failed to read revert.sh: %v", err)
	}
	shStr := string(shBytes)

	// CRITICAL SAFETY INVARIANT: No 'eval' in generated scripts
	if strings.Contains(shStr, "eval") {
		t.Errorf("CRITICAL SAFETY VIOLATION: revert.sh contains 'eval'!")
	}

	// Defensive headers and flags
	if !strings.Contains(shStr, "set -euo pipefail") {
		t.Errorf("expected 'set -euo pipefail' in revert.sh")
	}
	if !strings.Contains(shStr, "EXECUTE=false") {
		t.Errorf("expected default dry-run mode (EXECUTE=false) in revert.sh")
	}
	if !strings.Contains(shStr, "revoke-security-group-ingress") {
		t.Errorf("expected revoke command in revert.sh")
	}
}

func TestReconcile_PermissionsAndPolicy(t *testing.T) {
	evals := EvaluatePermissions([]string{"ec2", "s3"})
	if len(evals) == 0 {
		t.Errorf("expected evaluated permissions for ec2 and s3")
	}

	for _, ev := range evals {
		if ev.Evaluation != EvalAllowed {
			t.Errorf("expected %s to be ALLOWED, got %s", ev.Action, ev.Evaluation)
		}
	}

	policyBytes, err := GenerateMinimalIAMPolicy([]string{"ec2", "s3", "iam"})
	if err != nil {
		t.Fatalf("failed to generate IAM policy: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(policyBytes, &parsed); err != nil {
		t.Fatalf("generated policy is not valid JSON: %v", err)
	}

	if parsed["Version"] != "2012-10-17" {
		t.Errorf("expected policy Version 2012-10-17")
	}
}

func TestReconcile_SynthesizedHCL_TerraformFmt(t *testing.T) {
	tfPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI not available in PATH, skipping terraform fmt check")
	}

	report := &models.ScanReport{
		Items: []models.DriftItem{
			{
				Type: models.DriftShadow,
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: true,
				},
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-012345",
					Type:        "aws_security_group",
					ProviderID:  "sg-012345",
					Name:        "unmanaged_web_sg",
					Attributes: map[string]any{
						"description": "Unmanaged SG",
					},
				},
			},
		},
	}

	hclBytes, err := GenerateHCLReconciliation(report, "")
	if err != nil {
		t.Fatalf("GenerateHCLReconciliation failed: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "reconcile.tf")
	if err := os.WriteFile(tmpFile, hclBytes, 0600); err != nil {
		t.Fatalf("failed to write temp tf file: %v", err)
	}

	cmd := exec.Command(tfPath, "fmt", "-check", tmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("terraform fmt -check failed on synthesized HCL: %v\nOutput: %s\nHCL Content:\n%s", err, string(out), string(hclBytes))
	}
}

func TestReconcile_ConfidenceAndSafeguards(t *testing.T) {
	tmpDir := t.TempDir()

	report := &models.ScanReport{
		Items: []models.DriftItem{
			// 1. High confidence CIS rule finding
			{
				Type:              models.DriftAttribute,
				Severity:          models.SeverityCritical,
				CISRuleID:         "DW-CIS-EC2-001",
				FindingConfidence: 0.95,
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: true,
				},
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:security_group/sg-high-conf",
					Type:        "aws_security_group",
					ProviderID:  "sg-high-conf",
					AccountID:   "123456789012",
					Region:      "us-east-1",
				},
			},
			// 2. Medium confidence finding (e.g. shadow resource)
			{
				Type:              models.DriftShadow,
				Severity:          models.SeverityHigh,
				FindingConfidence: 0.70,
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: true,
				},
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:ec2:us-east-1:123456789012:instance/i-medium-shadow",
					Type:        "aws_instance",
					ProviderID:  "i-medium-shadow",
					AccountID:   "123456789012",
					Region:      "us-east-1",
				},
			},
			// 3. Low confidence finding (< 0.5)
			{
				Type:              models.DriftAttribute,
				Severity:          models.SeverityCritical,
				CISRuleID:         "DW-CIS-S3-001",
				FindingConfidence: 0.35,
				Capabilities: models.CollectorCapabilities{
					Discover:  true,
					Reconcile: true,
				},
				Resource: models.CanonicalResource{
					CanonicalID: "aws:aws:s3:::bucket/bucket-low-conf",
					Type:        "aws_s3_bucket",
					ProviderID:  "bucket-low-conf",
					AccountID:   "123456789012",
					Region:      "us-east-1",
				},
			},
		},
	}

	plan, err := GenerateRevertArtifacts(report, tmpDir)
	if err != nil {
		t.Fatalf("GenerateRevertArtifacts failed: %v", err)
	}

	if plan.TotalActions != 3 {
		t.Fatalf("expected 3 actions, got %d", plan.TotalActions)
	}

	// Action 1: HIGH confidence
	act1 := plan.Actions[0]
	if act1.Confidence != ConfidenceHigh {
		t.Errorf("expected act1 Confidence HIGH, got %s", act1.Confidence)
	}
	if !act1.AutomatedPREligible {
		t.Errorf("expected act1 to be marked AutomatedPREligible")
	}
	if act1.RequiresManualReview {
		t.Errorf("expected act1 to NOT require manual review")
	}
	if act1.Safeguards.AccountID != "123456789012" || act1.Safeguards.Region != "us-east-1" || act1.Safeguards.ResourceType != "aws_security_group" {
		t.Errorf("act1 safeguards not properly populated: %+v", act1.Safeguards)
	}

	// Action 2: MEDIUM confidence
	act2 := plan.Actions[1]
	if act2.Confidence != ConfidenceMedium {
		t.Errorf("expected act2 Confidence MEDIUM, got %s", act2.Confidence)
	}
	if act2.AutomatedPREligible {
		t.Errorf("expected act2 to NOT be marked AutomatedPREligible")
	}
	if !act2.RequiresManualReview {
		t.Errorf("expected act2 to require manual review")
	}
	if act2.RiskWarning == "" {
		t.Errorf("expected act2 to have risk warning populated")
	}

	// Action 3: LOW confidence
	act3 := plan.Actions[2]
	if act3.Confidence != ConfidenceLow {
		t.Errorf("expected act3 Confidence LOW, got %s", act3.Confidence)
	}
	if act3.AutomatedPREligible {
		t.Errorf("expected act3 to NOT be marked AutomatedPREligible")
	}
	if !act3.RequiresManualReview {
		t.Errorf("expected act3 to require manual review")
	}

	// Verify revert.sh output annotations
	shBytes, err := os.ReadFile(filepath.Join(tmpDir, "revert.sh"))
	if err != nil {
		t.Fatalf("failed to read revert.sh: %v", err)
	}
	shStr := string(shBytes)

	if !strings.Contains(shStr, "[CONFIDENCE: HIGH] [AUTOMATED_PR_ELIGIBLE]") {
		t.Errorf("revert.sh missing HIGH confidence automated PR annotation")
	}
	if !strings.Contains(shStr, "# [CONFIDENCE: MEDIUM] # REQUIRES_MANUAL_REVIEW") {
		t.Errorf("revert.sh missing MEDIUM confidence manual review annotation")
	}
	if !strings.Contains(shStr, "# [CONFIDENCE: LOW] # REQUIRES_MANUAL_REVIEW") {
		t.Errorf("revert.sh missing LOW confidence manual review annotation")
	}

	// Verify revert-plan.md output
	mdBytes, err := os.ReadFile(filepath.Join(tmpDir, "revert-plan.md"))
	if err != nil {
		t.Fatalf("failed to read revert-plan.md: %v", err)
	}
	mdStr := string(mdBytes)
	if !strings.Contains(mdStr, "# REQUIRES_MANUAL_REVIEW") {
		t.Errorf("revert-plan.md missing REQUIRES_MANUAL_REVIEW warning")
	}

	// Verify HCL generation annotations
	hclBytes, err := GenerateHCLReconciliation(report, "")
	if err != nil {
		t.Fatalf("GenerateHCLReconciliation failed: %v", err)
	}
	hclStr := string(hclBytes)
	if !strings.Contains(hclStr, "[CONFIDENCE: HIGH] [AUTOMATED_PR_ELIGIBLE]") {
		t.Errorf("HCL output missing HIGH confidence automated PR eligible tag")
	}
	if !strings.Contains(hclStr, "# REQUIRES_MANUAL_REVIEW") {
		t.Errorf("HCL output missing # REQUIRES_MANUAL_REVIEW tag for MEDIUM/LOW items")
	}
}

func TestReconcile_SafeguardsValidation(t *testing.T) {
	sg := Safeguards{
		AccountID:    "123456789012",
		Region:       "us-east-1",
		ResourceType: "aws_security_group",
		Validated:    true,
	}

	// Positive match
	if err := sg.Validate("123456789012", "us-east-1", "aws_security_group"); err != nil {
		t.Fatalf("expected valid match, got error: %v", err)
	}

	// Account mismatch
	if err := sg.Validate("999999999999", "us-east-1", "aws_security_group"); err == nil {
		t.Fatalf("expected error on account ID mismatch")
	}

	// Region mismatch
	if err := sg.Validate("123456789012", "eu-central-1", "aws_security_group"); err == nil {
		t.Fatalf("expected error on region mismatch")
	}

	// Resource type mismatch
	if err := sg.Validate("123456789012", "us-east-1", "aws_s3_bucket"); err == nil {
		t.Fatalf("expected error on resource type mismatch")
	}
}

