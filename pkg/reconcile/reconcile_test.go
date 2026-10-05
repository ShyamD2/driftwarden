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

