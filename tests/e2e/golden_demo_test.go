package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShyamD2/driftwarden/pkg/evidence"
	"github.com/ShyamD2/driftwarden/pkg/models"
	"github.com/ShyamD2/driftwarden/pkg/reconcile"
)

// TestE2E_GoldenDemoWalkthrough verifies the entire end-to-end golden demo scenario:
// 1. Evidence bundle loading
// 2. Critical CIS violations presence (DW-CIS-EC2-001, DW-CIS-S3-001)
// 3. Rogue shadow resource detection with financial waste
// 4. GitOps HCL import block synthesis
// 5. Revert script zero-eval dry-run safety
func TestE2E_GoldenDemoWalkthrough(t *testing.T) {
	evidenceDir := filepath.Join("..", "..", "demo", "evidence")

	report, resources, err := evidence.LoadEvidenceBundle(evidenceDir)
	if err != nil {
		t.Fatalf("failed to load golden demo evidence bundle: %v", err)
	}

	if report.Status != "COMPLETE" {
		t.Fatalf("expected COMPLETE status, got %s", report.Status)
	}

	if len(report.Items) != 3 {
		t.Fatalf("expected 3 drift items in golden demo, got %d", len(report.Items))
	}

	// Verify Mutation A: SG SSH Port 22 Open (CRITICAL)
	var foundSG, foundS3, foundShadowEC2 bool
	for _, item := range report.Items {
		switch item.CISRuleID {
		case "DW-CIS-EC2-001":
			foundSG = true
			if item.Severity != models.SeverityCritical {
				t.Errorf("expected SG SSH violation to be CRITICAL, got %s", item.Severity)
			}
			if item.FindingConfidence != 1.0 {
				t.Errorf("expected 1.0 confidence, got %f", item.FindingConfidence)
			}
		case "DW-CIS-S3-001":
			foundS3 = true
			if item.Severity != models.SeverityCritical {
				t.Errorf("expected S3 PAB violation to be CRITICAL, got %s", item.Severity)
			}
		}

		if item.Type == models.DriftShadow && item.Resource.Type == "aws_instance" {
			foundShadowEC2 = true
			if item.Cost == nil || item.Cost.AmountMonthly <= 0 {
				t.Errorf("expected non-zero monthly waste on unmanaged shadow EC2 instance")
			}
		}
	}

	if !foundSG {
		t.Errorf("missing expected DW-CIS-EC2-001 violation in demo report")
	}
	if !foundS3 {
		t.Errorf("missing expected DW-CIS-S3-001 violation in demo report")
	}
	if !foundShadowEC2 {
		t.Errorf("missing expected unmanaged shadow EC2 instance in demo report")
	}

	// Verify GitOps HCL Synthesis
	hclBytes, err := reconcile.GenerateHCLReconciliation(report, "")
	if err != nil {
		t.Fatalf("GenerateHCLReconciliation failed: %v", err)
	}
	hclStr := string(hclBytes)
	if !strings.Contains(hclStr, "import {") || !strings.Contains(hclStr, "to = aws_security_group.web_prod_sg") {
		t.Errorf("reconciliation HCL missing expected import block for web_prod_sg")
	}

	// Verify Defensive Revert Plan Generation
	tmpDir := t.TempDir()
	plan, err := reconcile.GenerateRevertArtifacts(report, tmpDir)
	if err != nil {
		t.Fatalf("GenerateRevertArtifacts failed: %v", err)
	}
	if plan.TotalActions != 3 {
		t.Errorf("expected 3 revert actions, got %d", plan.TotalActions)
	}

	revertScript, err := os.ReadFile(filepath.Join(tmpDir, "revert.sh"))
	if err != nil {
		t.Fatalf("failed to read generated revert.sh: %v", err)
	}
	scriptStr := string(revertScript)

	// Enforce strict safety invariants on revert script
	if strings.Contains(scriptStr, "eval ") || strings.Contains(scriptStr, "\neval") {
		t.Fatalf("revert script must not contain eval")
	}
	if !strings.Contains(scriptStr, "EXECUTE=false") {
		t.Fatalf("revert script must default to EXECUTE=false")
	}
	if !strings.Contains(scriptStr, "set -euo pipefail") {
		t.Fatalf("revert script must include set -euo pipefail")
	}

	_ = resources
}
