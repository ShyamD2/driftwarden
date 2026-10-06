package reconcile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ShyamD2/driftwarden/pkg/identity"
	"github.com/ShyamD2/driftwarden/pkg/models"
)

// GenerateRevertArtifacts creates revert-plan.md, revert.json, and revert.sh.
func GenerateRevertArtifacts(report *models.ScanReport, outputDir string) (*RevertPlan, error) {
	if report == nil {
		return nil, fmt.Errorf("scan report is nil")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	plan := &RevertPlan{
		SchemaVersion: "1.0.0",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Actions:       make([]RevertAction, 0),
	}

	for _, item := range report.Items {
		actions := buildRevertActions(item)
		plan.Actions = append(plan.Actions, actions...)
	}
	plan.TotalActions = len(plan.Actions)

	// 1. revert.json
	jsonBytes, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal revert.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "revert.json"), jsonBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed to write revert.json: %w", err)
	}

	// 2. revert-plan.md
	mdContent := buildRevertMarkdown(plan)
	if err := os.WriteFile(filepath.Join(outputDir, "revert-plan.md"), []byte(mdContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write revert-plan.md: %w", err)
	}

	// 3. revert.sh
	shContent := buildRevertShell(plan)
	if err := os.WriteFile(filepath.Join(outputDir, "revert.sh"), []byte(shContent), 0755); err != nil {
		return nil, fmt.Errorf("failed to write revert.sh: %w", err)
	}

	return plan, nil
}

// determineActionConfidence evaluates confidence rating and automated PR patch eligibility.
func determineActionConfidence(item models.DriftItem) (Confidence, bool, string) {
	// 1. Unmanaged shadow resources carry operational disruption risk (e.g. stopping unmanaged VMs)
	if item.Type == models.DriftShadow {
		return ConfidenceMedium, false, "Shadow resource mutation has operational impact and requires manual verification before decommission."
	}

	// 2. Explicit finding confidence evaluations
	if item.FindingConfidence > 0 && item.FindingConfidence < 0.5 {
		return ConfidenceLow, false, "Finding confidence is LOW (< 0.50). Automated PR patch generation disallowed."
	}
	if item.FindingConfidence > 0 && item.FindingConfidence < 0.85 {
		return ConfidenceMedium, false, "Finding confidence is MEDIUM (< 0.85). Manual verification required."
	}

	// 3. Deterministic CIS rule remediations default to HIGH confidence
	return ConfidenceHigh, true, ""
}

func buildRevertActions(item models.DriftItem) []RevertAction {
	var actions []RevertAction
	res := item.Resource
	id := res.ProviderID
	if id == "" {
		id = res.Name
	}

	accountID := res.AccountID
	region := res.Region
	if (accountID == "" || region == "") && res.CanonicalID != "" {
		if comps, err := identity.ParseCanonicalID(res.CanonicalID); err == nil {
			if accountID == "" {
				accountID = comps.AccountID
			}
			if region == "" {
				region = comps.Region
			}
		}
	}

	safeguards := Safeguards{
		AccountID:    accountID,
		Region:       region,
		ResourceType: res.Type,
		Validated:    true,
	}

	conf, autoEligible, riskWarning := determineActionConfidence(item)
	reqManualReview := !autoEligible

	switch item.CISRuleID {
	case "DW-CIS-EC2-001":
		actions = append(actions, RevertAction{
			RuleID:               "DW-CIS-EC2-001",
			ResourceID:           id,
			CanonicalID:          res.CanonicalID,
			Severity:             models.SeverityCritical,
			Confidence:           conf,
			Safeguards:           safeguards,
			AutomatedPREligible:  autoEligible,
			RequiresManualReview: reqManualReview,
			RiskWarning:          riskWarning,
			Command:              []string{"aws", "ec2", "revoke-security-group-ingress", "--group-id", id, "--protocol", "tcp", "--port", "22", "--cidr", "0.0.0.0/0"},
			Description:          fmt.Sprintf("Revoke unrestricted SSH ingress (port 22) from 0.0.0.0/0 on %s", id),
		})
	case "DW-CIS-EC2-002":
		actions = append(actions, RevertAction{
			RuleID:               "DW-CIS-EC2-002",
			ResourceID:           id,
			CanonicalID:          res.CanonicalID,
			Severity:             models.SeverityCritical,
			Confidence:           conf,
			Safeguards:           safeguards,
			AutomatedPREligible:  autoEligible,
			RequiresManualReview: reqManualReview,
			RiskWarning:          riskWarning,
			Command:              []string{"aws", "ec2", "revoke-security-group-ingress", "--group-id", id, "--protocol", "tcp", "--port", "3389", "--cidr", "0.0.0.0/0"},
			Description:          fmt.Sprintf("Revoke unrestricted RDP ingress (port 3389) from 0.0.0.0/0 on %s", id),
		})
	case "DW-CIS-S3-001":
		actions = append(actions, RevertAction{
			RuleID:               "DW-CIS-S3-001",
			ResourceID:           id,
			CanonicalID:          res.CanonicalID,
			Severity:             models.SeverityCritical,
			Confidence:           conf,
			Safeguards:           safeguards,
			AutomatedPREligible:  autoEligible,
			RequiresManualReview: reqManualReview,
			RiskWarning:          riskWarning,
			Command:              []string{"aws", "s3api", "put-public-access-block", "--bucket", id, "--public-access-block-configuration", "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"},
			Description:          fmt.Sprintf("Enable full Public Access Block on S3 bucket %s", id),
		})
	case "DW-CIS-S3-002":
		actions = append(actions, RevertAction{
			RuleID:               "DW-CIS-S3-002",
			ResourceID:           id,
			CanonicalID:          res.CanonicalID,
			Severity:             models.SeverityHigh,
			Confidence:           conf,
			Safeguards:           safeguards,
			AutomatedPREligible:  autoEligible,
			RequiresManualReview: reqManualReview,
			RiskWarning:          riskWarning,
			Command:              []string{"aws", "s3api", "put-bucket-encryption", "--bucket", id, "--server-side-encryption-configuration", `{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}`},
			Description:          fmt.Sprintf("Enable default AES256 server-side encryption on S3 bucket %s", id),
		})
	default:
		// If shadow resource without a CIS rule, provide safe review action
		if item.Type == models.DriftShadow {
			if res.Type == "aws_instance" {
				actions = append(actions, RevertAction{
					ResourceID:           id,
					CanonicalID:          res.CanonicalID,
					Severity:             models.SeverityHigh,
					Confidence:           conf,
					Safeguards:           safeguards,
					AutomatedPREligible:  autoEligible,
					RequiresManualReview: reqManualReview,
					RiskWarning:          riskWarning,
					Command:              []string{"aws", "ec2", "stop-instances", "--instance-ids", id},
					Description:          fmt.Sprintf("Stop unmanaged shadow EC2 instance %s pending decommission", id),
				})
			}
		}
	}

	return actions
}

func buildRevertMarkdown(plan *RevertPlan) string {
	var sb strings.Builder
	sb.WriteString("# DriftWarden Security & Drift Revert Plan\n\n")
	sb.WriteString(fmt.Sprintf("**Generated At**: %s\n", plan.Timestamp))
	sb.WriteString(fmt.Sprintf("**Total Mutations**: %d\n\n", plan.TotalActions))
	sb.WriteString("> **SAFETY WARNING**: All actions are generated for human review. DriftWarden never applies changes destructively or automatically.\n\n")

	sb.WriteString("## Proposed Remediation Actions\n\n")
	sb.WriteString("| # | Resource ID | CIS Rule | Severity | Confidence | Automated PR | Proposed Action |\n")
	sb.WriteString("|---|-------------|----------|----------|------------|--------------|-----------------|\n")

	for i, act := range plan.Actions {
		rule := act.RuleID
		if rule == "" {
			rule = "DRIFT_SHADOW"
		}
		autoPR := "ELIGIBLE"
		if !act.AutomatedPREligible {
			autoPR = "# REQUIRES_MANUAL_REVIEW"
		}
		sb.WriteString(fmt.Sprintf("| %d | `%s` | `%s` | **%s** | `%s` | %s | %s |\n",
			i+1, act.ResourceID, rule, act.Severity, act.Confidence, autoPR, act.Description))
	}

	var reviewActions []RevertAction
	for _, act := range plan.Actions {
		if act.RequiresManualReview {
			reviewActions = append(reviewActions, act)
		}
	}
	if len(reviewActions) > 0 {
		sb.WriteString("\n### Manual Review Safeguards & Risk Warnings\n\n")
		sb.WriteString("> ⚠️ **# REQUIRES_MANUAL_REVIEW**: The following actions require human review before execution:\n")
		for _, act := range reviewActions {
			sb.WriteString(fmt.Sprintf("> - **%s** [%s]: %s\n", act.ResourceID, act.Confidence, act.RiskWarning))
		}
	}

	sb.WriteString("\n## Execution Instructions\n\n")
	sb.WriteString("1. Inspect `revert.json` and `revert.sh`.\n")
	sb.WriteString("2. Execute a dry-run first: `./revert.sh` (defaults to dry-run mode).\n")
	sb.WriteString("3. If and only if all proposed mutations are safe and verified, execute: `./revert.sh --execute`.\n")

	return sb.String()
}

func buildRevertShell(plan *RevertPlan) string {
	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env bash\n")
	sb.WriteString("# GENERATED BY DRIFTWARDEN - REQUIRES HUMAN REVIEW\n")
	sb.WriteString("# DriftWarden Safety Guard: Read-Only Boundary Enforced\n")
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", plan.Timestamp))
	sb.WriteString("set -euo pipefail\n\n")

	sb.WriteString("EXECUTE=false\n")
	sb.WriteString("if [[ \"${1:-}\" == \"--execute\" ]]; then\n")
	sb.WriteString("  EXECUTE=true\n")
	sb.WriteString("fi\n\n")

	sb.WriteString("if [ \"$EXECUTE\" = false ]; then\n")
	sb.WriteString("  echo \"[DRY-RUN] Running in dry-run mode. Pass --execute to apply changes.\"\n")
	sb.WriteString("fi\n\n")

	for i, act := range plan.Actions {
		sb.WriteString(fmt.Sprintf("# Action %d: %s\n", i+1, act.Description))
		if act.Confidence == ConfidenceHigh {
			sb.WriteString(fmt.Sprintf("# [CONFIDENCE: %s] [AUTOMATED_PR_ELIGIBLE]\n", act.Confidence))
		} else {
			sb.WriteString(fmt.Sprintf("# [CONFIDENCE: %s] # REQUIRES_MANUAL_REVIEW\n", act.Confidence))
			if act.RiskWarning != "" {
				sb.WriteString(fmt.Sprintf("# Risk Warning: %s\n", act.RiskWarning))
			}
		}
		// Format command array safely
		var quotedArgs []string
		for _, arg := range act.Command {
			quotedArgs = append(quotedArgs, fmt.Sprintf("%q", arg))
		}
		sb.WriteString(fmt.Sprintf("CMD_%d=(%s)\n", i+1, strings.Join(quotedArgs, " ")))
		sb.WriteString("if [ \"$EXECUTE\" = true ]; then\n")
		sb.WriteString(fmt.Sprintf("  echo \"[EXECUTE] Running: ${CMD_%d[*]}\"\n", i+1))
		sb.WriteString(fmt.Sprintf("  \"${CMD_%d[@]}\"\n", i+1))
		sb.WriteString("else\n")
		sb.WriteString(fmt.Sprintf("  echo \"[DRY-RUN] Would execute: ${CMD_%d[*]}\"\n", i+1))
		sb.WriteString("fi\n\n")
	}

	sb.WriteString("echo \"[COMPLETE] Revert script execution finished.\"\n")
	return sb.String()
}
