#!/usr/bin/env bash
# ==============================================================================
# DriftWarden Golden End-to-End Demonstration Script
# Scenario: Infrastructure Drift, Security Violation & GitOps Remediation
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================================"
echo "  🛡️  DRIFTWARDEN GOLDEN END-TO-END DEMO"
echo "================================================================================"
echo ""
echo "Scenario Overview:"
echo "1. Baseline Terraform declares SG with port 443 ONLY & S3 with PAB enabled."
echo "2. An operator manually introduces 3 live cloud mutations via AWS Console:"
echo "   • Adds port 22 (SSH) open to 0.0.0.0/0 on the Security Group."
echo "   • Disables S3 Public Access Block."
echo "   • Launches an unmanaged rogue t3.medium EC2 instance."
echo ""

echo "--------------------------------------------------------------------------------"
echo "STEP 1: Inspect Baseline Terraform Configuration"
echo "--------------------------------------------------------------------------------"
cat "${SCRIPT_DIR}/infra/main.tf"
echo ""

echo "--------------------------------------------------------------------------------"
echo "STEP 2: Run DriftWarden Diagnostic Dossier on Security Group"
echo "--------------------------------------------------------------------------------"
"${ROOT_DIR}/bin/driftwarden" explain \
  "aws:aws:ec2:us-east-1:123456789012:security_group/sg-demo-web" \
  --from-scan-dir "${SCRIPT_DIR}/evidence"
echo ""

echo "--------------------------------------------------------------------------------"
echo "STEP 3: Synthesize GitOps Remediation Code (Terraform 1.5+ import blocks)"
echo "--------------------------------------------------------------------------------"
"${ROOT_DIR}/bin/driftwarden" reconcile \
  --mode hcl \
  --from-scan-dir "${SCRIPT_DIR}/evidence" \
  --out "${SCRIPT_DIR}/remediation/reconcile.tf" \
  --plan-only=false

cat "${SCRIPT_DIR}/remediation/reconcile.tf"
echo ""

echo "--------------------------------------------------------------------------------"
echo "STEP 4: Generate Defensive Dry-Run Revert Scripts (Zero eval, strict safety)"
echo "--------------------------------------------------------------------------------"
"${ROOT_DIR}/bin/driftwarden" reconcile \
  --mode revert \
  --from-scan-dir "${SCRIPT_DIR}/evidence" \
  --out "${SCRIPT_DIR}/remediation" \
  --plan-only=false

cat "${SCRIPT_DIR}/remediation/revert.sh"
echo ""

echo "================================================================================"
echo "  ✅ GOLDEN DEMO EXECUTION COMPLETE"
echo "================================================================================"
