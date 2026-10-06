# DriftWarden Golden End-to-End Demonstration Script (PowerShell)
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $scriptDir

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  🛡️  DRIFTWARDEN GOLDEN END-TO-END DEMO" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Scenario Overview:"
Write-Host "1. Baseline Terraform declares SG with port 443 ONLY & S3 with PAB enabled."
Write-Host "2. An operator introduces 3 live cloud mutations via AWS Console:"
Write-Host "   • Adds port 22 (SSH) open to 0.0.0.0/0 on the Security Group."
Write-Host "   • Disables S3 Public Access Block."
Write-Host "   • Launches an unmanaged rogue t3.medium EC2 instance."
Write-Host ""

Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "STEP 1: Run Diagnostic Dossier on Diverged Security Group" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------------------------------"
& "$rootDir/bin/driftwarden.exe" explain "aws:aws:ec2:us-east-1:123456789012:security_group/sg-demo-web" --from-scan-dir "$scriptDir/evidence"

Write-Host ""
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "STEP 2: Synthesize GitOps Remediation Code (Terraform 1.5+ import blocks)" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------------------------------"
& "$rootDir/bin/driftwarden.exe" reconcile --mode hcl --from-scan-dir "$scriptDir/evidence" --out "$scriptDir/remediation/reconcile.tf" --plan-only=$false
Get-Content "$scriptDir/remediation/reconcile.tf"

Write-Host ""
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "STEP 3: Generate Defensive Dry-Run Revert Scripts (Zero eval, strict safety)" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------------------------------"
& "$rootDir/bin/driftwarden.exe" reconcile --mode revert --from-scan-dir "$scriptDir/evidence" --out "$scriptDir/remediation" --plan-only=$false
Get-Content "$scriptDir/remediation/revert.sh"

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  ✅ GOLDEN DEMO EXECUTION COMPLETE" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
