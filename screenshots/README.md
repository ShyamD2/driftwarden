# 📸 DriftWarden Visual Verification & Screenshots

This directory contains verified screenshots demonstrating DriftWarden's three-source state comparison, automated GitOps remediation, defensive revert scripting, rigorous test guarantees, and production CI pipeline.

---

### 1. Drift Diagnostic Dossier
**File**: [`01-drift-detection-dossier.png`](./01-drift-detection-dossier.png)  
**Command**:
```bash
driftwarden explain "aws:aws:ec2:us-east-1:123456789012:security_group/sg-demo-web" \
  --from-scan-dir ./demo/evidence
```
**Key Highlights**:
* Shows Canonical Resource ID and 1.00 Finding Confidence score.
* Double-Read Consistency Probe: `VERIFIED (Double-Read Confirmed)`.
* Exact Evidence Trail and CIS Benchmark violation mapping (`DW-CIS-EC2-001`, `CRITICAL`).
* Multi-plane Attribute Divergence Matrix (`DESIRED (HCL) ↔ STATE (TFSTATE) ↔ LIVE (AWS)`).

---

### 2. GitOps IaC Remediation Synthesis
**File**: [`02-gitops-remediation-hcl.png`](./02-gitops-remediation-hcl.png)  
**Artifact**: `demo/remediation/reconcile.tf`  
**Command**:
```bash
driftwarden reconcile --mode hcl --from-scan-dir ./demo/evidence --out ./reconcile.tf
```
**Key Highlights**:
* Automated synthesis of modern Terraform 1.5+ `import {}` blocks.
* Clean skeleton resource blocks for unmanaged shadow assets and drifted resources.
* Automated PR confidence markers: `[CONFIDENCE: HIGH] [AUTOMATED_PR_ELIGIBLE]`.

---

### 3. Defensive Shell Revert Script
**File**: [`03-defensive-revert-script.png`](./03-defensive-revert-script.png)  
**Artifact**: `demo/remediation/revert.sh`  
**Command**:
```bash
driftwarden reconcile --mode revert --from-scan-dir ./demo/evidence --out ./remediation
```
**Key Highlights**:
* Zero `eval` security guarantee with hardened shell options (`set -euo pipefail`).
* Strictly defaults to safe dry-run mode (`EXECUTE=false`).
* Explicit AWS CLI commands targeting revoked ingress and restored public access blocks.

---

### 4. Comprehensive Test Suite & Invariant Verification
**File**: [`04-test-suite-and-invariants.png`](./04-test-suite-and-invariants.png)  
**Command**:
```bash
go test -count=1 ./...
go test -v ./tests/invariants
```
**Key Highlights**:
* 100% passing across all 20 packages with live, un-cached execution timings.
* Explicit verification of safety invariants:
  * `TestInvariant_AccessDenied_QuarantinedAsPartialScan` (no false ghost resources on permission denials).
  * `TestInvariant_GhostVsAccessDenied`
  * `TestInvariant_Throttling_Classified`
  * `TestInvariant_MalformedState_SafeFailure`
  * `TestInvariant_ExitCodePrecedence`

---

### 5. GitHub Actions Production CI Pipeline
**File**: [`05-github-actions-ci-pipeline.png`](./05-github-actions-ci-pipeline.png)  
**Location**: GitHub Actions (`CI` workflow on branch `main`)  
**Key Highlights**:
* 100% Green pipeline across all active jobs.
* Rigorous verification gates: Module hygiene, Go vet, Staticcheck, Govulncheck, Race detector, and Multi-architecture cross-compilations (Windows, Linux, Darwin).
