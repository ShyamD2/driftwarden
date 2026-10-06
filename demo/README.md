# 🎬 DriftWarden Golden End-to-End Demonstration

> **A 100% reproducible walkthrough proving real drift detection, CIS benchmark security violations, and dual-action GitOps remediation.**

---

## 🎯 The Scenario

```
┌────────────────────────────────┐       ┌────────────────────────────────┐
│      DESIRED & STATE           │       │          LIVE AWS CLOUD        │
│  Terraform Configuration (Git) │  vs.  │  Console Operator Mutations    │
├────────────────────────────────┤       ├────────────────────────────────┤
│ 1. SG: Ingress port 443 ONLY   │       │ 1. SG: Port 22 added (0.0.0.0) │
│ 2. S3: Public Access Block ON  │       │ 2. S3: Public Access Block OFF │
│ 3. EC2: None declared          │       │ 3. EC2: Rogue t3.medium launched│
└────────────────────────────────┘       └────────────────────────────────┘
```

---

## 🚀 Running the Demo

Run the automated reproduction script with a single command:

### On Linux / macOS:
```bash
./demo/run_demo.sh
```

### On Windows (PowerShell):
```powershell
.\demo\run_demo.ps1
```

---

## 🔍 Step-by-Step Walkthrough

### 1. The Incident: Manual Cloud Mutation
A cloud operator manually altered AWS resources via the AWS Console without updating Terraform:
* **Mutation A**: Added SSH port 22 open to `0.0.0.0/0` on `sg-demo-web`.
* **Mutation B**: Disabled Public Access Block on `prod-assets-corp-bucket-12345`.
* **Mutation C**: Launched an unmanaged rogue `t3.medium` EC2 instance (`i-rogue-shadow-99`).

---

### 2. Forensic Investigation via `driftwarden explain`

Inspect the diverged Security Group:

```bash
driftwarden explain "aws:aws:ec2:us-east-1:123456789012:security_group/sg-demo-web" \
  --from-scan-dir ./demo/evidence
```

**Output:**
```
========================================================================================
  DRIFTWARDEN DIAGNOSTIC DOSSIER
========================================================================================
Canonical ID:        aws:aws:ec2:us-east-1:123456789012:security_group/sg-demo-web
Resource Type:       aws_security_group
Provider ID:         sg-demo-web
Source Plane:        LIVE
Finding Confidence:  1.00
Double-Read Probe:   VERIFIED (Double-Read Confirmed)

----------------------------------------------------------------------------------------
DRIFT CLASSIFICATION
----------------------------------------------------------------------------------------
Drift Type:          ATTRIBUTE_DRIFT
Severity:            CRITICAL
Evidence Trail:
  • live_ingress_contains_0.0.0.0/0:22
  • state_specifies_443_only
  • Security group allows unrestricted SSH ingress (port 22) from 0.0.0.0/0

----------------------------------------------------------------------------------------
SECURITY & COMPLIANCE POSTURE
----------------------------------------------------------------------------------------
CIS Rule ID:         DW-CIS-EC2-001
Severity:            CRITICAL
```

---

### 3. Dual-Action Remediation

DriftWarden gives platform teams two defensive remediation paths:

#### Path A: GitOps PR Synthesis (`--mode hcl`)
Bring rogue resources into Terraform with modern 1.5+ `import {}` blocks:

```bash
driftwarden reconcile --mode hcl --from-scan-dir ./demo/evidence --out ./reconcile.tf
```

```hcl
import {
  to = aws_security_group.web_prod_sg
  id = "sg-demo-web"
}

resource "aws_security_group" "web_prod_sg" {
  description = "Production web security group"
  name        = "web-prod-sg"
}

import {
  to = aws_instance.unmanaged_shadow_host
  id = "i-rogue-shadow-99"
}

resource "aws_instance" "unmanaged_shadow_host" {
  instance_type = "t3.medium"
  tags = {
    CreatedBy = "unknown-console-user"
  }
}
```

#### Path B: Defensive Shell Revert (`--mode revert`)
Generate an actionable shell script to revert the live AWS mutations back to compliant state:

```bash
driftwarden reconcile --mode revert --from-scan-dir ./demo/evidence --out ./remediation/
```

Safety features in `revert.sh`:
- **Strictly zero `eval` execution**.
- **Enforces `set -euo pipefail`**.
- **Defaults strictly to dry-run mode** (`EXECUTE=false`).
- Requires human review and explicit flag: `./revert.sh --execute`.
