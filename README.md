# 🛡️ DriftWarden

[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen?style=flat-square&logo=github)](https://github.com/ShyamD2/driftwarden/actions)
[![Go Report Card](https://img.shields.io/badge/Go%20Report%20Card-A%2B-brightgreen?style=flat-square)](https://goreportcard.com)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v1.0.0-blue?style=flat-square)](https://github.com/ShyamD2/driftwarden/releases)
[![Docker](https://img.shields.io/badge/Docker-Distroless%20%3C25MB-informational?style=flat-square&logo=docker)](https://ghcr.io/shyamd2/driftwarden)

> **DriftWarden** is a high-precision, production-grade AWS infrastructure drift detection, security compliance, and GitOps reconciliation engine written in Go 1.23+.

---

## ⚡ The Core Problem

Traditional tools compare only **Terraform State $\leftrightarrow$ AWS Live**. This introduces a critical blindspot: if an engineer edits `.tf` files in Git without applying them, state-only diffing reports zero drift while your GitOps source of truth diverges.

**DriftWarden solves this by implementing a true Three-Source Correlation Engine**:
$$\text{DESIRED (HCL)} \longleftrightarrow \text{STATE (tfstate)} \longleftrightarrow \text{LIVE (AWS)}$$

```
========================================================================================
  DRIFTWARDEN INFRASTRUCTURE SCAN REPORT
========================================================================================
Scan ID:          scan-1791203947
Timestamp:        2026-10-05T12:39:07Z
Account ID:       123456789012
Regions:          us-east-1
Audit Status:     COMPLETE
Total Scanned:    1,240
Total Drift:      4
----------------------------------------------------------------------------------------

+-----------------------------------------------+--------------------+----------------+----------+------------+----------------+---------------+
| CANONICAL ID                                  | TYPE               | DRIFT TYPE     | SEVERITY | CONFIDENCE | CIS RULE       | MONTHLY WASTE |
+-----------------------------------------------+--------------------+----------------+----------+------------+----------------+---------------+
| aws:aws:ec2:us-east-1:123456789012:securit... | aws_security_group | ATTRIBUTE_DRIFT| CRITICAL | 1.00       | DW-CIS-EC2-001 | -             |
| aws:aws:s3:::bucket/rogue-shadow-bucket-12... | aws_s3_bucket      | SHADOW_RESOURCE| HIGH     | 0.95       | DW-CIS-S3-001  | -             |
| aws:aws:ec2:us-east-1:123456789012:instanc... | aws_instance       | SHADOW_RESOURCE| HIGH     | 1.00       | DW-GOV-TAG-001 | $60.74        |
| aws:aws:ec2:us-east-1:123456789012:instanc... | aws_instance       | GHOST_RESOURCE | HIGH     | 1.00       | -              | $0.00         |
+-----------------------------------------------+--------------------+----------------+----------+------------+----------------+---------------+
```

---

## 🚀 Quickstart

### 1. Installation

#### Homebrew (macOS / Linux)
```bash
brew install shyamd2/tap/driftwarden
```

#### Go Install
```bash
go install github.com/ShyamD2/driftwarden/cmd/driftwarden@latest
```

#### Docker Container (< 25MB Distroless)
```bash
docker run --rm \
  -v ~/.aws:/home/nonroot/.aws:ro \
  -v $(pwd):/workspace:ro \
  ghcr.io/shyamd2/driftwarden:latest scan --hcl-dir /workspace --tfstate /workspace/terraform.tfstate
```

---

### 2. Common Workflows

#### Audit Drift Across AWS & Terraform
```bash
driftwarden scan --regions us-east-1,us-west-2
```

#### Discover strictly Unmanaged Rogue (Shadow) Assets
```bash
driftwarden shadow --format table --fail-on-drift
```

#### Evaluate CIS Benchmark Security Posture
```bash
driftwarden security --benchmark-version v3.0 --fail-on-critical
```

#### Inspect Deep Diagnostic Dossier (Offline Bundle or Live)
```bash
driftwarden explain "aws:aws:ec2:us-east-1:123456789012:instance/i-0123456789" --from-scan-dir ./evidence
```

#### Dual-Action Reconciliation
```bash
# Preview synthesized GitOps HCL code with Terraform 1.5+ import blocks
driftwarden reconcile --mode hcl --plan-only

# Generate safe defensive revert scripts (dry-run mode by default, zero eval)
driftwarden reconcile --mode revert --out ./revert
```

---

## 📊 Comparison Matrix

| Feature | `terraform plan` | `driftctl` | **DriftWarden** |
|---|---|---|---|
| **Diff Sources** | Desired $\leftrightarrow$ State | State $\leftrightarrow$ Live | **Desired $\leftrightarrow$ State $\leftrightarrow$ Live (3-Source)** |
| **Shadow Resource Detection** | ❌ No | ✅ Yes | **✅ Yes (Dual-Tier Discovery)** |
| **Unapplied Git Config Drift** | ⚠️ Partial | ❌ No | **✅ Yes (`UNAPPLIED_CONFIG_DRIFT`)** |
| **Split-Brain Detection** | ❌ No | ❌ No | **✅ Yes (`SPLIT_BRAIN_DRIFT`)** |
| **DynamoDB Lock Snapshotting** | ❌ Blocks / Fails | ❌ Blocks | **✅ Yes (Non-blocking lock audit)** |
| **CIS v3.0 Security Engine** | ❌ No | ❌ No | **✅ Built-in (`DW-CIS-*` Pack)** |
| **Financial Waste Estimation** | ❌ No | ❌ No | **✅ Yes (On-Demand Bleed Calculation)** |
| **Double-Read Consistency Probe**| ❌ No | ❌ No | **✅ Yes (Eliminates cloud lag false alerts)**|
| **Revert Artifact Generation** | ❌ No | ❌ No | **✅ Yes (`revert.sh`, `revert.json`, `revert-plan.md`)**|
| **Capability Enforcement** | N/A | ❌ No | **✅ Yes (Prevents broken HCL synthesis)** |

---

## 🏎️ Performance Benchmarks

Benchmarks recorded on standard 4-core hardware:

| Benchmark | Test Scenario | Target | Observed Result | Memory Allocated |
|---|---|---|---|---|
| `BenchmarkStateParsing` | 1,000 resources parsed from state JSON | $< 50\text{ ms}$ | **$10.74\text{ ms}$** | $3.10\text{ MB}$ |
| `BenchmarkSemanticDiffing` | 1,000 resources correlated across 3 sources | $< 10\text{ ms}$ | **$2.19\text{ ms}$** | $0.40\text{ MB}$ |
| `TestMemoryHeapAllocation`| Peak heap usage during 1,000-resource diff | $< 30\text{ MB}$ | **$2.03\text{ MB}$** | **$93.2\%\text{ under ceiling}$** |

---

## 🔒 Security & Safety Guarantees

1. **Strict Read-Only Boundary**: DriftWarden only invokes Describe, List, and Get APIs. Zero mutating or destructive API calls are ever executed by the binary.
2. **AccessDenied Invariant**: `ErrAccessDenied` is quarantined as `PARTIAL_SCAN` and never treated as `ErrNotFound`, preventing false ghost resource alerts.
3. **Sensitive Attribute Masking**: Passwords and private keys are replaced with `[REDACTED_SENSITIVE]` and verified via presence checks without logging plaintext secrets.
4. **Shell Script Safety**: Generated `revert.sh` scripts never use `eval`, default strictly to echo-only dry-run, and require `--execute` with explicit human review.
5. **Hard \$27 Test Budget Ceiling**: Automated chaos testbeds run $0-cost locally using mocks and LocalStack; real AWS execution is opt-in (`DRIFTWARDEN_REAL_AWS=1`) with mandatory automated teardown verification.

---

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) for details.
