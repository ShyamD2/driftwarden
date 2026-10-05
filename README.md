<div align="center">

```
  ____       _  __ _   __        __               _             
 |  _ \ _ __(_)/ _| |_ \ \      / /_ _ _ __ __| | ___ _ __   
 | | | | '__| | |_| __| \ \ /\ / / _` | '__/ _` |/ _ \ '_ \  
 | |_| | |  | |  _| |_   \ V  V / (_| | | | (_| |  __/ | | | 
 |____/|_|  |_|_|  \__|   \_/\_/ \__,_|_|  \__,_|\___|_| |_| 
```

### High-Precision Three-Source AWS Drift Detection, CIS Security Audit & GitOps Reconciliation Engine

[![CI](https://github.com/ShyamD2/driftwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/ShyamD2/driftwarden/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ShyamD2/driftwarden)](https://goreportcard.com/report/github.com/ShyamD2/driftwarden)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![Docker Image](https://img.shields.io/badge/Docker-Distroless%20%3C25MB-2496ED?style=flat-square&logo=docker)](https://github.com/ShyamD2/driftwarden/pkgs/container/driftwarden)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20AWS-v3.0%20Compliant-success?style=flat-square&logo=securityscorecard)](pkg/rules/cis/v3)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=flat-square)](https://github.com/ShyamD2/driftwarden/pulls)

<p align="center">
  <a href="#-the-three-source-architecture">Architecture</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-quickstart">Quickstart</a> •
  <a href="#-cli-command-matrix">CLI Matrix</a> •
  <a href="#-comparison">Comparison</a> •
  <a href="#-benchmarks">Benchmarks</a> •
  <a href="#-github-action--cicd">CI/CD</a> •
  <a href="#-safety--security-invariants">Safety</a>
</p>

---

</div>

## 💡 The Blindspot in Modern Cloud Infrastructure

Traditional drift detection tools only inspect **Terraform State $\longleftrightarrow$ AWS Live State**.

This leaves an alarming blindspot: **Unapplied GitOps Changes**. When an engineer modifies `.tf` files in Git without applying them, state-only diffing reports zero drift—even as your actual declarative truth diverges from reality. Conversely, legacy scanners treat temporary API latency as true drift, triggering spurious alerts that cause alert fatigue.

**DriftWarden solves this with a mathematically verified Three-Source Correlation Matrix**:

$$\text{DESIRED (Git HCL)} \quad \longleftrightarrow \quad \text{STATE (Terraform tfstate)} \quad \longleftrightarrow \quad \text{LIVE (AWS Cloud)}$$

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        DRIFTWARDEN THREE-SOURCE SCAN REPORT                            │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Scan ID:     scan-0182749021                  Execution Time:   184 ms                 │
│ Account ID:  197550036081                     Regions Audited:  us-east-1, ap-south-1  │
│ Lock State:  DynamoDB Audited (Non-blocking)  Audit Status:     COMPLETE               │
│ Resources:   1,420 Scanned                    Drift Detected:   4 Discrepancies        │
└────────────────────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────┬────────────────────┬─────────────────┬──────────┬────────────┬────────────────┬───────────────┐
│ CANONICAL ID                                  │ TYPE               │ DRIFT TYPE      │ SEVERITY │ CONFIDENCE │ CIS RULE       │ MONTHLY WASTE │
├───────────────────────────────────────────────┼────────────────────┼─────────────────┼──────────┼────────────┼────────────────┼───────────────┤
│ aws:aws:ec2:us-east-1:197550036081:sec-group/…│ aws_security_group │ ATTRIBUTE_DRIFT │ CRITICAL │ 1.00       │ DW-CIS-EC2-001 │ -             │
│ aws:aws:s3:::bucket/rogue-shadow-bucket-prod  │ aws_s3_bucket      │ SHADOW_RESOURCE │ HIGH     │ 0.95       │ DW-CIS-S3-001  │ -             │
│ aws:aws:ec2:us-east-1:197550036081:instance/… │ aws_instance       │ SHADOW_RESOURCE │ HIGH     │ 1.00       │ DW-GOV-TAG-001 │ $60.74        │
│ aws:aws:ec2:us-east-1:197550036081:instance/… │ aws_instance       │ GHOST_RESOURCE  │ MEDIUM   │ 1.00       │ -              │ $0.00         │
└───────────────────────────────────────────────┴────────────────────┴─────────────────┴──────────┴────────────┴────────────────┴───────────────┘
```

---

## 🏛️ The Three-Source Architecture

```mermaid
flowchart TD
    subgraph Inputs ["1. Three-Source Ingest Engine"]
        HCL["Git Desired (HCL 2.0 Parser)"]
        State["Terraform State (v4 JSON / S3 Glob)"]
        Live["AWS Live Discovery (Dual-Tier)"]
        Lock["DynamoDB Lock-Aware Snapshot"]
    end

    subgraph Normalization ["2. Normalizer & Integrity Verification"]
        Norm["Semantic Normalizer\n• Canonical SG Rule Sorting\n• System Tag Stripping (aws:*)\n• Default Equivalence"]
        Mask["Sensitive Attribute Masking\n[REDACTED_SENSITIVE]"]
        Probe["Double-Read Consistency Probe\n(Eliminates propagation lag)"]
        Ignore[".driftwardenignore Engine"]
    end

    subgraph Correlation ["3. Correlation Matrix & Rule Evaluation"]
        DiffMatrix{"Three-Source Drift Matrix\n• DESIRED ↔ STATE\n• STATE ↔ LIVE\n• DESIRED ↔ LIVE"}
        CISEE["CIS Benchmark Engine v3.0\n• EC2/S3/IAM/Governance"]
        FinOps["Static FinOps Cost Provider\n(Idle Bleed Calculation)"]
    end

    subgraph Outputs ["4. Output Exporters & Dual Remediation"]
        CLI["Rich ANSI Terminal Table"]
        JSON["JSON v1.0.0 & Evidence Bundle"]
        JUnit["JUnit XML (CI/CD Quality Gates)"]
        Dossier["Deep Diagnostic Dossier (explain)"]
        GitOps["GitOps Reconciler\n(Terraform 1.5+ import blocks)"]
        Revert["Safe Revert Scripts\n(dry-run default, zero eval)"]
    end

    HCL --> Norm
    State --> Norm
    Lock -.-> State
    Live --> Probe --> Norm
    Norm --> Mask --> Ignore --> DiffMatrix
    DiffMatrix --> CISEE
    DiffMatrix --> FinOps
    CISEE --> CLI & JSON & JUnit & Dossier & GitOps & Revert
    FinOps --> CLI & JSON & Dossier & GitOps
```

---

## ⚡ Key Features

* 🎯 **Three-Source Correlation Matrix**: Detects not just standard drift, but **Unapplied Config Drift** (HCL updated but unapplied) and **Split-Brain Drift** (live modified while state also changed).
* 🛡️ **Built-in CIS Benchmark v3.0 Pack**:
  * `DW-CIS-EC2-001`: SSH (port 22) open to `0.0.0.0/0` (CRITICAL)
  * `DW-CIS-EC2-002`: RDP (port 3389) open to `0.0.0.0/0` (CRITICAL)
  * `DW-CIS-S3-001`: S3 Public Access Block disabled (CRITICAL)
  * `DW-CIS-S3-002`: S3 default server-side encryption missing (HIGH)
  * `DW-CIS-IAM-001`: Granular wildcard privilege escalation detection (`*` action/resource)
  * `DW-GOV-TAG-001`: Mandatory tagging enforcement (`Environment`, `Owner`, `CostCenter`)
* 💰 **FinOps On-Demand Cost Bleed Engine**: Computes exact hourly and monthly dollar waste for unmanaged rogue instances, orphaned EBS volumes, and idle unattached Elastic IPs.
* ⏱️ **Double-Read Consistency Probe**: Automatically re-probes anomalous resources after a configurable delay (`--verify-consistency-delay 2.5s`) to completely eliminate false alerts caused by AWS eventual consistency.
* 🔒 **Lock-Aware State Snapshots**: Audits S3-backed states protected by DynamoDB lock tables without deadlocking active CI/CD Terraform pipelines.
* 🏢 **Multi-Account AWS Organizations Fan-Out**: Automatically discovers all active member accounts in AWS Organizations and runs multi-threaded cross-account audits with token bucket rate limiting.
* 🛠️ **Capability-Aware Dual Remediation**:
  * **GitOps Mode**: Generates modern Terraform 1.5+ `import {}` blocks and resource skeletons ready for Pull Requests.
  * **Revert Mode**: Generates defensive remediation shell scripts (`revert.sh`), runbooks (`revert-plan.md`), and JSON payloads with **strict dry-run safety and zero `eval` execution**.

---

## 🚀 Quickstart

### Installation

#### Via Homebrew (macOS / Linux)
```bash
brew tap ShyamD2/tap
brew install driftwarden
```

#### Via Go Install (Go 1.24+)
```bash
go install github.com/ShyamD2/driftwarden/cmd/driftwarden@latest
```

#### Via Docker (Distroless < 25MB)
```bash
docker pull ghcr.io/shyamd2/driftwarden:latest

docker run --rm \
  -v ~/.aws:/home/nonroot/.aws:ro \
  -v $(pwd):/workspace:ro \
  ghcr.io/shyamd2/driftwarden:latest scan \
    --hcl-dir /workspace \
    --tfstate /workspace/terraform.tfstate \
    --regions us-east-1
```

#### Pre-Compiled Release Binaries
Download signed binaries for Linux (`amd64`, `arm64`), macOS (`Apple Silicon`, `Intel`), and Windows from [GitHub Releases](https://github.com/ShyamD2/driftwarden/releases).

---

## 🎮 CLI Command Matrix

DriftWarden features a strictly defined 9-subcommand CLI architecture:

| Command | Description | Typical Use Case |
|---|---|---|
| [`driftwarden scan`](#1-driftwarden-scan) | Complete three-source audit (HCL ↔ State ↔ AWS) | CI/CD scheduled pipelines & drift detection |
| [`driftwarden shadow`](#2-driftwarden-shadow) | Discovers strictly unmanaged rogue assets | Incident response & ghost asset discovery |
| [`driftwarden security`](#3-driftwarden-security) | Evaluates CIS AWS Foundations Benchmark compliance | Cloud security posture management (CSPM) |
| [`driftwarden explain`](#4-driftwarden-explain) | Compiles deep multi-section diagnostic dossier | Deep debugging single resource divergence |
| [`driftwarden reconcile`](#5-driftwarden-reconcile) | Synthesizes GitOps HCL or defensive revert script | Remediation workflow & auto-PR generation |
| [`driftwarden check-permissions`](#6-driftwarden-check-permissions) | Simulates required read-only AWS IAM permissions | Pre-flight audit credential validation |
| [`driftwarden generate-iam-policy`](#7-driftwarden-generate-iam-policy) | Synthesizes strictly minimal read-only IAM policy | Least-privilege IAM role provisioning |
| [`driftwarden doctor`](#8-driftwarden-doctor) | Environment diagnostics & LocalStack health check | Local troubleshooting & setup verification |
| [`driftwarden version`](#9-driftwarden-version) | Prints version, commit hash, and compiler details | Build verification & debugging |

---

### Command Walkthroughs

#### 1. `driftwarden scan`
Performs full three-source reconciliation across local files, S3 state backends, and live AWS APIs:
```bash
driftwarden scan \
  --hcl-dir ./infra \
  --tfstate ./infra/terraform.tfstate \
  --regions us-east-1,ap-south-1 \
  --save-evidence-dir ./evidence \
  --fail-on-critical
```

#### 2. `driftwarden shadow`
Isolates resources existing in AWS but completely absent from Terraform configuration:
```bash
driftwarden shadow \
  --regions us-east-1 \
  --format table \
  --fail-on-drift
```

#### 3. `driftwarden security`
Scans live resources and drift findings for CIS AWS Foundations Benchmark violations:
```bash
driftwarden security \
  --regions us-east-1 \
  --benchmark-version v3.0 \
  --fail-on-critical
```

#### 4. `driftwarden explain`
Generates a complete forensic dossier for a specific canonical resource ID (supports offline audit from saved evidence bundles):
```bash
driftwarden explain "aws:aws:ec2:us-east-1:197550036081:instance/i-0a1b2c3d4e5f67890" \
  --from-scan-dir ./evidence
```

#### 5. `driftwarden reconcile`
Generates safe remediation artifacts:
```bash
# GitOps Mode: Generates Terraform 1.5+ modern import blocks
driftwarden reconcile --mode hcl --out ./reconcile.tf

# Revert Mode: Generates dry-run shell script and markdown action plan
driftwarden reconcile --mode revert --out ./remediation/
```

#### 6. `driftwarden generate-iam-policy`
Synthesizes the exact, least-privilege read-only AWS IAM policy needed to audit selected services:
```bash
driftwarden generate-iam-policy --services ec2,s3,iam > driftwarden-readonly-policy.json
```

---

## 🛡️ The `.driftwardenignore` Engine

Exclude intentional anomalies, ephemeral test resources, or external automation tags using `.driftwardenignore` at your workspace root:

```gitignore
# Ignore entire resource types in specific regions
aws:aws:ec2:us-west-2:*:security_group/*

# Ignore ephemeral spot instances by tag pattern
tags.Environment=testing
tags.Lifecycle=spot-ephemeral

# Suppress noisy computed attribute diffs
*.attributes.latest_restorable_time
aws_s3_bucket.attributes.tags_all
```

---

## 🤖 GitHub Action & CI/CD Integration

DriftWarden includes a battle-tested GitHub Action with automated pull request commenting:

```yaml
name: Infrastructure Drift & Security Audit

on:
  schedule:
    - cron: '0 6 * * *' # Daily at 06:00 UTC
  pull_request:
    branches: [ main ]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      pull-requests: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DRIFTWARDEN_ROLE_ARN }}
          aws-region: us-east-1

      - name: Run DriftWarden Audit
        uses: ShyamD2/driftwarden@v1
        with:
          tfstate: 'terraform.tfstate'
          hcl-dir: '.'
          regions: 'us-east-1'
          fail-on-critical: 'true'
          comment-pr: 'true'
```

---

## 📊 Comparison Matrix

| Feature Dimension | `terraform plan` | `driftctl` | AWS Config | **DriftWarden** |
|---|:---:|:---:|:---:|:---:|
| **Reconciliation Model** | Desired $\leftrightarrow$ State | State $\leftrightarrow$ Live | Live Rules Only | **Desired $\leftrightarrow$ State $\leftrightarrow$ Live (3-Source)** |
| **Shadow Resource Detection** | ❌ No | ✅ Yes | ⚠️ Complex | **✅ Yes (Dual-Tier Discovery)** |
| **Unapplied HCL Drift** | ⚠️ Plan Only | ❌ No | ❌ No | **✅ Yes (`UNAPPLIED_CONFIG_DRIFT`)** |
| **Split-Brain Drift Detection** | ❌ No | ❌ No | ❌ No | **✅ Yes (`SPLIT_BRAIN_DRIFT`)** |
| **DynamoDB Lock-Aware** | ❌ Hard Lock Block | ❌ Hard Lock Block | N/A | **✅ Yes (Non-blocking Lock Audit)** |
| **CIS v3.0 Benchmark Engine** | ❌ No | ❌ No | ⚠️ Pay-per-rule | **✅ Built-in (`DW-CIS-*` Engine)** |
| **FinOps Idle Cost Estimator** | ❌ No | ❌ No | ❌ No | **✅ Built-in ($/month bleed)** |
| **Double-Read Consistency Probe** | ❌ No | ❌ No | ❌ No | **✅ Yes (Zero cloud lag false alerts)** |
| **Modern Terraform 1.5+ Imports** | ❌ No | ❌ No (tf 0.13) | ❌ No | **✅ Yes (`import {}` block synthesis)** |
| **Defensive Dry-Run Revert Scripts** | ❌ No | ❌ No | ❌ No | **✅ Yes (`revert.sh` with zero eval)** |
| **Container Image Size** | N/A | ~85 MB | Cloud SaaS | **`< 25 MB` Distroless Static** |

---

## 🏎️ Hardware-Honest Performance Benchmarks

Recorded on standard commodity hardware (**11th Gen Intel Core i3-1115G4 @ 3.00GHz, 4 vCPUs**):

| Benchmark Suite | Test Workload Scenario | Hard Target SLA | Measured Result | Performance Margin |
|---|---|:---:|:---:|:---:|
| **`BenchmarkStateParsing`** | 1,000 resources parsed from state JSON | $< 50.0\text{ ms}$ | **$8.58\text{ ms}$** | **$5.8\times\text{ faster than target}$** |
| **`BenchmarkSemanticDiffing`** | 1,000 resources correlated across 3 sources | $< 10.0\text{ ms}$ | **$1.62\text{ ms}$** | **$6.2\times\text{ faster than target}$** |
| **`TestMemoryHeapAllocation`** | Peak memory allocated during 1,000-resource diff | $< 30.0\text{ MB}$ | **$2.03\text{ MB}$** | **$14.7\times\text{ below target}$** |

---

## 🔒 Safety & Security Guarantees

1. **Strict Read-Only Guarantee**: DriftWarden only executes `Describe*`, `List*`, and `Get*` API calls. Destructive or mutating cloud operations are architecturally impossible within the core binary.
2. **AccessDenied Invariant**: Permission errors (`ErrAccessDenied`) are strictly quarantined as `PARTIAL_SCAN` (exit code 4) and are never falsely classified as `ErrNotFound`, completely preventing false ghost-resource warnings.
3. **Sensitive Data Masking**: All passwords, secret tokens, private keys, and auth attributes are masked to `[REDACTED_SENSITIVE]` prior to comparison, logging, or export.
4. **Defensive Revert Script Integrity**: Revert scripts synthesized by `driftwarden reconcile --mode revert` strictly prohibit `eval`, default to `EXECUTE=false` echo-only mode, and enforce `set -euo pipefail`.
5. **Exit Code Precedence Guarantee**: Standardized deterministic CLI exit codes:
   * `0`: Clean scan (Zero drift / zero violations)
   * `1`: General runtime error
   * `2`: Drift detected / CRITICAL security violation
   * `3`: Terraform state locked
   * `4`: Partial scan (AccessDenied on some resources)
   * `5`: Invalid configuration / bad flags

---

## 🤝 Contributing

Contributions are warmly welcomed! Please read our [Architecture Guide](docs/ARCHITECTURE.md) to understand the three-source correlation internals and collector pipelines.

```bash
# Clone the repository
git clone https://github.com/ShyamD2/driftwarden.git
cd driftwarden

# Run tests and static analysis
make test
make lint

# Run benchmarks
make bench
```

---

## 📄 License

DriftWarden is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full license text.
