# DriftWarden Architecture & System Design

DriftWarden is an enterprise-grade AWS cloud infrastructure drift detection, security compliance, and reconciliation engine built in Go 1.23+.

---

## 1. High-Level System Architecture

```mermaid
flowchart TD
    subgraph INGEST ["Three-Source Ingestion Engine"]
        HCL["Desired Plane (HCL Parser)"]
        TFSTATE["State Plane (Schema v4 / S3 Globbing)"]
        DDB["DynamoDB Lock-Aware Snapshot"]
    end

    subgraph DISCOVERY ["Dual-Tier AWS Discovery Engine"]
        SDK["Tier 1: Core 9 AWS SDK Collectors"]
        CC["Tier 2: CloudControl API Collector"]
        ORG["AWS Organizations Multi-Account Dispatcher"]
        POOL["Token Bucket Rate Limiter & Worker Pool"]
    end

    subgraph ENGINE ["Three-Source Correlation & Normalization"]
        NORM["Semantic Normalizer (Tags, Computed, SG Rules)"]
        IGNORE["Policy-as-Code Engine (.driftwardenignore)"]
        PROBE["Double-Read Consistency Probe"]
        COMP["Three-Source Comparator (D ↔ S ↔ L)"]
    end

    subgraph ANALYZER ["Intelligence & Security Layer"]
        CIS["CIS Foundations v3.0 Rules Engine"]
        COST["Static On-Demand Pricing Provider"]
    end

    subgraph OUTPUT ["Diagnostics & Remediation Plane"]
        CLI["Diagnostic UI (ANSI Tables)"]
        EXP["Machine Exporters (JSON 1.0.0, JUnit XML)"]
        BUNDLE["Audit Evidence Bundles (--save-evidence-dir)"]
        RECON["GitOps HCL Synthesizer & Safe Revert Plan"]
    end

    HCL --> COMP
    TFSTATE --> COMP
    DDB --> TFSTATE

    SDK --> POOL
    CC --> POOL
    ORG --> POOL
    POOL --> PROBE --> COMP

    COMP --> NORM --> IGNORE --> ANALYZER
    CIS --> CLI
    COST --> CLI
    ANALYZER --> EXP
    ANALYZER --> BUNDLE
    ANALYZER --> RECON
```

---

## 2. Three-Source Correlation Plane (D ↔ S ↔ L)

Unlike legacy tools that perform binary two-source comparisons (`State ↔ Live`), DriftWarden correlates across three distinct truth sources:

| Desired (HCL) | State (tfstate) | Live (AWS) | Classification | Explanation |
|---|---|---|---|---|
| **$X$** | **$X$** | **$X$** | `IN_SYNC` | Perfect alignment across all planes. |
| **$X$** | **$X$** | **$Y$** | `ATTRIBUTE_DRIFT` | Out-of-band cloud mutation made directly in AWS console or CLI. |
| **$Y$** | **$X$** | **$X$** | `UNAPPLIED_CONFIG_DRIFT` | Code changed in Git/HCL but `terraform apply` was never executed. |
| **$Z$** | **$X$** | **$Y$** | `SPLIT_BRAIN_DRIFT` | Concurrent divergence: Git has new code while AWS suffered rogue mutation. |
| $\emptyset$ | $\emptyset$ | **$X$** | `SHADOW_RESOURCE` | Rogue untracked cloud asset provisioned outside Terraform. |
| **$X$** | **$X$** | $\emptyset$ | `GHOST_RESOURCE` | Resource exists in state/code but was deleted in live cloud. |

---

## 3. Trust Boundaries & Security Model

```mermaid
flowchart LR
    subgraph CI ["CI/CD Pipeline (GitHub Actions)"]
        RUNNER["Runner Node"]
        OIDC["OIDC Token Provider"]
    end

    subgraph AWS ["Target AWS Cloud Account"]
        STS["AWS STS (AssumeRoleWithWebIdentity)"]
        ROLE["DriftWardenExecutionRole (Read-Only)"]
        LIVE["AWS Resources (EC2, S3, IAM, VPC)"]
    end

    OIDC -- Short-Lived JWT --> STS
    STS -- Scoped Temp Credentials --> RUNNER
    RUNNER -- Read-Only API Calls --> LIVE
```

### Security Guardrails
1. **Strict Read-Only Guarantee**: DriftWarden only invokes Describe, List, and Get APIs. Zero mutating or destructive API calls are ever executed by the binary.
2. **AccessDenied Invariant**: Permission errors (`ErrAccessDenied`) are strictly quarantined as `PARTIAL_SCAN` and never misclassified as `ErrNotFound` (preventing false ghost resource alerts).
3. **Sensitive Attribute Masking**: Passwords, private keys, and tokens are masked with `[REDACTED_SENSITIVE]` and compared via existence verification without logging secrets.
4. **Shell Script Safety Boundary**: Generated `revert.sh` scripts never use `eval`, default strictly to echo-only dry-run, and require human review with `--execute`.
