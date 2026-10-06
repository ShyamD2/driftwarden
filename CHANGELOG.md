# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-06

### Added
- **Three-Source Correlation Engine**:
  - High-precision reconciliation across Desired (Git HCL 2.0), State (Terraform v4 JSON / S3 Remote Backend), and Live (AWS Cloud).
  - Classification of 6 deterministic drift types: `IN_SYNC`, `ATTRIBUTE_DRIFT`, `SHADOW_RESOURCE`, `GHOST_RESOURCE`, `UNAPPLIED_CONFIG_DRIFT`, and `SPLIT_BRAIN_DRIFT`.
  - Non-blocking DynamoDB lock table auditing for S3-backed state files.
  - Dual-tier live resource discovery combining AWS Resource Groups Tagging API with service-specific SDK APIs.
- **CIS AWS Foundations Benchmark v3.0 Compliance**:
  - Built-in rule engine evaluating cloud security posture across multiple AWS services:
    - `DW-CIS-EC2-001`: Ingress security group SSH (port 22) open to `0.0.0.0/0` (CRITICAL).
    - `DW-CIS-EC2-002`: Ingress security group RDP (port 3389) open to `0.0.0.0/0` (CRITICAL).
    - `DW-CIS-S3-001`: S3 Public Access Block settings disabled (CRITICAL).
    - `DW-CIS-S3-002`: S3 default server-side encryption disabled (HIGH).
    - `DW-CIS-IAM-001`: Administrative IAM wildcard permissions (`*` action/resource) (HIGH).
    - `DW-CIS-RDS-001`: Publicly accessible RDS database instances (CRITICAL).
    - `DW-CIS-CT-001`: Multi-region CloudTrail logging disabled or missing (HIGH).
    - `DW-CIS-VPC-001`: Default security group allowing inbound/outbound traffic (HIGH).
    - `DW-GOV-TAG-001`: Mandatory resource governance tagging enforcement (`Environment`, `Owner`, `CostCenter`).
- **Golden End-to-End Demonstration**:
  - Fully reproducible offline demonstration harness executable via Bash (`demo/run_demo.sh`) and PowerShell (`demo/run_demo.ps1`).
  - Simulates console mutations against a baseline Terraform infrastructure with instant sub-5-second execution, zero AWS credentials required, and automated evidence bundle generation.
- **Fuzz Testing & Invariant Verification**:
  - Continuous property fuzzing for normalizer idempotency (`FuzzNormalizerIdempotency`).
  - Continuous fuzz testing for correlation matrix determinism (`FuzzDriftCorrelationDeterminism`).
  - Formal test suites verifying read-only invariants and permission error handling.
- **FinOps Idle Cost Bleed Estimator**:
  - Embedded cost estimation calculating hourly and monthly dollar waste for unmanaged shadow EC2 instances, unattached EBS volumes, and idle Elastic IPs.
- **Double-Read Consistency Probe**:
  - Automated re-verification of anomalous cloud resources after a configurable delay (`--verify-consistency-delay`) to eliminate false positives caused by AWS API eventual consistency.
- **Multi-Account AWS Organizations Fan-Out**:
  - Automatic member account discovery and concurrent scanning with token bucket rate limiting and cross-account STS AssumeRole support.
- **Dual Capability-Aware Remediation**:
  - **GitOps Mode**: Generates modern Terraform 1.5+ declarative `import {}` blocks and HCL resource definitions for Pull Request workflows.
  - **Revert Mode**: Generates defensive remediation scripts (`revert.sh`) and runbooks (`revert-plan.md`) with dry-run default execution (`EXECUTE=false`) and zero `eval` execution.
- **Forensic Evidence Bundles**:
  - Complete audit persistence supporting offline analysis (`driftwarden explain`) with SHA-256 cryptographic manifests (`manifest.json`, `checksums.txt`, `report.json`, `resources.ndjson`, `provenance.json`).
- **GitHub Action & CI/CD Suite**:
  - Composite GitHub Action with immutable SHA pinning, exit code propagation, and automated sticky PR comments with markdown injection protection.
  - Multi-architecture static binaries for Windows AMD64, Linux AMD64, Linux ARM64, and Darwin ARM64.
  - Minimal (<25MB) distroless container image pinned with immutable digest hashes.

### Security
- **Strict Read-Only Guarantee**: Architecture strictly restricted to `Describe*`, `List*`, and `Get*` AWS API calls.
- **AccessDenied Quarantine**: Non-permission errors never masked as not-found; quarantined under `PARTIAL_SCAN` (exit code 4).
- **Sensitive Attribute Masking**: All secrets, passwords, and tokens redacted as `[REDACTED_SENSITIVE]` prior to comparison, logging, or persistence.
- **STRIDE Threat Model**: Comprehensive security model documentation and adversarial verification test matrix.
