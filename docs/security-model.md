# DriftWarden Security Model & Threat Matrix

This document defines the formal security boundaries, threat mitigations, and automated verification tests enforced by DriftWarden.

---

## 1. Security Architecture & Invariants

DriftWarden operates as an **adversarial-resilient, read-only cloud auditor**. Its core design guarantees that it cannot be coerced into mutating cloud resources, exposing sensitive secrets, or misclassifying infrastructure permissions.

```
┌────────────────────────────────────────────────────────┐
│               UNTRUSTED INPUT BOUNDARY                 │
│  • Public AWS APIs (eventual consistency, throttling)   │
│  • Arbitrary Git HCL configuration                     │
│  • External Terraform State JSON (v4)                  │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│             DRIFTWARDEN SECURITY FILTERS               │
│  1. Sensitive Attribute Redaction ([REDACTED])         │
│  2. Error Classification Guard (AccessDenied Isolation) │
│  3. Double-Read Eventual Consistency Probe             │
│  4. Safe Shell Array Generation (Strict Zero-eval)     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│                SECURE AUDIT ARTIFACTS                  │
│  • Forensic Evidence Bundles (SHA-256 Checksums)       │
│  • Deterministic GitOps Import Blocks (HCL 1.5+)       │
│  • Dry-Run Revert Plans (EXECUTE=false by default)     │
└────────────────────────────────────────────────────────┘
```

---

## 2. Threat vs Protection vs Automated Test Matrix

| Threat Category | Potential Impact | DriftWarden Architectural Protection | Verifying Automated Test |
|:---|:---|:---|:---|
| **Accidental or Malicious Deletion** | Live AWS resource terminated | **Strict Read-Only Boundary**: Scanner utilizes strictly `Describe*`, `List*`, and `Get*` SDK APIs. Mutating SDK clients are excluded from core collectors. | `tests/adversarial/adversarial_test.go` |
| **Accidental Cloud Mutation** | Resource configuration altered in AWS | **Zero Mutate APIs**: Core collectors contain no update/modify API hooks. | `tests/adversarial/adversarial_test.go` |
| **Secret & Credential Leakage** | Database passwords, API tokens, or SSH keys exposed in scan logs or reports | **Sensitive Masking Layer**: Attribute names matching dictionary (`password`, `secret_key`, `token`, `private_key`) are masked with `[REDACTED]`. Presence verification only. | `pkg/normalizer/fuzz_test.go:FuzzSensitiveMasking` & `tests/adversarial/adversarial_test.go:TestAdversarial_SecretLeakage` |
| **AccessDenied Mistaken for Ghost** | Cloud permission errors generate false "resource deleted" alarms | **Quarantined Classification**: `ErrAccessDenied` sets resource availability to `UNAVAILABLE` and triggers `PARTIAL_SCAN` (exit code 4), never `ABSENT`/Ghost. | `tests/invariants/invariants_test.go:TestInvariant_AccessDenied_QuarantinedAsPartialScan` |
| **AWS API Eventual Consistency Lag** | Transient cloud lag falsely reported as live drift | **Double-Read Consistency Probe**: Re-probes live resources after `--verify-consistency-delay 2.5s` before finalizing attribute/ghost drift findings. | `pkg/diff/consistency_test.go:TestConsistencyProbe_TransientAttributePropagationLag` |
| **Malicious HCL Syntax Injection** | Memory exhaustion or buffer overflow via crafted `.tf` files | **Isolated HCL 2.0 AST Parser**: Syntax errors return safe diagnostics without panic or arbitrary evaluation. | `tests/invariants/invariants_test.go:TestInvariant_MalformedHCL_SafeFailure` |
| **Shell Command Injection in Revert Scripts** | Malicious resource tags or names execute arbitrary code when running `revert.sh` | **Strict Zero-Eval & Bash Array Safety**: Generated scripts prohibit `eval`, format all arguments as quoted elements in bash arrays (`CMD=(...)`), and enforce `set -euo pipefail`. | `tests/adversarial/adversarial_test.go:TestAdversarial_ShellInjectionNoEval` |
| **Unintended Remediation Execution** | Revert script executes destructive actions prematurely | **Dry-Run by Default**: Revert scripts initialize `EXECUTE=false` and require explicit `--execute` flag. | `tests/adversarial/adversarial_test.go:TestAdversarial_ShellInjectionNoEval` |
| **State Table Deadlock** | CI/CD pipeline blocked by active DynamoDB state lock | **Non-Blocking Lock Inspection**: Reads lock metadata without acquiring or modifying locks; supports `--allow-historical-snapshot` for auditing in-flight runs. | `pkg/terraform/lock_test.go:TestAcquireStateSnapshot_Locked_PermittedHistoricalSnapshot` |

---

## 3. Least-Privilege IAM Boundary

DriftWarden requires **only read-only permissions** to discover infrastructure. Use the built-in generator to synthesize the minimal IAM policy:

```bash
driftwarden generate-iam-policy --services ec2,s3,iam > readonly-policy.json
```

The resulting policy contains only `Describe*`, `List*`, and `Get*` actions.
