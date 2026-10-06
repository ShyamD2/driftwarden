# DriftWarden Threat Model (STRIDE Methodology)

This document specifies the formal threat model for **DriftWarden**, following the Microsoft STRIDE methodology. It defines the trust boundaries, threat actors, assets under protection, identified attack vectors, architectural mitigations, and explicit test verifications.

---

## 1. System Architecture & Trust Boundaries

```
           [ Untrusted Internet / Public Cloud APIs ]
                             |
                      (AWS IAM Boundary)
                             v
+-------------------------------------------------------------+
| HOST SYSTEM (CI/CD Runner / Dev Workstation)                |
|                                                             |
|   +-------------------+       +-----------------------+     |
|   | Terraform State   |       | HCL Codebase          |     |
|   | (terraform.tfstate|       | (*.tf files)          |     |
|   +---------+---------+       +-----------+-----------+     |
|             |                             |                 |
|             +------------+   +------------+                 |
|                          |   |                              |
|                          v   v                              |
|              +-----------------------------+                |
|              | DriftWarden Core Binary     |                |
|              |  - Normalizer Engine        |                |
|              |  - Three-Source Correlator  |                |
|              |  - CIS Security Engine      |                |
|              |  - Sensitive Redaction Mask |                |
|              +--------------+--------------+                |
|                             |                               |
|       +---------------------+---------------------+         |
|       v                                           v         |
|  [ ANSI Terminal / Exporter ]             [ Forensic Bundle ]|
|  (STDOUT / Report JSON)                   (manifest + sha256)|
+-------------------------------------------------------------+
```

### Trust Zones
1. **Zone A: Cloud Provider Control Plane (AWS)**: Untrusted external interface. Responses may be throttled, delayed (eventual consistency), malformed, or injected with malicious tag payloads.
2. **Zone B: Local Storage / Workspace**: Semi-trusted boundary containing `.tf` definitions, `.tfstate` snapshots, and configuration files. May contain sensitive credentials in plaintext attributes.
3. **Zone C: Execution Process (DriftWarden)**: Trusted memory space. Must enforce zero-mutation, zero-eval, and zero-leakage invariants.
4. **Zone D: Output Artifacts**: Forensic evidence bundles and generated remediation scripts consumed by automation engines.

---

## 2. Threat Actor Profiles

| Actor Profile | Description | Capability / Access | Objective |
| :--- | :--- | :--- | :--- |
| **Malicious Insider** | Developer or operator with cloud or Git repository write access | Can alter cloud infrastructure out-of-band or modify Terraform definitions | Inject rogue shadow infrastructure or hide configuration drift |
| **Compromised CI Pipeline** | Attacker compromising CI runner environment | Can manipulate environment variables, CLI arguments, and state files | Force DriftWarden to run arbitrary commands or exfiltrate credentials |
| **Untrusted Terraform Author** | Author contributing pull requests | Controls resource names, attribute strings, and tags in HCL | Achieve command injection during remediation script generation |
| **AWS Control Plane Adversary** | Compromised AWS credentials or MITM attacker | Controls AWS API responses | Cause denial-of-service, induce false alerts, or mask existing drift |

---

## 3. STRIDE Threat Analysis Matrix

### S — Spoofing

| Threat ID | Threat Description | Attack Vector | DriftWarden Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **TH-S-01** | **AWS Account / Identity Spoofing** | Compromised ambient credentials scan incorrect AWS account | DriftWarden queries `sts:GetCallerIdentity` on startup to verify expected target Account ID and ARN against configuration. | `pkg/collector/dispatcher_test.go` |
| **TH-S-02** | **Provider ID Masquerading** | Cloud resource returns spoofed ARN or ID matching a different state resource | Canonical IDs are computed deterministically via standard format `aws:provider:service:region:account:type/id`. | `pkg/models/models_test.go` |

---

### T — Tampering

| Threat ID | Threat Description | Attack Vector | DriftWarden Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **TH-T-01** | **Local State File Tampering** | Manipulated or truncated `terraform.tfstate` injected into runner | State parsing strictly validates schema syntax, required fields, and JSON integrity. Fails fast with `ERR_STATE_PARSE` rather than misclassifying missing items. | `tests/invariants/TestInvariant_MalformedState_SafeFailure` |
| **TH-T-02** | **Forensic Evidence Tampering** | Auditor or pipeline modifies evidence JSON or NDJSON after scan | Evidence bundles include `manifest.json` and `checksums.txt` with SHA-256 digests for all generated artifacts. | `pkg/evidence/bundle_test.go` |
| **TH-T-03** | **Cloud Resource Mutation by Auditor** | Auditor tool inadvertently writes or mutates live cloud state | Strictly enforced read-only architecture: code imports only `Describe*`, `Get*`, and `List*` AWS SDK operations. Mutating SDK calls (`Create*`, `Delete*`, `Update*`) are barred by CI lint rules. | `tests/adversarial/adversarial_test.go` |

---

### R — Repudiation

| Threat ID | Threat Description | Attack Vector | DriftWarden Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **TH-R-01** | **Unattributed Drift Findings** | Team disputes who or what modified an unmanaged cloud resource | Every drift finding records cloud ARN, region, account ID, timestamp, and cryptographic scan fingerprint in `provenance.json`. | `pkg/evidence/bundle_test.go` |
| **TH-R-02** | **False Drift Claims Due to Cloud Lag** | Temporary AWS replication lag claims drift that resolves immediately | Configurable double-read probe (`--verify-consistency-delay`) re-verifies discrepancies before emitting findings, eliminating false allegations. | `pkg/diff/consistency_test.go` |

---

### I — Information Disclosure

| Threat ID | Threat Description | Attack Vector | DriftWarden Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **TH-I-01** | **Sensitive Credential Leakage in Reports** | Database passwords or secret strings in state files printed to stdout/logs | `pkg/normalizer/sensitive.go` maintains a sensitive attribute mask. Matching keys (`password`, `secret_string`, `private_key`) are masked with `[REDACTED_SENSITIVE]`. | `tests/adversarial/TestAdversarial_SecretLeakage` |
| **TH-I-02** | **Directory Traversal via Scan Arguments** | Attacker specifies malicious `--save-evidence-dir` or output paths | All evidence and output paths are validated and cleaned using `filepath.Clean` and checked against parent boundary escapes. | `tests/adversarial/TestAdversarial_PathTraversalProtection` |

---

### D — Denial of Service

| Threat ID | Threat Description | Attack Vector | DriftWarden Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **TH-D-01** | **AWS API Rate Limit Starvation** | Deep scans trigger AWS control plane throttling (`RequestLimitExceeded`) | Multi-account dispatcher enforces exponential backoff with jitter and per-service concurrency limits. API efficiency metrics track throttles in real time. | `tests/invariants/TestInvariant_Throttling_Classified` |
| **TH-D-02** | **Memory Exhaustion on Massive States** | Malicious or extreme state files (100k+ resources) crash runner | Streaming state parser and memory-conscious data structures keep peak heap allocation under 35 MB even for 10,000 resources. | `benchmarks/results/benchmark-2026-10.md` |
| **TH-D-03** | **Network Timeout Hang** | Unresponsive AWS endpoints cause pipeline to hang indefinitely | Context deadlines are strictly propagated throughout all collector routines, guaranteeing graceful degradation and deterministic exit. | `tests/invariants/TestInvariant_Timeout_GracefulDegradation` |

---

### E — Elevation of Privilege

| Threat ID | Threat Description | Attack Vector | DriftWarden Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **TH-E-01** | **Shell Injection via Resource Name / Tag** | Attacker creates resource named `test; rm -rf /;` expecting bash execution | Remediation generator (`pkg/reconcile/`) emits bash command arrays without `eval` or naked string expansion. Variables are quoted safely, and execution defaults to dry-run (`EXECUTE=false`). | `tests/adversarial/TestAdversarial_ShellInjectionNoEval` |
| **TH-E-02** | **Arbitrary Code Execution via Plugins** | Malicious third-party rule packs execute unsafe system routines | All rule interfaces are compiled in Go statically; rules run within pure memory evaluation without access to child processes or OS shells. | `pkg/rules/cis/v3/rules_test.go` |

---

## 4. Residual Risks & Operational Guidance

1. **Local State File Security**: DriftWarden reads `terraform.tfstate` from disk. If the local state file contains plaintext secrets written by Terraform, the operator must secure the filesystem with least-privilege POSIX file modes (`0600`).
2. **Ambient AWS Credentials**: DriftWarden assumes the identity granted to it by the execution environment. Operators must assign least-privilege IAM policies (`SecurityAudit` or `ViewOnlyAccess`) to prevent accidental permission creep.
3. **Third-Party AWS Providers**: DriftWarden supports AWS resources natively. Cloud resources managed through unsupported bespoke providers will be reported as unknown rather than drifted.
