# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

The DriftWarden team takes the security of cloud infrastructure seriously. If you discover a security vulnerability, please report it privately rather than opening a public GitHub issue.

### How to Report
1. Email your finding to `security@driftwarden.dev` (or open a private GitHub Security Advisory at [github.com/ShyamD2/driftwarden/security/advisories](https://github.com/ShyamD2/driftwarden/security/advisories)).
2. Include:
   - Type of issue (e.g. secret leakage, command injection in remediation scripts, improper classification).
   - Step-by-step reproduction instructions or a minimal proof of concept.
   - Potential impact on audited infrastructure.

### Response Timeline
- **Initial Acknowledgment**: Within 24 hours.
- **Triage & Status Update**: Within 72 hours.
- **Remediation & Patch Release**: Within 7 business days for critical vulnerabilities.

---

## Security Architectural Guarantees

* **Read-Only Invariant**: DriftWarden's discovery collectors never execute mutate or delete APIs against live cloud infrastructure.
* **Sensitive Attribute Redaction**: All secrets (passwords, private keys, API tokens) are masked to `[REDACTED]` prior to logging, display, or JSON persistence.
* **Zero `eval` in Revert Generation**: Revert scripts are strictly formatted as safely quoted bash arrays and default to dry-run mode (`EXECUTE=false`).
