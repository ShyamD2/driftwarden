# DriftWarden Security & Drift Revert Plan

**Generated At**: 2026-10-06T13:02:41Z
**Total Mutations**: 3

> **SAFETY WARNING**: All actions are generated for human review. DriftWarden never applies changes destructively or automatically.

## Proposed Remediation Actions

| # | Resource ID | CIS Rule | Severity | Proposed Action |
|---|-------------|----------|----------|-----------------|
| 1 | `sg-demo-web` | `DW-CIS-EC2-001` | **CRITICAL** | Revoke unrestricted SSH ingress (port 22) from 0.0.0.0/0 on sg-demo-web |
| 2 | `prod-assets-corp-bucket-12345` | `DW-CIS-S3-001` | **CRITICAL** | Enable full Public Access Block on S3 bucket prod-assets-corp-bucket-12345 |
| 3 | `i-rogue-shadow-99` | `DRIFT_SHADOW` | **HIGH** | Stop unmanaged shadow EC2 instance i-rogue-shadow-99 pending decommission |

## Execution Instructions

1. Inspect `revert.json` and `revert.sh`.
2. Execute a dry-run first: `./revert.sh` (defaults to dry-run mode).
3. If and only if all proposed mutations are safe and verified, execute: `./revert.sh --execute`.
