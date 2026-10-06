# DriftWarden Forensic Evidence Bundle Specification

**Version**: `1.0.0`  
**Purpose**: Immutable, cryptographically verifiable forensic record of cloud infrastructure divergence, security violations, and observation provenance.

---

## 1. Bundle Directory Hierarchy

When `--save-evidence-dir <dir>` is specified, DriftWarden produces an enterprise-grade forensic bundle containing 6 artifacts:

```
evidence/
├── manifest.json       # Audit metadata, account, regions, and SHA-256 file hashes
├── report.json         # Complete ScanReport with 3-source divergence & CIS findings
├── resources.ndjson    # Canonical state of every scanned resource (newline-delimited JSON)
├── provenance.json     # Finding-to-evidence cryptographic mapping & observation timestamps
├── checksums.txt       # Standard sha256sum file for external cryptographic verification
└── schema_version.txt  # Semantic version of the evidence format (1.0.0)
```

---

## 2. Artifact Schema Details

### 1. `manifest.json`
The root manifest records execution parameters and SHA-256 hashes of all bundle files:

```json
{
  "schema_version": "1.0.0",
  "tool_version": "1.0.0",
  "scan_id": "scan-1791203947",
  "timestamp": "2026-10-06T12:00:00Z",
  "account_id": "197550036081",
  "regions": ["us-east-1", "ap-south-1"],
  "total_resources": 1420,
  "total_drift": 4,
  "status": "COMPLETE",
  "files": [
    "report.json",
    "resources.ndjson",
    "provenance.json",
    "manifest.json",
    "schema_version.txt",
    "checksums.txt"
  ],
  "checksums": {
    "report.json": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "resources.ndjson": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "provenance.json": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  }
}
```

---

### 2. `provenance.json`
Establishes an unbroken chain of custody for every finding. Enables platform engineers and security auditors to answer: *"What exact evidence did DriftWarden observe when it flagged this divergence?"*

```json
{
  "scan_id": "scan-1791203947",
  "tool_version": "1.0.0",
  "generated_at": "2026-10-06T12:00:01Z",
  "findings": [
    {
      "finding_id": "finding-scan-1791203947-0001",
      "resource_id": "sg-0a1b2c3d4e5f67890",
      "canonical_id": "aws:aws:ec2:us-east-1:197550036081:security_group/sg-0a1b2c3d4e5f67890",
      "drift_type": "ATTRIBUTE_DRIFT",
      "severity": "CRITICAL",
      "observed_at": "2026-10-06T12:00:00Z",
      "confidence": 1.0,
      "cis_rule_id": "DW-CIS-EC2-001",
      "evidence_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    }
  ]
}
```

---

### 3. Cryptographic Verification
Any third-party auditor or compliance system can independently verify bundle authenticity:

```bash
cd evidence/
sha256sum -c checksums.txt
```
