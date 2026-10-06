# DriftWarden Versioning & Stability Policy

This document defines the versioning guarantees, backward compatibility promises, and stability lifecycles for DriftWarden CLI flags, JSON schemas, evidence bundles, and internal Go packages.

---

## 1. Semantic Versioning Specification (SemVer 2.0.0)

DriftWarden strictly follows [Semantic Versioning 2.0.0](https://semver.org/):

$$\text{Version} = \text{MAJOR}.\text{MINOR}.\text{PATCH}$$

- **MAJOR**: Breaking changes to CLI command syntax, removal of flags, breaking modifications to JSON schemas, or changes in exit code semantics.
- **MINOR**: Backward-compatible new features, new CIS benchmark rules, new resource collectors, additive fields in JSON reports, or performance improvements.
- **PATCH**: Backward-compatible bug fixes, security patches, documentation updates, and false-positive normalizer corrections.

---

## 2. CLI Surface & Flag Stability Guarantees

### Stability Tiers

| Tier | Definition | Change Policy |
| :--- | :--- | :--- |
| **Stable (GA)** | Core CLI commands (`scan`, `shadow`, `security`, `explain`, `reconcile`) and their documented flags | Breaking changes require a MAJOR version increment and a 6-month deprecation notice. |
| **Experimental** | Pre-release features marked with `--experimental-*` or documented as beta | May change or be removed between MINOR versions with release note notice. |

### Deprecation Process
1. A flag or command targeted for deprecation emits a warning to stderr when invoked.
2. The flag remains functional for at least one full MINOR release lifecycle.
3. The flag is permanently removed in the next MAJOR release.

### Exit Code Contract
Exit codes are strictly stabilized across all 1.x releases:

| Exit Code | Constant | Meaning | Stability |
| :--- | :--- | :--- | :--- |
| `0` | `ExitCodeClean` | No drift and no security violations detected | **Guaranteed** |
| `1` | `ExitCodeSystemError` | Unrecoverable error (e.g., missing credentials, fatal I/O) | **Guaranteed** |
| `2` | `ExitCodeDriftFound` | Infrastructure drift detected | **Guaranteed** |
| `3` | `ExitCodeSecurityViolation` | CIS benchmark or security rule violation detected | **Guaranteed** |
| `4` | `ExitCodePartialScan` | Scan completed with quarantined permissions (`AccessDenied`) | **Guaranteed** |

---

## 3. Machine-Readable Schema Stability

DriftWarden generates machine-readable outputs designed for consumption in automated CI/CD and SIEM pipelines.

### JSON Report (`--format json`)
- The JSON output contains a top-level field `schema_version` (currently `"1.0.0"`).
- **Additive Changes**: New fields may be added in MINOR releases without incrementing the major schema version.
- **Subtractive / Altering Changes**: Removing existing keys, altering field types, or changing enum string values requires bumping `schema_version` and is restricted to MAJOR DriftWarden releases.
- Consumer parsers are expected to ignore unknown fields.

### JUnit XML (`--format junit`)
- Complies with standard JUnit XML schema.
- Test suites represent resource categories; test cases represent evaluated drift and security invariants.
- Compatible with GitHub Actions, GitLab CI, Jenkins, and Azure DevOps test reporters.

---

## 4. Forensic Evidence Bundle Compatibility

Evidence bundles created via `--save-evidence-dir` maintain deterministic artifact naming and format:

| Artifact | Format | Stability Contract |
| :--- | :--- | :--- |
| `schema_version.txt` | ASCII Text | Contains the specification version (e.g. `1.0.0`). |
| `manifest.json` | JSON | Contains scan metadata, tool version, and SHA-256 hashes of all files in the bundle. |
| `report.json` | JSON | Full `ScanReport` matching the JSON report schema. |
| `resources.ndjson` | NDJSON | Stream of all `CanonicalResource` records across Desired, State, and Live. |
| `provenance.json` | JSON | Cryptographic finding provenance linking each drift item to source states and live ARNs. |
| `checksums.txt` | SHA-256 Text | BSD/GNU format SHA-256 checksums (`<hash>  <filename>`). |

Third-party forensic and compliance tools can safely depend on the presence of these 6 files in any DriftWarden evidence bundle.

---

## 5. Security Rule Versioning

Security rule IDs adhere to an immutable naming convention:
- `DW-CIS-<SERVICE>-<NUMBER>`: CIS AWS Foundations Benchmark rules (e.g. `DW-CIS-EC2-001`, `DW-CIS-S3-001`).
- `DW-GOV-<CATEGORY>-<NUMBER>`: Governance and compliance rules (e.g. `DW-GOV-TAG-001`).

Once a rule ID is published, its detection intent and ID will never change. Refinements to rule heuristics that eliminate false positives are released in PATCH versions. New rules are released in MINOR versions.
