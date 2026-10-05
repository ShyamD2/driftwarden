# DriftWarden: The Authoritative 14-Question Technical Interview Guide

This guide provides deep-dive, engineering-grade answers to the 14 hardest architectural and systems questions behind DriftWarden.

---

### Q1: How does DriftWarden establish deterministic Canonical Identity across heterogeneous sources?
**Answer**:
Cloud resources lack uniform identifiers across tools. A single EC2 instance is referenced by Terraform address (`aws_instance.web`), provider ID (`i-0123456789`), or ARN (`arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789`). DriftWarden unifies all planes using a byte-for-byte deterministic URN generator adhering to RFC-compliant syntax:
$$\text{URN} = \text{aws}:\langle\text{partition}\rangle:\langle\text{service}\rangle:\langle\text{region}\rangle:\langle\text{account}\rangle:\langle\text{type}\rangle/\langle\text{id}\rangle$$
- **Precedence Hierarchy**: Full ARN > Provider ID + Region + Account > Terraform Address.
- **Global Resources**: Global assets (S3 buckets, IAM roles) normalize region to empty string (`""`), preventing cross-region false duplicates.
- **Identity Confidence Scoring**: Deterministic URN matches yield confidence $1.0$, whereas heuristic tag or name matches score $\le 0.6$, triggering automatic low-confidence suppression.

---

### Q2: Why is binary two-source diffing insufficient, and how does Three-Source Correlation work?
**Answer**:
Traditional tools like `driftctl` only compare State ($\mathbf{S}$) against Live ($\mathbf{L}$). If someone edits an HCL file in Git ($\mathbf{D}$) without running `terraform apply`, a two-source engine reports "in sync" because $\mathbf{S} == \mathbf{L}$, silently hiding unapplied infrastructure changes.
DriftWarden evaluates the full $3 \times 3$ divergence matrix across Desired ($\mathbf{D}$), State ($\mathbf{S}$), and Live ($\mathbf{L}$):
1. $\mathbf{D} == \mathbf{S} == \mathbf{L} \implies \text{IN\_SYNC}$
2. $\mathbf{D} == \mathbf{S} \neq \mathbf{L} \implies \text{ATTRIBUTE\_DRIFT}$ (Cloud console mutation)
3. $\mathbf{D} \neq \mathbf{S} == \mathbf{L} \implies \text{UNAPPLIED\_CONFIG\_DRIFT}$ (Git commit without apply)
4. $\mathbf{D} \neq \mathbf{S} \neq \mathbf{L} \implies \text{SPLIT\_BRAIN\_DRIFT}$ (Code changed and cloud mutated simultaneously)
5. $\mathbf{D} == \emptyset, \mathbf{S} == \emptyset, \mathbf{L} \neq \emptyset \implies \text{SHADOW\_RESOURCE}$ (Rogue unmanaged resource)
6. $\mathbf{S} \neq \emptyset, \mathbf{L} == \emptyset \implies \text{GHOST\_RESOURCE}$ (State exists, cloud asset deleted)

---

### Q3: How does DriftWarden audit production infrastructure without causing DynamoDB state-lock contention?
**Answer**:
CI/CD pipelines frequently fail if an audit tool acquires or blocks on the DynamoDB state-lock table (`terraform-lock-table`). DriftWarden executes read-only lock awareness:
1. Queries the lock table item for `LockID == <state-path>-md5`.
2. If unlocked, audits current state without mutating or locking.
3. If actively locked:
   - Without `--allow-historical-snapshot`: returns `ErrStateLocked` immediately (Exit Code 3).
   - With `--allow-historical-snapshot`: fetches the latest unlocked S3 object version (`s3-version-id`), emits an `AUDITING STALE HISTORICAL SNAPSHOT` warning, and marks the report mode as `HISTORICAL_SNAPSHOT (STALE)`.

---

### Q4: Explain the Dual-Tier AWS Discovery Architecture.
**Answer**:
AWS exposes hundreds of resource types. DriftWarden divides discovery into two tiers:
- **Tier 1 (Core 9 Collectors)**: High-performance, specialized collectors using native AWS SDK v2 paginators for `aws_instance`, `aws_ebs_volume`, `aws_eip`, `aws_security_group`, `aws_vpc`, `aws_subnet`, `aws_route_table`, `aws_s3_bucket`, and `aws_iam_role`. Includes bespoke deep queries (e.g. S3 Public Access Block and SSE configuration).
- **Tier 2 (CloudControl API)**: Generic discovery fallback querying `cloudcontrol:ListResources` for long-tail AWS resource types (`AWS::RDS::DBInstance`, `AWS::DynamoDB::Table`), automatically mapping CloudFormation identifiers to canonical models.

---

### Q5: How do you prevent AWS API throttling (429 / RateExceeded) during mass discovery?
**Answer**:
DriftWarden pairs a token bucket rate limiter (`golang.org/x/time/rate`) with a bounded worker pool:
- Worker pool concurrency defaults to 8 parallel workers.
- Rate limiter enforces a strict threshold (default 15 queries/sec).
- Each collector call is wrapped in exponential backoff middleware with decorrelated jitter (attempting up to 3 retries over 4 seconds) specifically handling `ThrottlingException` and `RequestLimitExceeded`.

---

### Q6: What is the Double-Read Consistency Probe and why is it necessary?
**Answer**:
AWS is eventually consistent. An automated deployment or auto-scaling event may trigger a temporary control-plane read replica lag. To prevent false alerts:
1. When candidate drift is detected on an active resource, DriftWarden pauses for `--verify-consistency-delay` (default 2.5s).
2. Issues an isolated, targeted second read (`Get` API) directly against AWS.
3. If the second read matches state attributes, the drift is dismissed as transient propagation lag.
4. If a resource remains absent and returns `404 NotFound`, it is confirmed as `DoubleReadVerified = true`.
5. If the second read returns `AccessDenied`, it enforces the permission boundary and never marks the resource as absent.

---

### Q7: How does the Semantic Normalizer eliminate false positive drift?
**Answer**:
Cloud providers inject metadata and reorder fields that trigger false diffs:
- **Tag Scrubbing**: Filters cloud-injected system tags matching `aws:*` (`aws:ec2launch:*`, `aws:cloudformation:*`).
- **Security Group Canonicalization**: Ingress and egress rules are sorted deterministically by `Protocol:FromPort:ToPort:CIDR` before comparison.
- **Computed Stripping**: Read-only runtime attributes (`arn`, `owner_id`, `creation_date`, `availability_zone_id`) are stripped while preserving parser metadata (`_attribute_kinds`).
- **System Defaults Equivalence**: Auto-generated default VPCs, default SGs, and main route tables are tagged `IsDefault = true` and suppressed unless `--include-system-defaults` is set.

---

### Q8: How are sensitive attributes protected from log leakage?
**Answer**:
Secret attributes (`password`, `private_key`, `secret_key`, `token`) are identified via pattern matching. Values are masked with `[REDACTED_SENSITIVE]`. Comparisons use existence verification (checking both values are populated) rather than comparing plaintext secrets, guaranteeing zero sensitive leaks in CLI tables, JSON exports, or JUnit XML.

---

### Q9: How does the Policy-as-Code Ignore Engine merge with Terraform lifecycle blocks?
**Answer**:
DriftWarden parses `.driftwardenignore` YAML rules (supporting resource and attribute wildcards like `aws_instance.* -> [ami, tags]`) and merges them with HCL `lifecycle.ignore_changes` blocks declared in Terraform code. Both are evaluated before attribute comparison; ignored attributes are discarded from drift reporting.

---

### Q10: What is the Capability Matrix and how does it prevent broken reconciliation code?
**Answer**:
Every collector declares `CollectorCapabilities` (`Discover`, `Normalize`, `Compare`, `SecurityAnalyze`, `CostEstimate`, `Reconcile`).
When synthesizing GitOps HCL, if `item.Capabilities.Reconcile == false` (e.g. Tier 2 CloudControl resources), DriftWarden strictly refuses to emit speculative HCL. Instead, it emits an explicit comment warning operator that manual import is required, preventing invalid Terraform files.

---

### Q11: What safety guardrails exist in the Revert Script Generator?
**Answer**:
1. **No Destructive Action by DriftWarden**: The binary never invokes mutations.
2. **Strict Dry-Run Default**: Generated `revert.sh` has `EXECUTE=false` by default; executing `./revert.sh` prints commands without applying.
3. **No `eval`**: Commands are constructed as explicit bash argument arrays (`"${CMD[@]}"`), eliminating shell injection vulnerabilities.
4. **Defensive Shell Header**: Scripts enforce `set -euo pipefail`.

---

### Q12: How does the CIS Security Rules Engine evaluate compliance?
**Answer**:
The engine implements versioned rule packs (e.g. CIS AWS Foundations Benchmark v3.0). Rules directly evaluate live cloud state:
- `DW-CIS-EC2-001` / `002`: Unrestricted port 22/3389 ingress open to `0.0.0.0/0` (`CRITICAL`).
- `DW-CIS-S3-001`: Public access block disabled (`CRITICAL`).
- `DW-CIS-S3-002`: Default encryption missing (`HIGH`).
- `DW-CIS-IAM-001`: Granular action wildcard evaluation:
  * `Action: "*"` and `Resource: "*"` $\implies \text{CRITICAL}$
  * `Action: "*"` on specific resource $\implies \text{HIGH}$
  * `Action: "ec2:*"` $\implies \text{MEDIUM}$
- `DW-GOV-TAG-001`: Missing required tags (`Environment`, `Owner`, `CostCenter`) $\implies \text{MEDIUM}$.

---

### Q13: How does DriftWarden calculate financial waste bleed?
**Answer**:
Using static on-demand pricing reference tables (`pkg/analyzer/pricing/us-east-1.json`):
- **EC2 instances**: Hourly rate $\times 730\text{ hours/month}$.
- **Unmanaged Shadow Resources**: 100% of running cost is categorized as waste bleed.
- **Instance Sizing Drift**: Calculates delta cost ($\text{Live} - \text{Desired}$).
- **Unattached EBS Volumes & Idle EIPs**: Flagged as 100% idle bleed.
- Reports explicitly state estimates are based on On-Demand catalog models, not exact billing claims.

---

### Q14: How does DriftWarden maintain a hard $27 budget ceiling during Chaos Testing?
**Answer**:
1. **$0-Cost Local Development**: 95%+ of all testing runs offline using unit mocks and LocalStack.
2. **Gated Real-AWS Flag**: Real AWS calls require explicit `DRIFTWARDEN_REAL_AWS=1`.
3. **Strict Resource Constraints**: Only minimal footprint resources (`t3.nano`, standard SGs, S3 buckets) are provisioned. High-cost resources (NAT Gateways, ALBs, RDS) are barred.
4. **Mandatory Post-Test Teardown**: Automated cleanup scripts run `terraform destroy` and verify deletion via AWS describe APIs (polling until empty), ensuring test costs remain well below the \$27.00 ceiling.
