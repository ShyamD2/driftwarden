# DriftWarden Formal Normalization Contract & Specification

This specification establishes the formal mathematical contract, canonicalization rules, and semantic equivalence invariants enforced by the DriftWarden Normalization Engine (`pkg/normalizer`).

---

## 1. Executive Summary & Purpose

Cloud infrastructure state is inherently heterogeneous across the Three Planes of truth:
1. **Desired Plane ($\mathcal{D}$)**: Abstract, declarative HCL code (Terraform configuration files).
2. **State Plane ($\mathcal{S}$)**: Serialized runtime JSON representations (`terraform.tfstate`).
3. **Live Plane ($\mathcal{L}$)**: Dynamic provider API responses directly from cloud hypervisors (AWS SDK).

Due to disparities in cloud provider serialization, runtime-injected metadata, default value omitting, and unordered collection representations, raw comparisons between $\mathcal{D}$, $\mathcal{S}$, and $\mathcal{L}$ yield spurious false-positive drift alarms.

The **DriftWarden Normalization Function** $\mathcal{N}: \mathcal{R} \to \mathcal{R}$ transforms an arbitrary resource definition into a deterministic, canonical representation such that semantic equivalence equals structural equality:

$$\text{Equivalent}(r_1, r_2) \iff \mathcal{N}(r_1) \equiv \mathcal{N}(r_2)$$

---

## 2. Formal Invariants & Contract

```
┌────────────────────────────────────────────────────────────────────────┐
│                        NORMALIZATION PIPELINE                          │
│                                                                        │
│   Raw Resource (D, S, or L)                                            │
│            │                                                           │
│            ▼                                                           │
│   [1. System Tag Stripping]        Strip aws:*, cloudformation, etc.   │
│            │                                                           │
│            ▼                                                           │
│   [2. Computed Attribute Filter]   Remove arn, owner_id, timestamps    │
│            │                                                           │
│            ▼                                                           │
│   [3. Ordering-Independence]       Sort SG rules, tags, CIDRs          │
│            │                                                           │
│            ▼                                                           │
│   [4. Type Safety & Coercion]      Coerce 443 == "443", bools, floats  │
│            │                                                           │
│            ▼                                                           │
│   [5. Null & Empty Equivalence]    null == omitted == [] == {}         │
│            │                                                           │
│            ▼                                                           │
│   [6. Provider Default Equivalence] encrypted=false == omitted         │
│            │                                                           │
│            ▼                                                           │
│   [7. Sensitive Redaction]         Mask write-only secrets to [REDACTED]
│            │                                                           │
│            ▼                                                           │
│   Canonical Normalized Resource N(x)                                   │
└────────────────────────────────────────────────────────────────────────┘
```

---

### Invariant 1: Ordering-Independence

Collections in declarative infrastructure that lack inherent semantic ordering must evaluate identically regardless of permutation.

#### 1.1 Security Group Rules
- **Problem**: AWS EC2 APIs return ingress and egress rule sets in non-deterministic order, while Terraform HCL files declare them arbitrarily.
- **Invariant**: Security group rules are sorted into a strictly ordered canonical sequence using a deterministic composite sort key:
  $$\text{Key}(rule) = \text{Protocol} \mathbin{\Vert} \text{FromPort} \mathbin{\Vert} \text{ToPort} \mathbin{\Vert} \text{TargetCIDR/GroupID}$$
- **Verification**: `pkg/normalizer/normalizer_test.go:TestNormalizer_SecurityGroupRuleSorting` & `pkg/normalizer/fuzz_test.go:FuzzSecurityGroupRuleSortingPermutations`.

#### 1.2 Resource Tags
- **Problem**: Map iteration in Go and JSON object serialization does not guarantee key ordering.
- **Invariant**: Tag maps are canonicalized by lexicographically sorting keys prior to hashing or serialization.

#### 1.3 CIDR Blocks & Subnet Associations
- **Problem**: Lists of CIDR blocks (e.g. `["10.0.0.0/16", "192.168.1.0/24"]` vs `["192.168.1.0/24", "10.0.0.0/16"]`) represent identical firewall topologies.
- **Invariant**: CIDR slices are sorted numerically by network prefix and mask length.

---

### Invariant 2: Type Safety & Coercion

Configuration languages often serialize scalar values using interchangeable types (e.g., string vs number).

#### 2.1 Numeric vs String Representations
- **Invariant**: Numeric strings representing port numbers, counts, or thresholds coerce to their canonical numeric representation:
  $$443 \equiv \text{"443"} \quad (\text{Port 443})$$
  $$22 \equiv \text{"22"} \quad (\text{Port 22})$$
  $$0 \equiv \text{"0"} \equiv 0.0$$

#### 2.2 Boolean Representations
- **Invariant**: String representations of booleans coerce to canonical boolean values:
  $$\text{"true"} \equiv \text{"TRUE"} \equiv \text{true}$$
  $$\text{"false"} \equiv \text{"FALSE"} \equiv \text{false}$$

#### 2.3 Float vs Integer Representation
- **Invariant**: Floating-point representations with zero fractional part coerce to integer equivalence (`80.0 == 80`).

---

### Invariant 3: Null & Empty Equivalence

The absence of an attribute in one plane must not trigger false drift against an empty or explicit null declaration in another plane.

$$\text{null} \equiv \text{undefined / omitted} \equiv \text{""} \equiv [] \equiv \{\}$$

#### Invariant Rules:
1. An attribute set to `nil` in State is equivalent to that attribute being omitted in Desired HCL.
2. An empty string (`""`) for an optional string attribute is equivalent to `nil` or omission.
3. An empty slice (`[]any{}`) is equivalent to `nil` or an omitted list attribute.
4. An empty map (`map[string]any{}`) is equivalent to `nil` or an omitted map attribute.

---

### Invariant 4: Provider Default Equivalence

Cloud providers inject implicit default values at resource creation time if an attribute is omitted from user configuration.

$$\text{Attribute}(a) = \text{omitted} \iff \text{Attribute}(a) = \text{ProviderDefault}(a)$$

#### Supported Default Equivalences (`pkg/normalizer/defaults.go`):

| Resource Type | Attribute | Provider Default | Semantic Equivalence |
|:---|:---|:---|:---|
| `aws_ebs_volume` | `encrypted` | `false` | `encrypted = false` $\equiv$ omitted |
| `aws_ebs_volume` | `volume_type` | `"gp2"` | `volume_type = "gp2"` $\equiv$ omitted |
| `aws_ebs_volume` | `iops` | `0` | `iops = 0` $\equiv$ omitted |
| `aws_vpc` | `enable_dns_hostnames` | `false` | `enable_dns_hostnames = false` $\equiv$ omitted |
| `aws_vpc` | `enable_dns_support` | `true` | `enable_dns_support = true` $\equiv$ omitted |
| `aws_subnet` | `map_public_ip_on_launch` | `false` | `map_public_ip_on_launch = false` $\equiv$ omitted |
| `aws_s3_bucket` | `server_side_encryption_enabled` | `false` | `sse = false` $\equiv$ omitted |
| `aws_s3_bucket` | `block_public_acls` | `false` | `block_public_acls = false` $\equiv$ omitted |

---

### Invariant 5: System Tag Stripping

Cloud providers and deployment orchestrators automatically inject synthetic runtime tags into live cloud resources. These tags do not exist in Terraform configurations and must never be reported as drift.

#### Stripped Tag Namespaces:
- `aws:*`: AWS internal reserved tags (e.g., `aws:ec2launch:version`, `aws:cloudformation:stack-id`, `aws:cloudformation:logical-id`).
- CloudFormation tags (`cloudformation:*`).
- AWS Elastic Beanstalk tags (`elasticbeanstalk:*`).

#### Invariant:
$$\forall k \in \text{Keys}(\text{Tags}), \quad \text{has\_prefix}(k, \text{"aws:"}) \implies k \notin \mathcal{N}(\text{Tags})$$

- **Verification**: `pkg/normalizer/normalizer_test.go:TestNormalizer_TagCleaningAndComputedStripping`.

---

### Invariant 6: Sensitive Attribute Redaction

Security-critical secrets (passwords, private keys, API tokens, master credentials) are write-only in cloud APIs and must never be leaked into scan reports, evidence bundles, or diff logs.

#### Redaction Policy:
1. **Target Attributes**: Any attribute key containing substrings:
   - `password`, `master_password`, `admin_password`
   - `private_key`, `certificate_private_key`
   - `secret_key`, `secret_string`, `client_secret`
   - `token`, `oauth_token`
2. **Masking Format**: Values are irreversibly replaced with standard placeholder:
   `[REDACTED_SENSITIVE]` (or `[REDACTED]`).
3. **Presence Verification**: Because AWS APIs suppress read-back of write-only secrets, if State defines a password and Live returns empty/omitted, **no drift is emitted**. Drift is only flagged if State lacks a password that Desired mandates.
4. **Verification**: `tests/adversarial/adversarial_test.go:TestAdversarial_SecretLeakage` & `pkg/normalizer/fuzz_test.go:FuzzSensitiveMasking`.

---

### Invariant 7: Normalization Idempotency

Applying the normalization function multiple times to any resource MUST yield the exact same output without mutation or side effects.

$$\mathcal{N}(\mathcal{N}(x)) = \mathcal{N}(x)$$

- **Mathematical Proof & Verification**:
  Fuzz testing in `pkg/normalizer/fuzz_test.go:FuzzNormalizerIdempotency` exercises arbitrary permuted strings, tags, and attributes across millions of cycles, confirming that for all valid resources $x$:
  $$\mathcal{N}^k(x) = \mathcal{N}(x) \quad \forall k \ge 1$$

---

### Invariant 8: Canonical Determinism

Given identical logical resources across different execution environments, operating systems, memory layouts, or Goroutines, the canonical serialized representation and its cryptographic checksum must be 100% bit-for-bit identical.

$$\text{SHA-256}(\mathcal{N}(x)_A) = \text{SHA-256}(\mathcal{N}(x)_B)$$

#### Properties Guaranteed:
1. **Zero Randomness**: No non-deterministic map iteration or memory pointer addresses leak into serialized output.
2. **Platform Invariance**: Serialization matches identically on Windows, Linux, and macOS.
3. **Time Invariance**: Normalization operations are pure functions and do not introduce timestamps into canonical hashes.
4. **Verification**: `pkg/diff/fuzz_test.go:FuzzDriftCorrelationDeterminism`.

---

## 3. Normalization Compliance Matrix

| Invariant | Code Implementation | Verifying Test Suite |
|:---|:---|:---|
| **Ordering-Independence** | `pkg/normalizer/normalizer.go:canonicalizeSecurityGroup` | `pkg/normalizer/fuzz_test.go:FuzzSecurityGroupRuleSortingPermutations` |
| **Type Safety & Coercion** | `pkg/diff/comparator.go` & `pkg/normalizer/defaults.go` | `pkg/diff/fuzz_test.go:FuzzDriftCorrelationDeterminism` |
| **Null & Empty Equivalence** | `pkg/normalizer/defaults.go:isZeroVal` | `pkg/diff/comparator_test.go` |
| **Default Equivalence** | `pkg/normalizer/defaults.go:IsEquivalentToDefault` | `pkg/diff/comparator_test.go` |
| **System Tag Stripping** | `pkg/normalizer/normalizer.go:cleanTags` | `pkg/normalizer/normalizer_test.go:TestNormalizer_TagCleaningAndComputedStripping` |
| **Sensitive Redaction** | `pkg/normalizer/sensitive.go:RedactSensitiveValue` | `tests/adversarial/adversarial_test.go:TestAdversarial_SecretLeakage` |
| **Idempotency** | `pkg/normalizer/normalizer.go:Normalize` | `pkg/normalizer/fuzz_test.go:FuzzNormalizerIdempotency` |
| **Determinism** | `pkg/identity/canonical.go` & `pkg/diff/comparator.go` | `pkg/diff/fuzz_test.go:FuzzDriftCorrelationDeterminism` |
