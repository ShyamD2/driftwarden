# Contributing to DriftWarden

Thank you for your interest in contributing to **DriftWarden**! We welcome contributions from the community to help make cloud infrastructure drift detection faster, more reliable, and mathematically sound.

Please review this document to understand our contribution process, development environment, coding standards, and safety requirements.

---

## Code of Conduct

All contributors and maintainers are expected to abide by our [Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant v2.1).

---

## Core Architectural Invariants

Before writing code, keep in mind DriftWarden's core design guarantees:
1. **Strictly Read-Only**: DriftWarden NEVER creates, updates, or deletes real cloud resources. Only AWS `Describe*`, `Get*`, and `List*` SDK operations are permitted.
2. **Zero Shell Evaluation**: Reconcile script generation MUST NEVER use `eval` or naked shell expansions. All arguments are passed as safely quoted arrays.
3. **Sensitive Attribute Protection**: Credentials, private keys, and passwords must never be printed or logged in plaintext.
4. **Deterministic Exit Codes**: CLI exit codes are strictly specified (`0` = clean, `1` = error, `2` = drift, `3` = security, `4` = partial scan).

---

## Development Setup

### Prerequisites
- **Go**: Version `1.23` or newer
- **Make**: Standard build automation
- **Git**: Version `2.30+`

### Clone and Build
```bash
git clone https://github.com/ShyamD2/driftwarden.git
cd driftwarden

# Verify dependencies
go mod download

# Build binary
make build
# Binary is generated at bin/driftwarden (or bin/driftwarden.exe on Windows)
```

---

## Running Tests

DriftWarden maintains a comprehensive test suite across several categories:

### 1. Unit Tests
```bash
make test
# or: go test -v -race ./pkg/...
```

### 2. Invariant & Safety Tests
Verifies AccessDenied quarantining, throttling resilience, and malformed state handling:
```bash
go test -v ./tests/invariants/...
```

### 3. Adversarial Security Tests
Verifies zero-eval shell protection, secret redaction, and path traversal defenses:
```bash
go test -v ./tests/adversarial/...
```

### 4. Golden End-to-End Demo Tests
```bash
go test -v ./tests/e2e/...
```

### 5. Fuzz Testing
```bash
make fuzz
# or: go test -fuzz=FuzzNormalizerIdempotency -fuzztime=30s ./pkg/normalizer/...
```

### 6. Performance Benchmarks
```bash
make benchmark
# Automatically executes runner and updates benchmarks/results/
```

---

## How to Add a New CIS Security Rule

Adding a new CIS benchmark rule is straightforward and modular:

### Step 1: Implement the `SecurityRule` Interface
Create a new file in `pkg/rules/cis/v3/`:
```go
package v3

import (
    "fmt"
    "github.com/ShyamD2/driftwarden/pkg/models"
)

type DWCIS_NEW_001 struct{}

func NewDWCIS_NEW_001() *DWCIS_NEW_001 {
    return &DWCIS_NEW_001{}
}

func (r *DWCIS_NEW_001) ID() string {
    return "DW-CIS-NEW-001"
}

func (r *DWCIS_NEW_001) BenchmarkVersion() string {
    return "CIS AWS Foundations Benchmark v3.0.0"
}

func (r *DWCIS_NEW_001) Description() string {
    return "Describe the specific security posture check here"
}

func (r *DWCIS_NEW_001) EvaluateResource(res models.CanonicalResource) (violation bool, severity models.Severity, evidence string, remediation string, err error) {
    if res.Type != "target_resource_type" {
        return false, "", "", "", nil
    }

    // Evaluate configuration attributes
    if isNonCompliant {
        return true, models.SeverityHigh, "Evidence description", "AWS CLI remediation command", nil
    }

    return false, "", "", "", nil
}
```

### Step 2: Register in Rule Registry
Open `pkg/rules/registry.go` and append your rule to `NewDefaultRuleRegistry()`:
```go
reg.Register(cisv3.NewDWCIS_NEW_001())
```

### Step 3: Write Unit Tests
In `pkg/rules/cis/v3/rules_test.go`, add unit tests covering:
- Positive violation detection with expected severity.
- Safe/compliant configurations yielding no violation.
- Irrelevant resource types safely skipped.

---

## Pull Request Guidelines

1. **Branch Naming**: Use `feature/short-description` or `fix/short-description`.
2. **Commit Messages**: Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add DW-CIS-ELB-001 rule for TLS listeners`
   - `fix: handle null CIDR blocks in SG normalizer`
   - `docs: update threat model with AWS STS identity check`
   - `test: add fuzz test for IAM policy normalization`
3. **CI Passing**: Ensure `make test`, `golangci-lint`, and CodeQL all pass cleanly.
4. **No Secrets**: Never commit AWS credentials, API tokens, or production state files.
