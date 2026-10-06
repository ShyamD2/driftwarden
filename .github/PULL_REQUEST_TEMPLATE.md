## Description
<!-- Provide a brief description of the changes introduced by this pull request. -->

## Related Issues
<!-- Link related issues using GitHub keywords, e.g., Closes #12, Fixes #34 -->

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] New security rule / CIS benchmark check
- [ ] Documentation update
- [ ] Performance improvement / Refactoring
- [ ] Breaking change (fix or feature causing existing functionality to change)

## Safety & Invariant Checklist
- [ ] **Strictly Read-Only**: Confirmed no mutating AWS SDK operations are introduced.
- [ ] **Zero-Eval Shell Safety**: Verified remediation script generator uses safely quoted arrays.
- [ ] **Sensitive Masking**: Checked that new attributes do not leak plaintext secrets.
- [ ] **Unit Tests**: Added or updated unit tests covering changes (`make test`).
- [ ] **Invariants**: Ran invariant and adversarial tests (`go test -v ./tests/...`).
- [ ] **Lint & Format**: Code is formatted with `gofmt` and passes `golangci-lint`.
