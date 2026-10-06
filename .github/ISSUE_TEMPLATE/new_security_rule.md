---
name: New Security / CIS Rule Proposal
about: Propose a new CIS Benchmark or Governance compliance check
title: '[RULE] '
labels: ['rule-pack', 'security']
assignees: ''
---

**Rule Identification**
- Proposed Rule ID (e.g., `DW-CIS-ELB-001`):
- Benchmark Specification (e.g., CIS AWS Foundations Benchmark v3.0.0 Section 2.1):
- Target Resource Type (e.g., `aws_lb`, `aws_security_group`, `aws_rds_cluster`):

**Severity Assessment**
- [ ] CRITICAL (Direct internet exposure, unauthenticated admin access, plaintext credentials)
- [ ] HIGH (Missing encryption, disabled audit logging, overly permissive IAM roles)
- [ ] MEDIUM (Missing organizational governance tags, improper default configurations)
- [ ] LOW (Informational posture recommendations)

**Detection Logic**
Describe the exact attribute check or policy condition:
```
Example:
res.Attributes["listener_protocol"] == "HTTP" && res.Attributes["redirect_action"] == nil
```

**Remediation Guidance**
Provide the standard AWS CLI command or Terraform block to remediate the violation:
```bash
aws elbv2 modify-listener --listener-arn <arn> --protocol HTTPS ...
```
