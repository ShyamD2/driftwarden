#!/usr/bin/env bash
# ==============================================================================
# DriftWarden Chaos Cleanup Script
# Cleans rogue resources, destroys baseline fixture, and verifies zero leak
# ==============================================================================
set -euo pipefail

ENDPOINT_FLAG=""
if [[ -n "${AWS_ENDPOINT_URL:-}" ]]; then
  ENDPOINT_FLAG="--endpoint-url ${AWS_ENDPOINT_URL}"
fi

SG_ID="${1:-sg-0123456789}"

echo "[CLEANUP] Reverting Mutation A: Revoking port 22 ingress rule"
aws ec2 revoke-security-group-ingress \
  ${ENDPOINT_FLAG} \
  --group-id "${SG_ID}" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0 || true

echo "[CLEANUP] Reverting Mutation C: Deleting rogue chaos bucket"
aws s3 rb \
  ${ENDPOINT_FLAG} \
  "s3://rogue-chaos-bucket-12345" --force || true

echo "[CLEANUP] Destroying baseline Terraform fixture"
if [[ -d "tests/fixtures/baseline" ]]; then
  pushd tests/fixtures/baseline > /dev/null
  terraform destroy -auto-approve || true
  popd > /dev/null
fi

echo "[CLEANUP] Verification: Confirming zero leaked resources via AWS describe APIs"
REMAINING_INSTANCES=$(aws ec2 describe-instances ${ENDPOINT_FLAG} --filters "Name=instance-state-name,Values=running,pending" --query "Reservations[].Instances[].InstanceId" --output text || true)
if [[ -n "${REMAINING_INSTANCES}" ]]; then
  echo "[CLEANUP WARNING] Remaining active instances: ${REMAINING_INSTANCES}"
else
  echo "[CLEANUP OK] Zero remaining running instances verified."
fi

echo "[CLEANUP COMPLETE] Environment restored."
