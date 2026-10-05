#!/usr/bin/env bash
# ==============================================================================
# DriftWarden Chaos Drift Injection Script
# Injects the 4 ground-truth mutations against LocalStack or Real AWS
# ==============================================================================
set -euo pipefail

ENDPOINT_FLAG=""
if [[ -n "${AWS_ENDPOINT_URL:-}" ]]; then
  ENDPOINT_FLAG="--endpoint-url ${AWS_ENDPOINT_URL}"
fi

SG_ID="${1:-sg-0123456789}"
INSTANCE_ID="${2:-i-0123456789}"
SUBNET_ID="${3:-subnet-0123456789}"

echo "[CHAOS] Injecting Mutation A: Open port 22 on Security Group (DW-CIS-EC2-001)"
aws ec2 authorize-security-group-ingress \
  ${ENDPOINT_FLAG} \
  --group-id "${SG_ID}" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0 || true

echo "[CHAOS] Injecting Mutation B: Rogue unmanaged EC2 instance (SHADOW_RESOURCE)"
aws ec2 run-instances \
  ${ENDPOINT_FLAG} \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.nano \
  --subnet-id "${SUBNET_ID}" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=rogue-shadow-server}]' || true

echo "[CHAOS] Injecting Mutation C: Unmanaged public S3 bucket (SHADOW_RESOURCE)"
aws s3api create-bucket \
  ${ENDPOINT_FLAG} \
  --bucket "rogue-chaos-bucket-12345" \
  --region us-east-1 || true

echo "[CHAOS] Injecting Mutation D: Terminate baseline EC2 instance (GHOST_RESOURCE)"
aws ec2 terminate-instances \
  ${ENDPOINT_FLAG} \
  --instance-ids "${INSTANCE_ID}" || true

echo "[CHAOS] All 4 mutations injected successfully."
