#!/usr/bin/env bash
set -euo pipefail

ENDPOINT_URL="${LOCALSTACK_ENDPOINT:-http://localhost:4566}"
AWS_REGION="us-east-1"
AWS_CMD="aws --endpoint-url=$ENDPOINT_URL --region=$AWS_REGION"

echo "=== Seeding LocalStack Sandbox at $ENDPOINT_URL ==="

# 1. Create S3 Bucket
echo "Creating S3 bucket: company-assets-prod-123456..."
$AWS_CMD s3 mb s3://company-assets-prod-123456 || true

# Put Public Access Block
$AWS_CMD s3api put-public-access-block \
    --bucket company-assets-prod-123456 \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" || true

# 2. Create DynamoDB State Lock Table
echo "Creating DynamoDB state lock table: terraform-lock-table..."
$AWS_CMD dynamodb create-table \
    --table-name terraform-lock-table \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST || true

# 3. Create VPC
echo "Creating VPC..."
VPC_ID=$($AWS_CMD ec2 create-vpc --cidr-block 10.0.0.0/16 --query 'Vpc.VpcId' --output text)
echo "Created VPC: $VPC_ID"

# 4. Create Subnet
echo "Creating Subnet..."
SUBNET_ID=$($AWS_CMD ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block 10.0.1.0/24 --query 'Subnet.SubnetId' --output text)
echo "Created Subnet: $SUBNET_ID"

# 5. Create Security Group
echo "Creating Security Group: web-sg..."
SG_ID=$($AWS_CMD ec2 create-security-group \
    --group-name web-sg \
    --description "Security group for web instances" \
    --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text)
echo "Created Security Group: $SG_ID"

# 6. Create IAM Role
echo "Creating IAM Role: web-app-role..."
$AWS_CMD iam create-role \
    --role-name web-app-role \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' || true

echo "=== LocalStack Sandbox Seeding Complete ==="
