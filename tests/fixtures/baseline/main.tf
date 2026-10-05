terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_vpc" "baseline_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "driftwarden-baseline-vpc"
    Environment = "production"
    Owner       = "security-ops"
    CostCenter  = "CC-7701"
  }
}

resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.baseline_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name        = "driftwarden-subnet-public-1"
    Environment = "production"
    Owner       = "security-ops"
    CostCenter  = "CC-7701"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.baseline_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false

  tags = {
    Name        = "driftwarden-subnet-public-2"
    Environment = "production"
    Owner       = "security-ops"
    CostCenter  = "CC-7701"
  }
}

resource "aws_security_group" "clean_sg" {
  name        = "driftwarden-clean-sg"
  description = "Baseline secure SG with restricted internal ingress"
  vpc_id      = aws_vpc.baseline_vpc.id

  ingress {
    description = "Internal VPC HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "driftwarden-clean-sg"
    Environment = "production"
    Owner       = "security-ops"
    CostCenter  = "CC-7701"
  }
}

resource "aws_s3_bucket" "baseline_bucket" {
  bucket = "driftwarden-baseline-vault-12345"

  tags = {
    Name        = "driftwarden-baseline-vault"
    Environment = "production"
    Owner       = "security-ops"
    CostCenter  = "CC-7701"
  }
}

resource "aws_s3_bucket_public_access_block" "baseline_bucket_pab" {
  bucket = aws_s3_bucket.baseline_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "baseline_bucket_sse" {
  bucket = aws_s3_bucket.baseline_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_instance" "baseline_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.nano"
  subnet_id     = aws_subnet.public_1.id

  vpc_security_group_ids = [aws_security_group.clean_sg.id]

  tags = {
    Name        = "driftwarden-baseline-ec2"
    Environment = "production"
    Owner       = "security-ops"
    CostCenter  = "CC-7701"
  }
}
