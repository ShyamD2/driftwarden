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
  region = "us-east-1"
}

# Baseline Production Security Group (Compliant: Ingress 443 only)
resource "aws_security_group" "web_sg" {
  name        = "web-prod-sg"
  description = "Production web security group"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "Allow HTTPS inbound"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "production"
    Owner       = "devops-team"
    CostCenter  = "cc-900"
  }
}

# Baseline Production S3 Bucket (Compliant: Public access block enabled)
resource "aws_s3_bucket" "prod_assets" {
  bucket = "prod-assets-corp-bucket-12345"

  tags = {
    Environment = "production"
    Owner       = "devops-team"
    CostCenter  = "cc-900"
  }
}
