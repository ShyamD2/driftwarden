# DriftWarden Phase 2 Golden Baseline HCL

variable "environment" {
  type    = string
  default = "production"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "main-vpc"
    Environment = var.environment
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-1"
  }
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Security group for web instances"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "web-sg"
  }
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [
    aws_security_group.web.id
  ]

  lifecycle {
    ignore_changes = [
      tags,
      ami
    ]
  }

  tags = {
    Name        = "web-server-prod"
    Environment = var.environment
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "company-assets-prod-123456"

  tags = {
    Purpose = "static-assets"
  }
}
