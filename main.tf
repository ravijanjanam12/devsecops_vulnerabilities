##############################################################################
# INSECURE SAMPLE — for testing secagent only. DO NOT deploy this.
# Every block below contains at least one intentional security issue.
##############################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Issue: hardcoded cloud credentials in source (CWE-798).
provider "aws" {
  region     = "us-east-1"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

# Issue: security group opens SSH and all traffic to the entire internet.
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "web sg"

  ingress {
    description = "SSH from specific IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] # Example IP range
  }

  ingress {
    description = "HTTP and HTTPS"
    from_port   = 80
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] # Example IP range
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Issue: public-read S3 bucket, no encryption, no versioning.
resource "aws_s3_bucket" "data" {
  bucket = "my-company-super-secret-data"
  acl    = "private"
}

# Issue: RDS instance is publicly accessible, unencrypted, with a hardcoded
# password and no backups.
resource "aws_db_instance" "app" {
  identifier          = "app-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = var.db_password
  publicly_accessible = false
  storage_encrypted   = true
  skip_final_snapshot = true
}

# Issue: IAM policy grants full admin (*:* on all resources).
resource "aws_iam_policy" "admin" {
  name = "allow-everything"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:Describe*", "s3:ListBucket"]
        Resource = "*"
      }
    ]
  })
}

# Issue: unencrypted EBS volume.
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}

# Issue: CloudTrail with log file validation disabled and no encryption.
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.data.id
  enable_log_file_validation    = false
  include_global_service_events = false
}
