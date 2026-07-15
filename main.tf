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
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Issue: security group opens SSH and all traffic to the entire internet.
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "web sg"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "All ports open"
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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
  acl    = "public-read"
}

# Issue: RDS instance is publicly accessible, unencrypted, with a hardcoded
# password and no backups.
resource "aws_db_instance" "app" {
  identifier          = "app-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "SuperSecret123!"
  publicly_accessible = true
  storage_encrypted   = false
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
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Issue: unencrypted EBS volume.
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# Issue: CloudTrail with log file validation disabled and no encryption.
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.data.id
  enable_log_file_validation    = false
  include_global_service_events = false
}
