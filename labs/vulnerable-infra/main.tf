# =============================================================================
# Intentionally Vulnerable AWS Infrastructure
# =============================================================================
# These resources contain deliberate security misconfigurations for
# demonstrating IaC scanning with Checkov. Each misconfiguration maps
# to a CIS AWS Benchmark control and a Checkov check ID.
#
# DO NOT deploy this infrastructure.
# =============================================================================


# --- CKV_AWS_18: S3 bucket without access logging ---
# --- CKV_AWS_19: S3 bucket without server-side encryption ---
# --- CKV_AWS_21: S3 bucket without versioning ---
# --- CKV_AWS_53: S3 bucket with public access not blocked ---
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-app-data-vulnerable"

  # MISSING: no server-side encryption
  # MISSING: no access logging
  # MISSING: no versioning
  # MISSING: no public access block
}

# An attacker can read/write data, no encryption at rest,
# no audit trail, and deleted data is gone forever.


# --- CKV_AWS_24: Security group allows ingress from 0.0.0.0/0 to port 22 ---
resource "aws_security_group" "vulnerable_sg" {
  name        = "allow-all-ssh"
  description = "SSH open to the entire internet"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: open to the world
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: unrestricted outbound
  }
}

# Anyone on the internet can attempt SSH brute force.
# Unrestricted egress allows data exfiltration.


# --- CKV_AWS_16: RDS instance without encryption ---
# --- CKV_AWS_17: RDS instance without audit logging ---
# --- CKV_AWS_157: RDS instance publicly accessible ---
resource "aws_db_instance" "vulnerable_db" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name              = "appdb"
  username             = "admin"
  password             = "SuperSecret123!"  # VULNERABLE: hardcoded password
  skip_final_snapshot  = true

  publicly_accessible    = true   # VULNERABLE: database reachable from internet
  storage_encrypted      = false  # VULNERABLE: data at rest not encrypted
  
  # MISSING: no enhanced monitoring
  # MISSING: no audit logging
  # MISSING: no multi-AZ for availability
}

# Database is on the public internet with a hardcoded password
# and no encryption. Triple threat.


# --- CKV_AWS_145: KMS key rotation disabled ---
resource "aws_kms_key" "vulnerable_key" {
  description         = "App encryption key"
  enable_key_rotation = false  # VULNERABLE: key never rotates
}

# Compromised key material remains valid indefinitely.


# --- CKV_AWS_8: Launch configuration with unencrypted EBS ---
resource "aws_launch_configuration" "vulnerable_lc" {
  image_id      = "ami-12345678"
  instance_type = "t3.micro"

  root_block_device {
    volume_size = 20
    encrypted   = false  # VULNERABLE: root volume not encrypted
  }

  # MISSING: no IMDSv2 requirement (metadata service v1 is SSRF target)
  metadata_options {
    http_tokens = "optional"  # VULNERABLE: IMDSv1 allowed (SSRF risk)
  }
}

# Unencrypted disk means data exposure if volume is snapshotted or
# instance is compromised. IMDSv1 is the classic SSRF target for
# stealing IAM credentials from the metadata service.


# --- CKV_AWS_23: EC2 security group with description "Managed by Terraform" ---
# --- CKV2_AWS_5: Security group not attached to any resource ---
resource "aws_security_group" "unused_sg" {
  name        = "unused-open-sg"
  description = "Managed by Terraform"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: all ports open
  }
}

# Orphaned security group with all ports open. If accidentally
# attached to a resource, entire attack surface is exposed.


# --- CKV_AWS_50: Lambda function without X-Ray tracing ---
# --- CKV_AWS_272: Lambda function without code signing ---
resource "aws_lambda_function" "vulnerable_lambda" {
  function_name = "data-processor"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  handler       = "index.handler"
  runtime       = "python3.11"
  filename      = "lambda.zip"

  # MISSING: no X-Ray tracing
  # MISSING: no code signing configuration
  # MISSING: no VPC configuration (runs outside VPC)
  # MISSING: no dead letter queue

  environment {
    variables = {
      API_KEY     = "sk_live_hardcoded_key_12345"  # VULNERABLE: secret in env
      DB_PASSWORD = "admin123"                      # VULNERABLE: secret in env
    }
  }
}

# Secrets in environment variables are visible in the Lambda console
# and CloudWatch logs. Use Secrets Manager or Parameter Store instead.
