# Mega Test Terraform File
# This intentionally contains insecure configurations to trigger many rules.

provider "aws" {
  region = "us-east-1"
}

# ❌ S3 bucket with public ACL and no logging
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-bad-bucket"
  acl    = "public-read"   # Should trigger: public ACLs

  versioning {
    enabled    = true
    mfa_delete = false     # Should trigger: MFA delete disabled
  }
  # No logging block => Should trigger: missing logging
}

# ❌ Another S3 bucket without encryption
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "unencrypted-bucket"
  acl    = "private"
  # No server_side_encryption_configuration => should trigger
}

# ❌ Security group open to world
resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Open to the world"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Should trigger: unrestricted SSH
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Should trigger: unrestricted RDP
  }
}

# ❌ RDS instance without encryption
resource "aws_db_instance" "unencrypted_db" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = "default.mysql5.7"
  # Missing: storage_encrypted = true
}

# ❌ IAM user with access keys hardcoded
resource "aws_iam_user" "bad_user" {
  name = "bad-user"
}

resource "aws_iam_access_key" "bad_key" {
  user    = aws_iam_user.bad_user.name
  pgp_key = "bad-pgp-key"
  # Hardcoding access keys will trigger sensitive info rules
}

# ❌ SNS topic without KMS encryption
resource "aws_sns_topic" "unencrypted_topic" {
  name = "unencrypted-topic"
  # Missing kms_master_key_id => Should trigger unencrypted SNS
}

# ❌ CloudWatch log group without encryption
resource "aws_cloudwatch_log_group" "unencrypted_logs" {
  name              = "unencrypted-logs"
  retention_in_days = 7
  # Missing kms_key_id => Should trigger unencrypted log group
}
