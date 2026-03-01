# Test file to trigger rule:
# Using unencrypted SNS topics is security-sensitive

provider "aws" {
  region = "us-east-1"
}

# ❌ Noncompliant: SNS topic without encryption (no kms_master_key_id)
resource "aws_sns_topic" "unencrypted_topic" {
  name = "unencrypted-topic"  # Should trigger
}

# ❌ Another noncompliant example: explicitly empty KMS key
resource "aws_sns_topic" "unencrypted_topic_explicit" {
  name             = "unencrypted-topic-explicit"
  kms_master_key_id = ""  # Should also trigger
}

resource "aws_sqs_queue" "unencrypted_queue" {
  name = "unencrypted-queue"
  # No kms_master_key_id means unencrypted
}
