provider "aws" {
  region = "us-east-1"
}

# ❌ Noncompliant example (bad tag keys)
resource "aws_s3_bucket" "bad_tags" {
  bucket = "bad-tag-bucket"

  tags = {
    "Project Name" = "Test"      # contains space ❌
    "ENV"          = "dev"       # uppercase ❌
    "123project"   = "invalid"   # starts with number ❌
    "team@ops"     = "backend"   # special character ❌
  }
}

# ✅ Compliant example (good tag keys)
resource "aws_s3_bucket" "good_tags" {
  bucket = "good-tag-bucket"

  tags = {
    "project-name" = "test"      # lowercase, hyphen-separated ✅
    "env"          = "dev"       # lowercase ✅
    "team"         = "backend"   # lowercase ✅
  }
}
