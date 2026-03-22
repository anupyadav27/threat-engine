resource "google_dns_managed_zone" "bad_example" {
  name     = var.dns_zone_name
  dns_name = var.dns_domain_name
  dnssec_config {
    state = "off" # Should trigger DNSSEC rule
  }
}
provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = var.bucket_name
  acl    = var.bucket_acl
  tags = {
    Name        = var.bucket_name
    Environment = "Dev"
  }
}
