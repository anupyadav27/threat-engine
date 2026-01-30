variable "dns_zone_name" {
  description = "Name of the DNS zone."
  type        = string
  default     = "my-zone"
}

variable "dns_domain_name" {
  description = "Domain name for the DNS zone."
  type        = string
  default     = "example.com."
}
variable "bucket_name" {
  description = "Name of the S3 bucket."
  type        = string
  default     = "my-public-bucket"
}

variable "aws_region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "bucket_acl" {
  description = "ACL for the S3 bucket."
  type        = string
  default     = "public-read" # Should trigger public ACL rule
}
