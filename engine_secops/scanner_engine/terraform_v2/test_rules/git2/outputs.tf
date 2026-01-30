output "dns_zone_id" {
  description = "The ID of the DNS managed zone."
  value       = google_dns_managed_zone.bad_example.id
}
output "bucket_arn" {
  description = "The ARN of the S3 bucket."
  value       = aws_s3_bucket.public_bucket.arn
}

output "bucket_name" {
  description = "The name of the S3 bucket."
  value       = aws_s3_bucket.public_bucket.bucket
}
