# Output exposing a secret (should trigger output secret rule)
output "db_password" {
	value = var.db_password
	description = "Exposes DB password (should trigger secret output rule)"
}
# Output with TODO comment (should trigger TODO rule)
output "bucket_name" {
	value = aws_s3_bucket.public_bucket.bucket # TODO: check if this should be public
}
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Output declarations
