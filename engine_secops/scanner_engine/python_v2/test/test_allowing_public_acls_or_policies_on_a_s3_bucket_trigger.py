# Test to trigger 'allowing_public_acls_or_policies_on_a_s3_bucket_is_securitysensitive'

import boto3

s3 = boto3.client('s3')

# Noncompliant: public ACL
s3.put_bucket_acl(Bucket='my-bucket', ACL='public-read')

# Noncompliant: public policy
s3.put_bucket_policy(Bucket='my-bucket', Policy='{"Statement": [{"Effect": "Allow", "Principal": "*"}]}')

# Compliant: private ACL
s3.put_bucket_acl(Bucket='my-bucket', ACL='private')

# Compliant: restricted policy
s3.put_bucket_policy(Bucket='my-bucket', Policy='{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/SpecificUser"}}]}')
