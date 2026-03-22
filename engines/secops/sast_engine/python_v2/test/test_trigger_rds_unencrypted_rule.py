# Test to trigger using_unencrypted_rds_db_resources_is_securitysensitive rule

import boto3

client = boto3.client('rds')
response = client.describe_db_instances()
