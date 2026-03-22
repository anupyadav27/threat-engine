# Test script to trigger aws_region_should_not_be_set_with_a_hardcoded_string rule
import boto3

def create_client():
    # Hardcoded AWS region (should trigger the rule)
    client = boto3.client('s3', region_name='us-west-2')
    return client

if __name__ == "__main__":
    s3 = create_client()
    print(s3)
