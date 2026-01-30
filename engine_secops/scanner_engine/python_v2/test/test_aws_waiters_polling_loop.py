"""
Test script to trigger aws_waiters_should_be_used_instead_of_custom_polling_loops rule
"""
import boto3
import time

def poll_for_object():
    while True:
        response = boto3.client('s3').head_object(Bucket='my_bucket', Key='my_key')
        if response.get('ResponseMetadata', {}).get('HTTPHeaders', {}).get('x-amz-request-id') != '12345':
            break
        time.sleep(5)

if __name__ == "__main__":
    poll_for_object()
