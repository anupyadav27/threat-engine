"""
Test for: reusable_resources_should_be_initialized_at_construction_time_of_lambda_functions
This script is designed to trigger the rule by initializing resources inside the lambda handler.
"""

import boto3

def lambda_handler(event, context):
    # Noncompliant: AWS resources initialized inside the handler
    if event:
        # Initialize resource inside handler
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('my-table')
        
        # Another resource initialized conditionally
        if event.get('use_s3'):
            s3 = boto3.client('s3')
            bucket = s3.create_bucket(Bucket='my-bucket')
    
    return {"statusCode": 200}
