import boto3

def trigger_s3_encryption_rule():
    s3_client = boto3.client('s3')
    # Noncompliant: No Encryption in CreateBucketConfiguration
    s3_client.create_bucket(
        Bucket='my-bucket',
        CreateBucketConfiguration={
            'LocationConstraint': 'us-west-2'
        }
    )

if __name__ == "__main__":
    trigger_s3_encryption_rule()
