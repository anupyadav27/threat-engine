import boto3

def trigger_s3_versioning_rule():
    s3 = boto3.resource('s3')
    bucket_name = 'my-bucket'
    # Noncompliant: Versioning is suspended
    s3.Bucket(bucket_name).versioning.VersioningConfiguration(versioning_configuration={'Status': 'Suspended'})

if __name__ == "__main__":
    trigger_s3_versioning_rule()
