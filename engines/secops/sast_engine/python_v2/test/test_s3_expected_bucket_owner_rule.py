import boto3

def delete_s3_object(bucket_name, key):
    s3 = boto3.resource('s3')
    # Noncompliant: Missing ExpectedBucketOwner parameter
    s3.Bucket(bucket_name).Object(key).delete()

if __name__ == "__main__":
    delete_s3_object("my-bucket", "my-key")
