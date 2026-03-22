import boto3

def upload_file_to_s3():
    # ❌ This line will trigger the rule: hardcoded AWS region
    s3 = boto3.client('s3', region_name='us-west-2')

    s3.upload_file('test.txt', 'mybucket', 'test.txt')
    print("File uploaded successfully.")

upload_file_to_s3()
