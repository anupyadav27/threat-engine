# Test script to trigger only the boto3 pagination rule
import boto3

def test_list_buckets_without_paginator():
    s3 = boto3.client('s3')
    response = s3.list_buckets()  # Should trigger: direct call to list_buckets
    print(response)

def test_list_buckets_with_paginator():
    s3 = boto3.client('s3')
    paginator = s3.get_paginator('list_buckets')
    for page in paginator.paginate():
        print(page)  # Should NOT trigger

if __name__ == "__main__":
    test_list_buckets_without_paginator()
    test_list_buckets_with_paginator()
