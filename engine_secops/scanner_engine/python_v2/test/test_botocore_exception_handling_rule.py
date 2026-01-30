# Test script to trigger only the botocoreexceptionsclienterror_must_be_explicitly_catch_and_handled rule
import boto3

def test_no_exception_handling():
    s3 = boto3.client('s3')
    s3.get_object(Bucket='mybucket', Key='myobject')  # Should trigger: no exception handling

def test_with_exception_handling():
    s3 = boto3.client('s3')
    try:
        s3.get_object(Bucket='mybucket', Key='myobject')  # Should NOT trigger: handled
    except Exception as e:
        print(e)

if __name__ == "__main__":
    test_no_exception_handling()
    test_with_exception_handling()
