import boto3

def bad_namespace():
    # This should trigger the rule: Namespace starts with 'aws'
    boto3.client('cloudwatch').put_metric_data(Namespace='aws.example', Value=123)

def good_namespace():
    # This should NOT trigger the rule: Namespace does not start with 'aws'
    boto3.client('cloudwatch').put_metric_data(Namespace='my_prefix.example', Value=123)

if __name__ == "__main__":
    bad_namespace()
    good_namespace()
