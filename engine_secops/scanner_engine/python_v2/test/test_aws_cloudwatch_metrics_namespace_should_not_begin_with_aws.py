"""
Test for aws_cloudwatch_metrics_namespace_should_not_begin_with_aws rule
This test triggers the rule by using Namespace='aws.example' in a function call.
"""

def bad_namespace():
    aws.put_metric_data(Namespace='aws.example', Value=123)

# Compliant example (should NOT trigger the rule)
def good_namespace():
    my_prefix.put_metric_data(Namespace='my_prefix.example', Value=123)
