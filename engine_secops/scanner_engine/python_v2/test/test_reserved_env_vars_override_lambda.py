# Test for: reserved_environment_variable_names_should_not_be_overridden_in_lambda_functions
import os

def lambda_handler(event, context):
    # Noncompliant: Overriding reserved AWS environment variable
    os.environ['AWS_REGION'] = 'custom_region'  # Should trigger the rule
    os.environ['AWS_ACCESS_KEY_ID'] = 'dummy_key'  # Should trigger the rule
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'dummy_secret'  # Should trigger the rule
    # Compliant: Using non-reserved environment variable
    os.environ['CUSTOM_VAR'] = 'custom_value'  # Should NOT trigger the rule
    # Compliant: Reading reserved variable, not overriding
    print(os.environ['AWS_REGION'])
