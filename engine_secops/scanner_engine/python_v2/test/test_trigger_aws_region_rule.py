import json
from python_v2.python_generic_rule import PythonGenericRule

# Load the rule metadata for aws_region_should_not_be_set_with_a_hardcoded_string
with open('../python_docs/aws_region_should_not_be_set_with_a_hardcoded_string_metadata.json', 'r') as f:
    metadata = json.load(f)

# AST simulating a hardcoded AWS region
example_ast = {
    'node_type': 'Call',
    'func': {'name': 'client'},
    'keywords': [
        {'arg': 'region_name', 'value': {'node_type': 'Constant', 'value': 'us-west-2'}}
    ],
    'lineno': 1,
    'col_offset': 0,
    'source_lines': ["s3 = boto3.client('s3', region_name='us-west-2')"]
}

rule = PythonGenericRule(metadata)
findings = rule.check(example_ast, filename='example.py')
if not findings:
    print("[DEBUG] No findings returned by rule.")
else:
    print("[DEBUG] Findings returned by rule:")
    for finding in findings:
        print(finding)
