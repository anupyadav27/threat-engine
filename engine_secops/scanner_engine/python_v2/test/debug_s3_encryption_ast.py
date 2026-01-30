import ast
import pprint

with open("d:/scanner/python_v2/test/test_trigger_s3_encryption_rule.py", "r") as f:
    tree = ast.parse(f.read(), filename="test_trigger_s3_encryption_rule.py")

for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        print(f"Call node at line {node.lineno}:")
        pprint.pprint(ast.dump(node, indent=2))
