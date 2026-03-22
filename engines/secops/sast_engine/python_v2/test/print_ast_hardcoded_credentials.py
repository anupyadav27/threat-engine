import ast

with open('d:/scanner/python_v2/test/test_hardcoded_credentials_trigger.py', 'r', encoding='utf-8') as f:
    source = f.read()

parsed = ast.parse(source)
print(ast.dump(parsed, indent=4))
