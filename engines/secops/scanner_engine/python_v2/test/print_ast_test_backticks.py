import ast

with open("d:/scanner/python_v2/test/test_backticks_should_not_be_used.py", "r") as f:
    source = f.read()

parsed = ast.parse(source)

print(ast.dump(parsed, indent=4))
