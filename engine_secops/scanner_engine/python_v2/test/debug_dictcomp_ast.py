import ast
import pprint

code = """
result = {42: value for value in range(5)}
result2 = {key: value for key, value in enumerate(range(5))}
"""
tree = ast.parse(code)
for node in ast.walk(tree):
    if isinstance(node, ast.DictComp):
        print("Raw AST node:")
        pprint.pprint(ast.dump(node, indent=2))
        print("\nAST as dict:")
        pprint.pprint(node.__dict__)
