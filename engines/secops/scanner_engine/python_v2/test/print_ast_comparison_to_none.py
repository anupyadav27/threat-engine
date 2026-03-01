import ast

code = """
if x != None:
    pass
if x is not None:
    pass
"""

tree = ast.parse(code)
print(ast.dump(tree, indent=2))
