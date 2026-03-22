import ast
import pprint

code = """
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def my_view(request):
    return 'Hello world'
"""
tree = ast.parse(code)
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
        print("Raw AST node:")
        pprint.pprint(ast.dump(node, indent=2))
        print("\nAST as dict:")
        pprint.pprint(node.__dict__)
