import ast
import pprint

with open('d:/scanner/python_v2/test/test_trigger_boolean_expressions_in_except.py', 'r', encoding='utf-8') as f:
    tree = ast.parse(f.read(), filename='test_trigger_boolean_expressions_in_except.py')

def print_except_handlers(node):
    for child in ast.walk(node):
        if isinstance(child, ast.ExceptHandler):
            print('--- ExceptHandler Node ---')
            pprint.pprint(ast.dump(child, annotate_fields=True, include_attributes=True))

print_except_handlers(tree)
