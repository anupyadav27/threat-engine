import ast
import pprint

with open("d:/scanner/python_v2/test/test_aws_region_hardcoded.py", "r", encoding="utf-8") as f:
    source = f.read()

tree = ast.parse(source, filename="test_aws_region_hardcoded.py")

def ast_to_dict(node):
    result = {
        'node_type': type(node).__name__,
        'lineno': getattr(node, 'lineno', None),
        'end_lineno': getattr(node, 'end_lineno', None),
        'col_offset': getattr(node, 'col_offset', None),
    }
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            result[field] = [ast_to_dict(item) if isinstance(item, ast.AST) else item for item in value]
        elif isinstance(value, ast.AST):
            result[field] = ast_to_dict(value)
        else:
            result[field] = value
    return result

ast_dict = ast_to_dict(tree)
pprint.pprint(ast_dict, width=120, compact=True)
