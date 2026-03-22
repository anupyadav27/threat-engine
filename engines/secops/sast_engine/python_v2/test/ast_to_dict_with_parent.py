import ast
import json

def ast_to_dict(node, parent=None):
    if isinstance(node, ast.AST):
        result = {'node_type': type(node).__name__}
        for field in node._fields:
            value = getattr(node, field)
            result[field] = ast_to_dict(value, result)
        result['__parent__'] = parent
        # Optionally add line/col info
        for attr in ['lineno', 'col_offset', 'end_lineno', 'end_col_offset']:
            if hasattr(node, attr):
                result[attr] = getattr(node, attr)
        return result
    elif isinstance(node, list):
        return [ast_to_dict(item, parent) for item in node]
    else:
        return node

if __name__ == "__main__":
    with open("d:/scanner/python_v2/test/test_bare_raise_in_finally.py", "r") as f:
        source = f.read()
    tree = ast.parse(source)
    ast_dict = ast_to_dict(tree)
    print(json.dumps(ast_dict, indent=2))
