import ast, pprint
with open('d:/scanner/python_v2/test/test_cancellation_scopes_should_contain_checkpoints_trigger.py', 'r') as f:
    tree = ast.parse(f.read())
    def ast_to_dict(node):
        result = {'node_type': type(node).__name__}
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                result[field] = [ast_to_dict(item) if isinstance(item, ast.AST) else item for item in value]
            elif isinstance(value, ast.AST):
                result[field] = ast_to_dict(value)
            else:
                result[field] = value
        return result
    pprint.pprint(ast_to_dict(tree), width=120)
