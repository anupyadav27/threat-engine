import ast
from python_v2.logic_implementations import is_unnecessary_equality_check

test_code = '''
def foo(x):
    if x == 1 or x == 2 or x == 3:
        print("triggered")
'''

tree = ast.parse(test_code)

def find_boolop_nodes(node):
    results = []
    for child in ast.walk(node):
        if isinstance(child, ast.BoolOp):
            # Convert AST node to dict format expected by is_unnecessary_equality_check
            node_dict = ast_to_dict(child)
            if is_unnecessary_equality_check(node_dict):
                results.append(child)
    return results

def ast_to_dict(node):
    # Minimal AST to dict conversion for BoolOp and Compare nodes
    if isinstance(node, ast.BoolOp):
        return {
            'node_type': 'BoolOp',
            'op': {'node_type': type(node.op).__name__},
            'values': [ast_to_dict(v) for v in node.values]
        }
    if isinstance(node, ast.Compare):
        return {
            'node_type': 'Compare',
            'left': ast_to_dict(node.left),
            'ops': [{'node_type': type(op).__name__} for op in node.ops],
            'comparators': [ast_to_dict(c) for c in node.comparators]
        }
    if isinstance(node, ast.Name):
        return {'node_type': 'Name', 'id': node.id}
    if isinstance(node, ast.Constant):
        return {'node_type': 'Constant', 'value': node.value}
    return {}

if __name__ == "__main__":
    matches = find_boolop_nodes(tree)
    print(f"Found {len(matches)} unnecessary equality check(s).")
    for match in matches:
        print(f"Line: {match.lineno}")
