import ast

def dictcomp_static_key_check(node):
    """Return True if a DictComp uses a static key (Constant node)."""
    if isinstance(node, ast.DictComp):
        # If key is ast.Constant, it's static
        return isinstance(node.key, ast.Constant)
    return False
