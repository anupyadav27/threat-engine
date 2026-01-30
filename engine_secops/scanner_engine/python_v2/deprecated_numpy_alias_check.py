def deprecated_numpy_alias_check(node, ast_root=None):
    """
    Returns True if node is a Call to np.array with dtype set to a forbidden built-in alias (int, float, str, bool, complex).
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    # Check for np.array call
    if func.get('attr') != 'array':
        return False
    value = func.get('value', {})
    if value.get('id') != 'np':
        return False
    forbidden = {"int", "float", "str", "bool", "complex"}
    for kw in node.get('keywords', []):
        if kw.get('arg') == 'dtype':
            val = kw.get('value', {})
            # For Constant node: value is under 'value'
            if val.get('node_type') == 'Constant' and val.get('value') in forbidden:
                return True
            # For Str node: value is under 's'
            if val.get('node_type') == 'Str' and val.get('s') in forbidden:
                return True
            # For direct string
            if isinstance(val, str) and val in forbidden:
                return True
    return False
