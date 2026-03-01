def logging_basicConfig_debug_check(node, ast_root=None):
    """
    Returns True if node is a Call to logging.basicConfig with level=logging.DEBUG.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    # Check for basicConfig function
    if func.get('attr') != 'basicConfig':
        return False
    value = func.get('value', {})
    if value.get('id') != 'logging':
        return False
    # Check for level=logging.DEBUG in keywords
    for kw in node.get('keywords', []):
        if kw.get('arg') == 'level':
            val = kw.get('value', {})
            # logging.DEBUG is Attribute node with attr 'DEBUG' and value id 'logging'
            if val.get('node_type') == 'Attribute' and val.get('attr') == 'DEBUG':
                val_value = val.get('value', {})
                if val_value.get('id') == 'logging':
                    return True
    return False
