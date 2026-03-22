def allowing_public_s3_access_check(node):
    if node.get('node_type') != 'Call':
        return False
    
    # Check function name
    func = node.get('func', {})
    if func.get('node_type') == 'Attribute':
        method_name = func.get('attr')
        if method_name == 'put_bucket_acl':
            # Check ACL parameter
            keywords = node.get('keywords', [])
            for kw in keywords:
                if kw.get('arg') == 'ACL' and isinstance(kw.get('value'), dict):
                    value = kw.get('value', {}).get('value')
                    if value in ['public-read', 'public-read-write']:
                        return True
        elif method_name == 'put_bucket_policy':
            # Check Policy parameter for public access
            keywords = node.get('keywords', [])
            for kw in keywords:
                if kw.get('arg') == 'Policy' and isinstance(kw.get('value'), dict):
                    value = kw.get('value', {}).get('value')
                    if isinstance(value, str) and '*' in value and 'Principal' in value:
                        return True
    
    return False