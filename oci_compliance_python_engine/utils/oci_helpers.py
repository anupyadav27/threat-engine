"""
OCI Helper Utilities

Provides helper functions for OCI SDK operations.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger('oci-helpers')


def extract_value(obj: Any, path: str) -> Any:
    """
    Extract value from nested object using dot notation
    
    Args:
        obj: Object to extract from
        path: Dot-notation path (e.g., 'display_name')
        
    Returns:
        Extracted value or None
    """
    if obj is None:
        return None
    
    parts = path.split('.')
    current = obj
    
    for part in parts:
        if hasattr(current, part):
            current = getattr(current, part)
        elif isinstance(current, dict):
            current = current.get(part)
            if current is None:
                return None
        elif isinstance(current, list):
            if part.isdigit():
                index = int(part)
                if 0 <= index < len(current):
                    current = current[index]
                else:
                    return None
            else:
                result = []
                for item in current:
                    val = extract_value(item, part)
                    if val is not None:
                        result.append(val)
                return result if result else None
        else:
            return None
    
    return current


def resolve_template(text: str, context: Dict[str, Any]) -> Any:
    """
    Resolve template variables like {{ variable }}
    
    Args:
        text: Template string
        context: Context dictionary with variable values
        
    Returns:
        Resolved value
    """
    if not isinstance(text, str) or '{{' not in text:
        return text
    
    import re
    
    def replace_var(match):
        var_path = match.group(1).strip()
        value = extract_value(context, var_path)
        return str(value) if value is not None else ''
    
    resolved = re.sub(r'\{\{\s*([^}]+)\s*\}\}', replace_var, text)
    
    # Try to convert to appropriate type
    if resolved.isdigit():
        return int(resolved)
    elif resolved.replace('.', '', 1).isdigit():
        return float(resolved)
    elif resolved.lower() in ('true', 'false'):
        return resolved.lower() == 'true'
    
    return resolved


def paginate_list_call(list_func, **kwargs) -> List[Any]:
    """
    Paginate through OCI list results
    
    Args:
        list_func: OCI list function
        **kwargs: Function parameters
        
    Returns:
        List of all items
    """
    all_items = []
    page = None
    
    while True:
        if page:
            kwargs['page'] = page
        
        try:
            response = list_func(**kwargs)
            all_items.extend(response.data)
            
            if not response.has_next_page:
                break
            
            page = response.next_page
            
        except Exception as e:
            logger.warning(f"Pagination stopped: {e}")
            break
    
    return all_items


def oci_response_to_dict(obj: Any) -> Dict[str, Any]:
    """
    Convert OCI response object to dictionary
    
    Args:
        obj: OCI response object
        
    Returns:
        Dictionary representation
    """
    if obj is None:
        return {}
    
    if isinstance(obj, dict):
        return obj
    
    if isinstance(obj, list):
        return [oci_response_to_dict(item) for item in obj]
    
    if hasattr(obj, '__dict__'):
        result = {}
        for key, value in obj.__dict__.items():
            if not key.startswith('_'):
                if isinstance(value, (str, int, float, bool, type(None))):
                    result[key] = value
                elif isinstance(value, list):
                    result[key] = [oci_response_to_dict(item) for item in value]
                elif hasattr(value, '__dict__'):
                    result[key] = oci_response_to_dict(value)
                else:
                    result[key] = str(value)
        return result
    
    return str(obj)

