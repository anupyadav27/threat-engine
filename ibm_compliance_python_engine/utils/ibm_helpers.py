"""
IBM Cloud Helper Utilities

Provides helper functions for IBM Cloud SDK operations.
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import re

logger = logging.getLogger('ibm-helpers')


def extract_value(obj: Any, path: str) -> Any:
    """
    Extract value from nested object using dot notation
    
    Args:
        obj: Object to extract from (dict, object, or list)
        path: Dot-notation path (e.g., 'mfa_traits.mfa_enabled')
        
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
                    val = extract_value(item, '.'.join(parts[parts.index(part):]))
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
    
    def replace_var(match):
        var_path = match.group(1).strip()
        value = extract_value(context, var_path)
        return str(value) if value is not None else ''
    
    resolved = re.sub(r'\{\{\s*([^}]+)\s*\}\}', replace_var, text)
    
    # Try to convert to appropriate type
    if resolved.isdigit():
        return int(resolved)
    elif resolved.replace('.', '', 1).replace('-', '', 1).isdigit():
        try:
            return float(resolved)
        except:
            return resolved
    elif resolved.lower() in ('true', 'false'):
        return resolved.lower() == 'true'
    
    return resolved


def ibm_response_to_dict(obj: Any) -> Dict[str, Any]:
    """
    Convert IBM Cloud SDK response object to dictionary
    
    Args:
        obj: IBM SDK response object
        
    Returns:
        Dictionary representation
    """
    if obj is None:
        return {}
    
    if isinstance(obj, dict):
        return obj
    
    if isinstance(obj, list):
        return [ibm_response_to_dict(item) for item in obj]
    
    # Handle IBM SDK DetailedResponse
    if hasattr(obj, 'get_result'):
        return ibm_response_to_dict(obj.get_result())
    
    # Handle objects with to_dict method
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    
    # Handle objects with __dict__
    if hasattr(obj, '__dict__'):
        result = {}
        for key, value in obj.__dict__.items():
            if not key.startswith('_'):
                if isinstance(value, (str, int, float, bool, type(None))):
                    result[key] = value
                elif isinstance(value, list):
                    result[key] = [ibm_response_to_dict(item) for item in value]
                elif hasattr(value, '__dict__'):
                    result[key] = ibm_response_to_dict(value)
                else:
                    result[key] = str(value)
        return result
    
    return str(obj)


def evaluate_condition(value: Any, operator: str, expected: Any) -> bool:
    """
    Evaluate a condition based on operator
    
    Args:
        value: Actual value from resource
        operator: Comparison operator
        expected: Expected value
        
    Returns:
        True if condition passes, False otherwise
    """
    try:
        if operator == 'exists':
            return value is not None and value != '' and value != []
        
        elif operator == 'not_exists':
            return value is None or value == '' or value == []
        
        elif operator == 'equals':
            return value == expected
        
        elif operator == 'not_equals':
            return value != expected
        
        elif operator == 'contains':
            if isinstance(value, (list, tuple)):
                return expected in value
            elif isinstance(value, str):
                return str(expected) in value
            return False
        
        elif operator == 'not_contains':
            if isinstance(value, (list, tuple)):
                return expected not in value
            elif isinstance(value, str):
                return str(expected) not in value
            return True
        
        elif operator == 'in':
            if isinstance(expected, (list, tuple)):
                return value in expected
            return False
        
        elif operator == 'not_in':
            if isinstance(expected, (list, tuple)):
                return value not in expected
            return True
        
        elif operator == 'greater_than':
            return float(value) > float(expected)
        
        elif operator == 'less_than':
            return float(value) < float(expected)
        
        elif operator == 'greater_equal':
            return float(value) >= float(expected)
        
        elif operator == 'less_equal':
            return float(value) <= float(expected)
        
        elif operator == 'age_days':
            # Check if resource is older than X days
            if isinstance(value, str):
                try:
                    created_date = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    age = (datetime.now(timezone.utc) - created_date).days
                    return age > int(expected)
                except:
                    return False
            return False
        
        elif operator == 'not_expired':
            # Check if date is not in the past
            if isinstance(value, str):
                try:
                    expiration_date = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    return expiration_date > datetime.now(timezone.utc)
                except:
                    return False
            return False
        
        elif operator == 'regex':
            if isinstance(value, str):
                return bool(re.match(str(expected), value))
            return False
        
        elif operator == 'not_regex':
            if isinstance(value, str):
                return not bool(re.match(str(expected), value))
            return True
        
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False
            
    except Exception as e:
        logger.error(f"Error evaluating condition: {e}")
        return False


def paginate_list_call(list_func, **kwargs) -> List[Any]:
    """
    Paginate through IBM Cloud list results
    
    Args:
        list_func: IBM Cloud list function
        **kwargs: Function parameters
        
    Returns:
        List of all items
    """
    all_items = []
    offset = 0
    limit = kwargs.get('limit', 100)
    
    while True:
        try:
            kwargs['offset'] = offset
            kwargs['limit'] = limit
            
            response = list_func(**kwargs)
            
            # Handle DetailedResponse
            if hasattr(response, 'get_result'):
                result = response.get_result()
            else:
                result = response
            
            # Extract items from response
            if isinstance(result, dict):
                # Try common IBM Cloud response patterns
                items = (result.get('resources') or 
                        result.get('items') or 
                        result.get('results') or
                        result.get('data') or
                        [])
            elif isinstance(result, list):
                items = result
            else:
                items = []
            
            if not items:
                break
            
            all_items.extend(items)
            
            # Check if there are more pages
            if len(items) < limit:
                break
            
            offset += limit
            
        except Exception as e:
            logger.warning(f"Pagination stopped: {e}")
            break
    
    return all_items


def get_resource_crn(resource: Dict[str, Any]) -> Optional[str]:
    """
    Extract Cloud Resource Name (CRN) from resource
    
    Args:
        resource: IBM Cloud resource
        
    Returns:
        CRN string or None
    """
    if isinstance(resource, dict):
        return resource.get('crn') or resource.get('resource_crn')
    elif hasattr(resource, 'crn'):
        return resource.crn
    elif hasattr(resource, 'resource_crn'):
        return resource.resource_crn
    return None


def parse_crn(crn: str) -> Dict[str, str]:
    """
    Parse IBM Cloud Resource Name (CRN)
    
    Format: crn:version:cname:ctype:service-name:location:scope:service-instance:resource-type:resource
    
    Args:
        crn: Cloud Resource Name
        
    Returns:
        Dictionary with CRN components
    """
    if not crn or not crn.startswith('crn:'):
        return {}
    
    parts = crn.split(':')
    
    return {
        'crn': crn,
        'version': parts[1] if len(parts) > 1 else '',
        'cname': parts[2] if len(parts) > 2 else '',
        'ctype': parts[3] if len(parts) > 3 else '',
        'service_name': parts[4] if len(parts) > 4 else '',
        'location': parts[5] if len(parts) > 5 else '',
        'scope': parts[6] if len(parts) > 6 else '',
        'service_instance': parts[7] if len(parts) > 7 else '',
        'resource_type': parts[8] if len(parts) > 8 else '',
        'resource': parts[9] if len(parts) > 9 else '',
    }


def format_timestamp(ts: Any) -> str:
    """
    Format timestamp to ISO 8601 string
    
    Args:
        ts: Timestamp (datetime object, string, or int)
        
    Returns:
        ISO 8601 formatted string
    """
    if isinstance(ts, datetime):
        return ts.isoformat() + 'Z'
    elif isinstance(ts, str):
        return ts
    elif isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() + 'Z'
    return str(ts)
