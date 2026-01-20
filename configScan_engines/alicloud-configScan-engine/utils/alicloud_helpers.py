"""
AliCloud Helper Utilities

Provides helper functions for AliCloud SDK operations.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest

logger = logging.getLogger('alicloud-helpers')


def make_api_call(
    client: AcsClient,
    product: str,
    version: str,
    action: str,
    params: Optional[Dict[str, Any]] = None,
    method: str = 'POST'
) -> Dict[str, Any]:
    """
    Make a generic API call to any AliCloud service
    
    Args:
        client: AliCloud client
        product: Product/service name (e.g., 'Ecs', 'Rds')
        version: API version (e.g., '2014-05-26')
        action: API action (e.g., 'DescribeInstances')
        params: Request parameters
        method: HTTP method (GET or POST)
        
    Returns:
        API response as dictionary
    """
    request = CommonRequest()
    request.set_accept_format('json')
    request.set_domain(f'{product.lower()}.aliyuncs.com')
    request.set_method(method)
    request.set_protocol_type('https')
    request.set_version(version)
    request.set_action_name(action)
    
    if params:
        for key, value in params.items():
            request.add_query_param(key, value)
    
    try:
        response = client.do_action_with_exception(request)
        return json.loads(response)
    except Exception as e:
        logger.error(f"API call failed: {product}.{action} - {e}")
        raise


def paginate_results(
    client: AcsClient,
    product: str,
    version: str,
    action: str,
    params: Optional[Dict[str, Any]] = None,
    page_size: int = 50,
    max_pages: int = 100
) -> List[Dict[str, Any]]:
    """
    Paginate through API results
    
    Args:
        client: AliCloud client
        product: Product/service name
        version: API version
        action: API action
        params: Request parameters
        page_size: Number of items per page
        max_pages: Maximum number of pages to retrieve
        
    Returns:
        List of all items
    """
    all_items = []
    page_number = 1
    
    if params is None:
        params = {}
    
    while page_number <= max_pages:
        params['PageSize'] = page_size
        params['PageNumber'] = page_number
        
        try:
            response = make_api_call(client, product, version, action, params)
            
            # Different services use different result keys
            # Try common patterns
            items = None
            for key in ['Instances', 'Buckets', 'DBInstances', 'LoadBalancers', 'Items']:
                if key in response:
                    items = response[key].get(key[:-1] if key.endswith('s') else key, [])
                    if isinstance(items, list):
                        break
            
            if items is None:
                # No more items
                break
            
            all_items.extend(items)
            
            # Check if there are more pages
            total_count = response.get('TotalCount', 0)
            if len(all_items) >= total_count or len(items) < page_size:
                break
            
            page_number += 1
            
        except Exception as e:
            logger.warning(f"Pagination stopped at page {page_number}: {e}")
            break
    
    return all_items


def extract_value(obj: Any, path: str) -> Any:
    """
    Extract value from nested object using dot notation
    
    Args:
        obj: Object to extract from
        path: Dot-notation path (e.g., 'Instance.Status')
        
    Returns:
        Extracted value or None
    """
    if obj is None:
        return None
    
    parts = path.split('.')
    current = obj
    
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
            if current is None:
                return None
        elif isinstance(current, list):
            # Handle array notation
            if part.isdigit():
                index = int(part)
                if 0 <= index < len(current):
                    current = current[index]
                else:
                    return None
            else:
                # Collect from all items
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


def build_arn(
    service: str,
    region: str,
    account_id: str,
    resource_type: str,
    resource_id: str
) -> str:
    """
    Build AliCloud ARN-like resource identifier
    
    Args:
        service: Service name
        region: Region ID
        account_id: Account ID
        resource_type: Resource type
        resource_id: Resource ID
        
    Returns:
        ARN string
    """
    return f"acs:{service}:{region}:{account_id}:{resource_type}/{resource_id}"


def get_regions(client: AcsClient) -> List[str]:
    """
    Get list of available regions
    
    Args:
        client: AliCloud client
        
    Returns:
        List of region IDs
    """
    try:
        response = make_api_call(
            client,
            'Ecs',
            '2014-05-26',
            'DescribeRegions',
            {}
        )
        regions = response.get('Regions', {}).get('Region', [])
        return [r.get('RegionId') for r in regions if r.get('RegionId')]
    except Exception as e:
        logger.warning(f"Failed to fetch regions: {e}")
        # Return common regions as fallback
        return [
            'cn-hangzhou',
            'cn-shanghai',
            'cn-beijing',
            'cn-shenzhen',
            'ap-southeast-1'
        ]

