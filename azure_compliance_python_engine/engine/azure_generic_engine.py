"""
Azure Generic Compliance Engine - Unified YAML-Driven Scanner

Hierarchy:
- Tenants → Management Groups → Subscriptions → Resource Groups → Regions → Services

Features:
- Generic YAML-driven (same format as GCP/AWS)
- Dynamic client creation
- Dynamic action parsing
- Supports all Azure SDK patterns (mgmt, data-plane, Graph API)
"""

import os
import json
import yaml
import logging
import importlib
from typing import Any, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import threading
import requests

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.managementgroups import ManagementGroupsAPI

# Configuration
MAX_WORKERS = int(os.getenv("COMPLIANCE_ENGINE_MAX_WORKERS", "16"))
REGION_MAX_WORKERS = int(os.getenv("COMPLIANCE_ENGINE_REGION_MAX_WORKERS", "8"))

# Filters
_SERVICE_FILTER: Set[str] = {s.strip() for s in os.getenv("AZURE_ENGINE_FILTER_SERVICES", "").split(",") if s.strip()}
_SUBSCRIPTION_FILTER: Set[str] = {s.strip() for s in os.getenv("AZURE_ENGINE_FILTER_SUBSCRIPTIONS", "").split(",") if s.strip()}
_REGION_FILTER: Set[str] = {s.strip() for s in os.getenv("AZURE_ENGINE_FILTER_REGIONS", "").split(",") if s.strip()}
_CHECK_ID_FILTER: Set[str] = {s.strip() for s in os.getenv("AZURE_ENGINE_FILTER_CHECK_IDS", "").split(",") if s.strip()}

# Setup logging
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, f"compliance_azure_generic.log")
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('azure-generic-engine')

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def serialize_azure_object(obj: Any) -> Any:
    """
    Serialize Azure SDK objects to JSON-compatible format
    
    Azure SDK objects have custom types that don't serialize well.
    This converts them to clean dictionaries.
    """
    if obj is None:
        return None
    
    # Handle datetime objects
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    
    # Handle Azure SDK model objects (have as_dict method)
    if hasattr(obj, 'as_dict'):
        try:
            return obj.as_dict()
        except:
            pass
    
    # Handle objects with __dict__
    if hasattr(obj, '__dict__') and not isinstance(obj, (str, int, float, bool)):
        try:
            # Get all public attributes
            result = {}
            for key, value in obj.__dict__.items():
                if not key.startswith('_'):
                    result[key] = serialize_azure_object(value)
            return result
        except:
            pass
    
    # Handle lists
    if isinstance(obj, list):
        return [serialize_azure_object(item) for item in obj]
    
    # Handle dicts
    if isinstance(obj, dict):
        return {k: serialize_azure_object(v) for k, v in obj.items()}
    
    # Handle primitive types
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    
    # Fallback: try to convert to string representation
    try:
        # For objects we can't serialize, just use their string name or id
        if hasattr(obj, 'name'):
            return str(obj.name)
        elif hasattr(obj, 'id'):
            return str(obj.id)
        else:
            return str(type(obj).__name__)
    except:
        return str(type(obj).__name__)


def extract_value(obj: Any, path: str):
    """Extract value from nested object using dot notation"""
    if obj is None:
        return None
    
    # Handle __self__ to return object itself
    if path == '__self__':
        return obj
    
    parts = path.split('.')
    current = obj
    
    for idx, part in enumerate(parts):
        # Handle lists
        if isinstance(current, list):
            result = []
            for item in current:
                sub = extract_value(item, '.'.join(parts[idx:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        
        # Handle array notation key[]
        if part.endswith('[]'):
            key = part[:-2]
            if isinstance(current, dict):
                arr = current.get(key, [])
            else:
                arr = getattr(current, key, [])
            
            if not isinstance(arr, list):
                arr = list(arr) if hasattr(arr, '__iter__') and not isinstance(arr, (str, bytes)) else []
            
            if not parts[idx+1:]:
                return arr
            
            result = []
            for item in arr:
                sub = extract_value(item, '.'.join(parts[idx+1:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        else:
            # Regular attribute/dict access
            if isinstance(current, dict):
                current = current.get(part)
            else:
                current = getattr(current, part, None)
            
            if current is None:
                return None
    
    return current


def evaluate_field(value: Any, operator: str, expected: Any = None) -> bool:
    """Evaluate field condition"""
    if operator == 'exists':
        return (value is not None and value != '' and value != []) if expected is None else (bool(value) == bool(expected))
    if operator == 'equals':
        return value == expected
    if operator == 'not_equals':
        return value != expected
    if operator == 'contains':
        if isinstance(value, list):
            return expected in value
        return str(expected) in (str(value) if value is not None else '')
    if operator == 'not_contains':
        if isinstance(value, list):
            return expected not in value
        return str(expected) not in (str(value) if value is not None else '')
    if operator == 'gt':
        return float(value) > float(expected) if value is not None else False
    if operator == 'gte':
        return float(value) >= float(expected) if value is not None else False
    if operator == 'lt':
        return float(value) < float(expected) if value is not None else False
    if operator == 'lte':
        return float(value) <= float(expected) if value is not None else False
    return False


def substitute_templates(text: str, context: Dict[str, Any]) -> str:
    """Replace {{variable}} templates with values from context"""
    if not isinstance(text, str) or '{{' not in text:
        return text
    
    import re
    pattern = r'\{\{(\w+)\}\}'
    
    def replacer(match):
        var_name = match.group(1)
        value = context.get(var_name)
        return str(value) if value is not None else ''
    
    return re.sub(pattern, replacer, text)


# ============================================================================
# AZURE DISCOVERY - HIERARCHY
# ============================================================================

def get_default_credential():
    """Get Azure credential"""
    return DefaultAzureCredential(exclude_visual_studio_code_credential=False)


def discover_subscriptions(credential) -> List[Dict[str, str]]:
    """Discover all subscriptions"""
    env_subs = os.getenv('SCAN_SUBSCRIPTIONS')
    if env_subs:
        subs = [s.strip() for s in env_subs.split(',') if s.strip()]
        return [{'id': s, 'name': s} for s in subs]
    
    client = SubscriptionClient(credential)
    subscriptions = []
    
    try:
        for sub in client.subscriptions.list():
            if hasattr(sub, 'subscription_id') and hasattr(sub, 'display_name'):
                subscriptions.append({
                    'id': sub.subscription_id,
                    'name': sub.display_name or sub.subscription_id
                })
    except Exception as e:
        logger.warning(f"Failed to list subscriptions: {e}")
    
    if _SUBSCRIPTION_FILTER:
        subscriptions = [s for s in subscriptions if s['id'] in _SUBSCRIPTION_FILTER]
    
    return subscriptions


def discover_regions(credential, subscription_id: str) -> List[str]:
    """Discover all regions for a subscription"""
    client = SubscriptionClient(credential)
    regions = []
    
    try:
        locs = client.subscriptions.list_locations(subscription_id)
        for loc in locs:
            if hasattr(loc, 'name') and loc.name:
                regions.append(loc.name)
    except Exception as e:
        logger.warning(f"Failed to list regions for subscription {subscription_id}: {e}")
        regions = ['eastus', 'westus', 'centralus']  # Fallback
    
    if _REGION_FILTER:
        regions = [r for r in regions if r in _REGION_FILTER]
    
    return regions


def discover_resource_groups(credential, subscription_id: str) -> List[str]:
    """Discover all resource groups in a subscription"""
    try:
        client = ResourceManagementClient(credential, subscription_id)
        return [rg.name for rg in client.resource_groups.list()]
    except Exception as e:
        logger.warning(f"Failed to list resource groups for {subscription_id}: {e}")
        return []


def discover_management_groups(credential) -> List[str]:
    """Discover all management groups"""
    env_mgs = os.getenv('SCAN_MANAGEMENT_GROUPS')
    if env_mgs:
        return [m.strip() for m in env_mgs.split(',') if m.strip()]
    
    try:
        client = ManagementGroupsAPI(credential)
        return [mg.name for mg in client.management_groups.list()]
    except Exception as e:
        logger.warning(f"Failed to list management groups: {e}")
        return []


# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

def load_service_catalog() -> List[Dict[str, Any]]:
    """Load service catalog from service_list.yaml"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.yaml")
    
    # Check if YAML exists, otherwise try JSON
    if not os.path.exists(config_path):
        config_path = config_path.replace('.yaml', '.json')
        with open(config_path) as f:
            data = json.load(f)
            services = data.get("services", [])
    else:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
            services = data.get("services", [])
    
    for svc in services:
        svc.setdefault("enabled", True)
        svc.setdefault("scope", "subscription")
    
    return services


def load_service_rules(service_name: str) -> Dict[str, Any]:
    """Load service rules YAML"""
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
    
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    
    # Handle both nested and flat formats
    if service_name in rules:
        return rules[service_name]
    else:
        return rules


# ============================================================================
# CLIENT FACTORY - DYNAMIC CLIENT CREATION
# ============================================================================

_CLIENT_CACHE: Dict[str, Any] = {}
_CACHE_LOCK = threading.RLock()


def create_client(service_name: str, rules: Dict[str, Any], credential, subscription_id: Optional[str] = None) -> Any:
    """
    Dynamically create Azure client based on YAML metadata
    
    Supports:
    - Management plane clients (azure-mgmt-*)
    - Data plane clients (azure-storage-*, azure-keyvault-*)
    - Microsoft Graph API
    """
    cache_key = f"{service_name}_{subscription_id or 'global'}"
    
    with _CACHE_LOCK:
        if cache_key in _CLIENT_CACHE:
            return _CLIENT_CACHE[cache_key]
    
    try:
        # Get client metadata from rules
        sdk_package = rules.get('sdk_package') or rules.get('package')
        client_class = rules.get('client_class')
        api_type = rules.get('api_type', 'management')  # management, data_plane, graph
        
        # Convert package name format (azure-mgmt-storage → azure.mgmt.storage)
        if sdk_package and '-' in sdk_package:
            sdk_package = sdk_package.replace('-', '.')
        
        client = None
        
        if api_type == 'graph':
            # Microsoft Graph API - no client needed, use direct REST calls
            client = None  # We'll handle Graph API calls separately
        elif sdk_package and client_class:
            # Dynamic SDK client creation
            try:
                module = importlib.import_module(sdk_package)
                client_cls = getattr(module, client_class)
                
                # Determine constructor parameters based on client type
                if 'mgmt' in sdk_package:
                    # Management plane client
                    if subscription_id:
                        client = client_cls(credential, subscription_id)
                    else:
                        client = client_cls(credential)
                else:
                    # Data plane client (e.g., BlobServiceClient, KeyClient)
                    # These typically need specific endpoints
                    # For now, skip data-plane clients that need endpoints
                    logger.warning(f"Data plane client {client_class} requires endpoint configuration")
                    client = None
            except Exception as e:
                logger.warning(f"Failed to create client for {service_name}: {e}")
                client = None
        else:
            logger.warning(f"Missing SDK package or client class for {service_name}")
            client = None
        
        with _CACHE_LOCK:
            _CLIENT_CACHE[cache_key] = client
        
        return client
    
    except Exception as e:
        logger.error(f"Failed to create client for {service_name}: {e}")
        return None


# ============================================================================
# ACTION EXECUTOR - DYNAMIC ACTION EXECUTION
# ============================================================================

def execute_action(client: Any, action: str, params: Optional[Dict[str, Any]] = None, credential=None, rules: Optional[Dict] = None) -> Any:
    """
    Dynamically execute action on Azure client
    
    Examples:
    - action: 'storage_accounts.list' → client.storage_accounts.list()
    - action: 'virtual_machines.list' → client.virtual_machines.list(...)
    - action: 'self' → return resource itself
    """
    if action in (None, '', 'self'):
        return client
    
    params = params or {}
    
    try:
        # Handle Microsoft Graph API
        if rules and rules.get('api_type') == 'graph':
            # Substitute templates in action path from params
            # action might be like: /v1.0/servicePrincipals/{{id}}/passwordCredentials
            if params:
                for key, value in params.items():
                    if isinstance(value, (str, int)) and '{{' in action:
                        action = action.replace(f'{{{{{key}}}}}', str(value))
            return execute_graph_api(action, params, credential)
        
        # Parse action path (e.g., 'storage_accounts.list')
        parts = action.split('.')
        target = client
        
        # Navigate to the method
        for part in parts[:-1]:
            target = getattr(target, part, None)
            if target is None:
                logger.warning(f"Action path not found: {action}")
                return None
        
        # Get the final method
        method_name = parts[-1]
        method = getattr(target, method_name, None)
        
        if method is None:
            logger.warning(f"Method not found: {method_name} in action {action}")
            return None
        
        # Execute with params
        result = method(**params)
        
        # Handle paged results (Azure SDK returns iterators for list operations)
        if hasattr(result, '__iter__') and not isinstance(result, (str, bytes, dict)):
            try:
                return list(result)
            except:
                return result
        
        return result
    
    except Exception as e:
        logger.debug(f"Action execution failed for {action}: {e}")
        return None


def execute_graph_api(path: str, params: Optional[Dict] = None, credential=None) -> Any:
    """Execute Microsoft Graph API call"""
    try:
        token = credential.get_token('https://graph.microsoft.com/.default').token
        
        # Handle template substitution in path (e.g., /v1.0/servicePrincipals/{{id}})
        query_params = {}
        if params:
            # Substitute templates in path from params
            for key, value in params.items():
                if isinstance(value, (str, int)) and '{{' in path:
                    path = path.replace(f'{{{{{key}}}}}', str(value))
                elif key != 'method':
                    # Add non-template params to query string
                    query_params[key] = value
        
        url = f'https://graph.microsoft.com{path}'
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
        
        method = params.get('method', 'GET') if params else 'GET'
        resp = requests.request(method, url, headers=headers, params=query_params if query_params else None)
        resp.raise_for_status()
        
        return resp.json()
    except Exception as e:
        logger.debug(f"Graph API call failed for {path}: {e}")
        return None


# ============================================================================
# GENERIC SERVICE RUNNER - NO HARDCODED LOGIC
# ============================================================================

def run_service_compliance(
    service_name: str,
    subscription_id: str,
    credential,
    region: Optional[str] = None,
    resource_group: Optional[str] = None,
    tenant_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generic service scanner - dynamically interprets YAML
    Works for ALL Azure services with NO hardcoded logic
    """
    # Load rules
    try:
        rules = load_service_rules(service_name)
    except Exception as e:
        logger.error(f"Failed to load rules for {service_name}: {e}")
        return {
            'service': service_name,
            'subscription': subscription_id,
            'inventory': {},
            'checks': [],
            'error': str(e)
        }
    
    # Create client (subscription_id can be None for tenant-scoped services)
    client = create_client(service_name, rules, credential, subscription_id)
    
    # DISCOVERY PHASE
    discovery: Dict[str, List[Any]] = {}
    
    for disc in rules.get('discovery', []):
        disc_id = disc.get('discovery_id', '')
        discovery[disc_id] = []
        
        for call in disc.get('calls', []):
            action = call.get('action', '')
            
            try:
                # Build params with context
                params = call.get('params', {}).copy()
                
                # Inject scope parameters
                if region and call.get('region_param'):
                    params[call.get('region_param')] = region
                
                if resource_group and call.get('resource_group_param'):
                    params[call.get('resource_group_param')] = resource_group
                
                # Execute action
                result = execute_action(client, action, params, credential, rules)
                
                if result:
                    # Extract fields
                    fields = call.get('fields', [])
                    if fields:
                        for field in fields:
                            path = field.get('path', '__self__')
                            value = extract_value(result, path)
                            
                            # Serialize Azure objects to clean JSON
                            if isinstance(value, list):
                                serialized_values = [serialize_azure_object(v) for v in value]
                                discovery[disc_id].extend(serialized_values)
                            else:
                                serialized_value = serialize_azure_object(value)
                                discovery[disc_id].append(serialized_value)
                    else:
                        # No fields specified, save entire result
                        if isinstance(result, list):
                            discovery[disc_id] = [serialize_azure_object(r) for r in result]
                        else:
                            discovery[disc_id] = [serialize_azure_object(result)]
            
            except Exception as e:
                logger.debug(f"Discovery {disc_id} action '{action}' failed: {e}")
                discovery[disc_id] = []
    
    # CHECKS PHASE
    checks_out: List[Dict[str, Any]] = []
    
    for check in rules.get('checks', []):
        if _CHECK_ID_FILTER and check.get('check_id') not in _CHECK_ID_FILTER:
            continue
        
        for_each = check.get('for_each', '')
        resources = discovery.get(for_each, [])
        logic = (check.get('logic') or 'AND').upper()
        
        def eval_resource(resource):
            call_results: List[bool] = []
            
            for call in check.get('calls', []):
                action = call.get('action', '')
                fields = call.get('fields', [])
                
                try:
                    if action in ('self', 'eval'):
                        # Evaluate on resource directly
                        field_results = []
                        for fld in fields:
                            value = extract_value(resource, fld['path'])
                            if isinstance(value, list):
                                res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in value)
                            else:
                                res = evaluate_field(value, fld['operator'], fld.get('expected'))
                            field_results.append(res)
                        call_results.append(all(field_results) if field_results else False)
                    else:
                        # Execute action on client
                        params = call.get('params', {}).copy()
                        
                        # Substitute templates in params
                        resource_dict = resource if isinstance(resource, dict) else {'item': resource}
                        # Add common fields for Graph API resources
                        if isinstance(resource, dict):
                            if 'id' in resource:
                                resource_dict['id'] = resource['id']
                            if 'name' in resource:
                                resource_dict['name'] = resource['name']
                        
                        for key, val in params.items():
                            params[key] = substitute_templates(val, resource_dict)
                        
                        # Substitute templates in action path for Graph API
                        action_with_templates = action
                        if rules and rules.get('api_type') == 'graph' and isinstance(resource, dict):
                            for key, value in resource.items():
                                if isinstance(value, (str, int)) and '{{' in action_with_templates:
                                    action_with_templates = action_with_templates.replace(f'{{{{{key}}}}}', str(value))
                        
                        result = execute_action(client, action_with_templates, params, credential, rules)
                        
                        if result:
                            field_results = []
                            for fld in fields:
                                value = extract_value(result, fld['path'])
                                if isinstance(value, list):
                                    res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in value)
                                else:
                                    res = evaluate_field(value, fld['operator'], fld.get('expected'))
                                field_results.append(res)
                            call_results.append(all(field_results) if field_results else False)
                        else:
                            call_results.append(False)
                
                except Exception as e:
                    logger.debug(f"Check evaluation failed: {e}")
                    call_results.append(False)
            
            final = (any(call_results) if logic == 'OR' else all(call_results)) if call_results else False
            
            # Serialize resource for output
            if isinstance(resource, dict):
                resource_name = resource.get('name', resource.get('id', 'unknown'))
                resource_output = resource  # Already a dict
            else:
                resource_name = getattr(resource, 'name', str(resource))
                resource_output = serialize_azure_object(resource)
            
            result_dict = {
                'check_id': check['check_id'],
                'resource_name': resource_name,
                'resource': resource_output,
                'subscription': subscription_id,
                'result': 'PASS' if final else 'FAIL'
            }
            
            if region:
                result_dict['region'] = region
            if resource_group:
                result_dict['resource_group'] = resource_group
            if tenant_id:
                result_dict['tenant'] = tenant_id
            
            return result_dict
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(eval_resource, r) for r in resources]
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        checks_out.append(res)
                except Exception as e:
                    logger.debug(f"Check future failed: {e}")
    
    result = {
        'service': service_name,
        'subscription': subscription_id,
        'inventory': discovery,
        'checks': checks_out,
        'scope': rules.get('scope', 'subscription')
    }
    
    if region:
        result['region'] = region
    if resource_group:
        result['resource_group'] = resource_group
    if tenant_id:
        result['tenant'] = tenant_id
    
    return result


# ============================================================================
# ORCHESTRATION - FULL HIERARCHY SCAN
# ============================================================================

def run_for_subscription(subscription_id: str, credential, enabled_services: Set[str], tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Run all enabled services for a subscription"""
    outputs: List[Dict[str, Any]] = []
    catalog = load_service_catalog()
    
    # Group services by scope
    global_services = [s.get('name') for s in catalog if s.get('scope') == 'global' and s.get('name') in enabled_services]
    subscription_services = [s.get('name') for s in catalog if s.get('scope') == 'subscription' and s.get('name') in enabled_services]
    regional_services = [s.get('name') for s in catalog if s.get('scope') == 'regional' and s.get('name') in enabled_services]
    
    # Global services (tenant-wide, no subscription)
    for svc in global_services:
        try:
            outputs.append(run_service_compliance(svc, subscription_id, credential, tenant_id=tenant_id))
        except Exception as e:
            logger.error(f"Error scanning {svc}: {e}")
    
    # Subscription-scoped services
    for svc in subscription_services:
        try:
            outputs.append(run_service_compliance(svc, subscription_id, credential, tenant_id=tenant_id))
        except Exception as e:
            logger.error(f"Error scanning {svc}: {e}")
    
    # Regional services
    if regional_services:
        regions = discover_regions(credential, subscription_id)
        
        for svc in regional_services:
            with ThreadPoolExecutor(max_workers=REGION_MAX_WORKERS) as pool:
                futures = [pool.submit(run_service_compliance, svc, subscription_id, credential, r, None, tenant_id) for r in regions]
                for fut in as_completed(futures):
                    try:
                        outputs.append(fut.result())
                    except Exception as e:
                        logger.error(f"Error scanning regional {svc}: {e}")
    
    return outputs


def run() -> List[Dict[str, Any]]:
    """Main entry - scan all subscriptions"""
    credential = get_default_credential()
    subscriptions = discover_subscriptions(credential)
    
    # Get enabled services (from catalog)
    catalog = load_service_catalog()
    enabled_services = {s['name'] for s in catalog if s.get('enabled', True)}
    
    if _SERVICE_FILTER:
        enabled_services = {s for s in enabled_services if s in _SERVICE_FILTER}
    
    # Separate tenant-scoped services (run once per tenant, not per subscription)
    tenant_services = {s['name'] for s in catalog if s.get('scope') == 'tenant' and s.get('name') in enabled_services}
    non_tenant_services = enabled_services - tenant_services
    
    logger.info(f"Scanning {len(subscriptions)} subscriptions with {len(non_tenant_services)} subscription services and {len(tenant_services)} tenant services")
    
    all_outputs: List[Dict[str, Any]] = []
    
    # Handle tenant-scoped services (run once, not per subscription)
    for service_name in tenant_services:
        try:
            # Load scope from rules to confirm
            rules = load_service_rules(service_name)
            scope = rules.get('scope', 'subscription')
            if scope == 'tenant':
                # For tenant services, subscription_id can be None or first subscription
                sub_id = subscriptions[0].get('id') if subscriptions else None
                result = run_service_compliance(service_name, sub_id, credential, tenant_id=None)
                all_outputs.append(result)
        except Exception as e:
            logger.error(f"Error scanning tenant service {service_name}: {e}")
            all_outputs.append({
                'service': service_name,
                'inventory': {},
                'checks': [],
                'error': str(e),
                'scope': 'tenant'
            })
    
    # Handle subscription-scoped services
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = []
        
        for sub in subscriptions:
            sub_id = sub.get('id')
            if sub_id:
                futures.append(ex.submit(run_for_subscription, sub_id, credential, non_tenant_services, None))
        
        for fut in as_completed(futures):
            try:
                all_outputs.extend(fut.result())
            except Exception as e:
                logger.error(f"Subscription scan failed: {e}")
    
    return all_outputs


def main():
    """Entry point"""
    results = run()
    print(json.dumps(results, indent=2, default=str))
    
    # Save results
    try:
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from utils.inventory_reporter import save_scan_results, save_split_scan_results
        
        output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'output'))
        os.makedirs(output_dir, exist_ok=True)
        
        path = save_scan_results(results, output_dir, None)
        logger.info(f"Saved results to: {path}")
        print(f"Saved results to: {path}")
        
        split_folder = save_split_scan_results(results, output_dir, None)
        logger.info(f"Saved split results to: {split_folder}")
        print(f"Saved split results to: {split_folder}")
    except ImportError:
        # Fallback: just save JSON
        output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'output'))
        os.makedirs(output_dir, exist_ok=True)
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output_file = os.path.join(output_dir, f"azure_scan_{timestamp}.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Saved results to: {output_file}")


if __name__ == '__main__':
    main()

