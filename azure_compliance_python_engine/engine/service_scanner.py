"""
Azure Service Scanner - Core service-level scanning

Consolidated from azure_sdk_engine.py, azure_generic_engine.py, and optimized_executor.py
Equivalent to AWS service_scanner.py
"""

import json
import os
import yaml
import logging
from typing import Any, List, Dict, Optional
from time import sleep
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import HttpResponseError

logger = logging.getLogger('azure-service-scanner')

# Retry settings
MAX_RETRIES = int(os.getenv('COMPLIANCE_MAX_RETRIES', '5'))
BASE_DELAY = float(os.getenv('COMPLIANCE_BASE_DELAY', '0.8'))
BACKOFF_FACTOR = float(os.getenv('COMPLIANCE_BACKOFF_FACTOR', '2.0'))


def extract_value(obj: Any, path: str):
    """Extract value from nested object using dot notation"""
    if obj is None:
        return None
    
    if path == '__self__':
        # Return list if iterable, otherwise object itself
        if isinstance(obj, list):
            return obj
        try:
            return list(iter(obj))
        except (TypeError, AttributeError):
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
        
        # Handle array syntax key[]
        if part.endswith('[]'):
            key = part[:-2]
            arr = getattr(current, key, None) if not isinstance(current, dict) else current.get(key, [])
            if not arr:
                return []
            
            # Convert to list if needed
            if not isinstance(arr, list):
                try:
                    arr = list(iter(arr))
                except (TypeError, AttributeError):
                    arr = [arr]
            
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
        
        # Handle dict/object access
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
        
        if current is None:
            return None
    
    return current


def extract_checked_fields(cond_config: Dict[str, Any]) -> set:
    """Extract all field names referenced in check conditions"""
    fields = set()
    
    if isinstance(cond_config, dict):
        if 'all' in cond_config:
            for sub_cond in cond_config['all']:
                fields.update(extract_checked_fields(sub_cond))
        elif 'any' in cond_config:
            for sub_cond in cond_config['any']:
                fields.update(extract_checked_fields(sub_cond))
        else:
            var = cond_config.get('var', '')
            if var:
                # Extract field name from 'item.field' or just 'field'
                field_name = var.replace('item.', '') if var.startswith('item.') else var
                fields.add(field_name)
    
    return fields

def evaluate_condition(value: Any, operator: str, expected: Any = None) -> bool:
    """Evaluate a condition with the given operator"""
    if operator == 'exists':
        return value is not None and value != '' and value != []
    elif operator == 'equals':
        return value == expected
    elif operator == 'not_equals':
        return value != expected
    elif operator == 'contains':
        if isinstance(value, (list, str)):
            return expected in value
        return False
    elif operator == 'not_empty':
        return value is not None and value != '' and value != [] and value != {}
    elif operator == 'not_contains':
        if isinstance(value, (list, str)):
            return expected not in value
        return False
    elif operator == 'gt':
        return float(value) > float(expected) if value is not None else False
    elif operator == 'gte':
        return float(value) >= float(expected) if value is not None else False
    elif operator == 'lt':
        return float(value) < float(expected) if value is not None else False
    elif operator == 'lte':
        return float(value) <= float(expected) if value is not None else False
    elif operator == 'length_gte':
        if isinstance(value, (list, str)):
            return len(value) >= int(expected)
        return False
    else:
        logger.warning(f"Unknown operator: {operator}")
        return False


def load_enabled_services_with_scope():
    """Load enabled Azure services from config"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "subscription")) for s in data["services"] if s.get("enabled")]


def load_service_rules(service_name):
    """Load service rules from YAML
    
    New structure: services/{sdk_client}/rules/{sdk_client}.yaml
    Old structure (fallback): services/{service_name}/{service_name}_rules.yaml
    """
    # Try new structure first (rules/ folder)
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, "rules", f"{service_name}.yaml")
    if os.path.exists(rules_path):
        with open(rules_path) as f:
            rules = yaml.safe_load(f)
        return rules
    
    # Fallback to old structure for backward compatibility
    old_rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
    if os.path.exists(old_rules_path):
        with open(old_rules_path) as f:
            rules = yaml.safe_load(f)
        return rules
    
    # If neither exists, raise error
    raise FileNotFoundError(f"Rules file not found for {service_name}. Tried: {rules_path} and {old_rules_path}")


def _retry_call(func, *args, **kwargs):
    """Retry logic with exponential backoff"""
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            delay = BASE_DELAY * (BACKOFF_FACTOR ** attempt)
            logger.debug(f"Retrying after error: {e} (attempt {attempt+1}/{MAX_RETRIES}, sleep {delay:.2f}s)")
            sleep(delay)


def run_service_scan(
    service_name: str,
    subscription_id: str,
    location: Optional[str] = None,
    credential: Optional[DefaultAzureCredential] = None
) -> Dict[str, Any]:
    """
    Run compliance scan for an Azure service
    
    Args:
        service_name: Azure service name (e.g., 'storage', 'compute')
        subscription_id: Azure subscription ID
        location: Azure location (optional, for location-specific services)
        credential: Azure credential (optional, will create if not provided)
    
    Returns:
        Scan results with inventory and checks
    """
    try:
        service_rules = load_service_rules(service_name)
        
        if credential is None:
            from auth.azure_auth import get_default_credential
            credential = get_default_credential()
        
        # Import Azure client factory
        from auth.azure_client_factory import AzureClientFactory
        
        # Create client factory
        client_factory = AzureClientFactory(subscription_id=subscription_id, credential=credential)
        
        # Get Azure client for this service
        try:
            azure_client = client_factory.get_client(service_name)
        except Exception as e:
            logger.warning(f"Could not create client for {service_name}: {e}")
            azure_client = None
        
        discovery_results = {}
        checks_output = []
        saved_data = {}  # Store responses from discovery calls
        
        # Process discovery
        logger.info(f"Processing {len(service_rules.get('discovery', []))} discovery operations for {service_name}")
        for discovery in service_rules.get('discovery', []):
            discovery_id = discovery['discovery_id']
            logger.info(f"  Discovery: {discovery_id}")
            
            if not azure_client:
                logger.warning(f"  No Azure client available for {service_name}, skipping discovery")
                discovery_results[discovery_id] = []
                continue
            
            try:
                # Process calls in discovery
                for call in discovery.get('calls', []):
                    action = call.get('action')
                    params = call.get('params', {})
                    save_as = call.get('save_as', f'{action}_response')
                    
                    if not action:
                        continue
                    
                    # Execute Azure SDK call using DiscoveryHelper
                    try:
                        from engine.discovery_helper import DiscoveryHelper
                        
                        # Find the correct method using DiscoveryHelper
                        method = DiscoveryHelper.find_discovery_method(azure_client, service_name, action)
                        
                        if method:
                            # Execute using DiscoveryHelper's execution logic
                            try:
                                response = DiscoveryHelper.execute_discovery(
                                    method, action, params, subscription_id, credential
                                )
                                
                                # Azure SDK returns iterable, convert to list
                                # Store both the raw response and the list for flexibility
                                if hasattr(response, '__iter__') and not isinstance(response, (str, dict, bytes)):
                                    try:
                                        response_list = list(response)
                                        # Store as both the list and in a 'value' key (for YAML compatibility)
                                        saved_data[save_as] = {
                                            'value': response_list,  # For YAML items_for: {{ response.value }}
                                            '_items': response_list  # Direct access
                                        }
                                        response = response_list
                                    except:
                                        # If it's a paged response, get value
                                        if hasattr(response, 'value'):
                                            response_list = list(response.value) if hasattr(response.value, '__iter__') else [response.value]
                                            saved_data[save_as] = {
                                                'value': response_list,
                                                '_items': response_list
                                            }
                                            response = response_list
                                        else:
                                            saved_data[save_as] = {'value': [], '_items': []}
                                            response = []
                                else:
                                    # Single item or dict
                                    saved_data[save_as] = {
                                        'value': [response] if response is not None else [],
                                        '_items': [response] if response is not None else []
                                    }
                                    response = [response] if response is not None else []
                                
                                count = len(response) if isinstance(response, list) else 1
                                logger.info(f"    Discovery call {action} succeeded: {count} items found")
                                
                            except Exception as e:
                                logger.warning(f"Discovery execution failed: {e}")
                                saved_data[save_as] = []
                                continue
                        else:
                            logger.warning(f"Could not find discovery method for {service_name}.{action}")
                            saved_data[save_as] = []
                            continue
                    except Exception as e:
                        logger.warning(f"Discovery call {action} failed: {e}")
                        saved_data[save_as] = []
                
                # Process emit to extract items
                emit_config = discovery.get('emit', {})
                if 'items_for' in emit_config:
                    items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                    # Try to extract items
                    items = extract_value(saved_data, items_path)
                    
                    # If not found, try alternative paths
                    if not items or (isinstance(items, list) and len(items) == 0):
                        # Try direct access to save_as
                        for call in discovery.get('calls', []):
                            save_as = call.get('save_as', '')
                            if save_as and save_as in saved_data:
                                saved_response = saved_data[save_as]
                                # If it's a dict with 'value', get that
                                if isinstance(saved_response, dict) and 'value' in saved_response:
                                    items = saved_response['value']
                                elif isinstance(saved_response, list):
                                    items = saved_response
                                break
                    
                    if items and isinstance(items, list):
                        # Extract item fields
                        item_template = emit_config.get('item', {})
                        discovered_items = []
                        
                        for item in items:
                            # Convert Azure SDK model to dict if needed
                            if hasattr(item, 'as_dict'):
                                try:
                                    item_dict = item.as_dict()
                                except:
                                    # Fallback: use direct attributes
                                    item_dict = {attr: getattr(item, attr, None) 
                                               for attr in dir(item) 
                                               if not attr.startswith('_') and not callable(getattr(item, attr, None))}
                            elif hasattr(item, '__dict__'):
                                item_dict = item.__dict__
                            elif isinstance(item, dict):
                                item_dict = item
                            else:
                                # Try to access as object
                                item_dict = {}
                                for field_name in item_template.keys():
                                    if hasattr(item, field_name):
                                        item_dict[field_name] = getattr(item, field_name)
                            
                            discovered_item = {}
                            for field_name, field_template in item_template.items():
                                if isinstance(field_template, str) and '{{' in field_template:
                                    # Resolve template
                                    field_path = field_template.replace('{{ ', '').replace(' }}', '').replace('item.', '')
                                    value = extract_value(item_dict, field_path)
                                    discovered_item[field_name] = value
                                else:
                                    discovered_item[field_name] = field_template
                            
                            discovered_items.append(discovered_item)
                        
                        discovery_results[discovery_id] = discovered_items
                        logger.info(f"  Discovery {discovery_id} completed: {len(discovered_items)} items discovered")
                    else:
                        discovery_results[discovery_id] = []
                else:
                    discovery_results[discovery_id] = []
                    
            except Exception as e:
                logger.error(f"Discovery {discovery_id} failed: {e}")
                discovery_results[discovery_id] = []
        
        # Process checks
        for check in service_rules.get('checks', []):
            check_id = check['rule_id']
            for_each = check.get('for_each')
            conditions = check.get('conditions', {})
            
            # Get items for this check
            items = []
            if for_each and for_each in discovery_results:
                items = discovery_results[for_each]
            
            # Evaluate check for each item (or once if no for_each)
            if not items:
                items = [None]  # Run check once if no items
            
            for item_idx, item in enumerate(items):
                result = 'PASS'
                resource_id = extract_value(item, 'id') if item else None
                
                # Extract checked fields from conditions for evidence filtering
                checked_fields = extract_checked_fields(conditions) if conditions else set()
                
                # Evaluate conditions
                if conditions:
                    var_path = conditions.get('var', '').replace('item.', '')
                    operator = conditions.get('op', 'exists')
                    expected = conditions.get('value')
                    
                    if item:
                        value = extract_value(item, var_path)
                    else:
                        value = None
                    
                    # Evaluate condition
                    if not evaluate_condition(value, operator, expected):
                        result = 'FAIL'
                    
                    # Log check evaluation details
                    if len(items) > 1:
                        logger.info(f"    Item {item_idx + 1}/{len(items)}: {result} (resource: {resource_id.split('/')[-1] if resource_id else 'global'})")
                    else:
                        logger.info(f"    Result: {result} (resource: {resource_id.split('/')[-1] if resource_id else 'global'})")
                
                record = {
                    'rule_id': check_id,
                    'title': check.get('title', ''),
                    'severity': check.get('severity', 'medium'),
                    'result': result,
                    'subscription': subscription_id,
                    'location': location or 'global',
                    'resource_id': resource_id,
                    '_checked_fields': list(checked_fields)  # Store for evidence filtering
                }
                
                # Add item data to record
                if item and isinstance(item, dict):
                    for key, value in item.items():
                        record[key] = value
                
                checks_output.append(record)
        
        # Summary logging
        total_discovered = sum(len(v) if isinstance(v, list) else 0 for v in discovery_results.values())
        passed_checks = sum(1 for c in checks_output if c.get('result') == 'PASS')
        failed_checks = sum(1 for c in checks_output if c.get('result') == 'FAIL')
        
        logger.info(f"Service {service_name} scan complete:")
        logger.info(f"  Discovered: {total_discovered} resources")
        logger.info(f"  Checks: {len(checks_output)} total (PASS={passed_checks}, FAIL={failed_checks})")
        
        return {
            'inventory': discovery_results,
            'checks': checks_output,
            'service': service_name,
            'scope': 'global' if not location else 'regional',
            'subscription': subscription_id,
            'location': location or 'global'
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Service {service_name} failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': 'global' if not location else 'regional',
            'subscription': subscription_id,
            'location': location or 'global',
            'unavailable': True,
            'error': str(e)
        }


def run_global_service(service_name, subscription_id, credential_override: Optional[DefaultAzureCredential] = None):
    """Run compliance checks for a global Azure service"""
    return run_service_scan(service_name, subscription_id, location=None, credential=credential_override)


def run_regional_service(service_name, location, subscription_id, credential_override: Optional[DefaultAzureCredential] = None):
    """Run compliance checks for a regional Azure service"""
    return run_service_scan(service_name, subscription_id, location=location, credential=credential_override)


def main():
    """Main entry point for single subscription scan"""
    enabled_services = load_enabled_services_with_scope()
    
    if not enabled_services:
        logger.warning("No enabled services found")
        return
    
    # Get subscription from environment
    subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
    if not subscription_id:
        logger.error("AZURE_SUBSCRIPTION_ID environment variable required")
        return
    
    logger.info(f"Running compliance checks for {len(enabled_services)} services")
    logger.info(f"Subscription: {subscription_id}")
    
    all_results = []
    
    for service_name, scope in enabled_services:
        logger.info(f"Processing {service_name} ({scope})")
        
        if scope == 'global':
            result = run_global_service(service_name, subscription_id)
        else:
            # For regional, default to primary location
            result = run_regional_service(service_name, 'eastus', subscription_id)
        
        all_results.append(result)
        
        # Print summary
        if result.get('checks'):
            passed = sum(1 for c in result['checks'] if c['result'] == 'PASS')
            failed = sum(1 for c in result['checks'] if c['result'] == 'FAIL')
            logger.info(f"  Results: {passed} PASS, {failed} FAIL")
    
    logger.info("Compliance check completed")
    
    # Save results
    try:
        from utils.reporting_manager import save_reporting_bundle
        report_folder = save_reporting_bundle(all_results, subscription_id=subscription_id)
        logger.info(f"Results saved to: {report_folder}")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")
    
    return all_results


if __name__ == "__main__":
    main()
