import json
import os
import boto3
import yaml
import logging
from typing import Any, List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.reporting_manager import save_reporting_bundle
from auth.aws_auth import get_boto3_session, get_session_for_account
from engine.discovery_helper import get_boto3_client_name
import threading
import re

# Logging will be configured per-scan in output/scan_TIMESTAMP/logs/
# This allows each scan to have its own log file
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('compliance-boto3')

# Retry/backoff settings
MAX_RETRIES = int(os.getenv('COMPLIANCE_MAX_RETRIES', '5'))
BASE_DELAY = float(os.getenv('COMPLIANCE_BASE_DELAY', '0.8'))
BACKOFF_FACTOR = float(os.getenv('COMPLIANCE_BACKOFF_FACTOR', '2.0'))

# Botocore retry/timeout config
BOTO_CONFIG = BotoConfig(
    retries={'max_attempts': int(os.getenv('BOTO_MAX_ATTEMPTS', '5')), 'mode': os.getenv('BOTO_RETRY_MODE', 'standard')},
    read_timeout=int(os.getenv('BOTO_READ_TIMEOUT', '60')),
    connect_timeout=int(os.getenv('BOTO_CONNECT_TIMEOUT', '10')),
    max_pool_connections=int(os.getenv('BOTO_MAX_POOL_CONNECTIONS', '50')),
)

def extract_value(obj: Any, path: str):
    """Extract value from nested object using dot notation and array syntax"""
    if obj is None:
        return None
        
    parts = path.split('.')
    current = obj
    for idx, part in enumerate(parts):
        # Handle numeric array indices first
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if 0 <= index < len(current):
                current = current[index]
            else:
                return None
        elif part.endswith('[]'):
            key = part[:-2]
            arr = current.get(key, []) if isinstance(current, dict) else []
            if not parts[idx+1:]:  # Last part
                return arr
            result = []
            for item in arr:
                sub = extract_value(item, '.'.join(parts[idx+1:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        elif isinstance(current, list):
            result = []
            for item in current:
                sub = extract_value(item, '.'.join(parts[idx:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        else:
            if isinstance(current, dict):
                current = current.get(part)
                if current is None:
                    return None
            else:
                return None
    return current

def evaluate_condition(value: Any, operator: str, expected: Any = None) -> bool:
    """Evaluate a condition with the given operator and expected value"""
    if operator == 'exists':
        return value is not None and value != '' and value != []
    elif operator == 'equals':
        return value == expected
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
    elif operator == 'not_contains':
        if isinstance(value, (list, str)):
            return expected not in value
        return False
    elif operator == 'contains':
        if isinstance(value, (list, str)):
            return expected in value
        return False
    else:
        logger.warning(f"Unknown operator: {operator}")
        return False

def resolve_template(text: str, context: Dict[str, Any]) -> Any:
    """Resolve template variables like {{ variable }} in text"""
    if not isinstance(text, str) or '{{' not in text:
        return text
    
    def replace_var(match):
        var_path = match.group(1).strip()
        
        # Handle special functions
        if var_path.startswith('exists('):
            path = var_path[7:-1]  # Remove 'exists(' and ')'
            value = extract_value(context, path)
            exists_result = value is not None and value != '' and value != []
            return str(exists_result)
        
        # Handle complex expressions with dynamic keys like user_details[u.UserName].User.PasswordLastUsed
        if '[' in var_path and ']' in var_path:
            # Find the dynamic key part like [u.UserName]
            start_bracket = var_path.find('[')
            end_bracket = var_path.find(']')
            if start_bracket != -1 and end_bracket != -1:
                # Extract the base path and dynamic key
                base_path = var_path[:start_bracket]
                dynamic_key_expr = var_path[start_bracket+1:end_bracket]
                remaining_path = var_path[end_bracket+1:]
                
                # Resolve the dynamic key (e.g., u.UserName)
                # For simple expressions like u.UserName, we need to handle them directly
                if '.' in dynamic_key_expr and not dynamic_key_expr.startswith('{{'):
                    # Simple dot notation like u.UserName
                    dynamic_key = extract_value(context, dynamic_key_expr)
                else:
                    # Complex expression that needs template resolution
                    dynamic_key = resolve_template(dynamic_key_expr, context)
                logger.debug(f"Dynamic key expression: {dynamic_key_expr} -> {dynamic_key}")
                
                # Build the full path - the data is stored as user_details.administrator, not user_details.administrator.User.PasswordLastUsed
                # For complex keys with dots, we need to access them as nested dictionaries
                if '.' in dynamic_key:
                    # If the dynamic key contains dots, we need to access it as a nested dictionary
                    full_key = base_path
                    # We'll handle the nested access in the extract_value call
                else:
                    full_key = f"{base_path}.{dynamic_key}"
                
                logger.debug(f"Complex template: {var_path} -> {full_key}")
                # Check if the full key exists in context
                if full_key in context:
                    logger.debug(f"Full key {full_key} exists in context: {context[full_key]}")
                    # The data is stored directly under the full key, so we need to extract the remaining path from it
                    if remaining_path:
                        # Remove the leading dot from remaining_path and handle array indices
                        remaining_path_clean = remaining_path.lstrip('.')
                        # Convert [0] to 0 for array access
                        remaining_path_clean = remaining_path_clean.replace('[', '').replace(']', '')
                        logger.debug(f"Extracting from {full_key} with path: {remaining_path_clean}")
                        value = extract_value(context[full_key], remaining_path_clean)
                    else:
                        value = context[full_key]
                else:
                    logger.debug(f"Full key {full_key} not found in context keys: {list(context.keys())}")
                    value = None
                
                # Handle nested access for complex keys
                if '.' in dynamic_key and full_key in context:
                    # Build the full path with the dynamic key
                    full_path = f"{dynamic_key}.{remaining_path_clean}" if remaining_path else dynamic_key
                    logger.debug(f"Extracting from {full_key} with nested path: {full_path}")
                    value = extract_value(context[full_key], full_path)
                logger.debug(f"Complex template result: {value}")
                return str(value) if value is not None else ''
        
        # Debug logging
        logger.debug(f"Resolving template variable: {var_path}")
        logger.debug(f"Context keys: {list(context.keys())}")
        if 'u' in context:
            logger.debug(f"Context 'u' object: {context['u']}")
        
        value = extract_value(context, var_path)
        logger.debug(f"Extracted value: {value}")
        
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

def load_enabled_services_with_scope():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "regional")) for s in data["services"] if s.get("enabled")]

def load_service_rules(service_name):
    """
    Load service rules YAML file.
    Handles service name mapping from config names to folder names.
    Each service has its own folder and YAML file.
    The boto3 client mapping (SERVICE_TO_BOTO3_CLIENT) handles SDK client selection.
    """
    base_path = os.path.join(os.path.dirname(__file__), "..", "services")
    
    # Original logic - load from service folder
    # Try multiple name variations
    possible_names = [
        service_name,  # Exact match
        service_name.replace('_', ''),  # Remove underscores (api_gateway -> apigateway)
    ]
    
    # Also try with common variations
    if '_' in service_name:
        # Try with different underscore positions
        parts = service_name.split('_')
        possible_names.append(''.join(parts))  # api_gateway -> apigateway
        if len(parts) == 2:
            possible_names.append(parts[0] + parts[1].capitalize())  # api_gateway -> apiGateway
    
    # Try each possible name
    rules_path = None
    for name in possible_names:
        test_path = os.path.join(base_path, name, "rules", f"{name}.yaml")
        if os.path.exists(test_path):
            rules_path = test_path
            break
    
    # If still not found, try to find by scanning folders
    if not rules_path:
        service_norm = service_name.replace('_', '').lower()
        if os.path.exists(base_path):
            for folder_name in os.listdir(base_path):
                folder_path = os.path.join(base_path, folder_name)
                if os.path.isdir(folder_path):
                    folder_norm = folder_name.replace('_', '').lower()
                    if folder_norm == service_norm:
                        test_path = os.path.join(folder_path, "rules", f"{folder_name}.yaml")
                        if os.path.exists(test_path):
                            rules_path = test_path
                            break
    
    if not rules_path:
        raise FileNotFoundError(f"Service rules not found for '{service_name}'. Tried: {possible_names}")
    
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    
    # Normalize to Phase 2 format (handles both Phase 2 and Phase 3)
    return normalize_to_phase2_format(rules)

def convert_assert_to_conditions(assertion):
    """
    Convert Phase 3 assert to Phase 2 conditions
    
    Examples:
      assert: item.exists → {var: item.exists, op: exists}
      assert: {item.status: ACTIVE} → {var: item.status, op: equals, value: ACTIVE}
    """
    if isinstance(assertion, str):
        # Simple assertion: assert: item.exists
        return {'var': assertion, 'op': 'exists'}
    
    elif isinstance(assertion, dict):
        # Dict assertion: assert: {item.status: ACTIVE}
        # Take first key-value pair
        for var, value in assertion.items():
            return {'var': var, 'op': 'equals', 'value': value}
    
    # Fallback - return as-is
    return assertion

def convert_phase3_to_phase2(rules):
    """
    Convert Phase 3 ultra-simplified format to Phase 2 format
    
    Phase 3 format:
      service: account
      resources:
        alternate_contacts:
          actions:
          - get_alternate_contact: {AlternateContactType: SECURITY}
      checks:
        contact.configured:
          resource: alternate_contacts
          assert: item.exists
    
    Phase 2 format:
      service: account
      discovery:
      - discovery_id: aws.account.alternate_contacts
        calls:
        - action: get_alternate_contact
          params: {AlternateContactType: SECURITY}
      checks:
      - rule_id: aws.account.contact.configured
        for_each: aws.account.alternate_contacts
        conditions: {var: item.exists, op: exists}
    """
    service_name = rules.get('service', 'unknown')
    
    normalized = {
        'version': rules.get('version', '1.0'),
        'provider': rules.get('provider', 'aws'),
        'service': service_name
    }
    
    # Convert resources to discovery
    if 'resources' in rules:
        discoveries = []
        
        for resource_name, resource_def in rules['resources'].items():
            discovery_id = f'aws.{service_name}.{resource_name}'
            
            calls = []
            emit = None
            
            # Handle different resource definition formats
            if isinstance(resource_def, dict):
                # Extract emit if present at resource level
                if 'emit' in resource_def:
                    emit = resource_def['emit']
                
                # Handle 'actions' list (multiple actions)
                if 'actions' in resource_def:
                    for action_item in resource_def['actions']:
                        if isinstance(action_item, dict):
                            # {action_name: params_dict}
                            for action_name, params in action_item.items():
                                call = {'action': action_name}
                                if params and isinstance(params, dict):
                                    # Check if params are at top level or nested
                                    if 'params' in params:
                                        call['params'] = params['params']
                                    else:
                                        call['params'] = params
                                calls.append(call)
                        elif isinstance(action_item, str):
                            # Just action name
                            calls.append({'action': action_item})
                
                # Handle single action format: {action_name: {...}}
                else:
                    for key, value in resource_def.items():
                        if key != 'emit':
                            # This is an action
                            call = {'action': key}
                            if isinstance(value, dict):
                                if 'params' in value:
                                    call['params'] = value['params']
                                elif value:
                                    # Top-level dict is the params
                                    call['params'] = value
                                if 'extract' in value:
                                    call['fields'] = value['extract'] if isinstance(value['extract'], list) else [value['extract']]
                                if 'emit' in value:
                                    emit = value['emit']
                            calls.append(call)
            
            # Create discovery entry
            discovery = {
                'discovery_id': discovery_id,
                'calls': calls
            }
            
            if emit:
                discovery['emit'] = emit
            
            discoveries.append(discovery)
        
        normalized['discovery'] = discoveries
    
    # Copy discovery section if exists (Phase 2 format)
    elif 'discovery' in rules:
        normalized['discovery'] = rules['discovery']
    
    # Convert checks
    if 'checks' in rules:
        checks_list = []
        
        # Phase 3 format: checks is a dict
        if isinstance(rules['checks'], dict):
            for check_name, check_def in rules['checks'].items():
                rule_id = f'aws.{service_name}.{check_name}'
                
                check_entry = {
                    'rule_id': rule_id
                }
                
                # Convert resource reference to for_each
                if 'resource' in check_def:
                    resource_ref = check_def['resource']
                    check_entry['for_each'] = f'aws.{service_name}.{resource_ref}'
                
                # Convert assert to conditions
                if 'assert' in check_def:
                    check_entry['conditions'] = convert_assert_to_conditions(check_def['assert'])
                elif 'conditions' in check_def:
                    check_entry['conditions'] = check_def['conditions']
                
                # Copy other fields
                for key in ['params', 'assertion_id']:
                    if key in check_def:
                        check_entry[key] = check_def[key]
                
                checks_list.append(check_entry)
        
        # Phase 2 format: checks is a list
        elif isinstance(rules['checks'], list):
            checks_list = rules['checks']
        
        normalized['checks'] = checks_list
    
    return normalized

def normalize_to_phase2_format(rules):
    """
    Detect YAML format version and normalize to Phase 2 format for processing
    
    Supports:
    - Phase 2: discovery/checks (current) - returns as-is
    - Phase 3: resources/checks (ultra-simplified) - converts to Phase 2
    """
    if not rules:
        return rules
    
    # Detect format version
    if 'resources' in rules:
        # Phase 3 format - needs conversion
        logger.debug(f"Detected Phase 3 format, converting to Phase 2")
        return convert_phase3_to_phase2(rules)
    else:
        # Phase 2 or earlier - return as-is
        logger.debug(f"Detected Phase 2 format, using directly")
        return rules

def _retry_call(func, *args, **kwargs):
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            delay = BASE_DELAY * (BACKOFF_FACTOR ** attempt)
            logger.debug(f"Retrying after error: {e} (attempt {attempt+1}/{MAX_RETRIES}, sleep {delay:.2f}s)")
            sleep(delay)

def run_global_service(service_name, session_override: Optional[boto3.session.Session] = None):
    """Run compliance checks for a global service"""
    try:
        service_rules = load_service_rules(service_name)
        session = session_override or get_boto3_session(default_region='us-east-1')
        boto3_client_name = get_boto3_client_name(service_name)
        client = session.client(boto3_client_name, region_name='us-east-1', config=BOTO_CONFIG)
        
        discovery_results = {}
        saved_data = {}
        
        # Process discovery
        for discovery in service_rules.get('discovery', []):
            discovery_id = discovery['discovery_id']
            
            # Process calls in order
            for call in discovery.get('calls', []):
                action = call['action']
                params = call.get('params', {})
                # Auto-generate save_as if not provided
                save_as = call.get('save_as', f'{action}_response')
                for_each = call.get('for_each')
                as_var = call.get('as', 'item')
                # Default to 'continue' for better resilience
                on_error = call.get('on_error', 'continue')
                
                try:
                    if for_each:
                        # Get the items to iterate over
                        items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                        
                        # Extract items from saved data
                        items = extract_value(saved_data, items_ref)
                        
                        # Debug logging
                        logger.debug(f"Looking for items in: {items_ref}")
                        logger.debug(f"Saved data keys: {list(saved_data.keys())}")
                        logger.debug(f"Extracted items count: {len(items) if items else 0}")
                        
                        if items:
                            for item in items:
                                # Create context for this item
                                context = {as_var: item}
                                context.update(saved_data)
                                
                                # Resolve parameters recursively
                                def resolve_params_recursive(obj, context):
                                    if isinstance(obj, dict):
                                        return {k: resolve_params_recursive(v, context) for k, v in obj.items()}
                                    elif isinstance(obj, list):
                                        return [resolve_params_recursive(item, context) for item in obj]
                                    elif isinstance(obj, str):
                                        return resolve_template(obj, context)
                                    else:
                                        return obj
                                
                                resolved_params = resolve_params_recursive(params, context)
                                
                                logger.debug(f"Calling {action} with params: {resolved_params}")
                                
                                # Use service client by default, or specified client if different
                                call_client = client
                                specified_client = call.get('client', service_name)
                                if specified_client != service_name:
                                    # Only create new client if different from service
                                    call_client = session.client(specified_client, region_name='us-east-1', config=BOTO_CONFIG)
                                
                                response = _retry_call(getattr(call_client, action), **resolved_params)
                                
                                # Save response if specified
                                if save_as:
                                    save_key = resolve_template(save_as, context)
                                    # Apply field extraction if specified
                                    if 'fields' in call:
                                        extracted_data = {}
                                        for field in call['fields']:
                                            value = extract_value(response, field)
                                            if value is not None:
                                                # For array fields like Keys[], store the array directly
                                                if field.endswith('[]'):
                                                    extracted_data = value
                                                else:
                                                    # For other fields, store in a nested structure
                                                    parts = field.split('.')
                                                    current = extracted_data
                                                    for part in parts[:-1]:
                                                        if part not in current:
                                                            current[part] = {}
                                                        current = current[part]
                                                    current[parts[-1]] = value
                                        saved_data[save_key] = extracted_data
                                    else:
                                        saved_data[save_key] = response
                    else:
                        # Regular call - use service client or specified client
                        call_client = client
                        if 'client' in call and call['client'] != service_name:
                            # Only create new client if different from service
                            call_client = session.client(call['client'], region_name='us-east-1', config=BOTO_CONFIG)
                        
                        # Use service client by default, or specified client if different
                        specified_client = call.get('client', service_name)
                        if specified_client != service_name:
                            # Only create new client if different from service
                            call_client = session.client(specified_client, region_name='us-east-1', config=BOTO_CONFIG)
                        
                        response = _retry_call(getattr(call_client, action), **params)
                        if save_as:
                            # Apply field extraction if specified
                            if 'fields' in call:
                                extracted_data = {}
                                for field in call['fields']:
                                    value = extract_value(response, field)
                                    if value is not None:
                                        # For array fields like Keys[], store the array directly
                                        if field.endswith('[]'):
                                            extracted_data = value
                                        else:
                                            # For other fields, store in a nested structure
                                            parts = field.split('.')
                                            current = extracted_data
                                            for part in parts[:-1]:
                                                if part not in current:
                                                    current[part] = {}
                                                current = current[part]
                                            current[parts[-1]] = value
                                saved_data[save_as] = extracted_data
                            else:
                                saved_data[save_as] = response
                            
                except Exception as e:
                    if on_error == 'continue':
                        logger.warning(f"Failed {action}: {e}")
                        continue
                    else:
                        raise
            
            # Process emit
            emit_config = discovery.get('emit', {})
            if 'items_for' in emit_config:
                items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                as_var = emit_config.get('as', 'r')
                
                # Extract items from saved data
                items = extract_value(saved_data, items_path)
                
                results = []
                
                if items:
                    logger.debug(f"Processing {len(items)} items for {discovery_id}")
                    for item in items:
                        context = {as_var: item}
                        context.update(saved_data)
                        logger.debug(f"Context for {as_var}: {context}")
                        logger.debug(f"Saved data keys: {list(saved_data.keys())}")
                        
                        item_data = {}
                        for field_name, field_template in emit_config.get('item', {}).items():
                            logger.debug(f"Processing field {field_name} with template: {field_template}")
                            resolved_value = resolve_template(field_template, context)
                            item_data[field_name] = resolved_value
                            logger.debug(f"Resolved {field_name}: {resolved_value}")
                        
                        results.append(item_data)
                
                discovery_results[discovery_id] = results
            
            elif 'item' in emit_config:
                # Single item
                item_data = {}
                for field_name, field_template in emit_config['item'].items():
                    resolved_value = resolve_template(field_template, saved_data)
                    item_data[field_name] = resolved_value
                discovery_results[discovery_id] = [item_data]
        
        # Process checks
        checks_output = []
        for check in service_rules.get('checks', []):
            check_id = check['rule_id']
            title = check.get('title', '')
            severity = check.get('severity', 'medium')
            assertion_id = check.get('assertion_id', '')
            for_each = check.get('for_each')
            params = check.get('params', {})
            conditions = check.get('conditions', {})
            
            # Get items to check
            # Standardized for_each handling:
            # - String: discovery_id (e.g., 'aws.s3.buckets')
            # - Dict: {'discovery': 'aws.s3.buckets', 'as': 'bucket'} (legacy, 'as' and 'item' ignored)
            if for_each and isinstance(for_each, dict):
                # Dict format (legacy support)
                discovery_id = for_each.get('discovery')
                if discovery_id:
                    items = discovery_results.get(discovery_id, [])
                elif discovery_results:
                    # Fallback to first discovery
                    first_discovery_id = list(discovery_results.keys())[0]
                    items = discovery_results.get(first_discovery_id, [])
                else:
                    items = [{}]
            elif for_each:
                # String format (simplified, recommended)
                items = discovery_results.get(for_each, [])
            else:
                items = [{}]
            
            # Always use 'item' as the standard variable name in context
            for item in items:
                context = {'item': item, 'params': params}
                
                # Evaluate conditions
                def eval_conditions(cond_config):
                    if 'all' in cond_config:
                        return all(eval_conditions(sub_cond) for sub_cond in cond_config['all'])
                    elif 'any' in cond_config:
                        return any(eval_conditions(sub_cond) for sub_cond in cond_config['any'])
                    else:
                        var = cond_config.get('var')
                        op = cond_config.get('op')
                        value = cond_config.get('value')
                        
                        if isinstance(value, str) and '{{' in value:
                            value = resolve_template(value, context)
                        
                        actual_value = extract_value(context, var) if var else None
                        return evaluate_condition(actual_value, op, value)
                
                try:
                    result = eval_conditions(conditions)
                    status = 'PASS' if result else 'FAIL'
                except Exception as e:
                    logger.warning(f"Error evaluating {check_id}: {e}")
                    status = 'ERROR'
                
                record = {
                    'rule_id': check_id,
                    'title': title,
                    'severity': severity,
                    'assertion_id': assertion_id,
                    'result': status,
                    'region': 'us-east-1'
                }
                
                # Add item data
                if item:
                    for key, value in item.items():
                        record[key] = value
                
                checks_output.append(record)
        
        return {
            'inventory': discovery_results,
            'checks': checks_output,
            'service': service_name,
            'scope': 'global'
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Global service {service_name} failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': 'global',
            'unavailable': True,
            'error': str(e)
        }

def run_regional_service(service_name, region, session_override: Optional[boto3.session.Session] = None):
    """Run compliance checks for a regional service"""
    try:
        service_rules = load_service_rules(service_name)
        session = session_override or get_boto3_session(default_region=region)
        boto3_client_name = get_boto3_client_name(service_name)
        client = session.client(boto3_client_name, region_name=region, config=BOTO_CONFIG)
        
        discovery_results = {}
        saved_data = {}
        
        # Process discovery (same as global service)
        for discovery in service_rules.get('discovery', []):
            discovery_id = discovery['discovery_id']
            
            # Process calls in order
            for call in discovery.get('calls', []):
                action = call['action']
                params = call.get('params', {})
                # Auto-generate save_as if not provided
                save_as = call.get('save_as', f'{action}_response')
                for_each = call.get('for_each')
                as_var = call.get('as', 'item')
                # Default to 'continue' for better resilience
                on_error = call.get('on_error', 'continue')
                
                try:
                    if for_each:
                        # Get the items to iterate over
                        items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                        items = extract_value(saved_data, items_ref)
                        
                        if items:
                            for item in items:
                                context = {as_var: item}
                                context.update(saved_data)
                                
                                def resolve_params_recursive(obj, context):
                                    if isinstance(obj, dict):
                                        return {k: resolve_params_recursive(v, context) for k, v in obj.items()}
                                    elif isinstance(obj, list):
                                        return [resolve_params_recursive(item, context) for item in obj]
                                    elif isinstance(obj, str):
                                        return resolve_template(obj, context)
                                    else:
                                        return obj
                                
                                resolved_params = resolve_params_recursive(params, context)
                                
                                # Use service client by default, or specified client if different
                                call_client = client
                                specified_client = call.get('client', service_name)
                                if specified_client != service_name:
                                    # Only create new client if different from service
                                    call_client = session.client(specified_client, region_name=region, config=BOTO_CONFIG)
                                
                                response = _retry_call(getattr(call_client, action), **resolved_params)
                                
                                if save_as:
                                    save_key = resolve_template(save_as, context)
                                    if 'fields' in call:
                                        extracted_data = {}
                                        for field in call['fields']:
                                            value = extract_value(response, field)
                                            if value is not None:
                                                if field.endswith('[]'):
                                                    extracted_data = value
                                                else:
                                                    parts = field.split('.')
                                                    current = extracted_data
                                                    for part in parts[:-1]:
                                                        if part not in current:
                                                            current[part] = {}
                                                        current = current[part]
                                                    current[parts[-1]] = value
                                        saved_data[save_key] = extracted_data
                                    else:
                                        saved_data[save_key] = response
                    else:
                        # Use service client by default, or specified client if different
                        call_client = client
                        specified_client = call.get('client', service_name)
                        if specified_client != service_name:
                            # Only create new client if different from service
                            call_client = session.client(specified_client, region_name=region, config=BOTO_CONFIG)
                        
                        response = _retry_call(getattr(call_client, action), **params)
                        if save_as:
                            if 'fields' in call:
                                extracted_data = {}
                                for field in call['fields']:
                                    value = extract_value(response, field)
                                    if value is not None:
                                        if field.endswith('[]'):
                                            extracted_data = value
                                        else:
                                            parts = field.split('.')
                                            current = extracted_data
                                            for part in parts[:-1]:
                                                if part not in current:
                                                    current[part] = {}
                                                current = current[part]
                                            current[parts[-1]] = value
                                saved_data[save_as] = extracted_data
                            else:
                                saved_data[save_as] = response
                            
                except Exception as e:
                    if on_error == 'continue':
                        logger.warning(f"Failed {action}: {e}")
                        continue
                    else:
                        raise
            
            # Process emit (same as global)
            emit_config = discovery.get('emit', {})
            if 'items_for' in emit_config:
                items_path = emit_config['items_for'].replace('{{ ', '').replace(' }}', '')
                as_var = emit_config.get('as', 'r')
                items = extract_value(saved_data, items_path)
                results = []
                
                if items:
                    for item in items:
                        context = {as_var: item}
                        context.update(saved_data)
                        item_data = {}
                        for field_name, field_template in emit_config.get('item', {}).items():
                            resolved_value = resolve_template(field_template, context)
                            item_data[field_name] = resolved_value
                        results.append(item_data)
                
                discovery_results[discovery_id] = results
            
            elif 'item' in emit_config:
                item_data = {}
                for field_name, field_template in emit_config['item'].items():
                    resolved_value = resolve_template(field_template, saved_data)
                    item_data[field_name] = resolved_value
                discovery_results[discovery_id] = [item_data]
        
        # Process checks (same as global)
        checks_output = []
        for check in service_rules.get('checks', []):
            check_id = check['rule_id']
            title = check.get('title', '')
            severity = check.get('severity', 'medium')
            assertion_id = check.get('assertion_id', '')
            for_each = check.get('for_each')
            params = check.get('params', {})
            conditions = check.get('conditions', {})
            
            # Standardized for_each handling (same as run_global_service)
            if for_each and isinstance(for_each, dict):
                # Dict format (legacy support)
                discovery_id = for_each.get('discovery')
                if discovery_id:
                    items = discovery_results.get(discovery_id, [])
                elif discovery_results:
                    # Fallback to first discovery
                    first_discovery_id = list(discovery_results.keys())[0]
                    items = discovery_results.get(first_discovery_id, [])
                else:
                    items = [{}]
            elif for_each:
                # String format (simplified, recommended)
                items = discovery_results.get(for_each, [])
            else:
                items = [{}]
            
            # Always use 'item' as the standard variable name in context
            for item in items:
                context = {'item': item, 'params': params}
                
                def eval_conditions(cond_config):
                    if 'all' in cond_config:
                        return all(eval_conditions(sub_cond) for sub_cond in cond_config['all'])
                    elif 'any' in cond_config:
                        return any(eval_conditions(sub_cond) for sub_cond in cond_config['any'])
                    else:
                        var = cond_config.get('var')
                        op = cond_config.get('op')
                        value = cond_config.get('value')
                        
                        if isinstance(value, str) and '{{' in value:
                            value = resolve_template(value, context)
                        
                        actual_value = extract_value(context, var) if var else None
                        return evaluate_condition(actual_value, op, value)
                
                try:
                    result = eval_conditions(conditions)
                    status = 'PASS' if result else 'FAIL'
                except Exception as e:
                    logger.warning(f"Error evaluating {check_id}: {e}")
                    status = 'ERROR'
                
                record = {
                    'rule_id': check_id,
                    'title': title,
                    'severity': severity,
                    'assertion_id': assertion_id,
                    'result': status,
                    'region': region
                }
                
                if item:
                    for key, value in item.items():
                        record[key] = value
                
                checks_output.append(record)
        
        return {
            'inventory': discovery_results,
            'checks': checks_output,
            'service': service_name,
            'scope': 'regional',
            'region': region
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Regional service {service_name} in {region} failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': 'regional',
            'region': region,
            'unavailable': True,
            'error': str(e)
        }

def main():
    """Main entry point for the compliance engine"""
    enabled_services = load_enabled_services_with_scope()
    
    if not enabled_services:
        logger.warning("No enabled services found")
        return
    
    logger.info(f"Running compliance checks for {len(enabled_services)} services")
    
    all_results = []
    
    for service_name, scope in enabled_services:
        logger.info(f"Processing {service_name} ({scope})")
        
        if scope == 'global':
            result = run_global_service(service_name)
        else:
            result = run_regional_service(service_name, 'us-east-1')
        
        all_results.append(result)
        
        # Print summary
        if result.get('checks'):
            passed = sum(1 for c in result['checks'] if c['result'] == 'PASS')
            failed = sum(1 for c in result['checks'] if c['result'] == 'FAIL')
            errors = sum(1 for c in result['checks'] if c['result'] == 'ERROR')
            logger.info(f"  Results: {passed} PASS, {failed} FAIL, {errors} ERROR")
    
    logger.info("Compliance check completed")
    
    # Save results to reporting folder
    try:
        # Get account ID for reporting
        account_id = None
        try:
            sts_client = get_boto3_session().client('sts')
            account_id = sts_client.get_caller_identity().get('Account')
        except Exception as e:
            logger.warning(f"Could not get account ID: {e}")
        
        # Save reporting bundle with ARN generation and hierarchical structure
        report_folder = save_reporting_bundle(all_results, account_id)
        logger.info(f"Results saved to reporting folder: {report_folder}")
        
        # Print summary
        total_passed = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'PASS') for result in all_results)
        total_failed = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'FAIL') for result in all_results)
        total_errors = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'ERROR') for result in all_results)
        
        logger.info(f"TOTAL RESULTS: {total_passed} PASS, {total_failed} FAIL, {total_errors} ERROR")
        
    except Exception as e:
        logger.error(f"Failed to save reporting bundle: {e}")
    
    return all_results

if __name__ == "__main__":
    main()
