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

from utils.inventory_reporter import save_scan_results
from utils.inventory_reporter import save_split_scan_results
from utils.reporting_manager import save_reporting_bundle
from auth.aws_auth import get_boto3_session, get_session_for_account
import threading
import re

# Ensure logs directory exists and set up file logger
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, f"compliance_{os.getenv('HOSTNAME', 'local')}.log")
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('compliance-boto3')
if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
    fh = logging.FileHandler(log_path)
    fh.setLevel(os.getenv('LOG_LEVEL', 'INFO'))
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(fh)

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
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, "rules", f"{service_name}.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
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
        client = session.client(service_name, region_name='us-east-1', config=BOTO_CONFIG)
        
        discovery_results = {}
        saved_data = {}
        
        # Process discovery
        for discovery in service_rules.get('discovery', []):
            discovery_id = discovery['discovery_id']
            
            # Process calls in order
            for call in discovery.get('calls', []):
                action = call['action']
                params = call.get('params', {})
                save_as = call.get('save_as')
                for_each = call.get('for_each')
                as_var = call.get('as', 'u')
                on_error = call.get('on_error', 'fail')
                
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
                                
                                # Make API call - handle different clients
                                call_client = client
                                if 'client' in call:
                                    call_client = session.client(call['client'], region_name='us-east-1', config=BOTO_CONFIG)
                                
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
                        # Regular call - handle different clients
                        call_client = client
                        if 'client' in call:
                            call_client = session.client(call['client'], region_name='us-east-1', config=BOTO_CONFIG)
                        
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
            items = discovery_results.get(for_each, []) if for_each else [{}]
            
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
        logger.error(f"Global service {service_name} failed: {e}")
        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': 'global',
            'unavailable': True,
            'error': str(e)
        }

def run_regional_service(service_name, region, session_override: Optional[boto3.session.Session] = None):
    # Similar to global but with region
    return run_global_service(service_name, session_override)

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
