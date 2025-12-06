"""
AliCloud SDK Compliance Engine

Main engine for executing compliance checks against AliCloud infrastructure.
Based on AWS boto3_engine_simple.py with AliCloud SDK adaptations.
"""

import json
import os
import yaml
import logging
import re
import sys
from typing import Any, List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.inventory_reporter import save_scan_results, save_split_scan_results
from utils.reporting_manager import save_reporting_bundle
from utils.alicloud_helpers import extract_value, resolve_template, make_api_call
from auth.alicloud_auth import AliCloudAuth, get_alicloud_client

# Setup logging
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, f"compliance_{os.getenv('HOSTNAME', 'local')}.log")
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('alicloud-compliance')
if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
    fh = logging.FileHandler(log_path)
    fh.setLevel(os.getenv('LOG_LEVEL', 'INFO'))
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(fh)

# Retry/backoff settings
MAX_RETRIES = int(os.getenv('COMPLIANCE_MAX_RETRIES', '5'))
BASE_DELAY = float(os.getenv('COMPLIANCE_BASE_DELAY', '0.8'))
BACKOFF_FACTOR = float(os.getenv('COMPLIANCE_BACKOFF_FACTOR', '2.0'))


def evaluate_condition(value: Any, operator: str, expected: Any = None) -> bool:
    """
    Evaluate a condition with the given operator and expected value
    
    Args:
        value: Actual value
        operator: Comparison operator
        expected: Expected value
        
    Returns:
        Boolean result of evaluation
    """
    if operator == 'exists':
        return value is not None and value != '' and value != []
    elif operator == 'not_exists':
        return value is None or value == '' or value == []
    elif operator == 'equals':
        return value == expected
    elif operator == 'not_equals':
        return value != expected
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
    elif operator == 'contains':
        if isinstance(value, (list, str)):
            return expected in value
        return False
    elif operator == 'not_contains':
        if isinstance(value, (list, str)):
            return expected not in value
        return False
    elif operator == 'is_true':
        return bool(value)
    elif operator == 'is_false':
        return not bool(value)
    elif operator == 'is_empty':
        return not value or len(value) == 0
    elif operator == 'is_not_empty':
        return bool(value) and len(value) > 0
    elif operator == 'in':
        if isinstance(expected, list):
            return value in expected
        return False
    elif operator == 'not_in':
        if isinstance(expected, list):
            return value not in expected
        return False
    else:
        logger.warning(f"Unknown operator: {operator}")
        return False


def load_enabled_services_with_scope():
    """Load enabled services from configuration"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "regional")) for s in data["services"] if s.get("enabled")]


def load_service_rules(service_name):
    """Load service rules from YAML file"""
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, "rules", f"{service_name}.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    return rules


def _retry_call(func, *args, **kwargs):
    """Retry a function call with exponential backoff"""
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            delay = BASE_DELAY * (BACKOFF_FACTOR ** attempt)
            logger.debug(f"Retrying after error: {e} (attempt {attempt+1}/{MAX_RETRIES}, sleep {delay:.2f}s)")
            sleep(delay)


def run_global_service(service_name, auth_override: Optional[AliCloudAuth] = None):
    """
    Run compliance checks for a global service
    
    Args:
        service_name: Name of the service
        auth_override: Optional auth override
        
    Returns:
        Dictionary with inventory and check results
    """
    try:
        service_rules = load_service_rules(service_name)
        auth = auth_override or AliCloudAuth()
        client = auth.get_client()
        
        discovery_results = {}
        saved_data = {}
        
        # Process discovery
        for discovery in service_rules.get('discovery', []):
            discovery_id = discovery['discovery_id']
            
            # Process API calls in order
            for call in discovery.get('calls', []):
                product = call.get('product', service_name)
                version = call['version']
                action = call['action']
                params = call.get('params', {})
                save_as = call.get('save_as')
                for_each = call.get('for_each')
                as_var = call.get('as', 'item')
                on_error = call.get('on_error', 'fail')
                
                try:
                    if for_each:
                        # Iterate over items
                        items_ref = for_each.replace('{{ ', '').replace(' }}', '')
                        items = extract_value(saved_data, items_ref)
                        
                        if items:
                            for item in items:
                                context = {as_var: item}
                                context.update(saved_data)
                                
                                # Resolve parameters
                                resolved_params = {}
                                for key, val in params.items():
                                    resolved_params[key] = resolve_template(str(val), context)
                                
                                logger.debug(f"Calling {product}.{action} with params: {resolved_params}")
                                
                                response = _retry_call(
                                    make_api_call,
                                    client,
                                    product,
                                    version,
                                    action,
                                    resolved_params
                                )
                                
                                if save_as:
                                    save_key = resolve_template(save_as, context)
                                    saved_data[save_key] = response
                    else:
                        # Regular call
                        response = _retry_call(
                            make_api_call,
                            client,
                            product,
                            version,
                            action,
                            params
                        )
                        
                        if save_as:
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
                
                items = extract_value(saved_data, items_path)
                results = []
                
                if items:
                    logger.debug(f"Processing {len(items)} items for {discovery_id}")
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
            if for_each:
                items = discovery_results.get(for_each, [])
            else:
                items = [{}]
            
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
                    'region': auth.region
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


def run_regional_service(service_name, region, auth_override: Optional[AliCloudAuth] = None):
    """
    Run compliance checks for a regional service
    
    Args:
        service_name: Name of the service
        region: Region to scan
        auth_override: Optional auth override
        
    Returns:
        Dictionary with inventory and check results
    """
    # For regional services, create auth with specific region
    if auth_override:
        auth = auth_override
    else:
        auth = AliCloudAuth(region=region)
    
    return run_global_service(service_name, auth)


def main():
    """Main entry point for the compliance engine"""
    logger.info("="*80)
    logger.info("AliCloud Compliance Engine Starting")
    logger.info("="*80)
    
    enabled_services = load_enabled_services_with_scope()
    
    if not enabled_services:
        logger.warning("No enabled services found")
        return
    
    logger.info(f"Running compliance checks for {len(enabled_services)} services")
    
    all_results = []
    
    # Initialize auth
    try:
        auth = AliCloudAuth()
        logger.info(f"Authenticated for region: {auth.region}")
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        return
    
    for service_name, scope in enabled_services:
        logger.info(f"Processing {service_name} ({scope})")
        
        try:
            if scope == 'global':
                result = run_global_service(service_name, auth)
            else:
                # For regional services, scan current region
                result = run_regional_service(service_name, auth.region, auth)
            
            all_results.append(result)
            
            # Print summary
            if result.get('checks'):
                passed = sum(1 for c in result['checks'] if c['result'] == 'PASS')
                failed = sum(1 for c in result['checks'] if c['result'] == 'FAIL')
                errors = sum(1 for c in result['checks'] if c['result'] == 'ERROR')
                logger.info(f"  Results: {passed} PASS, {failed} FAIL, {errors} ERROR")
            else:
                logger.warning(f"  No checks executed for {service_name}")
                
        except Exception as e:
            logger.error(f"Failed to process {service_name}: {e}")
            all_results.append({
                'inventory': {},
                'checks': [],
                'service': service_name,
                'scope': scope,
                'unavailable': True,
                'error': str(e)
            })
    
    logger.info("="*80)
    logger.info("Compliance check completed")
    logger.info("="*80)
    
    # Save results
    try:
        # Save reporting bundle
        report_folder = save_reporting_bundle(all_results, None)
        logger.info(f"Results saved to reporting folder: {report_folder}")
        
        # Print summary
        total_passed = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'PASS') for result in all_results)
        total_failed = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'FAIL') for result in all_results)
        total_errors = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'ERROR') for result in all_results)
        
        logger.info(f"TOTAL RESULTS: {total_passed} PASS, {total_failed} FAIL, {total_errors} ERROR")
        
        print("\n" + "="*80)
        print(f"✅ AliCloud Compliance Scan Complete")
        print("="*80)
        print(f"  Passed:  {total_passed}")
        print(f"  Failed:  {total_failed}")
        print(f"  Errors:  {total_errors}")
        print(f"  Total:   {total_passed + total_failed + total_errors}")
        print("="*80)
        print(f"  Report: {report_folder}")
        print("="*80)
        
    except Exception as e:
        logger.error(f"Failed to save reporting bundle: {e}")
    
    return all_results


if __name__ == "__main__":
    main()

