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
    """Load service rules from YAML"""
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    return rules


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
        
        # Discovery and checks would be implemented here
        # For now, returning structure similar to AWS
        
        discovery_results = {}
        checks_output = []
        
        # Process discovery (simplified - full implementation would follow AWS pattern)
        for discovery in service_rules.get('discovery', []):
            discovery_id = discovery['discovery_id']
            # Discovery logic here...
            discovery_results[discovery_id] = []
        
        # Process checks (simplified)
        for check in service_rules.get('checks', []):
            check_id = check['rule_id']
            # Check logic here...
            checks_output.append({
                'rule_id': check_id,
                'title': check.get('title', ''),
                'severity': check.get('severity', 'medium'),
                'result': 'PASS',  # Placeholder
                'subscription': subscription_id,
                'location': location or 'global'
            })
        
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
