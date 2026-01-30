"""
IBM Cloud SDK Compliance Engine

Main engine for executing compliance checks against IBM Cloud infrastructure.
"""

import json
import os
import logging
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.reporting_manager import save_reporting_bundle
from utils.ibm_helpers import (
    extract_value, 
    resolve_template, 
    evaluate_condition,
    ibm_response_to_dict,
    get_resource_crn
)
from auth.ibm_auth import IBMCloudAuth

# Setup logging
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, f"compliance_{os.getenv('HOSTNAME', 'local')}.log")
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('ibm-compliance')
if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
    fh = logging.FileHandler(log_path)
    fh.setLevel(os.getenv('LOG_LEVEL', 'INFO'))
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(fh)


def load_enabled_services():
    """Load enabled services from configuration"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "regional")) for s in data["services"] if s.get("enabled")]


def load_service_rules(service_name: str) -> Optional[Dict[str, Any]]:
    """Load service rules from YAML file"""
    rules_path = os.path.join(
        os.path.dirname(__file__), 
        "..", 
        "services", 
        service_name, 
        "rules", 
        f"{service_name}.yaml"
    )
    
    if not os.path.exists(rules_path):
        logger.warning(f"Rules file not found: {rules_path}")
        return None
    
    try:
        with open(rules_path, 'r') as f:
            data = yaml.safe_load(f)
            return data.get(service_name) if data else None
    except Exception as e:
        logger.error(f"Error loading rules for {service_name}: {e}")
        return None


def execute_discovery(auth: IBMCloudAuth, service_config: Dict[str, Any], service_name: str) -> Dict[str, List[Any]]:
    """
    Execute discovery calls to fetch resources
    
    Returns:
        Dictionary mapping discovery_id to list of resources
    """
    discoveries = service_config.get('discovery', [])
    inventory = {}
    
    for discovery in discoveries:
        discovery_id = discovery.get('discovery_id')
        calls = discovery.get('calls', [])
        
        logger.info(f"  Running discovery: {discovery_id}")
        
        for call in calls:
            client_name = call.get('client', service_name)
            action = call.get('action')
            save_as = call.get('save_as', discovery_id)
            
            try:
                # Get the appropriate client
                client = get_ibm_client(auth, client_name, service_name)
                
                if client is None:
                    logger.warning(f"    Client '{client_name}' not available")
                    inventory[save_as] = []
                    continue
                
                # Get the method from client
                if hasattr(client, action):
                    method = getattr(client, action)
                    
                    # Execute the method
                    response = method()
                    
                    # Convert response to dict
                    result = ibm_response_to_dict(response)
                    
                    # Extract resources from response
                    if isinstance(result, dict):
                        resources = (result.get('resources') or 
                                   result.get('items') or 
                                   result.get('results') or
                                   result.get('data') or
                                   [result])  # If single resource
                    elif isinstance(result, list):
                        resources = result
                    else:
                        resources = [result]
                    
                    inventory[save_as] = resources
                    logger.info(f"    ✅ Found {len(resources)} {save_as}")
                else:
                    logger.warning(f"    Method '{action}' not found on client")
                    inventory[save_as] = []
                    
            except Exception as e:
                logger.error(f"    Error in discovery {discovery_id}: {e}")
                inventory[save_as] = []
    
    return inventory


def execute_check(
    auth: IBMCloudAuth, 
    check: Dict[str, Any], 
    inventory: Dict[str, List[Any]],
    service_name: str
) -> List[Dict[str, Any]]:
    """
    Execute a single check against inventory
    
    Returns:
        List of check results
    """
    check_id = check.get('check_id')
    for_each = check.get('for_each')
    calls = check.get('calls', [])
    
    results = []
    
    # Get resources to check
    resources = inventory.get(for_each, [])
    
    if not resources:
        logger.debug(f"    No resources found for {for_each}")
        return results
    
    # Execute check for each resource
    for resource in resources:
        resource_dict = ibm_response_to_dict(resource)
        
        # Execute check calls
        check_passed = True
        evidence = {}
        
        for call in calls:
            client_name = call.get('client', service_name)
            action = call.get('action')
            params = call.get('params', {})
            fields = call.get('fields', [])
            
            try:
                # Resolve parameters from resource context
                resolved_params = {}
                for key, value in params.items():
                    resolved_params[key] = resolve_template(value, resource_dict)
                
                # If action is 'eval', evaluate directly on resource
                if action == 'eval':
                    for field in fields:
                        path = field.get('path')
                        operator = field.get('operator', 'exists')
                        expected = field.get('expected', True)
                        
                        value = extract_value(resource_dict, path)
                        passed = evaluate_condition(value, operator, expected)
                        
                        evidence[path] = value
                        
                        if not passed:
                            check_passed = False
                else:
                    # Execute SDK call
                    client = get_ibm_client(auth, client_name, service_name)
                    
                    if client and hasattr(client, action):
                        method = getattr(client, action)
                        response = method(**resolved_params)
                        result = ibm_response_to_dict(response)
                        
                        # Evaluate fields
                        for field in fields:
                            path = field.get('path')
                            operator = field.get('operator', 'exists')
                            expected = field.get('expected', True)
                            
                            value = extract_value(result, path)
                            passed = evaluate_condition(value, operator, expected)
                            
                            evidence[path] = value
                            
                            if not passed:
                                check_passed = False
                    else:
                        check_passed = False
                        
            except Exception as e:
                logger.debug(f"      Check execution error: {e}")
                check_passed = False
        
        # Create check result
        result = {
            'check_id': check_id,
            'rule_id': check_id,
            'title': check.get('title', ''),
            'severity': check.get('severity', 'medium'),
            'result': 'PASS' if check_passed else 'FAIL',
            'reporting_result': 'PASS' if check_passed else 'FAIL',
            'resource_id': resource_dict.get('id', ''),
            'resource_name': resource_dict.get('name', ''),
            'resource_crn': get_resource_crn(resource_dict),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            **evidence
        }
        
        results.append(result)
    
    return results


def get_ibm_client(auth: IBMCloudAuth, client_name: str, service_name: str) -> Any:
    """Get IBM Cloud client for the specified service"""
    
    try:
        if client_name == 'iam_identity' or client_name == 'iam':
            return auth.get_iam_identity_service()
        elif client_name == 'iam_policy':
            # Would need to import and create IAM Policy service
            return None  # Placeholder
        elif client_name == 'iam_access_groups':
            # Would need to import and create IAM Access Groups service
            return None  # Placeholder
        elif client_name == 'vpc':
            return auth.get_vpc_service()
        elif client_name == 'resource_controller':
            return auth.get_resource_controller_service()
        else:
            # Generic client creation would go here
            return None
    except Exception as e:
        logger.error(f"Error creating client '{client_name}': {e}")
        return None


def process_service(
    service_name: str, 
    scope: str, 
    auth: IBMCloudAuth
) -> Dict[str, Any]:
    """Process a single service"""
    
    logger.info(f"Processing {service_name} ({scope})")
    print(f"  ⏳ Scanning {service_name}...")
    
    # Load service rules
    service_config = load_service_rules(service_name)
    
    if not service_config:
        return {
            'service': service_name,
            'scope': scope,
            'inventory': {},
            'checks': [],
            'status': 'no_rules',
            'message': 'Service rules not found'
        }
    
    # Execute discovery
    try:
        inventory = execute_discovery(auth, service_config, service_name)
    except Exception as e:
        logger.error(f"  Discovery failed for {service_name}: {e}")
        return {
            'service': service_name,
            'scope': scope,
            'inventory': {},
            'checks': [],
            'status': 'discovery_failed',
            'message': str(e)
        }
    
    # Execute checks
    all_checks = []
    checks = service_config.get('checks', [])
    
    logger.info(f"  Executing {len(checks)} checks...")
    
    for check in checks:
        try:
            check_results = execute_check(auth, check, inventory, service_name)
            all_checks.extend(check_results)
        except Exception as e:
            logger.error(f"  Check {check.get('check_id')} failed: {e}")
    
    total_pass = sum(1 for c in all_checks if c.get('result') == 'PASS')
    total_fail = sum(1 for c in all_checks if c.get('result') == 'FAIL')
    
    print(f"     ✅ {service_name} - {total_pass} passed, {total_fail} failed")
    
    return {
        'service': service_name,
        'scope': scope,
        'inventory': {k: len(v) for k, v in inventory.items()},
        'checks': all_checks,
        'status': 'completed',
        'message': f'{total_pass} passed, {total_fail} failed'
    }


def main():
    """Main entry point for the compliance engine"""
    logger.info("="*80)
    logger.info("IBM Cloud Compliance Engine Starting")
    logger.info("="*80)
    
    # Initialize auth
    try:
        auth = IBMCloudAuth()
        if not auth.test_connection():
            logger.error("IBM Cloud authentication test failed")
            print("❌ IBM Cloud authentication failed. Please check your credentials.")
            return
        logger.info("✅ IBM Cloud authentication successful")
        print("✅ IBM Cloud authentication successful")
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        print(f"❌ IBM Cloud authentication failed: {e}")
        print("\nPlease ensure:")
        print("  1. IBM_CLOUD_API_KEY environment variable is set")
        print("  2. API key is valid")
        print("  3. User has required permissions")
        return
    
    enabled_services = load_enabled_services()
    
    if not enabled_services:
        logger.warning("No enabled services found")
        print("⚠️  No services enabled in config/service_list.json")
        return
    
    logger.info(f"Found {len(enabled_services)} enabled services")
    print(f"\n{'='*80}")
    print(f"IBM Cloud Compliance Scan - {len(enabled_services)} services enabled")
    print(f"{'='*80}\n")
    
    # Process services
    all_results = []
    max_workers = int(os.getenv('COMPLIANCE_ENGINE_MAX_WORKERS', '4'))
    
    # For now, process sequentially to avoid rate limits
    for service_name, scope in enabled_services:
        result = process_service(service_name, scope, auth)
        all_results.append(result)
    
    logger.info("="*80)
    logger.info("Compliance scan completed")
    logger.info("="*80)
    
    # Calculate totals
    total_checks = sum(len(r.get('checks', [])) for r in all_results)
    total_pass = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'PASS') for r in all_results)
    total_fail = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'FAIL') for r in all_results)
    
    # Save results
    try:
        report_folder = save_reporting_bundle(all_results, None)
        logger.info(f"Results saved to: {report_folder}")
        
        print(f"\n{'='*80}")
        print(f"✅ IBM Cloud Compliance Scan Complete")
        print(f"{'='*80}")
        print(f"  Services scanned: {len(enabled_services)}")
        print(f"  Total checks:     {total_checks}")
        print(f"  Passed:           {total_pass}")
        print(f"  Failed:           {total_fail}")
        print(f"  Report:           {report_folder}")
        print(f"{'='*80}\n")
        
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
    
    return all_results


if __name__ == "__main__":
    main()
