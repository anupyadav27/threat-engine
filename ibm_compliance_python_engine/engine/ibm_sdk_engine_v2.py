"""
IBM Cloud SDK Compliance Engine V2

Executes compliance checks using REAL IBM Cloud SDK methods.
"""

import json
import os
import logging
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional
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


def get_ibm_client(auth: IBMCloudAuth, service_name: str, package: str = None, client_class: str = None):
    """Get IBM Cloud SDK client for the specified service"""
    
    try:
        if service_name == 'iam':
            return auth.get_iam_identity_service()
        elif service_name == 'vpc':
            return auth.get_vpc_service()
        elif service_name == 'resource_controller':
            return auth.get_resource_controller_service()
        elif service_name == 'cos' or service_name == 'object_storage':
            # Cloud Object Storage would need special setup
            logger.warning(f"COS client not yet implemented")
            return None
        elif service_name == 'databases':
            # Cloud Databases client would need to be added
            logger.warning(f"Databases client not yet implemented")
            return None
        else:
            logger.warning(f"Client for '{service_name}' not yet implemented")
            return None
    except Exception as e:
        logger.error(f"Error creating client for '{service_name}': {e}")
        return None


def execute_discovery_call(
    client: Any,
    action: str,
    params: Dict[str, Any],
    response_path: Optional[str],
    context: Dict[str, Any]
) -> List[Any]:
    """Execute a single discovery SDK call
    
    Args:
        client: IBM SDK client
        action: Method name to call (e.g., 'list_api_keys')
        params: Parameters for the method
        response_path: Path in response to extract resources (e.g., 'apikeys')
        context: Context for template resolution (account_id, etc.)
    
    Returns:
        List of discovered resources
    """
    
    if action == 'self':
        # Skip - manual review required
        logger.debug(f"  Skipping 'self' action - manual review required")
        return []
    
    if not client:
        logger.warning(f"  No client available for action: {action}")
        return []
    
    if not hasattr(client, action):
        logger.warning(f"  Method '{action}' not found on client")
        return []
    
    try:
        # Resolve parameters
        resolved_params = {}
        for key, value in params.items():
            resolved_params[key] = resolve_template(str(value), context)
        
        # Call SDK method
        method = getattr(client, action)
        logger.debug(f"  Calling {action}({resolved_params})")
        
        response = method(**resolved_params)
        
        # Convert to dict
        result = ibm_response_to_dict(response)
        
        # Extract resources from response
        if response_path:
            resources = extract_value(result, response_path)
            if resources and isinstance(resources, list):
                return resources
            elif resources:
                return [resources]
        else:
            # Direct response
            if isinstance(result, list):
                return result
            elif isinstance(result, dict):
                return [result]
        
        return []
        
    except Exception as e:
        logger.error(f"  Error executing {action}: {e}")
        return []


def execute_discovery(
    auth: IBMCloudAuth, 
    service_config: Dict[str, Any], 
    service_name: str,
    context: Dict[str, Any]
) -> Dict[str, List[Any]]:
    """Execute discovery calls to fetch resources"""
    
    discoveries = service_config.get('discovery', [])
    inventory = {}
    
    # Get client
    package = service_config.get('package')
    client_class = service_config.get('client_class')
    client = get_ibm_client(auth, service_name, package, client_class)
    
    for discovery in discoveries:
        discovery_id = discovery.get('discovery_id')
        calls = discovery.get('calls', [])
        
        logger.info(f"  Discovery: {discovery_id}")
        
        for call in calls:
            action = call.get('action')
            params = call.get('params', {})
            response_path = call.get('response_path')
            save_as = call.get('save_as', discovery_id.split('.')[-1])
            
            if call.get('note'):
                logger.debug(f"  Note: {call.get('note')}")
            
            resources = execute_discovery_call(client, action, params, response_path, context)
            
            inventory[save_as] = resources
            logger.info(f"    ✅ Found {len(resources)} {save_as}")
    
    return inventory


def execute_check(
    check: Dict[str, Any], 
    inventory: Dict[str, List[Any]],
    service_name: str
) -> List[Dict[str, Any]]:
    """Execute a single check against inventory"""
    
    check_id = check.get('check_id')
    for_each_key = check.get('for_each', '').split('.')[-1]  # Extract last part (e.g., 'api_keys' from 'iam.api_keys')
    calls = check.get('calls', [])
    
    results = []
    
    # Get resources to check
    resources = inventory.get(for_each_key, [])
    
    if not resources:
        logger.debug(f"    No resources for {for_each_key}")
        return results
    
    # Execute check for each resource
    for resource in resources:
        resource_dict = ibm_response_to_dict(resource) if not isinstance(resource, dict) else resource
        
        # Execute check calls
        check_passed = True
        evidence = {}
        
        for call in calls:
            action = call.get('action')
            fields = call.get('fields', [])
            
            # For 'self' action, evaluate directly on resource
            if action == 'self':
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
                # Other actions would need SDK calls (not implemented yet)
                logger.debug(f"      Skipping non-self action: {action}")
        
        # Create check result
        result = {
            'check_id': check_id,
            'rule_id': check_id,
            'title': check.get('title', ''),
            'severity': check.get('severity', 'medium'),
            'result': 'PASS' if check_passed else 'FAIL',
            'reporting_result': 'PASS' if check_passed else 'FAIL',
            'resource_id': resource_dict.get('id', resource_dict.get('iam_id', '')),
            'resource_name': resource_dict.get('name', ''),
            'resource_crn': get_resource_crn(resource_dict),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            **evidence
        }
        
        results.append(result)
    
    return results


def process_service(
    service_name: str, 
    scope: str, 
    auth: IBMCloudAuth,
    account_id: str
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
    
    # Create context for template resolution
    context = {
        'account_id': account_id,
        'region': auth.region
    }
    
    # Execute discovery
    try:
        inventory = execute_discovery(auth, service_config, service_name, context)
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
            if check.get('note'):
                continue  # Skip checks that need manual review
            
            check_results = execute_check(check, inventory, service_name)
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


def get_account_id(auth: IBMCloudAuth) -> str:
    """Get IBM Cloud account ID"""
    try:
        # Try to get from API keys
        iam_service = auth.get_iam_identity_service()
        response = iam_service.list_api_keys()
        result = ibm_response_to_dict(response)
        
        api_keys = result.get('apikeys', [])
        if api_keys and len(api_keys) > 0:
            return api_keys[0].get('account_id', 'unknown')
        
        return 'unknown'
    except Exception as e:
        logger.warning(f"Could not determine account ID: {e}")
        return 'unknown'


def main():
    """Main entry point for the compliance engine"""
    logger.info("="*80)
    logger.info("IBM Cloud Compliance Engine V2 Starting")
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
    
    # Get account ID
    account_id = get_account_id(auth)
    logger.info(f"Account ID: {account_id}")
    
    enabled_services = load_enabled_services()
    
    if not enabled_services:
        logger.warning("No enabled services found")
        print("⚠️  No services enabled in config/service_list.json")
        return
    
    logger.info(f"Found {len(enabled_services)} enabled services")
    print(f"\n{'='*80}")
    print(f"IBM Cloud Compliance Scan - {len(enabled_services)} services enabled")
    print(f"Account: {account_id}")
    print(f"{'='*80}\n")
    
    # Process services
    all_results = []
    
    for service_name, scope in enabled_services:
        result = process_service(service_name, scope, auth, account_id)
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
        report_folder = save_reporting_bundle(all_results, account_id)
        logger.info(f"Results saved to: {report_folder}")
        
        print(f"\n{'='*80}")
        print(f"✅ IBM Cloud Compliance Scan Complete")
        print(f"{'='*80}")
        print(f"  Account:          {account_id}")
        print(f"  Services scanned: {len(enabled_services)}")
        print(f"  Total checks:     {total_checks}")
        print(f"  Passed:           {total_pass}")
        print(f"  Failed:           {total_fail}")
        print(f"  Report:           {report_folder}")
        print(f"{'='*80}\n")
        
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        import traceback
        traceback.print_exc()
    
    return all_results


if __name__ == "__main__":
    main()





