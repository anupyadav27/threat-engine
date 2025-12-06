"""
OCI Compliance Engine

Main execution engine for running OCI compliance checks using OCI SDK.
Based on GCP engine pattern but adapted for OCI.
"""

import os
import json
import logging
import yaml
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# OCI SDK imports
import oci
from oci.config import from_file, validate_config

logger = logging.getLogger('oci-engine')

# Configuration
MAX_WORKERS = int(os.getenv("COMPLIANCE_ENGINE_MAX_WORKERS", "16"))
REGION_MAX_WORKERS = int(os.getenv("COMPLIANCE_ENGINE_REGION_MAX_WORKERS", "8"))

# Optional filters (env-driven)
_SERVICE_FILTER: Set[str] = {s.strip() for s in (os.getenv("OCI_ENGINE_FILTER_SERVICES", "").split(",")) if s.strip()}
_REGION_FILTER: Set[str] = {s.strip() for s in (os.getenv("OCI_ENGINE_FILTER_REGIONS", "").split(",")) if s.strip()}
_CHECK_ID_FILTER: Set[str] = {s.strip() for s in (os.getenv("OCI_ENGINE_FILTER_CHECK_IDS", "").split(",")) if s.strip()}


def extract_value(obj: Any, path: str) -> Any:
    """
    Extract value from nested object using dot notation
    
    Args:
        obj: OCI response object or dict
        path: Dot-notation path (e.g., 'display_name' or 'defined_tags.Environment')
        
    Returns:
        Extracted value or None
    """
    if obj is None:
        return None
    
    parts = path.split('.')
    current = obj
    
    for idx, part in enumerate(parts):
        # Handle lists
        if isinstance(current, list):
            result = []
            for item in current:
                sub = extract_value(item, '.'.join(parts[idx:]))
                if sub is not None:
                    result.extend(sub if isinstance(sub, list) else [sub])
            return result if result else None
        
        # Handle array notation
        if part.endswith('[]'):
            key = part[:-2]
            arr = getattr(current, key, None) if hasattr(current, key) else (current.get(key, []) if isinstance(current, dict) else [])
            result = []
            for item in (arr or []):
                sub = extract_value(item, '.'.join(parts[idx+1:]))
                if sub is not None:
                    result.extend(sub if isinstance(sub, list) else [sub])
            return result if result else None
        
        # Handle OCI objects (with attributes)
        if hasattr(current, part):
            current = getattr(current, part)
        # Handle dicts
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        
        if current is None:
            return None
    
    return current


def evaluate_field(value: Any, operator: str, expected: Any = None) -> bool:
    """
    Evaluate field condition
    
    Args:
        value: Value to evaluate
        operator: Comparison operator (exists, equals, contains, not_equals)
        expected: Expected value
        
    Returns:
        True if condition met, False otherwise
    """
    if operator == 'exists':
        if expected is None:
            return value is not None
        return (value is not None and value != '' and value != [] and value != {}) if expected else not value
    
    if operator == 'equals':
        return value == expected
    
    if operator == 'not_equals':
        return value != expected
    
    if operator == 'contains':
        if isinstance(value, list):
            return expected in value
        if isinstance(value, dict):
            return expected in value
        return str(expected) in (str(value) if value is not None else '')
    
    if operator == 'not_contains':
        if isinstance(value, list):
            return expected not in value
        if isinstance(value, dict):
            return expected not in value
        return str(expected) not in (str(value) if value is not None else '')
    
    return False


def oci_object_to_dict(obj: Any) -> Dict[str, Any]:
    """
    Convert OCI response object to dictionary
    
    Args:
        obj: OCI response object
        
    Returns:
        Dictionary representation
    """
    if obj is None:
        return {}
    
    if isinstance(obj, dict):
        return obj
    
    if isinstance(obj, list):
        return [oci_object_to_dict(item) for item in obj]
    
    if hasattr(obj, '__dict__'):
        result = {}
        for key, value in obj.__dict__.items():
            if not key.startswith('_'):
                if isinstance(value, (str, int, float, bool, type(None))):
                    result[key] = value
                elif isinstance(value, list):
                    result[key] = [oci_object_to_dict(item) for item in value]
                elif hasattr(value, '__dict__'):
                    result[key] = oci_object_to_dict(value)
                else:
                    result[key] = str(value)
        return result
    
    if hasattr(obj, 'data'):
        return oci_object_to_dict(obj.data)
    
    return str(obj)


def load_service_catalog() -> List[Dict[str, Any]]:
    """Load service catalog from config"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return data.get("services", [])


def load_service_rules(service_name: str) -> Dict[str, Any]:
    """Load service rules YAML"""
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, "rules", f"{service_name}.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    return rules.get(service_name, {})


def get_enabled_services() -> List[Tuple[str, str]]:
    """Get enabled services from catalog"""
    catalog = load_service_catalog()
    enabled = []
    for svc in catalog:
        if svc.get("enabled", False):
            name = svc["name"]
            scope = svc.get("scope", "regional")
            # Apply service filter if set
            if _SERVICE_FILTER and name not in _SERVICE_FILTER:
                continue
            enabled.append((name, scope))
    return enabled


def get_oci_regions(config: dict) -> List[str]:
    """Get list of OCI regions"""
    try:
        identity = oci.identity.IdentityClient(config)
        regions = identity.list_regions().data
        region_names = [r.name for r in regions]
        
        # Apply region filter if set
        if _REGION_FILTER:
            region_names = [r for r in region_names if r in _REGION_FILTER]
        
        return region_names
    except Exception as e:
        logger.warning(f"Failed to list regions: {e}")
        # Return home region as fallback
        return [config.get('region', 'us-ashburn-1')]


def get_compartments(config: dict) -> List[Dict[str, str]]:
    """Get list of compartments"""
    try:
        identity = oci.identity.IdentityClient(config)
        tenancy_id = config.get('tenancy')
        
        compartments = []
        # Add root compartment
        compartments.append({
            'id': tenancy_id,
            'name': 'root',
            'compartment_id': tenancy_id
        })
        
        # List all compartments
        response = identity.list_compartments(
            compartment_id=tenancy_id,
            compartment_id_in_subtree=True,
            lifecycle_state='ACTIVE'
        )
        
        for comp in response.data:
            compartments.append({
                'id': comp.id,
                'name': comp.name,
                'compartment_id': comp.compartment_id
            })
        
        return compartments
    except Exception as e:
        logger.error(f"Failed to list compartments: {e}")
        return [{'id': config.get('tenancy'), 'name': 'root', 'compartment_id': config.get('tenancy')}]


def create_client(client_name: str, config: dict, region: Optional[str] = None) -> Any:
    """
    Create OCI SDK client
    
    Args:
        client_name: Name of client class (e.g., 'IdentityClient')
        config: OCI config dict
        region: Optional region override
        
    Returns:
        OCI client instance
    """
    # Override region if specified
    if region and region != config.get('region'):
        config = dict(config)
        config['region'] = region
    
    # Map client names to OCI SDK modules
    client_mapping = {
        'IdentityClient': oci.identity.IdentityClient,
        'ComputeClient': oci.core.ComputeClient,
        'BlockstorageClient': oci.core.BlockstorageClient,
        'DatabaseClient': oci.database.DatabaseClient,
        'ObjectStorageClient': oci.object_storage.ObjectStorageClient,
        'VirtualNetworkClient': oci.core.VirtualNetworkClient,
        'ContainerEngineClient': oci.container_engine.ContainerEngineClient,
        'KmsVaultClient': oci.key_management.KmsVaultClient,
        'KmsManagementClient': oci.key_management.KmsManagementClient,
        'LoadBalancerClient': oci.load_balancer.LoadBalancerClient,
        'MonitoringClient': oci.monitoring.MonitoringClient,
        'AuditClient': oci.audit.AuditClient,
        'FunctionsClient': oci.functions.FunctionsManagementClient,
        'EventsClient': oci.events.EventsClient,
    }
    
    client_class = client_mapping.get(client_name)
    if not client_class:
        raise ValueError(f"Unknown client: {client_name}")
    
    return client_class(config)


def run_discovery(
    service_name: str,
    rules: Dict[str, Any],
    config: dict,
    compartments: List[Dict[str, str]],
    region: Optional[str] = None
) -> Tuple[Dict[str, List[Any]], Dict[str, Dict[str, Any]]]:
    """
    Run discovery for a service
    
    Returns:
        (discovery_results, discovered_vars)
    """
    discovery_results: Dict[str, List[Any]] = {}
    discovered_vars: Dict[str, Dict[str, Any]] = {}
    
    for discovery in rules.get('discovery', []):
        discovery_id = discovery['discovery_id']
        
        try:
            for call in discovery.get('calls', []):
                action = call.get('action')
                client_name = call.get('client')
                method_name = call.get('method')
                
                if not client_name or not method_name:
                    continue
                
                # Create client
                client = create_client(client_name, config, region)
                
                if action == 'list':
                    # List resources across all compartments
                    resources = []
                    for comp in compartments:
                        try:
                            method = getattr(client, method_name)
                            # Try to call with compartment_id
                            response = method(compartment_id=comp['id'])
                            
                            # Extract data
                            items = response.data if hasattr(response, 'data') else []
                            for item in items:
                                resource_dict = oci_object_to_dict(item)
                                # Extract fields
                                for field in call.get('fields', []):
                                    var_name = field.get('var')
                                    path = field.get('path')
                                    if var_name and path:
                                        value = extract_value(item, path)
                                        resource_dict[var_name] = value
                                resources.append(resource_dict)
                        except Exception as e:
                            logger.debug(f"Discovery {discovery_id} failed for compartment {comp['name']}: {e}")
                            continue
                    
                    discovery_results[discovery_id] = resources
                    logger.info(f"  Discovery {discovery_id}: {len(resources)} resources")
                
                elif action == 'get':
                    # Get details for previously discovered resources
                    for_each = discovery.get('for_each')
                    if not for_each or for_each not in discovery_results:
                        continue
                    
                    for resource in discovery_results[for_each]:
                        try:
                            resource_id = resource.get(f"{discovery['resource_type']}_id")
                            if not resource_id:
                                continue
                            
                            method = getattr(client, method_name)
                            # Call get method with resource ID
                            response = method(resource_id)
                            item = response.data if hasattr(response, 'data') else response
                            
                            # Extract fields into discovered_vars
                            for field in call.get('fields', []):
                                var_name = field.get('var')
                                path = field.get('path')
                                if var_name and path:
                                    value = extract_value(item, path)
                                    discovered_vars.setdefault(resource_id, {})[var_name] = value
                        except Exception as e:
                            logger.debug(f"Get details failed for {resource_id}: {e}")
                            continue
        
        except Exception as e:
            logger.warning(f"Discovery {discovery_id} failed: {e}")
            discovery_results[discovery_id] = []
    
    return discovery_results, discovered_vars


def run_checks(
    service_name: str,
    rules: Dict[str, Any],
    config: dict,
    discovery: Dict[str, List[Any]],
    discovered_vars: Dict[str, Dict[str, Any]],
    region: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Run checks for a service"""
    checks_out = []
    
    for check in rules.get('checks', []):
        check_id = check.get('check_id')
        
        # Apply check filter
        if _CHECK_ID_FILTER and check_id not in _CHECK_ID_FILTER:
            continue
        
        for_each = check.get('for_each')
        resources = discovery.get(for_each, [])
        logic = (check.get('logic') or 'AND').upper()
        
        def eval_resource(resource):
            try:
                call_results: List[bool] = []
                
                for call in check.get('calls', []):
                    action = call.get('action')
                    
                    if action == 'eval':
                        # Evaluate fields from discovered data
                        field_results: List[bool] = []
                        for field in call.get('fields', []):
                            path = field.get('path')
                            operator = field.get('operator')
                            expected = field.get('expected')
                            
                            # Try to get value from resource or discovered_vars
                            value = extract_value(resource, path)
                            if value is None:
                                resource_id = resource.get('id') or resource.get('name')
                                if resource_id in discovered_vars:
                                    value = discovered_vars[resource_id].get(path)
                            
                            result = evaluate_field(value, operator, expected)
                            field_results.append(result)
                        
                        call_results.append(all(field_results) if field_results else False)
                
                # Evaluate logic
                if logic == 'OR':
                    final = any(call_results) if call_results else False
                else:  # AND
                    final = all(call_results) if call_results else False
                
                return {
                    'rule_id': check_id,
                    'title': check.get('title', ''),
                    'severity': check.get('severity', 'medium'),
                    'resource_id': resource.get('id') or resource.get('name'),
                    'resource_name': resource.get('display_name') or resource.get('name'),
                    'compartment_id': resource.get('compartment_id'),
                    'region': region,
                    'result': 'PASS' if final else 'FAIL',
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
            except Exception as e:
                logger.debug(f"Check {check_id} failed for resource: {e}")
                return None
        
        # Parallel evaluation
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(eval_resource, r) for r in resources]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    checks_out.append(result)
    
    return checks_out


def run_service(
    service_name: str,
    scope: str,
    config: dict,
    compartments: List[Dict[str, str]],
    regions: List[str]
) -> Dict[str, Any]:
    """
    Run compliance checks for a service
    
    Returns:
        Service results dict
    """
    logger.info(f"Running service: {service_name} ({scope})")
    
    try:
        rules = load_service_rules(service_name)
    except Exception as e:
        logger.error(f"Failed to load rules for {service_name}: {e}")
        return {
            'service': service_name,
            'scope': scope,
            'status': 'error',
            'message': f'Failed to load rules: {e}',
            'inventory': {},
            'checks': []
        }
    
    if scope == 'global':
        # Run once for global services
        discovery, discovered_vars = run_discovery(service_name, rules, config, compartments)
        checks = run_checks(service_name, rules, config, discovery, discovered_vars)
        
        return {
            'service': service_name,
            'scope': scope,
            'status': 'completed',
            'inventory': discovery,
            'checks': checks
        }
    
    else:  # regional
        all_discovery = {}
        all_checks = []
        
        def run_region(region):
            discovery, discovered_vars = run_discovery(service_name, rules, config, compartments, region)
            checks = run_checks(service_name, rules, config, discovery, discovered_vars, region)
            return region, discovery, checks
        
        # Parallel region execution
        with ThreadPoolExecutor(max_workers=REGION_MAX_WORKERS) as executor:
            futures = [executor.submit(run_region, r) for r in regions]
            for future in as_completed(futures):
                region, discovery, checks = future.result()
                all_discovery[region] = discovery
                all_checks.extend(checks)
        
        return {
            'service': service_name,
            'scope': scope,
            'status': 'completed',
            'inventory': all_discovery,
            'checks': all_checks
        }


def run_engine(config: dict) -> List[Dict[str, Any]]:
    """
    Main engine entry point
    
    Args:
        config: OCI configuration dict
        
    Returns:
        List of service results
    """
    logger.info("="*80)
    logger.info("OCI Compliance Engine Starting")
    logger.info("="*80)
    
    # Get compartments
    compartments = get_compartments(config)
    logger.info(f"Found {len(compartments)} compartments")
    
    # Get regions
    regions = get_oci_regions(config)
    logger.info(f"Scanning {len(regions)} regions")
    
    # Get enabled services
    enabled_services = get_enabled_services()
    logger.info(f"Enabled services: {len(enabled_services)}")
    
    all_results = []
    
    for service_name, scope in enabled_services:
        try:
            result = run_service(service_name, scope, config, compartments, regions)
            all_results.append(result)
            logger.info(f"✅ {service_name}: {len(result.get('checks', []))} checks")
        except Exception as e:
            logger.error(f"❌ {service_name}: {e}")
            all_results.append({
                'service': service_name,
                'scope': scope,
                'status': 'error',
                'message': str(e),
                'inventory': {},
                'checks': []
            })
    
    logger.info("="*80)
    logger.info("OCI Compliance Engine Complete")
    logger.info("="*80)
    
    return all_results

