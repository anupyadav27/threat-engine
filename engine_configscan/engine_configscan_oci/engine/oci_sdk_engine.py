#!/usr/bin/env python3
"""
OCI Compliance Engine - Refactored and Aligned
Follows AWS/Azure/GCP engine patterns for consistency
Dynamic client creation, flattened results, unified discovery+checks
"""

import os
import json
import yaml
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep

import oci
from oci.config import from_file, validate_config

# Import standardized utilities
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.reporting_manager import save_reporting_bundle
from utils.inventory_reporter import save_scan_results

# Setup logging
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, f"compliance_{os.getenv('HOSTNAME', 'local')}.log")
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('compliance-oci')
if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
    fh = logging.FileHandler(log_path)
    fh.setLevel(os.getenv('LOG_LEVEL', 'INFO'))
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(fh)

# Retry/backoff settings
MAX_RETRIES = int(os.getenv('COMPLIANCE_MAX_RETRIES', '5'))
BASE_DELAY = float(os.getenv('COMPLIANCE_BASE_DELAY', '0.8'))
BACKOFF_FACTOR = float(os.getenv('COMPLIANCE_BACKOFF_FACTOR', '2.0'))

# Filters
_SERVICE_FILTER: Set[str] = {s.strip() for s in os.getenv("OCI_ENGINE_FILTER_SERVICES", "").split(",") if s.strip()}
_REGION_FILTER: Set[str] = {s.strip() for s in os.getenv("OCI_ENGINE_FILTER_REGIONS", "").split(",") if s.strip()}
_COMPARTMENT_FILTER: Set[str] = {s.strip() for s in os.getenv("OCI_ENGINE_FILTER_COMPARTMENTS", "").split(",") if s.strip()}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

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


def extract_value(obj: Any, path: str):
    """Extract value from nested object using dot notation"""
    if obj is None:
        return None
    
    parts = path.split('.')
    current = obj
    for idx, part in enumerate(parts):
        if isinstance(current, list):
            result = []
            for item in current:
                sub = extract_value(item, '.'.join(parts[idx:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        
        if part.endswith('[]'):
            key = part[:-2]
            arr = getattr(current, key, None) if hasattr(current, key) else (current.get(key, []) if isinstance(current, dict) else [])
            result = []
            for item in (arr or []):
                sub = extract_value(item, '.'.join(parts[idx+1:]))
                if isinstance(sub, list):
                    result.extend(sub)
                elif sub is not None:
                    result.append(sub)
            return result
        else:
            if isinstance(current, dict):
                current = current.get(part)
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return None
            
            if current is None:
                return None
    
    return current


def evaluate_field(value: Any, operator: str, expected: Any = None) -> bool:
    """Evaluate field condition"""
    if operator == 'exists':
        exists = value is not None and value != '' and value != []
        if expected is None:
            return exists
        return exists == bool(expected)
    elif operator == 'equals':
        return str(value) == str(expected)
    elif operator == 'not_equals':
        return str(value) != str(expected)
    elif operator == 'contains':
        if isinstance(value, list):
            return expected in value
        return str(expected) in (str(value) if value is not None else '')
    elif operator == 'not_contains':
        if isinstance(value, list):
            return expected not in value
        return str(expected) not in (str(value) if value is not None else '')
    elif operator == 'gt':
        try:
            return float(value) > float(expected)
        except:
            return False
    elif operator == 'gte':
        try:
            return float(value) >= float(expected)
        except:
            return False
    else:
        logger.warning(f"Unknown operator: {operator}")
        return False


# ============================================================================
# CONFIGURATION
# ============================================================================

def load_enabled_services() -> List[str]:
    """Load enabled services from services directory"""
    services_dir = Path(__file__).parent.parent / "services"
    enabled_services = []
    
    try:
        for service_dir in services_dir.iterdir():
            if service_dir.is_dir() and service_dir.name != '__pycache__':
                service_name = service_dir.name
                rules_file = service_dir / "rules" / f"{service_name}.yaml"
                
                if rules_file.exists():
                    enabled_services.append(service_name)
    except Exception as e:
        logger.error(f"Failed to load services: {e}")
    
    if _SERVICE_FILTER:
        enabled_services = [s for s in enabled_services if s in _SERVICE_FILTER]
        logger.info(f"Filtered to services: {', '.join(enabled_services)}")
    
    return sorted(enabled_services)


def load_service_rules(service_name: str) -> Dict[str, Any]:
    """Load service YAML rules"""
    rules_path = Path(__file__).parent.parent / "services" / service_name / "rules" / f"{service_name}.yaml"
    
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    
    # Handle both flat and nested structures
    if service_name in rules:
        return rules[service_name]
    return rules


def get_oci_config(config_file='~/.oci/config', profile='DEFAULT'):
    """Load and validate OCI configuration"""
    config = from_file(os.path.expanduser(config_file), profile)
    validate_config(config)
    return config


def discover_compartments(config: Dict) -> List[Dict]:
    """Discover all compartments (accounts)"""
    compartments = []
    
    try:
        identity = oci.identity.IdentityClient(config)
        tenancy_id = config['tenancy']
        
        # Add root compartment
        tenancy = identity.get_tenancy(tenancy_id).data
        compartments.append({
            'id': tenancy_id,
            'name': tenancy.name or 'Root',
            'type': 'root'
        })
        
        # List all child compartments
        all_compartments = identity.list_compartments(
            compartment_id=tenancy_id,
            compartment_id_in_subtree=True
        ).data
        
        for comp in all_compartments:
            if comp.lifecycle_state == 'ACTIVE':
                compartments.append({
                    'id': comp.id,
                    'name': comp.name,
                    'type': 'compartment'
                })
        
        if _COMPARTMENT_FILTER:
            compartments = [c for c in compartments if c['id'] in _COMPARTMENT_FILTER]
            logger.info(f"Filtered to compartments: {len(compartments)}")
        
        logger.info(f"Discovered {len(compartments)} compartments")
        return compartments
        
    except Exception as e:
        logger.error(f"Failed to discover compartments: {e}")
        # Return at least root tenancy
        return [{'id': config.get('tenancy'), 'name': 'Default', 'type': 'root'}]


def discover_regions(config: Dict) -> List[str]:
    """Discover all available regions"""
    regions = []
    
    try:
        identity = oci.identity.IdentityClient(config)
        region_subscriptions = identity.list_region_subscriptions(config['tenancy']).data
        
        for region_sub in region_subscriptions:
            if region_sub.is_home_region or region_sub.status == 'READY':
                regions.append(region_sub.region_name)
        
        if _REGION_FILTER:
            regions = [r for r in regions if r in _REGION_FILTER]
            logger.info(f"Filtered to regions: {', '.join(regions)}")
        
        if not regions:
            regions = [config.get('region', 'us-ashburn-1')]
        
        logger.info(f"Using regions: {', '.join(regions)}")
        return regions
        
    except Exception as e:
        logger.error(f"Failed to discover regions: {e}")
        return [config.get('region', 'us-ashburn-1')]


# ============================================================================
# DYNAMIC CLIENT FACTORY
# ============================================================================

def get_service_client(service_name: str, region: str, config: Dict) -> Any:
    """
    Dynamically create OCI service client
    Pattern: oci.<service>.<ServiceClient>
    """
    # Update config for this region
    region_config = dict(config)
    region_config['region'] = region
    
    # Client mapping for OCI SDK
    client_mapping = {
        'object_storage': ('object_storage', 'ObjectStorageClient'),
        'identity': ('identity', 'IdentityClient'),
        'compute': ('core', 'ComputeClient'),
        'virtual_network': ('core', 'VirtualNetworkClient'),
        'block_storage': ('core', 'BlockstorageClient'),
        'database': ('database', 'DatabaseClient'),
        'container_engine': ('container_engine', 'ContainerEngineClient'),
        'monitoring': ('monitoring', 'MonitoringClient'),
        'audit': ('audit', 'AuditClient'),
        'key_management': ('key_management', 'KmsVaultClient'),
        'logging': ('logging', 'LoggingManagementClient'),
        'events': ('events', 'EventsClient'),
        'file_storage': ('file_storage', 'FileStorageClient'),
        'load_balancer': ('load_balancer', 'LoadBalancerClient'),
        'dns': ('dns', 'DnsClient'),
        'functions': ('functions', 'FunctionsManagementClient'),
        'streaming': ('streaming', 'StreamAdminClient'),
        'ons': ('ons', 'NotificationControlPlaneClient'),
        'vault': ('vault', 'VaultsClient'),
        'nosql': ('nosql', 'NosqlClient'),
        'mysql': ('mysql', 'DbSystemClient'),
        'redis': ('redis', 'RedisClusterClient'),
        'queue': ('queue', 'QueueAdminClient'),
        'waf': ('waf', 'WafClient'),
        'apigateway': ('apigateway', 'GatewayClient'),
        'analytics': ('analytics', 'AnalyticsClient'),
        'ai_language': ('ai_language', 'AIServiceLanguageClient'),
        'ai_anomaly_detection': ('ai_anomaly_detection', 'AnomalyDetectionClient'),
        'artifacts': ('artifacts', 'ArtifactsClient'),
        'bds': ('bds', 'BdsClient'),
        'certificates': ('certificates', 'CertificatesManagementClient'),
        'cloud_guard': ('cloud_guard', 'CloudGuardClient'),
        'container_instances': ('container_instances', 'ContainerInstanceClient'),
        'data_catalog': ('data_catalog', 'DataCatalogClient'),
        'data_flow': ('data_flow', 'DataFlowClient'),
        'data_integration': ('data_integration', 'DataIntegrationClient'),
        'data_safe': ('data_safe', 'DataSafeClient'),
        'data_science': ('data_science', 'DataScienceClient'),
        'devops': ('devops', 'DevopsClient'),
        'edge_services': ('healthchecks', 'HealthChecksClient'),
        'network_firewall': ('network_firewall', 'NetworkFirewallClient'),
        'resource_manager': ('resource_manager', 'ResourceManagerClient'),
    }
    
    if service_name not in client_mapping:
        logger.warning(f"Unknown service: {service_name}")
        return None
    
    try:
        module_name, class_name = client_mapping[service_name]
        module = getattr(oci, module_name)
        client_class = getattr(module, class_name)
        return client_class(region_config)
    except Exception as e:
        logger.warning(f"Failed to create client for {service_name}: {e}")
        return None


# ============================================================================
# GENERIC SERVICE RUNNER - Unified Discovery + Checks
# ============================================================================

def run_service_compliance(service_name: str, compartment_id: str, compartment_name: str, region: str, config: Dict) -> Dict[str, Any]:
    """
    Generic service scanner - unified discovery and checks
    Follows AWS/Azure/GCP pattern for consistency
    """
    try:
        rules = load_service_rules(service_name)
    except Exception as e:
        return {
            'service': service_name,
            'compartment_id': compartment_id,
            'compartment_name': compartment_name,
            'region': region,
            'inventory': {},
            'checks': [],
            'error': f'Failed to load rules: {str(e)}'
        }
    
    # Get client
    client = get_service_client(service_name, region, config)
    if not client:
        return {
            'service': service_name,
            'compartment_id': compartment_id,
            'compartment_name': compartment_name,
            'region': region,
            'inventory': {},
            'checks': [],
            'unavailable': True
        }
    
    # DISCOVERY PHASE
    discovery_results: Dict[str, List[Any]] = {}
    
    for disc in rules.get('discovery', []):
        disc_id = disc.get('discovery_id', '')
        discovery_results[disc_id] = []
        
        for call in disc.get('calls', []):
            action = call.get('action', '')
            method = call.get('method', '')
            fields = call.get('fields', [])
            
            try:
                # Execute OCI SDK call
                if hasattr(client, method):
                    def _execute():
                        # Special handling for object storage
                        if service_name == 'object_storage' and method == 'list_buckets':
                            namespace = client.get_namespace().data
                            return getattr(client, method)(
                                namespace_name=namespace,
                                compartment_id=compartment_id
                            ).data
                        else:
                            # Standard OCI SDK call
                            return getattr(client, method)(compartment_id=compartment_id).data
                    
                    result = _retry_call(_execute)
                    
                    # Extract fields from result
                    for resource in (result if isinstance(result, list) else [result]):
                        extracted = {}
                        for field in fields:
                            path = field.get('path', '')
                            var_name = field.get('var', path)
                            extracted[var_name] = extract_value(resource, path)
                        discovery_results[disc_id].append(extracted)
                
            except Exception as e:
                logger.warning(f"Discovery {disc_id} action '{method}' failed: {e}")
                discovery_results[disc_id] = []
    
    # CHECKS PHASE
    checks_output: List[Dict[str, Any]] = []
    
    for check in rules.get('checks', []):
        check_id = check.get('check_id', '')
        title = check.get('title', '')
        severity = check.get('severity', 'medium')
        for_each = check.get('for_each', '')
        logic = check.get('logic', 'AND').upper()
        
        # Get resources to check
        resources = discovery_results.get(for_each, [])
        
        if not resources:
            # No resources found - skip check
            checks_output.append({
                'check_id': check_id,
                'title': title,
                'severity': severity.upper(),
                'result': 'SKIPPED',
                'resource_id': 'N/A',
                'resource_name': 'N/A',
                'compartment_id': compartment_id,
                'compartment_name': compartment_name,
                'region': region,
                'service': service_name,
                'details': 'No resources found for this check'
            })
            continue
        
        # Evaluate each resource
        for resource in resources:
            try:
                call_results = []
                
                for call in check.get('calls', []):
                    action = call.get('action', '')
                    fields = call.get('fields', [])
                    
                    if action == 'eval':
                        # Evaluate fields on resource
                        field_results = []
                        for fld in fields:
                            path = fld.get('path', '')
                            operator = fld.get('operator', 'exists')
                            expected = fld.get('expected')
                            
                            value = extract_value(resource, path)
                            
                            if isinstance(value, list):
                                res = all(evaluate_field(v, operator, expected) for v in value)
                            else:
                                res = evaluate_field(value, operator, expected)
                            
                            field_results.append(res)
                        
                        # Combine field results
                        call_results.append(all(field_results) if field_results else False)
                
                # Final check result based on logic
                if logic == 'OR':
                    final_result = any(call_results) if call_results else False
                else:
                    final_result = all(call_results) if call_results else False
                
                checks_output.append({
                    'check_id': check_id,
                    'title': title,
                    'severity': severity.upper(),
                    'result': 'PASS' if final_result else 'FAIL',
                    'resource_id': resource.get('bucket_id') or resource.get('id', 'unknown'),
                    'resource_name': resource.get('display_name') or resource.get('name', 'unknown'),
                    'compartment_id': compartment_id,
                    'compartment_name': compartment_name,
                    'region': region,
                    'service': service_name,
                    'details': f"Check {'passed' if final_result else 'failed'}"
                })
                
            except Exception as e:
                logger.error(f"Check {check_id} failed: {e}")
                checks_output.append({
                    'check_id': check_id,
                    'title': title,
                    'severity': severity.upper(),
                    'result': 'ERROR',
                    'resource_id': 'unknown',
                    'resource_name': 'unknown',
                    'compartment_id': compartment_id,
                    'compartment_name': compartment_name,
                    'region': region,
                    'service': service_name,
                    'details': f'Error: {str(e)}'
                })
    
    return {
        'service': service_name,
        'compartment_id': compartment_id,
        'compartment_name': compartment_name,
        'region': region,
        'inventory': discovery_results,
        'checks': checks_output,
        'scope': rules.get('scope', 'regional')
    }


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def run_for_compartment(compartment: Dict, regions: List[str], enabled_services: List[str], config: Dict) -> List[Dict[str, Any]]:
    """Run all enabled services for a compartment across all regions"""
    outputs: List[Dict[str, Any]] = []
    compartment_id = compartment['id']
    compartment_name = compartment['name']
    
    logger.info(f"Scanning compartment: {compartment_name}")
    
    for region in regions:
        logger.info(f"  Region: {region}")
        
        for service_name in enabled_services:
            try:
                result = run_service_compliance(
                    service_name,
                    compartment_id,
                    compartment_name,
                    region,
                    config
                )
                outputs.append(result)
                
                # Log summary
                if result.get('checks'):
                    passed = sum(1 for c in result['checks'] if c['result'] == 'PASS')
                    failed = sum(1 for c in result['checks'] if c['result'] == 'FAIL')
                    logger.info(f"    {service_name}: {passed} PASS, {failed} FAIL")
                
            except Exception as e:
                logger.error(f"Service {service_name} failed: {e}")
                outputs.append({
                    'service': service_name,
                    'compartment_id': compartment_id,
                    'compartment_name': compartment_name,
                    'region': region,
                    'inventory': {},
                    'checks': [],
                    'error': str(e)
                })
    
    return outputs


def main():
    """Main entry point - scan all compartments, regions, services"""
    logger.info("OCI Compliance Engine - Starting comprehensive scan")
    print("\n" + "="*80)
    print("OCI Compliance Engine - Refactored")
    print("="*80)
    
    # Load configuration
    config = get_oci_config()
    
    # Discover environment
    compartments = discover_compartments(config)
    regions = discover_regions(config)
    enabled_services = load_enabled_services()
    
    print(f"\nScan Configuration:")
    print(f"  Compartments: {len(compartments)}")
    print(f"  Regions: {len(regions)}")
    print(f"  Services: {len(enabled_services)}")
    print(f"  Services: {', '.join(enabled_services[:10])}{'...' if len(enabled_services) > 10 else ''}")
    print()
    
    # Execute scans
    all_outputs: List[Dict[str, Any]] = []
    
    with ThreadPoolExecutor(max_workers=int(os.getenv('COMPLIANCE_ENGINE_MAX_WORKERS', '8'))) as ex:
        futures = []
        for compartment in compartments:
            futures.append(ex.submit(run_for_compartment, compartment, regions, enabled_services, config))
        
        for fut in as_completed(futures):
            try:
                all_outputs.extend(fut.result())
            except Exception as e:
                logger.error(f"Compartment scan failed: {e}")
    
    # Save results using standardized reporting
    try:
        # Get tenancy ID for reporting
        tenancy_id = config.get('tenancy', 'unknown')
        
        # Save reporting bundle
        report_folder = save_reporting_bundle(all_outputs, tenancy_id)
        logger.info(f"Results saved to: {report_folder}")
        
        # Print summary
        total_passed = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'PASS') for result in all_outputs)
        total_failed = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'FAIL') for result in all_outputs)
        total_errors = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'ERROR') for result in all_outputs)
        total_skipped = sum(sum(1 for c in result.get('checks', []) if c['result'] == 'SKIPPED') for result in all_outputs)
        
        print(f"\n{'='*80}")
        print("Scan Complete")
        print(f"{'='*80}")
        print(f"Total Checks: {total_passed + total_failed + total_errors + total_skipped}")
        print(f"  PASS: {total_passed}")
        print(f"  FAIL: {total_failed}")
        print(f"  ERROR: {total_errors}")
        print(f"  SKIPPED: {total_skipped}")
        print(f"{'='*80}")
        print(f"Results: {report_folder}")
        print(f"{'='*80}\n")
        
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
    
    return all_outputs


if __name__ == '__main__':
    main()
