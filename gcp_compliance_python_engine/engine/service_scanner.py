"""
GCP Service Scanner - Core service-level scanning

Aligned with AWS and Azure service_scanner.py
Uses GCP Discovery API and google-cloud SDKs
"""

import json
import os
import yaml
import logging
import re
from typing import Any, List, Dict, Optional
from time import sleep
from google.api_core.exceptions import GoogleAPIError

logger = logging.getLogger('gcp-service-scanner')

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


def resolve_template(text: str, context: Dict[str, Any]) -> Any:
    """Resolve template variables like {{ variable }} in text"""
    if not isinstance(text, str) or '{{' not in text:
        return text
    
    def replace_var(match):
        var_path = match.group(1).strip()
        value = extract_value(context, var_path)
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
    """Load enabled GCP services from config"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    if not os.path.exists(config_path):
        # Try YAML format
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.yaml")
        with open(config_path) as f:
            data = yaml.safe_load(f)
    else:
        with open(config_path) as f:
            data = json.load(f)
    
    return [(s["name"], s.get("scope", "global")) for s in data["services"] if s.get("enabled")]


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


def get_gcp_api_client(service_name: str, api_version: str, credentials=None):
    """Get GCP API client for a service"""
    from googleapiclient.discovery import build
    from auth.gcp_auth import _get_credentials, _CLOUD_PLATFORM_RO_SCOPE
    
    if credentials is None:
        credentials = _get_credentials([_CLOUD_PLATFORM_RO_SCOPE])
    
    return build(service_name, api_version, credentials=credentials, cache_discovery=False)


def call_gcp_api(client, action: str, **params):
    """Call GCP API action with parameters"""
    # For simpler actions without dots, try direct call
    if '.' not in action:
        # Try to build the resource path first
        # e.g., getAccessApprovalSettings -> projects().getAccessApprovalSettings()
        if 'name' in params:
            # Use projects() for most services
            try:
                projects_resource = client.projects()
                method = getattr(projects_resource, action, None)
                if method:
                    request = method(**params)
                    response = request.execute()
                    return response
            except Exception:
                pass
        
        # Try direct method call
        method = getattr(client, action, None)
        if method:
            request = method(**params)
            response = request.execute()
            return response
    
    # Parse action to get method chain (e.g., "projects.list" -> client.projects().list())
    parts = action.split('.')
    
    # Build the method chain
    current = client
    for part in parts[:-1]:
        current = getattr(current, part)()
    
    # Get the final method
    method = getattr(current, parts[-1])
    
    # Call with parameters
    request = method(**params)
    
    # Execute the request
    response = request.execute()
    
    return response


def run_service_scan(
    service_name: str,
    project_id: str,
    region: Optional[str] = None,
    credentials=None
) -> Dict[str, Any]:
    """
    Run compliance scan for a GCP service
    
    Args:
        service_name: GCP service name (e.g., 'storage', 'compute')
        project_id: GCP project ID
        region: GCP region (optional, for regional services)
        credentials: GCP credentials (optional, will create if not provided)
    
    Returns:
        Scan results with inventory and checks
    """
    try:
        service_rules = load_service_rules(service_name)
        
        if credentials is None:
            from auth.gcp_auth import _get_credentials, _CLOUD_PLATFORM_RO_SCOPE
            credentials = _get_credentials([_CLOUD_PLATFORM_RO_SCOPE])
        
        # Get service-specific configuration
        service_config = service_rules.get(service_name, {})
        api_name = service_config.get('api_name', service_name)
        api_version = service_config.get('api_version', 'v1')
        project_param_format = service_config.get('project_param_format', 'projects/{{project_id}}')
        
        # Resolve project parameter
        project_param = project_param_format.replace('{{project_id}}', project_id)
        
        # Get API client
        client = get_gcp_api_client(api_name, api_version, credentials)
        
        discovery_results = {}
        saved_data = {}
        
        # Process discovery
        for discovery in service_config.get('discovery', []):
            discovery_id = discovery['discovery_id']
            discovery_items = []
            
            # Process calls in order
            for call in discovery.get('calls', []):
                action = call['action']
                params = call.get('params', {})
                
                # Resolve template variables in params
                resolved_params = {}
                for key, value in params.items():
                    if isinstance(value, str):
                        resolved_params[key] = resolve_template(value, {'project_id': project_id, 'region': region})
                    else:
                        resolved_params[key] = value
                
                # Add project parameter if not present
                if 'name' not in resolved_params and 'parent' not in resolved_params:
                    resolved_params['name'] = project_param
                
                try:
                    # Call GCP API
                    response = _retry_call(call_gcp_api, client, action, **resolved_params)
                    
                    # Extract fields if specified
                    fields = call.get('fields', [])
                    if fields:
                        item_data = {}
                        for field in fields:
                            path = field['path']
                            var = field.get('var', path)
                            value = extract_value(response, path)
                            item_data[var] = value
                            saved_data[var] = value
                        discovery_items.append(item_data)
                    else:
                        # Store entire response
                        discovery_items.append(response)
                        saved_data.update(response if isinstance(response, dict) else {})
                
                except Exception as e:
                    logger.warning(f"Discovery {discovery_id} call {action} failed: {e}")
                    # Continue with empty result
                    discovery_items.append({})
            
            discovery_results[discovery_id] = discovery_items
        
        # Process checks
        checks_output = []
        
        for check in service_config.get('checks', []):
            check_id = check['check_id']
            title = check.get('title', '')
            severity = check.get('severity', 'medium')
            for_each = check.get('for_each')
            logic = check.get('logic', 'AND')
            
            # Get items to check
            items_to_check = discovery_results.get(for_each, [{}])
            
            if not items_to_check:
                # No resources found, skip check
                checks_output.append({
                    'check_id': check_id,
                    'title': title,
                    'severity': severity,
                    'result': 'SKIP',
                    'reason': 'No resources found',
                    'project': project_id,
                    'region': region or 'global'
                })
                continue
            
            # Evaluate check for each item
            for item in items_to_check:
                # Merge item with saved_data for context
                context = {**saved_data, **item}
                
                # Evaluate conditions
                call_results = []
                for call in check.get('calls', []):
                    action = call['action']
                    
                    if action == 'eval':
                        # Evaluate fields
                        field_results = []
                        for field in call.get('fields', []):
                            path = field['path']
                            operator = field['operator']
                            expected = field.get('expected')
                            
                            value = extract_value(context, path)
                            result = evaluate_condition(value, operator, expected)
                            field_results.append(result)
                        
                        # All fields must pass for this call to pass
                        call_results.append(all(field_results))
                
                # Apply logic (AND/OR)
                if logic == 'OR':
                    final_result = any(call_results) if call_results else False
                else:  # AND
                    final_result = all(call_results) if call_results else False
                
                checks_output.append({
                    'check_id': check_id,
                    'title': title,
                    'severity': severity,
                    'result': 'PASS' if final_result else 'FAIL',
                    'project': project_id,
                    'region': region or 'global',
                    'resource_id': item.get('resource_name') or item.get('name') or 'unknown'
                })
        
        return {
            'inventory': discovery_results,
            'checks': checks_output,
            'service': service_name,
            'scope': 'global' if not region else 'regional',
            'project': project_id,
            'region': region or 'global'
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Service {service_name} failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'inventory': {},
            'checks': [],
            'service': service_name,
            'scope': 'global' if not region else 'regional',
            'project': project_id,
            'region': region or 'global',
            'unavailable': True,
            'error': str(e)
        }


def run_global_service(service_name, project_id, credentials=None):
    """Run compliance checks for a global GCP service"""
    return run_service_scan(service_name, project_id, region=None, credentials=credentials)


def run_regional_service(service_name, region, project_id, credentials=None):
    """Run compliance checks for a regional GCP service"""
    return run_service_scan(service_name, project_id, region=region, credentials=credentials)


def main():
    """Main entry point for single project scan"""
    enabled_services = load_enabled_services_with_scope()
    
    if not enabled_services:
        logger.warning("No enabled services found")
        return
    
    # Get project from environment
    from auth.gcp_auth import get_default_project_id
    project_id = os.getenv('GCP_PROJECT') or get_default_project_id()
    
    if not project_id:
        logger.error("GCP_PROJECT environment variable required or gcloud default project")
        return
    
    logger.info(f"Running compliance checks for {len(enabled_services)} services")
    logger.info(f"Project: {project_id}")
    
    all_results = []
    
    for service_name, scope in enabled_services:
        logger.info(f"Processing {service_name} ({scope})")
        
        if scope == 'global':
            result = run_global_service(service_name, project_id)
        else:
            # For regional, default to us-central1
            result = run_regional_service(service_name, 'us-central1', project_id)
        
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
        report_folder = save_reporting_bundle(all_results, project_id=project_id)
        logger.info(f"Results saved to: {report_folder}")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")
    
    return all_results


if __name__ == "__main__":
    main()
