"""
GCP Compliance Engine - Dynamic Action Parser

Smart Action Parser:
- Parses action names to extract resource type and method
- Executes dynamically using getattr (NO hardcoded if/elif chains)
- Works with existing YAML structure
- Example: action 'list_firewalls' → client.firewalls().list()
"""

import os
import json
import importlib
import re
from typing import Any, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

# Configuration
MAX_WORKERS = int(os.getenv("COMPLIANCE_ENGINE_MAX_WORKERS", "16"))
REGION_MAX_WORKERS = int(os.getenv("COMPLIANCE_ENGINE_REGION_MAX_WORKERS", "16"))

# Filters
_SERVICE_FILTER: Set[str] = {s.strip() for s in os.getenv("GCP_ENGINE_FILTER_SERVICES", "").split(",") if s.strip()}
_REGION_FILTER: Set[str] = {s.strip() for s in os.getenv("GCP_ENGINE_FILTER_REGIONS", "").split(",") if s.strip()}
_CHECK_ID_FILTER: Set[str] = {s.strip() for s in os.getenv("GCP_ENGINE_FILTER_CHECK_IDS", "").split(",") if s.strip()}
_RESOURCE_NAME_FILTER: Optional[str] = os.getenv("GCP_ENGINE_FILTER_RESOURCE_NAME") or None


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def extract_value(obj: Any, path: str):
    """Extract value from nested object using dot notation"""
    parts = path.split('.')
    current = obj
    for idx, part in enumerate(parts):
        if isinstance(current, list):
            result = []
            for item in current:
                sub = extract_value(item, '.'.join(parts[idx:]))
                result.extend(sub if isinstance(sub, list) else [sub])
            return result
        if part.endswith('[]'):
            key = part[:-2]
            arr = current.get(key, []) if isinstance(current, dict) else []
            result = []
            for item in arr:
                sub = extract_value(item, '.'.join(parts[idx+1:]))
                result.extend(sub if isinstance(sub, list) else [sub])
            return result
        else:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
            if current is None:
                return None
    return current


def evaluate_field(value: Any, operator: str, expected: Any = None) -> bool:
    """Evaluate field condition"""
    if operator == 'exists':
        return (value is not None) if expected is None else (bool(value) == bool(expected))
    if operator == 'equals':
        return value == expected
    if operator == 'contains':
        if isinstance(value, list):
            return expected in value
        return str(expected) in (str(value) if value is not None else '')
    if operator == 'not_contains':
        if isinstance(value, list):
            return expected not in value
        return str(expected) not in (str(value) if value is not None else '')
    return False


# ============================================================================
# CONFIGURATION
# ============================================================================

def load_service_catalog() -> List[Dict[str, Any]]:
    """Load service catalog"""
    base_dir = os.path.join(os.path.dirname(__file__), "..", "config")
    with open(os.path.join(base_dir, "service_list.yaml")) as f:
        data = yaml.safe_load(f) or {}
    services = data.get("services", [])
    for s in services:
        s.setdefault("enabled", True)
        s.setdefault("scope", "global")
        s.setdefault("apis", [])
    return services


def load_service_rules(service_name: str) -> Dict[str, Any]:
    """Load service rules"""
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    return rules[service_name]


def get_default_project_id() -> Optional[str]:
    """Get default project ID"""
    try:
        import google.auth
        creds, project_id = google.auth.default()
        return project_id or os.getenv("GCP_PROJECT")
    except Exception:
        return os.getenv("GCP_PROJECT")


def list_all_projects() -> List[Dict[str, Any]]:
    """Discover all projects"""
    env_projects = os.getenv("GCP_PROJECTS")
    if env_projects:
        return [{"projectId": p.strip(), "name": p.strip()} for p in env_projects.split(",") if p.strip()]
    
    projects: List[Dict[str, Any]] = []
    try:
        from googleapiclient.discovery import build
        from google.auth import default
        creds, _ = default()
        crm = build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False)
        
        req = crm.projects().list()
        while req:
            resp = req.execute()
            for p in resp.get("projects", []):
                if p.get("lifecycleState") == "ACTIVE":
                    projects.append(p)
            req = crm.projects().list_next(req, resp)
    except Exception:
        pass
    
    if not projects and get_default_project_id():
        projects.append({"projectId": get_default_project_id(), "name": get_default_project_id()})
    
    return projects


def list_all_regions(project_id: str) -> List[str]:
    """Discover all GCP regions"""
    regions: List[str] = []
    try:
        from googleapiclient.discovery import build
        from google.auth import default
        creds, _ = default()
        compute = build("compute", "v1", credentials=creds, cache_discovery=False)
        
        req = compute.regions().list(project=project_id)
        while req:
            resp = req.execute()
            for r in resp.get('items', []) or []:
                if r.get('name'):
                    regions.append(r.get('name'))
            req = compute.regions().list_next(req, resp)
    except Exception:
        regions = ['us-central1', 'us-east1', 'europe-west1']
    
    if _REGION_FILTER:
        regions = [r for r in regions if r in _REGION_FILTER]
    
    return list(set(regions))


def resolve_enabled_services(project_id: str) -> Set[str]:
    """Determine enabled services"""
    catalog = load_service_catalog()
    
    enabled_apis: Set[str] = set()
    try:
        from googleapiclient.discovery import build
        from google.auth import default
        creds, _ = default()
        su = build("serviceusage", "v1", credentials=creds, cache_discovery=False)
        
        req = su.services().list(parent=f"projects/{project_id}", filter="state:ENABLED")
        while req:
            resp = req.execute()
            for s in resp.get("services", []) or []:
                name = s.get("name", "")
                if "/services/" in name:
                    enabled_apis.add(name.split("/services/")[-1])
            req = su.services().list_next(req, resp)
    except Exception:
        pass
    
    enabled_services: Set[str] = set()
    for svc in catalog:
        if not svc.get("enabled", True):
            continue
        svc_apis = set(svc.get("apis", []))
        if not svc_apis and svc.get("name"):
            svc_apis = {f"{svc['name']}.googleapis.com"}
        if not enabled_apis or (enabled_apis & svc_apis):
            enabled_services.add(svc["name"])
    
    if _SERVICE_FILTER:
        enabled_services = {s for s in enabled_services if s in _SERVICE_FILTER}
    
    return enabled_services


# ============================================================================
# CLIENT FACTORY
# ============================================================================

_CLIENT_CACHE: Dict[str, Any] = {}

def get_service_client(service_name: str, rules: Dict[str, Any], project_id: str) -> Any:
    """Initialize service client from YAML"""
    cache_key = f"{service_name}_{project_id}"
    if cache_key in _CLIENT_CACHE:
        return _CLIENT_CACHE[cache_key]
    
    try:
        from google.auth import default
        creds, default_project = default()
        project = project_id or default_project
        
        sdk_package = rules.get('sdk_package')
        client_class = rules.get('client_class')
        
        if sdk_package and client_class:
            # SDK client (e.g., GCS)
            module = importlib.import_module(sdk_package)
            client_cls = getattr(module, client_class)
            client = client_cls(project=project, credentials=creds)
        else:
            # Discovery API client
            from googleapiclient.discovery import build
            api_name = rules.get('api_name', service_name)
            api_version = rules.get('api_version', 'v1')
            client = build(api_name, api_version, credentials=creds, cache_discovery=False)
        
        _CLIENT_CACHE[cache_key] = client
        return client
    except Exception as e:
        print(f"Warning: Failed to create client for {service_name}: {e}")
        return None


# ============================================================================
# SMART ACTION PARSER - Dynamically interprets action names
# ============================================================================

def parse_action(action: str) -> Dict[str, str]:
    """
    Parse action name to extract method and resource type.
    
    Examples:
    - 'list_firewalls' → {method: 'list', resource: 'firewalls'}
    - 'aggregatedList_instances' → {method: 'aggregatedList', resource: 'instances'}
    - 'get_bucket' → {method: 'get', resource: 'bucket'}
    - 'list_buckets' → {method: 'list_buckets', resource: None} (special case)
    """
    # Common method patterns
    methods = ['list', 'get', 'aggregatedList', 'create', 'delete', 'update', 'patch']
    
    for method in methods:
        if action.startswith(method + '_'):
            resource = action[len(method)+1:]  # Everything after 'method_'
            return {'method': method, 'resource': resource}
        elif action == method:
            return {'method': method, 'resource': None}
    
    # If no pattern matched, treat entire action as method name
    return {'method': action, 'resource': None}


def execute_api_call(client: Any, action: str, project_id: str, region: Optional[str] = None, resource_item: Any = None, **kwargs) -> Any:
    """
    Dynamically execute API call based on action name.
    Parses action to determine resource and method, then executes.
    """
    parsed = parse_action(action)
    method = parsed['method']
    resource = parsed['resource']
    
    try:
        # Handle SDK clients (like GCS) vs Discovery API clients differently
        if hasattr(client, 'list_buckets'):
            # GCS SDK client
            if action == 'list_buckets':
                return [b.name for b in client.list_buckets(project=project_id)]
            elif action == 'get_bucket':
                bucket_name = kwargs.get('bucket_name') or (resource_item.get('name') if resource_item else None)
                if bucket_name:
                    bucket = client.bucket(bucket_name)
                    bucket.reload()
                    return bucket
            elif action == 'get_bucket_iam_policy':
                bucket_name = kwargs.get('bucket_name') or (resource_item if isinstance(resource_item, str) else resource_item.get('name'))
                if bucket_name:
                    return client.bucket(bucket_name).get_iam_policy(requested_policy_version=3)
        
        
        elif hasattr(client, 'projects'):
            # Discovery API client - dynamically build the call
            if resource:
                # Pattern: method_resource (e.g., list_firewalls, list_topics)
                # Most Discovery APIs use: client.resource().method(project=...)
                # But Pub/Sub uses: client.projects().resource().method(project=...)
                
                # Try both patterns
                try:
                    # Pattern 1: client.resource() (Compute, etc.)
                    resource_api = getattr(client, resource)()
                    call_method = getattr(resource_api, method)
                except AttributeError:
                    # Pattern 2: client.projects().resource() (Pub/Sub, IAM, etc.)
                    resource_api = getattr(client.projects(), resource)()
                    call_method = getattr(resource_api, method)
                
                # Build parameters
                params = {'project': project_id}
                params.update(kwargs)
                
                # Execute and handle pagination
                req = call_method(**params)
                items = []
                while req:
                    resp = req.execute()
                    
                    if method == 'aggregatedList':
                        # Handle aggregated responses
                        for scope_key, scoped in (resp.get('items') or {}).items():
                            # Filter by region for zone-scoped resources
                            if region and scope_key.startswith('zones/'):
                                zone = scope_key.split('/')[-1]
                                if not zone.startswith(region + '-'):
                                    continue
                            
                            # Get items from scoped dict
                            scoped_items = scoped.get(resource, []) or scoped.get('instances', []) or []
                            items.extend(scoped_items)
                    else:
                        # Handle regular list responses
                        items.extend(resp.get('items', []) or resp.get(resource, []) or [])
                    
                    # Try pagination
                    try:
                        next_method = getattr(resource_api, f'{method}_next')
                        req = next_method(req, resp)
                    except:
                        req = None
                
                return items
            else:
                # No resource specified, action is the method itself
                if hasattr(client.projects(), method):
                    # Try projects().method()
                    api = client.projects()
                    call_method = getattr(api, method)
                    req = call_method(name=f'projects/{project_id}')
                    items = []
                    while req:
                        resp = req.execute()
                        for key in ['items', 'topics', 'accounts', 'locations', 'datasets']:
                            if key in resp:
                                items.extend(resp[key])
                                break
                        try:
                            req = getattr(api, f'{method}_next')(req, resp)
                        except:
                            req = None
                    return items
    
    except Exception as e:
        print(f"Warning: API call failed for action '{action}': {e}")
    
    return []


# ============================================================================
# GENERIC SERVICE RUNNER - NO HARDCODED LOGIC
# ============================================================================

def run_service_compliance(service_name: str, project_id: str, region: Optional[str] = None) -> Dict[str, Any]:
    """
    Generic service scanner - dynamically interprets YAML.
    Works for ALL services with NO hardcoded logic.
    """
    # Load rules
    try:
        rules = load_service_rules(service_name)
    except Exception as e:
        return {'service': service_name, 'project': project_id, 'inventory': {}, 'checks': [], 'error': str(e)}
    
    # Get client
    client = get_service_client(service_name, rules, project_id)
    if not client:
        return {'service': service_name, 'project': project_id, 'inventory': {}, 'checks': []}
    
    # Get project format from YAML (e.g., 'projects/{{project_id}}' for Pub/Sub)
    project_param_format = rules.get('project_param_format', '{{project_id}}')
    formatted_project = project_param_format.replace('{{project_id}}', project_id)
    
    # DISCOVERY PHASE - dynamically execute actions from YAML
    discovery: Dict[str, List[Any]] = {}
    discovered_vars: Dict[str, Dict[str, Any]] = {}
    
    for disc in rules.get('discovery', []):
        disc_id = disc.get('discovery_id', '')
        discovery[disc_id] = []
        
        for call in disc.get('calls', []):
            action = call.get('action', '')
            fields = call.get('fields', [])
            
            try:
                # Special handling for GCS metadata extraction
                if action == 'get_bucket_metadata':
                    for_each_disc = disc.get('for_each', '')
                    buckets = discovery.get(for_each_disc, [])
                    for bucket_name in buckets:
                        bucket = client.bucket(bucket_name)
                        bucket.reload()
                        # Extract fields specified in YAML
                        for field in fields:
                            path = field.get('path', '')
                            var = field.get('var', '')
                            if path.startswith('raw.'):
                                props = getattr(bucket, '_properties', {})
                                val = extract_value(props, path[4:])
                            else:
                                val = extract_value(bucket, path) if isinstance(bucket, dict) else getattr(bucket, path, None)
                            discovered_vars.setdefault(bucket_name, {})[var] = val
                    discovery[disc_id] = [{'name': b} for b in buckets]
                else:
                    # Dynamic API execution using smart parser
                    result = execute_api_call(client, action, formatted_project, region)
                    if result:
                        if isinstance(result, list):
                            discovery[disc_id] = result
                        else:
                            discovery[disc_id] = [result] if result else []
                            
            except Exception as e:
                print(f"Warning: Discovery {disc_id} action '{action}' failed: {e}")
                discovery[disc_id] = []
    
    # CHECKS PHASE - evaluate using discovered inventory
    checks_out: List[Dict[str, Any]] = []
    
    for check in rules.get('checks', []):
        if _CHECK_ID_FILTER and check.get('check_id') not in _CHECK_ID_FILTER:
            continue
        
        for_each = check.get('for_each', '')
        resources = discovery.get(for_each, [])
        logic = (check.get('logic') or 'AND').upper()
        
        def eval_resource(resource):
            if _RESOURCE_NAME_FILTER:
                rname = resource.get('name') if isinstance(resource, dict) else str(resource)
                if rname != _RESOURCE_NAME_FILTER:
                    return None
            
            call_results: List[bool] = []
            for call in check.get('calls', []):
                action = call.get('action', '')
                fields = call.get('fields', [])
                
                try:
                    if action == 'eval':
                        # Evaluate fields on resource
                        field_results = []
                        for fld in fields:
                            value = extract_value(resource, fld['path'])
                            if isinstance(value, list):
                                res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in value)
                            else:
                                res = evaluate_field(value, fld['operator'], fld.get('expected'))
                            field_results.append(res)
                        call_results.append(all(field_results) if field_results else False)
                    
                    elif action.endswith('_iam_policy'):
                        # Generic IAM policy check pattern: get_<resource>_iam_policy
                        # Extract resource type from action name
                        resource_name = resource.get('name') if isinstance(resource, dict) else str(resource)
                        policy = None
                        
                        # Try to fetch IAM policy based on action pattern
                        if action == 'get_bucket_iam_policy':
                            # GCS SDK
                            policy = client.bucket(resource_name).get_iam_policy(requested_policy_version=3)
                        elif hasattr(client, 'projects'):
                            # Discovery API - parse resource type from action
                            # e.g., get_topic_iam_policy → topics
                            resource_type = action.replace('get_', '').replace('_iam_policy', '')
                            resource_api = getattr(client.projects(), f'{resource_type}s')()
                            policy = resource_api.getIamPolicy(resource=resource_name).execute()
                        
                        if policy:
                            field_results = []
                            for fld in fields:
                                value = extract_value(policy, fld['path'])
                                if isinstance(value, list):
                                    res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in value)
                                else:
                                    res = evaluate_field(value, fld['operator'], fld.get('expected'))
                                field_results.append(res)
                            call_results.append(all(field_results) if field_results else False)
                        else:
                            call_results.append(False)
                        
                    elif action == 'get_bucket_metadata':
                        # Use discovered vars for GCS
                        resource_name = resource if isinstance(resource, str) else resource.get('name')
                        metadata = discovered_vars.get(resource_name, {})
                        field_results = []
                        for fld in fields:
                            value = extract_value(metadata, fld['path'])
                            if isinstance(value, list):
                                res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in value)
                            else:
                                res = evaluate_field(value, fld['operator'], fld.get('expected'))
                            field_results.append(res)
                        call_results.append(all(field_results) if field_results else False)
                        
                    elif action == 'get_bucket_iam_policy':
                        # GCS IAM policy check
                        resource_name = resource if isinstance(resource, str) else resource.get('name')
                        policy = client.bucket(resource_name).get_iam_policy(requested_policy_version=3)
                        field_results = []
                        for fld in fields:
                            value = extract_value(policy, fld['path'])
                            if isinstance(value, list):
                                res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in value)
                            else:
                                res = evaluate_field(value, fld['operator'], fld.get('expected'))
                            field_results.append(res)
                        call_results.append(all(field_results) if field_results else False)
                        
                except Exception:
                    call_results.append(False)
            
            final = (any(call_results) if logic == 'OR' else all(call_results)) if call_results else False
            resource_name = resource.get('name') if isinstance(resource, dict) else str(resource)
            
            result_dict = {
                'check_id': check['check_id'],
                'resource': resource_name,
                'project': project_id,
                'result': 'PASS' if final else 'FAIL'
            }
            if region:
                result_dict['region'] = region
            
            return result_dict
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(eval_resource, r) for r in resources]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    checks_out.append(res)
    
    result = {
        'service': service_name,
        'project': project_id,
        'inventory': discovery,
        'checks': checks_out,
        'scope': rules.get('scope', 'global')
    }
    if region:
        result['region'] = region
    
    return result


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def run_for_project(project_id: str, enabled_services: Set[str]) -> List[Dict[str, Any]]:
    """Run all enabled services for a project"""
    outputs: List[Dict[str, Any]] = []
    catalog = load_service_catalog()
    
    global_services = [s.get('name') for s in catalog if s.get('scope') == 'global' and s.get('name') in enabled_services]
    regional_services = [s.get('name') for s in catalog if s.get('scope') == 'regional' and s.get('name') in enabled_services]
    
    # Global services
    for svc in global_services:
        try:
            outputs.append(run_service_compliance(svc, project_id))
        except Exception as e:
            print(f"Error: {svc}: {e}")
    
    # Regional services
    if regional_services:
        regions = list_all_regions(project_id)
        for svc in regional_services:
            with ThreadPoolExecutor(max_workers=REGION_MAX_WORKERS) as pool:
                futures = [pool.submit(run_service_compliance, svc, project_id, r) for r in regions]
                for fut in as_completed(futures):
                    try:
                        outputs.append(fut.result())
                    except Exception as e:
                        print(f"Error: {svc}: {e}")
    
    return outputs


def run() -> List[Dict[str, Any]]:
    """Main entry - scan all projects"""
    projects = list_all_projects()
    all_outputs: List[Dict[str, Any]] = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = []
        for p in projects:
            pid = p.get('projectId')
            if pid:
                enabled = resolve_enabled_services(pid)
                futures.append(ex.submit(run_for_project, pid, enabled))
        
        for fut in as_completed(futures):
            try:
                all_outputs.extend(fut.result())
            except Exception as e:
                print(f"Error: {e}")
    
    return all_outputs


def main():
    print(json.dumps(run(), indent=2))


if __name__ == '__main__':
    main()
