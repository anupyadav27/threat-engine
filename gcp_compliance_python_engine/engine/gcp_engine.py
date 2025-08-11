import os
import json
from typing import Any, Dict, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from gcp_compliance_python_engine.auth.gcp_auth import (
    get_storage_client,
    get_default_project_id,
    get_resource_manager_client,
    get_service_usage_client,
    get_compute_client,
)
import yaml

MAX_WORKERS = int(os.getenv("COMPLIANCE_ENGINE_MAX_WORKERS", "16"))


def extract_value(obj: Any, path: str):
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
    if operator == 'exists':
        return (value is not None) if expected is None else (bool(value) == bool(expected))
    if operator == 'equals':
        return value == expected
    if operator == 'contains':
        if isinstance(value, list):
            return expected in value
        return str(expected) in (str(value) if value is not None else '')
    return False


# Catalog loading and service resolution

def _load_service_catalog() -> List[Dict[str, Any]]:
    base_dir = os.path.join(os.path.dirname(__file__), "..", "config")
    yaml_path = os.path.join(base_dir, "service_list.yaml")
    json_path = os.path.join(base_dir, "service_list.json")
    if os.path.exists(yaml_path):
        with open(yaml_path) as fh:
            data = yaml.safe_load(fh) or {}
    else:
        with open(json_path) as fh:
            data = json.load(fh)
    services = data.get("services", [])
    # Normalize structure
    for s in services:
        s.setdefault("enabled", True)
        s.setdefault("scope", "regional")
        s.setdefault("apis", [])
    return services


def _list_enabled_apis(project_id: str) -> Set[str]:
    apis: Set[str] = set()
    try:
        su = get_service_usage_client()
        parent = f"projects/{project_id}"
        req = su.services().list(parent=parent, filter="state:ENABLED")
        while req is not None:
            resp = req.execute()
            for s in resp.get("services", []) or []:
                name = s.get("name")  # e.g., projects/123/services/storage.googleapis.com
                if not name or "/services/" not in name:
                    continue
                apis.add(name.split("/services/")[-1])
            req = su.services().list_next(previous_request=req, previous_response=resp)
    except Exception:
        return set()
    return apis


def resolve_enabled_engine_services(project_id: str) -> Set[str]:
    catalog = _load_service_catalog()
    enabled_apis = _list_enabled_apis(project_id)
    enabled_services: Set[str] = set()
    for svc in catalog:
        if not svc.get("enabled", True):
            continue
        svc_apis = set(svc.get("apis", []) or [])
        # If apis list is empty, require exact API name equal to service name (back-compat)
        if not svc_apis and svc.get("name"):
            svc_apis = {f"{svc['name']}.googleapis.com"}
        if enabled_apis & svc_apis:
            enabled_services.add(svc["name"])
    return enabled_services


def load_enabled_services_with_scope() -> List[Tuple[str, str]]:
    services = _load_service_catalog()
    return [(s["name"], s.get("scope", "regional")) for s in services if s.get("enabled")]


def load_service_rules(service_name: str) -> Dict[str, Any]:
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    return rules[service_name]


def _load_project_ids() -> List[str]:
    # Allow explicit project list via env to avoid requiring CRM API
    env_val = os.getenv("GCP_PROJECTS")
    if env_val:
        return [p.strip() for p in env_val.split(",") if p.strip()]
    return []


def list_projects() -> List[Dict[str, Any]]:
    # If explicit projects provided, prefer them
    explicit = _load_project_ids()
    if explicit:
        return [{"projectId": p, "name": p} for p in explicit]
    # Prefer enumerating via Cloud Resource Manager; if unavailable, fall back to the default project only
    projects: List[Dict[str, Any]] = []
    try:
        crm = get_resource_manager_client()
        req = crm.projects().list()
        while req is not None:
            resp = req.execute()
            for p in resp.get("projects", []):
                if p.get("lifecycleState") == "ACTIVE":
                    projects.append(p)
            req = crm.projects().list_next(previous_request=req, previous_response=resp)
    except Exception:
        # CRM not enabled or not accessible; ignore and use default project if present
        pass
    if not projects and get_default_project_id():
        projects.append({"projectId": get_default_project_id(), "name": get_default_project_id()})
    return projects


# Services implementations

def _get_from_bucket(bucket: Any, path: str) -> Any:
    # Supports attribute traversal and raw properties via 'raw.' prefix
    if path.startswith('raw.'):
        obj: Any = getattr(bucket, '_properties', {}) or {}
        parts = path.split('.')[1:]
        for p in parts:
            if isinstance(obj, dict):
                obj = obj.get(p)
            else:
                return None
        return obj
    # Attribute traversal on the bucket object
    obj = bucket
    for p in path.split('.'):
        if hasattr(obj, p):
            obj = getattr(obj, p)
        else:
            return None
    return obj


def run_gcs(project_id: Optional[str] = None) -> Dict[str, Any]:
    service_name = 'gcs'
    rules = load_service_rules(service_name)
    storage = get_storage_client(project_id)
    # discovery
    discovery: Dict[str, List[Any]] = {}
    discovered_vars: Dict[str, Dict[str, Any]] = {}
    for d in rules.get('discovery', []):
        for call in d.get('calls', []):
            action = call['action']
            if action == 'list_buckets':
                buckets = [b.name for b in storage.list_buckets(project=project_id or get_default_project_id())]
                discovery[d['discovery_id']] = buckets
            elif action == 'get_bucket_metadata':
                resources = discovery.get(d.get('for_each'), [])
                out = []
                for b in resources:
                    bucket = storage.bucket(b)
                    bucket.reload()
                    # Extract only what YAML requests
                    for field in call.get('fields', []) or []:
                        path = field.get('path')
                        var_name = field.get('var') or (path.split('.')[-1] if path else None)
                        if not path or not var_name:
                            continue
                        value = _get_from_bucket(bucket, path)
                        discovered_vars.setdefault(b, {})[var_name] = value
                    out.append({'name': b, 'location': bucket.location})
                discovery[d['discovery_id']] = out
    # checks
    checks_out: List[Dict[str, Any]] = []
    for check in rules.get('checks', []):
        for_each = check.get('for_each')
        resources = discovery.get(for_each, [])
        logic = (check.get('logic') or 'AND').upper()
        errors_as_fail = set(check.get('errors_as_fail') or [])

        def eval_resource(resource):
            call_results: List[bool] = []
            for call in check.get('calls', []) or []:
                action = call.get('action')
                fields = call.get('fields') or []
                try:
                    if action == 'get_bucket_iam_policy':
                        policy = storage.bucket(resource).get_iam_policy(requested_policy_version=3)
                        field_results: List[bool] = []
                        for fld in fields:
                            values = extract_value(policy, fld['path'])
                            res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in (values if isinstance(values, list) else [values]))
                            field_results.append(res)
                        call_results.append(all(field_results) if field_results else False)
                    elif action == 'get_bucket_metadata':
                        metadata_obj = discovered_vars.get(resource, {})
                        field_results: List[bool] = []
                        for fld in fields:
                            value = extract_value(metadata_obj, fld['path'])
                            if isinstance(value, list):
                                res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in value)
                            else:
                                res = evaluate_field(value, fld['operator'], fld.get('expected'))
                            field_results.append(res)
                        call_results.append(all(field_results) if field_results else False)
                    else:
                        # Unknown action for GCS
                        call_results.append(False)
                except Exception as e:
                    err_str = getattr(e, 'message', None) or str(e)
                    if errors_as_fail:
                        call_results.append(any(token in err_str for token in errors_as_fail) is False and False or False)
                    else:
                        call_results.append(False)
            final = (any(call_results) if logic == 'OR' else all(call_results)) if call_results else False
            return { 'check_id': check['check_id'], 'resource': resource, 'project': project_id or get_default_project_id(), 'result': 'PASS' if final else 'FAIL' }
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for fut in as_completed([ex.submit(eval_resource, r) for r in resources]):
                checks_out.append(fut.result())
    return { 'service': service_name, 'project': project_id or get_default_project_id(), 'inventory': discovery, 'checks': checks_out, 'scope': 'global' }


def run_compute_regional(project_id: str, region: str) -> Dict[str, Any]:
    service_name = 'compute'
    rules = load_service_rules(service_name)
    compute = get_compute_client(project_id)

    discovery: Dict[str, List[Any]] = {"instances": [], "firewalls": []}

    # Aggregated instances (zone-level); filter to region prefix
    req = compute.instances().aggregatedList(project=project_id)
    while req is not None:
        resp = req.execute()
        for scope_key, scoped in (resp.get('items') or {}).items():
            # scope_key example: zones/us-central1-a
            if not scope_key.startswith('zones/'):
                continue
            z = scope_key.split('/')[-1]
            if not z.startswith(region + '-'):
                continue
            for inst in scoped.get('instances', []) or []:
                nic0 = (inst.get('networkInterfaces') or [{}])[0]
                access_configs = nic0.get('accessConfigs') or []
                has_ext_ip = any(ac.get('natIP') for ac in access_configs)
                shielded = (inst.get('shieldedInstanceConfig') or {}).get('enableSecureBoot') is True
                metadata_items = {i['key']: i.get('value') for i in (inst.get('metadata', {}).get('items') or []) if 'key' in i}
                serial_port_enabled = metadata_items.get('serial-port-enable') == '1'
                discovery['instances'].append({
                    'id': inst.get('id'),
                    'name': inst.get('name'),
                    'zone': z,
                    'region': region,
                    'has_external_ip': has_ext_ip,
                    'shielded_secure_boot': shielded,
                    'metadata': {
                        'serial_port_enabled': serial_port_enabled
                    }
                })
        req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)

    # Firewalls
    req_fw = compute.firewalls().list(project=project_id)
    while req_fw is not None:
        resp = req_fw.execute()
        for fw in resp.get('items', []) or []:
            allows = fw.get('allowed', []) or []
            tcp_ports: List[str] = []
            for a in allows:
                if a.get('IPProtocol') == 'tcp':
                    tcp_ports.extend(a.get('ports', []) or [])
            discovery['firewalls'].append({
                'name': fw.get('name'),
                'direction': fw.get('direction'),
                'source_ranges': fw.get('sourceRanges', []) or [],
                'allowed_tcp_ports': tcp_ports,
            })
        req_fw = compute.firewalls().list_next(previous_request=req_fw, previous_response=resp)

    # Evaluate checks (rules use action: eval to read from discovery objects)
    checks_out: List[Dict[str, Any]] = []
    for check in rules.get('checks', []):
        dataset = discovery.get(check.get('for_each'), [])
        logic = (check.get('logic') or 'AND').upper()

        def eval_row(row):
            call_results: List[bool] = []
            for call in check.get('calls', []) or []:
                if call.get('action') == 'eval':
                    field_results: List[bool] = []
                    for fld in call.get('fields', []) or []:
                        val = extract_value(row, fld['path'])
                        if isinstance(val, list):
                            res = all(evaluate_field(v, fld['operator'], fld.get('expected')) for v in val)
                        else:
                            res = evaluate_field(val, fld['operator'], fld.get('expected'))
                        field_results.append(res)
                    call_results.append(all(field_results) if field_results else False)
            final = (any(call_results) if logic == 'OR' else all(call_results)) if call_results else False
            resource = row.get('name') or row.get('id')
            return { 'check_id': check['check_id'], 'region': region, 'resource': resource, 'result': 'PASS' if final else 'FAIL' }
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for fut in as_completed([ex.submit(eval_row, r) for r in dataset]):
                checks_out.append(fut.result())
    return { 'service': service_name, 'project': project_id, 'region': region, 'scope': 'regional', 'inventory': discovery, 'checks': checks_out }


# Uniform interface


def run_global_service(service_name: str, project_id: Optional[str] = None) -> Dict[str, Any]:
    if service_name == 'gcs':
        return run_gcs(project_id)
    raise NotImplementedError(f"Global service not implemented: {service_name}")



def run_region_services(service_name: str, region: str, project_id: Optional[str] = None) -> Dict[str, Any]:
    if service_name == 'compute':
        return run_compute_regional(project_id or get_default_project_id(), region)
    raise NotImplementedError(f"Regional service not implemented for GCP: {service_name}")



def run_for_project(project_id: str, enabled_service_names: Set[str]) -> List[Dict[str, Any]]:
    outputs: List[Dict[str, Any]] = []
    catalog = _load_service_catalog()
    configured_services: Set[str] = {s.get('name') for s in catalog if s.get('enabled', True)}
    # If we couldn't detect enabled APIs (e.g., Service Usage disabled), optimistically try configured ones
    candidate_services: Set[str] = enabled_service_names or configured_services

    # Global services
    if 'gcs' in candidate_services:
        try:
            outputs.append(run_global_service('gcs', project_id))
        except Exception:
            # Skip if API disabled or no access
            pass

    # Regional services
    if 'compute' in candidate_services:
        try:
            compute = get_compute_client(project_id)
            regions_list: List[str] = []
            try:
                req = compute.regions().list(project=project_id)
                while req is not None:
                    resp = req.execute()
                    for r in resp.get('items', []) or []:
                        regions_list.append(r.get('name'))
                    req = compute.regions().list_next(previous_request=req, previous_response=resp)
            except Exception:
                pass
            regions_list = list({r for r in regions_list if r})
            for r in regions_list:
                try:
                    outputs.append(run_region_services('compute', r, project_id))
                except Exception:
                    pass
        except Exception:
            pass
    return outputs



def run() -> List[Dict[str, Any]]:
    all_outputs: List[Dict[str, Any]] = []
    projects = list_projects()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures: List[Any] = []
        for p in projects:
            pid = p.get('projectId')
            if not pid:
                continue
            enabled_service_names = resolve_enabled_engine_services(pid)
            futures.append(ex.submit(run_for_project, pid, enabled_service_names))
        for fut in as_completed(futures):
            for out in fut.result():
                all_outputs.append(out)
    return all_outputs



def main():
    print(json.dumps(run(), indent=2))

if __name__ == '__main__':
    main() 