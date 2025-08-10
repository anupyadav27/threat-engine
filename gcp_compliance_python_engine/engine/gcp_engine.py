import os
import json
from typing import Any, Dict, List, Optional, Tuple
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


def load_enabled_services_with_scope() -> List[Tuple[str, str]]:
    cfg = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(cfg) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "regional")) for s in data.get("services", []) if s.get("enabled")]


def load_service_rules(service_name: str) -> Dict[str, Any]:
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    return rules[service_name]


def list_projects() -> List[Dict[str, Any]]:
    crm = get_resource_manager_client()
    projects: List[Dict[str, Any]] = []
    req = crm.projects().list()
    while req is not None:
        resp = req.execute()
        for p in resp.get("projects", []):
            if p.get("lifecycleState") == "ACTIVE":
                projects.append(p)
        req = crm.projects().list_next(previous_request=req, previous_response=resp)
    # Fallback to default project if none
    if not projects and get_default_project_id():
        projects.append({"projectId": get_default_project_id(), "name": get_default_project_id()})
    return projects


def list_enabled_services(project_id: str) -> List[str]:
    su = get_service_usage_client()
    parent = f"projects/{project_id}"
    enabled: List[str] = []
    req = su.services().list(parent=parent, filter="state:ENABLED")
    while req is not None:
        resp = req.execute()
        for s in resp.get("services", []):
            name = s.get("name")  # e.g., projects/123/services/storage.googleapis.com
            if name and "/services/" in name:
                enabled.append(name.split("/services/")[-1])
        req = su.services().list_next(previous_request=req, previous_response=resp)
    return enabled


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
                    discovered_vars.setdefault(b, {})['iam_configuration_uniform'] = getattr(bucket.iam_configuration, 'is_uniform_bucket_level_access_enabled', None)
                    out.append({'name': b, 'location': bucket.location})
                discovery[d['discovery_id']] = out
    # checks
    checks_out: List[Dict[str, Any]] = []
    for check in rules.get('checks', []):
        for_each = check.get('for_each')
        resources = discovery.get(for_each, [])
        def eval_resource(resource):
            result_flags: List[bool] = []
            for call in check.get('calls', []):
                action = call['action']
                if action == 'get_bucket_iam_policy':
                    policy = storage.bucket(resource).get_iam_policy(requested_policy_version=3)
                    values = extract_value(policy, call['fields'][0]['path'])
                    res = all(evaluate_field(v, call['fields'][0]['operator'], call['fields'][0].get('expected')) for v in (values if isinstance(values, list) else [values]))
                    result_flags.append(res)
                elif action == 'get_bucket_metadata':
                    uniform = discovered_vars.get(resource, {}).get('iam_configuration_uniform')
                    op = call['fields'][0]
                    res = evaluate_field(uniform, op['operator'], op.get('expected'))
                    result_flags.append(res)
            final = all(result_flags) if result_flags else False
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
        def eval_row(row):
            flags: List[bool] = []
            for call in check.get('calls', []):
                if call.get('action') == 'eval':
                    field = call['fields'][0]
                    val = extract_value(row, field['path'])
                    res = all(evaluate_field(v, field['operator'], field.get('expected')) for v in val) if isinstance(val, list) else evaluate_field(val, field['operator'], field.get('expected'))
                    flags.append(res)
            final = all(flags) if flags else False
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


def run_for_project(project_id: str, enabled_services: List[str]) -> List[Dict[str, Any]]:
    outputs: List[Dict[str, Any]] = []
    # Global services
    if 'storage.googleapis.com' in enabled_services:
        outputs.append(run_global_service('gcs', project_id))
    # Regional: only run compute if API enabled
    if 'compute.googleapis.com' in enabled_services:
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
            outputs.append(run_region_services('compute', r, project_id))
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
            enabled = list_enabled_services(pid)
            futures.append(ex.submit(run_for_project, pid, enabled))
        for fut in as_completed(futures):
            for out in fut.result():
                all_outputs.append(out)
    return all_outputs


def main():
    print(json.dumps(run(), indent=2))

if __name__ == '__main__':
    main() 