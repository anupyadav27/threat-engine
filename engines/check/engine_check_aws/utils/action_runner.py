import os
import json
import argparse
from typing import Any, Dict, List, Tuple
from datetime import datetime, timezone

import yaml

from auth.aws_auth import get_boto3_session


def _config_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))


def _load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def _load_selection() -> Dict[str, List[str]]:
    data = _load_yaml(os.path.join(_config_dir(), "actions_selection.yaml"))
    profiles = data.get("profiles") or {}
    active = data.get("active_profile") or "default"
    profile = profiles.get(active) or {}
    return profile.get("selected_actions_by_check") or {}


def _load_catalog() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    data = _load_yaml(os.path.join(_config_dir(), "actions.yaml"))
    return data.get("standard_actions") or {}, data.get("arg_paths") or {}


def _load_reporting(report_folder: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    main_checks = json.load(open(os.path.join(report_folder, 'main_checks.json'))).get('checks') or []
    skipped_checks = json.load(open(os.path.join(report_folder, 'skipped_checks.json'))).get('checks') or []
    inventories = json.load(open(os.path.join(report_folder, 'inventories.json')))
    return main_checks, skipped_checks, inventories


def _build_indexes(inv: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build generic indexes for all services.
    Indexes are built dynamically based on service and resource type.
    """
    indexes = {}
    for entry in inv.get('inventories', []) or []:
        acct = entry.get('account')
        service = entry.get('service')
        region = entry.get('scope_region') or entry.get('region')
        data = entry.get('inventory') or {}
        
        # Generic indexing - create index key based on service
        index_key = f'{service}_resources'
        if index_key not in indexes:
            indexes[index_key] = {}
        
        # Index by (account, region, resource_id) tuple
        # Resource ID extraction is handled generically by extract_resource_identifier
        # This is a placeholder - actual indexing would depend on discovery structure
        pass
    
    return indexes


def _ensure_actions(item: Dict[str, Any], selected: Dict[str, List[str]], catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    if item.get('actions'):
        return item['actions']
    names = selected.get(item.get('check_id')) or []
    return [{"action": n, "args": (catalog.get(n) or {})} for n in names]


def _execute_boto3_action(service: str, operation: str, enforce: bool, 
                          region: str, params: Dict[str, Any]) -> Tuple[str, str]:
    """
    Generic boto3 action executor.
    Executes any boto3 operation for any service.
    """
    if not enforce:
        return ("DRY_RUN", f"{service}.{operation} region={region} params={params}")
    
    try:
        session = get_boto3_session(profile_name=os.getenv('AWS_PROFILE'))
        client = session.client(service, region_name=region)
        
        # Get the operation method dynamically
        operation_method = getattr(client, operation)
        resp = operation_method(**params)
        
        return ("SUCCESS", json.dumps(resp, default=str))
    except Exception as e:
        return ("ERROR", str(e))


def _run_action(item: Dict[str, Any], action: Dict[str, Any], enforce: bool) -> Dict[str, Any]:
    """
    Generic action runner - works with any service and action type.
    Uses action configuration from actions.yaml to determine execution method.
    """
    service = item.get('service')
    account = item.get('account')
    region = item.get('region')
    resource = item.get('resource') or item.get('resource_id') or item.get('resource_arn')
    name = action.get('action')
    args = action.get('args') or {}

    status = 'NOT_IMPLEMENTED'
    details = ''

    # Check if action has boto3 operation defined in args
    operation = args.get('operation')
    
    if operation:
        # Action has boto3 operation - execute generically
        # Build parameters from args and item data
        params = {}
        for key, value in args.items():
            if key == 'operation':
                continue
            # Resolve template variables like {{resource_id}}
            if isinstance(value, str) and '{{' in value:
                # Simple template resolution
                value = value.replace('{{resource_id}}', str(resource or ''))
                value = value.replace('{{resource_arn}}', str(item.get('resource_arn', '')))
                value = value.replace('{{account}}', str(account or ''))
                value = value.replace('{{region}}', str(region or ''))
            params[key] = value
        
        # Add resource identifier if not in params
        if 'Id' not in params and 'ResourceId' not in params and resource:
            # Try common parameter names
            if service in ['ec2', 'rds', 'lambda']:
                params['Ids'] = [resource] if not isinstance(resource, list) else resource
            elif service == 's3':
                params['Bucket'] = resource
            else:
                params['ResourceId'] = resource
        
        status, details = _execute_boto3_action(service, operation, enforce, region or 'us-east-1', params)
    
    elif name in ('notify', 'invoke_function', 'webhook'):
        # Generic notification/invocation actions
        status, details = ('DRY_RUN', json.dumps(args))
    
    else:
        # Fallback for actions without boto3 operation
        status, details = ('NOT_IMPLEMENTED', f"Action '{name}' for service '{service}' requires operation definition in actions.yaml")

    return {
        'check_id': item.get('check_id'),
        'service': service,
        'account': account,
        'region': region,
        'resource': resource,
        'action': name,
        'status': status,
        'details': details,
    }


def run(report_folder: str, enforce: bool = False) -> str:
    main_checks, skipped_checks, inv = _load_reporting(report_folder)
    selected = _load_selection()
    catalog, _ = _load_catalog()
    results: List[Dict[str, Any]] = []
    for item in [c for c in (main_checks + skipped_checks) if c.get('result') == 'FAIL']:
        for act in _ensure_actions(item, selected, catalog):
            results.append(_run_action(item, act, enforce))
    out = {'metadata': {'generated_at': datetime.now(timezone.utc).isoformat() + 'Z', 'report_folder': os.path.abspath(report_folder), 'enforce': enforce}, 'results': results}
    out_path = os.path.join(report_folder, 'action_results.json')
    with open(out_path, 'w') as fh:
        json.dump(out, fh, indent=2)
    return out_path


def main():
    ap = argparse.ArgumentParser(description='Run AWS actions based on reporting outputs')
    ap.add_argument('--report-folder', required=True)
    ap.add_argument('--enforce', action='store_true')
    args = ap.parse_args()
    print(run(args.report_folder, enforce=args.enforce))


if __name__ == '__main__':
    main() 