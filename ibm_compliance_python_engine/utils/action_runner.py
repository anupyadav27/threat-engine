import os
import json
import argparse
from typing import Any, Dict, List, Tuple
from datetime import datetime

import yaml

from aws_compliance_python_engine.auth.aws_auth import get_boto3_session


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
    indexes = {
        'ec2_instances': {},  # (account, region, instance_id) -> {}
        's3_buckets': {},     # (account, bucket_name) -> {}
    }
    for entry in inv.get('inventories', []) or []:
        acct = entry.get('account')
        service = entry.get('service')
        region = entry.get('scope_region') or entry.get('region')
        data = entry.get('inventory') or {}
        if service == 'ec2':
            # If inventory contains instance ids, index them (depends on discovery)
            pass
        elif service == 's3':
            # If inventory contains bucket names, index them
            pass
    return indexes


def _ensure_actions(item: Dict[str, Any], selected: Dict[str, List[str]], catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    if item.get('actions'):
        return item['actions']
    names = selected.get(item.get('check_id')) or []
    return [{"action": n, "args": (catalog.get(n) or {})} for n in names]


def _execute_ec2_stop(enforce: bool, account: str, region: str, instance_id: str) -> Tuple[str, str]:
    if not enforce:
        return ("DRY_RUN", f"ec2.stop_instances account={account} region={region} instance_id={instance_id}")
    try:
        session = get_boto3_session(profile_name=os.getenv('AWS_PROFILE'))
        ec2 = session.client('ec2', region_name=region)
        resp = ec2.stop_instances(InstanceIds=[instance_id])
        return ("SUCCESS", json.dumps(resp, default=str))
    except Exception as e:
        return ("ERROR", str(e))


def _run_action(item: Dict[str, Any], action: Dict[str, Any], enforce: bool) -> Dict[str, Any]:
    service = item.get('service')
    account = item.get('account')
    region = item.get('region')
    resource = item.get('resource') or item.get('instanceId') or item.get('bucket')
    name = action.get('action')
    args = action.get('args') or {}

    status = 'NOT_IMPLEMENTED'
    details = ''

    if service == 'ec2':
        if name == 'stop':
            status, details = _execute_ec2_stop(enforce, account or '', region or 'us-east-1', resource or '')
        elif name in ('tag', 'untag', 'quarantine'):
            status, details = ('DRY_RUN', f"{name} for ec2 instance {resource}")
        elif name in ('notify', 'invoke_function'):
            status, details = ('DRY_RUN', json.dumps(args))
    elif service == 's3':
        if name in ('notify', 'invoke_function'):
            status, details = ('DRY_RUN', json.dumps(args))
        else:
            status, details = ('DRY_RUN', f"{name} for s3 bucket {resource}")
    else:
        if name in ('notify', 'invoke_function'):
            status, details = ('DRY_RUN', json.dumps(args))
        else:
            status, details = ('NOT_IMPLEMENTED', f"service {service} action {name}")

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
    out = {'metadata': {'generated_at': datetime.utcnow().isoformat() + 'Z', 'report_folder': os.path.abspath(report_folder), 'enforce': enforce}, 'results': results}
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