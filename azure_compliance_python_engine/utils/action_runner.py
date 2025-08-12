import os
import json
import argparse
from typing import Any, Dict, List, Tuple
from datetime import datetime

import yaml


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


def _ensure_actions(item: Dict[str, Any], selected: Dict[str, List[str]], catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    if item.get('actions'):
        return item['actions']
    names = selected.get(item.get('check_id')) or []
    return [{"action": n, "args": (catalog.get(n) or {})} for n in names]


def _run_action(item: Dict[str, Any], action: Dict[str, Any], enforce: bool) -> Dict[str, Any]:
    name = action.get('action')
    args = action.get('args') or {}
    status = 'DRY_RUN'
    details = json.dumps(args)
    return {
        'check_id': item.get('check_id'),
        'service': item.get('service'),
        'subscription': item.get('subscription'),
        'region': item.get('region'),
        'resource': item.get('resource'),
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
    ap = argparse.ArgumentParser(description='Run Azure actions based on reporting outputs')
    ap.add_argument('--report-folder', required=True)
    ap.add_argument('--enforce', action='store_true')
    args = ap.parse_args()
    print(run(args.report_folder, enforce=args.enforce))


if __name__ == '__main__':
    main() 