import os
import json
import argparse
from typing import Any, Dict, List
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


def _load_catalog() -> Dict[str, Any]:
    data = _load_yaml(os.path.join(_config_dir(), "actions.yaml"))
    return data.get("standard_actions") or {}


def _load_reporting(report_folder: str) -> List[Dict[str, Any]]:
    main_checks = json.load(open(os.path.join(report_folder, 'main_checks.json'))).get('checks') or []
    skipped_checks = json.load(open(os.path.join(report_folder, 'skipped_checks.json'))).get('checks') or []
    return [*main_checks, *skipped_checks]


def run(report_folder: str, enforce: bool = False) -> str:
    selected = _load_selection()
    catalog = _load_catalog()
    items = _load_reporting(report_folder)
    results: List[Dict[str, Any]] = []
    for item in [c for c in items if c.get('status') in ('FAIL', 'ERROR')]:
        actions = [{"action": a, "args": (catalog.get(a) or {})} for a in (selected.get(item.get('check_id')) or [])]
        for act in actions:
            results.append({
                'check_id': item.get('check_id'),
                'component': item.get('metadata', {}).get('component'),
                'resource': item.get('resource_name') or item.get('resource_id'),
                'action': act.get('action'),
                'status': 'DRY_RUN',
                'details': json.dumps(act.get('args') or {}),
            })
    out = {'metadata': {'generated_at': datetime.utcnow().isoformat() + 'Z', 'report_folder': os.path.abspath(report_folder), 'enforce': enforce}, 'results': results}
    path = os.path.join(report_folder, 'action_results.json')
    with open(path, 'w') as fh:
        json.dump(out, fh, indent=2)
    return path


def main():
    ap = argparse.ArgumentParser(description='Run K8s actions based on reporting outputs')
    ap.add_argument('--report-folder', required=True)
    ap.add_argument('--enforce', action='store_true')
    args = ap.parse_args()
    print(run(args.report_folder, enforce=args.enforce))


if __name__ == '__main__':
    main() 