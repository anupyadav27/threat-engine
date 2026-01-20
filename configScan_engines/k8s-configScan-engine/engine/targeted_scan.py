import os
import json
import argparse
from typing import Any, Dict, List, Optional, Set

from k8_engine.engine import run_yaml_engine
from k8_engine.utils.reporting_manager import save_reporting_bundle


def _filter_results(results: List[Dict[str, Any]], check_ids: Optional[Set[str]], resource: Optional[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in results or []:
        if not isinstance(r, dict):
            continue
        if check_ids and r.get('check_id') not in check_ids:
            continue
        if resource and (resource not in str(r.get('resource_name') or r.get('resource_id') or '')):
            continue
        out.append(r)
    return out


def run_targeted_scan(
    rules_dir: Optional[str] = None,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
    components: Optional[List[str]] = None,
    check_ids: Optional[List[str]] = None,
    resource: Optional[str] = None,
    save_report: bool = False,
) -> List[Dict[str, Any]]:
    yaml_root = rules_dir or os.path.join(os.path.dirname(__file__), '..', 'rules')
    results = run_yaml_engine(
        yaml_root=os.path.abspath(yaml_root),
        kubeconfig=kubeconfig,
        context=context,
        target_components=components,
        auto_init=True,
    )
    filt = _filter_results(results, set(check_ids or []) or None, resource)
    if save_report:
        save_reporting_bundle(filt, cluster=context or 'kubernetes')
    return filt


def main():
    ap = argparse.ArgumentParser(description='Run targeted K8s YAML checks')
    ap.add_argument('--rules-dir', help='Path to YAML rules root (defaults to k8_engine/rules)')
    ap.add_argument('--kubeconfig', help='Path to kubeconfig')
    ap.add_argument('--context', help='Kube context name')
    ap.add_argument('--components', nargs='+', help='Limit to specific components (e.g., apiserver, scheduler)')
    ap.add_argument('--check-ids', help='Comma-separated check IDs to include')
    ap.add_argument('--resource', help='Filter by resource name/id substring')
    ap.add_argument('--save-report', action='store_true', help='Write a reporting bundle for the targeted run')
    args = ap.parse_args()

    checks = [c.strip() for c in (args.check_ids or '').split(',') if c.strip()] or None
    comps = args.components or None

    out = run_targeted_scan(
        rules_dir=args.rules_dir,
        kubeconfig=args.kubeconfig,
        context=args.context,
        components=comps,
        check_ids=checks,
        resource=args.resource,
        save_report=args.save_report,
    )
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main() 