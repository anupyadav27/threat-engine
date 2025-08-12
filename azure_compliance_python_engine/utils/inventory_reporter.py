import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _timestamped_folder(base_dir: str, prefix: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    folder = os.path.join(base_dir, ts)
    _ensure_dir(folder)
    return folder


def save_scan_results(results: List[Dict[str, Any]], output_dir: str, subscription_id: Optional[str] = None) -> str:
    _ensure_dir(output_dir)
    fname = f"azure_scan_results_{subscription_id or 'unknown'}.json"
    path = os.path.join(output_dir, fname)
    with open(path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    return path


def save_split_scan_results(results: List[Dict[str, Any]], output_dir: str, subscription_id: Optional[str] = None) -> str:
    folder = _timestamped_folder(output_dir, 'azure')
    checks_dir = os.path.join(folder, 'checks')
    inventory_dir = os.path.join(folder, 'inventory')
    _ensure_dir(checks_dir)
    _ensure_dir(inventory_dir)

    # Group results by service
    service_to_results: Dict[str, List[Dict[str, Any]]] = {}
    for rec in results:
        if isinstance(rec, dict) and 'service' in rec:
            service_to_results.setdefault(rec['service'], []).append(rec)

    for service, recs in service_to_results.items():
        # Aggregate checks
        all_checks: List[Dict[str, Any]] = []
        for r in recs:
            for c in r.get('checks', []) or []:
                all_checks.append(c)
        with open(os.path.join(checks_dir, f"{service}.json"), 'w') as f:
            json.dump(all_checks, f, indent=2, default=str)

        # Aggregate inventory as list per scope to preserve context
        inv_entries: List[Dict[str, Any]] = []
        for r in recs:
            entry = {
                'tenant': r.get('tenant'),
                'management_group': r.get('management_group'),
                'subscription': r.get('subscription'),
                'region': r.get('region'),
                'inventory': r.get('inventory', {})
            }
            inv_entries.append(entry)
        with open(os.path.join(inventory_dir, f"{service}.json"), 'w') as f:
            json.dump(inv_entries, f, indent=2, default=str)

    # Also write a small summary
    summary = {
        'services': list(service_to_results.keys()),
        'total_services': len(service_to_results),
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    }
    with open(os.path.join(folder, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)

    return folder 