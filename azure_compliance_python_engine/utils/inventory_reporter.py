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
    """
    Save scan results in AWS-compatible format
    
    AWS format:
    reporting_TIMESTAMP/account_ID/ACCOUNTID_scope_service_checks.json
    
    Azure format (matching):
    reporting_TIMESTAMP/subscription_ID/SUBID_scope_service_checks.json
    """
    folder = _timestamped_folder(output_dir, 'azure')

    # Group results by subscription (like AWS groups by account)
    by_subscription: Dict[str, List[Dict[str, Any]]] = {}
    for rec in results:
        if isinstance(rec, dict):
            sub_id = rec.get('subscription') or subscription_id or 'default'
            by_subscription.setdefault(sub_id, []).append(rec)
    
    # Create folder per subscription
    for sub_id, sub_results in by_subscription.items():
        # Create subscription folder (like AWS account folder)
        sub_folder_name = f"subscription_{sub_id[:8]}" if sub_id != 'default' else 'subscription_default'
        sub_folder = os.path.join(folder, sub_folder_name)
        _ensure_dir(sub_folder)
        
        # Group results by service within subscription
        service_to_results: Dict[str, List[Dict[str, Any]]] = {}
        for rec in sub_results:
            if 'service' in rec:
                service_to_results.setdefault(rec['service'], []).append(rec)

        for service, recs in service_to_results.items():
            # Determine scope and region for file naming
            scope = recs[0].get('scope', 'subscription') if recs else 'subscription'
            region = recs[0].get('region')
            
            # Create region subfolder if needed
            if region:
                region_folder = os.path.join(sub_folder, region)
                _ensure_dir(region_folder)
                target_folder = region_folder
                scope_prefix = region
            else:
                target_folder = sub_folder
                scope_prefix = scope
            
            # Aggregate checks - AWS format: {sub_id}_{scope}_{service}_checks.json
        all_checks: List[Dict[str, Any]] = []
        for r in recs:
            for c in r.get('checks', []) or []:
                all_checks.append(c)
        
        checks_file = os.path.join(target_folder, f"{sub_id[:8]}_{scope_prefix}_{service}_checks.json")
        with open(checks_file, 'w') as f:
            json.dump(all_checks, f, indent=2, default=str)

        # Aggregate inventory - AWS format: {sub_id}_{scope}_{service}_inventory.json
        all_inventory: Dict[str, Any] = {}
        for r in recs:
            inv = r.get('inventory', {})
            if inv:
                all_inventory.update(inv)
        
        if all_inventory:
            inv_file = os.path.join(target_folder, f"{sub_id[:8]}_{scope_prefix}_{service}_inventory.json")
            with open(inv_file, 'w') as f:
                json.dump(all_inventory, f, indent=2, default=str)

    # Create index matching AWS format
    index = {
        'metadata': {
            'subscription_id': subscription_id,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'report_folder': os.path.abspath(folder)
        },
        'summary': {
            'total_checks': sum(len(r.get('checks', [])) for results_list in by_subscription.values() for r in results_list),
            'total_resources': len(results),
            'total_subscriptions': len(by_subscription)
        },
        'subscription_folders': [f"subscription_{sid[:8]}" if sid != 'default' else 'subscription_default' for sid in by_subscription.keys()],
        'files': {
            'index': 'index.json'
    }
    }
    
    with open(os.path.join(folder, 'index.json'), 'w') as f:
        json.dump(index, f, indent=2)

    return folder 