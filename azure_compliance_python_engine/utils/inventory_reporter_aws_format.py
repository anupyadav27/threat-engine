"""
AWS-compatible inventory reporter for Azure
Creates account/subscription-based folder structure matching AWS format
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _timestamped_folder(base_dir: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    folder = os.path.join(base_dir, f"reporting_{ts}")
    _ensure_dir(folder)
    return folder


def save_scan_results_aws_format(
    results: List[Dict[str, Any]], 
    output_dir: str, 
    subscription_id: Optional[str] = None
) -> str:
    """
    Save scan results in AWS-compatible format
    
    AWS format:
    reporting/reporting_TIMESTAMP/
    ├── index.json
    └── account_ACCOUNTID/
        ├── ACCOUNTID_global_service_checks.json
        └── ACCOUNTID_region_service_checks.json
    
    Azure format (matching):
    reporting/reporting_TIMESTAMP/
    ├── index.json
    └── subscription_SUBID/
        ├── SUBID_tenant_service_checks.json
        ├── SUBID_tenant_service_inventory.json
        ├── SUBID_global_service_checks.json
        └── region/
            └── SUBID_region_service_checks.json
    """
    
    # Create timestamped folder
    report_folder = _timestamped_folder(output_dir)
    
    # Group results by subscription
    by_subscription = {}
    for result in results:
        sub_id = result.get('subscription') or subscription_id or 'default'
        if sub_id not in by_subscription:
            by_subscription[sub_id] = []
        by_subscription[sub_id].append(result)
    
    subscription_folders = []
    total_checks = 0
    total_resources = 0
    
    # Create folder per subscription (like AWS does per account)
    for sub_id, sub_results in by_subscription.items():
        sub_folder_name = f"subscription_{sub_id[:8]}"  # Shortened for readability
        sub_folder = os.path.join(report_folder, sub_folder_name)
        _ensure_dir(sub_folder)
        subscription_folders.append(sub_folder_name)
        
        # Group by scope and service within subscription
        for result in sub_results:
            service = result.get('service', 'unknown')
            scope = result.get('scope', 'subscription')
            region = result.get('region')
            
            # Determine folder
            if region:
                # Regional services go in region subfolder
                region_folder = os.path.join(sub_folder, region)
                _ensure_dir(region_folder)
                base_folder = region_folder
                scope_prefix = region
            else:
                base_folder = sub_folder
                scope_prefix = scope  # tenant, global, subscription
            
            # Save checks
            checks = result.get('checks', [])
            if checks:
                checks_file = os.path.join(
                    base_folder, 
                    f"{sub_id[:8]}_{scope_prefix}_{service}_checks.json"
                )
                with open(checks_file, 'w') as f:
                    json.dump(checks, f, indent=2, default=str)
                total_checks += len(checks)
            
            # Save inventory
            inventory = result.get('inventory', {})
            if inventory:
                inv_file = os.path.join(
                    base_folder,
                    f"{sub_id[:8]}_{scope_prefix}_{service}_inventory.json"
                )
                with open(inv_file, 'w') as f:
                    json.dump(inventory, f, indent=2, default=str)
                total_resources += len(inventory)
    
    # Create index (like AWS)
    index = {
        "metadata": {
            "subscription_id": subscription_id or list(by_subscription.keys())[0] if by_subscription else None,
            "generated_at": datetime.utcnow().isoformat() + 'Z',
            "report_folder": os.path.abspath(report_folder)
        },
        "summary": {
            "total_checks": total_checks,
            "total_resources": total_resources,
            "total_subscriptions": len(by_subscription)
        },
        "subscription_folders": subscription_folders,
        "files": {
            "index": "index.json"
        }
    }
    
    with open(os.path.join(report_folder, 'index.json'), 'w') as f:
        json.dump(index, f, indent=2)
    
    return os.path.abspath(report_folder)


# Backward compatibility - alias
save_scan_results = save_scan_results_aws_format

