import os
import json
import fnmatch
from datetime import datetime
from typing import Any, Dict, List
import yaml


def _config_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))


def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def create_report_folder() -> str:
    package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    base = os.path.join(package_root, "reporting")
    os.makedirs(base, exist_ok=True)
    folder = os.path.join(base, f"reporting_{_timestamp()}")
    os.makedirs(folder, exist_ok=True)
    return folder


def _meta(tenant: str | None, folder: str) -> Dict[str, Any]:
    return {"tenant": tenant, "generated_at": datetime.utcnow().isoformat() + "Z", "report_folder": os.path.abspath(folder)}


def _load_service_exceptions() -> List[Dict[str, Any]]:
    path = os.path.join(_config_dir(), "service_list.json")
    data: Dict[str, Any] = {}
    if os.path.exists(path):
        with open(path) as fh:
            data = json.load(fh) or {}
    out: List[Dict[str, Any]] = []
    for s in (data.get("services") or []):
        for ex in (s.get("exceptions") or []):
            out.append({**ex, "service": s.get("name")})
    return out


def _load_check_exceptions() -> List[Dict[str, Any]]:
    path = os.path.join(_config_dir(), "check_exceptions.yaml")
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    return list((data.get("exceptions") or []))


def _load_actions_config() -> Dict[str, Any]:
    path = os.path.join(_config_dir(), "actions.yaml")
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def _load_actions_selection() -> Dict[str, List[str]]:
    path = os.path.join(_config_dir(), "actions_selection.yaml")
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    profiles = data.get("profiles") or {}
    active = data.get("active_profile") or "default"
    profile = profiles.get(active) or {}
    return (profile.get("selected_actions_by_check") or {})


def _iso_not_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return True
    try:
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        return datetime.utcnow() <= dt
    except Exception:
        return True


def _match_scope(val: str | None, pattern: str | None) -> bool:
    if pattern is None:
        return True
    if val is None:
        return False
    return fnmatch.fnmatch(val, pattern)


def save_reporting_bundle(results: List[Dict[str, Any]], tenant: str | None = None) -> str:
    """
    Save reporting bundle in AWS-compatible format
    
    AWS: reporting_TIMESTAMP/account_ID/ACCOUNTID_scope_service_checks.json
    Azure: reporting_TIMESTAMP/subscription_ID/SUBID_scope_service_checks.json
    """
    folder = create_report_folder()
    svc_ex = _load_service_exceptions()
    chk_ex = _load_check_exceptions()
    actions_cfg = _load_actions_config()
    selected = _load_actions_selection()
    standard_actions = actions_cfg.get("standard_actions") or {}

    # Group by subscription (like AWS groups by account)
    by_subscription: Dict[str, Dict[str, Any]] = {}

    for r in results:
        service = r.get("service")
        sub = r.get("subscription") or 'default'
        region = r.get("region")
        scope = r.get("scope", "subscription")
        
        if sub not in by_subscription:
            by_subscription[sub] = {
                'inventories': [],
                'checks_main': [],
                'checks_skipped': []
            }
        
        # Add inventory
        by_subscription[sub]['inventories'].append({
            "subscription": sub,
            "service": service,
            "scope": scope,
            "inventory": r.get("inventory") or r.get("discovery") or {},
        })
        
        for c in r.get("checks", []) or []:
            item = {**c}
            item.setdefault("service", service)
            item.setdefault("subscription", sub)
            if region:
                item.setdefault("region", region)

            reporting_result = item.get("reporting_result")

            for ex in svc_ex:
                if ex.get("effect") not in {"mark_skipped", "skip_service"}:
                    continue
                if ex.get("service") != service:
                    continue
                sel = ex.get("selector") or {}
                if not _match_scope(sub, sel.get("subscription")):
                    continue
                if "region" in sel and not _match_scope(region, sel.get("region")):
                    continue
                if not _iso_not_expired(ex.get("expires_at")):
                    continue
                reporting_result = "SKIPPED"
                item["skip_meta"] = {"id": ex.get("id"), "scope": "service", "reason": ex.get("reason"), "expires_at": ex.get("expires_at")}
                break

            if reporting_result != "SKIPPED":
                for ex in chk_ex:
                    if ex.get("effect") not in {"mark_skipped", "skip_check"}:
                        continue
                    if ex.get("check_id") != item.get("check_id"):
                        continue
                    sel = ex.get("selector") or {}
                    if not _match_scope(sub, sel.get("subscription")):
                        continue
                    if "region" in sel and not _match_scope(region, sel.get("region")):
                        continue
                    if not _iso_not_expired(ex.get("expires_at")):
                        continue
                    reporting_result = "SKIPPED"
                    item["skip_meta"] = {"id": ex.get("id"), "scope": "check", "reason": ex.get("reason"), "expires_at": ex.get("expires_at")}
                    break

            if item.get("result") == "FAIL":
                sel_actions = selected.get(item.get("check_id")) or []
                if sel_actions:
                    item["actions"] = [{"action": a, "args": (standard_actions.get(a) or {})} for a in sel_actions]

            if reporting_result == "SKIPPED":
                item["reporting_result"] = "SKIPPED"
                by_subscription[sub]['checks_skipped'].append(item)
            else:
                by_subscription[sub]['checks_main'].append(item)
    
    # Create AWS-compatible folder structure per subscription
    subscription_folders = []
    total_checks = 0
    
    for sub_id, sub_data in by_subscription.items():
        # Create subscription folder (like AWS account folder)
        sub_folder_name = f"subscription_{sub_id[:8]}" if sub_id != 'default' else 'subscription_default'
        sub_folder = os.path.join(folder, sub_folder_name)
        os.makedirs(sub_folder, exist_ok=True)
        subscription_folders.append(sub_folder_name)
        
        # Group by service for file naming
        service_checks = {}
        service_inventory = {}
        
        for inv in sub_data['inventories']:
            svc = inv.get('service', 'unknown')
            service_inventory[svc] = inv
        
        for check in sub_data['checks_main'] + sub_data['checks_skipped']:
            svc = check.get('service', 'unknown')
            service_checks.setdefault(svc, []).append(check)
        
        # Save per service in AWS format: {subscription}_{scope}_{service}_checks.json
        for svc, checks in service_checks.items():
            scope = service_inventory.get(svc, {}).get('scope', 'subscription')
            
            # Checks file
            checks_file = os.path.join(sub_folder, f"{sub_id[:8]}_{scope}_{svc}_checks.json")
            with open(checks_file, 'w') as fh:
                json.dump(checks, fh, indent=2, default=str)
            total_checks += len(checks)
            
            # Inventory file
            if svc in service_inventory:
                inv_file = os.path.join(sub_folder, f"{sub_id[:8]}_{scope}_{svc}_inventory.json")
                with open(inv_file, 'w') as fh:
                    json.dump(service_inventory[svc], fh, indent=2, default=str)
    
    # Create index matching AWS format
    with open(os.path.join(folder, "index.json"), "w") as fh:
        json.dump({
            "metadata": {
                "subscription_id": list(by_subscription.keys())[0] if by_subscription else None,
                "generated_at": datetime.utcnow().isoformat() + 'Z',
                "report_folder": os.path.abspath(folder)
            },
            "summary": {
                "total_checks": total_checks,
                "total_subscriptions": len(by_subscription)
            },
            "subscription_folders": subscription_folders,
            "files": {"index": "index.json"}
        }, fh, indent=2, default=str)

    return os.path.abspath(folder) 