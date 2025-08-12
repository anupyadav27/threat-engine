import os
import json
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


def _meta(cluster: str | None, folder: str) -> Dict[str, Any]:
    return {"cluster": cluster, "generated_at": datetime.utcnow().isoformat() + "Z", "report_folder": os.path.abspath(folder)}


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


def save_reporting_bundle(results: List[Dict[str, Any]], cluster: str | None = None) -> str:
    folder = create_report_folder()
    chk_ex = _load_check_exceptions()
    actions_cfg = _load_actions_config()
    selected = _load_actions_selection()
    standard_actions = actions_cfg.get("standard_actions") or {}

    inventories: List[Dict[str, Any]] = []
    checks_main: List[Dict[str, Any]] = []
    checks_skipped: List[Dict[str, Any]] = []

    for r in results:
        # k8 engine results are CheckResult objects typically; ensure dict
        service = r.get("service") if isinstance(r, dict) else None
        # inventories may not be structured; keep empty or attach raw if provided
        # For now, we only process checks
        pass

    # k8 engine emits a flat list of CheckResult; split into main vs skipped
    for c in (results or []):
        if not isinstance(c, dict):
            continue
        item = dict(c)
        reporting_result = item.get("reporting_result")
        # Apply check-level exceptions by check_id/namespace
        for ex in chk_ex:
            if ex.get("effect") not in {"mark_skipped", "skip_check"}:
                continue
            if ex.get("check_id") != item.get("check_id"):
                continue
            if not _iso_not_expired(ex.get("expires_at")):
                continue
            reporting_result = "SKIPPED"
            item["skip_meta"] = {"id": ex.get("id"), "scope": "check", "reason": ex.get("reason"), "expires_at": ex.get("expires_at")}
            break
        # Attach actions
        sel_actions = selected.get(item.get("check_id")) or []
        if sel_actions:
            item["actions"] = [{"action": a, "args": (standard_actions.get(a) or {})} for a in sel_actions]
        # Split
        if reporting_result == "SKIPPED":
            item["reporting_result"] = "SKIPPED"
            checks_skipped.append(item)
        else:
            checks_main.append(item)

    with open(os.path.join(folder, "inventories.json"), "w") as fh:
        json.dump({"metadata": _meta(cluster, folder), "inventories": inventories}, fh, indent=2)
    with open(os.path.join(folder, "main_checks.json"), "w") as fh:
        json.dump({"metadata": _meta(cluster, folder), "checks": checks_main}, fh, indent=2)
    with open(os.path.join(folder, "skipped_checks.json"), "w") as fh:
        json.dump({"metadata": _meta(cluster, folder), "checks": checks_skipped}, fh, indent=2)
    with open(os.path.join(folder, "index.json"), "w") as fh:
        json.dump({
            "metadata": _meta(cluster, folder),
            "summary": {"inventories": len(inventories), "checks_main": len(checks_main), "checks_skipped": len(checks_skipped)},
            "files": {"inventories": "inventories.json", "checks_main": "main_checks.json", "checks_skipped": "skipped_checks.json", "index": "index.json"}
        }, fh, indent=2)

    return os.path.abspath(folder) 