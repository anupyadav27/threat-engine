import os
import json
import fnmatch
from datetime import datetime
from typing import Any, Dict, List, Tuple
import yaml


def _config_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))


def _load_reporting_cfg() -> Tuple[str, Dict[str, str]]:
    path = os.path.join(_config_dir(), "reporting.yaml")
    cfg: Dict[str, Any] = {}
    if os.path.exists(path):
        with open(path) as fh:
            cfg = yaml.safe_load(fh) or {}
    base_dir = cfg.get("base_dir") or ""  # unused now; kept for backward compat
    filenames = cfg.get("filenames") or {}
    return base_dir, {
        "index": filenames.get("index", "index.json"),
        "inventories": filenames.get("inventories", "inventories.json"),
        "checks_main": filenames.get("checks_main", "main_checks.json"),
        "checks_skipped": filenames.get("checks_skipped", "skipped_checks.json"),
    }


def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def create_report_folder() -> str:
    # Create under package root: reporting/reporting_<UTC_TIMESTAMP>
    package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    base = os.path.join(package_root, "reporting")
    os.makedirs(base, exist_ok=True)
    folder = os.path.join(base, f"reporting_{_timestamp()}")
    os.makedirs(folder, exist_ok=True)
    return folder


def _meta(project_id: str | None, folder: str) -> Dict[str, Any]:
    return {
        "project_id": project_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "report_folder": os.path.abspath(folder),
    }


def _load_service_exceptions() -> List[Dict[str, Any]]:
    path = os.path.join(_config_dir(), "service_list.yaml")
    data = {}
    if os.path.exists(path):
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
    out: List[Dict[str, Any]] = []
    for s in (data.get("services") or []):
        for ex in (s.get("exceptions") or []):
            out.append({**ex, "service": s.get("name")})
    return out


def _load_check_exceptions() -> List[Dict[str, Any]]:
    path = os.path.join(_config_dir(), "check_exceptions.yaml")
    data = {}
    if os.path.exists(path):
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
    return list((data.get("exceptions") or []))


def _load_actions_config() -> Dict[str, Any]:
    path = os.path.join(_config_dir(), "actions.yaml")
    data = {}
    if os.path.exists(path):
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
    return data


def _load_actions_selection() -> Dict[str, List[str]]:
    path = os.path.join(_config_dir(), "actions_selection.yaml")
    data = {}
    if os.path.exists(path):
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


def save_reporting_bundle(results: List[Dict[str, Any]], project_id: str | None = None) -> str:
    # Create under package root: reporting/reporting_<UTC_TIMESTAMP>
    _, names = _load_reporting_cfg()
    package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    base = os.path.join(package_root, "reporting")
    os.makedirs(base, exist_ok=True)
    folder = os.path.join(base, f"reporting_{_timestamp()}")
    os.makedirs(folder, exist_ok=True)

    # Load policy files
    svc_exceptions = _load_service_exceptions()
    chk_exceptions = _load_check_exceptions()
    actions_cfg = _load_actions_config()
    selected_actions_by_check = _load_actions_selection()
    standard_actions = actions_cfg.get("standard_actions") or {}

    inventories: List[Dict[str, Any]] = []
    checks_main: List[Dict[str, Any]] = []
    checks_skipped: List[Dict[str, Any]] = []

    for r in results:
        service = r.get("service")
        proj = r.get("project")
        region = r.get("region")
        inventories.append({
            "project": proj,
            "service": service,
            "scope": r.get("scope"),
            "inventory": r.get("inventory") or r.get("discovery") or {},
        })
        for c in r.get("checks", []) or []:
            # Build the item with context
            item = {**c}
            item.setdefault("service", service)
            item.setdefault("project", proj)
            if region:
                item.setdefault("region", region)

            # Derive reporting_result based on exceptions
            reporting_result = item.get("reporting_result")

            # Service-level exceptions
            for ex in svc_exceptions:
                if ex.get("effect") not in {"mark_skipped", "skip_service"}:
                    continue
                if ex.get("service") != service:
                    continue
                sel = ex.get("selector") or {}
                if not _match_scope(proj, sel.get("project")):
                    continue
                if "region" in sel and not _match_scope(region, sel.get("region")):
                    continue
                if not _iso_not_expired(ex.get("expires_at")):
                    continue
                reporting_result = "SKIPPED"
                item["skip_meta"] = {
                    "id": ex.get("id"),
                    "scope": "service",
                    "reason": ex.get("reason"),
                    "expires_at": ex.get("expires_at"),
                }
                break

            # Check-level exceptions
            if reporting_result != "SKIPPED":
                for ex in chk_exceptions:
                    if ex.get("effect") not in {"mark_skipped", "skip_check"}:
                        continue
                    if ex.get("check_id") != item.get("check_id"):
                        continue
                    sel = ex.get("selector") or {}
                    if not _match_scope(proj, sel.get("project")):
                        continue
                    if "region" in sel and not _match_scope(region, sel.get("region")):
                        continue
                    if not _iso_not_expired(ex.get("expires_at")):
                        continue
                    reporting_result = "SKIPPED"
                    item["skip_meta"] = {
                        "id": ex.get("id"),
                        "scope": "check",
                        "reason": ex.get("reason"),
                        "expires_at": ex.get("expires_at"),
                    }
                    break

            # Attach actions for FAIL items using selections + standard actions
            if item.get("result") == "FAIL":
                selected = selected_actions_by_check.get(item.get("check_id")) or []
                if selected:
                    item["actions"] = [{"action": a, "args": (standard_actions.get(a) or {})} for a in selected]

            # Split
            if reporting_result == "SKIPPED":
                item["reporting_result"] = "SKIPPED"
                checks_skipped.append(item)
            else:
                checks_main.append(item)

    with open(os.path.join(folder, names["inventories"]), "w") as fh:
        json.dump({"metadata": _meta(project_id, folder), "inventories": inventories}, fh, indent=2)
    with open(os.path.join(folder, names["checks_main"]), "w") as fh:
        json.dump({"metadata": _meta(project_id, folder), "checks": checks_main}, fh, indent=2)
    with open(os.path.join(folder, names["checks_skipped"]), "w") as fh:
        json.dump({"metadata": _meta(project_id, folder), "checks": checks_skipped}, fh, indent=2)
    with open(os.path.join(folder, names["index"]), "w") as fh:
        json.dump({
            "metadata": _meta(project_id, folder),
            "summary": {
                "inventories": len(inventories),
                "checks_main": len(checks_main),
                "checks_skipped": len(checks_skipped),
            },
            "files": names,
        }, fh, indent=2)

    return os.path.abspath(folder) 