import os
import json
import argparse
from typing import Any, Dict, List, Tuple
from datetime import datetime

from gcp_compliance_python_engine.auth.gcp_auth import (
    get_compute_client,
    get_storage_client,
)

import yaml


def _config_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))


def _load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    return data


def _load_actions_selection() -> Dict[str, List[str]]:
    sel_path = os.path.join(_config_dir(), "actions_selection.yaml")
    data = _load_yaml(sel_path)
    profiles = data.get("profiles") or {}
    active = data.get("active_profile") or "default"
    profile = profiles.get(active) or {}
    return (profile.get("selected_actions_by_check") or {})


def _load_actions_catalog() -> Tuple[Dict[str, Any], Dict[str, Dict[str, str]]]:
    cfg_path = os.path.join(_config_dir(), "actions.yaml")
    data = _load_yaml(cfg_path)
    return (data.get("standard_actions") or {}), (data.get("arg_paths") or {})


def _load_reporting_folder(report_folder: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    checks_main_path = os.path.join(report_folder, "main_checks.json")
    checks_skipped_path = os.path.join(report_folder, "skipped_checks.json")
    inventories_path = os.path.join(report_folder, "inventories.json")

    with open(checks_main_path) as fh:
        main_checks = json.load(fh).get("checks") or []
    with open(checks_skipped_path) as fh:
        skipped_checks = json.load(fh).get("checks") or []
    with open(inventories_path) as fh:
        inventories = json.load(fh)
    return main_checks, skipped_checks, inventories


def _build_indexes(inventories_payload: Dict[str, Any]) -> Dict[str, Any]:
    indexes: Dict[str, Any] = {
        "compute_instances": {},   # (project, name) -> {zone, region}
        "compute_firewalls": {},   # (project, name) -> {..}
        "gcs_buckets": {},         # (project, bucket_name) -> {location, ...}
    }
    for entry in inventories_payload.get("inventories", []) or []:
        project = entry.get("project")
        service = entry.get("service")
        inv = entry.get("inventory") or {}
        if service == "compute":
            for inst in inv.get("instances", []) or []:
                name = inst.get("name")
                if name:
                    indexes["compute_instances"][(project, name)] = {
                        "zone": inst.get("zone"),
                        "region": inst.get("region"),
                    }
            for fw in inv.get("firewalls", []) or []:
                name = fw.get("name")
                if name:
                    indexes["compute_firewalls"][(project, name)] = fw
        elif service == "gcs":
            # Prefer metadata list, fallback to names only
            for meta in inv.get("bucket_metadata", []) or []:
                name = meta.get("name")
                if name:
                    indexes["gcs_buckets"][(project, name)] = meta
            for name in inv.get("list_buckets", []) or []:
                indexes["gcs_buckets"].setdefault((project, name), {"name": name})
    return indexes


def _ensure_actions(item: Dict[str, Any], selections: Dict[str, List[str]], standard_actions: Dict[str, Any]) -> List[Dict[str, Any]]:
    if item.get("actions"):
        return item["actions"]
    selected = selections.get(item.get("check_id")) or []
    return [{"action": a, "args": (standard_actions.get(a) or {})} for a in selected]


def _execute_compute_stop(enforce: bool, project: str, instance: str, zone: str) -> Tuple[str, str]:
    if not enforce:
        return ("DRY_RUN", f"compute.instances.stop project={project} zone={zone} instance={instance}")
    try:
        comp = get_compute_client(project)
        req = comp.instances().stop(project=project, zone=zone, instance=instance)
        resp = req.execute()
        return ("SUCCESS", json.dumps(resp))
    except Exception as e:
        return ("ERROR", str(e))


def _execute_notify(enforce: bool, project: str, item: Dict[str, Any], args: Dict[str, Any]) -> Tuple[str, str]:
    # Stub: integrate Slack/webhook later
    desc = {"channel": args.get("channel"), "severity": args.get("severity"), "template": args.get("template")}
    return ("DRY_RUN" if not enforce else "SUCCESS", json.dumps(desc))


def _execute_quarantine(enforce: bool, project: str, item: Dict[str, Any], args: Dict[str, Any]) -> Tuple[str, str]:
    # Placeholder: add network tag to instance, etc.
    return ("NOT_IMPLEMENTED", "quarantine action not implemented yet")


def _execute_set_logging(enforce: bool, project: str, bucket: str, args: Dict[str, Any]) -> Tuple[str, str]:
    # Placeholder for setting GCS logging; implement with google-cloud-storage if needed
    desc = {"bucket": bucket, "log_bucket": args.get("log_bucket"), "log_prefix": args.get("log_prefix")}
    return ("DRY_RUN" if not enforce else "NOT_IMPLEMENTED", json.dumps(desc))


def _execute_invoke_function(enforce: bool, project: str, item: Dict[str, Any], args: Dict[str, Any]) -> Tuple[str, str]:
    # Placeholder: call HTTP-triggered function or Pub/Sub
    return ("NOT_IMPLEMENTED", json.dumps(args))


def _run_action_for_item(item: Dict[str, Any], action: Dict[str, Any], indexes: Dict[str, Any], enforce: bool) -> Dict[str, Any]:
    service = item.get("service")
    project = item.get("project")
    resource = item.get("resource")
    name = action.get("action")
    args = action.get("args") or {}

    status = "SKIPPED"
    details = ""

    if service == "compute":
        if name == "stop":
            idx = indexes.get("compute_instances", {})
            info = idx.get((project, resource)) or {}
            zone = info.get("zone")
            if not zone:
                status, details = ("ERROR", "zone not found for instance")
            else:
                status, details = _execute_compute_stop(enforce, project, resource, zone)
        elif name in ("tag", "untag", "quarantine"):
            status, details = ("NOT_IMPLEMENTED", f"{name} for compute not implemented yet")
        elif name == "notify":
            status, details = _execute_notify(enforce, project, item, args)
        elif name == "invoke_function":
            status, details = _execute_invoke_function(enforce, project, item, args)
        else:
            status, details = ("UNKNOWN_ACTION", name)

    elif service == "gcs":
        if name == "set-logging":
            status, details = _execute_set_logging(enforce, project, resource, args)
        elif name in ("notify", "invoke_function"):
            if name == "notify":
                status, details = _execute_notify(enforce, project, item, args)
            else:
                status, details = _execute_invoke_function(enforce, project, item, args)
        else:
            status, details = ("NOT_IMPLEMENTED", f"{name} for gcs not implemented yet")

    else:
        # Other services can be added here
        if name == "notify":
            status, details = _execute_notify(enforce, project, item, args)
        elif name == "invoke_function":
            status, details = _execute_invoke_function(enforce, project, item, args)
        else:
            status, details = ("NOT_IMPLEMENTED", f"service {service} action {name} not implemented")

    return {
        "check_id": item.get("check_id"),
        "service": service,
        "project": project,
        "resource": resource,
        "action": name,
        "status": status,
        "details": details,
    }


def run(report_folder: str, enforce: bool = False) -> str:
    main_checks, skipped_checks, inv_payload = _load_reporting_folder(report_folder)
    all_checks = [c for c in (main_checks + skipped_checks) if (c.get("result") == "FAIL")]

    # Ensure actions are present; if not, compute from selections + catalog
    selections = _load_actions_selection()
    standard_actions, _arg_paths = _load_actions_catalog()

    # Build indexes for param resolution
    indexes = _build_indexes(inv_payload)

    results: List[Dict[str, Any]] = []

    for item in all_checks:
        actions = _ensure_actions(item, selections, standard_actions)
        if not actions:
            continue
        for act in actions:
            results.append(_run_action_for_item(item, act, indexes, enforce))

    out = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "report_folder": os.path.abspath(report_folder),
            "enforce": enforce,
        },
        "results": results,
    }
    out_path = os.path.join(report_folder, "action_results.json")
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    return out_path


def main():
    ap = argparse.ArgumentParser(description="Run remediation actions based on reporting outputs")
    ap.add_argument("--report-folder", required=True, help="Path to reporting_<timestamp> folder")
    ap.add_argument("--enforce", action="store_true", help="Execute real changes (default: dry-run)")
    args = ap.parse_args()
    path = run(args.report_folder, enforce=args.enforce)
    print(path)


if __name__ == "__main__":
    main() 