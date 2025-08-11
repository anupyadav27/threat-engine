import json
import os
from datetime import datetime
from typing import Any, Dict, List


def _ensure_directory(directory_path: str) -> None:
    if not os.path.isdir(directory_path):
        os.makedirs(directory_path, exist_ok=True)


def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def _compose_filepath(output_directory: str, project_id: str | None = None) -> str:
    ts = _timestamp()
    proj = project_id or "unknown"
    filename = f"scan_{proj}_{ts}.json"
    return os.path.join(output_directory, filename)


def save_scan_results(results: List[Dict[str, Any]], output_directory: str, project_id: str | None = None) -> str:
    _ensure_directory(output_directory)
    output_filepath = _compose_filepath(output_directory, project_id)
    payload = {
        "metadata": {
            "project_id": project_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
        "results": results,
    }
    with open(output_filepath, "w") as fh:
        json.dump(payload, fh, indent=2)
    return output_filepath


def save_split_scan_results(results: List[Dict[str, Any]], output_directory: str, project_id: str | None = None) -> str:
    ts = _timestamp()
    # Folder now only uses timestamp, not project id
    scan_folder = os.path.join(output_directory, f"scan_{ts}")
    _ensure_directory(scan_folder)

    service_to_results: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        svc = r.get("service", "unknown")
        service_to_results.setdefault(svc, []).append(r)

    index_summary: List[Dict[str, Any]] = []

    for service, svc_results in service_to_results.items():
        inventories: List[Dict[str, Any]] = []
        checks: List[Dict[str, Any]] = []
        for r in svc_results:
            inventories.append({
                "project": r.get("project"),
                "scope": r.get("scope"),
                "inventory": r.get("inventory") or r.get("discovery") or {},
            })
            for c in r.get("checks", []) or []:
                if "project" not in c:
                    c = {**c, "project": r.get("project")}
                checks.append(c)
        inv_path = os.path.join(scan_folder, f"{service}_inventory.json")
        chk_path = os.path.join(scan_folder, f"{service}_checks.json")
        with open(inv_path, "w") as fh:
            json.dump({
                "metadata": {
                    "project_id": project_id,
                    "service": service,
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                },
                "inventories": inventories,
            }, fh, indent=2)
        with open(chk_path, "w") as fh:
            json.dump({
                "metadata": {
                    "project_id": project_id,
                    "service": service,
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                },
                "checks": checks,
            }, fh, indent=2)
        index_summary.append({
            "service": service,
            "inventory_file": os.path.basename(inv_path),
            "checks_file": os.path.basename(chk_path),
            "inventory_entries": len(inventories),
            "checks_count": len(checks),
        })

    with open(os.path.join(scan_folder, "index.json"), "w") as fh:
        json.dump({
            "metadata": {
                "project_id": project_id,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "scan_folder": os.path.abspath(scan_folder),
            },
            "summary": index_summary,
        }, fh, indent=2)

    return os.path.abspath(scan_folder) 