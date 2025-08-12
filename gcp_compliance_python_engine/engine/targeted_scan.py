import os
import json
import argparse
from typing import Any, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from gcp_compliance_python_engine.auth.gcp_auth import (
    get_default_project_id,
    get_compute_client,
)
from gcp_compliance_python_engine.engine.gcp_engine import (
    run_global_service,
    run_region_services,
)
from gcp_compliance_python_engine.utils.reporting_manager import save_reporting_bundle


def _list_compute_regions(project_id: str) -> List[str]:
    regions_list: List[str] = []
    try:
        compute = get_compute_client(project_id)
        req = compute.regions().list(project=project_id)
        while req is not None:
            resp = req.execute()
            for r in resp.get('items', []) or []:
                if r.get('name'):
                    regions_list.append(r.get('name'))
            req = compute.regions().list_next(previous_request=req, previous_response=resp)
    except Exception:
        pass
    return sorted(list({r for r in regions_list if r}))


def _filter_checks(checks: List[Dict[str, Any]], check_ids: Optional[Set[str]], resource_name: Optional[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in checks:
        if check_ids and c.get('check_id') not in check_ids:
            continue
        if resource_name and (c.get('resource') != resource_name):
            continue
        out.append(c)
    return out


def run_targeted_scan(
    project_id: Optional[str] = None,
    services: Optional[List[str]] = None,
    regions: Optional[List[str]] = None,
    check_ids: Optional[List[str]] = None,
    resource_name: Optional[str] = None,
    save_report: bool = False,
) -> List[Dict[str, Any]]:
    pid = project_id or get_default_project_id()
    if not pid:
        raise ValueError("project_id must be provided or default project must be set")

    requested_services = set([s.strip() for s in (services or []) if s and s.strip()]) or {"gcs", "compute"}
    requested_regions = list({r.strip() for r in (regions or []) if r and r.strip()})
    requested_check_ids = set([c.strip() for c in (check_ids or []) if c and c.strip()]) or None

    outputs: List[Dict[str, Any]] = []

    # GCS (global)
    if "gcs" in requested_services:
        try:
            result = run_global_service("gcs", pid)
            if requested_check_ids or resource_name:
                result = {
                    **result,
                    "checks": _filter_checks(result.get("checks") or [], requested_check_ids, resource_name),
                }
            outputs.append(result)
        except Exception:
            pass

    # Compute (regional)
    if "compute" in requested_services:
        region_list = requested_regions or _list_compute_regions(pid)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(run_region_services, "compute", r, pid) for r in region_list]
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if requested_check_ids or resource_name:
                        res = {
                            **res,
                            "checks": _filter_checks(res.get("checks") or [], requested_check_ids, resource_name),
                        }
                    outputs.append(res)
                except Exception:
                    pass

    if save_report:
        # Flatten to the reporting bundle format: list of service outputs
        save_reporting_bundle(outputs, project_id=pid)

    return outputs


def main():
    ap = argparse.ArgumentParser(description="Run a targeted GCP compliance scan without altering the main engine")
    ap.add_argument("--project", help="GCP project id (defaults to ADC project)")
    ap.add_argument("--services", help="Comma-separated services (compute,gcs)")
    ap.add_argument("--regions", help="Comma-separated regions (for compute)")
    ap.add_argument("--check-ids", help="Comma-separated check IDs to include")
    ap.add_argument("--resource", help="Specific resource name to filter (instance name, bucket name)")
    ap.add_argument("--save-report", action="store_true", help="Write a reporting bundle for the targeted scan")
    args = ap.parse_args()

    services = [s.strip() for s in (args.services or "").split(",") if s.strip()] or None
    regions = [r.strip() for r in (args.regions or "").split(",") if r.strip()] or None
    check_ids = [c.strip() for c in (args.check_ids or "").split(",") if c.strip()] or None

    outputs = run_targeted_scan(
        project_id=args.project,
        services=services,
        regions=regions,
        check_ids=check_ids,
        resource_name=args.resource,
        save_report=args.save_report,
    )
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main() 