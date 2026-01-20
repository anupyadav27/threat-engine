#!/usr/bin/env python3
"""
OCI Targeted Scan
Runs a filtered scan for specific compartments/regions/services and emits a concise report.
"""

import argparse
import json
from typing import Any, Dict, List, Optional, Set

from engine.enhanced_oci_engine import EnhancedOciEngine


def _csv(val: Optional[str]) -> Optional[List[str]]:
    if not val:
        return None
    return [v.strip() for v in val.split(",") if v.strip()]


def _filter_checks(checks: List[Dict[str, Any]], check_ids: Optional[Set[str]], resource_name: Optional[str]) -> List[Dict[str, Any]]:
    if not checks:
        return []
    out: List[Dict[str, Any]] = []
    for c in checks:
        if check_ids and c.get("check_id") not in check_ids:
            continue
        if resource_name and resource_name not in str(c.get("resource_name") or c.get("resource_id") or ""):
            continue
        out.append(c)
    return out


def run_targeted_scan(
    services: Optional[List[str]],
    compartments: Optional[List[str]],
    regions: Optional[List[str]],
    check_ids: Optional[List[str]],
    resource_name: Optional[str],
) -> List[Dict[str, Any]]:
    engine = EnhancedOciEngine(
        filter_services=services,
        filter_compartments=compartments,
        filter_regions=regions,
    )
    results = engine.execute_comprehensive_scan()
    flattened = engine._flatten_results_for_reporting(results)  # type: ignore[attr-defined]
    check_id_set = set([c.strip() for c in (check_ids or []) if c.strip()]) or None

    filtered = _filter_checks(flattened, check_id_set, resource_name)
    print(json.dumps({"checks": len(filtered), "filters": {"services": services, "compartments": compartments, "regions": regions, "check_ids": check_ids, "resource": resource_name}}, indent=2))
    return filtered


def main():
    ap = argparse.ArgumentParser(description="Run a targeted OCI compliance scan")
    ap.add_argument("--services", help="Comma separated services to include")
    ap.add_argument("--compartments", help="Comma separated compartment OCIDs to include")
    ap.add_argument("--regions", help="Comma separated regions to include")
    ap.add_argument("--check-ids", help="Comma separated check IDs to include")
    ap.add_argument("--resource", help="Filter by resource name/id substring")
    args = ap.parse_args()

    run_targeted_scan(
        services=_csv(args.services),
        compartments=_csv(args.compartments),
        regions=_csv(args.regions),
        check_ids=_csv(args.check_ids),
        resource_name=args.resource,
    )


if __name__ == "__main__":
    main()
