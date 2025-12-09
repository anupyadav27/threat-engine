#!/usr/bin/env python3
"""
Enhanced OCI Tester
Lightweight runner that wraps the enhanced engine with targeting flags.
"""

import argparse
import json
from datetime import datetime
from typing import List, Optional

from engine.enhanced_oci_engine import EnhancedOciEngine
from utils.reporting_manager import save_reporting_bundle


def _parse_csv(val: Optional[str]) -> Optional[List[str]]:
    if not val:
        return None
    return [v.strip() for v in val.split(",") if v.strip()]


def run_test(
    config_file: str,
    profile: str,
    services: Optional[List[str]],
    compartments: Optional[List[str]],
    regions: Optional[List[str]],
    save_report: bool,
) -> dict:
    engine = EnhancedOciEngine(
        config_file=config_file,
        profile=profile,
        filter_services=services,
        filter_compartments=compartments,
        filter_regions=regions,
    )

    results = engine.execute_comprehensive_scan()
    flattened = engine._flatten_results_for_reporting(results)  # type: ignore[attr-defined]

    if save_report:
        save_reporting_bundle(flattened, account_id=results.get("scan_metadata", {}).get("tenancy"))

    summary = {
        "session": results.get("scan_metadata", {}).get("session_id"),
        "accounts": results.get("total_accounts_scanned"),
        "regions": results.get("total_regions_scanned"),
        "checks": results.get("total_checks_executed"),
        "resources": results.get("total_resources_discovered"),
        "services": results.get("total_services_scanned"),
        "filters": {
            "services": services,
            "compartments": compartments,
            "regions": regions,
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    print(json.dumps(summary, indent=2))
    return results


def main():
    ap = argparse.ArgumentParser(description="Run enhanced OCI tester with optional targeting filters")
    ap.add_argument("--config", default="~/.oci/config", help="OCI config file path")
    ap.add_argument("--profile", default="DEFAULT", help="OCI config profile")
    ap.add_argument("--services", help="Comma separated services to include (default: all)")
    ap.add_argument("--compartments", help="Comma separated compartment OCIDs to include")
    ap.add_argument("--regions", help="Comma separated regions to include")
    ap.add_argument("--save-report", action="store_true", help="Persist reporting bundle")
    args = ap.parse_args()

    run_test(
        config_file=args.config,
        profile=args.profile,
        services=_parse_csv(args.services),
        compartments=_parse_csv(args.compartments),
        regions=_parse_csv(args.regions),
        save_report=args.save_report,
    )


if __name__ == "__main__":
    main()
