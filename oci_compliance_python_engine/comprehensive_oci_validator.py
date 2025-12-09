#!/usr/bin/env python3
"""
Comprehensive OCI Validator
Runs quality analysis, optional corrections, then executes the enhanced tester.
"""

import argparse
import json
from datetime import datetime

from enhanced_oci_tester import run_test
from oci_quality_analyzer import run_analysis
from oci_smart_corrector import run_corrections


def main():
    ap = argparse.ArgumentParser(description="Full OCI validation loop: analyze -> (optional) correct -> test")
    ap.add_argument("--apply-fixes", action="store_true", help="Apply smart corrector before testing")
    ap.add_argument("--services", help="Comma separated services to include")
    ap.add_argument("--compartments", help="Comma separated compartment OCIDs to include")
    ap.add_argument("--regions", help="Comma separated regions to include")
    ap.add_argument("--save-report", action="store_true", help="Persist reporting bundle from tester")
    ap.add_argument("--config", default="~/.oci/config", help="OCI config file path")
    ap.add_argument("--profile", default="DEFAULT", help="OCI profile name")
    args = ap.parse_args()

    def _csv(val):
        return [v.strip() for v in val.split(",") if v.strip()] if val else None

    quality = run_analysis()
    corrections = None
    if args.apply_fixes:
        corrections = run_corrections(dry_run=False)

    test_results = run_test(
        config_file=args.config,
        profile=args.profile,
        services=_csv(args.services),
        compartments=_csv(args.compartments),
        regions=_csv(args.regions),
        save_report=args.save_report,
    )

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "quality": {
            "services_analyzed": quality.get("services_analyzed"),
            "total_issues": quality.get("total_issues"),
        },
        "corrections": corrections,
        "test": {
            "total_checks": test_results.get("total_checks_executed"),
            "total_resources": test_results.get("total_resources_discovered"),
            "accounts": test_results.get("total_accounts_scanned"),
            "regions": test_results.get("total_regions_scanned"),
            "services": test_results.get("total_services_scanned"),
        },
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
