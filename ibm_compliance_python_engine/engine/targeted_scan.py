#!/usr/bin/env python3
"""
Targeted IBM scan with full filtering capabilities

Aligned with main engine - supports:
- Service filtering
- Region filtering
- Check ID filtering
- Resource name filtering
- Save report bundle
"""

from __future__ import annotations

import argparse
import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from auth.ibm_auth import IBMCloudAuth
from engine.ibm_sdk_engine_v2 import load_enabled_services, process_service, get_account_id, load_service_rules
from utils.reporting_manager import save_reporting_bundle


def _filter_services(enabled: List[Tuple[str, str]], include: Optional[List[str]]) -> List[Tuple[str, str]]:
    """Filter services by name"""
    if not include:
        return enabled
    targets = {s.strip().lower() for s in include}
    return [(name, scope) for name, scope in enabled if name.lower() in targets]


def _index_checks(enabled_services: List[Tuple[str, str]]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return mappings: check_id -> service_name, check_id -> param_name (resource key)"""
    check_to_service: Dict[str, str] = {}
    check_to_param: Dict[str, str] = {}
    for service_name, _ in enabled_services:
        try:
            rules = load_service_rules(service_name)
            if not rules:
                continue
        except Exception:
            continue
        for chk in rules.get('checks', []) or []:
            cid = chk.get('check_id')
            if cid:
                check_to_service[cid] = service_name
                # Get param from for_each
                for_each = chk.get('for_each', '')
                if for_each:
                    param = for_each.split('.')[-1]
                    check_to_param[cid] = param
    return check_to_service, check_to_param


def _filter_checks(
    checks: List[Dict[str, Any]], 
    check_ids: Optional[Set[str]], 
    resource_name: Optional[str],
    resource_param: Optional[str]
) -> List[Dict[str, Any]]:
    """Filter checks by check_id and/or resource name"""
    out: List[Dict[str, Any]] = []
    for c in checks or []:
        # Filter by check_id
        if check_ids and c.get('check_id') not in check_ids:
            continue
        
        # Filter by resource name
        if resource_name:
            key = resource_param
            if key and key in c and c.get(key) != resource_name:
                continue
            if key and key not in c:
                # Fallback: check if resource_name appears in any field
                if resource_name not in [str(v) for v in c.values() if isinstance(v, (str, int))]:
                    continue
            if not key:
                # No param specified, check all values including resource_id, resource_name, resource_crn
                resource_fields = [
                    c.get('resource_id', ''),
                    c.get('resource_name', ''),
                    c.get('resource_crn', ''),
                ] + [str(v) for v in c.values() if isinstance(v, (str, int))]
                if resource_name not in ' '.join(resource_fields):
                    continue
        
        out.append(c)
    return out


def run_targeted_scan(
    account_id: Optional[str] = None,
    services: Optional[List[str]] = None,
    region: Optional[str] = None,
    check_ids: Optional[List[str]] = None,
    resource_name: Optional[str] = None,
    resource_param: Optional[str] = None,
    save_report: bool = False,
    output_dir: str = "output",
) -> List[Dict[str, Any]]:
    """
    Run targeted compliance scan for IBM Cloud
    
    Args:
        account_id: IBM Cloud account ID (optional, auto-detected)
        services: List of service names to scan (optional)
        region: Region to target (optional, e.g., us-south, eu-de)
        check_ids: List of specific check IDs to run (optional)
        resource_name: Specific resource identifier to filter (optional)
        resource_param: Record key name to match the resource (optional)
        save_report: Whether to save reporting bundle (default: False)
        output_dir: Directory to save reports (default: "output")
    
    Returns:
        List of scan results
    """
    # Initialize auth
    auth = IBMCloudAuth(region=region)
    if not auth.test_connection():
        raise RuntimeError("IBM auth failed. Ensure IBM_CLOUD_API_KEY and network access.")
    
    # Get account ID
    if not account_id:
        account_id = get_account_id(auth)
    
    # Load and filter services
    enabled_services = load_enabled_services()
    
    # Prepare filters
    req_checks: Optional[Set[str]] = set([c.strip() for c in (check_ids or []) if c and c.strip()]) or None
    explicit_services: Optional[List[str]] = services
    
    # Index checks to derive services and params
    check_to_service, check_to_param = _index_checks(enabled_services)
    
    # Derive services from check_ids if provided
    if req_checks:
        derived_services = [check_to_service[c] for c in req_checks if c in check_to_service]
        if derived_services:
            explicit_services = list(set(derived_services))
    
    # Filter services
    selected = _filter_services(enabled_services, explicit_services)
    
    if not selected:
        raise ValueError("No services selected. Enable in config/service_list.json or pass --services.")
    
    # Infer resource_param from the first requested check if not provided
    if not resource_param and req_checks:
        for c in req_checks:
            if c in check_to_param:
                resource_param = check_to_param[c]
                break
    
    # Execute scans
    results: List[Dict[str, Any]] = []
    for service_name, scope in selected:
        result = process_service(
            service_name, 
            "regional" if region else scope, 
            auth, 
            account_id, 
            region=region
        )
        if result:
            # Apply filters to checks
            if req_checks or resource_name:
                result = {
                    **result,
                    'checks': _filter_checks(
                        result.get('checks', []),
                        req_checks,
                        resource_name,
                        resource_param
                    )
                }
            results.append(result)
    
    # Save report if requested
    if save_report:
        os.makedirs(output_dir, exist_ok=True)
        save_reporting_bundle(results, account_id, output_directory=output_dir)
    
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Targeted IBM compliance scan")
    parser.add_argument("--account", help="IBM Cloud account ID (optional, auto-detected)")
    parser.add_argument("--services", help="Comma-separated list of services to scan")
    parser.add_argument("--region", help="Region to target (e.g., us-south, eu-de)")
    parser.add_argument("--check-ids", help="Comma-separated check IDs to include")
    parser.add_argument("--resource", help="Specific resource identifier to filter")
    parser.add_argument("--resource-param", help="Record key name to match the resource (if omitted, inferred from check)")
    parser.add_argument("--save-report", action="store_true", help="Write a reporting bundle for the targeted scan")
    parser.add_argument("--output-dir", default="output", help="Directory to save reporting bundle")
    parser.add_argument("--print-summary", action="store_true", help="Print pass/fail summary")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    
    services = [s.strip() for s in (args.services or '').split(',') if s.strip()] or None
    check_ids = [c.strip() for c in (args.check_ids or '').split(',') if c.strip()] or None
    
    try:
        results = run_targeted_scan(
            account_id=args.account,
            services=services,
            region=args.region,
            check_ids=check_ids,
            resource_name=args.resource,
            resource_param=args.resource_param,
            save_report=args.save_report,
            output_dir=args.output_dir,
        )
        
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            account_id = results[0].get('account_id', 'unknown') if results else 'unknown'
            print(f"Account: {account_id}")
            print(f"Services: {', '.join([r.get('service', 'unknown') for r in results])}")
            if args.region:
                print(f"Region: {args.region}")
            print("-" * 60)
            
            if args.print_summary:
                total_checks = sum(len(r.get("checks", [])) for r in results)
                total_pass = sum(
                    sum(1 for c in r.get("checks", []) if c.get("result") == "PASS")
                    for r in results
                )
                total_fail = sum(
                    sum(1 for c in r.get("checks", []) if c.get("result") == "FAIL")
                    for r in results
                )
                print(f"Checks: {total_pass} passed / {total_fail} failed / {total_checks} total")
            
            if args.save_report:
                print(f"✅ Targeted scan complete. Report saved to: {args.output_dir}")
            else:
                print(f"✅ Targeted scan complete.")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
