#!/usr/bin/env python3
"""
AliCloud Targeted Scan Engine
Runs filtered scans for specific accounts/regions/services/resources

Aligned with main engine - difference is filtering capability
"""

import os
import json
import argparse
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.alicloud_auth import AliCloudAuth
from engine.alicloud_sdk_engine import (
    run_global_service,
    run_regional_service,
    load_enabled_services_with_scope,
    load_service_rules,
)
from utils.reporting_manager import save_reporting_bundle


def _index_checks(enabled_services_with_scope: List[Tuple[str, str]]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return mappings: check_id -> service_name, check_id -> param_name (resource key)"""
    check_to_service: Dict[str, str] = {}
    check_to_param: Dict[str, str] = {}
    for service_name, _ in enabled_services_with_scope:
        try:
            rules = load_service_rules(service_name)
            service_config = rules.get(service_name, {})
        except Exception:
            continue
        for chk in service_config.get('checks', []) or []:
            cid = chk.get('check_id')
            if cid:
                check_to_service[cid] = service_name
                if chk.get('param'):
                    check_to_param[cid] = chk.get('param')
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
                # No param specified, check all values
                if resource_name not in [str(v) for v in c.values() if isinstance(v, (str, int))]:
                    continue
        
        out.append(c)
    return out


def _list_regions(auth: AliCloudAuth) -> List[str]:
    """Discover all available AliCloud regions"""
    try:
        client = auth.get_client()
        # AliCloud regions discovery
        regions = [
            'cn-hangzhou', 'cn-shanghai', 'cn-beijing', 'cn-shenzhen',
            'cn-hongkong', 'ap-southeast-1', 'us-west-1', 'us-east-1',
            'eu-central-1', 'ap-northeast-1'
        ]
        return regions
    except Exception:
        return ['cn-hangzhou']  # Default region


def run_targeted_scan(
    account_id: Optional[str] = None,
    services: Optional[List[str]] = None,
    regions: Optional[List[str]] = None,
    check_ids: Optional[List[str]] = None,
    resource_name: Optional[str] = None,
    resource_param: Optional[str] = None,
    save_report: bool = False,
) -> List[Dict[str, Any]]:
    """
    Run targeted compliance scan for AliCloud
    
    Args:
        account_id: AliCloud account ID (optional, uses default from auth)
        services: List of service names to scan (optional)
        regions: List of regions to scan (optional, discovers all if not provided)
        check_ids: List of specific check IDs to run (optional)
        resource_name: Specific resource identifier to filter (optional)
        resource_param: Record key name to match the resource (optional)
        save_report: Whether to save reporting bundle (default: False)
    
    Returns:
        List of scan results
    """
    # Initialize auth
    auth = AliCloudAuth()
    
    # Load enabled services
    enabled_services_with_scope = load_enabled_services_with_scope()
    
    # Prepare filters
    req_checks: Optional[Set[str]] = set([c.strip() for c in (check_ids or []) if c and c.strip()]) or None
    explicit_services: Optional[Set[str]] = set([s.strip() for s in (services or []) if s and s.strip()]) or None
    
    # Index checks to derive services and params
    check_to_service, check_to_param = _index_checks(enabled_services_with_scope)
    
    # Derive services from check_ids if provided
    if req_checks:
        derived_services = {check_to_service[c] for c in req_checks if c in check_to_service}
    else:
        derived_services = set()
    
    # Determine target services
    target_services: Set[str] = explicit_services or derived_services or {s for s, _ in enabled_services_with_scope}
    
    # Infer resource_param from the first requested check if not provided
    if not resource_param and req_checks:
        for c in req_checks:
            if c in check_to_param:
                resource_param = check_to_param[c]
                break
    
    # Prepare regions
    requested_regions = list({r.strip() for r in (regions or []) if r and r.strip()})
    
    outputs: List[Dict[str, Any]] = []
    
    # Execute per service respecting scope
    for service_name, scope in enabled_services_with_scope:
        if service_name not in target_services:
            continue
        
        try:
            if scope == 'global':
                # Run global service
                res = run_global_service(service_name, auth)
                if req_checks or resource_name:
                    res = {
                        **res,
                        'checks': _filter_checks(res.get('checks') or [], req_checks, resource_name, resource_param)
                    }
                outputs.append(res)
            else:
                # Run regional service
                region_list = requested_regions or _list_regions(auth)
                with ThreadPoolExecutor(max_workers=8) as pool:
                    futures = [pool.submit(run_regional_service, service_name, r, auth) for r in region_list]
                    for fut in as_completed(futures):
                        try:
                            rres = fut.result()
                            if req_checks or resource_name:
                                rres = {
                                    **rres,
                                    'checks': _filter_checks(rres.get('checks') or [], req_checks, resource_name, resource_param)
                                }
                            outputs.append(rres)
                        except Exception:
                            pass
        except Exception:
            pass
    
    # Save report if requested
    if save_report:
        save_reporting_bundle(outputs, account_id=account_id or 'alicloud_account')
    
    return outputs


def main():
    """Command-line interface for targeted AliCloud scan"""
    ap = argparse.ArgumentParser(description='Run a targeted AliCloud compliance scan')
    ap.add_argument('--account', help='Account ID (optional, uses default from credentials)')
    ap.add_argument('--services', help='Comma-separated services to include (optional; auto-derived from checks if omitted)')
    ap.add_argument('--regions', help='Comma-separated regions (for regional services)')
    ap.add_argument('--check-ids', help='Comma-separated check IDs to include')
    ap.add_argument('--resource', help='Specific resource identifier to filter (e.g., instance-id, bucket-name)')
    ap.add_argument('--resource-param', help='Record key name to match the resource (if omitted, inferred from check)')
    ap.add_argument('--save-report', action='store_true', help='Write a reporting bundle for the targeted scan')
    args = ap.parse_args()
    
    services = [s.strip() for s in (args.services or '').split(',') if s.strip()] or None
    regions = [r.strip() for r in (args.regions or '').split(',') if r.strip()] or None
    check_ids = [c.strip() for c in (args.check_ids or '').split(',') if c.strip()] or None
    
    outputs = run_targeted_scan(
        account_id=args.account,
        services=services,
        regions=regions,
        check_ids=check_ids,
        resource_name=args.resource,
        resource_param=args.resource_param,
        save_report=args.save_report,
    )
    print(json.dumps(outputs, indent=2, default=str))


if __name__ == '__main__':
    main()
