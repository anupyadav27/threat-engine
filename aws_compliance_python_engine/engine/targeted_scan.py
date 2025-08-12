import os
import json
import argparse
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from aws_compliance_python_engine.auth.aws_auth import (
    get_boto3_session,
    get_session_for_account,
)
from aws_compliance_python_engine.engine.boto3_engine import (
    run_global_service,
    run_regional_service,
    load_enabled_services_with_scope,
    load_service_rules,
)
from aws_compliance_python_engine.utils.reporting_manager import save_reporting_bundle

import botocore


def _sts_account_id(session) -> Optional[str]:
    try:
        return session.client('sts').get_caller_identity().get('Account')
    except Exception:
        return None


def _list_regions(session) -> List[str]:
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        data = ec2.describe_regions(AllRegions=True)
        return sorted([r.get('RegionName') for r in (data.get('Regions') or []) if r.get('OptInStatus') in (None, 'opt-in-not-required', 'opted-in')])
    except botocore.exceptions.ClientError:
        return ['us-east-1']
    except Exception:
        return ['us-east-1']


def _index_checks(enabled_services_with_scope: List[Tuple[str, str]]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return mappings: check_id -> service_name, check_id -> param_name (resource key)"""
    check_to_service: Dict[str, str] = {}
    check_to_param: Dict[str, str] = {}
    for service_name, _ in enabled_services_with_scope:
        try:
            rules = load_service_rules(service_name)
        except Exception:
            continue
        for chk in rules.get('checks', []) or []:
            cid = chk.get('check_id')
            if cid:
                check_to_service[cid] = service_name
                if chk.get('param'):
                    check_to_param[cid] = chk.get('param')
    return check_to_service, check_to_param


def _filter_checks(checks: List[Dict[str, Any]], check_ids: Optional[Set[str]], resource_name: Optional[str], resource_param: Optional[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in checks or []:
        if check_ids and c.get('check_id') not in check_ids:
            continue
        if resource_name:
            key = resource_param
            # If record contains a field matching the resource_param or the key inferred from the check, use it strictly
            if key and key in c and c.get(key) != resource_name:
                continue
            if key and key not in c:
                # fallback heuristic: pass if any string value equals resource
                if resource_name not in [str(v) for v in c.values() if isinstance(v, (str, int))]:
                    continue
            if not key:
                if resource_name not in [str(v) for v in c.values() if isinstance(v, (str, int))]:
                    continue
        out.append(c)
    return out


def run_targeted_scan(
    account_id: Optional[str] = None,
    services: Optional[List[str]] = None,
    regions: Optional[List[str]] = None,
    check_ids: Optional[List[str]] = None,
    resource_name: Optional[str] = None,
    resource_param: Optional[str] = None,
    save_report: bool = False,
) -> List[Dict[str, Any]]:
    base_session = get_boto3_session()
    session = get_session_for_account(
        account_id=account_id,
        role_name=os.getenv('ASSUME_ROLE_NAME'),
        default_region=os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
        base_profile=os.getenv('AWS_PROFILE'),
        external_id=os.getenv('AWS_EXTERNAL_ID'),
    ) if account_id else base_session

    eff_account = account_id or _sts_account_id(session)

    enabled_services_with_scope = load_enabled_services_with_scope()
    # Derive services from inputs
    req_checks: Optional[Set[str]] = set([c.strip() for c in (check_ids or []) if c and c.strip()]) or None
    explicit_services: Optional[Set[str]] = set([s.strip() for s in (services or []) if s and s.strip()]) or None

    check_to_service, check_to_param = _index_checks(enabled_services_with_scope)

    if req_checks:
        derived_services = {check_to_service[c] for c in req_checks if c in check_to_service}
    else:
        derived_services = set()

    target_services: Set[str] = explicit_services or derived_services or {s for s, _ in enabled_services_with_scope}

    # Infer resource_param from the first requested check if not provided
    if not resource_param and req_checks:
        for c in req_checks:
            if c in check_to_param:
                resource_param = check_to_param[c]
                break

    requested_regions = list({r.strip() for r in (regions or []) if r and r.strip()})

    outputs: List[Dict[str, Any]] = []

    # Execute per service respecting scope
    for service_name, scope in enabled_services_with_scope:
        if service_name not in target_services:
            continue
        try:
            if scope == 'global':
                res = run_global_service(service_name, session)
                if req_checks or resource_name:
                    res = {**res, 'checks': _filter_checks(res.get('checks') or [], req_checks, resource_name, resource_param)}
                outputs.append(res)
            else:
                region_list = requested_regions or _list_regions(session)
                with ThreadPoolExecutor(max_workers=8) as pool:
                    futures = [pool.submit(run_regional_service, service_name, r, session) for r in region_list]
                    for fut in as_completed(futures):
                        try:
                            rres = fut.result()
                            if req_checks or resource_name:
                                rres = {**rres, 'checks': _filter_checks(rres.get('checks') or [], req_checks, resource_name, resource_param)}
                            outputs.append(rres)
                        except Exception:
                            pass
        except Exception:
            pass

    if save_report:
        save_reporting_bundle(outputs, account_id=eff_account)

    return outputs


def main():
    ap = argparse.ArgumentParser(description='Run a targeted AWS compliance scan (non-intrusive)')
    ap.add_argument('--account', help='Account ID to target (assumes role if configured)')
    ap.add_argument('--services', help='Comma-separated services to include (optional; auto-derived from checks if omitted)')
    ap.add_argument('--regions', help='Comma-separated regions (for regional services)')
    ap.add_argument('--check-ids', help='Comma-separated check IDs to include')
    ap.add_argument('--resource', help='Specific resource identifier to filter (e.g., i-123456, bucket-name)')
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
    print(json.dumps(outputs, indent=2))


if __name__ == '__main__':
    main() 