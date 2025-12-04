import os
import json
import argparse
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from azure_compliance_python_engine.auth.azure_auth import (
    get_default_credential,
    get_credential_for_tenant,
)
from azure_compliance_python_engine.engine.azure_sdk_engine import (
    run_global_service,
    run_subscription_service,
    run_regional_service,
    run_tenant_service,
    load_enabled_services_with_scope,
    load_service_rules,
    load_service_scope_from_rules,
)
from azure_compliance_python_engine.utils.reporting_manager import save_reporting_bundle


def _index_checks(enabled_services_with_scope: List[Tuple[str, str]]) -> Tuple[Dict[str, str], Dict[str, str]]:
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
            if key and key in c and c.get(key) != resource_name:
                continue
            if key and key not in c:
                if resource_name not in [str(v) for v in c.values() if isinstance(v, (str, int))]:
                    continue
            if not key:
                if resource_name not in [str(v) for v in c.values() if isinstance(v, (str, int))]:
                    continue
        out.append(c)
    return out


def run_targeted_scan(
    tenant: Optional[str] = None,
    subscriptions: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    regions: Optional[List[str]] = None,
    check_ids: Optional[List[str]] = None,
    resource_name: Optional[str] = None,
    resource_param: Optional[str] = None,
    save_report: bool = False,
) -> List[Dict[str, Any]]:
    credential = get_credential_for_tenant(tenant) if tenant else get_default_credential()

    enabled_services_with_scope = load_enabled_services_with_scope()
    req_checks: Optional[Set[str]] = set([c.strip() for c in (check_ids or []) if c and c.strip()]) or None
    explicit_services: Optional[Set[str]] = set([s.strip() for s in (services or []) if s and s.strip()]) or None

    check_to_service, check_to_param = _index_checks(enabled_services_with_scope)

    if req_checks:
        derived_services = {check_to_service[c] for c in req_checks if c in check_to_service}
    else:
        derived_services = set()

    target_services: Set[str] = explicit_services or derived_services or {s for s, _ in enabled_services_with_scope}

    if not resource_param and req_checks:
        for c in req_checks:
            if c in check_to_param:
                resource_param = check_to_param[c]
                break

    requested_regions = list({r.strip() for r in (regions or []) if r and r.strip()})

    # Discover subscriptions if not provided
    if not subscriptions:
        # Basic discovery via SDK: list subscriptions is done inside the engine in main; here we expect caller to pass subs or rely on default context
        subscriptions = []

    outputs: List[Dict[str, Any]] = []

    for service_name, _scope in enabled_services_with_scope:
        if service_name not in target_services:
            continue
        scope = load_service_scope_from_rules(service_name) or _scope or 'subscription'
        try:
            if scope == 'tenant':
                # tenant: run once per tenant (e.g., AAD, Entra ID)
                res = run_tenant_service(service_name, tenant, credential)
                if req_checks or resource_name:
                    res = {**res, 'checks': _filter_checks(res.get('checks') or [], req_checks, resource_name, resource_param)}
                outputs.append(res)
            elif scope == 'global':
                # global: run once per subscription context (pass subscription if required by service semantics)
                res = run_global_service(service_name, tenant, (subscriptions[0] if subscriptions else None), credential)
                if req_checks or resource_name:
                    res = {**res, 'checks': _filter_checks(res.get('checks') or [], req_checks, resource_name, resource_param)}
                outputs.append(res)
            elif scope == 'regional':
                # regions within each subscription; if none provided, rely on engine defaults
                regions_list = requested_regions or []
                subs = subscriptions or [None]
                with ThreadPoolExecutor(max_workers=8) as pool:
                    futures = []
                    for sub in subs:
                        if regions_list:
                            for r in regions_list:
                                futures.append(pool.submit(run_regional_service, service_name, tenant, sub, r, credential))
                        else:
                            # Let engine determine regions if not provided by passing None (engine may expect a list; this path may result in no-ops)
                            pass
                    for fut in as_completed(futures):
                        try:
                            rres = fut.result()
                            if req_checks or resource_name:
                                rres = {**rres, 'checks': _filter_checks(rres.get('checks') or [], req_checks, resource_name, resource_param)}
                            outputs.append(rres)
                        except Exception:
                            pass
            else:
                # default subscription-scope
                subs = subscriptions or [None]
                with ThreadPoolExecutor(max_workers=8) as pool:
                    futures = [pool.submit(run_subscription_service, service_name, tenant, sub, credential) for sub in subs]
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
        save_reporting_bundle(outputs, tenant=tenant)

    return outputs


def main():
    ap = argparse.ArgumentParser(description='Run a targeted Azure compliance scan (non-intrusive)')
    ap.add_argument('--tenant', help='Tenant ID (optional)')
    ap.add_argument('--subscriptions', help='Comma-separated subscription IDs (optional)')
    ap.add_argument('--services', help='Comma-separated services to include (optional; auto-derived from checks if omitted)')
    ap.add_argument('--regions', help='Comma-separated regions (for regional services)')
    ap.add_argument('--check-ids', help='Comma-separated check IDs to include')
    ap.add_argument('--resource', help='Specific resource identifier to filter (e.g., vmName, storage account)')
    ap.add_argument('--resource-param', help='Record key name to match the resource (if omitted, inferred from check)')
    ap.add_argument('--save-report', action='store_true', help='Write a reporting bundle for the targeted scan')
    args = ap.parse_args()

    services = [s.strip() for s in (args.services or '').split(',') if s.strip()] or None
    regions = [r.strip() for r in (args.regions or '').split(',') if r.strip()] or None
    check_ids = [c.strip() for c in (args.check_ids or '').split(',') if c.strip()] or None
    subs = [s.strip() for s in (args.subscriptions or '').split(',') if s.strip()] or None

    outputs = run_targeted_scan(
        tenant=args.tenant,
        subscriptions=subs,
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