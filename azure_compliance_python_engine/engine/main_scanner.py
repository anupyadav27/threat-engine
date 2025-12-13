#!/usr/bin/env python3
"""
Azure Unified Flexible Scanner

Supports all granularity levels:
- Tenant-wide (all subscriptions)
- Multi-subscription
- Single subscription
- Single location
- Single service
- Single resource
"""

import os
import sys
import logging
import fnmatch
from typing import List, Dict, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.azure_auth import get_default_credential, get_credential_for_tenant
from utils.subscription_scanner import (
    list_subscriptions,
    get_current_subscription_id,
    list_locations,
    filter_subscriptions_by_config,
    filter_locations_by_config
)
from engine.service_scanner import (
    run_global_service,
    run_regional_service,
    load_enabled_services_with_scope
)
from utils.reporting_manager import (
    create_scan_folder,
    setup_scan_logging,
)
from utils.simple_reporter import save_scan_results

logger = logging.getLogger(__name__)


def resolve_subscriptions(
    subscription: Optional[str],
    include_subscriptions: Optional[List[str]],
    exclude_subscriptions: Optional[List[str]],
    credential
) -> List[Dict[str, str]]:
    """Resolve which subscriptions to scan"""
    
    if subscription:
        # Single specific subscription
        return [{
            'subscription_id': subscription,
            'display_name': f'Subscription-{subscription}',
            'state': 'Enabled',
            'tenant_id': 'unknown'
        }]
    
    if include_subscriptions:
        # Multiple specific subscriptions
        return [
            {
                'subscription_id': sub_id,
                'display_name': f'Subscription-{sub_id}',
                'state': 'Enabled',
                'tenant_id': 'unknown'
            }
            for sub_id in include_subscriptions
        ]
    
    # All subscriptions in tenant
    all_subscriptions = list_subscriptions(credential)
    
    if not all_subscriptions:
        # Fallback to current subscription
        current_sub = get_current_subscription_id(credential)
        if current_sub:
            all_subscriptions = [{
                'subscription_id': current_sub,
                'display_name': 'Current Subscription',
                'state': 'Enabled',
                'tenant_id': 'unknown'
            }]
        else:
            return []
    
    # Apply exclusions
    if exclude_subscriptions:
        exclude_set = set(exclude_subscriptions)
        all_subscriptions = [s for s in all_subscriptions 
                            if s['subscription_id'] not in exclude_set]
    
    return all_subscriptions


def resolve_locations(
    location: Optional[str],
    include_locations: Optional[List[str]],
    exclude_locations: Optional[List[str]],
    credential,
    subscription_id: str
) -> List[str]:
    """Resolve which locations to scan"""
    
    if location:
        # Single specific location
        return [location]
    
    if include_locations:
        # Multiple specific locations
        return include_locations
    
    # All locations
    all_locations = list_locations(credential, subscription_id)
    
    # Apply exclusions
    if exclude_locations:
        exclude_set = set(exclude_locations)
        all_locations = [loc for loc in all_locations if loc not in exclude_set]
    
    return all_locations


def resolve_services(
    service: Optional[str],
    include_services: Optional[List[str]],
    exclude_services: Optional[List[str]]
) -> List[tuple]:
    """Resolve which services to scan"""
    
    all_services = load_enabled_services_with_scope()
    
    if service:
        # Single specific service
        for svc_name, scope in all_services:
            if svc_name == service:
                return [(svc_name, scope)]
        raise ValueError(f"Service '{service}' not found or not enabled")
    
    if include_services:
        # Multiple specific services
        include_set = set(include_services)
        filtered = [(s, scope) for s, scope in all_services if s in include_set]
        if not filtered:
            raise ValueError(f"None of the specified services are enabled")
        return filtered
    
    # All enabled services
    services = all_services
    
    # Apply exclusions
    if exclude_services:
        exclude_set = set(exclude_services)
        services = [(s, scope) for s, scope in services if s not in exclude_set]
    
    return services


def create_resource_filter(
    resource: Optional[str],
    resource_pattern: Optional[str],
    resource_type: Optional[str]
) -> Optional[Callable]:
    """Create resource filter function"""
    
    if resource:
        return lambda r: r.get('resource_id') == resource
    
    if resource_pattern:
        return lambda r: fnmatch.fnmatch(r.get('resource_id', ''), resource_pattern)
    
    if resource_type:
        return lambda r: r.get('resource_type') == resource_type
    
    return None


def scan_service_in_scope(
    subscription_id: str,
    location: str,
    service_name: str,
    scope: str,
    credential,
    resource_filter: Optional[Callable]
) -> Dict[str, Any]:
    """Scan a single service with optional resource filtering"""
    
    try:
        if scope == 'global':
            result = run_global_service(service_name, subscription_id, credential_override=credential)
        else:
            result = run_regional_service(service_name, location, subscription_id, credential_override=credential)
        
        # Apply resource filter if specified
        if resource_filter and result.get('checks'):
            filtered_checks = [
                check for check in result['checks']
                if resource_filter({'resource_id': check.get('resource_id', check.get('name'))})
            ]
            result['checks'] = filtered_checks
            logger.info(f"Filtered to {len(filtered_checks)} checks")
        
        result['subscription'] = subscription_id
        result['location'] = location if scope != 'global' else 'global'
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to scan {service_name} in {subscription_id}/{location}: {e}")
        return {
            'service': service_name,
            'subscription': subscription_id,
            'location': location,
            'scope': scope,
            'checks': [],
            'error': str(e)
        }


def scan_subscription_scope(
    subscription: Dict[str, str],
    locations: List[str],
    services: List[tuple],
    resource_filter: Optional[Callable],
    credential,
    max_workers: int
) -> List[Dict[str, Any]]:
    """Scan one subscription with specified scope"""
    
    subscription_id = subscription['subscription_id']
    
    # Build scan tasks
    tasks = []
    for service_name, scope in services:
        if scope == 'global':
            tasks.append({
                'subscription_id': subscription_id,
                'location': 'global',
                'service_name': service_name,
                'scope': scope,
                'credential': credential
            })
        else:
            for location in locations:
                tasks.append({
                    'subscription_id': subscription_id,
                    'location': location,
                    'service_name': service_name,
                    'scope': scope,
                    'credential': credential
                })
    
    logger.info(f"  Scan tasks: {len(tasks)}")
    
    # Execute tasks in parallel
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                scan_service_in_scope,
                task['subscription_id'],
                task['location'],
                task['service_name'],
                task['scope'],
                task['credential'],
                resource_filter
            ): task
            for task in tasks
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                task = futures[future]
                logger.error(f"Task failed: {task['service_name']}: {e}")
    
    return results


def scan(
    # Subscription scope
    subscription: Optional[str] = None,
    include_subscriptions: Optional[List[str]] = None,
    exclude_subscriptions: Optional[List[str]] = None,
    
    # Location scope
    location: Optional[str] = None,
    include_locations: Optional[List[str]] = None,
    exclude_locations: Optional[List[str]] = None,
    
    # Service scope
    service: Optional[str] = None,
    include_services: Optional[List[str]] = None,
    exclude_services: Optional[List[str]] = None,
    
    # Resource scope
    resource: Optional[str] = None,
    resource_pattern: Optional[str] = None,
    resource_type: Optional[str] = None,
    
    # Performance
    max_subscription_workers: int = 3,
    max_workers: int = 10,
    
    # Auth
    tenant_id: Optional[str] = None,
    
    # Output
    save_report: bool = True
) -> List[Dict[str, Any]]:
    """
    Flexible Azure compliance scanner
    
    Args:
        subscription: Single subscription ID
        include_subscriptions: Multiple subscription IDs
        exclude_subscriptions: Subscriptions to exclude
        location: Single location
        include_locations: Multiple locations
        exclude_locations: Locations to exclude
        service: Single service
        include_services: Multiple services
        exclude_services: Services to exclude
        resource: Single resource ID
        resource_pattern: Resource ID pattern
        resource_type: Filter by resource type
        max_subscription_workers: Parallel subscription scanning (default: 3)
        max_workers: Parallel service/location scanning (default: 10)
        tenant_id: Azure tenant ID (optional)
        save_report: Save results
    
    Returns:
        List of scan results
    """
    
    # Create scan folder and logging
    scan_folder, scan_id = create_scan_folder()
    logger = setup_scan_logging(scan_folder, scan_id)
    
    logger.info("="*80)
    logger.info("AZURE FLEXIBLE COMPLIANCE SCANNER")
    logger.info("="*80)
    
    # Get credential
    credential = get_credential_for_tenant(tenant_id) if tenant_id else get_default_credential()
    
    # Resolve scope
    subscriptions_to_scan = resolve_subscriptions(
        subscription, include_subscriptions, exclude_subscriptions, credential
    )
    
    if not subscriptions_to_scan:
        logger.error("No subscriptions to scan")
        return []
    
    # Get locations from first subscription
    first_sub_id = subscriptions_to_scan[0]['subscription_id']
    locations_to_scan = resolve_locations(
        location, include_locations, exclude_locations, credential, first_sub_id
    )
    
    services_to_scan = resolve_services(service, include_services, exclude_services)
    resource_filter = create_resource_filter(resource, resource_pattern, resource_type)
    
    # Log scope
    logger.info(f"\nScan Scope:")
    logger.info(f"  Subscriptions: {len(subscriptions_to_scan)} - {[s['subscription_id'] for s in subscriptions_to_scan]}")
    logger.info(f"  Locations: {len(locations_to_scan)} - {locations_to_scan}")
    logger.info(f"  Services: {len(services_to_scan)} - {[s for s, _ in services_to_scan]}")
    
    logger.info(f"\nParallelism:")
    logger.info(f"  Subscription workers: {max_subscription_workers}")
    logger.info(f"  Service/location workers: {max_workers}")
    
    # Scan subscriptions
    all_results = []
    
    if max_subscription_workers == 1:
        # Sequential
        logger.info("\nScanning subscriptions sequentially...")
        for idx, sub in enumerate(subscriptions_to_scan, 1):
            logger.info(f"[{idx}/{len(subscriptions_to_scan)}] Scanning {sub['display_name']} ({sub['subscription_id']})")
            results = scan_subscription_scope(
                sub, locations_to_scan, services_to_scan, resource_filter,
                credential, max_workers
            )
            all_results.extend(results)
    else:
        # Parallel
        logger.info(f"\nScanning {len(subscriptions_to_scan)} subscriptions in parallel (max {max_subscription_workers})...")
        
        with ThreadPoolExecutor(max_workers=max_subscription_workers) as executor:
            future_to_sub = {
                executor.submit(
                    scan_subscription_scope,
                    sub, locations_to_scan, services_to_scan, resource_filter,
                    credential, max_workers
                ): sub
                for sub in subscriptions_to_scan
            }
            
            completed = 0
            for future in as_completed(future_to_sub):
                sub = future_to_sub[future]
                completed += 1
                
                try:
                    results = future.result()
                    all_results.extend(results)
                    total_checks = sum(len(r.get('checks', [])) for r in results)
                    logger.info(f"[{completed}/{len(subscriptions_to_scan)}] ✓ {sub['display_name']}: {total_checks} checks")
                except Exception as e:
                    logger.error(f"[{completed}/{len(subscriptions_to_scan)}] ✗ {sub['display_name']}: {e}")
    
    # Summary
    total_checks = sum(len(r.get('checks', [])) for r in all_results)
    total_passed = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'PASS') for r in all_results)
    total_failed = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'FAIL') for r in all_results)
    
    logger.info("\n" + "="*80)
    logger.info("SCAN COMPLETE")
    logger.info("="*80)
    logger.info(f"Total checks: {total_checks}")
    logger.info(f"  PASS: {total_passed}")
    logger.info(f"  FAIL: {total_failed}")
    
    # Save report
    if save_report:
        save_scan_results(all_results, scan_folder)
        logger.info(f"\nReport: {scan_folder}")
        logger.info(f"Latest: {os.path.join(os.path.dirname(scan_folder), 'latest')}")
    
    return all_results


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Azure Flexible Compliance Scanner - All Granularity Levels',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full tenant (all subscriptions)
  %(prog)s --tenant-id xxx
  
  # Single subscription
  %(prog)s --subscription xxx-xxx-xxx
  
  # Single subscription + location
  %(prog)s --subscription xxx --location eastus
  
  # Single subscription + location + service
  %(prog)s --subscription xxx --location eastus --service storage
  
  # Single subscription + location + service + resource
  %(prog)s --subscription xxx --location eastus --service storage --resource mystorageaccount
  
  # Multiple subscriptions
  %(prog)s --include-subscriptions "sub1,sub2,sub3"
  
  # Pattern matching
  %(prog)s --subscription xxx --service storage --resource-pattern "*prod*"
        """
    )
    
    # Subscription scope
    sub_group = parser.add_mutually_exclusive_group()
    sub_group.add_argument('--subscription', help='Single subscription ID')
    sub_group.add_argument('--include-subscriptions', help='Comma-separated subscription IDs')
    parser.add_argument('--exclude-subscriptions', help='Comma-separated subscription IDs to exclude')
    
    # Location scope
    loc_group = parser.add_mutually_exclusive_group()
    loc_group.add_argument('--location', help='Single location (e.g., eastus)')
    loc_group.add_argument('--include-locations', help='Comma-separated locations')
    parser.add_argument('--exclude-locations', help='Comma-separated locations to exclude')
    
    # Service scope
    svc_group = parser.add_mutually_exclusive_group()
    svc_group.add_argument('--service', help='Single service name')
    svc_group.add_argument('--include-services', help='Comma-separated services')
    parser.add_argument('--exclude-services', help='Comma-separated services to exclude')
    
    # Resource scope
    res_group = parser.add_mutually_exclusive_group()
    res_group.add_argument('--resource', help='Specific resource ID')
    res_group.add_argument('--resource-pattern', help='Resource ID pattern with wildcards')
    parser.add_argument('--resource-type', help='Filter by resource type')
    
    # Performance
    parser.add_argument('--max-subscription-workers', type=int, default=3,
                       help='Max subscriptions in parallel (default: 3)')
    parser.add_argument('--max-workers', type=int, default=10,
                       help='Max services/locations per subscription (default: 10)')
    
    # Auth
    parser.add_argument('--tenant-id', default=os.getenv('AZURE_TENANT_ID'),
                       help='Azure tenant ID')
    
    # Output
    parser.add_argument('--no-save', action='store_true', help='Skip saving report')
    
    args = parser.parse_args()
    
    # Validate
    if args.resource and not args.service:
        parser.error("--resource requires --service")
    if args.resource_pattern and not args.service:
        parser.error("--resource-pattern requires --service")
    
    # Parse lists
    include_subscriptions = [s.strip() for s in (args.include_subscriptions or '').split(',') if s.strip()] or None
    exclude_subscriptions = [s.strip() for s in (args.exclude_subscriptions or '').split(',') if s.strip()] or None
    include_locations = [l.strip() for l in (args.include_locations or '').split(',') if l.strip()] or None
    exclude_locations = [l.strip() for l in (args.exclude_locations or '').split(',') if l.strip()] or None
    include_services = [s.strip() for s in (args.include_services or '').split(',') if s.strip()] or None
    exclude_services = [s.strip() for s in (args.exclude_services or '').split(',') if s.strip()] or None
    
    # Execute scan
    results = scan(
        subscription=args.subscription,
        include_subscriptions=include_subscriptions,
        exclude_subscriptions=exclude_subscriptions,
        location=args.location,
        include_locations=include_locations,
        exclude_locations=exclude_locations,
        service=args.service,
        include_services=include_services,
        exclude_services=exclude_services,
        resource=args.resource,
        resource_pattern=args.resource_pattern,
        resource_type=args.resource_type,
        max_subscription_workers=args.max_subscription_workers,
        max_workers=args.max_workers,
        tenant_id=args.tenant_id,
        save_report=not args.no_save
    )
    
    return results


if __name__ == '__main__':
    main()
