#!/usr/bin/env python3
"""
Unified Flexible AWS Compliance Scanner

Supports all granularity levels:
- Organization-wide
- Multi-account
- Single account
- Single region
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

from auth.aws_auth import get_boto3_session, get_session_for_account
from utils.organizations_scanner import (
    list_organization_accounts,
    get_current_account_id,
    list_enabled_regions
)
from engine.service_scanner import (
    run_global_service,
    run_regional_service,
    load_enabled_services_with_scope
)
from utils.reporting_manager import (
    create_scan_folder,
    setup_scan_logging,
    save_reporting_bundle
)

logger = logging.getLogger(__name__)


def resolve_accounts(
    account: Optional[str],
    include_accounts: Optional[List[str]],
    exclude_accounts: Optional[List[str]],
    session
) -> List[Dict[str, str]]:
    """Resolve which accounts to scan"""
    
    if account:
        # Single specific account
        return [{
            'Id': account,
            'Name': f'Account-{account}',
            'Email': 'unknown',
            'Status': 'ACTIVE'
        }]
    
    if include_accounts:
        # Multiple specific accounts
        return [
            {
                'Id': acc_id,
                'Name': f'Account-{acc_id}',
                'Email': 'unknown',
                'Status': 'ACTIVE'
            }
            for acc_id in include_accounts
        ]
    
    # All accounts in organization
    all_accounts = list_organization_accounts(session)
    
    if not all_accounts:
        # Fallback to current account
        current_account = get_current_account_id(session)
        all_accounts = [{
            'Id': current_account,
            'Name': 'Current Account',
            'Email': 'unknown',
            'Status': 'ACTIVE'
        }]
    
    # Apply exclusions
    if exclude_accounts:
        exclude_set = set(exclude_accounts)
        all_accounts = [a for a in all_accounts if a['Id'] not in exclude_set]
    
    return all_accounts


def resolve_regions(
    region: Optional[str],
    include_regions: Optional[List[str]],
    exclude_regions: Optional[List[str]],
    session
) -> List[str]:
    """Resolve which regions to scan"""
    
    if region:
        # Single specific region
        return [region]
    
    if include_regions:
        # Multiple specific regions
        return include_regions
    
    # All enabled regions
    all_regions = list_enabled_regions(session)
    
    # Apply exclusions
    if exclude_regions:
        exclude_set = set(exclude_regions)
        all_regions = [r for r in all_regions if r not in exclude_set]
    
    return all_regions


def resolve_services(
    service: Optional[str],
    include_services: Optional[List[str]],
    exclude_services: Optional[List[str]]
) -> List[tuple]:
    """Resolve which services to scan"""
    
    # Load all enabled services
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
        # Exact match
        return lambda r: r.get('resource_id') == resource
    
    if resource_pattern:
        # Pattern matching with wildcards
        return lambda r: fnmatch.fnmatch(r.get('resource_id', ''), resource_pattern)
    
    if resource_type:
        # Filter by resource type
        return lambda r: r.get('resource_type') == resource_type
    
    # No filter - all resources
    return None


def scan_service_in_scope(
    account_id: str,
    region: str,
    service_name: str,
    scope: str,
    session,
    resource_filter: Optional[Callable]
) -> Dict[str, Any]:
    """Scan a single service with optional resource filtering"""
    
    try:
        # Run service scan
        if scope == 'global':
            result = run_global_service(service_name, session_override=session)
        else:
            result = run_regional_service(service_name, region, session_override=session)
        
        # Apply resource filter if specified
        if resource_filter and result.get('checks'):
            filtered_checks = []
            for check in result['checks']:
                # Create pseudo-resource for filtering
                resource_obj = {
                    'resource_id': (
                        check.get('instance_id') or
                        check.get('bucket_name') or
                        check.get('db_instance_identifier') or
                        check.get('function_name') or
                        check.get('user_name') or
                        check.get('resource_id')
                    ),
                    'resource_type': check.get('resource_type')
                }
                
                if resource_filter(resource_obj):
                    filtered_checks.append(check)
            
            result['checks'] = filtered_checks
            logger.info(f"Filtered to {len(filtered_checks)} checks for resource filter")
        
        # Add metadata
        result['account'] = account_id
        result['region'] = region if scope == 'regional' else 'global'
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to scan {service_name} in {account_id}/{region}: {e}")
        return {
            'service': service_name,
            'account': account_id,
            'region': region,
            'scope': scope,
            'checks': [],
            'error': str(e)
        }


def scan(
    # Account scope
    account: Optional[str] = None,
    include_accounts: Optional[List[str]] = None,
    exclude_accounts: Optional[List[str]] = None,
    
    # Region scope
    region: Optional[str] = None,
    include_regions: Optional[List[str]] = None,
    exclude_regions: Optional[List[str]] = None,
    
    # Service scope
    service: Optional[str] = None,
    include_services: Optional[List[str]] = None,
    exclude_services: Optional[List[str]] = None,
    
    # Resource scope
    resource: Optional[str] = None,
    resource_pattern: Optional[str] = None,
    resource_type: Optional[str] = None,
    
    # Performance
    max_account_workers: int = 3,
    max_workers: int = 10,
    
    # Auth
    role_name: Optional[str] = None,
    external_id: Optional[str] = None,
    
    # Output
    save_report: bool = True
) -> List[Dict[str, Any]]:
    """
    Flexible compliance scanner supporting all granularity levels
    
    Args:
        account: Single account ID
        include_accounts: Multiple account IDs
        exclude_accounts: Accounts to exclude
        region: Single region
        include_regions: Multiple regions
        exclude_regions: Regions to exclude
        service: Single service
        include_services: Multiple services
        exclude_services: Services to exclude
        resource: Single resource ID
        resource_pattern: Resource ID pattern with wildcards
        resource_type: Filter by resource type
        max_account_workers: Parallel account scanning (default: 3)
        max_workers: Parallel service/region scanning (default: 10)
        role_name: IAM role for cross-account access
        external_id: External ID for role assumption
        save_report: Save results to output folder
    
    Returns:
        List of scan results
    """
    
    # Create scan folder and setup logging
    scan_folder, scan_id = create_scan_folder()
    logger = setup_scan_logging(scan_folder, scan_id)
    
    logger.info("="*80)
    logger.info("AWS FLEXIBLE COMPLIANCE SCANNER")
    logger.info("="*80)
    
    # Get base session
    base_session = get_boto3_session(default_region='us-east-1')
    
    # Resolve scope
    accounts_to_scan = resolve_accounts(account, include_accounts, exclude_accounts, base_session)
    regions_to_scan = resolve_regions(region, include_regions, exclude_regions, base_session)
    services_to_scan = resolve_services(service, include_services, exclude_services)
    resource_filter = create_resource_filter(resource, resource_pattern, resource_type)
    
    # Log scope
    logger.info(f"\nScan Scope:")
    logger.info(f"  Accounts: {len(accounts_to_scan)} - {[a['Id'] for a in accounts_to_scan]}")
    logger.info(f"  Regions: {len(regions_to_scan)} - {regions_to_scan}")
    logger.info(f"  Services: {len(services_to_scan)} - {[s for s, _ in services_to_scan]}")
    if resource:
        logger.info(f"  Resource: {resource} (exact match)")
    elif resource_pattern:
        logger.info(f"  Resource Pattern: {resource_pattern}")
    elif resource_type:
        logger.info(f"  Resource Type: {resource_type}")
    else:
        logger.info(f"  Resources: All")
    
    logger.info(f"\nParallelism:")
    logger.info(f"  Account workers: {max_account_workers}")
    logger.info(f"  Service/region workers: {max_workers}")
    logger.info(f"  Max concurrent tasks: {max_account_workers * max_workers}")
    
    # Build scan tasks
    all_results = []
    
    # Scan accounts
    if max_account_workers == 1:
        # Sequential account scanning
        logger.info("\nScanning accounts sequentially...")
        for idx, acc in enumerate(accounts_to_scan, 1):
            logger.info(f"[{idx}/{len(accounts_to_scan)}] Scanning {acc['Name']} ({acc['Id']})")
            results = scan_account_scope(
                acc, regions_to_scan, services_to_scan, resource_filter,
                role_name, external_id, max_workers
            )
            all_results.extend(results)
    else:
        # Parallel account scanning
        logger.info(f"\nScanning {len(accounts_to_scan)} accounts in parallel (max {max_account_workers})...")
        
        with ThreadPoolExecutor(max_workers=max_account_workers) as executor:
            future_to_account = {
                executor.submit(
                    scan_account_scope,
                    acc, regions_to_scan, services_to_scan, resource_filter,
                    role_name, external_id, max_workers
                ): acc
                for acc in accounts_to_scan
            }
            
            completed = 0
            for future in as_completed(future_to_account):
                acc = future_to_account[future]
                completed += 1
                
                try:
                    results = future.result()
                    all_results.extend(results)
                    total_checks = sum(len(r.get('checks', [])) for r in results)
                    logger.info(f"[{completed}/{len(accounts_to_scan)}] ✓ {acc['Name']} ({acc['Id']}): {total_checks} checks")
                except Exception as e:
                    logger.error(f"[{completed}/{len(accounts_to_scan)}] ✗ {acc['Name']} ({acc['Id']}): {e}")
    
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
        report_folder = save_reporting_bundle(all_results, account_id=None, scan_folder=scan_folder)
        logger.info(f"\nReport: {report_folder}")
    
    return all_results


def scan_account_scope(
    account: Dict[str, str],
    regions: List[str],
    services: List[tuple],
    resource_filter: Optional[Callable],
    role_name: Optional[str],
    external_id: Optional[str],
    max_workers: int
) -> List[Dict[str, Any]]:
    """Scan one account with specified scope"""
    
    account_id = account['Id']
    
    # Get session for this account
    try:
        session = get_session_for_account(
            account_id=account_id,
            role_name=role_name,
            default_region='us-east-1',
            external_id=external_id
        ) if role_name else get_boto3_session()
    except Exception as e:
        logger.error(f"Failed to access account {account_id}: {e}")
        return []
    
    # Build scan tasks
    tasks = []
    for service_name, scope in services:
        if scope == 'global':
            tasks.append({
                'account_id': account_id,
                'region': 'us-east-1',
                'service_name': service_name,
                'scope': scope,
                'session': session
            })
        else:
            for region in regions:
                tasks.append({
                    'account_id': account_id,
                    'region': region,
                    'service_name': service_name,
                    'scope': scope,
                    'session': session
                })
    
    logger.info(f"  Scan tasks: {len(tasks)}")
    
    # Execute tasks in parallel
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                scan_service_in_scope,
                task['account_id'],
                task['region'],
                task['service_name'],
                task['scope'],
                task['session'],
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


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Flexible AWS Compliance Scanner - All Granularity Levels',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full organization
  %(prog)s --role-name ComplianceScannerRole
  
  # Single account
  %(prog)s --account 123456789012
  
  # Single account + region
  %(prog)s --account 123456789012 --region us-east-1
  
  # Single account + region + service
  %(prog)s --account 123456789012 --region us-east-1 --service ec2
  
  # Single account + region + service + resource
  %(prog)s --account 123456789012 --region us-east-1 --service ec2 --resource i-xxx
  
  # Multiple accounts + specific regions
  %(prog)s --role-name X --include-accounts "123,456" --include-regions "us-east-1,us-west-2"
  
  # All accounts + exclude services
  %(prog)s --role-name X --exclude-services "cloudwatch,cloudtrail"
  
  # Pattern matching
  %(prog)s --account 123 --region us-east-1 --service ec2 --resource-pattern "i-*-prod-*"
        """
    )
    
    # Account scope
    account_group = parser.add_mutually_exclusive_group()
    account_group.add_argument('--account', help='Single account ID')
    account_group.add_argument('--include-accounts', help='Comma-separated account IDs')
    parser.add_argument('--exclude-accounts', help='Comma-separated account IDs to exclude')
    
    # Region scope
    region_group = parser.add_mutually_exclusive_group()
    region_group.add_argument('--region', help='Single region')
    region_group.add_argument('--include-regions', help='Comma-separated regions')
    parser.add_argument('--exclude-regions', help='Comma-separated regions to exclude')
    
    # Service scope
    service_group = parser.add_mutually_exclusive_group()
    service_group.add_argument('--service', help='Single service name')
    service_group.add_argument('--include-services', help='Comma-separated services')
    parser.add_argument('--exclude-services', help='Comma-separated services to exclude')
    
    # Resource scope
    resource_group = parser.add_mutually_exclusive_group()
    resource_group.add_argument('--resource', help='Specific resource ID (requires --service)')
    resource_group.add_argument('--resource-pattern', help='Resource ID pattern with wildcards (requires --service)')
    parser.add_argument('--resource-type', help='Filter by resource type')
    
    # Performance
    parser.add_argument('--max-account-workers', type=int, default=3,
                       help='Max accounts in parallel (default: 3)')
    parser.add_argument('--max-workers', type=int, default=10,
                       help='Max services/regions per account (default: 10)')
    
    # Auth
    parser.add_argument('--role-name', default=os.getenv('ASSUME_ROLE_NAME'),
                       help='IAM role to assume in accounts')
    parser.add_argument('--external-id', default=os.getenv('AWS_EXTERNAL_ID'),
                       help='External ID for role assumption')
    
    # Output
    parser.add_argument('--no-save', action='store_true', help='Skip saving report')
    parser.add_argument('--output-dir', help='Custom output directory')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.resource and not args.service:
        parser.error("--resource requires --service")
    if args.resource_pattern and not args.service:
        parser.error("--resource-pattern requires --service")
    if args.account and args.include_accounts:
        parser.error("Cannot use --account with --include-accounts")
    if args.region and args.include_regions:
        parser.error("Cannot use --region with --include-regions")
    if args.service and args.include_services:
        parser.error("Cannot use --service with --include-services")
    
    # Parse comma-separated lists
    include_accounts = [a.strip() for a in (args.include_accounts or '').split(',') if a.strip()] or None
    exclude_accounts = [a.strip() for a in (args.exclude_accounts or '').split(',') if a.strip()] or None
    include_regions = [r.strip() for r in (args.include_regions or '').split(',') if r.strip()] or None
    exclude_regions = [r.strip() for r in (args.exclude_regions or '').split(',') if r.strip()] or None
    include_services = [s.strip() for s in (args.include_services or '').split(',') if s.strip()] or None
    exclude_services = [s.strip() for s in (args.exclude_services or '').split(',') if s.strip()] or None
    
    # Execute scan
    results = scan(
        account=args.account,
        include_accounts=include_accounts,
        exclude_accounts=exclude_accounts,
        region=args.region,
        include_regions=include_regions,
        exclude_regions=exclude_regions,
        service=args.service,
        include_services=include_services,
        exclude_services=exclude_services,
        resource=args.resource,
        resource_pattern=args.resource_pattern,
        resource_type=args.resource_type,
        max_account_workers=args.max_account_workers,
        max_workers=args.max_workers,
        role_name=args.role_name,
        external_id=args.external_id,
        save_report=not args.no_save
    )
    
    return results


if __name__ == '__main__':
    main()
