#!/usr/bin/env python3
"""
GCP Unified Flexible Scanner

Supports all granularity levels:
- Organization-wide (all projects)
- Multi-project
- Single project
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

from auth.gcp_auth import _get_credentials, get_default_project_id, _CLOUD_PLATFORM_RO_SCOPE
from utils.project_scanner import (
    list_organization_projects,
    list_gcp_regions
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


def resolve_projects(
    project: Optional[str],
    include_projects: Optional[List[str]],
    exclude_projects: Optional[List[str]],
    credentials
) -> List[Dict[str, str]]:
    """Resolve which projects to scan"""
    
    if project:
        # Single specific project
        return [{
            'project_id': project,
            'display_name': f'Project-{project}',
            'state': 'ACTIVE'
        }]
    
    if include_projects:
        # Multiple specific projects
        return [
            {
                'project_id': proj_id,
                'display_name': f'Project-{proj_id}',
                'state': 'ACTIVE'
            }
            for proj_id in include_projects
        ]
    
    # All projects in organization
    all_projects = list_organization_projects(credentials)
    
    if not all_projects:
        # Fallback to current project
        current_project = get_default_project_id()
        if current_project:
            all_projects = [{
                'project_id': current_project,
                'display_name': 'Current Project',
                'state': 'ACTIVE'
            }]
        else:
            return []
    
    # Apply exclusions
    if exclude_projects:
        exclude_set = set(exclude_projects)
        all_projects = [p for p in all_projects 
                       if p['project_id'] not in exclude_set]
    
    return all_projects


def resolve_regions(
    region: Optional[str],
    include_regions: Optional[List[str]],
    exclude_regions: Optional[List[str]]
) -> List[str]:
    """Resolve which regions to scan"""
    
    if region:
        # Single specific region
        return [region]
    
    if include_regions:
        # Multiple specific regions
        return include_regions
    
    # All GCP regions
    all_regions = list_gcp_regions()
    
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
    project_id: str,
    region: str,
    service_name: str,
    scope: str,
    credentials,
    resource_filter: Optional[Callable]
) -> Dict[str, Any]:
    """Scan a single service with optional resource filtering"""
    
    try:
        # Run service scan
        if scope == 'global':
            result = run_global_service(service_name, project_id, credentials=credentials)
        else:
            result = run_regional_service(service_name, region, project_id, credentials=credentials)
        
        # Apply resource filter if specified
        if resource_filter and result.get('checks'):
            filtered_checks = []
            for check in result['checks']:
                # Create pseudo-resource for filtering
                resource_obj = {
                    'resource_id': check.get('resource_id', ''),
                    'resource_type': check.get('resource_type', '')
                }
                
                if resource_filter(resource_obj):
                    filtered_checks.append(check)
            
            result['checks'] = filtered_checks
            logger.info(f"Filtered to {len(filtered_checks)} checks for resource filter")
        
        # Add metadata
        result['project'] = project_id
        result['region'] = region if scope == 'regional' else 'global'
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to scan {service_name} in {project_id}/{region}: {e}")
        return {
            'service': service_name,
            'project': project_id,
            'region': region,
            'scope': scope,
            'checks': [],
            'error': str(e)
        }


def scan(
    # Project scope
    project: Optional[str] = None,
    include_projects: Optional[List[str]] = None,
    exclude_projects: Optional[List[str]] = None,
    
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
    max_project_workers: int = 3,
    max_workers: int = 10,
    
    # Output
    save_report: bool = True
) -> List[Dict[str, Any]]:
    """
    Flexible compliance scanner supporting all granularity levels
    
    Args:
        project: Single project ID
        include_projects: Multiple project IDs
        exclude_projects: Projects to exclude
        region: Single region
        include_regions: Multiple regions
        exclude_regions: Regions to exclude
        service: Single service
        include_services: Multiple services
        exclude_services: Services to exclude
        resource: Single resource ID
        resource_pattern: Resource ID pattern with wildcards
        resource_type: Filter by resource type
        max_project_workers: Parallel project scanning (default: 3)
        max_workers: Parallel service/region scanning (default: 10)
        save_report: Save results to output folder
    
    Returns:
        List of scan results
    """
    
    # Create scan folder and setup logging
    scan_folder, scan_id = create_scan_folder()
    logger_instance = setup_scan_logging(scan_folder, scan_id)
    
    logger_instance.info("="*80)
    logger_instance.info("GCP FLEXIBLE COMPLIANCE SCANNER")
    logger_instance.info("="*80)
    
    # Get credentials
    credentials = _get_credentials([_CLOUD_PLATFORM_RO_SCOPE])
    
    # Resolve scope
    projects_to_scan = resolve_projects(project, include_projects, exclude_projects, credentials)
    regions_to_scan = resolve_regions(region, include_regions, exclude_regions)
    services_to_scan = resolve_services(service, include_services, exclude_services)
    resource_filter = create_resource_filter(resource, resource_pattern, resource_type)
    
    # Log scope
    logger_instance.info(f"\nScan Scope:")
    logger_instance.info(f"  Projects: {len(projects_to_scan)} - {[p['project_id'] for p in projects_to_scan]}")
    logger_instance.info(f"  Regions: {len(regions_to_scan)} - {regions_to_scan}")
    logger_instance.info(f"  Services: {len(services_to_scan)} - {[s for s, _ in services_to_scan]}")
    if resource:
        logger_instance.info(f"  Resource: {resource} (exact match)")
    elif resource_pattern:
        logger_instance.info(f"  Resource Pattern: {resource_pattern}")
    elif resource_type:
        logger_instance.info(f"  Resource Type: {resource_type}")
    else:
        logger_instance.info(f"  Resources: All")
    
    logger_instance.info(f"\nParallelism:")
    logger_instance.info(f"  Project workers: {max_project_workers}")
    logger_instance.info(f"  Service/region workers: {max_workers}")
    logger_instance.info(f"  Max concurrent tasks: {max_project_workers * max_workers}")
    
    # Build scan tasks
    all_results = []
    
    # Scan projects
    if max_project_workers == 1:
        # Sequential project scanning
        logger_instance.info("\nScanning projects sequentially...")
        for idx, proj in enumerate(projects_to_scan, 1):
            logger_instance.info(f"[{idx}/{len(projects_to_scan)}] Scanning {proj['display_name']} ({proj['project_id']})")
            results = scan_project_scope(
                proj, regions_to_scan, services_to_scan, resource_filter,
                credentials, max_workers
            )
            all_results.extend(results)
    else:
        # Parallel project scanning
        logger_instance.info(f"\nScanning {len(projects_to_scan)} projects in parallel (max {max_project_workers})...")
        
        with ThreadPoolExecutor(max_workers=max_project_workers) as executor:
            future_to_project = {
                executor.submit(
                    scan_project_scope,
                    proj, regions_to_scan, services_to_scan, resource_filter,
                    credentials, max_workers
                ): proj
                for proj in projects_to_scan
            }
            
            completed = 0
            for future in as_completed(future_to_project):
                proj = future_to_project[future]
                completed += 1
                
                try:
                    results = future.result()
                    all_results.extend(results)
                    total_checks = sum(len(r.get('checks', [])) for r in results)
                    logger_instance.info(f"[{completed}/{len(projects_to_scan)}] ✓ {proj['display_name']} ({proj['project_id']}): {total_checks} checks")
                except Exception as e:
                    logger_instance.error(f"[{completed}/{len(projects_to_scan)}] ✗ {proj['display_name']} ({proj['project_id']}): {e}")
    
    # Summary
    total_checks = sum(len(r.get('checks', [])) for r in all_results)
    total_passed = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'PASS') for r in all_results)
    total_failed = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'FAIL') for r in all_results)
    
    logger_instance.info("\n" + "="*80)
    logger_instance.info("SCAN COMPLETE")
    logger_instance.info("="*80)
    logger_instance.info(f"Total checks: {total_checks}")
    logger_instance.info(f"  PASS: {total_passed}")
    logger_instance.info(f"  FAIL: {total_failed}")
    
    # Save report
    if save_report:
        report_folder = save_scan_results(all_results, scan_folder)
        logger_instance.info(f"\nReport: {report_folder}")
    
    return all_results


def scan_project_scope(
    project: Dict[str, str],
    regions: List[str],
    services: List[tuple],
    resource_filter: Optional[Callable],
    credentials,
    max_workers: int
) -> List[Dict[str, Any]]:
    """Scan one project with specified scope"""
    
    project_id = project['project_id']
    
    # Build scan tasks
    tasks = []
    for service_name, scope in services:
        if scope == 'global':
            tasks.append({
                'project_id': project_id,
                'region': 'global',
                'service_name': service_name,
                'scope': scope,
                'credentials': credentials
            })
        else:
            for region in regions:
                tasks.append({
                    'project_id': project_id,
                    'region': region,
                    'service_name': service_name,
                    'scope': scope,
                    'credentials': credentials
                })
    
    logger.info(f"  Scan tasks: {len(tasks)}")
    
    # Execute tasks in parallel
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                scan_service_in_scope,
                task['project_id'],
                task['region'],
                task['service_name'],
                task['scope'],
                task['credentials'],
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
        description='Flexible GCP Compliance Scanner - All Granularity Levels',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full organization
  %(prog)s
  
  # Single project
  %(prog)s --project my-project-id
  
  # Single project + region
  %(prog)s --project my-project-id --region us-central1
  
  # Single project + region + service
  %(prog)s --project my-project-id --region us-central1 --service compute
  
  # Single project + region + service + resource
  %(prog)s --project my-project-id --region us-central1 --service compute --resource instance-1
  
  # Multiple projects + specific regions
  %(prog)s --include-projects "project1,project2" --include-regions "us-central1,us-east1"
  
  # All projects + exclude services
  %(prog)s --exclude-services "logging,monitoring"
        """
    )
    
    # Project scope
    project_group = parser.add_mutually_exclusive_group()
    project_group.add_argument('--project', help='Single project ID')
    project_group.add_argument('--include-projects', help='Comma-separated project IDs')
    parser.add_argument('--exclude-projects', help='Comma-separated project IDs to exclude')
    
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
    parser.add_argument('--max-project-workers', type=int, default=3,
                       help='Max projects in parallel (default: 3)')
    parser.add_argument('--max-workers', type=int, default=10,
                       help='Max services/regions per project (default: 10)')
    
    # Output
    parser.add_argument('--no-save', action='store_true', help='Skip saving report')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.resource and not args.service:
        parser.error("--resource requires --service")
    if args.resource_pattern and not args.service:
        parser.error("--resource-pattern requires --service")
    
    # Parse comma-separated lists
    include_projects = [p.strip() for p in (args.include_projects or '').split(',') if p.strip()] or None
    exclude_projects = [p.strip() for p in (args.exclude_projects or '').split(',') if p.strip()] or None
    include_regions = [r.strip() for r in (args.include_regions or '').split(',') if r.strip()] or None
    exclude_regions = [r.strip() for r in (args.exclude_regions or '').split(',') if r.strip()] or None
    include_services = [s.strip() for s in (args.include_services or '').split(',') if s.strip()] or None
    exclude_services = [s.strip() for s in (args.exclude_services or '').split(',') if s.strip()] or None
    
    # Execute scan
    results = scan(
        project=args.project,
        include_projects=include_projects,
        exclude_projects=exclude_projects,
        region=args.region,
        include_regions=include_regions,
        exclude_regions=exclude_regions,
        service=args.service,
        include_services=include_services,
        exclude_services=exclude_services,
        resource=args.resource,
        resource_pattern=args.resource_pattern,
        resource_type=args.resource_type,
        max_project_workers=args.max_project_workers,
        max_workers=args.max_workers,
        save_report=not args.no_save
    )
    
    return results


if __name__ == '__main__':
    main()
