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
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Tuple
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
    save_reporting_bundle,
    save_summary,
    _get_tenant_id,
    compute_asset_hash
)

logger = logging.getLogger(__name__)


def _results_ndjson_mode() -> str:
    """
    Controls what we write to results.ndjson.
    - finding (default): one NDJSON line per finding/check (minimal; Option A)
    - task: one NDJSON line per scanned service task (no inventory)
    - legacy: original task dict (includes inventory)
    """
    return os.getenv("RESULTS_NDJSON_MODE", "finding").strip().lower()


def _to_minimal_finding_records(
    *,
    scan_id: str,
    tenant_id: str,
    provider: str,
    result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Convert a service task result (with checks[]) into minimal finding records.
    Keeps `rule_id` as the metadata key (UI can enrich later).
    """
    account_id = result.get("account") or result.get("account_id") or "unknown"
    region = result.get("region") or "global"
    service = result.get("service") or "unknown"
    scope = result.get("scope") or ("global" if region in ("global", None) else "regional")

    findings: List[Dict[str, Any]] = []
    for c in (result.get("checks", []) or []):
        # Keep only stable identifiers and evaluation outcome.
        status = c.get("status") or c.get("result") or "UNKNOWN"
        created_at = c.get("created_at") or result.get("created_at") or datetime.utcnow().isoformat() + "Z"

        finding = {
            "schema_version": "cspm_finding.v1",
            "tenant_id": tenant_id,
            "scan_run_id": scan_id,
            "provider": provider,
            "account_id": account_id,
            "region": region,
            "scope": scope,
            "service": service,
            "rule_id": c.get("rule_id") or "",
            "status": status,
            "result": status,  # alias
            "created_at": created_at,
            # Resource identifiers (optional)
            "resource_uid": c.get("resource_uid") or "",
            "resource_arn": c.get("resource_arn") or "",
            "resource_id": c.get("resource_id") or "",
            "resource_type": c.get("resource_type") or "",
            "resource_name": c.get("resource_name") or c.get("name") or c.get("Name") or "",
        }
        findings.append(finding)
    return findings


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
        # Normalize service name (handle folder name vs config name differences)
        service_normalized = service.replace('_', '').lower()
        for svc_name, scope in all_services:
            if svc_name == service:
                return [(svc_name, scope)]
            # Also check normalized match (e.g., vpcflowlogs matches vpc_flow_logs)
            svc_name_normalized = svc_name.replace('_', '').lower()
            if svc_name_normalized == service_normalized:
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
    # New: Parallel account+region combinations (replaces max_account_workers when > 0)
    max_account_region_workers: int = 0,  # 0 = use old model, >0 = use new account+region model
    # Optimized: Flattened Account+Region+Service parallelism (maximum speed, replaces both above when > 0)
    max_total_workers: int = 0,  # 0 = use nested model, >0 = use flattened Account+Region+Service model (recommended: 50-100 for full scans)
    
    # Auth
    role_name: Optional[str] = None,
    external_id: Optional[str] = None,
    
    # Output
    save_report: bool = True,
    # When true, write task results to disk incrementally to keep memory stable (recommended for API scans)
    stream_results: bool = False,
    # Optional: force the output folder name (useful to match API scan_id)
    output_scan_id: Optional[str] = None
) -> Dict[str, Any]:
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
        max_account_workers: Parallel account scanning (default: 3, legacy mode)
        max_workers: Parallel service/region scanning (default: 10)
        max_account_region_workers: Parallel account+region combinations (default: 0 = legacy, >0 = new model)
        max_total_workers: Flattened Account+Region+Service parallelism (default: 0 = nested model, >0 = flattened for max speed)
        role_name: IAM role for cross-account access
        external_id: External ID for role assumption
        save_report: Save results to output folder
    
    Returns:
        List of scan results
    """
    
    # Create scan folder and setup logging (prefer stable ID when running via API)
    scan_folder, scan_id = create_scan_folder(output_scan_id)
    logger = setup_scan_logging(scan_folder, scan_id)
    
    # Track start time for duration calculation
    scan_start_time = datetime.utcnow()
    
    logger.info("="*80)
    logger.info("AWS FLEXIBLE COMPLIANCE SCANNER")
    logger.info("="*80)
    
    # Get base session
    # If AWS_ACCESS_KEY_ID is set, get_boto3_session() will use it (AWS_ROLE_ARN should be cleared by caller)
    # If AWS_ROLE_ARN is set and no access keys, get_boto3_session() will assume role
    # If role_name is provided, scan_account_scope() will use it instead
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
    
    # Check which parallel model to use (priority: flattened > account+region > legacy)
    use_flattened_model = max_total_workers > 0
    use_account_region_model = max_account_region_workers > 0 and not use_flattened_model

    # Populated by flattened/account+region models (so we can attach them to the final summary at the end)
    results_files_list: List[str] = []
    discoveries_files_list: List[str] = []
    
    if use_flattened_model:
        from utils.reporting_manager import is_global_service
        # Calculate total tasks: account × region × service + account × global_services
        global_services = [s for s, _ in services_to_scan if is_global_service(s)]
        regional_services = [s for s, _ in services_to_scan if not is_global_service(s)]
        regional_tasks = len(accounts_to_scan) * len(regions_to_scan) * len(regional_services)
        global_tasks = len(accounts_to_scan) * len(global_services)
        total_tasks = regional_tasks + global_tasks
        
        logger.info(f"\nParallelism (Flattened Account+Region+Service Model - MAXIMUM SPEED):")
        logger.info(f"  Total tasks: {total_tasks} (account×region×service granularity)")
        logger.info(f"  Max concurrent workers: {max_total_workers}")
        logger.info(f"  Regional tasks: {regional_tasks} ({len(accounts_to_scan)} accounts × {len(regions_to_scan)} regions × {len(regional_services)} services)")
        logger.info(f"  Global tasks: {global_tasks} ({len(accounts_to_scan)} accounts × {len(global_services)} services)")
    elif use_account_region_model:
        logger.info(f"\nParallelism (Account+Region Model):")
        logger.info(f"  Account+Region workers: {max_account_region_workers}")
        logger.info(f"  Service workers (per account+region): {max_workers}")
        # Calculate total combinations
        from utils.reporting_manager import is_global_service
        global_services = [s for s, _ in services_to_scan if is_global_service(s)]
        regional_services = [s for s, _ in services_to_scan if not is_global_service(s)]
        total_combinations = len(accounts_to_scan) * len(regions_to_scan) + len(accounts_to_scan)  # account+region + global per account
        logger.info(f"  Total combinations: {total_combinations} (account+region + global services)")
        logger.info(f"  Max concurrent tasks: {max_account_region_workers * max_workers}")
    else:
        logger.info(f"\nParallelism (Legacy Model):")
    logger.info(f"  Account workers: {max_account_workers}")
    logger.info(f"  Service/region workers: {max_workers}")
    logger.info(f"  Max concurrent tasks: {max_account_workers * max_workers}")
    
    # When streaming, append each completed task result to an NDJSON file and keep only counters in memory.
    results_ndjson_path = os.path.join(scan_folder, "results.ndjson") if stream_results and not use_account_region_model else None
    discoveries_ndjson_path = os.path.join(scan_folder, "discoveries.ndjson") if stream_results and not use_account_region_model else None
    if stream_results and not use_account_region_model:
        # Ensure files exist
        with open(results_ndjson_path, "a", encoding="utf-8"):
            pass
        with open(discoveries_ndjson_path, "a", encoding="utf-8"):
            pass

    def _write_result(result: Dict[str, Any]) -> None:
        if not stream_results or use_account_region_model:
            return
        # Always write discoveries to discoveries.ndjson (best-effort)
        _write_inventory_assets(result, discoveries_ndjson_path)

        mode = _results_ndjson_mode()
        if mode == "legacy":
            # Original behavior (includes inventory) - not recommended.
            with open(results_ndjson_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(result, default=str) + "\n")
            return

        if mode == "task":
            # One line per service task, but never embed inventory.
            task_out = {k: v for k, v in result.items() if k not in ("inventory", "_raw_data")}
            with open(results_ndjson_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(task_out, default=str) + "\n")
            return

        # Default: one NDJSON line per finding/check (Option A).
        tenant_id = _get_tenant_id()
        provider = result.get("provider") or "aws"
        for finding in _to_minimal_finding_records(
            scan_id=scan_id,
            tenant_id=tenant_id,
            provider=provider,
            result=result,
        ):
            with open(results_ndjson_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(finding, default=str) + "\n")
    
    def _write_inventory_assets(result: Dict[str, Any], inventory_path: str) -> None:
        """Extract inventory assets from a single result using canonical schema"""
        from engine.service_scanner import extract_resource_identifier
        from utils.reporting_manager import is_global_service
        
        tenant_id = _get_tenant_id()
        service = result.get("service")
        account = result.get("account") or "unknown"
        region = result.get("region") or "global"
        scope = result.get("scope", "regional")
        inventory = result.get("inventory", {})
        
        # Build raw_ref path
        raw_ref_base = os.path.join(scan_folder, "raw", "aws", account, region)
        
        seen_in_this_result = set()  # Track duplicates within this result
        
        for discovery_id, items in inventory.items():
            if not isinstance(items, list):
                continue
            
            # Check if this discovery should produce inventory assets (universal heuristic)
            from utils.reporting_manager import is_cspm_inventory_resource
            if not is_cspm_inventory_resource(discovery_id, discovery_config=None):
                continue
            
            # Extract service name from discovery_id (e.g., "aws.s3.list_buckets" -> "s3")
            parts = discovery_id.split(".")
            if len(parts) >= 2 and parts[0] == "aws":
                service_from_discovery = parts[1]
            else:
                service_from_discovery = service
            
            # Determine if service is global or regional
            discovery_service_is_global = is_global_service(service_from_discovery)
            discovery_region = None if discovery_service_is_global else (region if region != "global" else "us-east-1")
            final_region = "global" if discovery_service_is_global else (discovery_region or "global")
            final_scope = "global" if discovery_service_is_global else "regional"
            
            # Build raw_ref path
            raw_ref_path = os.path.join(raw_ref_base, f"{service_from_discovery}.json")
            
            for idx, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                
                # Debug: check item keys for first S3 bucket
                if idx == 0 and service_from_discovery == 's3' and discovery_id == 'aws.s3.list_buckets':
                    logger.info(f"[DEBUG-ITEM] First S3 bucket item keys: {list(item.keys())}")
                    logger.info(f"[DEBUG-ITEM] Has Status field: {'Status' in item}, Has MFADelete: {'MFADelete' in item}")
                
                # Use existing extract_resource_identifier function (generic for all services)
                try:
                    resource_info = extract_resource_identifier(
                        item,
                        service_from_discovery,
                        discovery_region,
                        account,
                        discovery_id=discovery_id  # Pass discovery_id for resource type inference
                    )
                    
                    resource_id = resource_info.get("resource_id")
                    resource_type = resource_info.get("resource_type", "resource")
                    resource_arn = resource_info.get("resource_arn")
                    resource_uid = resource_info.get("resource_uid")
                    
                    # Skip if no valid identifiers or duplicate
                    if (not resource_id and not resource_arn) or resource_uid in seen_in_this_result:
                        continue
                    seen_in_this_result.add(resource_uid)
                    
                    # Extract tags (generic approach)
                    tags = {}
                    if "Tags" in item and isinstance(item["Tags"], list):
                        for tag in item["Tags"]:
                            if isinstance(tag, dict) and "Key" in tag and "Value" in tag:
                                tags[tag["Key"]] = tag["Value"]
                    elif "tags" in item and isinstance(item["tags"], dict):
                        tags = item["tags"]
                    elif "tags" in item and isinstance(item["tags"], str):
                        try:
                            tags = json.loads(item["tags"]) if item["tags"] else {}
                        except:
                            tags = {}
                    
                    # Extract name and created_at
                    name = item.get("name") or item.get("Name") or resource_id or ""
                    created_at = item.get("CreationDate") or item.get("CreateDate") or item.get("createdAt")
                    if created_at and not isinstance(created_at, str):
                        try:
                            created_at = created_at.isoformat() + "Z" if hasattr(created_at, 'isoformat') else str(created_at)
                        except:
                            created_at = None
                    
                    # Validate resource_id
                    if resource_id:
                        resource_id_str = str(resource_id).strip()
                        if not resource_id_str or resource_id_str in ["[]", "{}", ""]:
                            continue  # Skip invalid resource_id
                    
                    # Validate ARN if present
                    if resource_arn and (not resource_arn.startswith("arn:aws:") or "[]" in resource_arn or "{}" in resource_arn):
                        continue  # Skip invalid ARN
                    
                    # Format resource_type to match AWS service structure: service:resource-type
                    formatted_resource_type = f"{service_from_discovery}:{resource_type}" if resource_type != "resource" else service_from_discovery
                    
                    # Standard template fields (protected)
                    standard_fields = {
                        "schema_version", "tenant_id", "scan_run_id", "provider", "service",
                        "account_id", "region", "scope", "resource_type", "resource_id",
                        "resource_arn", "resource_uid", "name", "tags", "metadata", "hash_sha256"
                    }
                    
                    # Create asset record with canonical cspm_asset.v1 schema
                    asset = {
                        "schema_version": "cspm_asset.v1",
                        "tenant_id": tenant_id,
                        "scan_run_id": scan_id,
                        "provider": "aws",
                        "service": service_from_discovery,  # Add service field
                        "account_id": account,
                        "region": final_region,
                        "scope": final_scope,
                        "resource_type": formatted_resource_type,  # Format: service:resource-type
                        "resource_id": resource_id or "",
                        "resource_arn": resource_arn or "",  # Move ARN to top level
                        "resource_uid": resource_uid,
                        "name": name,
                        "tags": tags,
                        "metadata": {
                            "created_at": created_at,
                            "labels": {},
                            "raw_refs": [raw_ref_path],
                            "discovery_operation": discovery_id
                        }
                    }
                    
                    # Preserve enriched fields from dependent discoveries (nested approach)
                    # Store entire dependent discovery data under _dependent_data key
                    # This must be done BEFORE the loop that skips _ fields
                    if '_dependent_data' in item and isinstance(item['_dependent_data'], dict):
                        asset['_dependent_data'] = item['_dependent_data']
                        enriched_discoveries = list(item['_dependent_data'].keys())
                        logger.info(f"[INVENTORY-WRITE] Preserved _dependent_data with {len(enriched_discoveries)} discoveries: {enriched_discoveries[:3]}")
                    
                    # Also preserve individual enriched fields for backward compatibility (if not using nested approach)
                    enriched_fields_added = []
                    for key, value in item.items():
                        # Skip standard fields, matching keys, internal tracking fields
                        # NOTE: _dependent_data is already handled above, so skip it here
                        if key in standard_fields or (key.startswith('_') and key != '_dependent_data') or key in ['Name', 'Bucket', 'ResourceId', 'CreationDate', 'CreateDate']:
                            continue
                        # Skip None values
                        if value is None:
                            continue
                        # Add enriched field to asset
                        asset[key] = value
                        enriched_fields_added.append(key)
                    
                    if enriched_fields_added:
                        logger.debug(f"[INVENTORY-WRITE] Preserved {len(enriched_fields_added)} individual enriched fields for {name}: {enriched_fields_added[:5]}")
                    
                    # Preserve _enriched_from if present (for tracking)
                    if '_enriched_from' in item and item['_enriched_from']:
                        asset['metadata']['enriched_from'] = item['_enriched_from']
                    
                    # Compute hash for drift detection
                    asset["hash_sha256"] = compute_asset_hash(asset)
                    
                    # Append to inventory file
                    with open(inventory_path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(asset, default=str) + "\n")
                        
                except Exception as e:
                    # Log but continue processing other items
                    logger.debug(f"Failed to extract resource identifier for {discovery_id}: {e}")
                    continue

    total_checks = 0
    total_passed = 0
    total_failed = 0

    # Build/accumulate results only if not streaming
    all_results: List[Dict[str, Any]] = []
    account_region_summaries = []  # For new account+region model
    
    # FLATTENED MODEL (Account+Region+Service level - Maximum Speed)
    if use_flattened_model:
        from utils.reporting_manager import is_global_service
        import threading
        
        logger.info("\nUsing Flattened Account+Region+Service concurrent scanning model (MAXIMUM SPEED)...")
        
        # Separate global and regional services
        global_services = [(svc, scope) for svc, scope in services_to_scan if is_global_service(svc)]
        regional_services = [(svc, scope) for svc, scope in services_to_scan if not is_global_service(svc)]
        
        # Build all (account, region, service) tasks - ONE task per service scan
        all_service_tasks = []
        
        for account in accounts_to_scan:
            account_id = account['Id']
            
            # Global service tasks (one per account+service)
            for service_name, scope in global_services:
                all_service_tasks.append({
                    'account': account,
                    'account_id': account_id,
                    'region': 'global',
                    'service_name': service_name,
                    'scope': 'global',
                    'results_file': os.path.join(scan_folder, f"results_{account_id}_global.ndjson"),
                    'discoveries_file': os.path.join(scan_folder, f"discoveries_{account_id}_global.ndjson"),
                })
            
            # Regional service tasks (one per account+region+service)
            for region in regions_to_scan:
                for service_name, scope in regional_services:
                    all_service_tasks.append({
                        'account': account,
                        'account_id': account_id,
                        'region': region,
                        'service_name': service_name,
                        'scope': 'regional',
                        'results_file': os.path.join(scan_folder, f"results_{account_id}_{region}.ndjson"),
                        'discoveries_file': os.path.join(scan_folder, f"discoveries_{account_id}_{region}.ndjson"),
                    })
        
        logger.info(f"  Generated {len(all_service_tasks)} service-level tasks")
        
        # Thread-safe file writing
        file_lock = threading.Lock()
        task_stats = {'completed': 0, 'started': 0}
        
        def _write_service_result(task: Dict, result: Dict[str, Any]) -> None:
            """Write result for a single service scan (thread-safe)"""
            nonlocal total_checks, total_passed, total_failed
            scan_run_id = os.path.basename(scan_folder)
            
            # Save raw data
            raw_data = result.get("_raw_data")
            if raw_data:
                service = result.get("service")
                account_id = task['account_id']
                region = task['region']
                
                raw_dir = os.path.join(scan_folder, "raw", "aws", account_id, region)
                os.makedirs(raw_dir, exist_ok=True)
                raw_file = os.path.join(raw_dir, f"{service}.json")
                
                # Organize raw data by discovery_id for better structure
                # Extract discovery_id mappings (stored as _discovery_{save_as} keys)
                clean_raw_data = {k: v for k, v in raw_data.items() if not k.endswith('_contexts') and not k.startswith('_discovery_')}
                discovery_mappings = {k.replace('_discovery_', ''): v for k, v in raw_data.items() if k.startswith('_discovery_')}
                
                with file_lock:
                    existing_data = {}
                    if os.path.exists(raw_file):
                        try:
                            with open(raw_file, "r") as f:
                                existing_data = json.load(f)
                        except:
                            existing_data = {}
                    
                    # Structure: organize by discovery_id (using mappings from service_scanner)
                    structured_data = existing_data.copy()
                    for save_as_key, response_data in clean_raw_data.items():
                        # Get discovery_id for this save_as key
                        discovery_id = discovery_mappings.get(save_as_key)
                        if discovery_id:
                            # Organize by discovery_id
                            if discovery_id not in structured_data:
                                structured_data[discovery_id] = {}
                            structured_data[discovery_id][save_as_key] = response_data
                        else:
                            # Fallback: keep flat structure if discovery_id not available
                            if save_as_key not in structured_data:
                                structured_data[save_as_key] = response_data
                            elif isinstance(structured_data[save_as_key], list) and isinstance(response_data, list):
                                structured_data[save_as_key].extend(response_data)
                            elif isinstance(structured_data[save_as_key], dict) and isinstance(response_data, dict):
                                structured_data[save_as_key] = {**structured_data[save_as_key], **response_data}
                            else:
                                structured_data[save_as_key] = response_data
                    
                    with open(raw_file, "w", encoding="utf-8") as f:
                        json.dump(structured_data, f, default=str, indent=2)
            
            # Write results (Option A by default: one line per finding, no embedded inventory)
            mode = _results_ndjson_mode()
            with file_lock:
                os.makedirs(os.path.dirname(task["results_file"]), exist_ok=True)
                if mode == "legacy":
                    # Original behavior (includes inventory) - not recommended.
                    result_for_output = {k: v for k, v in result.items() if k != "_raw_data"}
                    with open(task["results_file"], "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(result_for_output, default=str) + "\n")
                elif mode == "task":
                    # One line per service task, but never embed inventory.
                    task_out = {k: v for k, v in result.items() if k not in ("inventory", "_raw_data")}
                    with open(task["results_file"], "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(task_out, default=str) + "\n")
                else:
                    # Default: one line per finding/check (Option A).
                    tenant_id = _get_tenant_id()
                    provider = result.get("provider") or "aws"
                    findings_written = False
                    for finding in _to_minimal_finding_records(
                        scan_id=scan_run_id,
                        tenant_id=tenant_id,
                        provider=provider,
                        result=result,
                    ):
                        with open(task["results_file"], "a", encoding="utf-8") as fh:
                            fh.write(json.dumps(finding, default=str) + "\n")
                        findings_written = True
                    
                    # If no findings but scan completed, write a task record to indicate scan ran
                    if not findings_written:
                        task_record = {
                            "schema_version": "cspm_task.v1",
                            "tenant_id": tenant_id,
                            "scan_run_id": scan_run_id,
                            "provider": provider,
                            "account_id": task['account_id'],
                            "region": task['region'],
                            "service": result.get("service") or task['service_name'],
                            "status": "completed",
                            "checks_count": len(result.get("checks", []) or []),
                            "inventory_count": sum(len(items) if isinstance(items, list) else 0 for items in (result.get("inventory", {}) or {}).values()),
                            "created_at": datetime.utcnow().isoformat() + "Z"
                        }
                        with open(task["results_file"], "a", encoding="utf-8") as fh:
                            fh.write(json.dumps(task_record, default=str) + "\n")
            
            # Write inventory (reuse existing logic)
            service_from_result = result.get("service")
            account_from_result = result.get("account") or task['account_id']
            region_from_result = result.get("region") or task['region']
            inventory = result.get("inventory", {})
            
            tenant_id = _get_tenant_id()
            # scan_run_id computed above (used for both results + inventory)
            
            # Ensure inventory file exists (create if doesn't exist)
            with file_lock:
                os.makedirs(os.path.dirname(task["discoveries_file"]), exist_ok=True)
                # Touch file to ensure it exists
                with open(task["discoveries_file"], "a", encoding="utf-8"):
                    pass
            
            # Extract and write inventory assets
            from utils.reporting_manager import is_cspm_inventory_resource
            seen_in_result = set()
            inventory_written = False
            
            for discovery_id, items in inventory.items():
                if not isinstance(items, list):
                    continue
                
                if not is_cspm_inventory_resource(discovery_id, discovery_config=None):
                    continue
                
                parts = discovery_id.split(".")
                if len(parts) >= 2 and parts[0] == "aws":
                    service_from_discovery = parts[1]
                else:
                    service_from_discovery = service_from_result
                
                discovery_service_is_global = is_global_service(service_from_discovery)
                discovery_region = None if discovery_service_is_global else region_from_result
                
                raw_ref_path = os.path.join(scan_folder, "raw", "aws", account_from_result, region_from_result, f"{service_from_discovery}.json")
                
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    
                    try:
                        asset = _create_canonical_asset(
                            item, service_from_discovery, discovery_region,
                            account_from_result, tenant_id, scan_run_id,
                            raw_ref_path, discovery_id
                        )
                        
                        if not asset:
                            continue
                        
                        resource_uid = asset.get("resource_uid")
                        if resource_uid in seen_in_result:
                            continue
                        seen_in_result.add(resource_uid)
                        
                        with file_lock:
                            with open(task["discoveries_file"], "a", encoding="utf-8") as fh:
                                fh.write(json.dumps(asset, default=str) + "\n")
                            inventory_written = True
                                
                    except Exception as e:
                        logger.debug(f"Failed to create asset for {discovery_id}: {e}")
                        continue
            
            # Count checks
            checks = result.get("checks", []) or []
            with file_lock:
                total_checks += len(checks)
                total_passed += sum(1 for c in checks if c.get("result") == "PASS")
                total_failed += sum(1 for c in checks if c.get("result") == "FAIL")
        
        def _scan_service_task(task: Dict) -> Dict[str, Any]:
            """Scan a single service for one account+region"""
            task_stats['started'] += 1
            account = task['account']
            account_id = task['account_id']
            region = task['region']
            service_name = task['service_name']
            scope = task['scope']
            
            try:
                # Get session for this account
                session = get_session_for_account(
                    account_id=account_id,
                    role_name=role_name,
                    default_region=region if region != 'global' else 'us-east-1',
                    external_id=external_id,
                ) if role_name else get_boto3_session()
            except Exception as e:
                logger.error(f"Failed to access {account_id}: {e}")
                return None
            
            # Scan service
            try:
                if scope == 'global':
                    result = run_global_service(service_name, session_override=session)
                else:
                    result = run_regional_service(service_name, region, session_override=session)
                
                if result:
                    result['account'] = account_id
                    result['region'] = region
                    _write_service_result(task, result)
                    
                    # MEMORY OPTIMIZATION: Clear large data structures after writing to disk
                    # This reduces peak memory usage when many services run in parallel
                    # Raw data is already written to disk, so we can safely delete it
                    if '_raw_data' in result:
                        del result['_raw_data']
                    
                    # Replace full inventory with summary counts (inventory already written to disk)
                    # Keep only counts for summary/aggregation purposes
                    inventory = result.get('inventory', {})
                    if inventory:
                        inventory_summary = {}
                        for discovery_id, items in inventory.items():
                            if isinstance(items, list):
                                inventory_summary[discovery_id] = len(items)
                            else:
                                inventory_summary[discovery_id] = 0
                        result['inventory'] = inventory_summary
                        result['_inventory_written'] = True  # Flag to indicate full data was written
                
                return result
            except Exception as e:
                logger.error(f"Failed to scan {service_name} in {account_id}/{region}: {e}")
                return None
        
        # Execute all service tasks in parallel with single ThreadPoolExecutor
        import time
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_total_workers) as executor:
            future_to_task = {
                executor.submit(_scan_service_task, task): task
                for task in all_service_tasks
            }
            
            completed = 0
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                completed += 1
                task_stats['completed'] = completed
                
                try:
                    result = future.result()
                    elapsed = time.time() - start_time
                    rate = completed / elapsed if elapsed > 0 else 0
                    logger.info(f"[{completed}/{len(all_service_tasks)}] ✓ {task['account_id']}/{task['region']}/{task['service_name']} ({rate:.1f} tasks/sec)")
                except Exception as e:
                    logger.error(f"[{completed}/{len(all_service_tasks)}] ✗ {task['account_id']}/{task['region']}/{task['service_name']}: {e}")
        
        # Aggregate results files (group by account+region)
        results_files_by_key = {}
        discoveries_files_by_key = {}
        
        for task in all_service_tasks:
            key = f"{task['account_id']}_{task['region']}"
            if task['results_file'] not in results_files_by_key.get(key, []):
                if key not in results_files_by_key:
                    results_files_by_key[key] = []
                results_files_by_key[key].append(task['results_file'])
            if task["discoveries_file"] not in discoveries_files_by_key.get(key, []):
                if key not in discoveries_files_by_key:
                    discoveries_files_by_key[key] = []
                discoveries_files_by_key[key].append(task["discoveries_file"])
        
        # Flatten to lists (summary is built later; keep these for the final return value)
        results_files_list = [f for files in results_files_by_key.values() for f in files]
        discoveries_files_list = [f for files in discoveries_files_by_key.values() for f in files]
        
        # Create summary entries per account+region
        for key, files in results_files_by_key.items():
            account_region_summaries.append({
                "account_id": key.split('_')[0] if '_' in key else key,
                "region": key.split('_', 1)[1] if '_' in key else "global",
                "results_file": files[0] if files else None,
                "discoveries_file": discoveries_files_by_key.get(key, [None])[0],
            })
        
        # account_region_summaries is attached to summary later (summary built at end)
        
        elapsed_total = time.time() - start_time
        logger.info(f"\n✓ Flattened model completed: {len(all_service_tasks)} tasks in {elapsed_total:.1f}s ({len(all_service_tasks)/elapsed_total:.1f} tasks/sec avg)")
    
    # NEW ACCOUNT+REGION MODEL
    elif use_account_region_model:
        from utils.reporting_manager import is_global_service
        
        logger.info("\nUsing Account+Region concurrent scanning model...")
        
        # Separate global and regional services
        global_services = [(svc, scope) for svc, scope in services_to_scan if is_global_service(svc)]
        regional_services = [(svc, scope) for svc, scope in services_to_scan if not is_global_service(svc)]
        
        # Build tasks: account+region combinations for regional services
        account_region_tasks = []
        for account in accounts_to_scan:
            for region in regions_to_scan:
                account_region_tasks.append({
                    'account': account,
                    'region': region,
                    'results_file': os.path.join(scan_folder, f"results_{account['Id']}_{region}.ndjson"),
                    'discoveries_file': os.path.join(scan_folder, f"discoveries_{account['Id']}_{region}.ndjson"),
                })
        
        # Build tasks: global services (one per account)
        global_tasks = []
        for account in accounts_to_scan:
            global_tasks.append({
                'account': account,
                'results_file': os.path.join(scan_folder, f"results_{account['Id']}_global.ndjson"),
                'discoveries_file': os.path.join(scan_folder, f"discoveries_{account['Id']}_global.ndjson"),
            })
        
        all_tasks = account_region_tasks + global_tasks
        logger.info(f"  Generated {len(account_region_tasks)} account+region tasks + {len(global_tasks)} global service tasks")
        
        # Run all tasks in parallel
        with ThreadPoolExecutor(max_workers=max_account_region_workers) as executor:
            # Submit account+region tasks
            future_to_task = {}
            for task in account_region_tasks:
                future = executor.submit(
                    scan_account_region_scope,
                    task['account'],
                    task['region'],
                    regional_services,
                    resource_filter,
                    role_name,
                    external_id,
                    max_workers,
                    task['results_file'],
                    task["discoveries_file"],
                )
                future_to_task[future] = task
            
            # Submit global service tasks
            for task in global_tasks:
                future = executor.submit(
                    scan_account_global_services,
                    task['account'],
                    global_services,
                    resource_filter,
                    role_name,
                    external_id,
                    max_workers,
                    task['results_file'],
                    task["discoveries_file"],
                )
                future_to_task[future] = task
            
            # Collect results
            completed = 0
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                completed += 1
                
                try:
                    c_total, c_passed, c_failed, task_summary = future.result()
                    total_checks += c_total
                    total_passed += c_passed
                    total_failed += c_failed
                    account_region_summaries.append(task_summary)
                    
                    account_id = task['account']['Id']
                    region = task.get('region', 'global')
                    logger.info(f"[{completed}/{len(all_tasks)}] ✓ {account_id}/{region}: {c_total} checks ({c_passed} PASS, {c_failed} FAIL)")
                except Exception as e:
                    account_id = task['account']['Id']
                    region = task.get('region', 'global')
                    logger.error(f"[{completed}/{len(all_tasks)}] ✗ {account_id}/{region}: {e}")
        
        # Create aggregated summary with all account+region files
        summary["account_region_summaries"] = account_region_summaries
        summary["results_files"] = [s.get("results_file") for s in account_region_summaries if s.get("results_file")]
        summary["discoveries_files"] = [s.get("discoveries_file") for s in account_region_summaries if s.get("discoveries_file")]
        
    # LEGACY MODEL
    elif max_account_workers == 1:
        # Sequential account scanning
        logger.info("\nScanning accounts sequentially...")
        for idx, acc in enumerate(accounts_to_scan, 1):
            logger.info(f"[{idx}/{len(accounts_to_scan)}] Scanning {acc['Name']} ({acc['Id']})")
            if stream_results:
                c_total, c_passed, c_failed = scan_account_scope_streaming(
                    acc, regions_to_scan, services_to_scan, resource_filter,
                    role_name, external_id, max_workers, _write_result
                )
                total_checks += c_total
                total_passed += c_passed
                total_failed += c_failed
                logger.info(f"  Account {acc['Id']} completed: {c_total} checks ({c_passed} PASS, {c_failed} FAIL)")
            else:
                results = scan_account_scope(
                    acc, regions_to_scan, services_to_scan, resource_filter,
                    role_name, external_id, max_workers
                )
                all_results.extend(results)
    else:
        # Parallel account scanning WITH streaming support
        logger.info(f"\nScanning {len(accounts_to_scan)} accounts in parallel (max {max_account_workers})...")
        
        with ThreadPoolExecutor(max_workers=max_account_workers) as executor:
            if stream_results:
                # Use streaming version - writes results incrementally
                future_to_account = {
                    executor.submit(
                        scan_account_scope_streaming,
                        acc, regions_to_scan, services_to_scan, resource_filter,
                        role_name, external_id, max_workers, _write_result
                    ): acc
                    for acc in accounts_to_scan
                }
            else:
                # Use non-streaming version - collects all results
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
                    if stream_results:
                        # Streaming version returns tuple: (total_checks, passed_checks, failed_checks)
                        c_total, c_passed, c_failed = future.result()
                        total_checks += c_total
                        total_passed += c_passed
                        total_failed += c_failed
                        logger.info(f"[{completed}/{len(accounts_to_scan)}] ✓ {acc['Name']} ({acc['Id']}): {c_total} checks ({c_passed} PASS, {c_failed} FAIL)")
                    else:
                        # Non-streaming version returns list of results
                        results = future.result()
                        all_results.extend(results)
                        acc_total = sum(len(r.get('checks', [])) for r in results)
                        total_checks += acc_total
                        total_passed += sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'PASS') for r in results)
                        total_failed += sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'FAIL') for r in results)
                        logger.info(f"[{completed}/{len(accounts_to_scan)}] ✓ {acc['Name']} ({acc['Id']}): {acc_total} checks")
                except Exception as e:
                    logger.error(f"[{completed}/{len(accounts_to_scan)}] ✗ {acc['Name']} ({acc['Id']}): {e}")
    
    # Summary
    if not stream_results and not use_account_region_model and not use_flattened_model:
        total_checks = sum(len(r.get('checks', [])) for r in all_results)
        total_passed = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'PASS') for r in all_results)
        total_failed = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'FAIL') for r in all_results)
    
    logger.info("\n" + "="*80)
    logger.info("SCAN COMPLETE")
    logger.info("="*80)
    logger.info(f"Scan ID: {scan_id}")
    logger.info(f"Accounts scanned: {len(accounts_to_scan)}")
    logger.info(f"Services scanned: {len(services_to_scan)}")
    logger.info(f"Regions scanned: {len(regions_to_scan)}")
    logger.info(f"Total checks: {total_checks}")
    logger.info(f"  PASS: {total_passed}")
    logger.info(f"  FAIL: {total_failed}")
    if total_checks > 0:
        pass_rate = (total_passed / total_checks) * 100
        logger.info(f"  Pass rate: {pass_rate:.1f}%")
    
    if use_flattened_model or use_account_region_model:
        logger.info(f"Results files: {len(account_region_summaries)} account+region files")
        logger.info(f"Inventory files: {len(account_region_summaries)} account+region files")
    else:
        logger.info(f"Results file: {results_ndjson_path if stream_results else 'N/A (in-memory)'}")
    
    logger.info(f"Report folder: {scan_folder}")
    
    # Calculate and log duration
    scan_end_time = datetime.utcnow()
    scan_duration = (scan_end_time - scan_start_time).total_seconds()
    logger.info(f"Duration: {scan_duration:.1f} seconds ({scan_duration/60:.1f} minutes)")
    logger.info(f"Started: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    logger.info(f"Ended: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    logger.info("="*80)
    logger.info("SCAN ENDED SUCCESSFULLY")
    logger.info("="*80)
    
    # Calculate error and skipped checks from results (if available)
    total_errors = 0
    total_skipped = 0
    
    if not use_account_region_model and not stream_results and all_results:
        # Count errors and skipped from in-memory results
        for result in all_results:
            for check in result.get('checks', []):
                check_result = check.get('result', '').upper()
                if check_result == 'ERROR':
                    total_errors += 1
                elif check_result == 'SKIPPED':
                    total_skipped += 1
    
    # Format timestamps for UI
    started_at_iso = scan_start_time.isoformat() + 'Z'
    completed_at_iso = scan_end_time.isoformat() + 'Z'
    
    # Determine scan type (manual for now, can be enhanced)
    scan_type = "manual"  # Could be "scheduled", "on-demand", etc.
    
    # Determine status
    status = "completed"  # Could be "running", "failed", etc.
    
    summary = {
        # Existing fields
        "scan_id": scan_id,
        "total_checks": int(total_checks),
        "passed_checks": int(total_passed),
        "failed_checks": int(total_failed),
        "results_file": results_ndjson_path if stream_results and not use_account_region_model else None,
        "report_folder": scan_folder,
        # UI-required fields for THREAT SCAN RESULTS table
        "provider": "aws",
        "scan_type": scan_type,
        "status": status,
        "started_at": started_at_iso,
        "completed_at": completed_at_iso,
        "error_checks": int(total_errors),
        "skipped_checks": int(total_skipped),
        # Additional metadata
        "accounts_scanned": len(accounts_to_scan),
        "services_scanned": len(services_to_scan),
        "regions_scanned": len(regions_to_scan),
        "duration_seconds": int(scan_duration)
    }

    # Attach per-account+region output files for the new concurrency models
    if use_flattened_model or use_account_region_model:
        summary["results_files"] = results_files_list
        summary["discoveries_files"] = discoveries_files_list
        summary["account_region_summaries"] = account_region_summaries

        # Also produce consolidated scan-level NDJSON files for consumers that expect them.
        # This is a simple concatenation of the per-account+region outputs.
        # Can be disabled via WRITE_CONSOLIDATED_NDJSON=0 if needed for very large scans.
        if os.getenv("WRITE_CONSOLIDATED_NDJSON", "1").strip() not in ("0", "false", "False"):
            consolidated_results = os.path.join(scan_folder, "results.ndjson")
            consolidated_discoveries = os.path.join(scan_folder, "discoveries.ndjson")

            def _concat_ndjson(out_path: str, inputs: List[str]) -> None:
                with open(out_path, "w", encoding="utf-8") as out_f:
                    for in_path in inputs:
                        if not in_path or not os.path.exists(in_path):
                            continue
                        # Skip empty files
                        try:
                            if os.path.getsize(in_path) == 0:
                                continue
                        except OSError:
                            continue
                        with open(in_path, "r", encoding="utf-8") as in_f:
                            for line in in_f:
                                if line:
                                    out_f.write(line)

            try:
                _concat_ndjson(consolidated_results, results_files_list)
                _concat_ndjson(consolidated_discoveries, discoveries_files_list)
                summary["results_file"] = consolidated_results
                summary["discoveries_file"] = consolidated_discoveries
                logger.info(f"Consolidated results written to: {consolidated_results}")
                logger.info(f"Consolidated discoveries written to: {consolidated_discoveries}")
            except Exception as e:
                logger.warning(f"Failed to write consolidated NDJSON files: {e}")

    # Save report bundle (heavy) only when not streaming and not using account+region model.
    # Account+region model already writes per-account+region files.
    # Streaming mode already writes per-task results to results.ndjson.
    if save_report and not stream_results and not use_account_region_model:
        report_folder = save_reporting_bundle(all_results, account_id=None, scan_folder=scan_folder)
        logger.info(f"\nReport: {report_folder}")
        summary["report_folder"] = report_folder

    # Always write summary.json so sidecar can sync it and API can read it later.
    save_summary(scan_folder, summary)

    return summary


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
                if result:
                    # MEMORY OPTIMIZATION: Clear large data structures after writing to disk
                    # (Note: This function doesn't write to disk, but results are collected)
                    # For consistency, we still clear large data to reduce memory
                    if '_raw_data' in result:
                        del result['_raw_data']
                    
                    # Replace full inventory with summary counts
                    inventory = result.get('inventory', {})
                    if inventory:
                        inventory_summary = {}
                        for discovery_id, items in inventory.items():
                            if isinstance(items, list):
                                inventory_summary[discovery_id] = len(items)
                            else:
                                inventory_summary[discovery_id] = 0
                        result['inventory'] = inventory_summary
                        result['_inventory_written'] = True
                
                results.append(result)
            except Exception as e:
                task = futures[future]
                logger.error(f"Task failed: {task['service_name']}: {e}")
    
    return results


def scan_account_scope_streaming(
    account: Dict[str, str],
    regions: List[str],
    services: List[tuple],
    resource_filter: Optional[Callable],
    role_name: Optional[str],
    external_id: Optional[str],
    max_workers: int,
    on_result: Callable[[Dict[str, Any]], None],
) -> Tuple[int, int, int]:
    """
    Scan one account and stream each task result to `on_result` as soon as it completes.

    Returns:
        (total_checks, passed_checks, failed_checks)
    """
    account_id = account["Id"]

    # Get session for this account
    try:
        session = get_session_for_account(
            account_id=account_id,
            role_name=role_name,
            default_region="us-east-1",
            external_id=external_id,
        ) if role_name else get_boto3_session()
    except Exception as e:
        logger.error(f"Failed to access account {account_id}: {e}")
        return (0, 0, 0)

    # Build scan tasks
    tasks = []
    for service_name, scope in services:
        if scope == "global":
            tasks.append(
                {
                    "account_id": account_id,
                    "region": "us-east-1",
                    "service_name": service_name,
                    "scope": scope,
                    "session": session,
                }
            )
        else:
            for region in regions:
                tasks.append(
                    {
                        "account_id": account_id,
                        "region": region,
                        "service_name": service_name,
                        "scope": scope,
                        "session": session,
                    }
                )

    logger.info(f"  Scan tasks: {len(tasks)} (streaming)")

    total_checks = 0
    passed_checks = 0
    failed_checks = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                scan_service_in_scope,
                task["account_id"],
                task["region"],
                task["service_name"],
                task["scope"],
                task["session"],
                resource_filter,
            ): task
            for task in tasks
        }

        for future in as_completed(futures):
            try:
                result = future.result()
                on_result(result)
                checks = result.get("checks", []) or []
                total_checks += len(checks)
                passed_checks += sum(1 for c in checks if c.get("result") == "PASS")
                failed_checks += sum(1 for c in checks if c.get("result") == "FAIL")
            except Exception as e:
                task = futures[future]
                logger.error(f"Task failed: {task['service_name']}: {e}")

    return (total_checks, passed_checks, failed_checks)


def _create_canonical_asset(
    item: Dict[str, Any],
    service_from_discovery: str,
    discovery_region: Optional[str],
    account: str,
    tenant_id: str,
    scan_run_id: str,
    raw_ref_path: str,
    discovery_id: str
) -> Optional[Dict[str, Any]]:
    """
    Helper function to create canonical cspm_asset.v1 asset from raw item.
    
    Returns None if asset cannot be created (missing identifiers).
    """
    from engine.service_scanner import extract_resource_identifier
    from utils.reporting_manager import is_global_service
    
    try:
        resource_info = extract_resource_identifier(
            item,
            service_from_discovery,
            discovery_region,
            account,
            discovery_id=discovery_id  # Pass discovery_id for resource type inference
        )
        
        resource_id = resource_info.get("resource_id")
        resource_type = resource_info.get("resource_type", "resource")
        resource_arn = resource_info.get("resource_arn")
        resource_uid = resource_info.get("resource_uid")
        
        # Validate resource_id - must be a valid, non-empty string
        if resource_id:
            resource_id_str = str(resource_id).strip()
            # Skip invalid resource_ids
            if not resource_id_str or resource_id_str in ["[]", "{}", ""]:
                resource_id = None
        
        # STRICT ARN VALIDATION: Every real AWS resource should have a valid ARN
        # Skip resources without valid ARNs (likely not real resources - attributes/config instead)
        if not resource_arn:
            return None  # No ARN = not a real AWS resource
        
        # Validate ARN format
        if not resource_arn.startswith("arn:aws:"):
            return None  # Invalid ARN format
        
        # Skip ARNs with invalid patterns (arrays, empty objects, etc.)
        if "[]" in resource_arn or "{}" in resource_arn or "['" in resource_arn or '["' in resource_arn:
            return None  # Invalid ARN content
        
        # Determine scope and region
        discovery_service_is_global = is_global_service(service_from_discovery)
        final_region = "global" if discovery_service_is_global else (discovery_region or "global")
        final_scope = "global" if discovery_service_is_global else "regional"
        
        # Extract tags
        tags = {}
        if "Tags" in item and isinstance(item["Tags"], list):
            for tag in item["Tags"]:
                if isinstance(tag, dict) and "Key" in tag and "Value" in tag:
                    tags[tag["Key"]] = tag["Value"]
        elif "tags" in item and isinstance(item["tags"], dict):
            tags = item["tags"]
        elif "tags" in item and isinstance(item["tags"], str):
            try:
                tags = json.loads(item["tags"]) if item["tags"] else {}
            except:
                tags = {}
        
        # Extract name
        name = item.get("name") or item.get("Name") or item.get("resource_name") or resource_id or ""
        
        # Extract created_at (for UI: created_at)
        created_at = item.get("CreationDate") or item.get("CreateDate") or item.get("createdAt") or item.get("CreatedAt")
        if created_at and not isinstance(created_at, str):
            try:
                created_at = created_at.isoformat() + "Z" if hasattr(created_at, 'isoformat') else str(created_at)
            except:
                created_at = None
        
        # Extract updated_at (for UI: updated_at)
        updated_at = item.get("LastModifiedDate") or item.get("UpdateDate") or item.get("updatedAt") or item.get("UpdatedAt") or item.get("LastUpdateDate")
        if updated_at and not isinstance(updated_at, str):
            try:
                updated_at = updated_at.isoformat() + "Z" if hasattr(updated_at, 'isoformat') else str(updated_at)
            except:
                updated_at = None
        
        # Extract environment from tags (for UI: environment)
        environment = (
            tags.get("Environment") or 
            tags.get("env") or 
            tags.get("Env") or 
            tags.get("environment") or
            tags.get("ENV") or
            ""
        )
        
        # Derive category from service/resource_type (for UI: category)
        category_map = {
            "ec2": "Compute",
            "s3": "Storage",
            "rds": "Database",
            "lambda": "Compute",
            "iam": "Security",
            "vpc": "Network",
            "elb": "Network",
            "cloudfront": "Network",
            "route53": "Network",
            "sns": "Application",
            "sqs": "Application",
            "dynamodb": "Database",
            "kms": "Security",
            "secretsmanager": "Security",
            "cloudwatch": "Monitoring",
            "account": "Account"
        }
        category = category_map.get(service_from_discovery.lower(), "Other")
        
        # Extract lifecycle_state (for UI: lifecycle_state)
        lifecycle_state = (
            item.get("State") or 
            item.get("Status") or 
            item.get("LifecycleState") or 
            item.get("InstanceState") or
            item.get("DBInstanceStatus") or
            item.get("BucketLocationConstraint") or
            ""
        )
        # Normalize state values for UI
        if lifecycle_state and isinstance(lifecycle_state, dict):
            lifecycle_state = lifecycle_state.get("Name", "")
        lifecycle_state = str(lifecycle_state).title() if lifecycle_state else ""
        
        # Extract health_status (for UI: health_status)
        health_status = (
            item.get("HealthStatus") or 
            item.get("Health") or 
            item.get("StateReason") or  # For EC2 instances
            ""
        )
        # Normalize health status for UI
        if health_status and isinstance(health_status, str):
            health_status = health_status.title()
        health_status = health_status if health_status else "Unknown"
        
        # Use ARN as resource_id if available (more useful for AWS UI)
        display_resource_id = resource_arn or resource_id or ""
        
        # Format resource_type to match AWS service structure: service:resource-type
        # e.g., "rds:security-group", "ec2:instance", "s3:bucket"
        formatted_resource_type = f"{service_from_discovery}:{resource_type}" if resource_type != "resource" else service_from_discovery
        
        # Create canonical asset with UI-required fields
        asset = {
            "schema_version": "cspm_asset.v1",
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "provider": "aws",
            "service": service_from_discovery,  # Add service field for clarity
            "account_id": account,
            "region": final_region,
            "scope": final_scope,
            "resource_type": formatted_resource_type,  # Format: service:resource-type
            "resource_id": display_resource_id,  # Prefer ARN if available
            "resource_arn": resource_arn or "",  # Move ARN to top level
            "resource_uid": resource_uid,
            "name": name,
            "tags": tags,
            # UI-required fields (add to top level for easy access)
            "environment": environment,
            "category": category,
            "lifecycle_state": lifecycle_state,
            "health_status": health_status,
            "created_at": created_at,
            "updated_at": updated_at,
            "is_aws_managed": resource_info.get("is_aws_managed", False),  # NEW: AWS-managed flag
            "metadata": {
                "created_at": created_at,  # Keep in metadata for compatibility
                "updated_at": updated_at,  # Keep in metadata
                "labels": {},
                "raw_refs": [raw_ref_path],
                "discovery_operation": discovery_id,
                "original_resource_id": resource_id  # Keep original ID if ARN was used
            }
        }
        
        # Preserve enriched fields from dependent discoveries (nested approach)
        # Store entire dependent discovery data under _dependent_data key
        if '_dependent_data' in item and isinstance(item['_dependent_data'], dict):
            asset['_dependent_data'] = item['_dependent_data']
            enriched_discoveries = list(item['_dependent_data'].keys())
            logger.debug(f"[INVENTORY-WRITE] Preserved _dependent_data with {len(enriched_discoveries)} discoveries: {enriched_discoveries[:3]}")
        
        # Compute hash
        asset["hash_sha256"] = compute_asset_hash(asset)
        
        return asset
        
    except Exception as e:
        logger.debug(f"Failed to create asset: {e}")
        return None


def scan_account_region_scope(
    account: Dict[str, str],
    region: str,
    services: List[tuple],
    resource_filter: Optional[Callable],
    role_name: Optional[str],
    external_id: Optional[str],
    max_workers: int,
    results_file: str,
    discoveries_file: str,
) -> Tuple[int, int, int, Dict[str, Any]]:
    """
    Scan one account+region combination with all regional services.
    Writes results to account+region-specific files.
    
    Args:
        account: Account dict with 'Id' and 'Name'
        region: AWS region to scan
        services: List of (service_name, scope) tuples (only regional services)
        resource_filter: Optional resource filter function
        role_name: Optional IAM role for cross-account access
        external_id: Optional external ID for role assumption
        max_workers: Parallel service workers within this account+region
        results_file: Path to write results.ndjson
        discoveries_file: Path to write discoveries.ndjson
    
    Returns:
        (total_checks, passed_checks, failed_checks, summary_dict)
    """
    from utils.reporting_manager import is_global_service
    from engine.service_scanner import extract_resource_identifier
    
    account_id = account["Id"]
    account_name = account.get("Name", account_id)
    
    # Get session for this account
    try:
        session = get_session_for_account(
            account_id=account_id,
            role_name=role_name,
            default_region=region,
            external_id=external_id,
        ) if role_name else get_boto3_session()
    except Exception as e:
        logger.error(f"Failed to access account {account_id}: {e}")
        return (0, 0, 0, {"error": str(e)})
    
    # Filter to only regional services for this account+region scan
    regional_services = [(svc, scope) for svc, scope in services if not is_global_service(svc)]
    
    if not regional_services:
        logger.info(f"  No regional services for {account_id}/{region}")
        return (0, 0, 0, {"message": "No regional services"})
    
    # Build scan tasks (only regional services for this region)
    tasks = []
    for service_name, scope in regional_services:
        tasks.append({
            "account_id": account_id,
            "region": region,
            "service_name": service_name,
            "scope": scope,
            "session": session,
        })
    
    logger.info(f"  [{account_name}/{region}] Scanning {len(tasks)} regional services")
    
    # Ensure output files exist
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    with open(results_file, "a", encoding="utf-8"):
        pass
    with open(discoveries_file, "a", encoding="utf-8"):
        pass
    
    total_checks = 0
    passed_checks = 0
    failed_checks = 0
    results = []
    
    # Thread-safe file writing helper
    import threading
    file_lock = threading.Lock()
    
    def _write_result(result: Dict[str, Any]) -> None:
        """Write result to account+region-specific files"""
        nonlocal total_checks, passed_checks, failed_checks
        
        # Save raw data to disk (if present in result)
        raw_data = result.get("_raw_data")
        if raw_data:
            service = result.get("service")
            account_from_result = result.get("account") or account_id
            region_from_result = result.get("region") or region
            
            # Determine raw data path: raw/aws/{account}/{region}/{service}.json
            raw_dir = os.path.join(os.path.dirname(results_file), "raw", "aws", account_from_result, region_from_result)
            os.makedirs(raw_dir, exist_ok=True)
            raw_file = os.path.join(raw_dir, f"{service}.json")
            
            # Organize raw data by discovery_id for better structure
            # Extract discovery_id mappings (stored as _discovery_{save_as} keys)
            clean_raw_data = {k: v for k, v in raw_data.items() if not k.endswith('_contexts') and not k.startswith('_discovery_')}
            discovery_mappings = {k.replace('_discovery_', ''): v for k, v in raw_data.items() if k.startswith('_discovery_')}
            
            with file_lock:
                existing_data = {}
                if os.path.exists(raw_file):
                    try:
                        with open(raw_file, "r") as f:
                            existing_data = json.load(f)
                    except:
                        existing_data = {}
                
                # Structure: organize by discovery_id (using mappings from service_scanner)
                structured_data = existing_data.copy()
                for save_as_key, response_data in clean_raw_data.items():
                    discovery_id = discovery_mappings.get(save_as_key)
                    if discovery_id:
                        if discovery_id not in structured_data:
                            structured_data[discovery_id] = {}
                        structured_data[discovery_id][save_as_key] = response_data
                    else:
                        # Fallback: keep flat structure if discovery_id not available
                        if save_as_key not in structured_data:
                            structured_data[save_as_key] = response_data
                        elif isinstance(structured_data[save_as_key], list) and isinstance(response_data, list):
                            structured_data[save_as_key].extend(response_data)
                        elif isinstance(structured_data[save_as_key], dict) and isinstance(response_data, dict):
                            structured_data[save_as_key] = {**structured_data[save_as_key], **response_data}
                        else:
                            structured_data[save_as_key] = response_data
                
                with open(raw_file, "w", encoding="utf-8") as f:
                    json.dump(structured_data, f, default=str, indent=2)
        
        # Write check results (Option A by default: one line per finding, no embedded inventory)
        mode = _results_ndjson_mode()
        if mode == "legacy":
            result_for_output = {k: v for k, v in result.items() if k != "_raw_data"}
            with file_lock:
                with open(results_file, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(result_for_output, default=str) + "\n")
        elif mode == "task":
            task_out = {k: v for k, v in result.items() if k not in ("inventory", "_raw_data")}
            with file_lock:
                with open(results_file, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(task_out, default=str) + "\n")
        else:
            tenant_id = _get_tenant_id()
            provider = result.get("provider") or "aws"
            for finding in _to_minimal_finding_records(
                scan_id=scan_run_id,
                tenant_id=tenant_id,
                provider=provider,
                result=result,
            ):
                with file_lock:
                    with open(results_file, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(finding, default=str) + "\n")
        
        # Extract and write inventory assets
        service = result.get("service")
        account_from_result = result.get("account") or account_id
        region_from_result = result.get("region") or region
        inventory = result.get("inventory", {})
        
        seen_in_this_result = set()
        tenant_id = _get_tenant_id()
        scan_run_id = os.path.basename(os.path.dirname(results_file))
        
        for discovery_id, items in inventory.items():
            if not isinstance(items, list):
                continue
            
            # Check if this discovery should produce inventory assets (universal heuristic)
            from utils.reporting_manager import is_cspm_inventory_resource
            if not is_cspm_inventory_resource(discovery_id, discovery_config=None):
                continue
            
            # Extract service name from discovery_id
            parts = discovery_id.split(".")
            if len(parts) >= 2 and parts[0] == "aws":
                service_from_discovery = parts[1]
            else:
                service_from_discovery = service
            
            discovery_service_is_global = is_global_service(service_from_discovery)
            discovery_region = None if discovery_service_is_global else region_from_result
            
            # Build raw_ref path
            raw_ref_path = os.path.join(os.path.dirname(results_file), "raw", "aws", account_from_result, region_from_result, f"{service_from_discovery}.json")
            
            for item in items:
                if not isinstance(item, dict):
                    continue
                
                try:
                    # Create canonical asset using helper
                    asset = _create_canonical_asset(
                        item, service_from_discovery, discovery_region,
                        account_from_result, tenant_id, scan_run_id,
                        raw_ref_path, discovery_id
                    )
                    
                    if not asset:
                        continue
                    
                    resource_uid = asset.get("resource_uid")
                    if resource_uid in seen_in_this_result:
                        continue
                    seen_in_this_result.add(resource_uid)
                    
                    # Append to inventory file
                    with file_lock:
                        with open(discoveries_file, "a", encoding="utf-8") as fh:
                            fh.write(json.dumps(asset, default=str) + "\n")
                            
                except Exception as e:
                    logger.debug(f"Failed to extract resource identifier for {discovery_id}: {e}")
                    continue
        
        # Count checks
        checks = result.get("checks", []) or []
        total_checks += len(checks)
        passed_checks += sum(1 for c in checks if c.get("result") == "PASS")
        failed_checks += sum(1 for c in checks if c.get("result") == "FAIL")
        
        results.append(result)
    
    # Execute tasks in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                scan_service_in_scope,
                task["account_id"],
                task["region"],
                task["service_name"],
                task["scope"],
                task["session"],
                resource_filter,
            ): task
            for task in tasks
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                # Write result even if empty (no inventory, no checks) - important for tracking
                if result:
                    _write_result(result)
                    
                    # MEMORY OPTIMIZATION: Clear large data structures after writing to disk
                    # This reduces peak memory usage when many services run in parallel
                    if '_raw_data' in result:
                        del result['_raw_data']
                    
                    # Replace full inventory with summary counts (inventory already written to disk)
                    inventory = result.get('inventory', {})
                    if inventory:
                        inventory_summary = {}
                        for discovery_id, items in inventory.items():
                            if isinstance(items, list):
                                inventory_summary[discovery_id] = len(items)
                            else:
                                inventory_summary[discovery_id] = 0
                        result['inventory'] = inventory_summary
                        result['_inventory_written'] = True
                else:
                    # Log empty results for debugging
                    task = futures[future]
                    logger.debug(f"Empty result for {task['service_name']} in {account_id}/{region}")
            except Exception as e:
                task = futures[future]
                logger.error(f"Task failed: {task['service_name']} in {account_id}/{region}: {e}")
    
    summary = {
        "account_id": account_id,
        "account_name": account_name,
        "region": region,
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "services_scanned": len(regional_services),
        "results_file": results_file,
        "discoveries_file": discoveries_file,
    }
    
    logger.info(f"  [{account_name}/{region}] Completed: {total_checks} checks ({passed_checks} PASS, {failed_checks} FAIL)")
    
    return (total_checks, passed_checks, failed_checks, summary)


def scan_account_global_services(
    account: Dict[str, str],
    services: List[tuple],
    resource_filter: Optional[Callable],
    role_name: Optional[str],
    external_id: Optional[str],
    max_workers: int,
    results_file: str,
    discoveries_file: str,
) -> Tuple[int, int, int, Dict[str, Any]]:
    """
    Scan global services for one account (run once per account, not per region).
    Writes results to account-specific files.
    
    Args:
        account: Account dict with 'Id' and 'Name'
        services: List of (service_name, scope) tuples (only global services)
        resource_filter: Optional resource filter function
        role_name: Optional IAM role for cross-account access
        external_id: Optional external ID for role assumption
        max_workers: Parallel service workers
        results_file: Path to write results.ndjson
        discoveries_file: Path to write discoveries.ndjson
    
    Returns:
        (total_checks, passed_checks, failed_checks, summary_dict)
    """
    from utils.reporting_manager import is_global_service
    from engine.service_scanner import extract_resource_identifier
    
    account_id = account["Id"]
    account_name = account.get("Name", account_id)
    
    # Get session for this account
    try:
        session = get_session_for_account(
            account_id=account_id,
            role_name=role_name,
            default_region="us-east-1",
            external_id=external_id,
        ) if role_name else get_boto3_session()
    except Exception as e:
        logger.error(f"Failed to access account {account_id}: {e}")
        return (0, 0, 0, {"error": str(e)})
    
    # Filter to only global services
    global_services = [(svc, scope) for svc, scope in services if is_global_service(svc)]
    
    if not global_services:
        logger.info(f"  No global services for {account_id}")
        return (0, 0, 0, {"message": "No global services"})
    
    # Build scan tasks (global services run in us-east-1)
    tasks = []
    for service_name, scope in global_services:
        tasks.append({
            "account_id": account_id,
            "region": "us-east-1",  # Global services use us-east-1
            "service_name": service_name,
            "scope": scope,
            "session": session,
        })
    
    logger.info(f"  [{account_name}/global] Scanning {len(tasks)} global services")
    
    # Ensure output files exist
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    with open(results_file, "a", encoding="utf-8"):
        pass
    with open(discoveries_file, "a", encoding="utf-8"):
        pass
    
    total_checks = 0
    passed_checks = 0
    failed_checks = 0
    results = []
    
    # Thread-safe file writing helper
    import threading
    file_lock = threading.Lock()
    
    def _write_result(result: Dict[str, Any]) -> None:
        """Write result to account-specific files"""
        nonlocal total_checks, passed_checks, failed_checks
        
        # Save raw data to disk (if present in result)
        raw_data = result.get("_raw_data")
        if raw_data:
            service = result.get("service")
            account_from_result = result.get("account") or account_id
            region_from_result = "global"  # Global services
            
            # Determine raw data path: raw/aws/{account}/global/{service}.json
            raw_dir = os.path.join(os.path.dirname(results_file), "raw", "aws", account_from_result, "global")
            os.makedirs(raw_dir, exist_ok=True)
            raw_file = os.path.join(raw_dir, f"{service}.json")
            
            # Organize raw data by discovery_id for better structure
            # Extract discovery_id mappings (stored as _discovery_{save_as} keys)
            clean_raw_data = {k: v for k, v in raw_data.items() if not k.endswith('_contexts') and not k.startswith('_discovery_')}
            discovery_mappings = {k.replace('_discovery_', ''): v for k, v in raw_data.items() if k.startswith('_discovery_')}
            
            with file_lock:
                existing_data = {}
                if os.path.exists(raw_file):
                    try:
                        with open(raw_file, "r") as f:
                            existing_data = json.load(f)
                    except:
                        existing_data = {}
                
                # Structure: organize by discovery_id (using mappings from service_scanner)
                structured_data = existing_data.copy()
                for save_as_key, response_data in clean_raw_data.items():
                    discovery_id = discovery_mappings.get(save_as_key)
                    if discovery_id:
                        if discovery_id not in structured_data:
                            structured_data[discovery_id] = {}
                        structured_data[discovery_id][save_as_key] = response_data
                    else:
                        # Fallback: keep flat structure if discovery_id not available
                        if save_as_key not in structured_data:
                            structured_data[save_as_key] = response_data
                        elif isinstance(structured_data[save_as_key], list) and isinstance(response_data, list):
                            structured_data[save_as_key].extend(response_data)
                        elif isinstance(structured_data[save_as_key], dict) and isinstance(response_data, dict):
                            structured_data[save_as_key] = {**structured_data[save_as_key], **response_data}
                        else:
                            structured_data[save_as_key] = response_data
                
                with open(raw_file, "w", encoding="utf-8") as f:
                    json.dump(structured_data, f, default=str, indent=2)
        
        # Write check results (Option A by default: one line per finding, no embedded inventory)
        mode = _results_ndjson_mode()
        if mode == "legacy":
            result_for_output = {k: v for k, v in result.items() if k != "_raw_data"}
            with file_lock:
                with open(results_file, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(result_for_output, default=str) + "\n")
        elif mode == "task":
            task_out = {k: v for k, v in result.items() if k not in ("inventory", "_raw_data")}
            with file_lock:
                with open(results_file, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(task_out, default=str) + "\n")
        else:
            tenant_id = _get_tenant_id()
            provider = result.get("provider") or "aws"
            for finding in _to_minimal_finding_records(
                scan_id=scan_run_id,
                tenant_id=tenant_id,
                provider=provider,
                result=result,
            ):
                with file_lock:
                    with open(results_file, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(finding, default=str) + "\n")
        
        # Extract and write inventory assets (same logic as account_region_scope)
        service = result.get("service")
        account_from_result = result.get("account") or account_id
        region_from_result = "global"  # Global services
        inventory = result.get("inventory", {})
        
        seen_in_this_result = set()
        tenant_id = _get_tenant_id()
        scan_run_id = os.path.basename(os.path.dirname(results_file))
        
        for discovery_id, items in inventory.items():
            if not isinstance(items, list):
                continue
            
            # Check if this discovery should produce inventory assets (universal heuristic)
            from utils.reporting_manager import is_cspm_inventory_resource
            if not is_cspm_inventory_resource(discovery_id, discovery_config=None):
                continue
            
            parts = discovery_id.split(".")
            if len(parts) >= 2 and parts[0] == "aws":
                service_from_discovery = parts[1]
            else:
                service_from_discovery = service
            
            discovery_service_is_global = is_global_service(service_from_discovery)
            discovery_region = None  # Global services have no region
            
            # Build raw_ref path for global services
            raw_ref_path = os.path.join(os.path.dirname(results_file), "raw", "aws", account_from_result, "global", f"{service_from_discovery}.json")
            
            for item in items:
                if not isinstance(item, dict):
                    continue
                
                try:
                    # Create canonical asset using helper
                    asset = _create_canonical_asset(
                        item, service_from_discovery, discovery_region,
                        account_from_result, tenant_id, scan_run_id,
                        raw_ref_path, discovery_id
                    )
                    
                    if not asset:
                        continue
                    
                    resource_uid = asset.get("resource_uid")
                    if resource_uid in seen_in_this_result:
                        continue
                    seen_in_this_result.add(resource_uid)
                    
                    # Append to inventory file
                    with file_lock:
                        with open(discoveries_file, "a", encoding="utf-8") as fh:
                            fh.write(json.dumps(asset, default=str) + "\n")
                            
                except Exception as e:
                    logger.debug(f"Failed to extract resource identifier for {discovery_id}: {e}")
                    continue
        
        # Count checks
        checks = result.get("checks", []) or []
        total_checks += len(checks)
        passed_checks += sum(1 for c in checks if c.get("result") == "PASS")
        failed_checks += sum(1 for c in checks if c.get("result") == "FAIL")
        
        results.append(result)
    
    # Execute tasks in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                scan_service_in_scope,
                task["account_id"],
                task["region"],
                task["service_name"],
                task["scope"],
                task["session"],
                resource_filter,
            ): task
            for task in tasks
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                # Write result even if empty (no inventory, no checks) - important for tracking
                if result:
                    _write_result(result)
                    
                    # MEMORY OPTIMIZATION: Clear large data structures after writing to disk
                    if '_raw_data' in result:
                        del result['_raw_data']
                    
                    # Replace full inventory with summary counts (inventory already written to disk)
                    inventory = result.get('inventory', {})
                    if inventory:
                        inventory_summary = {}
                        for discovery_id, items in inventory.items():
                            if isinstance(items, list):
                                inventory_summary[discovery_id] = len(items)
                            else:
                                inventory_summary[discovery_id] = 0
                        result['inventory'] = inventory_summary
                        result['_inventory_written'] = True
                else:
                    # Log empty results for debugging
                    task = futures[future]
                    logger.debug(f"Empty result for {task['service_name']} in {account_id}/global")
            except Exception as e:
                task = futures[future]
                logger.error(f"Task failed: {task['service_name']} in {account_id}/global: {e}")
    
    summary = {
        "account_id": account_id,
        "account_name": account_name,
        "region": "global",
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "services_scanned": len(global_services),
        "results_file": results_file,
        "discoveries_file": discoveries_file,
    }
    
    logger.info(f"  [{account_name}/global] Completed: {total_checks} checks ({passed_checks} PASS, {failed_checks} FAIL)")
    
    return (total_checks, passed_checks, failed_checks, summary)


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
