"""
Phase 0 — Enumerator (all CSPs)

Runs root_ops for each service via the existing CSP scanner classes.
Builds canonical UIDs from emitted_fields using uid_builder.
Skips rows where UID cannot be built — logs to di_scan_errors.

Scanner reuse pattern:
  - Imports scanner classes from providers.* (copied from engines/discoveries/providers/)
  - Calls scanner.authenticate() once per account
  - Calls scanner.scan_service(service, region, config) per service×region pair
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from .identifier_loader import load_identifiers
from .uid_builder import build_uid, ResourceIdMissingError

logger = logging.getLogger("di.phase0.enumerator")

# ── Scanner dispatch table (same classes as engines/discoveries/run_scan.py) ──
def _get_scanner_class(provider: str):
    """Import and return the scanner class for a given provider."""
    provider = provider.lower()
    if provider == "aws":
        from providers.aws.scanner.service_scanner import AWSDiscoveryScanner
        return AWSDiscoveryScanner
    elif provider == "azure":
        from providers.azure.scanner.service_scanner import AzureDiscoveryScanner
        return AzureDiscoveryScanner
    elif provider == "gcp":
        from providers.gcp.scanner.service_scanner import GCPDiscoveryScanner
        return GCPDiscoveryScanner
    elif provider == "oci":
        from providers.oci.scanner.service_scanner import OCIDiscoveryScanner
        return OCIDiscoveryScanner
    elif provider == "ibm":
        from providers.ibm.scanner.service_scanner import IBMDiscoveryScanner
        return IBMDiscoveryScanner
    elif provider == "alicloud":
        from providers.alicloud.scanner.service_scanner import AliCloudDiscoveryScanner
        return AliCloudDiscoveryScanner
    elif provider in ("k8s", "kubernetes"):
        from providers.kubernetes.scanner.service_scanner import K8sDiscoveryScanner
        return K8sDiscoveryScanner
    else:
        raise ValueError(f"Unsupported provider: {provider}")


class Phase0Result:
    """Holds Phase 0 enumeration output."""

    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []          # rows ready for Phase 2 write
        self.errors: List[Dict[str, Any]] = []         # rows for di_scan_errors
        self.scanner: Any = None                        # authenticated scanner (for Phase 1)
        self.account_id: str = ""


async def run_phase0(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    credentials: Dict[str, Any],
    include_regions: Optional[List[str]] = None,
    exclude_regions: Optional[List[str]] = None,
    include_services: Optional[List[str]] = None,
    exclude_services: Optional[List[str]] = None,
    # legacy param kept for callers that haven't migrated yet
    regions: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
) -> Phase0Result:
    """Run Phase 0 enumeration for one cloud account.

    Args:
        scan_run_id: Pipeline scan run UUID.
        tenant_id: Tenant identifier (from AuthContext).
        account_id: Cloud account/subscription/project ID.
        provider: Cloud provider name (aws, azure, gcp, oci, ibm, alicloud, k8s).
        credentials: Resolved credential dict (from SecretsManagerStorage).
        include_regions: Explicit allowlist of regions; discovers all if None.
        exclude_regions: Regions to skip even when included/discovered.
        include_services: Service allowlist; scans all if None.
        exclude_services: Services to skip even when in the allowlist.
        regions, services: Legacy aliases for include_regions / include_services.

    Returns:
        Phase0Result with rows (ready for Phase 1/2) and errors.
    """
    # Resolve legacy aliases so existing callers still work
    if include_regions is None and regions is not None:
        include_regions = regions
    if include_services is None and services is not None:
        include_services = services
    result = Phase0Result()

    logger.info(
        "Phase 0 start: provider=%s account=%s scan_run_id=%s",
        provider, account_id, scan_run_id,
    )

    # ── Load identifier table ─────────────────────────────────────────────────
    identifiers = load_identifiers(provider)
    if not identifiers:
        logger.warning(
            "No identifiers found for provider=%s — skipping Phase 0", provider
        )
        return result

    # ── Authenticate ──────────────────────────────────────────────────────────
    scanner_class = _get_scanner_class(provider)
    scanner = scanner_class(credentials=credentials, provider=provider)
    scanner.authenticate()
    result.scanner = scanner
    result.account_id = getattr(scanner, "account_id", None) or account_id

    logger.info(
        "Authenticated to provider=%s account=%s",
        provider, result.account_id,
    )

    # ── Discover regions ──────────────────────────────────────────────────────
    if include_regions is None:
        if hasattr(scanner, "list_available_regions"):
            include_regions = await scanner.list_available_regions()
        else:
            include_regions = []

    # Apply region exclusion
    exclude_regions_set = set(exclude_regions) if exclude_regions else set()
    effective_regions = [r for r in include_regions if r not in exclude_regions_set]

    logger.info(
        "Phase 0 scanning %d regions for provider=%s (include=%d exclude=%d)",
        len(effective_regions), provider,
        len(include_regions), len(exclude_regions_set),
    )

    # ── Enumerate services × regions (parallel) ──────────────────────────────
    global_workers   = int(os.getenv("MAX_GLOBAL_WORKERS",   "10"))
    regional_workers = int(os.getenv("MAX_REGIONAL_WORKERS", "30"))
    global_sem   = asyncio.Semaphore(global_workers)
    regional_sem = asyncio.Semaphore(regional_workers)

    service_sems: Dict[str, asyncio.Semaphore] = {}
    services_seen: Dict[str, bool] = {}

    # Build task list (deduplicated by discovery_id:region)
    include_services_set = set(include_services) if include_services else None
    exclude_services_set = set(exclude_services) if exclude_services else set()
    scan_tasks = []
    for identifier in identifiers.values():
        if not identifier.get("root_op"):
            continue
        svc = identifier.get("service", "")
        if include_services_set and svc not in include_services_set:
            continue
        if svc in exclude_services_set:
            continue
        scan_regions = _get_scan_regions(provider, svc, effective_regions)
        for region in scan_regions:
            key = f"{identifier['discovery_id']}:{region}"
            if key in services_seen:
                continue
            services_seen[key] = True
            scan_tasks.append((identifier, region))
            # Register per-service semaphore if DB specifies a cap
            svc = identifier["service"]
            cap = identifier.get("max_workers", 0)
            if cap and cap > 0 and svc not in service_sems:
                service_sems[svc] = asyncio.Semaphore(int(cap))

    global_count   = sum(1 for _, r in scan_tasks if r == "global")
    regional_count = len(scan_tasks) - global_count
    logger.info(
        "Phase 0 dispatch: %d tasks for provider=%s (global=%d workers=%d, regional=%d workers=%d)",
        len(scan_tasks), provider, global_count, global_workers, regional_count, regional_workers,
    )

    def _pick_semaphore(identifier: Dict[str, Any], region: str) -> asyncio.Semaphore:
        svc = identifier["service"]
        if svc in service_sems:
            return service_sems[svc]
        return global_sem if region == "global" else regional_sem

    async def _scan_task(identifier: Dict[str, Any], region: str) -> Tuple[List, List]:
        """Run one (identifier, region) scan under the appropriate semaphore."""
        service = identifier["service"]
        resource_type = identifier["resource_type"]
        discovery_id = identifier["discovery_id"]
        enrich_ops = identifier.get("enrich_ops", [])

        async with _pick_semaphore(identifier, region):
            try:
                items = await _scan_one(
                    scanner=scanner,
                    service=service,
                    region=region,
                    root_op=identifier["root_op"],
                    enrich_ops=enrich_ops,
                    provider=provider,
                )
            except Exception as e:
                logger.error(
                    "Scan failed: provider=%s service=%s region=%s: %s",
                    provider, service, region, e,
                )
                return [], [{
                    "scan_run_id": scan_run_id,
                    "tenant_id": tenant_id,
                    "account_id": result.account_id,
                    "provider": provider,
                    "service": service,
                    "region": region,
                    "resource_type": resource_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e)[:2000],
                    "raw_item_keys": None,
                }]

        context = {
            "csp": provider,
            "region": region,
            "account_id": result.account_id,
            "partition": "aws" if provider == "aws" else provider,
        }
        rows: List[Dict] = []
        errors: List[Dict] = []

        for item in items:
            if item.get("_discovery_id") and item["_discovery_id"] != discovery_id:
                continue

            emitted = item if isinstance(item, dict) else {"value": item}
            try:
                uid = build_uid(
                    uid_template=identifier.get("uid_template"),
                    uid_source=identifier.get("uid_source", "heuristic"),
                    item=item,
                    context=context,
                    identifier=identifier,
                )
            except ResourceIdMissingError as e:
                errors.append({
                    "scan_run_id": scan_run_id,
                    "tenant_id": tenant_id,
                    "account_id": result.account_id,
                    "provider": provider,
                    "service": service,
                    "region": region,
                    "resource_type": resource_type,
                    "error_type": "ResourceIdMissingError",
                    "error_message": e.reason[:2000],
                    "raw_item_keys": e.item_keys,
                })
                continue

            resource_name = _extract_name(emitted, provider)
            rows.append({
                "scan_run_id": scan_run_id,
                "tenant_id": tenant_id,
                "account_id": result.account_id,
                "provider": provider,
                "region": region,
                "credential_ref": credentials.get("credential_ref") or credentials.get("role_arn"),
                "credential_type": credentials.get("credential_type"),
                "resource_uid": uid,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "service": service,
                "discovery_id": discovery_id,
                "phase": 1,
                "emitted_fields": emitted,
                "raw_response": emitted,
            })

        return rows, errors

    # ── Gather all tasks in parallel ──────────────────────────────────────────
    task_results = await asyncio.gather(
        *[_scan_task(ident, rgn) for ident, rgn in scan_tasks],
        return_exceptions=True,
    )

    for task_result in task_results:
        if isinstance(task_result, Exception):
            logger.error("Task raised exception: %s", task_result)
            continue
        task_rows, task_errors = task_result
        result.rows.extend(task_rows)
        result.errors.extend(task_errors)

    logger.info(
        "Phase 0 complete: provider=%s rows=%d errors=%d",
        provider, len(result.rows), len(result.errors),
    )
    return result


async def _scan_one(
    scanner: Any,
    service: str,
    region: str,
    root_op: Dict[str, Any],
    enrich_ops: List[Dict[str, Any]],
    provider: str,
) -> List[Dict[str, Any]]:
    """Call scanner.scan_service() for one root op + its enrich ops in one region.

    Passes root_op and enrich_ops together so the scanner runs enumeration
    and per-resource enrichment in a single pass. Items are returned with
    enriched data already merged in by the scanner's for_each logic.
    """
    if not hasattr(scanner, "scan_service"):
        logger.debug("Scanner has no scan_service method for provider=%s", provider)
        return []

    config = {"discovery": [root_op] + enrich_ops}
    try:
        result = await scanner.scan_service(
            service=service,
            region=region,
            config=config,
            skip_dependents=False,
        )
        # Normalize: AWS/GCP/OCI return (items, metadata); Azure returns plain List
        if isinstance(result, tuple):
            items = result[0] if result else []
        else:
            items = result or []
        return items
    except Exception:
        raise


def _get_scan_regions(provider: str, service: str, regions: List[str]) -> List[str]:
    """Return the effective region list for a service.

    Global services (IAM, S3 global list, etc.) are scanned once with 'global'.
    K8s is always 'global'.
    """
    _GLOBAL_SERVICES = {
        # Only services where boto3 resolves to a single global endpoint regardless of region_name.
        # S3/route53/wafv2/shield/sts are NOT here — passing region="global" to boto3 for these
        # causes EndpointConnectionError (e.g. sts.global.amazonaws.com) during cred resolution.
        # Those services scan per-region; S3 list_buckets returns all buckets in every region,
        # so ON CONFLICT (resource_uid, discovery_id, scan_run_id, tenant_id, provider) deduplicates.
        "aws": {"iam", "organizations", "cloudfront", "globalaccelerator"},
        "gcp": set(),
        "azure": {"activedirectory"},
        "oci": set(),
        "ibm": set(),
        "alicloud": {"ram"},
        "k8s": {"*"},
    }

    if provider == "k8s":
        return ["global"]

    global_svcs = _GLOBAL_SERVICES.get(provider, set())
    if service in global_svcs or "*" in global_svcs:
        return ["global"]

    return regions


def _extract_name(item: Dict[str, Any], provider: str) -> Optional[str]:
    """Extract a human-readable resource name from emitted_fields."""
    candidates = [
        "resource_name", "Name", "name", "FunctionName", "DBInstanceIdentifier",
        "BucketName", "TableName", "ClusterName", "DomainName", "TopicName",
        "QueueName", "StreamName", "RoleName", "UserName", "PolicyName",
        "displayName", "title",
    ]
    for key in candidates:
        val = item.get(key)
        if val and isinstance(val, str):
            return val[:512]
    return None
