"""
Phase 2 — Asset Inventory Writer

Writes Phase 0/1 rows to asset_inventory with ON CONFLICT upsert.
Writes di_scan_errors for any enumeration failures.
Computes config_hash for drift detection.

Batch size: 500 rows per transaction.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import date, datetime
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras

from .sensitive_scrubber import scrub_row

logger = logging.getLogger("di.phase2.writer")

_BATCH_SIZE = 500

# AWS/cloud-managed resources that AWS creates automatically in every account/region.
# These are not customer-managed assets and add noise to the inventory.
# Key: discovery_id  Value: set of resource_name values to exclude.
_MANAGED_EXCLUSIONS: dict = {
    "aws.sagemaker.list_resource_catalogs": {"DefaultFeatureGroupCatalog"},
    "aws.sagemaker.list_hubs": {"SageMakerPublicHub"},
    "aws.bedrock.list_inference_profiles": None,  # None = exclude ALL items from this discovery
    "aws.bedrock.list_prompt_routers": None,       # AWS-managed Bedrock routers
    "aws.ecs.describe_capacity_providers": {"FARGATE", "FARGATE_SPOT"},
    "aws.cloudtrail.list_channels": None,          # AWS-managed service channels
    # Amazon Connect Customer Profiles — default objects pre-created in every region
    "aws.customer-profiles.list_object_type_names": {
        "Campaign", "Servicenow", "Salesforce", "CTR", "Shopify", "Zendesk",
        "Marketo", "S3", "Segment", "SNOWFLAKE",
    },
    # Route53 Resolver — system-managed rule association in every region
    "aws.route53resolver.list_resolver_rule_associations": {"System Rule Association"},
}


# resource_type-level exclusions for cases where discovery_id may be NULL.
# None = exclude all resources of this type.
_MANAGED_RESOURCE_TYPES: dict = {
    "bedrock_inference_profile": None,  # all AWS-managed Bedrock profiles
    "bedrock_prompt_router": None,      # all AWS-managed Bedrock routers
    "sagemaker_resource_catalog": {"DefaultFeatureGroupCatalog"},
    "sagemaker_hub": {"SageMakerPublicHub"},
    "ecs_capacity_provider": {"FARGATE", "FARGATE_SPOT"},
    "cloudtrail_channel": None,
}


def _is_managed_exclusion(row: Dict[str, Any]) -> bool:
    """Return True if this asset is an AWS-managed resource that should be excluded."""
    did = row.get("discovery_id") or ""
    if did in _MANAGED_EXCLUSIONS:
        names = _MANAGED_EXCLUSIONS[did]
        if names is None:
            return True
        if (row.get("resource_name") or "") in names:
            return True

    rt = row.get("resource_type") or ""
    if rt in _MANAGED_RESOURCE_TYPES:
        names = _MANAGED_RESOURCE_TYPES[rt]
        if names is None:
            return True
        if (row.get("resource_name") or "") in names:
            return True

    return False


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _safe_dumps(obj: Any) -> str:
    return json.dumps(obj, default=_json_default)


def _get_di_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("DI_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DI_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.getenv("DI_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("DI_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or os.getenv("DISCOVERIES_DB_PASSWORD", "")
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def _compute_hash(raw_response: Any) -> str:
    """Compute MD5 of scrubbed raw_response for drift detection."""
    try:
        canonical = json.dumps(raw_response, sort_keys=True, default=str)
        return hashlib.md5(canonical.encode()).hexdigest()
    except Exception:
        return ""


def write_assets(rows: List[Dict[str, Any]]) -> int:
    """Write asset rows to asset_inventory in batches of 500.

    Each row MUST have sensitive fields scrubbed before calling this function.
    Uses ON CONFLICT (resource_uid, scan_run_id, tenant_id) to upsert.
    Sets drift_detected = (old config_hash != new config_hash).

    Returns:
        Number of rows written (inserts + updates).
    """
    if not rows:
        return 0

    before = len(rows)
    rows = [r for r in rows if not _is_managed_exclusion(r)]
    skipped = before - len(rows)
    if skipped:
        logger.info("Excluded %d AWS-managed resources from inventory write", skipped)

    if not rows:
        return 0

    conn = _get_di_conn()
    total_written = 0
    try:
        for batch_start in range(0, len(rows), _BATCH_SIZE):
            batch = rows[batch_start: batch_start + _BATCH_SIZE]
            _write_batch(conn, batch)
            total_written += len(batch)
            logger.debug(
                "Wrote batch: offset=%d count=%d", batch_start, len(batch)
            )
        logger.info("Phase 2 write complete: total_rows=%d", total_written)
    finally:
        conn.close()

    return total_written


def _write_batch(
    conn: psycopg2.extensions.connection,
    batch: List[Dict[str, Any]],
) -> None:
    """Write one batch to asset_inventory with upsert semantics."""
    # Deduplicate by conflict key — same resource scanned in multiple regions for global services
    # ON CONFLICT DO UPDATE cannot affect the same row twice in one statement
    seen_keys: set = set()
    deduped_batch = []
    for row in batch:
        key = (row["resource_uid"], row.get("discovery_id"), row["scan_run_id"],
               row["tenant_id"], row["provider"])
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_batch.append(row)
    batch = deduped_batch

    records = []
    for row in batch:
        # Scrub is idempotent — safe to call again as a safety net
        row = scrub_row(row)
        raw_resp = row.get("raw_response") or {}
        config_hash = _compute_hash(raw_resp)

        records.append((
            row["scan_run_id"],
            row["tenant_id"],
            row["account_id"],
            row["provider"],
            row.get("region", "global"),
            row.get("credential_ref"),
            row.get("credential_type"),
            row["resource_uid"],
            row["resource_type"],
            row.get("resource_name"),
            row["service"],
            row.get("discovery_id"),
            row.get("phase", 0),
            _safe_dumps(row.get("emitted_fields") or {}),
            _safe_dumps(raw_resp),
            config_hash,
            row.get("severity", "informational"),
            row.get("status", "active"),
        ))

    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """
            INSERT INTO asset_inventory (
                scan_run_id, tenant_id, account_id, provider, region,
                credential_ref, credential_type,
                resource_uid, resource_type, resource_name,
                service, discovery_id, phase,
                emitted_fields, raw_response, config_hash,
                severity, status,
                first_seen_at, last_seen_at
            )
            VALUES %s
            ON CONFLICT (resource_uid, discovery_id, scan_run_id, tenant_id, provider) DO UPDATE
                SET last_seen_at          = NOW(),
                    phase                 = GREATEST(
                                              asset_inventory.phase,
                                              EXCLUDED.phase
                                            ),
                    emitted_fields        = EXCLUDED.emitted_fields,
                    raw_response          = EXCLUDED.raw_response,
                    previous_config_hash  = asset_inventory.config_hash,
                    config_hash           = EXCLUDED.config_hash,
                    drift_detected        = (
                                              asset_inventory.config_hash IS NOT NULL
                                              AND asset_inventory.config_hash != EXCLUDED.config_hash
                                            ),
                    resource_name         = COALESCE(
                                              EXCLUDED.resource_name,
                                              asset_inventory.resource_name
                                            ),
                    status                = EXCLUDED.status
            """,
            records,
            template=(
                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
                " %s::jsonb, %s::jsonb, %s, %s, %s, NOW(), NOW())"
            ),
        )
    conn.commit()


def write_errors(errors: List[Dict[str, Any]]) -> int:
    """Write enumeration errors to di_scan_errors.

    Returns:
        Number of error rows written.
    """
    if not errors:
        return 0

    conn = _get_di_conn()
    try:
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO di_scan_errors (
                    scan_run_id, tenant_id, account_id, provider,
                    service, region, resource_type,
                    error_type, error_message, raw_item_keys
                ) VALUES %s
                """,
                [
                    (
                        e["scan_run_id"],
                        e["tenant_id"],
                        e.get("account_id"),
                        e.get("provider"),
                        e.get("service"),
                        e.get("region"),
                        e.get("resource_type"),
                        e["error_type"],
                        e.get("error_message", "")[:2000],
                        e.get("raw_item_keys"),
                    )
                    for e in errors
                ],
            )
        conn.commit()
        logger.info("Wrote %d scan errors to di_scan_errors", len(errors))
        return len(errors)
    finally:
        conn.close()


def update_scan_status(
    scan_run_id: str,
    tenant_id: str,
    status: str,
    phase: int = 0,
    resources_enumerated: int = 0,
    resources_enriched: int = 0,
    resources_written: int = 0,
    relationships_written: int = 0,
    error_count: int = 0,
) -> None:
    """Upsert scan progress to di_scan_status."""
    conn = _get_di_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO di_scan_status (
                    scan_run_id, tenant_id, status, phase,
                    resources_enumerated, resources_enriched,
                    resources_written, relationships_written, error_count,
                    completed_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                    CASE WHEN %s IN ('completed', 'failed') THEN NOW() ELSE NULL END,
                    NOW()
                )
                ON CONFLICT (scan_run_id) DO UPDATE
                    SET status               = EXCLUDED.status,
                        phase                = EXCLUDED.phase,
                        resources_enumerated = EXCLUDED.resources_enumerated,
                        resources_enriched   = EXCLUDED.resources_enriched,
                        resources_written    = EXCLUDED.resources_written,
                        relationships_written = EXCLUDED.relationships_written,
                        error_count          = EXCLUDED.error_count,
                        completed_at         = CASE
                            WHEN EXCLUDED.status IN ('completed', 'failed') THEN NOW()
                            ELSE di_scan_status.completed_at
                        END,
                        updated_at           = NOW()
                """,
                (
                    scan_run_id, tenant_id, status, phase,
                    resources_enumerated, resources_enriched,
                    resources_written, relationships_written, error_count,
                    status,
                ),
            )
        conn.commit()
    finally:
        conn.close()
