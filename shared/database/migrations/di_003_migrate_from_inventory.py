"""DI-S4-01 — Migrate enriched data from inventory_findings → asset_inventory.

Preferred migration source: inventory_findings has fully normalised, enriched data
(properties = emitted_fields equivalent, configuration = raw API response).

Only rows with canonical UIDs are migrated.  Synthetic UIDs (region:name format)
are dropped — they cannot be matched to real cloud resources and must not enter
asset_inventory.

Idempotent: ON CONFLICT (resource_uid, discovery_id, scan_run_id, tenant_id, provider) DO NOTHING
means running this script twice is safe and the second run inserts 0 rows.

Non-destructive: inventory_findings is never modified.

Run via kubectl exec on engine-di pod:
  kubectl cp shared/database/migrations/di_003_migrate_from_inventory.py \\
    threat-engine-engines/<engine-di-pod>:/tmp/di_003_migrate_from_inventory.py
  kubectl exec -n threat-engine-engines <engine-di-pod> -- \\
    python3 /tmp/di_003_migrate_from_inventory.py
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import execute_values, RealDictCursor


def _is_valid_uuid(val: Any) -> bool:
    try:
        uuid.UUID(str(val))
        return True
    except (ValueError, AttributeError):
        return False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("di_003_migrate_inventory")

BATCH_SIZE = 500

CANONICAL_PREFIXES = (
    "arn:",           # AWS
    "ocid1.",         # OCI
    "/subscriptions/", # Azure
    "crn:",           # IBM
    "projects/",      # GCP
)


def is_canonical(uid: str) -> bool:
    """Return True only for real cloud resource identifiers."""
    if not uid:
        return False
    return any(uid.startswith(p) for p in CANONICAL_PREFIXES)


def _extract_service_from_discovery_ids(source_ids: Any) -> str:
    """Extract service name from source_discovery_ids JSONB array.

    source_discovery_ids is a JSONB array like:
      ["aws.s3.list_buckets", "aws.s3.get_bucket_acl"]
    Service = second segment of the first entry.
    """
    if not source_ids:
        return "unknown"
    entries = source_ids if isinstance(source_ids, list) else []
    if not entries:
        return "unknown"
    parts = str(entries[0]).split(".")
    return parts[1] if len(parts) >= 2 else "unknown"


def _extract_discovery_id(source_ids: Any) -> Optional[str]:
    """Return the first discovery_id from source_discovery_ids, or None."""
    if not source_ids:
        return None
    entries = source_ids if isinstance(source_ids, list) else []
    return str(entries[0]) if entries else None


def _as_jsonb(value: Any) -> str:
    """Ensure value is serialized JSON string for psycopg2 execute_values."""
    if value is None:
        return "{}"
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, str):
        # Already serialised — validate it's valid JSON, return as-is
        try:
            json.loads(value)
            return value
        except (json.JSONDecodeError, TypeError):
            return "{}"
    return "{}"


def _connect_inventory() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["INVENTORY_DB_HOST"],
        port=int(os.getenv("INVENTORY_DB_PORT", "5432")),
        database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.environ["INVENTORY_DB_USER"],
        password=os.environ["INVENTORY_DB_PASSWORD"],
    )


def _connect_di() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["DI_DB_HOST"],
        port=int(os.getenv("DI_DB_PORT", "5432")),
        database=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.environ["DI_DB_USER"],
        password=os.environ["DI_DB_PASSWORD"],
    )


def _build_insert_row(row: Dict[str, Any]) -> Optional[Tuple]:
    """Map an inventory_findings row to an asset_inventory insert tuple.

    Returns None if the resource_uid is not canonical (will be counted as skipped).
    """
    uid: str = row.get("resource_uid") or ""
    if not is_canonical(uid):
        return None

    # Skip rows with legacy non-UUID scan_run_ids (pre-UUID era records)
    if not _is_valid_uuid(row.get("scan_run_id")):
        return None

    source_ids = row.get("source_discovery_ids")
    service = _extract_service_from_discovery_ids(source_ids)
    discovery_id = _extract_discovery_id(source_ids)

    # inventory_findings: properties = enriched metadata → emitted_fields
    #                     configuration = raw API response → raw_response
    emitted = _as_jsonb(row.get("properties"))
    raw = _as_jsonb(row.get("configuration"))

    return (
        row["scan_run_id"],           # scan_run_id
        row["tenant_id"],             # tenant_id
        row.get("account_id") or "",  # account_id
        row["provider"],              # provider  (partition key — must be in ON CONFLICT)
        row.get("region") or "global", # region
        row.get("credential_ref"),    # credential_ref
        row.get("credential_type"),   # credential_type
        uid,                          # resource_uid
        row.get("resource_type") or "unknown", # resource_type
        row.get("name"),              # resource_name
        service,                      # service
        discovery_id,                 # discovery_id
        1,                            # phase=1 (enriched historical)
        emitted,                      # emitted_fields
        raw,                          # raw_response
        "informational",              # severity
        "active",                     # status
        row.get("first_seen_at"),                                        # first_seen_at
        row.get("last_seen_at") or row.get("first_seen_at"),            # last_seen_at (never null)
    )


INSERT_SQL = """
    INSERT INTO asset_inventory (
        scan_run_id, tenant_id, account_id, provider, region,
        credential_ref, credential_type,
        resource_uid, resource_type, resource_name, service, discovery_id,
        phase, emitted_fields, raw_response,
        severity, status, first_seen_at, last_seen_at
    ) VALUES %s
    ON CONFLICT (resource_uid, discovery_id, scan_run_id, tenant_id, provider) DO NOTHING
"""


def run() -> None:
    """Execute the inventory → asset_inventory migration."""
    inv_conn = _connect_inventory()
    di_conn = _connect_di()

    stats: Dict[str, int] = {"migrated": 0, "skipped_synthetic": 0, "errors": 0}
    offset = 0

    try:
        # Migrate only the latest scan per asset (scan_run_id = latest_scan_run_id)
        # to avoid bloating asset_inventory with stale historical scans.
        FETCH_SQL = """
            SELECT
                scan_run_id, tenant_id, account_id, provider, region,
                credential_ref, credential_type,
                resource_uid, resource_type, name,
                properties, configuration,
                source_discovery_ids,
                first_seen_at, last_seen_at
            FROM inventory_findings
            WHERE scan_run_id = latest_scan_run_id
            ORDER BY tenant_id, resource_uid
            LIMIT %s OFFSET %s
        """

        while True:
            with inv_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(FETCH_SQL, (BATCH_SIZE, offset))
                rows = cur.fetchall()

            if not rows:
                break

            batch: List[Tuple] = []
            for row in rows:
                mapped = _build_insert_row(dict(row))
                if mapped is None:
                    stats["skipped_synthetic"] += 1
                else:
                    batch.append(mapped)

            if batch:
                try:
                    with di_conn.cursor() as cur:
                        execute_values(cur, INSERT_SQL, batch)
                    di_conn.commit()
                    stats["migrated"] += len(batch)
                except Exception as exc:
                    di_conn.rollback()
                    logger.error(
                        "Batch insert failed at offset=%d: %s", offset, exc
                    )
                    stats["errors"] += len(batch)

            offset += BATCH_SIZE
            logger.info(
                "Progress offset=%d  migrated=%d  skipped=%d  errors=%d",
                offset,
                stats["migrated"],
                stats["skipped_synthetic"],
                stats["errors"],
            )

    finally:
        inv_conn.close()
        di_conn.close()

    if stats["errors"] > 0:
        logger.error("MIGRATION FINISHED WITH ERRORS: %s", stats)
    else:
        logger.info("MIGRATION COMPLETE: %s", stats)


if __name__ == "__main__":
    run()
