"""DI-S4-01 — Supplement migration from discovery_findings → asset_inventory.

Secondary migration source: discovery_findings has raw enumeration data for resources
that may not have been normalised into inventory_findings yet.  Runs AFTER
di_003_migrate_from_inventory.py so inventory-enriched rows take precedence
(ON CONFLICT DO NOTHING skips discoveries rows where an inventory row already exists).

Only rows with canonical UIDs are migrated.  Synthetic UIDs (region:name format)
are dropped and counted as skipped.

Idempotent: ON CONFLICT (resource_uid, scan_run_id, tenant_id, provider) DO NOTHING.
Non-destructive: discovery_findings is never modified.

Run via kubectl exec on engine-di pod AFTER di_003_migrate_from_inventory.py:
  kubectl cp shared/database/migrations/di_004_migrate_from_discoveries.py \\
    threat-engine-engines/<engine-di-pod>:/tmp/di_004_migrate_from_discoveries.py
  kubectl exec -n threat-engine-engines <engine-di-pod> -- \\
    python3 /tmp/di_004_migrate_from_discoveries.py
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
logger = logging.getLogger("di_004_migrate_discoveries")

BATCH_SIZE = 500

CANONICAL_PREFIXES = (
    "arn:",            # AWS
    "ocid1.",          # OCI
    "/subscriptions/", # Azure
    "crn:",            # IBM
    "projects/",       # GCP
)


def is_canonical(uid: str) -> bool:
    """Return True only for real cloud resource identifiers."""
    if not uid:
        return False
    return any(uid.startswith(p) for p in CANONICAL_PREFIXES)


def _as_jsonb(value: Any) -> str:
    """Ensure value is serialized JSON string for psycopg2 execute_values."""
    if value is None:
        return "{}"
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, str):
        try:
            json.loads(value)
            return value
        except (json.JSONDecodeError, TypeError):
            return "{}"
    return "{}"


def _connect_discoveries() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ["DISCOVERIES_DB_HOST"],
        port=int(os.getenv("DISCOVERIES_DB_PORT", "5432")),
        database=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.environ["DISCOVERIES_DB_USER"],
        password=os.environ["DISCOVERIES_DB_PASSWORD"],
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
    """Map a discovery_findings row to an asset_inventory insert tuple.

    Returns None if resource_uid is synthetic.
    """
    uid: str = row.get("resource_uid") or ""
    if not is_canonical(uid):
        return None

    if not _is_valid_uuid(row.get("scan_run_id")):
        return None

    return (
        row["scan_run_id"],                    # scan_run_id
        row["tenant_id"],                      # tenant_id
        row.get("account_id") or "",           # account_id
        row["provider"],                       # provider (partition key)
        row.get("region") or "global",         # region
        row.get("credential_ref"),             # credential_ref
        row.get("credential_type"),            # credential_type
        uid,                                   # resource_uid
        row.get("resource_type") or "unknown", # resource_type
        row.get("resource_name"),              # resource_name
        row.get("service") or "unknown",       # service
        row.get("discovery_id"),               # discovery_id
        1,                                     # phase=1 (historical data treated as enriched)
        _as_jsonb(row.get("emitted_fields")),  # emitted_fields
        _as_jsonb(row.get("raw_response")),    # raw_response
        "informational",                       # severity
        row.get("status") or "active",         # status
        row.get("first_seen_at"),              # first_seen_at
        row.get("last_seen_at") or row.get("first_seen_at"),  # last_seen_at (never null)
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
    """Execute the discovery_findings → asset_inventory supplemental migration."""
    disc_conn = _connect_discoveries()
    di_conn = _connect_di()

    stats: Dict[str, int] = {"migrated": 0, "skipped_synthetic": 0, "errors": 0}
    offset = 0

    try:
        # Migrate the most-recent row per (resource_uid, tenant_id, provider) to
        # avoid duplicating stale scan_run_ids into asset_inventory.  Use a
        # DISTINCT ON subquery ordered by last_seen_at DESC so each resource
        # carries its latest scan context.
        FETCH_SQL = """
            SELECT DISTINCT ON (resource_uid, tenant_id, provider)
                scan_run_id, tenant_id, account_id, provider, region,
                credential_ref, credential_type,
                resource_uid, NULL AS resource_name, resource_type, service, discovery_id,
                emitted_fields, raw_response, status,
                first_seen_at, last_seen_at
            FROM discovery_findings
            ORDER BY resource_uid, tenant_id, provider, last_seen_at DESC NULLS LAST
            LIMIT %s OFFSET %s
        """

        while True:
            with disc_conn.cursor(cursor_factory=RealDictCursor) as cur:
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
        disc_conn.close()
        di_conn.close()

    if stats["errors"] > 0:
        logger.error("MIGRATION FINISHED WITH ERRORS: %s", stats)
    else:
        logger.info("MIGRATION COMPLETE: %s", stats)


if __name__ == "__main__":
    run()
