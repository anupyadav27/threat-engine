"""
Daily billing snapshot job.

Runs once per day at 01:00 UTC. Queries inventory_findings cross-tenant,
counts billable resources per (org_id, account_id, provider), and upserts
one row per group into billing_resource_snapshots in the billing DB.

Billable resource types are defined by is_billable=TRUE on resource_inventory_identifier.
"""

from __future__ import annotations

import logging
import os
from datetime import date

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

# ── Inventory DB (read-only query) ───────────────────────────────────────────
_INVENTORY_DSN = dict(
    host=os.environ.get("INVENTORY_DB_HOST", ""),
    dbname=os.environ.get("INVENTORY_DB_NAME", "threat_engine_inventory"),
    user=os.environ.get("INVENTORY_DB_USER", "postgres"),
    password=os.environ.get("INVENTORY_DB_PASSWORD", ""),
    sslmode="require",
    connect_timeout=15,
)

# ── Billing DB (write) ────────────────────────────────────────────────────────
_BILLING_DSN = dict(
    host=os.environ.get("BILLING_DB_HOST", ""),
    port=int(os.environ.get("BILLING_DB_PORT", "5432")),
    dbname=os.environ.get("BILLING_DB_NAME", "threat_engine_billing"),
    user=os.environ.get("BILLING_APP_DB_USER", "billing_app"),
    password=os.environ.get("BILLING_APP_DB_PASSWORD", ""),
    sslmode="require",
    connect_timeout=15,
)

_SNAPSHOT_SQL = """
SELECT
    f.tenant_id            AS org_id,
    f.account_id,
    f.provider,
    COUNT(DISTINCT f.resource_uid) AS billable_count
FROM inventory_findings f
WHERE f.resource_type = ANY(%s)
  AND f.provider = ANY(%s)
  AND f.tenant_id IS NOT NULL
  AND f.tenant_id <> ''
GROUP BY f.tenant_id, f.account_id, f.provider
"""

_UPSERT_SQL = """
INSERT INTO billing_resource_snapshots
    (snapshot_date, org_id, account_id, provider, billable_count)
VALUES %s
ON CONFLICT (snapshot_date, org_id, account_id, provider)
DO UPDATE SET billable_count = EXCLUDED.billable_count
"""


def _fetch_billable_types() -> tuple[list[str], list[str]]:
    """Fetch billable resource types and their CSPs from billing DB.

    Returns:
        Tuple of (resource_types list, csp list) for use in inventory query.
    """
    conn = psycopg2.connect(**_BILLING_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT csp, resource_type FROM billing_billable_types")
            rows = cur.fetchall()
    finally:
        conn.close()
    resource_types = list({r[1] for r in rows})
    csps = list({r[0] for r in rows})
    return resource_types, csps


def run_billing_snapshot() -> None:
    """Query inventory DB and write today's billable resource counts to billing DB."""
    today = date.today()
    logger.info("billing_snapshot: starting for date=%s", today)

    try:
        resource_types, csps = _fetch_billable_types()
    except Exception as exc:
        logger.error("billing_snapshot: cannot fetch billable types: %s", exc)
        return

    if not resource_types:
        logger.warning("billing_snapshot: no billable types configured — skipping")
        return

    try:
        inv_conn = psycopg2.connect(**_INVENTORY_DSN)
    except psycopg2.OperationalError as exc:
        logger.error("billing_snapshot: cannot connect to inventory DB: %s", exc)
        return

    try:
        with inv_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(_SNAPSHOT_SQL, (resource_types, csps))
            rows = cur.fetchall()
    except Exception as exc:
        logger.error("billing_snapshot: inventory query failed: %s", exc)
        inv_conn.close()
        return
    finally:
        inv_conn.close()

    if not rows:
        logger.info("billing_snapshot: no billable resources found — skipping write")
        return

    values = [
        (today, r["org_id"], r["account_id"], r["provider"], r["billable_count"])
        for r in rows
    ]

    try:
        bill_conn = psycopg2.connect(**_BILLING_DSN)
    except psycopg2.OperationalError as exc:
        logger.error("billing_snapshot: cannot connect to billing DB: %s", exc)
        return

    try:
        with bill_conn.cursor() as cur:
            psycopg2.extras.execute_values(cur, _UPSERT_SQL, values)
        bill_conn.commit()
        logger.info(
            "billing_snapshot: upserted %d rows for %s", len(values), today
        )
    except Exception as exc:
        bill_conn.rollback()
        logger.error("billing_snapshot: billing DB write failed: %s", exc)
    finally:
        bill_conn.close()
