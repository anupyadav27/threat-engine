"""
Companion script for 0013_billing_grandfathering.sql.

Queries the Django platform DB for all org IDs, then provisions grandfathered
Pro-tier subscriptions for any org that has no billing row yet.

Run ONCE after applying the SQL migration:
    python3 shared/database/migrations/0013_billing_grandfathering.py

Environment variables required:
    BILLING_DB_HOST      — hostname of the RDS instance (billing DB)
    BILLING_DB_USER      — Postgres user with INSERT on org_subscriptions
    BILLING_DB_PASSWORD  — password for BILLING_DB_USER

    PLATFORM_DB_HOST     — hostname of the RDS instance (platform/Django DB)
    PLATFORM_DB_USER     — Postgres user with SELECT on the orgs table
    PLATFORM_DB_PASSWORD — password for PLATFORM_DB_USER

Optional:
    BILLING_DB_NAME      — defaults to 'threat_engine_billing'
    PLATFORM_DB_NAME     — defaults to 'cspm_platform'
    BILLING_DB_PORT      — defaults to 5432
    PLATFORM_DB_PORT     — defaults to 5432

Cross-DB note:
    The billing database and the Django platform database reside on the same
    RDS instance but are separate Postgres databases.  A single SQL JOIN across
    the two databases is not possible in Postgres; this script handles it by
    opening two separate connections and performing the reconciliation in Python.

Idempotency:
    INSERT … ON CONFLICT (org_id) DO NOTHING — re-running this script never
    creates duplicate rows or overwrites an existing subscription.
    billing_audit_log rows are guarded by the same NOT EXISTS check in the SQL
    companion migration; the Python step does NOT write additional audit rows
    for newly-inserted orgs to avoid double-counting — the SQL step already
    wrote rows for existing subscriptions and the Python step writes its own
    audit entries only for new rows it inserts.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg2

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DB connection parameters resolved from environment variables.
# ---------------------------------------------------------------------------

_BILLING_DB: dict = {
    "host": os.environ.get("BILLING_DB_HOST", ""),
    "port": int(os.environ.get("BILLING_DB_PORT", "5432")),
    "dbname": os.environ.get("BILLING_DB_NAME", "threat_engine_billing"),
    "user": os.environ.get("BILLING_DB_USER", ""),
    "password": os.environ.get("BILLING_DB_PASSWORD", ""),
    "connect_timeout": 10,
}

_PLATFORM_DB: dict = {
    "host": os.environ.get("PLATFORM_DB_HOST", ""),
    "port": int(os.environ.get("PLATFORM_DB_PORT", "5432")),
    "dbname": os.environ.get("PLATFORM_DB_NAME", "cspm_platform"),
    "user": os.environ.get("PLATFORM_DB_USER", ""),
    "password": os.environ.get("PLATFORM_DB_PASSWORD", ""),
    "connect_timeout": 10,
}

# ---------------------------------------------------------------------------
# Migration marker — written to override_by_user_id for idempotency queries.
# ---------------------------------------------------------------------------
_MIGRATION_ACTOR: str = "system_migration_0013"


def _validate_env() -> None:
    """Raise SystemExit if any required environment variable is missing.

    Args:
        None

    Raises:
        SystemExit: If a required environment variable is not set.
    """
    required = [
        "BILLING_DB_HOST",
        "BILLING_DB_USER",
        "BILLING_DB_PASSWORD",
        "PLATFORM_DB_HOST",
        "PLATFORM_DB_USER",
        "PLATFORM_DB_PASSWORD",
    ]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        logger.error(
            "Missing required environment variables: %s", ", ".join(missing)
        )
        sys.exit(1)


def _get_pro_plan_id(bcur: "psycopg2.extensions.cursor") -> Optional[str]:
    """Return the UUID of the 'pro' subscription plan from the billing DB.

    Args:
        bcur: Active psycopg2 cursor on the billing database.

    Returns:
        plan_id string, or None if the plan row does not exist.
    """
    bcur.execute(
        "SELECT plan_id FROM subscription_plans WHERE plan_name = 'pro' AND is_active = true",
    )
    row = bcur.fetchone()
    return str(row[0]) if row else None


def _get_all_platform_org_ids(
    pcur: "psycopg2.extensions.cursor",
) -> list[str]:
    """Return every org ID from the Django platform DB.

    The Django identity backend uses the table `user_auth_organization`.
    If the table name differs in your deployment, adjust the query below.

    Args:
        pcur: Active psycopg2 cursor on the platform/Django database.

    Returns:
        List of org ID strings.
    """
    # Try the most common Django model table names in order.
    candidate_queries = [
        "SELECT id FROM user_auth_organization",
        "SELECT id FROM organizations",
        "SELECT id FROM tenants_tenant",
    ]
    for query in candidate_queries:
        try:
            pcur.execute(query)
            return [str(r[0]) for r in pcur.fetchall()]
        except psycopg2.errors.UndefinedTable:
            pcur.connection.rollback()
            continue

    logger.error(
        "Could not find the organisation table in the platform DB. "
        "Tried: %s",
        ", ".join(candidate_queries),
    )
    sys.exit(1)


def _get_existing_billing_org_ids(
    bcur: "psycopg2.extensions.cursor",
) -> set[str]:
    """Return the set of org_ids already present in org_subscriptions.

    Args:
        bcur: Active psycopg2 cursor on the billing database.

    Returns:
        Set of org_id strings.
    """
    bcur.execute("SELECT org_id FROM org_subscriptions")
    return {r[0] for r in bcur.fetchall()}


def run() -> None:
    """Main entry point: connect to both DBs and insert missing orgs.

    Returns:
        None. Prints a summary to stdout.

    Raises:
        SystemExit: If environment variables are missing or DB connections fail.
    """
    _validate_env()

    logger.info("Connecting to platform DB: %s/%s", _PLATFORM_DB["host"], _PLATFORM_DB["dbname"])
    try:
        platform_conn = psycopg2.connect(**_PLATFORM_DB)
    except psycopg2.OperationalError as exc:
        logger.error("Cannot connect to platform DB: %s", exc)
        sys.exit(1)

    logger.info("Connecting to billing DB: %s/%s", _BILLING_DB["host"], _BILLING_DB["dbname"])
    try:
        billing_conn = psycopg2.connect(**_BILLING_DB)
    except psycopg2.OperationalError as exc:
        logger.error("Cannot connect to billing DB: %s", exc)
        sys.exit(1)

    try:
        pcur = platform_conn.cursor()
        bcur = billing_conn.cursor()

        # Fetch the Pro plan UUID from the billing DB
        pro_plan_id = _get_pro_plan_id(bcur)
        if not pro_plan_id:
            logger.error("Pro plan not found in subscription_plans — ensure 0012 was applied")
            sys.exit(1)

        logger.info("Pro plan_id: %s", pro_plan_id)

        # Collect org IDs from both DBs
        all_org_ids = _get_all_platform_org_ids(pcur)
        existing_billing_ids = _get_existing_billing_org_ids(bcur)

        logger.info(
            "Platform orgs: %d | Already in billing DB: %d",
            len(all_org_ids),
            len(existing_billing_ids),
        )

        # Determine orgs that need a new subscription row
        missing_org_ids = [oid for oid in all_org_ids if oid not in existing_billing_ids]
        logger.info("Orgs missing from billing DB (to be grandfathered): %d", len(missing_org_ids))

        if not missing_org_ids:
            logger.info("Nothing to do — all platform orgs already have subscription rows.")
            print("Grandfathered 0 new orgs (all orgs already had subscription rows).")
            return

        grandfathered_until: datetime = datetime.now(timezone.utc) + timedelta(days=90)
        inserted = 0

        for org_id in missing_org_ids:
            try:
                bcur.execute(
                    """
                    INSERT INTO org_subscriptions
                        (org_id, plan_id, status, is_overridden, override_reason,
                         override_by_user_id, grandfathered_until)
                    VALUES (%s, %s, 'active', true,
                            'Grandfathered — existing user, 90-day Pro equivalent',
                            %s, %s)
                    ON CONFLICT (org_id) DO NOTHING
                    """,
                    (org_id, pro_plan_id, _MIGRATION_ACTOR, grandfathered_until),
                )

                if bcur.rowcount > 0:
                    # Write billing_audit_log entry for this new row
                    bcur.execute(
                        """
                        INSERT INTO billing_audit_log
                            (org_id, event_type, actor_id, actor_role,
                             change_summary, new_state)
                        VALUES (%s, 'grandfathering.applied', %s, 'system',
                                'Existing org grandfathered to Pro plan for 90 days from billing launch',
                                %s)
                        """,
                        (
                            org_id,
                            _MIGRATION_ACTOR,
                            psycopg2.extras.Json({
                                "plan": "pro",
                                "grandfathered_until": grandfathered_until.isoformat(),
                                "is_overridden": True,
                            }),
                        ),
                    )
                    inserted += 1

            except psycopg2.Error as exc:
                logger.warning("Failed to insert org_id=%s: %s — skipping", org_id, exc)
                billing_conn.rollback()
                continue

        billing_conn.commit()
        logger.info("Grandfathering complete: inserted %d new rows.", inserted)
        print(f"Grandfathered {inserted} new orgs.")

    finally:
        try:
            platform_conn.close()
        except Exception:
            pass
        try:
            billing_conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    # psycopg2.extras required for Json() adapter
    import psycopg2.extras  # noqa: F401 — imported here to keep the top-level clean

    run()
