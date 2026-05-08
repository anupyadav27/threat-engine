"""
Platform Admin — Billing Overview router.

GET /api/v1/padmin/billing
  Returns per-org 30-day average billable resource count and monthly_amount_usd.
  Requires platform:admin permission.

Pricing:
  0-50 billable resources  →  $1,000 flat
  51+                      →  $1,000 + (count - 50) * $20
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg2.extras
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db import get_conn, put_conn

logger = logging.getLogger(__name__)

router = APIRouter(tags=["billing"])


# ── Response models ───────────────────────────────────────────────────────────

class AccountBillable(BaseModel):
    account_id: str
    provider: str
    avg_billable_30d: int


class OrgBillingRow(BaseModel):
    org_id: str
    plan_name: str
    status: str
    accounts: list[AccountBillable]
    total_billable: int
    monthly_amount_usd: int


class PricingConfig(BaseModel):
    flat_fee_usd: int
    flat_cap_resources: int
    per_resource_usd: int


class CsvBillingRow(BaseModel):
    org_id: str
    plan_name: str
    status: str
    account_id: str
    provider: str
    avg_billable_30d: int
    monthly_amount_usd: int


class BillingOverviewResponse(BaseModel):
    orgs: list[OrgBillingRow]
    total_orgs: int
    pricing: PricingConfig
    csv_rows: list[CsvBillingRow]

_FLAT_FEE = 1000
_PER_RESOURCE = 20
_FLAT_CAP = 50


def _calc_amount(billable: int) -> int:
    if billable <= 0:
        return 0
    if billable <= _FLAT_CAP:
        return _FLAT_FEE
    return _FLAT_FEE + (billable - _FLAT_CAP) * _PER_RESOURCE


# 30-day average per org/account/provider from snapshots
_SNAPSHOT_SQL = """
SELECT
    s.org_id,
    s.account_id,
    s.provider,
    ROUND(AVG(s.billable_count))::int AS avg_billable
FROM billing_resource_snapshots s
WHERE s.snapshot_date >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY s.org_id, s.account_id, s.provider
ORDER BY s.org_id, s.provider, s.account_id
"""

# Org names and plan from org_subscriptions
_ORGS_SQL = """
SELECT
    os.org_id,
    sp.plan_name,
    os.status
FROM org_subscriptions os
LEFT JOIN subscription_plans sp ON sp.plan_id = os.plan_id
"""


@router.get("/billing", response_model=BillingOverviewResponse)
def get_billing_overview() -> BillingOverviewResponse:
    """Return 30-day average billable resource counts and monthly amounts per org.

    Returns:
        Dict with orgs list. Each org has total billable count, monthly_amount_usd,
        and per-account breakdown.
    """
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(_SNAPSHOT_SQL)
            snapshot_rows = cur.fetchall()

            cur.execute(_ORGS_SQL)
            org_rows = {r["org_id"]: r for r in cur.fetchall()}
    except Exception as exc:
        logger.error("billing overview query failed: %s", exc)
        raise HTTPException(status_code=500, detail="Billing query failed")
    finally:
        put_conn(conn)

    # Group snapshot rows by org_id
    orgs: dict[str, dict[str, Any]] = {}
    for row in snapshot_rows:
        oid = row["org_id"]
        if oid not in orgs:
            meta = org_rows.get(oid, {})
            orgs[oid] = {
                "org_id": oid,
                "plan_name": meta.get("plan_name", "unknown"),
                "status": meta.get("status", "unknown"),
                "accounts": [],
                "total_billable": 0,
            }
        avg = row["avg_billable"]
        orgs[oid]["accounts"].append({
            "account_id": row["account_id"],
            "provider": row["provider"],
            "avg_billable_30d": avg,
        })
        orgs[oid]["total_billable"] += avg

    # Compute monthly amount at org level
    result = []
    for org in orgs.values():
        total = org["total_billable"]
        org["monthly_amount_usd"] = _calc_amount(total)
        result.append(org)

    result.sort(key=lambda o: o["monthly_amount_usd"], reverse=True)

    org_rows_typed = [OrgBillingRow(**o) for o in result]

    csv_rows = [
        CsvBillingRow(
            org_id=org.org_id,
            plan_name=org.plan_name,
            status=org.status,
            account_id=acct.account_id,
            provider=acct.provider,
            avg_billable_30d=acct.avg_billable_30d,
            monthly_amount_usd=org.monthly_amount_usd,
        )
        for org in org_rows_typed
        for acct in org.accounts
    ]

    return BillingOverviewResponse(
        orgs=org_rows_typed,
        total_orgs=len(org_rows_typed),
        pricing=PricingConfig(
            flat_fee_usd=_FLAT_FEE,
            flat_cap_resources=_FLAT_CAP,
            per_resource_usd=_PER_RESOURCE,
        ),
        csv_rows=csv_rows,
    )
