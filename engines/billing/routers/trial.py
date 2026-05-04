"""
Billing Engine — Trial provisioning endpoint.

POST /api/v1/billing/trial/provision

Called by the Django backend on org creation. No end-user auth is required
(internal call). Domain-abuse check: if org_email_domain OR admin_email_domain
already has a prior subscription with an active/trialing status, provisions
Free tier instead of trial.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Response

from db import get_conn, put_conn
from models import TrialProvisionRequest, TrialProvisionResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["trial"])


def _extract_domain(email: str) -> Optional[str]:
    """Extract the domain portion from an email address.

    Args:
        email: Full email address string, e.g. 'user@example.com'.

    Returns:
        Lowercased domain string (e.g. 'example.com'), or None if the email
        does not contain exactly one '@' character or is blank.
    """
    email = (email or "").strip().lower()
    if "@" not in email:
        return None
    parts = email.split("@", 1)
    domain = parts[1].strip()
    return domain if domain else None


@router.post("/trial/provision", status_code=201)
async def provision_trial(body: TrialProvisionRequest, response: Response) -> Dict[str, Any]:
    """Provision a 14-day Pro trial for a new organisation.

    Domain-abuse guard (two checks):
    1. org_email_domain: if the org domain slug already appears in
       org_subscriptions (any existing org), provision Free tier instead.
    2. admin_email_domain: if the domain extracted from ``admin_email`` already
       appears in org_subscriptions on a row with a non-free tier OR a
       trialing/active status, provision Free tier instead and return
       ``reason="domain_already_trialed"``.

    If the org already has a subscription row (org_id conflict), the existing
    row is left unchanged and ``provisioned=false`` is returned.

    Args:
        body: TrialProvisionRequest with org_id, optional email_domain, and
              optional admin_email.

    Returns:
        TrialProvisionResponse dict. HTTP 201 on fresh trial, HTTP 200 on
        domain-abuse or existing subscription.
    """
    org_id = body.org_id
    email_domain = (body.email_domain or "").strip().lower()

    # Derive admin_email_domain from the admin_email field (added in BILL-08).
    admin_email_domain: Optional[str] = _extract_domain(body.admin_email or "")

    conn = get_conn()
    try:
        cur = conn.cursor()

        # ------------------------------------------------------------------
        # Domain-abuse check 1: org_email_domain
        # ------------------------------------------------------------------
        domain_count = 0
        if email_domain:
            cur.execute(
                "SELECT COUNT(*) FROM org_subscriptions WHERE org_email_domain = %s",
                (email_domain,),
            )
            domain_count = cur.fetchone()[0]

        # ------------------------------------------------------------------
        # Domain-abuse check 2: admin_email_domain
        # Check if any existing row for this admin email domain has a non-free
        # tier OR a trialing/active status — catching both paid and trial abuse.
        # ------------------------------------------------------------------
        admin_domain_abused = False
        if admin_email_domain and domain_count == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM org_subscriptions os
                JOIN subscription_plans sp ON sp.plan_id = os.plan_id
                WHERE os.admin_email_domain = %s
                  AND (
                      sp.plan_name != 'free'
                      OR os.status IN ('trialing', 'active')
                  )
                """,
                (admin_email_domain,),
            )
            admin_domain_count = cur.fetchone()[0]
            if admin_domain_count > 0:
                admin_domain_abused = True

        if domain_count > 0 or admin_domain_abused:
            # Provision Free tier instead of trial
            cur.execute(
                "SELECT plan_id FROM subscription_plans WHERE plan_name = 'free' AND is_active = true",
            )
            free_row = cur.fetchone()
            if not free_row:
                raise HTTPException(status_code=500, detail="Free plan not found in DB")
            plan_id = free_row[0]
            status = "active"
            trial_start = None
            trial_end = None
            provisioned = False
            reason = "domain_already_trialed"
        else:
            # Full 14-day Pro trial
            cur.execute(
                "SELECT plan_id FROM subscription_plans WHERE plan_name = 'pro' AND is_active = true",
            )
            pro_row = cur.fetchone()
            if not pro_row:
                raise HTTPException(status_code=500, detail="Pro plan not found in DB")
            plan_id = pro_row[0]
            status = "trialing"
            trial_start = datetime.now(timezone.utc)
            trial_end = trial_start + timedelta(days=14)
            provisioned = True
            reason = None

        cur.execute(
            """
            INSERT INTO org_subscriptions
                (org_id, plan_id, status, trial_start_at, trial_end_at,
                 org_email_domain, admin_email_domain)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (org_id) DO NOTHING
            """,
            (
                org_id,
                plan_id,
                status,
                trial_start,
                trial_end,
                email_domain or None,
                admin_email_domain or None,
            ),
        )

        inserted = cur.rowcount
        conn.commit()
        cur.close()

        if inserted == 0:
            # org_id already existed — leave existing row untouched
            response.status_code = 200
            return TrialProvisionResponse(
                provisioned=False,
                reason="org_already_subscribed",
                status="existing",
            ).model_dump()

        if not provisioned:
            # Domain-abuse path: Free tier provisioned instead of trial
            response.status_code = 200

        return TrialProvisionResponse(
            provisioned=provisioned,
            reason=reason,
            status=status,
        ).model_dump()

    except HTTPException:
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("provision_trial failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to provision trial")
    finally:
        put_conn(conn)
