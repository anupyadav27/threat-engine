"""
Celery task — weekly credential expiry health-check for all active cloud accounts.

Queries cloud_accounts for accounts expiring within 14 days and sends SES warning
emails.  Also marks accounts past their expiry date as INACTIVE.

Schedule: every Monday at 03:00 UTC (configured in celery_app.py beat_schedule).
"""
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

try:
    from celery import shared_task

    _CELERY_AVAILABLE = True
except ImportError:
    _CELERY_AVAILABLE = False

    def shared_task(f=None, **_kwargs):  # type: ignore[misc]
        """No-op decorator when Celery is not installed."""
        return f if f else lambda fn: fn


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SES helpers
# ---------------------------------------------------------------------------

_ses_client = None


def _get_ses_client():
    """Return a cached SES client for ap-south-1."""
    global _ses_client
    if _ses_client is None:
        _ses_client = boto3.client("ses", region_name=os.environ.get("AWS_REGION", "ap-south-1"))
    return _ses_client


def _send_expiry_warning_email(account: Dict[str, Any]) -> None:
    """Send an SES email warning that a cloud account credential is expiring.

    Args:
        account: Row dict from cloud_accounts containing at minimum
                 account_id, account_name, expires_at, tenant_id.
    """
    from_email = os.environ.get("FROM_EMAIL", "")
    admin_email = os.environ.get("PLATFORM_ADMIN_EMAIL", "")

    if not from_email or not admin_email:
        logger.warning(
            "credential_health_check: FROM_EMAIL or PLATFORM_ADMIN_EMAIL not set; "
            "skipping email for account %s",
            account.get("account_id"),
        )
        return

    account_id = account.get("account_id", "unknown")
    account_name = account.get("account_name") or account_id
    expires_at = account.get("expires_at")

    subject = f"[Onam Security] Credential Expiry Warning: {account_name}"
    body_text = (
        f"This is an automated warning from Onam Security CSPM.\n\n"
        f"Cloud account credentials for '{account_name}' (account_id: {account_id}) "
        f"will expire on {expires_at}.\n\n"
        f"Please renew the credentials before the expiry date to avoid disruption "
        f"to security scanning.\n\n"
        f"Tenant ID: {account.get('tenant_id', 'N/A')}\n"
    )

    try:
        ses = _get_ses_client()
        ses.send_email(
            Source=from_email,
            Destination={"ToAddresses": [admin_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body_text}},
            },
        )
        logger.info(
            "credential_health_check: sent expiry warning email for account %s to %s",
            account_id,
            admin_email,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.error(
            "credential_health_check: failed to send SES email for account %s: %s",
            account_id,
            exc,
        )


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _get_db_connection():
    """Return a psycopg2 connection to the onboarding database.

    Uses DATABASE_URL env var (injected by K8s ConfigMap threat-engine-db-config).
    Falls back to individual host/user/password vars if DATABASE_URL is absent.
    """
    import psycopg2

    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        # Replace default DB name with onboarding DB
        conn = psycopg2.connect(database_url, dbname="threat_engine_onboarding")
    else:
        conn = psycopg2.connect(
            host=os.environ["ONBOARDING_DB_HOST"],
            port=int(os.environ.get("ONBOARDING_DB_PORT", "5432")),
            dbname="threat_engine_onboarding",
            user=os.environ["ONBOARDING_DB_USER"],
            password=os.environ["ONBOARDING_DB_PASSWORD"],
        )
    return conn


def _fetch_expiring_accounts() -> List[Dict[str, Any]]:
    """Return active accounts whose expires_at <= NOW() + INTERVAL '14 days'.

    Excludes accounts already expired (validation_status = 'expired') to avoid
    duplicate notifications once they have been marked INACTIVE.

    Returns:
        List of row dicts with keys: account_id, tenant_id, account_name,
        expires_at, account_status.
    """
    sql = """
        SELECT account_id, tenant_id, account_name, expires_at, account_status
        FROM cloud_accounts
        WHERE expires_at <= NOW() + INTERVAL '14 days'
          AND account_status = 'active'
          AND validation_status != 'expired'
        ORDER BY expires_at ASC
    """
    conn = _get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            cols = [desc[0] for desc in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    finally:
        conn.close()


def _mark_expired_accounts_inactive() -> int:
    """Set account_status = 'INACTIVE' for accounts whose expires_at <= NOW().

    Returns:
        Number of rows updated.
    """
    sql = """
        UPDATE cloud_accounts
        SET account_status = 'INACTIVE',
            updated_at = NOW()
        WHERE expires_at <= NOW()
          AND account_status = 'active'
    """
    conn = _get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            updated = cur.rowcount
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------


@shared_task(
    name="engine_onboarding.tasks.credential_health_check.run_credential_health_check",
    bind=True,
    max_retries=0,
    ignore_result=False,
    soft_time_limit=3600,  # 1 hour — handles large account fleets
)
def run_credential_health_check(self=None) -> Dict[str, Any]:
    """Weekly Celery Beat task — credential expiry check for all active accounts.

    1. Queries cloud_accounts for accounts expiring within 14 days and sends an
       SES warning email for each one.
    2. Marks all accounts whose expires_at has already passed as INACTIVE.

    Returns:
        Summary dict with counts of emails_sent, accounts_marked_inactive,
        errors, and completed_at timestamp.
    """
    logger.info("credential_health_check: starting weekly expiry sweep")

    emails_sent = 0
    email_errors = 0
    accounts_marked_inactive = 0

    # --- Step 1: warn accounts expiring within 14 days --------------------
    try:
        expiring_soon: List[Dict[str, Any]] = _fetch_expiring_accounts()
        logger.info(
            "credential_health_check: found %d accounts expiring within 14 days",
            len(expiring_soon),
        )
        for account in expiring_soon:
            try:
                _send_expiry_warning_email(account)
                emails_sent += 1
            except Exception as exc:
                logger.error(
                    "credential_health_check: error sending warning for account %s: %s",
                    account.get("account_id"),
                    exc,
                )
                email_errors += 1
    except Exception as exc:
        logger.error("credential_health_check: error fetching expiring accounts: %s", exc)
        email_errors += 1

    # --- Step 2: mark expired accounts INACTIVE ---------------------------
    try:
        accounts_marked_inactive = _mark_expired_accounts_inactive()
        logger.info(
            "credential_health_check: marked %d expired accounts as INACTIVE",
            accounts_marked_inactive,
        )
    except Exception as exc:
        logger.error(
            "credential_health_check: error marking expired accounts inactive: %s", exc
        )

    summary: Dict[str, Any] = {
        "emails_sent": emails_sent,
        "email_errors": email_errors,
        "accounts_marked_inactive": accounts_marked_inactive,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info("credential_health_check: done — %s", summary)
    return summary
