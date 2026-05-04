"""
Celery task — weekly credential health-check for all active cloud accounts.

For each account with stored credentials, re-runs the provider validator
and updates credential_validation_status + last_credential_check_at on the
cloud_accounts row.  Never blocks scan pipelines; runs in its own worker.
"""
import logging
from datetime import datetime, timezone
from typing import Dict, Any

try:
    from engine_onboarding.celery_app import app
    from celery import shared_task
    _CELERY_AVAILABLE = True
except ImportError:
    _CELERY_AVAILABLE = False
    app = None
    def shared_task(f=None, **_kwargs):  # type: ignore[misc]
        """No-op decorator when Celery is not installed."""
        return f if f else lambda fn: fn

from engine_onboarding.database.cloud_accounts_operations import (
    list_cloud_accounts,
    update_cloud_account,
)

logger = logging.getLogger(__name__)


def _validate_one(account: Dict[str, Any]) -> Dict[str, Any]:
    """Re-validate a single account's credentials. Returns result dict."""
    account_id      = account["account_id"]
    provider        = account.get("provider", "")
    credential_type = account.get("credential_type", "")

    if not account.get("credential_ref"):
        return {"account_id": account_id, "status": "skipped", "reason": "no credential_ref"}

    try:
        from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
        creds = secrets_manager_storage.retrieve(account_id)
    except Exception as exc:
        logger.warning("health_check: could not retrieve creds for %s: %s", account_id, exc)
        return {"account_id": account_id, "status": "skipped", "reason": str(exc)}

    try:
        from engine_onboarding.api.cloud_accounts import _get_validator
        import asyncio
        validator = _get_validator(provider, credential_type)
        result = asyncio.run(validator.validate(creds))
        new_status = "valid" if result.success else "invalid"
        update_cloud_account(account_id, {
            "credential_validation_status":  new_status,
            "credential_validation_message": result.message,
            "last_credential_check_at":      datetime.now(timezone.utc),
        })
        return {"account_id": account_id, "status": new_status}
    except Exception as exc:
        logger.error("health_check: validation error for %s: %s", account_id, exc)
        update_cloud_account(account_id, {
            "last_credential_check_at": datetime.now(timezone.utc),
        })
        return {"account_id": account_id, "status": "error", "reason": str(exc)}


@shared_task(
    name="engine_onboarding.tasks.credential_health_check.run_credential_health_check",
    bind=True,
    max_retries=0,
    ignore_result=False,
    soft_time_limit=3600,   # 1 hour — handles large account fleets
)
def run_credential_health_check(self=None) -> Dict[str, Any]:
    """
    Weekly Celery Beat task — re-validates credentials for all active accounts.

    Iterates all active cloud accounts in pages of 100, re-runs the provider
    validator, and stamps last_credential_check_at.

    Returns a summary dict (stored in Celery result backend for observability).
    """
    logger.info("credential_health_check: starting weekly sweep")
    total = valid = invalid = skipped = errors = 0
    offset = 0

    while True:
        accounts = list_cloud_accounts(
            filters={"account_status": "active"},
            limit=100,
            offset=offset,
        )
        if not accounts:
            break

        for acct in accounts:
            total += 1
            try:
                res = _validate_one(acct)
                status = res.get("status", "error")
                if status == "valid":
                    valid += 1
                elif status == "invalid":
                    invalid += 1
                elif status == "skipped":
                    skipped += 1
                else:
                    errors += 1
            except Exception as exc:
                logger.error("health_check: unhandled error for %s: %s", acct.get("account_id"), exc)
                errors += 1

        offset += 100

    summary = {
        "total": total, "valid": valid, "invalid": invalid,
        "skipped": skipped, "errors": errors,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info("credential_health_check: done — %s", summary)
    return summary
