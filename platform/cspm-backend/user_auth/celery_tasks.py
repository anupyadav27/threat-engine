"""
Celery tasks for user_auth.

sync_tenant_to_onboarding — async tenant sync with exponential backoff and dead-letter.
provision_billing_trial   — async 14-day Pro trial provisioning after tenant creation.
"""
import logging
import os

import requests as http_requests
from celery import shared_task
from celery.exceptions import MaxRetriesExceededError

logger = logging.getLogger(__name__)

_ONBOARDING_ENGINE_URL = os.getenv(
    "ONBOARDING_ENGINE_URL",
    "http://engine-onboarding.threat-engine-engines.svc.cluster.local/api/v1",
)


def _dead_letter(tenant_id: str) -> None:
    """Mark tenant sync_failed and emit an audit event. Never raises."""
    try:
        from tenant_management.models import Tenants
        Tenants.objects.filter(id=tenant_id).update(status="sync_failed")
    except Exception as exc:
        logger.error("dead_letter: could not set sync_failed on %s: %s", tenant_id, exc)

    try:
        from user_auth.utils.audit_utils import log_auth_event
        log_auth_event("tenant.sync_failed", extra={"tenant_id": tenant_id})
    except Exception as exc:
        logger.error("dead_letter: audit log failed for %s: %s", tenant_id, exc)

    logger.warning("tenant.sync_failed tenant_id=%s", tenant_id)


@shared_task(bind=True, max_retries=5, queue="tenant-sync")
def sync_tenant_to_onboarding(self, tenant_id: str, customer_id: str) -> None:
    """POST to onboarding engine to create matching tenant row.

    Retry schedule (seconds): 1, 2, 4, 8, 16 then dead-letter.
    Payload contains ONLY UUIDs — no email, credentials, or PII.
    """
    url = f"{_ONBOARDING_ENGINE_URL}/tenants"
    payload = {"tenant_id": tenant_id, "customer_id": customer_id}

    try:
        resp = http_requests.post(url, json=payload, timeout=10)

        if resp.status_code in (200, 201):
            from tenant_management.models import Tenants
            Tenants.objects.filter(id=tenant_id).update(status="active")
            logger.info("tenant.sync_ok tenant_id=%s", tenant_id)
            return

        if resp.status_code == 409:
            # Idempotent — tenant already exists in onboarding engine
            from tenant_management.models import Tenants
            Tenants.objects.filter(id=tenant_id).update(status="active")
            logger.info("tenant.sync_idempotent tenant_id=%s", tenant_id)
            return

        if 400 <= resp.status_code < 500:
            # 4xx (not 409): configuration error, do not retry
            logger.error(
                "tenant.sync_4xx tenant_id=%s status=%s body=%.200s",
                tenant_id, resp.status_code, resp.text,
            )
            _dead_letter(tenant_id)
            return

        # 5xx — transient, retry with backoff
        exc = RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)

    except http_requests.RequestException as exc:
        logger.debug("tenant.sync_network_err tenant_id=%s attempt=%s: %s",
                     tenant_id, self.request.retries, exc)
        try:
            raise self.retry(exc=exc, countdown=2 ** self.request.retries)
        except MaxRetriesExceededError:
            _dead_letter(tenant_id)
    except MaxRetriesExceededError:
        _dead_letter(tenant_id)


