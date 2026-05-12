"""
Celery tasks for user_auth.

sync_tenant_to_onboarding — async tenant sync with fixed-interval retry and dead-letter.
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
    "http://engine-onboarding.threat-engine-engines.svc.cluster.local:8008",
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


@shared_task(bind=True, name="tenant.sync_to_onboarding", max_retries=3, queue="tenant-sync")
def sync_tenant_to_onboarding(self, tenant_id: str, customer_id: str) -> None:
    """POST to onboarding engine internal sync endpoint to upsert tenant row.

    Retries up to 3 times with a fixed 30-second countdown between attempts.
    On final failure, calls dead_letter to mark the tenant sync_failed.
    Payload contains ONLY UUIDs — no email, credentials, or PII.

    Args:
        tenant_id: UUID string of the tenant to sync.
        customer_id: Customer-level identifier for the owning org.
    """
    url = f"{_ONBOARDING_ENGINE_URL}/internal/tenants/sync"
    secret = os.getenv("X_INTERNAL_SECRET", "")
    payload = {"tenant_id": tenant_id, "customer_id": customer_id}

    try:
        resp = http_requests.post(
            url,
            json=payload,
            headers={"X-Internal-Secret": secret},
            timeout=10,
        )

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

        # 5xx — transient, retry with fixed 30-second countdown
        exc = RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            raise self.retry(exc=exc, countdown=30)
        except MaxRetriesExceededError:
            logger.error(
                "tenant.sync_max_retries tenant_id=%s: exhausted 3 attempts, dead-lettering",
                tenant_id,
            )
            _dead_letter(tenant_id)

    except http_requests.RequestException as exc:
        logger.debug(
            "tenant.sync_network_err tenant_id=%s attempt=%s: %s",
            tenant_id, self.request.retries, exc,
        )
        try:
            raise self.retry(exc=exc, countdown=30)
        except MaxRetriesExceededError:
            logger.error(
                "tenant.sync_max_retries tenant_id=%s: network error exhausted retries",
                tenant_id,
            )
            _dead_letter(tenant_id)


_BILLING_ENGINE_URL = os.getenv(
    "BILLING_ENGINE_URL",
    "http://engine-billing.threat-engine-engines.svc.cluster.local:8009",
)


@shared_task(bind=True, name="billing.provision_trial", max_retries=3, queue="billing-provision")
def provision_billing_trial(self, tenant_id: str) -> None:
    """Provision a 14-day Pro trial subscription for a newly created tenant.

    Fetches the tenant's contact_email from the DB inside the task body — PII
    is never stored in Celery task args (SEC-01).

    Retry schedule: up to 3 retries with a 60-second fixed countdown.
    A 4xx response is not retried (configuration error — admin must fix and
    use the billing engine's admin endpoint to re-provision manually).

    Args:
        tenant_id: UUID string of the tenant to provision a trial for.
    """
    billing_secret = os.getenv("BILLING_INTERNAL_SECRET", "")

    try:
        from tenant_management.models import Tenants
        tenant = Tenants.objects.get(id=tenant_id)
    except Exception as exc:
        # Tenant not found — nothing to provision
        logger.error("billing.trial_provision_no_tenant tenant_id=%s: %s", tenant_id, exc)
        return

    contact_email: str = tenant.contact_email or ""
    email_domain: str = contact_email.split("@")[-1] if "@" in contact_email else ""
    url = f"{_BILLING_ENGINE_URL}/internal/billing/trial"

    try:
        resp = http_requests.post(
            url,
            json={
                "org_id": tenant_id,
                "admin_email": contact_email,
                "email_domain": email_domain,
                "plan": "trial",
            },
            headers={"X-Internal-Secret": billing_secret},
            timeout=15,
        )

        if resp.status_code in (200, 201):
            logger.info("billing.trial_provision_ok tenant_id=%s", tenant_id)
            return

        if resp.status_code == 409:
            logger.info("billing.trial_already_exists tenant_id=%s", tenant_id)
            return

        if 400 <= resp.status_code < 500:
            logger.error(
                "billing.trial_provision_4xx tenant_id=%s status=%s body=%.200s",
                tenant_id, resp.status_code, resp.text,
            )
            return  # Do not retry 4xx

        # 5xx — transient, retry
        exc = RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            raise self.retry(exc=exc, countdown=60)
        except MaxRetriesExceededError:
            logger.critical(
                "billing.trial_provision_failed tenant_id=%s: exhausted retries",
                tenant_id,
            )

    except http_requests.RequestException as exc:
        logger.debug(
            "billing.trial_provision_network_err tenant_id=%s: %s",
            tenant_id, exc,
        )
        try:
            raise self.retry(exc=exc, countdown=60)
        except MaxRetriesExceededError:
            logger.critical(
                "billing.trial_provision_failed tenant_id=%s: network error exhausted retries",
                tenant_id,
            )
