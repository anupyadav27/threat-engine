"""Django signals for billing engine integration.

Fires a trial provisioning request to engine-billing whenever a new Tenants
record is created (which represents a new organization/customer workspace).
The request is fire-and-forget: if engine-billing is unreachable the tenant
creation succeeds anyway. A warning is logged so ops can manually provision
or rely on the next billing cron cycle.
"""
import logging
import os

from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)

BILLING_ENGINE_URL = os.environ.get(
    "BILLING_ENGINE_URL", "http://engine-billing:8040"
)


def _connect():
    """Register signal handlers.

    Called by UserAuthConfig.ready() to ensure the signal is connected only
    after all Django apps are fully loaded.
    """
    from tenant_management.models import Tenants  # noqa: F401 — import triggers connect

    @receiver(post_save, sender=Tenants, dispatch_uid="provision_billing_trial")
    def provision_billing_trial(sender, instance, created, **kwargs):
        """On new tenant creation: call billing engine to provision trial.

        Args:
            sender: The Tenants model class.
            instance: The newly created Tenants row.
            created: True only on INSERT (not UPDATE).
            **kwargs: Standard Django signal kwargs.
        """
        if not created:
            return

        # Derive email domain from the tenant's contact_email field.
        email = getattr(instance, "contact_email", "") or ""
        email_domain = email.split("@")[-1] if "@" in email else ""

        try:
            import httpx

            with httpx.Client(timeout=5.0) as client:
                resp = client.post(
                    f"{BILLING_ENGINE_URL}/api/v1/billing/trial/provision",
                    json={
                        "org_id": str(instance.id),
                        "email_domain": email_domain,
                    },
                    headers={"X-Internal-Call": "django-backend"},
                )
                if resp.status_code in (200, 201):
                    logger.info(
                        "Trial provisioned for tenant %s (domain: %s)",
                        instance.id,
                        email_domain,
                    )
                else:
                    logger.warning(
                        "Trial provision returned %s for tenant %s",
                        resp.status_code,
                        instance.id,
                    )
        except Exception as exc:
            logger.warning(
                "engine-billing unreachable — trial not provisioned for tenant %s (%s). "
                "Manual provisioning or next cron cycle required.",
                instance.id,
                exc,
            )
