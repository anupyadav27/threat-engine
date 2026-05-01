"""
Auto-provision a tenant for new users who sign in via SSO/OAuth
and don't yet belong to any tenant. Also syncs the tenant to the
onboarding engine so both DBs share the same UUID.
"""
import logging
import os
import time
import uuid
from typing import Optional

import requests as http_requests
from django.db import transaction

logger = logging.getLogger(__name__)

_ONBOARDING_ENGINE_URL = os.getenv(
    "ONBOARDING_ENGINE_URL",
    "http://engine-onboarding.threat-engine-engines.svc.cluster.local/api/v1",
)


def get_or_create_admin_role():
    """Return (or create) the built-in 'Tenant Admin' role."""
    from user_auth.models import Roles
    role, _ = Roles.objects.get_or_create(
        name="Tenant Admin",
        defaults={
            "id": str(uuid.uuid4()),
            "description": "Full administrative access within a tenant",
            "tenant_scoped": True,
        },
    )
    return role


def provision_first_tenant(user, company_name: str = "") -> Optional["Tenants"]:
    """Create a tenant for a user who has none yet, then sync to onboarding engine.

    Called on email signup and Google/SSO first login.
    Uses transaction.atomic() so a failed onboarding sync rolls back the
    Django records — no orphaned platform tenants.

    Args:
        user: Users instance for the new account owner.
        company_name: Display name; derived from email domain if blank.

    Returns:
        The created Tenants instance, or None if user already has a tenant.
    """
    from tenant_management.models import Tenants, TenantUsers

    if TenantUsers.objects.filter(user=user).exists():
        return None

    if not company_name:
        domain = user.email.split("@")[-1].split(".")[0].capitalize()
        company_name = f"{domain} (auto)"

    tenant_id = str(uuid.uuid4())

    with transaction.atomic():
        tenant = Tenants.objects.create(
            id=tenant_id,
            name=company_name,
            status="active",
            plan="trial",
            contact_email=user.email,
            created_by=user,
        )

        role = get_or_create_admin_role()
        TenantUsers.objects.create(
            id=str(uuid.uuid4()),
            tenant=tenant,
            user=user,
            role=role,
            is_active=True,
        )

        _sync_tenant_to_onboarding(tenant_id, company_name, str(user.id))

    logger.info(f"Provisioned tenant '{tenant.name}' (id={tenant_id}) for {user.email}")
    return tenant


def _sync_tenant_to_onboarding(
    tenant_id: str,
    tenant_name: str,
    customer_id: str,
    max_retries: int = 3,
) -> None:
    """POST to onboarding engine to create matching tenant row.

    Raises RuntimeError on all retries exhausted — caller's transaction.atomic()
    will roll back the Django tenant and TenantUsers records.

    Args:
        tenant_id: UUID already created in platform DB.
        tenant_name: Display name for the tenant.
        customer_id: platform Users.id of the tenant creator.
        max_retries: Number of attempts before raising.
    """
    url = f"{_ONBOARDING_ENGINE_URL}/tenants"
    payload = {
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "customer_id": customer_id,
    }
    for attempt in range(max_retries):
        try:
            resp = http_requests.post(url, json=payload, timeout=10)
            if resp.status_code in (200, 201):
                logger.info(f"Onboarding sync OK for tenant {tenant_id}")
                return
            if resp.status_code == 409:
                logger.info(f"Tenant {tenant_id} already exists in onboarding — skipping sync")
                return
            logger.warning(
                f"Onboarding sync attempt {attempt + 1} returned {resp.status_code}: {resp.text[:200]}"
            )
        except http_requests.RequestException as exc:
            logger.warning(f"Onboarding sync attempt {attempt + 1} failed: {exc}")

        if attempt < max_retries - 1:
            time.sleep(2 ** attempt)

    raise RuntimeError(
        f"Failed to sync tenant {tenant_id} to onboarding engine after {max_retries} attempts"
    )
