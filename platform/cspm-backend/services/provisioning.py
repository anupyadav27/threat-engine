"""
Tenant provisioning service.

provision_tenant_for_new_user() — canonical entry point for provisioning the
first tenant for a newly registered user (any auth provider: local, Google,
Microsoft, OIDC, SAML).

Design decisions:
  - customer_id is generated here as ``cust_<12-hex-chars>`` and written to
    the user row only if not already set (idempotent).
  - The entire operation is wrapped in ``transaction.atomic()`` so that a
    failed Tenants.create() rolls back the customer_id write (AC7).
  - Celery tasks (onboarding sync + billing trial) are enqueued via
    ``transaction.on_commit`` so they fire only on successful commit (AC9).
  - Returns a plain dict ``{"customer_id", "tenant_id", "tenant_type"}`` so
    downstream callers (invite flow, Celery tasks) never hold a model ref
    across process boundaries (AC8).
"""
import logging
import uuid
from uuid import uuid4

from django.db import transaction

logger = logging.getLogger(__name__)


def provision_tenant_for_new_user(user, tenant_type: str = "cloud") -> dict:
    """Provision a customer_id and initial Tenant for a newly created user.

    Idempotent: if the user already has a customer_id (e.g. invited into an
    existing org before self-provisioning), the existing value is reused and no
    new Tenant is created for that user (returns None for tenant_id).

    Args:
        user: The Django Users instance being provisioned.
        tenant_type: One of ``'cloud'``, ``'vulnerability'``, ``'secops'``.
            Defaults to ``'cloud'``.

    Returns:
        dict with keys:
            customer_id (str): The org-level key written to the user row.
            tenant_id (str):   UUID of the newly created Tenant, or the
                               existing tenant's UUID if user was already a
                               member of a tenant.
            tenant_type (str): The tenant_type value stored on the Tenant row.

    Raises:
        RuntimeError: If the ``org_admin`` role is not seeded in the DB.
    """
    from tenant_management.models import Tenants, TenantUsers
    from user_auth.models import UserAdminScope, UserRoles

    # Early-exit: user already has a tenant — return existing tenant info.
    existing_membership = TenantUsers.objects.filter(user=user).select_related("tenant").first()
    if existing_membership:
        tenant = existing_membership.tenant
        return {
            "customer_id": user.customer_id or str(user.id),
            "tenant_id": str(tenant.id),
            "tenant_type": tenant.tenant_type,
        }

    # Build human-readable company name from email domain.
    domain = user.email.split("@")[-1].split(".")[0].capitalize()
    company_name = f"{domain} (auto)"

    with transaction.atomic():
        # AC2: generate customer_id only if not already set.
        if not user.customer_id:
            user.customer_id = f"cust_{uuid4().hex[:12]}"
            user.save(update_fields=["customer_id"])

        customer_id = user.customer_id
        tenant_id = str(uuid.uuid4())

        org_admin_role = _get_org_admin_role()

        # AC3: tenant.customer_id matches user.customer_id.
        # AC4: tenant.tenant_type matches the parameter.
        tenant = Tenants.objects.create(
            id=tenant_id,
            engine_tenant_id=tenant_id,
            name=company_name,
            status="provisioning",
            tenant_type=tenant_type,
            customer_id=customer_id,
            plan="trial",
            contact_email=user.email,
            created_by=user,
        )

        TenantUsers.objects.create(
            id=str(uuid.uuid4()),
            tenant=tenant,
            user=user,
            role=org_admin_role,
            is_active=True,
        )

        UserRoles.objects.get_or_create(
            user=user,
            role=org_admin_role,
            defaults={"id": str(uuid.uuid4())},
        )

        UserAdminScope.objects.create(
            id=str(uuid.uuid4()),
            user=user,
            role=org_admin_role,
            scope_type="organization",
            scope_id=customer_id,
        )

        # Enqueue async tasks AFTER transaction commits so a rollback cancels
        # both tasks and does not leave the customer_id persisted (AC7/AC9).
        def _enqueue_sync():
            try:
                from user_auth.celery_tasks import sync_tenant_to_onboarding
                sync_tenant_to_onboarding.apply_async(
                    args=[tenant_id, customer_id],
                    queue="tenant-sync",
                )
                logger.info("Enqueued onboarding sync for tenant %s", tenant_id)
            except Exception as exc:
                logger.warning(
                    "Could not enqueue onboarding sync for %s: %s. "
                    "Tenant status remains 'provisioning' — use "
                    "/api/v1/tenants/%s/resync/ to retry.",
                    tenant_id, exc, tenant_id,
                )

            try:
                from user_auth.celery_tasks import provision_billing_trial
                provision_billing_trial.apply_async(
                    args=[tenant_id],
                    queue="billing-provision",
                )
                logger.info("Enqueued billing trial provision for tenant %s", tenant_id)
            except Exception as exc:
                logger.warning(
                    "Could not enqueue billing trial provision for %s: %s. "
                    "Trial may need manual provisioning.",
                    tenant_id, exc,
                )

        transaction.on_commit(_enqueue_sync)

    logger.info(
        "Provisioned tenant '%s' (id=%s, type=%s, customer_id=%s) for %s",
        company_name, tenant_id, tenant_type, customer_id, user.email,
    )

    # AC8: return dict, not a model instance.
    return {
        "customer_id": customer_id,
        "tenant_id": tenant_id,
        "tenant_type": tenant_type,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_org_admin_role():
    """Return the seeded org_admin Role or raise RuntimeError."""
    from user_auth.models import Roles
    try:
        return Roles.objects.get(name="org_admin")
    except Roles.DoesNotExist:
        raise RuntimeError("Role 'org_admin' not found — run migration user_auth.0009 first.")
