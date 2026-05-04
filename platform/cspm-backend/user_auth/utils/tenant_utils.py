"""
Tenant provisioning utilities.

provision_tenant_for_new_user() — creates the first tenant for a new org founder.
  Sets user.customer_id = str(user.id) as the permanent org key, creates the Tenant,
  TenantUsers (org_admin), and UserAdminScope (organization scope), then dispatches
  the Celery sync task AFTER the transaction commits (Auth-A3).

accept_invite_membership() — wires TenantUsers + UserRoles for an invite acceptor.
"""
import logging
import uuid

from django.db import transaction

logger = logging.getLogger(__name__)


def _get_org_admin_role():
    from user_auth.models import Roles
    try:
        return Roles.objects.get(name="org_admin")
    except Roles.DoesNotExist:
        raise RuntimeError("Role 'org_admin' not found — run migration user_auth.0009 first.")


def _get_viewer_role():
    from user_auth.models import Roles
    try:
        return Roles.objects.get(name="viewer")
    except Roles.DoesNotExist:
        raise RuntimeError("Role 'viewer' not found — run migration user_auth.0009 first.")


def accept_invite_membership(user, invite) -> None:
    """Create TenantUsers + UserRoles for an accepted invite and mark it used.

    Cross-org invites (invite.tenant.customer_id != user.customer_id) are
    accepted but capped to the viewer role to prevent privilege escalation
    across org boundaries.

    Idempotent — safe to call even if membership already exists.
    """
    from tenant_management.models import TenantUsers
    from user_auth.models import UserRoles

    role = invite.role or _get_viewer_role()

    # Cross-org invite: cap to viewer regardless of the assigned role
    user_customer_id = getattr(user, "customer_id", None) or str(user.id)
    tenant_customer_id = getattr(invite.tenant, "customer_id", None)
    if tenant_customer_id and tenant_customer_id != user_customer_id:
        logger.info(
            "Cross-org invite accepted for %s — capping role to viewer "
            "(tenant customer_id=%s, user customer_id=%s)",
            user.email, tenant_customer_id, user_customer_id,
        )
        role = _get_viewer_role()

    TenantUsers.objects.get_or_create(
        user=user,
        tenant=invite.tenant,
        defaults={"id": str(uuid.uuid4()), "role": role, "is_active": True},
    )

    UserRoles.objects.get_or_create(
        user=user,
        role=role,
        defaults={"id": str(uuid.uuid4())},
    )

    invite.used = True
    invite.save(update_fields=["used"])


def provision_tenant_for_new_user(user, company_name: str = ""):
    """Create the first tenant for a new org founder.

    Sets customer_id = str(user.id) as the immutable org key. Creates:
      - Tenants row (status='provisioning', customer_id=str(user.id))
      - TenantUsers (org_admin role)
      - UserAdminScope (scope_type='organization', scope_id=str(user.id))
      - UserRoles (global org_admin assignment)

    After the transaction commits, enqueues sync_tenant_to_onboarding via Celery
    (Auth-A3). The transaction.on_commit callback fires only if the transaction
    succeeds — a rollback cancels the enqueue.

    Returns the created Tenants instance, or None if user already has a tenant.
    """
    from tenant_management.models import Tenants, TenantUsers
    from user_auth.models import UserAdminScope, UserRoles

    if TenantUsers.objects.filter(user=user).exists():
        return None

    if not company_name:
        domain = user.email.split("@")[-1].split(".")[0].capitalize()
        company_name = f"{domain} (auto)"

    slug = company_name.lower().replace(" ", "-")[:50]
    tenant_id = str(uuid.uuid4())
    customer_id = str(user.id)
    org_admin_role = _get_org_admin_role()

    with transaction.atomic():
        # Set org key on user — immutable after this point
        user.customer_id = customer_id
        user.save(update_fields=["customer_id"])

        tenant = Tenants.objects.create(
            id=tenant_id,
            engine_tenant_id=tenant_id,
            name=company_name,
            status="provisioning",
            tenant_type="cloud",
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

        # Dispatch async onboarding sync AFTER transaction commits (Auth-A3)
        # Import is deferred so Django starts cleanly even if Celery is unavailable
        def _enqueue_sync():
            try:
                from user_auth.celery_tasks import sync_tenant_to_onboarding
                sync_tenant_to_onboarding.apply_async(
                    args=[tenant_id, customer_id],
                    queue="tenant-sync",
                )
                logger.info(f"Enqueued onboarding sync for tenant {tenant_id}")
            except Exception as exc:
                logger.warning(
                    f"Could not enqueue onboarding sync for {tenant_id}: {exc}. "
                    "Tenant status remains 'provisioning' — use /api/v1/tenants/{id}/resync/"
                )

        transaction.on_commit(_enqueue_sync)

    logger.info(f"Provisioned tenant '{company_name}' (id={tenant_id}) for {user.email}")
    return tenant


# ---------------------------------------------------------------------------
# Backward-compat alias — callers referencing the old name still work
# while we migrate all call sites.
# ---------------------------------------------------------------------------
provision_first_tenant = provision_tenant_for_new_user
