"""
Auto-provision a tenant for new users who sign in via SSO/OAuth
and don't yet belong to any tenant.
"""
import logging
import uuid

logger = logging.getLogger(__name__)


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


def provision_first_tenant(user, company_name: str = ""):
    """
    Create a tenant for a user who has none yet.
    Called on:
      - Email signup (company_name from form)
      - Google/SAML first login (company_name derived from email domain)
    Returns the Tenants instance.
    """
    from tenant_management.models import Tenants, TenantUsers

    # Don't double-provision
    if TenantUsers.objects.filter(user=user).exists():
        return None

    if not company_name:
        domain = user.email.split("@")[-1].split(".")[0].capitalize()
        company_name = f"{domain} (auto)"

    tenant = Tenants.objects.create(
        id=str(uuid.uuid4()),
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

    logger.info(f"Auto-provisioned tenant '{tenant.name}' for user {user.email}")
    return tenant
