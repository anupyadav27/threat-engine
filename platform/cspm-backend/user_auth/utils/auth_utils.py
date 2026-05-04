# utils/auth_utils.py
import secrets
from typing import Any, List, Tuple
from django.contrib.auth.hashers import make_password, check_password


def generate_token() -> str:
    """
    Generate a cryptographically secure random token.
    Suitable for access/refresh tokens.
    """
    return secrets.token_urlsafe(64)


def hash_token(token: str) -> str:
    """
    Hash a token for secure storage (like a password).
    Uses Django's default hasher (e.g., PBKDF2).
    """
    return make_password(token)


def verify_token(provided_token: str, stored_hashed_token: str) -> bool:
    """
    Verify a raw token against its hashed version in the DB.
    """
    return check_password(provided_token, stored_hashed_token)


def compute_auth_caches(user: Any) -> Tuple[List[str], dict]:
    """Compute permissions_cache and scope_cache for a user at login time.

    Args:
        user: A Users model instance.

    Returns:
        A tuple of (permissions_cache, scope_cache) where:
          - permissions_cache is a sorted list of unique permission key strings
            derived from all global roles assigned to the user via UserRoles.
          - scope_cache is a dict with the shape
            {"tenant_ids": [str, ...], "account_ids": None}.
            tenant_ids contains only tenants where is_active=True.
            account_ids is None (unrestricted within allowed tenants).

    Security note: This function is computed exclusively from server-side DB
    joins — no client-supplied data is accepted or used.
    """
    from user_auth.models import Permissions as PermissionsModel, UserRoles
    from tenant_management.models import TenantUsers

    # Collect all permission keys from all global roles assigned to this user.
    # Traversal: Permissions ←(related_name='roles')→ Roles ←(userroles reverse FK)→ UserRoles → user
    # UserRoles.role FK has no explicit related_name so Django generates 'userroles' (lowercase model name).
    perm_keys = list(
        PermissionsModel.objects.filter(
            roles__userroles__user=user
        ).values_list("key", flat=True).distinct()
    )
    permissions_cache: List[str] = sorted(perm_keys)

    # Platform admins have unrestricted cross-tenant access; collect tenant IDs
    # only for lower-scoped roles.
    from user_auth.models import UserRoles as _UR
    platform_admin = _UR.objects.filter(user=user, role__level=1).exists()
    if platform_admin:
        from tenant_management.models import Tenants
        first_tenant = Tenants.objects.order_by("created_at").first()
        default_engine_tenant_id = (
            first_tenant.engine_tenant_id or str(first_tenant.id)
        ) if first_tenant else None
        scope_cache: dict = {
            "tenant_ids": None,
            "account_ids": None,
            "engine_tenant_id": default_engine_tenant_id,
        }
    else:
        memberships = (
            TenantUsers.objects.filter(user=user, is_active=True)
            .select_related("tenant")
        )
        engine_tenant_ids = []
        for m in memberships:
            eid = m.tenant.engine_tenant_id or str(m.tenant.id)
            engine_tenant_ids.append(eid)
        # Resolve account_ids: explicit grants restrict to specific accounts;
        # no grants means unrestricted (None) within the tenant.
        from tenant_management.models import UserAccountAccess
        account_grants = list(
            UserAccountAccess.objects.filter(user=user)
            .values_list("account_id", flat=True)
        )
        scope_cache = {
            "tenant_ids": engine_tenant_ids,
            "engine_tenant_id": engine_tenant_ids[0] if engine_tenant_ids else None,
            "account_ids": account_grants if account_grants else None,
        }

    return permissions_cache, scope_cache