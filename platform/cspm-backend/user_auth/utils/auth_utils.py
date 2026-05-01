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
        scope_cache: dict = {"tenant_ids": None, "account_ids": None}
    else:
        tenant_ids = list(
            TenantUsers.objects.filter(user=user, is_active=True)
            .values_list("tenant_id", flat=True)
        )
        scope_cache = {
            "tenant_ids": [str(tid) for tid in tenant_ids],
            "account_ids": None,
        }

    return permissions_cache, scope_cache