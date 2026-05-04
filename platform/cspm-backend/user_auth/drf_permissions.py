"""DRF permission factories — built on the session permissions_cache."""
from rest_framework.permissions import BasePermission


def HasPermission(permission_key: str) -> type:
    """Return a DRF permission class that requires a specific key.

    The key is checked against session.permissions_cache (list of strings)
    set by compute_auth_caches() at login time.

    Usage:
        permission_classes = [HasPermission("tenants:read")]
    """

    class _Permission(BasePermission):
        def has_permission(self, request, view):
            session = request.auth
            if session is None:
                return False
            permissions = session.permissions_cache or []
            return permission_key in permissions

    _Permission.__name__ = f"HasPermission[{permission_key}]"
    _Permission.__qualname__ = f"HasPermission[{permission_key}]"
    return _Permission
