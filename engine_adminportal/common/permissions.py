"""
Admin permission classes for the admin portal.
"""
from rest_framework import permissions


class IsSuperAdmin(permissions.BasePermission):
    """Only super admins can access."""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            (request.user.is_superuser or getattr(request.user, 'is_super_admin', False))
        )


class IsAdmin(permissions.BasePermission):
    """Admins and super admins can access."""
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Super admin
        if request.user.is_superuser or getattr(request.user, 'is_super_admin', False):
            return True
        
        # Regular admin
        return getattr(request.user, 'is_admin', False)


class IsSupportAdmin(permissions.BasePermission):
    """Support admins and above can access (read-only for support)."""
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Super admin or admin
        if (request.user.is_superuser or 
            getattr(request.user, 'is_super_admin', False) or 
            getattr(request.user, 'is_admin', False)):
            return True
        
        # Support admin (read-only)
        if getattr(request.user, 'is_support_admin', False):
            return request.method in permissions.SAFE_METHODS
        
        return False
