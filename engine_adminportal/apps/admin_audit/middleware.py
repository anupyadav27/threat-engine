"""
Audit logging middleware for admin portal.
"""
import logging
from django.utils.deprecation import MiddlewareMixin
from .models import AdminAuditLog

logger = logging.getLogger(__name__)


class AuditLoggingMiddleware(MiddlewareMixin):
    """Middleware to log admin actions."""
    
    # Actions that should be logged
    LOGGED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    EXCLUDED_PATHS = ['/health/', '/api/admin/health/', '/api/admin/audit/']
    
    def process_response(self, request, response):
        """Log admin actions after response."""
        # Skip if not an admin action
        if not request.user or not request.user.is_authenticated:
            return response
        
        # Skip excluded paths
        if any(request.path.startswith(path) for path in self.EXCLUDED_PATHS):
            return response
        
        # Only log write operations
        if request.method not in self.LOGGED_METHODS:
            return response
        
        # Determine action type
        action_type = self._get_action_type(request.method, request.path)
        if not action_type:
            return response
        
        # Get resource info
        resource_type, resource_id = self._extract_resource_info(request.path)
        
        try:
            AdminAuditLog.objects.create(
                admin_user_id=str(request.user.id),
                action_type=action_type,
                resource_type=resource_type,
                resource_id=resource_id,
                details={
                    'path': request.path,
                    'method': request.method,
                    'status_code': response.status_code
                },
                ip_address=self._get_client_ip(request)
            )
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
        
        return response
    
    def _get_action_type(self, method: str, path: str) -> str:
        """Determine action type from method and path."""
        if '/users/' in path:
            if method == 'POST':
                return 'user_create'
            elif method in ['PUT', 'PATCH']:
                return 'user_update'
            elif method == 'DELETE':
                return 'user_delete'
        elif '/tenants/' in path:
            if method == 'POST':
                if 'suspend' in path:
                    return 'tenant_suspend'
                elif 'activate' in path:
                    return 'tenant_activate'
                return 'tenant_create'
            elif method in ['PUT', 'PATCH']:
                return 'tenant_update'
        elif '/assign-tenant' in path:
            return 'role_assign'
        
        return None
    
    def _extract_resource_info(self, path: str) -> tuple:
        """Extract resource type and ID from path."""
        parts = path.strip('/').split('/')
        
        if 'users' in parts:
            idx = parts.index('users')
            if idx + 1 < len(parts):
                return 'user', parts[idx + 1]
            return 'user', None
        elif 'tenants' in parts:
            idx = parts.index('tenants')
            if idx + 1 < len(parts):
                return 'tenant', parts[idx + 1]
            return 'tenant', None
        
        return 'unknown', None
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
