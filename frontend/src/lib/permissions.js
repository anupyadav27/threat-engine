import { useAuth } from './auth-context';
import { FALLBACK_VIEWER_PERMISSIONS } from './permission-constants';

export { FALLBACK_VIEWER_PERMISSIONS };

export const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  TENANT_ADMIN: 'tenant_admin',
  USER: 'user',
};

// Map routes to the required permission key.
// null means the route is always accessible to any authenticated user.
export const ROUTE_CAPABILITIES = {
  '/dashboard':                null,
  '/assets':                   'inventory:read',
  '/inventory':                'inventory:read',
  '/threats':                  'threat:read',
  '/threats/attack-paths':     'threat:read',
  '/compliance':               'compliance:read',
  '/compliance/[framework]':   'compliance:read',
  '/iam':                      'iam:read',
  '/datasec':                  'datasec:read',
  '/scans':                    'scans:create',
  '/scans/[scanId]':           'scans:create',
  '/secops':                   'secops:read',
  '/secops/[scanId]':          'secops:read',
  '/risk':                     'risk:read',
  '/onboarding':               'tenants:read',
  '/onboarding/wizard':        'tenants:read',
  '/settings':                 'settings:read',
  '/vulnerability':            'vulnerability:read',
  '/vulnerability/scans':      'vulnerability:read',
  '/vulnerability/cves':       'vulnerability:read',
  '/vulnerability/agents':     'vulnerability:read',
  '/network-security':         'network:read',
  '/ciem':                     'ciem:read',
  '/rules':                    'rules:write',
  '/policies':                 'settings:write',
};

/**
 * Check whether a permissions array includes a specific permission key.
 * Returns true when permissionKey is null (route has no restriction).
 * Returns false when permissions is empty/null (no access).
 *
 * @param {string[]|null|undefined} permissions - Permissions array from API
 * @param {string|null} permissionKey           - Required permission key
 * @returns {boolean}
 */
export function hasPermission(permissions, permissionKey) {
  if (!permissionKey) return true;  // no restriction on this route
  if (!permissions || permissions.length === 0) return false;
  return permissions.includes(permissionKey);
}

/**
 * Check whether the user can access a route based on their permissions.
 *
 * @param {string[]|null|undefined} permissions - Permissions array from API
 * @param {string} pathname                     - Route pathname
 * @returns {boolean}
 */
export function canAccessRoute(permissions, pathname) {
  // Walk ROUTE_CAPABILITIES longest-prefix-first
  for (const [route] of Object.entries(ROUTE_CAPABILITIES)) {
    const normalizedRoute = route.replace(/\/\[.*?\]/g, '');
    if (pathname === normalizedRoute || pathname.startsWith(normalizedRoute + '/')) {
      const required = ROUTE_CAPABILITIES[route];
      return hasPermission(permissions, required);
    }
  }
  // Default: allow access if no capability is required for this route
  return true;
}

/**
 * Check if user is a super admin.
 * @param {string} role
 * @returns {boolean}
 */
export function isSuperAdmin(role) {
  return role === ROLES.SUPER_ADMIN;
}

/**
 * React hook — returns permission helpers backed by the live auth context.
 * All permission data originates from the /api/auth/me response (API-driven,
 * not from any localStorage or client-mutable state).
 *
 * @returns {{ hasPermission: (key: string) => boolean, canAccessRoute: (path: string) => boolean, permissions: string[], role: string }}
 */
export function usePermissions() {
  const { role, permissions, hasPermission: ctxHasPermission } = useAuth();

  return {
    // Prefer the pre-bound helper on the context so callers don't need to pass the array
    hasPermission: (key) => ctxHasPermission(key),
    canAccessRoute: (pathname) => canAccessRoute(permissions, pathname),
    isSuperAdmin: () => isSuperAdmin(role),
    role,
    permissions,
    // Deprecated alias — kept so any remaining callers don't hard-crash before
    // they are individually updated.  Will be removed in RBAC-09.
    /** @deprecated Use hasPermission() with the canonical permission key instead */
    hasCapability: (key) => ctxHasPermission(key),
    /** @deprecated Use permissions instead */
    capabilities: permissions,
  };
}

/**
 * Single-key convenience hook — returns a boolean for one permission key.
 *
 * @param {string} key - Permission key to check (e.g. 'threat:read')
 * @returns {boolean}
 */
export function usePermission(key) {
  const { hasPermission: ctxHasPermission } = useAuth();
  return ctxHasPermission(key);
}
