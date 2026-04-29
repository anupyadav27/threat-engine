import { useAuth } from './auth-context';

export const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  TENANT_ADMIN: 'tenant_admin',
  USER: 'user',
};

// Map routes to required capabilities
export const ROUTE_CAPABILITIES = {
  '/dashboard': 'view_dashboard',
  '/assets': 'view_assets',
  '/inventory': 'view_assets',
  '/threats': 'view_threats',
  '/threats/attack-paths': 'view_threats',
  '/compliance': 'view_compliance',
  '/compliance/[framework]': 'view_compliance',
  '/iam': 'view_iam',
  '/datasec': 'view_datasec',
  '/scans': 'view_scans',
  '/scans/[scanId]': 'view_scans',
  '/secops': 'view_scans',
  '/secops/[scanId]': 'view_scans',
  '/risk': 'view_threats',
  '/onboarding': 'manage_tenants',
  '/onboarding/wizard': 'manage_tenants',
  '/settings': 'manage_settings',
};

// Role-to-capability mappings
const ROLE_CAPABILITIES = {
  [ROLES.SUPER_ADMIN]: [
    'view_dashboard',
    'view_assets',
    'view_threats',
    'view_compliance',
    'view_iam',
    'view_datasec',
    'view_scans',
    'create_scans',
    'manage_tenants',
    'manage_settings',
    'manage_users',
    'delete_scans',
  ],
  [ROLES.ADMIN]: [
    'view_dashboard',
    'view_assets',
    'view_threats',
    'view_compliance',
    'view_iam',
    'view_datasec',
    'view_scans',
    'create_scans',
    'manage_tenants',
    'manage_settings',
    'manage_users',
  ],
  [ROLES.TENANT_ADMIN]: [
    'view_dashboard',
    'view_assets',
    'view_threats',
    'view_compliance',
    'view_iam',
    'view_datasec',
    'view_scans',
    'create_scans',
    'manage_tenants',
    'manage_settings',
  ],
  [ROLES.USER]: [
    'view_dashboard',
    'view_assets',
    'view_threats',
    'view_compliance',
    'view_iam',
    'view_datasec',
    'view_scans',
  ],
};

/**
 * Check if user has a specific capability
 */
export function hasCapability(capabilities, capability) {
  if (!capabilities || !Array.isArray(capabilities)) {
    return false;
  }
  return capabilities.includes(capability);
}

/**
 * Check if user can access a route based on pathname
 */
export function canAccessRoute(capabilities, pathname) {
  // Remove dynamic segments from pathname
  const routeKey = pathname.replace(/\/\[.*?\]/g, '');

  // Find matching route capability
  for (const [route, capability] of Object.entries(ROUTE_CAPABILITIES)) {
    const normalizedRoute = route.replace(/\/\[.*?\]/g, '');
    if (pathname.startsWith(normalizedRoute)) {
      return hasCapability(capabilities, capability);
    }
  }

  // Default to allowing access if no capability is required
  return true;
}

/**
 * Check if user is a super admin
 */
export function isSuperAdmin(role) {
  return role === ROLES.SUPER_ADMIN;
}

/**
 * Get capabilities for a specific role
 */
export function getCapabilitiesForRole(role) {
  return ROLE_CAPABILITIES[role] || [];
}

/**
 * Hook to use permissions in components
 */
export function usePermissions() {
  const { role, capabilities } = useAuth();

  return {
    hasCapability: (capability) => hasCapability(capabilities, capability),
    canAccessRoute: (pathname) => canAccessRoute(capabilities, pathname),
    isSuperAdmin: () => isSuperAdmin(role),
    role,
    capabilities,
  };
}
