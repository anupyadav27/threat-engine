/**
 * Route -> capability mapping and helpers for RBAC.
 * Super landlord bypasses all checks.
 */

export const ROUTE_CAPABILITY = {
    "/dashboard": "can_access_dashboard",
    "/assets": "can_access_assets",
    "/vulnerabilities": "can_access_assets",
    "/threats": "can_access_threats",
    "/compliances": "can_access_compliance",
    "/policies": "can_access_policies",
    "/secops": "can_access_secops",
    "/reports": "can_access_reports",
    "/settings": "can_access_settings",
    "/settings/profile": "can_access_settings",
    "/settings/users": "can_manage_users",
    "/settings/tenants": "can_manage_tenants",
    "/settings/notifications": "can_access_settings",
    "/settings/integrations": "can_access_settings",
};

/**
 * Find required capability for pathname (longest prefix match).
 */
export function capabilityForRoute(pathname) {
    if (!pathname) return null;
    let cap = null;
    let longest = 0;
    for (const [route, c] of Object.entries(ROUTE_CAPABILITY)) {
        if (pathname.startsWith(route) && route.length > longest) {
            longest = route.length;
            cap = c;
        }
    }
    return cap;
}

/**
 * Check if user can access route. Super landlord always can.
 */
export function canAccessRoute(pathname, capabilities, isSuperLandlord) {
    if (isSuperLandlord) return true;
    const cap = capabilityForRoute(pathname);
    if (!cap) return true;
    return Array.isArray(capabilities) && capabilities.includes(cap);
}

/**
 * Filter menu items by capabilities. Super landlord sees all.
 */
export function filterMenuByCapabilities(items, capabilities, isSuperLandlord) {
    if (isSuperLandlord) return items;
    if (!Array.isArray(capabilities)) return items;
    return items.filter((item) => {
        const cap = item.capability ?? ROUTE_CAPABILITY[item.link];
        if (!cap) return true;
        return capabilities.includes(cap);
    });
}
