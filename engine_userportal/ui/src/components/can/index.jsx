"use client";

import { usePermissions } from "@/context/appContext/usePermissions";

/**
 * <Can capability="can_manage_users">...</Can>
 * Renders children only when user has the capability (or is super landlord).
 */
export default function Can({ capability, children, fallback = null }) {
    const { can } = usePermissions();
    if (!capability) return <>{children}</>;
    return can(capability) ? <>{children}</> : <>{fallback}</>;
}
