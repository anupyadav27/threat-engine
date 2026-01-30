"use client";

import { useMemo } from "react";
import { useAppContext } from "./index";
import { capabilityForRoute } from "@/utils/permissions";

/**
 * usePermissions() — roles, capabilities, scope, can(cap), canAccessRoute(path).
 */
export function usePermissions() {
    const { state } = useAppContext();
    const capabilities = state.capabilities ?? [];
    const scope = state.scope ?? {};
    const isSuperLandlord = !!scope.is_super_landlord;

    const can = useMemo(
        () =>
            function (cap) {
                if (isSuperLandlord) return true;
                return capabilities.includes(cap);
            },
        [isSuperLandlord, capabilities]
    );

    const canAccessRoute = useMemo(
        () =>
            function (pathname) {
                if (isSuperLandlord) return true;
                const cap = capabilityForRoute(pathname);
                if (!cap) return true;
                return capabilities.includes(cap);
            },
        [isSuperLandlord, capabilities]
    );

    return {
        roles: state.roles ?? [],
        capabilities,
        scope,
        isSuperLandlord,
        can,
        canAccessRoute,
    };
}
