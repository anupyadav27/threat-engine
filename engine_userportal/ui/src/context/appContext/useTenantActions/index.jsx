import { useAppContext } from "@/context/appContext";

export const useTenantActions = () => {
    const { state, dispatch } = useAppContext();

    const switchTenant = (tenantId) => {
        const tenant = state.tenants.data.find((t) => t.id === tenantId);
        if (tenant) {
            dispatch({ type: "SELECT_TENANT", payload: tenant });
            return { success: true, tenant };
        }
        return { success: false, error: "Tenant not found" };
    };

    const createTenant = (tenantData) => {
        const newTenant = {
            id: String(state.tenants.data.length + 1),
            ...tenantData,
            createdAt: new Date().toISOString(),
        };
        const updatedTenants = [...state.tenants, newTenant];
        dispatch({ type: "SET_TENANTS", payload: updatedTenants });
        return { success: true, tenant: newTenant };
    };

    const updateTenant = (tenantId, updatedData) => {
        const updatedTenants = state.tenants.map((t) =>
            t.id === tenantId ? { ...t, ...updatedData } : t
        );
        dispatch({ type: "SET_TENANTS", payload: updatedTenants });

        if (state.selectedTenant?.id === tenantId) {
            const updatedTenant = { ...state.selectedTenant, ...updatedData };
            dispatch({ type: "SELECT_TENANT", payload: updatedTenant });
        }
        return { success: true };
    };

    const deleteTenant = (tenantId) => {
        const updated = state.tenants.filter((t) => t.id !== tenantId);
        dispatch({ type: "SET_TENANTS", payload: updated });

        if (state.selectedTenant?.id === tenantId && updated.length > 0) {
            dispatch({ type: "SELECT_TENANT", payload: updated[0] });
        }
        return { success: true };
    };

    return { state, switchTenant, createTenant, updateTenant, deleteTenant };
};
