'use client';
/**
 * TenantContext — workspace list and active workspace state.
 *
 * Workspace list is derived directly from the auth session (/me response)
 * — no separate onboarding DB fetch. This keeps the source of truth in one place.
 *
 * customerId  — user's platform UUID (stable, from auth.customer_id).
 *               Used when creating tenants or cloud accounts.
 * activeTenant — { tenant_id, tenant_name, account_count } currently selected.
 *                tenant_id here is the engine_tenant_id.
 * tenants      — all workspaces the user is a member of (from auth.tenants).
 * setActiveTenant(tenant) — switch active workspace.
 * refreshTenants()        — no-op; workspace list refreshes on auth re-validate.
 */

import { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import { useAuth } from '@/lib/auth-context';

const TenantContext = createContext(null);

const LS_TENANT_KEY = 'cspm_active_tenant';

export function TenantProvider({ children }) {
  const { tenants: authTenants, customerId, selectedTenant, level } = useAuth();

  // Map /me tenant format → workspace switcher format.
  // engine_tenant_id is what every engine uses as tenant_id.
  const tenants = useMemo(() =>
    (authTenants || [])
      .filter(t => t.status === 'active')
      .map(t => ({
        tenant_id:    t.engine_tenant_id || t.tenant_id,
        tenant_name:  t.tenant_name,
        account_count: t.account_count ?? 0,
      })),
    [authTenants]
  );

  const [activeTenant, setActiveTenantState] = useState(null);

  // Restore persisted active workspace once tenants are loaded.
  // platform_admin (level 1) defaults to null = "All Tenants" unless they
  // previously saved a specific tenant in localStorage.
  useEffect(() => {
    if (tenants.length === 0) return;
    const isPlatformAdmin = level === 1;

    // If auth context explicitly carries null for platform_admin, honour it —
    // this means the user switched to "All Tenants" this session.
    if (isPlatformAdmin && selectedTenant === null) {
      const persisted = typeof window !== 'undefined'
        ? JSON.parse(localStorage.getItem(LS_TENANT_KEY) || 'null')
        : null;
      if (persisted) {
        // They had a specific tenant saved — keep it
        const still = tenants.find(t => t.tenant_id === persisted.tenant_id);
        setActiveTenantState(still || null);
      } else {
        setActiveTenantState(null);
      }
      return;
    }

    const persisted = typeof window !== 'undefined'
      ? JSON.parse(localStorage.getItem(LS_TENANT_KEY) || 'null')
      : null;
    if (persisted) {
      const still = tenants.find(t => t.tenant_id === persisted.tenant_id);
      setActiveTenantState(still || (isPlatformAdmin ? null : tenants[0]));
    } else {
      setActiveTenantState(isPlatformAdmin ? null : tenants[0]);
    }
  }, [tenants, level, selectedTenant]);

  function setActiveTenant(tenant) {
    setActiveTenantState(tenant);
    if (typeof window !== 'undefined') {
      if (tenant) localStorage.setItem(LS_TENANT_KEY, JSON.stringify(tenant));
      else localStorage.removeItem(LS_TENANT_KEY);
    }
  }

  // Workspace list is authoritative from auth — nothing to refresh here.
  const refreshTenants = useCallback(async () => {}, []);

  return (
    <TenantContext.Provider value={{
      customerId: customerId || null,
      activeTenant,
      tenants,
      loading: false,
      setActiveTenant,
      refreshTenants,
    }}>
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant() {
  const ctx = useContext(TenantContext);
  if (!ctx) throw new Error('useTenant must be used inside <TenantProvider>');
  return ctx;
}
