'use client';
/**
 * TenantContext — global tenant + customer state.
 *
 * Provides:
 *   customerId    — identity of the logged-in customer (from env or auth session)
 *   activeTenant  — { tenant_id, tenant_name, account_count } currently selected
 *   tenants       — full list of customer's tenants
 *   setActiveTenant(tenant) — switch active workspace
 *   refreshTenants()        — re-fetch from API
 *
 * customer_id source priority:
 *   1. NEXT_PUBLIC_CUSTOMER_ID env var  (dev / demo)
 *   2. localStorage 'customer_id'       (set after login)
 *   3. 'default-customer'               (fallback)
 *
 * activeTenant is persisted in localStorage so it survives page refreshes.
 */

import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { getFromEngine } from '@/lib/api';

const TenantContext = createContext(null);

const LS_TENANT_KEY    = 'cspm_active_tenant';
const LS_CUSTOMER_KEY  = 'customer_id';

function resolveCustomerId() {
  if (process.env.NEXT_PUBLIC_CUSTOMER_ID) return process.env.NEXT_PUBLIC_CUSTOMER_ID;
  if (typeof window !== 'undefined') {
    return localStorage.getItem(LS_CUSTOMER_KEY) || 'default-customer';
  }
  return 'default-customer';
}

export function TenantProvider({ children }) {
  const [customerId]     = useState(resolveCustomerId);
  const [tenants,  setTenants]       = useState([]);
  const [activeTenant, setActiveTenantState] = useState(null);
  const [loading, setLoading]        = useState(false);

  // Persist active tenant selection
  function setActiveTenant(tenant) {
    setActiveTenantState(tenant);
    if (typeof window !== 'undefined') {
      if (tenant) {
        localStorage.setItem(LS_TENANT_KEY, JSON.stringify(tenant));
      } else {
        localStorage.removeItem(LS_TENANT_KEY);
      }
    }
  }

  const refreshTenants = useCallback(async () => {
    if (!customerId) return;
    setLoading(true);
    const res = await getFromEngine('onboarding', '/api/v1/tenants', {
      customer_id: customerId,
      status: 'active',
    });
    setLoading(false);
    if (res.error || !res.tenants) return;

    setTenants(res.tenants);

    // Restore persisted selection or default to first tenant
    const persisted = typeof window !== 'undefined'
      ? JSON.parse(localStorage.getItem(LS_TENANT_KEY) || 'null')
      : null;

    if (persisted) {
      const still = res.tenants.find(t => t.tenant_id === persisted.tenant_id);
      setActiveTenantState(still || res.tenants[0] || null);
    } else if (res.tenants.length > 0) {
      setActiveTenantState(res.tenants[0]);
    }
  }, [customerId]);

  // Load on mount
  useEffect(() => { refreshTenants(); }, [refreshTenants]);

  return (
    <TenantContext.Provider value={{ customerId, activeTenant, tenants, loading, setActiveTenant, refreshTenants }}>
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant() {
  const ctx = useContext(TenantContext);
  if (!ctx) throw new Error('useTenant must be used inside <TenantProvider>');
  return ctx;
}
