'use client';

/**
 * GlobalFilterContext — cross-page scope selector.
 *
 * Scope hierarchy: Customer (org) → Tenant (multi) → Provider (multi) → Account (multi)
 * timeRange is independent.
 *
 * Filter state is persisted to localStorage (key: cspm_global_filter) so it
 * survives page refreshes and hard navigations. Restored on mount.
 *
 * Account data is fetched server-side:
 *   - 0 tenants selected → fetch all accounts (no tenant header; server returns all for platform_admin)
 *   - N tenants selected → N parallel fetches each with X-Active-Tenant-Id: tenantId, results merged
 */

import { createContext, useContext, useState, useCallback, useMemo, useEffect, useRef } from 'react';
import { useAuth } from './auth-context';
import { CLOUD_PROVIDERS, API_BASE } from './constants';

const GlobalFilterContext = createContext(null);
const LS_KEY = 'cspm_global_filter';

export const TIME_RANGE_OPTIONS = [
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d',  label: 'Last 7 Days'   },
  { value: '30d', label: 'Last 30 Days'  },
  { value: '90d', label: 'Last 90 Days'  },
];

function readStorage() {
  if (typeof window === 'undefined') return null;
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw);
    return {
      selectedTenantIds:   new Set(Array.isArray(p.tenants)   ? p.tenants   : []),
      selectedProviderIds: new Set(Array.isArray(p.providers) ? p.providers : []),
      selectedAccountIds:  new Set(Array.isArray(p.accounts)  ? p.accounts  : []),
      timeRange:           typeof p.timeRange === 'string' ? p.timeRange : '7d',
    };
  } catch {
    return null;
  }
}

function writeStorage(tenants, providers, accounts, timeRange) {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem(LS_KEY, JSON.stringify({
      tenants:   [...tenants],
      providers: [...providers],
      accounts:  [...accounts],
      timeRange,
    }));
  } catch {}
}

// Fetch cloud accounts from BFF, optionally scoped to a single tenant.
async function fetchAccountsFromBFF(tenantId) {
  const apiBase = API_BASE || '';
  let url;
  if (apiBase.startsWith('http')) {
    url = `${apiBase}/gateway/api/v1/views/onboarding/cloud_accounts`;
  } else {
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    url = `${origin}${apiBase}/gateway/api/v1/views/onboarding/cloud_accounts`;
  }
  const headers = { 'Content-Type': 'application/json' };
  if (tenantId) headers['X-Active-Tenant-Id'] = String(tenantId);

  const res = await fetch(url, { method: 'GET', headers, credentials: 'include' });
  if (!res.ok) {
    console.warn(`GlobalFilter: BFF returned ${res.status} for tenant=${tenantId}`);
    return [];
  }
  const data = await res.json();
  if (data?.error) {
    console.warn('GlobalFilter: BFF error:', data.error);
    return [];
  }
  const list = data?.accounts || (Array.isArray(data) ? data : []);
  return list.map((a) => ({
    provider: (a.provider || a.csp || 'AWS').toUpperCase(),
    account:  a.accountId || a.account_id || a.accountName || a.account_name || a.name || '',
    display:  a.accountName || a.account_name || a.name || a.accountId || a.account_id || '',
    regions:  a.regions || (a.region ? [a.region] : []),
  }));
}

export function GlobalFilterProvider({ children }) {
  const { isInitialized } = useAuth();

  // Restore persisted state on first render (before any effects run)
  const saved = useRef(readStorage());

  // Legacy single-select (backward compat for useViewFetch)
  const [provider,  setProvider]  = useState('');
  const [account,   setAccount]   = useState('');
  const [region,    setRegion]    = useState('');
  const [timeRange, setTimeRange] = useState(saved.current?.timeRange ?? '7d');

  // Multi-select sets — restored from localStorage
  const [selectedTenantIds,   setSelectedTenantIds]   = useState(saved.current?.selectedTenantIds   ?? new Set());
  const [selectedProviderIds, setSelectedProviderIds] = useState(saved.current?.selectedProviderIds ?? new Set());
  const [selectedAccountIds,  setSelectedAccountIds]  = useState(saved.current?.selectedAccountIds  ?? new Set());

  // Accounts fetched from server (already tenant-filtered)
  const [allAccounts, setAllAccounts] = useState([]);
  const fetchGenRef = useRef(0);

  // Persist filter state whenever it changes
  useEffect(() => {
    writeStorage(selectedTenantIds, selectedProviderIds, selectedAccountIds, timeRange);
  }, [selectedTenantIds, selectedProviderIds, selectedAccountIds, timeRange]);

  // Fetch accounts whenever auth initializes or tenant selection changes.
  const tenantKey = [...selectedTenantIds].sort().join(',');

  useEffect(() => {
    if (!isInitialized) return;
    const gen = ++fetchGenRef.current;

    (async () => {
      try {
        let accounts;
        if (selectedTenantIds.size === 0) {
          accounts = await fetchAccountsFromBFF(null);
        } else {
          const results = await Promise.all(
            [...selectedTenantIds].map(tid => fetchAccountsFromBFF(tid))
          );
          accounts = results.flat();
        }
        if (gen !== fetchGenRef.current) return;
        setAllAccounts(accounts);
      } catch (err) {
        console.warn('GlobalFilter: fetch error', err);
      }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isInitialized, tenantKey]);

  // Multi-select toggle helpers
  const toggleTenantFilter = useCallback((tenantId) => {
    setSelectedTenantIds(prev => {
      const next = new Set(prev);
      if (next.has(tenantId)) next.delete(tenantId); else next.add(tenantId);
      return next;
    });
    setSelectedProviderIds(new Set());
    setSelectedAccountIds(new Set());
    setProvider('');
    setAccount('');
  }, []);

  const toggleProviderFilter = useCallback((providerId) => {
    setSelectedProviderIds(prev => {
      const next = new Set(prev);
      if (next.has(providerId)) next.delete(providerId); else next.add(providerId);
      setProvider(next.size === 1 ? [...next][0] : '');
      return next;
    });
    setSelectedAccountIds(new Set());
    setAccount('');
  }, []);

  const toggleAccountFilter = useCallback((accountId) => {
    setSelectedAccountIds(prev => {
      const next = new Set(prev);
      if (next.has(accountId)) next.delete(accountId); else next.add(accountId);
      setAccount(next.size > 0 ? [...next][0] : '');
      return next;
    });
  }, []);

  const clearTenantFilter = useCallback(() => {
    setSelectedTenantIds(new Set());
    setSelectedProviderIds(new Set());
    setSelectedAccountIds(new Set());
    setProvider('');
    setAccount('');
  }, []);

  const clearProviderFilter = useCallback(() => {
    setSelectedProviderIds(new Set());
    setSelectedAccountIds(new Set());
    setProvider('');
    setAccount('');
  }, []);

  const clearAccountFilter = useCallback(() => {
    setSelectedAccountIds(new Set());
    setAccount('');
  }, []);

  const setFilter = useCallback((key, value) => {
    switch (key) {
      case 'provider':  setProvider(value); setAccount(''); setRegion(''); break;
      case 'account':   setAccount(value);  setRegion(''); break;
      case 'region':    setRegion(value); break;
      case 'timeRange': setTimeRange(value); break;
    }
  }, []);

  const clearAll = useCallback(() => {
    setProvider('');
    setAccount('');
    setRegion('');
    setTimeRange('7d');
    setSelectedTenantIds(new Set());
    setSelectedProviderIds(new Set());
    setSelectedAccountIds(new Set());
  }, []);

  const hasActiveFilters = !!(
    provider || account || region || timeRange !== '7d'
    || selectedTenantIds.size > 0 || selectedProviderIds.size > 0 || selectedAccountIds.size > 0
  );

  const providerOptions = useMemo(() => (
    [...new Set(allAccounts.map(a => a.provider))].map(p => ({
      value: p,
      label: CLOUD_PROVIDERS[p.toLowerCase()]?.name || p,
    }))
  ), [allAccounts]);

  const accountOptions = useMemo(() => {
    const base = selectedProviderIds.size > 0
      ? allAccounts.filter(a => selectedProviderIds.has(a.provider))
      : allAccounts;
    return base.map(a => ({ value: a.account, label: a.display || a.account }));
  }, [allAccounts, selectedProviderIds]);

  const regionOptions = useMemo(() => {
    const accts = allAccounts.filter(
      a => (!provider || a.provider === provider) && (!account || a.account === account)
    );
    return [...new Set(accts.flatMap(a => a.regions))].map(r => ({ value: r, label: r }));
  }, [provider, account, allAccounts]);

  const filterSummary = useMemo(() => {
    const parts = [];
    if (selectedTenantIds.size > 0)   parts.push(`${selectedTenantIds.size} tenant${selectedTenantIds.size > 1 ? 's' : ''}`);
    if (selectedProviderIds.size > 0) parts.push(`${selectedProviderIds.size} provider${selectedProviderIds.size > 1 ? 's' : ''}`);
    if (selectedAccountIds.size > 0)  parts.push(`${selectedAccountIds.size} account${selectedAccountIds.size > 1 ? 's' : ''}`);
    return parts.length ? parts.join(', ') : null;
  }, [selectedTenantIds, selectedProviderIds, selectedAccountIds]);

  const value = {
    provider, account, region, timeRange,
    setFilter, clearAll,
    hasActiveFilters, filterSummary,
    providerOptions, accountOptions, regionOptions,
    selectedTenantIds, selectedProviderIds, selectedAccountIds,
    toggleTenantFilter, toggleProviderFilter, toggleAccountFilter,
    clearTenantFilter, clearProviderFilter, clearAccountFilter,
  };

  return (
    <GlobalFilterContext.Provider value={value}>
      {children}
    </GlobalFilterContext.Provider>
  );
}

export function useGlobalFilter() {
  const ctx = useContext(GlobalFilterContext);
  if (!ctx) throw new Error('useGlobalFilter() must be used within <GlobalFilterProvider>');
  return ctx;
}
