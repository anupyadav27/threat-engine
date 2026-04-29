'use client';

/**
 * GlobalFilterContext — cross-page multi-CSP scope selector.
 *
 * Hierarchy: Provider → Account → Region (cascade resets on parent change)
 * timeRange is independent (no cascade).
 *
 * Fetches real cloud accounts from the onboarding API on mount.
 *
 * Usage:
 *   const { provider, account, region, timeRange, setFilter, clearAll } = useGlobalFilter();
 */

import { createContext, useContext, useState, useCallback, useMemo, useEffect } from 'react';
import { getFromEngine } from './api';

const GlobalFilterContext = createContext(null);

export const TIME_RANGE_OPTIONS = [
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d',  label: 'Last 7 Days'   },
  { value: '30d', label: 'Last 30 Days'  },
  { value: '90d', label: 'Last 90 Days'  },
];

export function GlobalFilterProvider({ children }) {
  const [provider,  setProvider]  = useState('');
  const [account,   setAccount]   = useState('');
  const [region,    setRegion]    = useState('');
  const [timeRange, setTimeRange] = useState('7d');

  // Real accounts fetched from onboarding API
  const [accounts, setAccounts] = useState([]);

  // Fetch real cloud accounts on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await getFromEngine('onboarding', '/api/v1/cloud-accounts');
        if (cancelled) return;
        const list = res?.accounts || res?.cloud_accounts || (Array.isArray(res) ? res : []);
        // Normalize to { provider, account, display, regions }
        const normalized = list.map((a) => ({
          provider:   (a.provider || a.csp || 'AWS').toUpperCase(),
          account:    a.account_id || a.account_name || a.name || '',
          display:    a.account_name || a.name || a.account_id || '',
          regions:    a.regions || (a.region ? [a.region] : []),
        }));
        setAccounts(normalized);
      } catch (err) {
        console.warn('GlobalFilter: failed to fetch cloud accounts', err);
        // No fallback — dropdowns stay empty until API responds
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // Cascade-aware setter
  const setFilter = useCallback((key, value) => {
    switch (key) {
      case 'provider':
        setProvider(value);
        setAccount('');
        setRegion('');
        break;
      case 'account':
        setAccount(value);
        setRegion('');
        break;
      case 'region':
        setRegion(value);
        break;
      case 'timeRange':
        setTimeRange(value);
        break;
    }
  }, []);

  const clearAll = useCallback(() => {
    setProvider('');
    setAccount('');
    setRegion('');
    setTimeRange('7d');
  }, []);

  const hasActiveFilters = !!(provider || account || region || timeRange !== '7d');

  // Derived dropdown options (memoised from real accounts)
  const providerOptions = useMemo(() =>
    [...new Set(accounts.map(a => a.provider))].map(p => ({ value: p, label: p })),
    [accounts]
  );

  const accountOptions = useMemo(() =>
    accounts
      .filter(a => !provider || a.provider === provider)
      .map(a => ({ value: a.account, label: a.display })),
    [provider, accounts]
  );

  const regionOptions = useMemo(() => {
    const accts = accounts.filter(
      a => (!provider || a.provider === provider) && (!account || a.account === account)
    );
    return [...new Set(accts.flatMap(a => a.regions))].map(r => ({ value: r, label: r }));
  }, [provider, account, accounts]);

  // Human-readable summary for display (e.g. "AWS › prod-account › us-east-1")
  const filterSummary = useMemo(() => {
    const parts = [];
    if (provider)   parts.push(provider);
    if (account) {
      const acctLabel = accounts.find(a => a.account === account)?.display || account;
      parts.push(acctLabel);
    }
    if (region)     parts.push(region);
    return parts.length ? parts.join(' › ') : null;
  }, [provider, account, region, accounts]);

  const value = {
    // Selected values
    provider, account, region, timeRange,
    // Actions
    setFilter, clearAll,
    // Flags
    hasActiveFilters,
    filterSummary,
    // Dropdown option lists
    providerOptions, accountOptions, regionOptions,
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
