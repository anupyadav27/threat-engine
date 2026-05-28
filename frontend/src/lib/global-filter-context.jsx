'use client';

/**
 * GlobalFilterContext — cross-page multi-CSP scope selector.
 *
 * Scope hierarchy: Client (org) → Tenant → Account (cloud account)
 * Provider/Region are legacy filters kept for backwards compat but no longer
 * shown in the main scope bar.
 *
 * Usage:
 *   const { selectedClients, selectedTenants, selectedAccounts, setFilter } = useGlobalFilter();
 */

import { createContext, useContext, useState, useCallback, useMemo, useEffect } from 'react';
import { fetchView } from './api';
import { useAuth } from './auth-context';
import { CLOUD_PROVIDERS } from './constants';

const STATIC_PROVIDER_OPTIONS = ['aws', 'gcp', 'azure', 'oci', 'alicloud', 'ibm'].map(p => ({
  value: p.toUpperCase(),
  label: CLOUD_PROVIDERS[p]?.name || p.toUpperCase(),
}));

const GlobalFilterContext = createContext(null);

export const TIME_RANGE_OPTIONS = [
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d',  label: 'Last 7 Days'   },
  { value: '30d', label: 'Last 30 Days'  },
  { value: '90d', label: 'Last 90 Days'  },
];

export function GlobalFilterProvider({ children }) {
  const { selectedTenant, level, user } = useAuth();

  // Legacy provider/account/region filters (kept for BFF backwards compat)
  const [provider,  setProvider]  = useState('');
  const [account,   setAccount]   = useState('');
  const [region,    setRegion]    = useState('');
  const [timeRange, setTimeRange] = useState('7d');

  // Scope bar multi-select arrays
  const [selectedClients,  setSelectedClients]  = useState([]);  // [] = All Clients (platform_admin only)
  const [selectedTenants,  setSelectedTenants]  = useState([]);  // [] = All Tenants
  const [selectedAccounts, setSelectedAccounts] = useState([]);  // [] = All Accounts

  // Real accounts fetched from onboarding API
  const [accounts, setAccounts] = useState([]);

  // Client list — populated for platform_admin from a future orgs BFF endpoint.
  // For all other roles the list stays empty (client is displayed as a static label).
  const [clients, setClients] = useState([]);

  useEffect(() => {
    if (level !== 1) return;  // Only platform_admin needs the client list
    let cancelled = false;
    (async () => {
      try {
        const res = await fetchView('platform/clients', {});
        if (cancelled) return;
        const list = res?.clients || (Array.isArray(res) ? res : []);
        setClients(list.map(c => ({
          value: c.customer_id || c.id,
          label: c.name || c.customer_id || c.id,
        })));
      } catch {
        // Endpoint not yet deployed — client dropdown stays empty
      }
    })();
    return () => { cancelled = true; };
  }, [level]);

  // Fetch cloud accounts scoped to the active tenant.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetchView('onboarding/cloud_accounts', {});
        if (cancelled) return;
        const list = res?.accounts || (Array.isArray(res) ? res : []);
        const normalized = list.map((a) => ({
          provider: (a.provider || a.csp || 'AWS').toUpperCase(),
          account:  a.accountId || a.account_id || a.accountName || a.account_name || a.name || '',
          display:  a.accountName || a.account_name || a.name || a.accountId || a.account_id || '',
          regions:  a.regions || (a.region ? [a.region] : []),
        }));
        setAccounts(normalized);
        setProvider('');
        setAccount('');
        setRegion('');
      } catch (err) {
        console.warn('GlobalFilter: failed to fetch cloud accounts', err);
      }
    })();
    return () => { cancelled = true; };
  }, [selectedTenant]);

  const setFilter = useCallback((key, value) => {
    switch (key) {
      case 'provider':
        setProvider(value); setAccount(''); setRegion('');
        break;
      case 'account':
        setAccount(value); setRegion('');
        break;
      case 'region':
        setRegion(value);
        break;
      case 'timeRange':
        setTimeRange(value);
        break;
      case 'toggleClient':
        setSelectedClients(prev =>
          prev.includes(value) ? prev.filter(id => id !== value) : [...prev, value]
        );
        break;
      case 'clearClients':
        setSelectedClients([]);
        break;
      case 'toggleTenant':
        setSelectedTenants(prev =>
          prev.includes(value) ? prev.filter(id => id !== value) : [...prev, value]
        );
        break;
      case 'clearTenants':
        setSelectedTenants([]);
        break;
      case 'toggleAccount':
        setSelectedAccounts(prev =>
          prev.includes(value) ? prev.filter(id => id !== value) : [...prev, value]
        );
        break;
      case 'clearAccounts':
        setSelectedAccounts([]);
        break;
    }
  }, []);

  const clearAll = useCallback(() => {
    setProvider(''); setAccount(''); setRegion('');
    setTimeRange('7d');
    setSelectedClients([]);
    setSelectedTenants([]);
    setSelectedAccounts([]);
  }, []);

  const hasActiveFilters = !!(
    provider || account || region || timeRange !== '7d'
    || selectedClients.length || selectedTenants.length || selectedAccounts.length
  );

  const providerOptions = useMemo(() => {
    if (accounts.length === 0) return STATIC_PROVIDER_OPTIONS;
    return [...new Set(accounts.map(a => a.provider))].map(p => ({ value: p, label: p }));
  }, [accounts]);

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

  const filterSummary = useMemo(() => {
    const parts = [];
    if (provider) parts.push(provider);
    if (account) {
      const acctLabel = accounts.find(a => a.account === account)?.display || account;
      parts.push(acctLabel);
    }
    if (region) parts.push(region);
    return parts.length ? parts.join(' › ') : null;
  }, [provider, account, region, accounts]);

  const value = {
    provider, account, region, timeRange,
    selectedClients, selectedTenants, selectedAccounts,
    clients,
    setFilter, clearAll,
    hasActiveFilters, filterSummary,
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
