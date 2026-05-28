'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { fetchView } from './api';
import { useAuth } from './auth-context';
import { useGlobalFilter } from './global-filter-context';

/**
 * useViewFetch — fetch a BFF view with global scope filters.
 *
 * Automatically injects tenant_ids and account_ids from the scope bar so every
 * page gets multi-tenant / multi-account filtering for free.
 *
 * @param {string} viewName   - BFF view name (e.g. 'dashboard', 'threats')
 * @param {object} extraParams - Additional query params merged into every request
 */
export function useViewFetch(viewName, extraParams = {}) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const { selectedTenant } = useAuth();
  const { provider, account, region, selectedTenants, selectedAccounts } = useGlobalFilter();

  const extraRef = useRef(extraParams);
  extraRef.current = extraParams;

  const doFetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {
        ...(provider  ? { provider }  : {}),
        ...(account   ? { account }   : {}),
        ...(region    ? { region }    : {}),
        // Scope bar: pass comma-joined lists; BFF reads via scope_utils.py
        ...(selectedTenants.length  ? { tenant_ids:  selectedTenants.join(',')  } : {}),
        ...(selectedAccounts.length ? { account_ids: selectedAccounts.join(',') } : {}),
        ...extraRef.current,
      };
      const result = await fetchView(viewName, params);
      if (result?.error) {
        setError(result.error);
        setData(null);
      } else {
        setData(result || {});
      }
    } catch (err) {
      setError(err?.message || 'Failed to load data');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [viewName, selectedTenant, provider, account, region, selectedTenants, selectedAccounts]);

  useEffect(() => {
    doFetch();
  }, [doFetch]);

  return { data: data || {}, loading, error, refetch: doFetch };
}

export default useViewFetch;
