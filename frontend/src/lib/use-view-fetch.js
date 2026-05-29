'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { fetchView } from './api';
import { useAuth } from './auth-context';
import { useGlobalFilter } from './global-filter-context';

/**
 * useViewFetch — fetch a BFF view with global filters.
 *
 * The BFF resolves tenant_id server-side from the X-Auth-Context header.
 * This hook only passes provider/account/region scope filters.
 *
 * @param {string} viewName  - BFF view name (e.g. 'dashboard', 'threats')
 * @param {object} extraParams - Additional query params merged into every request
 */
export function useViewFetch(viewName, extraParams = {}) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const { selectedTenant } = useAuth();
  const { provider, account, region } = useGlobalFilter();

  // Stable ref for extraParams to avoid unnecessary re-fetches
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
  }, [viewName, selectedTenant, provider, account, region]);

  useEffect(() => {
    doFetch();
  }, [doFetch]);

  return { data: data || {}, loading, error, refetch: doFetch };
}

export default useViewFetch;
