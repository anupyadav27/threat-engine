'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { fetchView } from './api';
import { TENANT_ID } from './constants';
import { useAuth } from './auth-context';
import { useGlobalFilter } from './global-filter-context';

/**
 * useViewFetch — fetch a BFF view with runtime tenant_id + global filters.
 *
 * Reads tenant_id from the auth session at runtime (not the build-time env var),
 * merges global provider/account/region filters, and exposes { data, loading, error, refetch }.
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
      const tenantId = selectedTenant || TENANT_ID || 'default-tenant';
      const params = {
        tenant_id: tenantId,
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
