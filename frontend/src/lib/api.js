'use client';

import { API_BASE, TENANT_ID, ENGINE_ENDPOINTS, CSP_DEFAULT, SCAN_ID_DEFAULT } from './constants';

/**
 * Build a URL from a path string. Handles both absolute (production) and
 * relative (local dev with Next.js rewrites) API_BASE values.
 */
function makeUrl(path) {
  if (path.startsWith('http')) return new URL(path);
  const origin =
    typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  return new URL(path, origin);
}

/**
 * Fetch from API with automatic tenant_id and base URL handling
 * @param {string} enginePath - Full path to endpoint (e.g., '/api/v1/threat/list')
 * @param {object} options - Fetch options (method, body, headers, etc.)
 * @returns {Promise<object>} Parsed JSON response or { error: message }
 */
export async function fetchApi(enginePath, options = {}) {
  try {
    const url = makeUrl(`${API_BASE}${enginePath}`);

    // Add tenant_id to query params if not already present
    if (TENANT_ID && !url.searchParams.has('tenant_id')) {
      url.searchParams.append('tenant_id', TENANT_ID);
    }

    const defaultHeaders = {
      'Content-Type': 'application/json',
    };

    const response = await fetch(url.toString(), {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
    });

    if (!response.ok) {
      return {
        error: `API error: ${response.status} ${response.statusText}`,
      };
    }

    return await response.json();
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : 'Unknown error occurred',
    };
  }
}

/**
 * GET request to a specific engine endpoint
 * @param {string} engine - Engine key from ENGINE_ENDPOINTS
 * @param {string} path - Path relative to engine (e.g., '/api/v1/threat/list')
 * @param {object} params - Query parameters
 * @returns {Promise<object>} API response or { error: message }
 */
export async function getFromEngine(engine, path, params = {}) {
  const enginePrefix = ENGINE_ENDPOINTS[engine];
  if (!enginePrefix) {
    return { error: `Unknown engine: ${engine}` };
  }

  const url = makeUrl(`${API_BASE}${enginePrefix}${path}`);

  // Add query parameters
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      url.searchParams.append(key, String(value));
    }
  });

  // Add tenant_id if not present
  if (TENANT_ID && !url.searchParams.has('tenant_id')) {
    url.searchParams.append('tenant_id', TENANT_ID);
  }

  try {
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      return {
        error: `API error: ${response.status} ${response.statusText}`,
      };
    }

    return await response.json();
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : 'Unknown error occurred',
    };
  }
}

/**
 * GET request to a specific engine endpoint with default CSP and scan_id params.
 * Used for IAM and DataSec which require csp and scan_id on every call.
 * @param {string} engine - Engine key from ENGINE_ENDPOINTS
 * @param {string} path - Path relative to engine
 * @param {object} extraParams - Additional query parameters (merged with csp/scan_id defaults)
 * @returns {Promise<object>} API response or { error: message }
 */
export async function getFromEngineScan(engine, path, extraParams = {}) {
  return getFromEngine(engine, path, {
    csp: CSP_DEFAULT,
    scan_id: SCAN_ID_DEFAULT,
    ...extraParams,
  });
}

/**
 * Fetch from the Django CSPM backend (includes session cookie).
 * Used for user/tenant management which lives in the Django app.
 * @param {string} path - Path relative to /cspm (e.g., '/api/users/')
 * @param {object} options - Fetch options
 */
export async function fetchFromCspm(path, options = {}) {
  try {
    const url = `${API_BASE}/cspm${path}`;
    const response = await fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...options.headers,
      },
    });
    if (!response.ok) {
      return { error: `CSPM API error: ${response.status} ${response.statusText}` };
    }
    return await response.json();
  } catch (err) {
    return { error: err instanceof Error ? err.message : 'Unknown error' };
  }
}


/**
 * Fetch a pre-built page view from the BFF layer.
 * Returns UI-ready JSON — no client-side normalization needed.
 * @param {string} page - View name (e.g., 'dashboard', 'threats', 'compliance')
 * @param {object} params - Query parameters (provider, account, region, etc.)
 * @returns {Promise<object>} UI-ready JSON or { error: message }
 */
export async function fetchView(page, params = {}) {
  return getFromEngine('gateway', `/api/v1/views/${page}`, params);
}

/**
 * POST request to a specific engine endpoint
 * @param {string} engine - Engine key from ENGINE_ENDPOINTS
 * @param {string} path - Path relative to engine (e.g., '/api/v1/threat/analyze')
 * @param {object} body - Request body
 * @returns {Promise<object>} API response or { error: message }
 */
export async function postToEngine(engine, path, body = {}) {
  const enginePrefix = ENGINE_ENDPOINTS[engine];
  if (!enginePrefix) {
    return { error: `Unknown engine: ${engine}` };
  }

  const url = makeUrl(`${API_BASE}${enginePrefix}${path}`);

  // Add tenant_id if not present
  if (TENANT_ID && !url.searchParams.has('tenant_id')) {
    url.searchParams.append('tenant_id', TENANT_ID);
  }

  try {
    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      return {
        error: `API error: ${response.status} ${response.statusText}`,
      };
    }

    return await response.json();
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : 'Unknown error occurred',
    };
  }
}
