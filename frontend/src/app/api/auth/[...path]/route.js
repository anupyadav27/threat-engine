/**
 * Server-side proxy for Django cspm-backend auth endpoints.
 *
 * Browser calls /api/auth/* → this handler → cspm-backend (cluster-internal).
 * AUTH_URL in auth-context.js is '' so all auth fetch calls are already relative.
 *
 * Cookie handling notes:
 *  - Django sets access_token with Secure flag (DEBUG=False).
 *  - Portal runs over HTTP, so browsers silently drop Secure cookies.
 *  - We strip the Secure flag here so the cookie reaches the browser.
 *  - SameSite is relaxed to Lax (Strict blocks normal page navigations).
 *
 * Env vars:
 *   CSPM_BACKEND_URL  — cluster-internal Django URL (set in K8s deployment)
 *   Falls back to http://cspm-backend (cluster-DNS shortname).
 */

const BACKEND = process.env.CSPM_BACKEND_URL || 'http://cspm-backend';

const LOCAL_DEV_BYPASS =
  process.env.LOCAL_DEV_BYPASS_AUTH === '1' ||
  process.env.NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH === '1';

const FAKE_SESSION = {
  user: {
    id: 'local-dev',
    email: 'local-dev@example.com',
    name: 'Local Dev',
    role: 'platform_admin',
    roles: ['platform_admin'],
    level: 1,
    tenants: [
      { tenant_id: 'default-tenant', engine_tenant_id: 'default-tenant', name: 'Default Tenant' },
    ],
    permissions: [
      'platform:admin',
      'attack_path:read', 'attack_path:write',
      'ai_security:read', 'api_security:read', 'billing:read', 'cdr:read', 'cdr:sensitive',
      'check:read', 'cloud_accounts:read', 'compliance:read', 'container_security:read',
      'cwpp:read', 'database_security:read', 'datasec:read', 'discoveries:read',
      'encryption:read', 'iam:read', 'inventory:read', 'network:read', 'risk:read',
      'scans:create', 'scans:read', 'secops:read', 'tenants:read', 'threat:read',
      'vulnerability:read',
    ],
  },
  tenants: [
    { tenant_id: 'default-tenant', engine_tenant_id: 'default-tenant', name: 'Default Tenant' },
  ],
  customerId: 'local-dev',
  permissions: [
    'platform:admin',
    'attack_path:read', 'ai_security:read', 'api_security:read', 'billing:read',
    'cdr:read', 'check:read', 'cloud_accounts:read', 'compliance:read',
    'container_security:read', 'cwpp:read', 'database_security:read', 'datasec:read',
    'discoveries:read', 'encryption:read', 'iam:read', 'inventory:read', 'network:read',
    'risk:read', 'scans:read', 'secops:read', 'tenants:read', 'threat:read',
    'vulnerability:read',
  ],
  expiresIn: 86400,
};

const FORWARD_REQ_HEADERS = ['content-type', 'cookie', 'authorization', 'x-csrftoken'];

function stripSecureFromCookie(setCookieHeader) {
  return setCookieHeader
    .replace(/;\s*Secure/gi, '')
    .replace(/SameSite=Strict/gi, 'SameSite=Lax');
}

async function proxy(request, { params }) {
  const pathParts = (await params).path;

  // Local dev bypass — return fake session for /me without hitting Django.
  if (LOCAL_DEV_BYPASS && pathParts.join('/') === 'me') {
    return new Response(JSON.stringify(FAKE_SESSION), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const { searchParams } = new URL(request.url);
  const qs = searchParams.toString();
  const targetPath = `/api/auth/${pathParts.join('/')}/${qs ? `?${qs}` : ''}`;
  const targetUrl = `${BACKEND}${targetPath}`;

  const reqHeaders = {};
  for (const h of FORWARD_REQ_HEADERS) {
    const v = request.headers.get(h);
    if (v) reqHeaders[h] = v;
  }

  let body;
  const method = request.method;
  if (!['GET', 'HEAD'].includes(method)) {
    body = await request.arrayBuffer();
  }

  try {
    const upstream = await fetch(targetUrl, { method, headers: reqHeaders, body, redirect: 'manual' });

    // Build response headers — must support multiple Set-Cookie values.
    // Use raw [key, value] pairs so duplicates aren't collapsed.
    const headerPairs = [];

    const ct = upstream.headers.get('content-type');
    if (ct) headerPairs.push(['Content-Type', ct]);

    // Forward every Set-Cookie header, stripping Secure so it works over HTTP.
    // Node.js fetch collapses repeated headers with ", " — split on ", " for
    // cookies that are genuinely comma-less (cookie values don't contain commas).
    const rawSetCookie = upstream.headers.get('set-cookie');
    if (rawSetCookie) {
      // Heuristic split: each cookie starts with a known name pattern.
      // More robust: split on the cookie boundary (name=value; ...).
      const cookieParts = rawSetCookie.split(/,\s*(?=[a-zA-Z_][^=]+=)/);
      for (const cookie of cookieParts) {
        headerPairs.push(['Set-Cookie', stripSecureFromCookie(cookie.trim())]);
      }
    }

    const respBody = await upstream.arrayBuffer();
    return new Response(respBody, {
      status: upstream.status,
      headers: headerPairs,
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Auth proxy error', detail: err.message }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
