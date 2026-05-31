/**
 * Local-dev gateway proxy — injects synthetic X-Auth-Context so the
 * production NLB gateway accepts requests without a real session cookie.
 *
 * Only active when NEXT_PUBLIC_GATEWAY_URL is set to this proxy prefix
 * (see next.config.js — activated when LOCAL_DEV_BYPASS_AUTH=1).
 *
 * The gateway's AuthMiddleware trusts an incoming X-Auth-Context header
 * directly (internal service-to-service path, middleware.py:89-102).
 */

const NLB =
  process.env.NEXT_PUBLIC_NLB_URL ||
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';

const LOCAL_DEV_TENANT = process.env.LOCAL_DEV_TENANT_ID || 'my-tenant';
const LOCAL_DEV_USER   = process.env.LOCAL_DEV_USER_ID   || 'local-dev';
const LOCAL_DEV_EMAIL  = process.env.LOCAL_DEV_EMAIL      || 'local-dev@example.com';

const SYNTHETIC_AUTH_CTX = JSON.stringify({
  user_id:          LOCAL_DEV_USER,
  email:            LOCAL_DEV_EMAIL,
  role:             'platform_admin',
  level:            1,
  scope_level:      'platform',
  org_ids:          null,
  tenant_ids:       null,
  account_ids:      null,
  engine_tenant_id: LOCAL_DEV_TENANT,
  permissions: [
    'account:threats:read',
    'ai_security:read',        'ai_security:write',
    'api_security:read',       'api_security:write',
    'attack_path:read',        'attack_path:write',
    'billing:read',            'billing:write',
    'cdr:read',                'cdr:sensitive',
    'check:read',              'check:write',
    'cloud_accounts:read',     'cloud_accounts:write',
    'compliance:read',         'compliance:write',
    'container_security:read', 'container_security:write',
    'cwpp:read',               'cwpp:write',
    'database_security:read',  'database_security:write',
    'datasec:read',            'datasec:write',
    'discoveries:read',        'discoveries:write',
    'encryption:read',         'encryption:write',
    'iam:read',                'iam:write',
    'inventory:read',          'inventory:write',
    'network:read',            'network:write',
    'platform:admin',
    'risk:read',               'risk:write',
    'scans:create',            'scans:read',   'scans:write',
    'secops:read',             'secops:write',
    'tenants:read',            'tenants:write',
    'threat:read',             'threat:write',
    'vulnerability:read',      'vulnerability:write',
  ],
});

async function proxy(request, { params }) {
  const pathParts = (await params).path;
  const { search } = new URL(request.url);

  // Reconstruct /gateway/api/... path from the catch-all segments
  const upstreamPath = '/gateway/api/' + pathParts.join('/') + search;
  const targetUrl = `${NLB}${upstreamPath}`;

  const fwdHeaders = { 'x-auth-context': SYNTHETIC_AUTH_CTX };
  for (const h of ['content-type', 'accept', 'x-tenant-id']) {
    const v = request.headers.get(h);
    if (v) fwdHeaders[h] = v;
  }

  let body;
  if (!['GET', 'HEAD'].includes(request.method)) {
    body = await request.arrayBuffer();
  }

  try {
    const upstream = await fetch(targetUrl, {
      method:  request.method,
      headers: fwdHeaders,
      body,
    });
    const data = await upstream.arrayBuffer();
    const respHeaders = {};
    const ct = upstream.headers.get('content-type');
    if (ct) respHeaders['Content-Type'] = ct;
    return new Response(data, { status: upstream.status, headers: respHeaders });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: 'local-gw proxy error', detail: err.message }),
      { status: 502, headers: { 'Content-Type': 'application/json' } },
    );
  }
}

export const GET    = proxy;
export const POST   = proxy;
export const PUT    = proxy;
export const PATCH  = proxy;
export const DELETE = proxy;
