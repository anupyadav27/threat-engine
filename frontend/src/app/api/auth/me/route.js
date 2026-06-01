// /api/auth/me — proxies to the Django backend server-side.
// The browser calls /ui/api/auth/me with credentials:'include', this route
// forwards the access_token cookie to Django and returns the response as-is.
// For local-dev with NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH=1, returns a fake session.

import { NextResponse } from 'next/server';

const DJANGO_BACKEND_URL =
  process.env.CSPM_BACKEND_URL ||
  'http://cspm-backend.threat-engine-engines.svc.cluster.local';

const LOCAL_DEV_BYPASS =
  process.env.LOCAL_DEV_BYPASS_AUTH === '1' ||
  process.env.NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH === '1';

const FAKE_SESSION = {
  user: {
    id: 'local-dev',
    email: 'local-dev@example.com',
    name: 'Local Dev',
    role: 'tenant_admin',
    roles: ['tenant_admin'],
    level: 4,
    permissions: [
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
      'risk:read',               'risk:write',
      'scans:create',            'scans:read',   'scans:write',
      'secops:read',             'secops:write',
      'tenants:read',            'tenants:write',
      'threat:read',             'threat:write',
      'vulnerability:read',      'vulnerability:write',
    ],
    tenants: [
      {
        tenant_id: 'my-tenant',
        engine_tenant_id: 'my-tenant',
        tenant_name: 'My Tenant',
        name: 'My Tenant',
        status: 'active',
        account_count: 3,
        tenant_type: 'standard',
      },
    ],
    customer_id: 'local-dev-customer',
  },
  customerId: 'local-dev-customer',
  expiresIn: 86400,
};

export async function GET(request) {
  if (LOCAL_DEV_BYPASS) {
    return NextResponse.json(FAKE_SESSION);
  }

  // Server-side proxy to Django — forwards access_token cookie so Django can
  // validate the session. Returns Django's response (200 with user data, or
  // 401 if the session is expired/missing).
  try {
    const cookieHeader = request.headers.get('cookie') || '';
    const res = await fetch(`${DJANGO_BACKEND_URL}/api/auth/me/`, {
      headers: { cookie: cookieHeader },
      signal: AbortSignal.timeout(5000), // fail fast — don't hang for 30s
    });

    let data;
    try {
      data = await res.json();
    } catch {
      data = { detail: 'invalid response from auth service' };
    }

    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: 'auth service unreachable' },
      { status: 503 },
    );
  }
}
