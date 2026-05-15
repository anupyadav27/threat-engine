// /api/auth/me — proxies to the Django backend server-side.
// The browser calls /ui/api/auth/me with credentials:'include', this route
// forwards the access_token cookie to Django and returns the response as-is.
// For local-dev with NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH=1, returns a fake session.

import { NextResponse } from 'next/server';

const DJANGO_BACKEND_URL =
  process.env.CSPM_BACKEND_URL ||
  'http://cspm-backend.threat-engine-engines.svc.cluster.local';

export async function GET(request) {
  if (process.env.NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH === '1') {
    return NextResponse.json({
      user: {
        id: 'local-dev',
        email: 'local-dev@example.com',
        name: 'Local Dev',
        roles: ['platform_admin'],
        permissions: [
          'platform:admin',
          'threat:read', 'threat:write',
          'inventory:read', 'inventory:write',
          'check:read', 'compliance:read',
          'iam:read', 'datasec:read',
          'cdr:read', 'cwpp:read',
          'container_security:read', 'database_security:read',
          'ai_security:read', 'encryption:read',
          'network:read', 'risk:read',
          'discoveries:read', 'cloud_accounts:read', 'cloud_accounts:write',
          'scans:create', 'scans:read', 'scans:write',
          'secops:read', 'vulnerability:read',
          'billing:read',
        ],
      },
      tenants: [
        { tenant_id: 'default-tenant', engine_tenant_id: 'default-tenant', name: 'Default Tenant' },
      ],
      customerId: null,
      permissions: [
        'platform:admin',
        'threat:read', 'inventory:read', 'check:read',
        'iam:read', 'datasec:read', 'cdr:read', 'cwpp:read',
        'container_security:read', 'database_security:read',
        'ai_security:read', 'encryption:read', 'network:read',
        'risk:read', 'discoveries:read', 'compliance:read',
        'scans:read', 'secops:read', 'vulnerability:read',
      ],
      expiresIn: 86400,
    });
  }

  // Server-side proxy to Django — forwards access_token cookie so Django can
  // validate the session. Returns Django's response (200 with user data, or
  // 401 if the session is expired/missing).
  try {
    const cookieHeader = request.headers.get('cookie') || '';
    const res = await fetch(`${DJANGO_BACKEND_URL}/api/auth/me/`, {
      headers: { cookie: cookieHeader },
      // No credentials:'include' needed — this is a server-side fetch
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
