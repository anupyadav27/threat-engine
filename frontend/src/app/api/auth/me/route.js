// Local-dev stub for /api/auth/me/.
// When NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH=1, returns a fake platform_admin
// session so the AuthGuard / auth-context don't redirect to /auth/login.
// Otherwise falls through to the next.config.js rewrite (which proxies to
// the deployed Django backend).

import { NextResponse } from 'next/server';

export async function GET() {
  if (process.env.NEXT_PUBLIC_LOCAL_DEV_BYPASS_AUTH !== '1') {
    return NextResponse.json({ detail: 'not configured' }, { status: 404 });
  }

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
        'ciem:read', 'cwpp:read',
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
    // Leave customerId null so AppShell skips the first-time-setup wizard
    // redirect (it short-circuits when !customerId).
    customerId: null,
    permissions: [
      'platform:admin',
      'threat:read', 'inventory:read', 'check:read',
      'iam:read', 'datasec:read', 'ciem:read', 'cwpp:read',
      'container_security:read', 'database_security:read',
      'ai_security:read', 'encryption:read', 'network:read',
      'risk:read', 'discoveries:read', 'compliance:read',
      'scans:read', 'secops:read', 'vulnerability:read',
    ],
    expiresIn: 86400,
  });
}
