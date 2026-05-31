/**
 * Server-side proxy for the Vulnerability Engine API.
 *
 * Why this exists:
 *  - Next.js rewrites strip trailing slashes from :path* before forwarding.
 *  - FastAPI routes are defined WITH trailing slashes (e.g. /api/v1/scans/).
 *  - Without the slash, FastAPI 307-redirects to the slash version, but the
 *    Location header points to the NLB directly (nginx ingress strips the
 *    /vulnerability prefix), so the browser gets a 404.
 *
 * This proxy runs server-side (Node.js):
 *  - No CORS issues
 *  - Adds trailing slash explicitly before forwarding
 *  - Follows 307 redirects correctly on the server
 *
 * Client calls:  /ui/api/vuln/v1/scans?agent_id=xxx
 * Proxy calls:   http://NLB/vulnerability/api/v1/scans/?agent_id=xxx  (X-API-Key header added server-side)
 */

const CLUSTER_NLB =
  process.env.NEXT_PUBLIC_NLB_URL ||
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';

const DJANGO_BACKEND_URL =
  process.env.CSPM_BACKEND_URL ||
  'http://cspm-backend.threat-engine-engines.svc.cluster.local';

const PLATFORM_ROLES = new Set(['platform_admin', 'org_admin']);

/**
 * Resolve the tenant scope AND permissions for the current session SERVER-SIDE.
 *
 * Validates the access_token cookie against Django and derives both the tenant
 * the caller is allowed to see and their permission set. The client never
 * controls either, so a user cannot read another tenant's vulnerabilities by
 * forging a query param, nor bypass RBAC.
 *
 * Returns:
 *   { ok: true, tenantId: string|null, permissions: string[], authContext: object }
 *   { ok: false }   // session invalid → caller should 401
 */
async function resolveTenantScope(request) {
  const cookie = request.headers.get('cookie') || '';
  if (!cookie.includes('access_token')) {
    return { ok: false };
  }
  try {
    const meRes = await fetch(`${DJANGO_BACKEND_URL}/api/auth/me`, {
      headers: { cookie },
    });
    if (!meRes.ok) return { ok: false };
    const session = await meRes.json();

    // Real Django /api/auth/me returns role/roles/level at the top level;
    // the local-dev FAKE_SESSION nests them under `user`. Support both.
    const u = session?.user || {};
    const roles = session?.roles || u.roles ||
      (session?.role ? [session.role] : (u.role ? [u.role] : []));
    const role = session?.role || u.role || (roles[0] || '');
    const level = session?.level != null ? session.level : u.level;
    const permissions = session?.permissions || u.permissions || [];
    const isPlatform = roles.some(r => PLATFORM_ROLES.has(r)) ||
      (level != null && level <= 2);

    const tenants = session?.tenants || [];
    const tenantId = isPlatform
      // Platform/org admins see all tenants unless they actively selected one.
      ? (request.headers.get('x-active-tenant-id') || null)
      // Tenant-scoped user: force their own tenant, ignore any client input.
      : (tenants[0]?.engine_tenant_id || tenants[0]?.tenant_id || null);

    // Build the X-Auth-Context the engine's require_vuln_read expects.
    const scopeLevel = level === 1 ? 'platform' : level === 2 ? 'organization'
      : level === 5 ? 'account' : 'tenant';
    const authContext = {
      user_id: session?.id || u.id || '',
      email: session?.email || u.email || '',
      role,
      level: level != null ? level : 4,
      scope_level: scopeLevel,
      permissions,
      tenant_ids: isPlatform ? null : tenants.map(t => t.engine_tenant_id || t.tenant_id),
      engine_tenant_id: tenantId,
    };

    return { ok: true, tenantId, permissions, authContext };
  } catch {
    return { ok: false };
  }
}

function buildTargetUrl(NLB_URL, pathParts, searchParams) {
  const isCollection = pathParts.length === 1;
  const trailingSlash = isCollection ? '/' : '';
  const qs = searchParams.toString();
  return `${NLB_URL}/vulnerability/api/v1/${pathParts.join('/')}${trailingSlash}${qs ? `?${qs}` : ''}`;
}

// Engine paths that return tenant-scoped vulnerability data and must be filtered.
// Agent registration/scan submission use their own Bearer auth and are excluded.
function needsTenantScope(pathParts) {
  const p = pathParts.join('/');
  return p.startsWith('vulnerabilities') || p.startsWith('scans');
}

export async function GET(request, { params }) {
  const NLB_URL = process.env.NLB_URL || process.env.NEXT_PUBLIC_GATEWAY_URL || CLUSTER_NLB;
  // VULN_API_KEY (no NEXT_PUBLIC_ prefix) — server-side only, never exposed to browser
  const API_KEY = process.env.VULN_API_KEY || process.env.NEXT_PUBLIC_VULN_API_KEY || 'threat-engine-internal-key';

  try {
    const pathParts = (await params).path;
    const { searchParams } = new URL(request.url);

    // Extra headers forwarded to the engine (X-Auth-Context for engine-side RBAC).
    const fwdHeaders = { 'Content-Type': 'application/json', 'X-API-Key': API_KEY };

    // Enforce tenant isolation + RBAC server-side on data endpoints.
    if (needsTenantScope(pathParts)) {
      const scope = await resolveTenantScope(request);
      if (!scope.ok) {
        return new Response(JSON.stringify({ error: 'Authentication required' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      // RBAC at the edge: require vulnerability:read (defense in depth — the
      // engine also enforces this from the forwarded X-Auth-Context).
      if (!scope.permissions.includes('vulnerability:read')) {
        return new Response(JSON.stringify({ error: 'Permission denied: requires vulnerability:read' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      // Strip any client-supplied tenant_id, then inject the server-derived one.
      searchParams.delete('tenant_id');
      if (scope.tenantId) {
        searchParams.set('tenant_id', scope.tenantId);
      }
      // Forward the validated auth context so the engine enforces RBAC too.
      fwdHeaders['X-Auth-Context'] = JSON.stringify(scope.authContext);
    }

    const targetUrl = buildTargetUrl(NLB_URL, pathParts, searchParams);

    const res = await fetch(targetUrl, {
      headers: fwdHeaders,
    });

    if (!res.ok) {
      return new Response(JSON.stringify({ error: `Upstream ${res.status}` }), {
        status: res.status,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const data = await res.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export async function PATCH(request, { params }) {
  const NLB_URL = process.env.NLB_URL || process.env.NEXT_PUBLIC_GATEWAY_URL || CLUSTER_NLB;
  const API_KEY = process.env.VULN_API_KEY || process.env.NEXT_PUBLIC_VULN_API_KEY || 'threat-engine-internal-key';

  try {
    const pathParts = (await params).path;
    const { searchParams } = new URL(request.url);
    const qs = searchParams.toString();
    // Sub-resource paths (e.g. scans/{id}/cancel) never get trailing slash
    const targetUrl = `${NLB_URL}/vulnerability/api/v1/${pathParts.join('/')}${qs ? `?${qs}` : ''}`;

    const body = await request.text().catch(() => '');
    const res = await fetch(targetUrl, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
      ...(body ? { body } : {}),
    });

    if (!res.ok) {
      return new Response(JSON.stringify({ error: `Upstream ${res.status}` }), {
        status: res.status,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const data = await res.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
