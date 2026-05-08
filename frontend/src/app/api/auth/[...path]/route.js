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

const FORWARD_REQ_HEADERS = ['content-type', 'cookie', 'authorization', 'x-csrftoken'];

function stripSecureFromCookie(setCookieHeader) {
  return setCookieHeader
    .replace(/;\s*Secure/gi, '')
    .replace(/SameSite=Strict/gi, 'SameSite=Lax');
}

async function proxy(request, { params }) {
  const pathParts = (await params).path;
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
