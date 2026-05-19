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

function buildTargetUrl(NLB_URL, pathParts, searchParams) {
  const isCollection = pathParts.length === 1;
  const trailingSlash = isCollection ? '/' : '';
  const qs = searchParams.toString();
  return `${NLB_URL}/vulnerability/api/v1/${pathParts.join('/')}${trailingSlash}${qs ? `?${qs}` : ''}`;
}

export async function GET(request, { params }) {
  const NLB_URL = process.env.NLB_URL || process.env.NEXT_PUBLIC_GATEWAY_URL || CLUSTER_NLB;
  const API_KEY = process.env.NEXT_PUBLIC_VULN_API_KEY || 'threat-engine-internal-key';

  try {
    const pathParts = (await params).path;
    const { searchParams } = new URL(request.url);
    const targetUrl = buildTargetUrl(NLB_URL, pathParts, searchParams);

    const res = await fetch(targetUrl, {
      headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
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
  const API_KEY = process.env.NEXT_PUBLIC_VULN_API_KEY || 'threat-engine-internal-key';

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
