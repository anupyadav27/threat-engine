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
 * Proxy calls:   http://NLB/vulnerability/api/v1/scans/?agent_id=xxx&api_key=xxx
 */

const NLB_URL = 'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';
const API_KEY = process.env.NEXT_PUBLIC_VULN_API_KEY || 'your-secret-api-key';

export async function GET(request, { params }) {
  try {
    const pathParts = (await params).path; // e.g. ['v1', 'scans'] or ['v1', 'vulnerabilities', 'stats', 'severity']
    const { searchParams } = new URL(request.url);
    searchParams.set('api_key', API_KEY);

    // Add trailing slash only for collection endpoints (single path segment).
    // Sub-resource and stats paths (e.g. scans/{id}/vulnerabilities,
    // vulnerabilities/stats/severity) are registered WITHOUT trailing slash
    // and would 307 if we added one.
    const isCollection = pathParts.length === 1;
    const trailingSlash = isCollection ? '/' : '';
    const targetUrl = `${NLB_URL}/vulnerability/api/v1/${pathParts.join('/')}${trailingSlash}?${searchParams}`;

    const res = await fetch(targetUrl, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`,
      },
      // Node.js fetch follows redirects server-side — no CORS issues
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
