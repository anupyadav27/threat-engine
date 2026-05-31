/**
 * Server-side proxy for the SBOM engine.
 *
 * Routes /api/sbom/* → ${NLB_URL}/sbom/api/v1/*
 *
 * Returns 200 with empty data when the SBOM engine is not deployed (503/404)
 * so the browser never logs a console error for a missing service.
 */

const SCA_API_KEY = 'sbom-api-key-2024';

const EMPTY_RESPONSES = {
  '/sbom': { sboms: [], total: 0 },
  default: null,
};

export async function GET(request, { params }) {
  const NLB_URL =
    process.env.NLB_URL ||
    process.env.NEXT_PUBLIC_NLB_URL ||
    'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';

  try {
    const pathParts = (await params).path;
    const { searchParams } = new URL(request.url);
    const qs = searchParams.toString();
    const targetUrl = `${NLB_URL}/sbom/api/v1/${pathParts.join('/')}${qs ? `?${qs}` : ''}`;

    const res = await fetch(targetUrl, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': SCA_API_KEY,
      },
    });

    if (!res.ok) {
      const emptyKey = `/${pathParts[0]}`;
      const emptyData = EMPTY_RESPONSES[emptyKey] ?? EMPTY_RESPONSES.default ?? [];
      return new Response(JSON.stringify(emptyData), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const data = await res.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch {
    const pathParts = (await params).path;
    const emptyKey = `/${pathParts[0]}`;
    const emptyData = EMPTY_RESPONSES[emptyKey] ?? EMPTY_RESPONSES.default ?? [];
    return new Response(JSON.stringify(emptyData), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
