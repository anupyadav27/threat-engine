/** @type {import('next').NextConfig} */

// NLB endpoint — used by Next.js rewrites to proxy API calls in local development.
// In production (Docker build), NEXT_PUBLIC_API_BASE is baked in and the browser
// calls the NLB directly, so these rewrites are never hit.
//
// Override for local development:
//   Create ui_samples/.env.local and set:
//   NEXT_PUBLIC_GATEWAY_URL=http://localhost:8000
// This routes all engine/BFF calls to a locally-running API gateway.
const NLB_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL ||
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';

// All engine prefixes that the nginx ingress routes on the cluster
const ENGINE_PREFIXES = [
  'onboarding',
  'discoveries',
  'check',
  'inventory',
  'threat',
  'compliance',
  'iam',
  'datasec',
  'secops',
  'risk',
  'rule',
  'gateway',
  'cspm',       // Django CSPM backend
  'vulnerability', // Vulnerability engine (port 8000, /vulnerability ingress)
];

const nextConfig = {
  reactStrictMode: true,
  basePath: process.env.NODE_ENV === 'production' ? '/ui' : '',
  output: 'standalone',
  // Prevent Next.js from stripping trailing slashes before rewrites run.
  // Without this, /secops/.../sbom/ gets 308-redirected to /sbom (no slash),
  // which then causes the FastAPI backend to 307-redirect back with a broken
  // Location header that nginx cannot route correctly.
  skipTrailingSlashRedirect: true,
  // Allow the preview/headless browser to load /_next/* resources from 127.0.0.1
  allowedDevOrigins: ['127.0.0.1', 'localhost'],

  // Proxy engine API paths to the NLB so the browser never makes cross-origin
  // requests during local development. basePath: false keeps paths at root (no /ui prefix).
  async rewrites() {
    // Only rewrite API calls (paths containing /api/), not page routes.
    // This prevents collisions with Next.js page routes like /compliance, /risk, /inventory.
    const engineRewrites = ENGINE_PREFIXES.map((prefix) => ({
      source: `/${prefix}/api/:path*`,
      destination: `${NLB_URL}/${prefix}/api/:path*`,
      basePath: false,
    }));

    // The Django CSPM backend sits behind an nginx ingress that strips the /cspm
    // prefix (rewrite-target: /$2). When Django issues redirects, the Location
    // header uses its own URL space (/api/auth/me) without the /cspm prefix.
    // This catch-all maps those redirected paths back to the NLB with /cspm.
    const djangoRedirectRewrites = [
      {
        source: '/api/:path*',
        destination: `${NLB_URL}/cspm/api/:path*`,
        basePath: false,
      },
    ];

    // Django catch-all (/api/*) moves to afterFiles so that local Next.js API
    // route handlers (e.g. /api/bff/*) are served from the file system first.
    // beforeFiles still handles the engine prefixes (gateway, compliance, etc.).
    return {
      beforeFiles: [...engineRewrites],
      afterFiles:  [...djangoRedirectRewrites],
    };
  },
};

module.exports = nextConfig;
