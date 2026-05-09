/**
 * Global fetch interceptor — redirects 402 responses to /billing?paywall=true.
 *
 * Skip-list: paths that must never trigger a redirect:
 *   - /api/auth/        (auth endpoints — avoid redirect loop on login)
 *   - /api/v1/health    (health checks)
 *   - /api/v1/billing/webhooks/  (Stripe webhooks — server-to-server)
 *   - /argo/            (Argo Workflows UI)
 *   - /billing          (billing page itself — avoid redirect loop)
 *
 * returnUrl: derived exclusively from window.location.pathname (current page),
 * never from query string, response body, or any external input.
 * Same-origin validated before use; cross-origin paths are discarded.
 *
 * SEC-01: returnUrl from window.location.pathname only
 * SEC-02: _isSameOrigin() validates before use
 * SEC-03: skip-list prevents redirect loops
 * SEC-04: only PAYWALL_ERRORS set triggers redirect
 * SEC-05: no npm dependencies
 * SEC-06: idempotent registration guard
 */

const SKIP_PREFIXES = [
  '/api/auth/',
  '/api/v1/health',
  '/api/v1/billing/webhooks/',
  '/argo/',
  '/billing',
];

const PAYWALL_ERRORS = new Set([
  'engine_not_in_plan',
  'org_suspended',
  'subscription_expired',
  'account_blocked',
]);

function _shouldSkip(url) {
  try {
    const path = new URL(url, window.location.origin).pathname;
    return SKIP_PREFIXES.some((p) => path.startsWith(p));
  } catch {
    return false;
  }
}

function _isSameOrigin(url) {
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.origin === window.location.origin;
  } catch {
    return false;
  }
}

export function registerFetchInterceptor() {
  if (typeof window === 'undefined') return; // SSR guard
  if (window.__fetchInterceptorRegistered) return; // idempotent — SEC-06
  window.__fetchInterceptorRegistered = true;

  const _originalFetch = window.fetch.bind(window);

  window.fetch = async function interceptedFetch(input, init) {
    const url = typeof input === 'string' ? input : input?.url ?? '';

    if (_shouldSkip(url)) {
      return _originalFetch(input, init);
    }

    const response = await _originalFetch(input, init);

    if (response.status === 402) {
      // Clone before reading body — response body can only be consumed once
      const cloned = response.clone();
      try {
        const body = await cloned.json();
        if (PAYWALL_ERRORS.has(body?.error)) {
          // SEC-01: returnUrl derived from current path only — never from
          // query params, response body, or any external source.
          const returnPath = window.location.pathname;
          // SEC-02: same-origin validation before use
          const safeReturn = _isSameOrigin(window.location.origin + returnPath)
            ? encodeURIComponent(returnPath)
            : '';
          const dest = safeReturn
            ? `/billing?paywall=true&returnUrl=${safeReturn}`
            : '/billing?paywall=true';
          window.location.href = dest;
        }
      } catch {
        // Non-JSON 402 — pass through without redirect
      }
    }

    return response;
  };
}
