/**
 * BFF-Only Frontend Rule (CSPM_CONSTITUTION §4.5 UI-Backend Contract)
 *
 * The frontend may only fetch:
 *   - /gateway/api/v1/views/* (BFF views)
 *   - /gateway/api/v1/asset-context/* (gateway-native aggregator)
 *   - paths in ALLOWED_DIRECT_ENGINE_BYPASSES below
 *
 * Adding a new entry here requires a bmad-architect-signed ADR.
 * Each entry MUST cite the ADR or spin-off story that justifies it.
 *
 * Source of truth for this list: see CSPM_CONSTITUTION §4.5 verdict table.
 */
export const ALLOWED_DIRECT_ENGINE_BYPASSES = [
  // ─── Auth handshake (PERMANENT exception, ADR §3.1.c) ────────────────────
  // Cookies set during these calls cannot be proxied without session forwarding.
  '/cspm/api/auth/login',
  '/cspm/api/auth/logout',
  '/cspm/api/auth/me',
  '/cspm/api/auth/csrf',
  '/cspm/api/auth/google/login',
  '/cspm/api/auth/google/callback',
  '/cspm/api/auth/saml',
  '/cspm/api/auth/register',
  '/cspm/api/auth/invite/accept',
  '/cspm/api/auth/change-password',

  // ─── Public bootstrap (PERMANENT) ────────────────────────────────────────
  // Pre-session — protected by HMAC at the engine.
  '/api/v1/agents/bootstrap',

  // ─── Stripe webhook (PERMANENT) ──────────────────────────────────────────
  // External webhook with Stripe-Signature HMAC verification.
  '/api/v1/billing/webhooks/stripe',

  // ─── DEFERRED: tenant/user/profile via Django (STORY-CSPM-TENANT-USER-MIGRATION)
  '/cspm/api/tenants',
  '/cspm/api/users',
  '/cspm/api/v1/tenants',
  '/cspm/api/profile',

  // ─── DEFERRED: onboarding writes (STORY-ONBOARDING-WRITE-BFF-MIGRATION)
  '/onboarding/api/v1/cloud-accounts',
  '/onboarding/api/v1/validate-credentials',
  '/onboarding/api/v1/agent-token',
  '/onboarding/api/v1/log-sources',
  '/onboarding/api/v1/aws/cloudformation-template',

  // ─── DEFERRED: vulnerability + sbom (STORY-VULN-BFF-MIGRATION, STORY-SBOM-BFF-MIGRATION)
  // Blocked on JNY-15 engine Pydantic schemas; migrate as engines adopt response_model=.
  '/vulnerability/api/v1',
  '/sbom/api/v1',
];

/**
 * Runtime helper: returns true if `url` is allowed by the BFF-only rule.
 * Used in dev tooling (tests, console-warn shims). The build-time gate is
 * the ESLint rule in `.eslintrc.json` — this helper is for runtime checks.
 *
 * @param {string} url
 * @returns {boolean}
 */
export function isAllowedBypass(url) {
  return ALLOWED_DIRECT_ENGINE_BYPASSES.some((prefix) => url.startsWith(prefix));
}
