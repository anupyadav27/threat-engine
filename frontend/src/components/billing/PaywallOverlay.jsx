'use client';

import { useSearchParams, useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';

/**
 * PaywallOverlay — renders a full-screen blocking overlay when the URL
 * contains ?paywall=true.
 *
 * Role-aware content:
 *   level <= 2 (platform_admin=1, org_admin=2): "Upgrade Now" CTA that
 *     POSTs to /gateway/api/v1/billing/checkout and redirects to checkout_url.
 *   level >= 4 (tenant_admin=4, analyst=4, viewer=4): read-only message to
 *     contact their org admin.
 *
 * The overlay does not render on the billing page itself — the skip-list in
 * fetchInterceptor.js prevents the interceptor from ever redirecting to
 * /billing?paywall=true while already on /billing, so this is defense-in-depth.
 *
 * SEC-07: "Upgrade Now" POST is to a hardcoded gateway path — no user-supplied
 *         URL in the checkout request.
 * SEC-08: checkout_url is used only for window.location.href — no DOM injection.
 */
export default function PaywallOverlay() {
  const params = useSearchParams();
  const router = useRouter();
  const { level } = useAuth();

  if (params.get('paywall') !== 'true') return null;

  // level from auth-context: 1=platform_admin, 2=org_admin, 4=tenant_admin/analyst/viewer
  const isAdmin = level <= 2;

  async function handleUpgrade() {
    try {
      // SEC-07: hardcoded path only — no user-supplied URL
      const resp = await fetch('/gateway/api/v1/billing/checkout', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (resp.ok) {
        const data = await resp.json();
        // SEC-08: checkout_url assigned to href only — no innerHTML/eval
        if (data?.checkout_url) {
          window.location.href = data.checkout_url;
          return;
        }
      }
    } catch {
      // Fall through to billing page on network/parse error
    }
    router.push('/billing');
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        backdropFilter: 'blur(4px)',
        backgroundColor: 'rgba(0,0,0,0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
      role="dialog"
      aria-modal="true"
      aria-label="Plan upgrade required"
    >
      <div
        style={{
          backgroundColor: 'var(--bg-card, #1e293b)',
          border: '1px solid var(--border-primary, rgba(255,255,255,0.1))',
          borderRadius: 12,
          padding: '40px 36px',
          maxWidth: 440,
          width: '90%',
          textAlign: 'center',
          boxShadow: '0 25px 50px rgba(0,0,0,0.6)',
        }}
      >
        {/* Lock icon */}
        <div
          style={{
            width: 48,
            height: 48,
            borderRadius: '50%',
            backgroundColor: 'rgba(99,102,241,0.15)',
            border: '1px solid rgba(99,102,241,0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 20px',
          }}
        >
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        </div>

        <h2
          style={{
            color: 'var(--text-primary, #f8fafc)',
            fontSize: 18,
            fontWeight: 700,
            margin: '0 0 10px',
          }}
        >
          Upgrade Required
        </h2>

        <p
          style={{
            color: 'var(--text-secondary, #94a3b8)',
            fontSize: 14,
            lineHeight: 1.6,
            margin: '0 0 28px',
          }}
        >
          {isAdmin
            ? 'This feature is not included in your current plan. Upgrade to continue.'
            : 'This feature requires a higher subscription plan. Contact your organization admin to upgrade.'}
        </p>

        {isAdmin ? (
          <button
            onClick={handleUpgrade}
            style={{
              backgroundColor: '#6366f1',
              color: '#ffffff',
              border: 'none',
              borderRadius: 8,
              padding: '11px 32px',
              fontSize: 14,
              fontWeight: 600,
              cursor: 'pointer',
              width: '100%',
              transition: 'background-color 0.15s ease',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#4f46e5'; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#6366f1'; }}
          >
            Upgrade Now
          </button>
        ) : (
          <p
            style={{
              color: 'var(--text-muted, #64748b)',
              fontSize: 13,
              margin: 0,
            }}
          >
            Contact your organization admin to upgrade.
          </p>
        )}
      </div>
    </div>
  );
}
