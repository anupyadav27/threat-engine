'use client';

import { useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Shield, Eye, EyeOff, Lock, ChevronRight, AlertCircle, ArrowRight, Mail } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';

const API_BASE = process.env.NEXT_PUBLIC_AUTH_URL || process.env.NEXT_PUBLIC_API_BASE || '';

const SSO_ERROR_MAP = {
  csrf_detected:       'Request rejected — possible CSRF. Please try again.',
  oidc_cancelled:      'Sign-in was cancelled.',
  oidc_failed:         'SSO sign-in failed. Check your IDP configuration.',
  oidc_invalid_token:  'Could not verify your identity token. Please try again.',
  oidc_no_email:       'Your SSO account has no email address.',
  saml_failed:         'SAML sign-in failed. Contact your administrator.',
  google_cancelled:    'Google sign-in was cancelled.',
  google_failed:       'Google sign-in failed. Please try again.',
  google_no_email:     'Your Google account has no email address.',
  microsoft_cancelled: 'Microsoft sign-in was cancelled.',
  microsoft_failed:    'Microsoft sign-in failed. Please try again.',
  microsoft_no_email:  'Your Microsoft account has no email address.',
};

// ── Shared SVG logos ─────────────────────────────────────────────────────────

const GoogleLogo = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 48 48">
    <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.2l6.7-6.7C35.8 2.5 30.3 0 24 0 14.6 0 6.5 5.5 2.5 13.5l7.8 6C12.2 13.2 17.6 9.5 24 9.5z"/>
    <path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.2-.4-4.7H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8C43.7 37.7 46.5 31.5 46.5 24.5z"/>
    <path fill="#FBBC05" d="M10.3 28.5A14.5 14.5 0 0 1 9.5 24c0-1.6.3-3.1.8-4.5l-7.8-6A23.9 23.9 0 0 0 0 24c0 3.9.9 7.5 2.5 10.8l7.8-6.3z"/>
    <path fill="#34A853" d="M24 48c6.3 0 11.6-2.1 15.4-5.6l-7.5-5.8c-2.1 1.4-4.8 2.3-7.9 2.3-6.4 0-11.8-3.7-13.7-9l-7.8 6C6.5 42.5 14.6 48 24 48z"/>
  </svg>
);

const MicrosoftLogo = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 21 21">
    <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
    <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
    <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
    <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
  </svg>
);

// ── Input style helper ────────────────────────────────────────────────────────

const inputCss = (focused) => ({
  width: '100%', padding: '13px 16px', borderRadius: 10,
  backgroundColor: '#0d1117',
  border: `1.5px solid ${focused ? '#3b82f6' : '#1e2d3d'}`,
  color: '#f1f5f9', fontSize: 15, outline: 'none',
  transition: 'border-color 0.2s', boxSizing: 'border-box',
});

// ── Spinner ──────────────────────────────────────────────────────────────────

const Spinner = () => (
  <div style={{
    width: 15, height: 15, borderRadius: '50%',
    border: '2px solid rgba(255,255,255,0.25)', borderTopColor: 'white',
    animation: 'spin 0.65s linear infinite', flexShrink: 0,
  }} />
);

// ── Main login form ───────────────────────────────────────────────────────────

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login, isLoading } = useAuth();

  const isAdminMode = searchParams.get('method') === 'local';
  const urlError    = searchParams.get('error');
  const topError    = urlError ? (SSO_ERROR_MAP[urlError] || 'Sign-in failed. Please try again.') : '';

  // Email-first SSO lookup
  const [email, setEmail]         = useState('');
  const [ssoLoading, setSsoLoading] = useState(false);
  const [ssoError, setSsoError]   = useState('');
  const [domainOptions, setDomainOptions] = useState(null); // null = not yet looked up, {domain} = fallback

  // Admin / local form
  const [adminEmail, setAdminEmail]       = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [showPw, setShowPw]               = useState(false);
  const [rememberMe, setRememberMe]       = useState(false);
  const [localError, setLocalError]       = useState('');
  const [focused, setFocused]             = useState(null);

  const handleEmailContinue = async (e) => {
    e.preventDefault();
    setSsoError('');
    setDomainOptions(null);
    const domain = email.trim().toLowerCase().split('@')[1];
    if (!domain) { setSsoError('Enter your work email address.'); return; }
    setSsoLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/tenants/idp-by-domain/?domain=${encodeURIComponent(domain)}`);
      const data = await res.json();
      if (data.redirect_url) {
        window.location.href = `${API_BASE}${data.redirect_url}`;
        return;
      }
      // No custom IDP — prompt user to use password login
      setDomainOptions({ domain });
    } catch {
      setSsoError('Could not reach the server. Please try again.');
    } finally {
      setSsoLoading(false);
    }
  };

  const handleLocalSubmit = async (e) => {
    e.preventDefault();
    setLocalError('');
    if (!adminEmail || !adminPassword) { setLocalError('Please fill in both fields.'); return; }
    const result = await login(adminEmail, adminPassword, rememberMe);
    if (result.success) router.push('/dashboard');
    else setLocalError(result.error || 'Login failed. Please try again.');
  };

  const goGoogle    = (hd = '') => { window.location.href = hd ? `${API_BASE}/api/auth/google/login/?hd=${encodeURIComponent(hd)}` : `${API_BASE}/api/auth/google/login/`; };
  const goMicrosoft = (hint = '') => { window.location.href = hint ? `${API_BASE}/api/auth/microsoft/login/?domain_hint=${encodeURIComponent(hint)}` : `${API_BASE}/api/auth/microsoft/login/`; };

  const btnBase = {
    width: '100%', padding: '13px', borderRadius: 10, border: 'none',
    fontSize: 15, fontWeight: 600, cursor: 'pointer',
    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
    transition: 'opacity 0.15s',
  };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: '#070b14', padding: '40px 20px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif',
    }}>
      <div style={{ width: '100%', maxWidth: 400 }}>

        {/* ── Logo ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 40, justifyContent: 'center' }}>
          <div style={{
            width: 44, height: 44, borderRadius: 12,
            background: 'linear-gradient(135deg, #2563eb 0%, #6366f1 100%)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 28px rgba(99,102,241,0.45)',
          }}>
            <Shield size={23} color="white" />
          </div>
          <div>
            <div style={{ fontSize: 18, fontWeight: 800, color: '#f1f5f9', letterSpacing: '0.05em' }}>
              THREAT ENGINE
            </div>
            <div style={{ fontSize: 10, color: '#818cf8', fontWeight: 700, letterSpacing: '0.14em', textTransform: 'uppercase' }}>
              Cloud Security Platform
            </div>
          </div>
        </div>

        {/* ── URL-level error ── */}
        {topError && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '12px 16px', borderRadius: 10, marginBottom: 22,
            backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
            color: '#f87171', fontSize: 14,
          }}>
            <AlertCircle size={15} style={{ flexShrink: 0 }} />
            {topError}
          </div>
        )}

        {/* ══════════ SSO MODE (default) ══════════ */}
        {!isAdminMode && (
          <>
            <h2 style={{ fontSize: 24, fontWeight: 700, color: '#f1f5f9', marginBottom: 4, textAlign: 'center' }}>
              Sign in
            </h2>
            <p style={{ fontSize: 14, color: '#475569', marginBottom: 28, textAlign: 'center' }}>
              Use your work account to continue
            </p>

            {/* ── Email-first SSO lookup ── */}
            {!domainOptions && (
              <form onSubmit={handleEmailContinue} style={{ marginBottom: 20 }}>
                <div style={{ position: 'relative', marginBottom: 10 }}>
                  <Mail size={15} style={{
                    position: 'absolute', left: 14, top: '50%',
                    transform: 'translateY(-50%)', color: '#475569', pointerEvents: 'none',
                  }} />
                  <input
                    type="email"
                    value={email}
                    onChange={e => { setEmail(e.target.value); setSsoError(''); }}
                    placeholder="name@company.com"
                    autoComplete="email"
                    autoFocus
                    style={{ ...inputCss(focused === 'ssoEmail'), paddingLeft: 42 }}
                    onFocus={() => setFocused('ssoEmail')}
                    onBlur={() => setFocused(null)}
                  />
                </div>
                {ssoError && (
                  <p style={{ fontSize: 12, color: '#f87171', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <AlertCircle size={12} style={{ flexShrink: 0 }} /> {ssoError}
                  </p>
                )}
                <button
                  type="submit"
                  disabled={ssoLoading || !email}
                  style={{
                    ...btnBase,
                    background: ssoLoading || !email
                      ? '#1a2540'
                      : 'linear-gradient(135deg, #2563eb 0%, #4f46e5 100%)',
                    color: 'white', fontWeight: 700,
                    boxShadow: ssoLoading || !email ? 'none' : '0 0 24px rgba(37,99,235,0.35)',
                    opacity: ssoLoading || !email ? 0.55 : 1,
                    cursor: ssoLoading || !email ? 'not-allowed' : 'pointer',
                  }}
                >
                  {ssoLoading ? <><Spinner /> Checking…</> : <>Continue <ChevronRight size={15} /></>}
                </button>
              </form>
            )}

            {/* ── No custom IDP found — direct to password login ── */}
            {domainOptions && (
              <div style={{ marginBottom: 20 }}>
                <div style={{
                  padding: '14px 16px', borderRadius: 10, marginBottom: 12,
                  backgroundColor: 'rgba(59,130,246,0.07)', border: '1px solid rgba(59,130,246,0.2)',
                }}>
                  <p style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8, lineHeight: 1.5 }}>
                    No SSO configured for <strong style={{ color: '#cbd5e1' }}>{domainOptions.domain}</strong>.
                    Sign in with your username and password instead.
                  </p>
                  <Link href="/auth/login?method=local" style={{
                    display: 'inline-flex', alignItems: 'center', gap: 6,
                    fontSize: 13, fontWeight: 600, color: '#3b82f6', textDecoration: 'none',
                  }}>
                    <ArrowRight size={13} /> Sign in with password
                  </Link>
                </div>
                <button
                  type="button"
                  onClick={() => { setDomainOptions(null); setSsoError(''); }}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    fontSize: 12, color: '#475569', width: '100%', padding: '6px',
                    textDecoration: 'underline',
                  }}
                >
                  Try a different email
                </button>
              </div>
            )}

            {/* ── Password / local login ── */}
            <p style={{ textAlign: 'center', fontSize: 12, color: '#475569', marginTop: 16 }}>
              No SSO?{' '}
              <Link href="/auth/login?method=local" style={{ color: '#6366f1', textDecoration: 'none', fontWeight: 600 }}>
                Sign in with password
              </Link>
            </p>

            {/* ── Admin break-glass (very subtle) ── */}
            <p style={{ textAlign: 'center', fontSize: 12, color: '#1e293b', marginTop: 4 }}>
              <Link href="/auth/platform-admin" style={{ color: '#334155', textDecoration: 'none' }}>
                Platform admin access
              </Link>
            </p>
          </>
        )}

        {/* ══════════ ADMIN / LOCAL MODE ══════════ */}
        {isAdminMode && (
          <>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 28,
              padding: '10px 14px', borderRadius: 8,
              backgroundColor: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)',
            }}>
              <Lock size={13} style={{ color: '#fbbf24', flexShrink: 0 }} />
              <span style={{ fontSize: 12, color: '#b45309' }}>
                Break-glass admin login — for emergency access only
              </span>
            </div>

            <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 24 }}>
              Admin sign-in
            </h2>

            {localError && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px',
                borderRadius: 10, marginBottom: 20, backgroundColor: 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.25)', color: '#f87171', fontSize: 14,
              }}>
                <AlertCircle size={15} style={{ flexShrink: 0 }} />
                {localError}
              </div>
            )}

            <form onSubmit={handleLocalSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  Email Address
                </label>
                <input
                  type="email" value={adminEmail} onChange={e => setAdminEmail(e.target.value)}
                  onFocus={() => setFocused('ae')} onBlur={() => setFocused(null)}
                  placeholder="admin@company.com" disabled={isLoading} autoComplete="email"
                  style={inputCss(focused === 'ae')}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  Password
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showPw ? 'text' : 'password'}
                    value={adminPassword} onChange={e => setAdminPassword(e.target.value)}
                    onFocus={() => setFocused('ap')} onBlur={() => setFocused(null)}
                    placeholder="••••••••••••" disabled={isLoading} autoComplete="current-password"
                    style={{ ...inputCss(focused === 'ap'), paddingRight: 48 }}
                  />
                  <button type="button" onClick={() => setShowPw(!showPw)} style={{
                    position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer', color: '#475569', padding: 4,
                    display: 'flex', alignItems: 'center',
                  }}>
                    {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <input id="rem" type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} style={{ width: 15, height: 15, accentColor: '#3b82f6', cursor: 'pointer' }} />
                <label htmlFor="rem" style={{ fontSize: 13, color: '#64748b', cursor: 'pointer' }}>Stay signed in for 7 days</label>
              </div>

              <button type="submit" disabled={isLoading} style={{
                ...btnBase,
                background: isLoading ? '#1d2d44' : 'linear-gradient(135deg, #2563eb 0%, #4f46e5 100%)',
                color: 'white', fontWeight: 700,
                boxShadow: isLoading ? 'none' : '0 0 24px rgba(37,99,235,0.35)',
                opacity: isLoading ? 0.65 : 1, cursor: isLoading ? 'not-allowed' : 'pointer',
              }}>
                {isLoading ? <><Spinner /> Authenticating…</> : <><Lock size={15} /> Sign In <ChevronRight size={15} /></>}
              </button>
            </form>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 14 }}>
              <Link href="/auth/login" style={{ fontSize: 13, color: '#475569', textDecoration: 'none' }}>
                ← Back to login
              </Link>
              <Link href="/auth/forgot-password" style={{ fontSize: 13, color: '#6366f1', textDecoration: 'none' }}>
                Forgot password?
              </Link>
            </div>
          </>
        )}

        {/* ── Footer ── */}
        <p style={{ textAlign: 'center', marginTop: 32, fontSize: 11, color: '#1e293b' }}>
          Protected by HTTPS · Invite-only access
        </p>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        input::placeholder { color: #334155 !important; }
      `}</style>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginContent />
    </Suspense>
  );
}
