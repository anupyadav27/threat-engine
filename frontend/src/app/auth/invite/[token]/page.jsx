'use client';

import { useState, useEffect } from 'react';
import Image from 'next/image';
import { useParams, useRouter } from 'next/navigation';
import { Shield, Eye, EyeOff, Lock, ChevronRight, AlertCircle, CheckCircle, Users } from 'lucide-react';

function GoogleLogo() {
  return (
    <svg width="16" height="16" viewBox="0 0 48 48" style={{ flexShrink: 0 }}>
      <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.2l6.7-6.7C35.8 2.5 30.3 0 24 0 14.6 0 6.5 5.5 2.5 13.5l7.8 6C12.2 13.2 17.6 9.5 24 9.5z"/>
      <path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.2-.4-4.7H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8C43.7 37.7 46.5 31.5 46.5 24.5z"/>
      <path fill="#FBBC05" d="M10.3 28.5A14.5 14.5 0 0 1 9.5 24c0-1.6.3-3.1.8-4.5l-7.8-6A23.9 23.9 0 0 0 0 24c0 3.9.9 7.5 2.5 10.8l7.8-6.3z"/>
      <path fill="#34A853" d="M24 48c6.3 0 11.6-2.1 15.4-5.6l-7.5-5.8c-2.1 1.4-4.8 2.3-7.9 2.3-6.4 0-11.8-3.7-13.7-9l-7.8 6C6.5 42.5 14.6 48 24 48z"/>
    </svg>
  );
}

function MicrosoftLogo() {
  return (
    <svg width="16" height="16" viewBox="0 0 21 21" style={{ flexShrink: 0 }}>
      <rect x="0" y="0" width="10" height="10" fill="#F25022"/>
      <rect x="11" y="0" width="10" height="10" fill="#7FBA00"/>
      <rect x="0" y="11" width="10" height="10" fill="#00A4EF"/>
      <rect x="11" y="11" width="10" height="10" fill="#FFB900"/>
    </svg>
  );
}

const IDP_LABELS = {
  google:    { label: 'Continue with Google',    Logo: GoogleLogo },
  microsoft: { label: 'Continue with Microsoft', Logo: MicrosoftLogo },
  saml:      { label: 'Continue with SSO',       Logo: null },
};

export default function InviteAcceptPage() {
  const { token } = useParams();
  const router = useRouter();

  const [invite, setInvite]         = useState(null);
  const [inviteError, setInviteError] = useState('');
  const [form, setForm]             = useState({ firstName: '', lastName: '', password: '' });
  const [showPw, setShowPw]         = useState(false);
  const [loading, setLoading]       = useState(false);
  const [ssoLoading, setSsoLoading] = useState(false);
  const [error, setError]           = useState('');
  const [done, setDone]             = useState(false);
  const [focused, setFocused]       = useState(null);

  const base = process.env.NEXT_PUBLIC_AUTH_URL || '';

  useEffect(() => {
    if (!token) return;
    fetch(`${base}/api/auth/invite/${token}/`, { credentials: 'include' })
      .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
      .then(({ ok, data }) => {
        if (ok) setInvite(data);
        else setInviteError(data.message || 'Invalid or expired invite link');
      })
      .catch(() => setInviteError('Network error. Please try again.'));
  }, [token, base]);

  const set = (k) => (e) => setForm(p => ({ ...p, [k]: e.target.value }));

  const handleSso = () => {
    setSsoLoading(true);
    window.location.href = `${base}/api/auth/invite/${token}/sso/`;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (form.password.length < 8) { setError('Password must be at least 8 characters'); return; }
    setLoading(true);
    try {
      await fetch(`${base}/api/auth/csrf/`, { credentials: 'include' });
      const csrfToken = document.cookie.split('; ').find(r => r.startsWith('csrftoken='))?.split('=')[1] || '';
      const resp = await fetch(`${base}/api/auth/invite/${token}/accept/`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify({ first_name: form.firstName, last_name: form.lastName, password: form.password }),
      });
      const data = await resp.json();
      if (!resp.ok) { setError(data.message || 'Failed to accept invite'); return; }
      setDone(true);
      setTimeout(() => router.push('/dashboard'), 2500);
    } catch { setError('Network error. Please try again.'); }
    finally { setLoading(false); }
  };

  const inputStyle = (f) => ({
    width: '100%', padding: '12px 16px', borderRadius: 10, outline: 'none',
    backgroundColor: '#0d1117', color: '#f1f5f9', fontSize: 14, boxSizing: 'border-box',
    border: `1.5px solid ${focused === f ? '#3b82f6' : '#1e2d3d'}`, transition: 'border-color 0.2s',
  });

  const labelStyle = {
    display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b',
    marginBottom: 7, letterSpacing: '0.08em', textTransform: 'uppercase',
  };

  const idpMeta = IDP_LABELS[invite?.idp_type] || IDP_LABELS.saml;

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: '#070b14', padding: '40px 20px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", sans-serif',
    }}>
      <div style={{ width: '100%', maxWidth: 440 }}>

        {/* Logo */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 36 }}>
          <img src="https://d1fp5dwui44wle.cloudfront.net/logo.svg" alt="Onam Security" style={{ width: 160, objectFit: 'contain' }} />
        </div>

        {/* ── Invalid invite ── */}
        {inviteError ? (
          <div>
            <div style={{
              width: 56, height: 56, borderRadius: '50%', marginBottom: 24,
              backgroundColor: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <AlertCircle size={28} style={{ color: '#f87171' }} />
            </div>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 10 }}>Invalid invite</h2>
            <p style={{ fontSize: 14, color: '#94a3b8', marginBottom: 24 }}>{inviteError}</p>
            <a href="/auth/login" style={{ fontSize: 14, color: '#6366f1', fontWeight: 600, textDecoration: 'none' }}>
              ← Back to sign in
            </a>
          </div>

        /* ── Success ── */
        ) : done ? (
          <div>
            <div style={{
              width: 56, height: 56, borderRadius: '50%', marginBottom: 24,
              backgroundColor: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <CheckCircle size={28} style={{ color: '#22c55e' }} />
            </div>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 10 }}>You&apos;re in!</h2>
            <p style={{ fontSize: 14, color: '#94a3b8' }}>Account created. Taking you to the dashboard…</p>
          </div>

        /* ── Invite loaded ── */
        ) : invite ? (
          <>
            {/* Invite context banner */}
            <div style={{
              padding: '16px 20px', borderRadius: 10, marginBottom: 28,
              backgroundColor: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)',
              display: 'flex', alignItems: 'center', gap: 14,
            }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10, flexShrink: 0,
                backgroundColor: 'rgba(99,102,241,0.15)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Users size={18} style={{ color: '#818cf8' }} />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0' }}>
                  Join {invite.tenant_name}
                </div>
                <div style={{ fontSize: 12, color: '#64748b' }}>
                  Invited as {invite.role} · {invite.email}
                  {invite.group_name && (
                    <span style={{ fontSize: 11, color: '#818cf8', marginLeft: 8 }}>
                      · Group: {invite.group_name}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 6 }}>
              Accept your invitation
            </h2>
            <p style={{ fontSize: 14, color: '#475569', marginBottom: 24 }}>
              {invite.idp_available
                ? 'Use your organization SSO to join — no password needed.'
                : 'Set a password to complete your account setup.'}
            </p>

            {/* ── SSO primary path ── */}
            {invite.idp_available && (
              <>
                <button
                  type="button"
                  onClick={handleSso}
                  disabled={ssoLoading}
                  style={{
                    width: '100%', padding: '13px', borderRadius: 10, border: 'none', marginBottom: 20,
                    background: ssoLoading ? '#1d2d44' : 'linear-gradient(135deg,#2563eb,#4f46e5)',
                    color: 'white', fontSize: 15, fontWeight: 700,
                    cursor: ssoLoading ? 'not-allowed' : 'pointer',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
                    boxShadow: ssoLoading ? 'none' : '0 0 24px rgba(37,99,235,0.3)',
                    opacity: ssoLoading ? 0.65 : 1,
                  }}
                >
                  {idpMeta.Logo && <idpMeta.Logo />}
                  {ssoLoading ? 'Redirecting…' : idpMeta.label}
                </button>

                {/* Divider to password fallback */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
                  <div style={{ flex: 1, height: 1, backgroundColor: '#1e2d3d' }} />
                  <span style={{ fontSize: 11, color: '#334155', fontWeight: 600, letterSpacing: '0.08em' }}>
                    OR SET A PASSWORD
                  </span>
                  <div style={{ flex: 1, height: 1, backgroundColor: '#1e2d3d' }} />
                </div>
              </>
            )}

            {error && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px',
                borderRadius: 10, marginBottom: 20, backgroundColor: 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.25)', color: '#f87171', fontSize: 13,
              }}>
                <AlertCircle size={14} style={{ flexShrink: 0 }} />
                {error}
              </div>
            )}

            {/* Password form */}
            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[['firstName', 'First name', 'Jane'], ['lastName', 'Last name', 'Smith']].map(([k, label, ph]) => (
                  <div key={k}>
                    <label style={labelStyle}>{label}</label>
                    <input value={form[k]} onChange={set(k)} placeholder={ph}
                      onFocus={() => setFocused(k)} onBlur={() => setFocused(null)}
                      style={inputStyle(k)} />
                  </div>
                ))}
              </div>
              <div>
                <label style={labelStyle}>Password</label>
                <div style={{ position: 'relative' }}>
                  <input type={showPw ? 'text' : 'password'} value={form.password}
                    onChange={set('password')} placeholder="Min. 8 characters"
                    autoComplete="new-password"
                    onFocus={() => setFocused('password')} onBlur={() => setFocused(null)}
                    style={{ ...inputStyle('password'), paddingRight: 44 }} />
                  <button type="button" onClick={() => setShowPw(!showPw)} style={{
                    position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer', color: '#475569', padding: 4,
                  }}>
                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              <button type="submit" disabled={loading} style={{
                width: '100%', padding: '13px', borderRadius: 10, border: 'none', marginTop: 4,
                background: loading ? '#1d2d44' : 'linear-gradient(135deg,#2563eb,#4f46e5)',
                color: 'white', fontSize: 15, fontWeight: 700,
                cursor: loading ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                opacity: loading ? 0.65 : 1,
                boxShadow: loading ? 'none' : '0 0 24px rgba(37,99,235,0.3)',
              }}>
                {loading ? 'Creating account…' : (
                  <><Lock size={14} />Accept &amp; Join<ChevronRight size={14} /></>
                )}
              </button>
            </form>
          </>

        /* ── Loading ── */
        ) : (
          <div style={{ color: '#64748b', fontSize: 14 }}>Validating invite…</div>
        )}
      </div>
      <style>{`input::placeholder { color: #334155; }`}</style>
    </div>
  );
}
