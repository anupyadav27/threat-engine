'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Shield, Mail, ChevronRight, AlertCircle, CheckCircle } from 'lucide-react';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [sent, setSent] = useState(false);
  const [focused, setFocused] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!email) { setError('Email is required'); return; }
    setLoading(true);
    try {
      const base = process.env.NEXT_PUBLIC_AUTH_URL || '';
      await fetch(`${base}/api/auth/csrf/`, { credentials: 'include' });
      const csrfToken = document.cookie.split('; ').find(r => r.startsWith('csrftoken='))?.split('=')[1] || '';
      await fetch(`${base}/api/auth/password-reset/request/`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify({ email }),
      });
      setSent(true);
    } catch { setError('Network error. Please try again.'); }
    finally { setLoading(false); }
  };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: '#070b14', padding: '40px 20px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", sans-serif',
    }}>
      <div style={{ width: '100%', maxWidth: 420 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 36 }}>
          <div style={{ width: 42, height: 42, borderRadius: 11, background: 'linear-gradient(135deg,#2563eb,#6366f1)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 24px rgba(99,102,241,0.4)' }}>
            <Shield size={22} color="white" />
          </div>
          <div>
            <div style={{ fontSize: 17, fontWeight: 800, color: '#f1f5f9', letterSpacing: '0.05em' }}>THREAT ENGINE</div>
            <div style={{ fontSize: 10, color: '#818cf8', fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase' }}>Cloud Security Platform</div>
          </div>
        </div>

        {sent ? (
          <div>
            <div style={{ width: 56, height: 56, borderRadius: '50%', margin: '0 0 24px', backgroundColor: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <CheckCircle size={28} style={{ color: '#22c55e' }} />
            </div>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 10 }}>Check your email</h2>
            <p style={{ fontSize: 14, color: '#94a3b8', lineHeight: 1.7, marginBottom: 28 }}>
              If <strong style={{ color: '#e2e8f0' }}>{email}</strong> is registered, a reset link has been sent.
            </p>
            <Link href="/auth/login" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '12px 24px', borderRadius: 10, background: 'linear-gradient(135deg,#2563eb,#4f46e5)', color: 'white', fontWeight: 700, fontSize: 14, textDecoration: 'none' }}>
              Back to sign in <ChevronRight size={14} />
            </Link>
          </div>
        ) : (
          <>
            <h2 style={{ fontSize: 24, fontWeight: 700, color: '#f1f5f9', marginBottom: 8 }}>Reset your password</h2>
            <p style={{ fontSize: 14, color: '#475569', marginBottom: 28 }}>Enter your account email and we&apos;ll send a reset link.</p>
            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderRadius: 10, marginBottom: 20, backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#f87171', fontSize: 13 }}>
                <AlertCircle size={14} />{error}
              </div>
            )}
            <form onSubmit={handleSubmit}>
              <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Email address</label>
              <div style={{ position: 'relative', marginBottom: 20 }}>
                <Mail size={14} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: '#475569', pointerEvents: 'none' }} />
                <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com"
                  onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
                  style={{ width: '100%', padding: '12px 16px 12px 36px', borderRadius: 10, outline: 'none', backgroundColor: '#0d1117', color: '#f1f5f9', fontSize: 14, boxSizing: 'border-box', border: `1.5px solid ${focused ? '#3b82f6' : '#1e2d3d'}`, transition: 'border-color 0.2s' }} />
              </div>
              <button type="submit" disabled={loading} style={{ width: '100%', padding: '13px', borderRadius: 10, border: 'none', background: loading ? '#1d2d44' : 'linear-gradient(135deg,#2563eb,#4f46e5)', color: 'white', fontSize: 15, fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, opacity: loading ? 0.65 : 1 }}>
                {loading ? 'Sending…' : (<>Send reset link <ChevronRight size={14} /></>)}
              </button>
            </form>
            <p style={{ textAlign: 'center', marginTop: 24, fontSize: 14, color: '#475569' }}>
              Remembered it?{' '}<Link href="/auth/login" style={{ color: '#6366f1', fontWeight: 600, textDecoration: 'none' }}>Back to sign in</Link>
            </p>
          </>
        )}
      </div>
      <style>{`input::placeholder { color: #334155; }`}</style>
    </div>
  );
}
