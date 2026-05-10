'use client';

import { useState, Suspense } from 'react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Shield, Eye, EyeOff, Lock, ChevronRight, AlertCircle } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';

const inputCss = (focused) => ({
  width: '100%', padding: '13px 16px', borderRadius: 10,
  backgroundColor: '#0d1117',
  border: `1.5px solid ${focused ? '#3b82f6' : '#1e2d3d'}`,
  color: '#f1f5f9', fontSize: 15, outline: 'none',
  transition: 'border-color 0.2s', boxSizing: 'border-box',
});

const Spinner = () => (
  <div style={{
    width: 15, height: 15, borderRadius: '50%',
    border: '2px solid rgba(255,255,255,0.25)', borderTopColor: 'white',
    animation: 'spin 0.65s linear infinite', flexShrink: 0,
  }} />
);

function PlatformAdminContent() {
  const router = useRouter();
  const { login, isLoading } = useAuth();

  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw]     = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError]       = useState('');
  const [focused, setFocused]   = useState(null);

  const btnBase = {
    width: '100%', padding: '13px', borderRadius: 10, border: 'none',
    fontSize: 15, fontWeight: 600, cursor: 'pointer',
    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
    transition: 'opacity 0.15s',
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!email || !password) { setError('Please fill in both fields.'); return; }
    const result = await login(email, password, rememberMe);
    if (result.success) router.push('/dashboard');
    else setError(result.error || 'Login failed. Please try again.');
  };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: '#070b14', padding: '40px 20px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif',
    }}>
      <div style={{ width: '100%', maxWidth: 400 }}>

        {/* Logo */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 32 }}>
          <img src="https://d1fp5dwui44wle.cloudfront.net/logo.svg" alt="Onam Security" style={{ width: 160, objectFit: 'contain' }} />
        </div>

        {/* Warning banner */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24,
          padding: '10px 14px', borderRadius: 8,
          backgroundColor: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)',
        }}>
          <Lock size={13} style={{ color: '#fbbf24', flexShrink: 0 }} />
          <span style={{ fontSize: 12, color: '#b45309' }}>
            Platform admin — break-glass access only
          </span>
        </div>

        <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 24 }}>
          Platform admin sign-in
        </h2>

        {error && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px',
            borderRadius: 10, marginBottom: 20, backgroundColor: 'rgba(239,68,68,0.08)',
            border: '1px solid rgba(239,68,68,0.25)', color: '#f87171', fontSize: 14,
          }}>
            <AlertCircle size={15} style={{ flexShrink: 0 }} />
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Email Address
            </label>
            <input
              type="email" value={email} onChange={e => setEmail(e.target.value)}
              onFocus={() => setFocused('email')} onBlur={() => setFocused(null)}
              placeholder="admin@company.com" disabled={isLoading} autoComplete="email" autoFocus
              style={inputCss(focused === 'email')}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={showPw ? 'text' : 'password'}
                value={password} onChange={e => setPassword(e.target.value)}
                onFocus={() => setFocused('pw')} onBlur={() => setFocused(null)}
                placeholder="••••••••••••" disabled={isLoading} autoComplete="current-password"
                style={{ ...inputCss(focused === 'pw'), paddingRight: 48 }}
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

        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 16 }}>
          <Link href="/auth/login" style={{ fontSize: 13, color: '#475569', textDecoration: 'none' }}>
            ← Back to login
          </Link>
          <Link href="/auth/forgot-password" style={{ fontSize: 13, color: '#6366f1', textDecoration: 'none' }}>
            Forgot password?
          </Link>
        </div>

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

export default function PlatformAdminLoginPage() {
  return (
    <Suspense fallback={null}>
      <PlatformAdminContent />
    </Suspense>
  );
}
