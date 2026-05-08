'use client';

import { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import { Shield, Eye, EyeOff, Lock, ChevronRight, AlertCircle, CheckCircle } from 'lucide-react';

function ResetForm() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const token = searchParams.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [focused, setFocused] = useState(null);

  useEffect(() => {
    if (!token) setError('Invalid or missing reset token. Please request a new link.');
  }, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (password.length < 8) { setError('Password must be at least 8 characters'); return; }
    if (password !== confirm) { setError('Passwords do not match'); return; }
    setLoading(true);
    try {
      const base = process.env.NEXT_PUBLIC_AUTH_URL || '';
      await fetch(`${base}/api/auth/csrf/`, { credentials: 'include' });
      const csrfToken = document.cookie.split('; ').find(r => r.startsWith('csrftoken='))?.split('=')[1] || '';
      const resp = await fetch(`${base}/api/auth/password-reset/confirm/`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify({ token, password }),
      });
      const data = await resp.json();
      if (!resp.ok) { setError(data.message || 'Reset failed. Please request a new link.'); return; }
      setDone(true);
      setTimeout(() => router.push('/auth/login'), 3000);
    } catch { setError('Network error. Please try again.'); }
    finally { setLoading(false); }
  };

  const inputStyle = (f) => ({
    width: '100%', padding: '12px 44px 12px 16px', borderRadius: 10, outline: 'none',
    backgroundColor: '#0d1117', color: '#f1f5f9', fontSize: 14, boxSizing: 'border-box',
    border: `1.5px solid ${focused === f ? '#3b82f6' : '#1e2d3d'}`, transition: 'border-color 0.2s',
  });

  return (
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

      {done ? (
        <div>
          <div style={{ width: 56, height: 56, borderRadius: '50%', margin: '0 0 24px', backgroundColor: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <CheckCircle size={28} style={{ color: '#22c55e' }} />
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 10 }}>Password updated!</h2>
          <p style={{ fontSize: 14, color: '#94a3b8', lineHeight: 1.7 }}>
            Your password has been changed. Redirecting to sign in…
          </p>
        </div>
      ) : (
        <>
          <h2 style={{ fontSize: 24, fontWeight: 700, color: '#f1f5f9', marginBottom: 8 }}>Choose a new password</h2>
          <p style={{ fontSize: 14, color: '#475569', marginBottom: 28 }}>Must be at least 8 characters.</p>
          {error && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderRadius: 10, marginBottom: 20, backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#f87171', fontSize: 13 }}>
              <AlertCircle size={14} />{error}
            </div>
          )}
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {[['password','New password', password, setPassword],['confirm','Confirm password', confirm, setConfirm]].map(([key, label, val, setter]) => (
              <div key={key}>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase' }}>{label}</label>
                <div style={{ position: 'relative' }}>
                  <input type={showPw ? 'text' : 'password'} value={val} onChange={e => setter(e.target.value)}
                    placeholder="••••••••" autoComplete="new-password"
                    onFocus={() => setFocused(key)} onBlur={() => setFocused(null)}
                    style={inputStyle(key)} />
                  {key === 'password' && (
                    <button type="button" onClick={() => setShowPw(!showPw)} style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#475569', padding: 4 }}>
                      {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  )}
                </div>
              </div>
            ))}
            <button type="submit" disabled={loading || !token} style={{ width: '100%', padding: '13px', borderRadius: 10, border: 'none', background: loading ? '#1d2d44' : 'linear-gradient(135deg,#2563eb,#4f46e5)', color: 'white', fontSize: 15, fontWeight: 700, cursor: (loading || !token) ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, opacity: (loading || !token) ? 0.65 : 1 }}>
              {loading ? 'Updating…' : (<><Lock size={14} />Set new password <ChevronRight size={14} /></>)}
            </button>
          </form>
        </>
      )}
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#070b14', padding: '40px 20px', fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", sans-serif' }}>
      <Suspense fallback={<div style={{ color: '#94a3b8' }}>Loading…</div>}>
        <ResetForm />
      </Suspense>
      <style>{`input::placeholder { color: #334155; }`}</style>
    </div>
  );
}
