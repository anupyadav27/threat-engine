'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { Shield, Eye, EyeOff, Lock, ChevronRight, AlertCircle, CheckCircle, Users } from 'lucide-react';

export default function InviteAcceptPage() {
  const { token } = useParams();
  const router = useRouter();

  const [invite, setInvite] = useState(null);
  const [inviteError, setInviteError] = useState('');
  const [form, setForm] = useState({ firstName: '', lastName: '', password: '' });
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [focused, setFocused] = useState(null);

  const base = process.env.NEXT_PUBLIC_AUTH_URL || '';

  useEffect(() => {
    if (!token) return;
    fetch(`${base}/api/auth/invite/${token}/`, { credentials: 'include' })
      .then(r => r.json().then(d => ({ ok: r.ok, data: d })))
      .then(({ ok, data }) => {
        if (ok) setInvite(data);
        else setInviteError(data.message || 'Invalid invite link');
      })
      .catch(() => setInviteError('Network error. Please try again.'));
  }, [token, base]);

  const set = (k) => (e) => setForm(p => ({ ...p, [k]: e.target.value }));

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

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#070b14', padding: '40px 20px', fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", sans-serif' }}>
      <div style={{ width: '100%', maxWidth: 440 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 36 }}>
          <div style={{ width: 42, height: 42, borderRadius: 11, background: 'linear-gradient(135deg,#2563eb,#6366f1)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 24px rgba(99,102,241,0.4)' }}>
            <Shield size={22} color="white" />
          </div>
          <div>
            <div style={{ fontSize: 17, fontWeight: 800, color: '#f1f5f9', letterSpacing: '0.05em' }}>THREAT ENGINE</div>
            <div style={{ fontSize: 10, color: '#818cf8', fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase' }}>Cloud Security Platform</div>
          </div>
        </div>

        {inviteError ? (
          <div>
            <div style={{ width: 56, height: 56, borderRadius: '50%', margin: '0 0 24px', backgroundColor: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <AlertCircle size={28} style={{ color: '#f87171' }} />
            </div>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 10 }}>Invalid invite</h2>
            <p style={{ fontSize: 14, color: '#94a3b8' }}>{inviteError}</p>
          </div>
        ) : done ? (
          <div>
            <div style={{ width: 56, height: 56, borderRadius: '50%', margin: '0 0 24px', backgroundColor: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <CheckCircle size={28} style={{ color: '#22c55e' }} />
            </div>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 10 }}>You&apos;re in!</h2>
            <p style={{ fontSize: 14, color: '#94a3b8' }}>Account created. Taking you to the dashboard…</p>
          </div>
        ) : invite ? (
          <>
            <div style={{ padding: '16px 20px', borderRadius: 10, marginBottom: 28, backgroundColor: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)', display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, backgroundColor: 'rgba(99,102,241,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <Users size={18} style={{ color: '#818cf8' }} />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0' }}>Join {invite.tenant_name}</div>
                <div style={{ fontSize: 12, color: '#64748b' }}>Invited as {invite.role} · {invite.email}</div>
              </div>
            </div>

            <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9', marginBottom: 6 }}>Set up your account</h2>
            <p style={{ fontSize: 14, color: '#475569', marginBottom: 24 }}>Your email is pre-verified from the invite.</p>

            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderRadius: 10, marginBottom: 20, backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#f87171', fontSize: 13 }}>
                <AlertCircle size={14} />{error}
              </div>
            )}

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[['firstName','First name','Jane'],['lastName','Last name','Smith']].map(([k, label, ph]) => (
                  <div key={k}>
                    <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 7, letterSpacing: '0.08em', textTransform: 'uppercase' }}>{label}</label>
                    <input value={form[k]} onChange={set(k)} placeholder={ph}
                      onFocus={() => setFocused(k)} onBlur={() => setFocused(null)}
                      style={inputStyle(k)} />
                  </div>
                ))}
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 7, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Password</label>
                <div style={{ position: 'relative' }}>
                  <input type={showPw ? 'text' : 'password'} value={form.password} onChange={set('password')}
                    placeholder="Min. 8 characters" autoComplete="new-password"
                    onFocus={() => setFocused('password')} onBlur={() => setFocused(null)}
                    style={{ ...inputStyle('password'), paddingRight: 44 }} />
                  <button type="button" onClick={() => setShowPw(!showPw)} style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#475569', padding: 4 }}>
                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>
              <button type="submit" disabled={loading} style={{ width: '100%', padding: '13px', borderRadius: 10, border: 'none', marginTop: 4, background: loading ? '#1d2d44' : 'linear-gradient(135deg,#2563eb,#4f46e5)', color: 'white', fontSize: 15, fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, opacity: loading ? 0.65 : 1, boxShadow: loading ? 'none' : '0 0 24px rgba(37,99,235,0.3)' }}>
                {loading ? 'Creating account…' : (<><Lock size={14} />Accept &amp; Join <ChevronRight size={14} /></>)}
              </button>
            </form>
          </>
        ) : (
          <div style={{ color: '#64748b', fontSize: 14 }}>Validating invite…</div>
        )}
      </div>
      <style>{`input::placeholder { color: #334155; }`}</style>
    </div>
  );
}
