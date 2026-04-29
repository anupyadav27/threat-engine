'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Eye, EyeOff, Lock, ChevronRight, AlertCircle, CheckCircle, Building2 } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';

export default function SignupPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [form, setForm] = useState({
    firstName: '', lastName: '', email: '', password: '', companyName: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [focused, setFocused] = useState(null);

  const set = (k) => (e) => setForm(p => ({ ...p, [k]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!form.email || !form.password) { setError('Email and password are required'); return; }
    if (form.password.length < 8) { setError('Password must be at least 8 characters'); return; }

    setLoading(true);
    try {
      const base = process.env.NEXT_PUBLIC_AUTH_URL || '';

      // Fetch CSRF first
      await fetch(`${base}/api/auth/csrf/`, { credentials: 'include' });
      const csrfCookie = document.cookie.split('; ').find(r => r.startsWith('csrftoken='));
      const csrfToken = csrfCookie ? csrfCookie.split('=')[1] : '';

      const resp = await fetch(`${base}/api/auth/signup/`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify({
          email: form.email,
          password: form.password,
          first_name: form.firstName,
          last_name: form.lastName,
          company_name: form.companyName,
        }),
      });
      const data = await resp.json();

      if (!resp.ok) {
        setError(data.message || 'Signup failed. Please try again.');
        return;
      }

      // Session cookies are already set by Django — refresh auth state then redirect
      router.push('/dashboard');
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogle = () => {
    const base = process.env.NEXT_PUBLIC_AUTH_URL || '';
    window.location.href = `${base}/api/auth/google/login/`;
  };

  const inputStyle = (field) => ({
    width: '100%', padding: '12px 16px', borderRadius: 10, outline: 'none',
    backgroundColor: '#0d1117', color: '#f1f5f9', fontSize: 14, boxSizing: 'border-box',
    border: `1.5px solid ${focused === field ? '#3b82f6' : '#1e2d3d'}`,
    transition: 'border-color 0.2s',
  });

  const labelStyle = {
    display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b',
    marginBottom: 7, letterSpacing: '0.08em', textTransform: 'uppercase',
  };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: '#070b14', padding: '40px 20px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", sans-serif',
    }}>
      <div style={{ width: '100%', maxWidth: 460 }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 36 }}>
          <div style={{
            width: 42, height: 42, borderRadius: 11,
            background: 'linear-gradient(135deg,#2563eb,#6366f1)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 24px rgba(99,102,241,0.4)',
          }}>
            <Shield size={22} color="white" />
          </div>
          <div>
            <div style={{ fontSize: 17, fontWeight: 800, color: '#f1f5f9', letterSpacing: '0.05em' }}>
              THREAT ENGINE
            </div>
            <div style={{ fontSize: 10, color: '#818cf8', fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase' }}>
              Cloud Security Platform
            </div>
          </div>
        </div>

        <h2 style={{ fontSize: 24, fontWeight: 700, color: '#f1f5f9', marginBottom: 6 }}>
          Create your account
        </h2>
        <p style={{ fontSize: 14, color: '#475569', marginBottom: 28 }}>
          Start your 14-day free trial. No credit card required.
        </p>

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

        {/* Google signup */}
        <button
          type="button" onClick={handleGoogle} disabled={loading}
          style={{
            width: '100%', padding: '12px', borderRadius: 10, marginBottom: 20,
            backgroundColor: '#0d1117', border: '1.5px solid #1e2d3d',
            color: '#e2e8f0', fontSize: 14, fontWeight: 600, cursor: 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
          }}
        >
          <svg width="16" height="16" viewBox="0 0 48 48">
            <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.2l6.7-6.7C35.8 2.5 30.3 0 24 0 14.6 0 6.5 5.5 2.5 13.5l7.8 6C12.2 13.2 17.6 9.5 24 9.5z"/>
            <path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.2-.4-4.7H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8C43.7 37.7 46.5 31.5 46.5 24.5z"/>
            <path fill="#FBBC05" d="M10.3 28.5A14.5 14.5 0 0 1 9.5 24c0-1.6.3-3.1.8-4.5l-7.8-6A23.9 23.9 0 0 0 0 24c0 3.9.9 7.5 2.5 10.8l7.8-6.3z"/>
            <path fill="#34A853" d="M24 48c6.3 0 11.6-2.1 15.4-5.6l-7.5-5.8c-2.1 1.4-4.8 2.3-7.9 2.3-6.4 0-11.8-3.7-13.7-9l-7.8 6C6.5 42.5 14.6 48 24 48z"/>
          </svg>
          Sign up with Google
        </button>

        {/* Divider */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
          <div style={{ flex: 1, height: 1, backgroundColor: '#1e2d3d' }} />
          <span style={{ fontSize: 11, color: '#334155', fontWeight: 600, letterSpacing: '0.08em' }}>OR</span>
          <div style={{ flex: 1, height: 1, backgroundColor: '#1e2d3d' }} />
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Name row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <label style={labelStyle}>First name</label>
              <input value={form.firstName} onChange={set('firstName')} placeholder="Jane"
                onFocus={() => setFocused('firstName')} onBlur={() => setFocused(null)}
                style={inputStyle('firstName')} />
            </div>
            <div>
              <label style={labelStyle}>Last name</label>
              <input value={form.lastName} onChange={set('lastName')} placeholder="Smith"
                onFocus={() => setFocused('lastName')} onBlur={() => setFocused(null)}
                style={inputStyle('lastName')} />
            </div>
          </div>

          {/* Email */}
          <div>
            <label style={labelStyle}>Work Email</label>
            <input type="email" value={form.email} onChange={set('email')}
              placeholder="jane@company.com" autoComplete="email"
              onFocus={() => setFocused('email')} onBlur={() => setFocused(null)}
              style={inputStyle('email')} />
          </div>

          {/* Company */}
          <div>
            <label style={labelStyle}>Company name</label>
            <div style={{ position: 'relative' }}>
              <Building2 size={14} style={{
                position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)',
                color: '#475569', pointerEvents: 'none',
              }} />
              <input value={form.companyName} onChange={set('companyName')}
                placeholder="Acme Corp" onFocus={() => setFocused('company')} onBlur={() => setFocused(null)}
                style={{ ...inputStyle('company'), paddingLeft: 36 }} />
            </div>
          </div>

          {/* Password */}
          <div>
            <label style={labelStyle}>Password</label>
            <div style={{ position: 'relative' }}>
              <input type={showPassword ? 'text' : 'password'} value={form.password}
                onChange={set('password')} placeholder="Min. 8 characters" autoComplete="new-password"
                onFocus={() => setFocused('password')} onBlur={() => setFocused(null)}
                style={{ ...inputStyle('password'), paddingRight: 44 }} />
              <button type="button" onClick={() => setShowPassword(!showPassword)} style={{
                position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)',
                background: 'none', border: 'none', cursor: 'pointer', color: '#475569', padding: 4,
              }}>
                {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          <button type="submit" disabled={loading} style={{
            width: '100%', padding: '13px', borderRadius: 10, border: 'none', marginTop: 4,
            background: loading ? '#1d2d44' : 'linear-gradient(135deg,#2563eb,#4f46e5)',
            color: 'white', fontSize: 15, fontWeight: 700,
            cursor: loading ? 'not-allowed' : 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            boxShadow: loading ? 'none' : '0 0 24px rgba(37,99,235,0.3)',
            opacity: loading ? 0.65 : 1,
          }}>
            {loading ? (
              <>
                <div style={{
                  width: 14, height: 14, borderRadius: '50%',
                  border: '2px solid rgba(255,255,255,0.25)', borderTopColor: 'white',
                  animation: 'spin 0.65s linear infinite',
                }} />
                Creating account…
              </>
            ) : (
              <>
                <Lock size={14} />
                Create account
                <ChevronRight size={14} />
              </>
            )}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 24, fontSize: 14, color: '#475569' }}>
          Already have an account?{' '}
          <Link href="/auth/login" style={{ color: '#6366f1', fontWeight: 600, textDecoration: 'none' }}>
            Sign in
          </Link>
        </p>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginTop: 20 }}>
          <CheckCircle size={12} style={{ color: '#22c55e' }} />
          <p style={{ fontSize: 12, color: '#334155' }}>
            By signing up you agree to our Terms of Service
          </p>
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } } input::placeholder { color: #334155; }`}</style>
    </div>
  );
}
