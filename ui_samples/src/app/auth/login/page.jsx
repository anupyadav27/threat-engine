'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Shield, Eye, EyeOff, Lock, Globe, Server, ChevronRight, AlertCircle, CheckCircle } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';

const FEATURES = [
  { icon: Shield, label: 'Multi-Cloud CSPM', desc: 'AWS, Azure, GCP, OCI, AliCloud, IBM' },
  { icon: Globe,  label: '13+ Compliance Frameworks', desc: 'CIS, NIST, ISO 27001, PCI-DSS, HIPAA' },
  { icon: Server, label: 'Real-time Threat Detection', desc: 'MITRE ATT&CK mapping, risk scoring 0–100' },
];

const STATS = [
  { value: '40+', label: 'Cloud Services' },
  { value: '13+', label: 'Frameworks' },
  { value: '3900+', label: 'Active Findings' },
];

export default function LoginPage() {
  const router = useRouter();
  const { login, isLoading } = useAuth();
  const [email, setEmail]             = useState('');
  const [password, setPassword]       = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe]   = useState(false);
  const [error, setError]             = useState('');
  const [focusedField, setFocusedField] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!email || !password) {
      setError('Please fill in both fields');
      return;
    }
    const result = await login(email, password, rememberMe);
    if (result.success) {
      router.push('/dashboard');
    } else {
      setError(result.error || 'Login failed. Please try again.');
    }
  };

  const handleSamlLogin = () => {
    const base = process.env.NEXT_PUBLIC_AUTH_URL || process.env.NEXT_PUBLIC_API_BASE || '';
    window.location.href = `${base}/api/auth/saml/login/`;
  };

  const handleGoogleLogin = () => {
    const base = process.env.NEXT_PUBLIC_AUTH_URL || process.env.NEXT_PUBLIC_API_BASE || '';
    window.location.href = `${base}/api/auth/google/login/`;
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      backgroundColor: '#070b14',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif',
    }}>
      {/* ── Left branding panel ───────────────────────────────────────────────── */}
      <div style={{
        width: '44%',
        flexShrink: 0,
        background: 'linear-gradient(160deg, #0f172a 0%, #1a1040 55%, #0c1a2e 100%)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        padding: '64px 56px',
        position: 'relative',
        overflow: 'hidden',
        borderRight: '1px solid rgba(99,102,241,0.18)',
      }}>
        {/* Dot grid background */}
        <div style={{
          position: 'absolute', inset: 0, opacity: 0.06,
          backgroundImage: 'radial-gradient(circle at 1px 1px, #818cf8 1px, transparent 0)',
          backgroundSize: '36px 36px',
        }} />

        {/* Radial glow */}
        <div style={{
          position: 'absolute',
          width: 500, height: 500,
          background: 'radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 65%)',
          top: '5%', left: '-120px', pointerEvents: 'none',
        }} />
        <div style={{
          position: 'absolute',
          width: 300, height: 300,
          background: 'radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 65%)',
          bottom: '10%', right: '-60px', pointerEvents: 'none',
        }} />

        <div style={{ position: 'relative', zIndex: 1 }}>
          {/* Logo mark */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 52 }}>
            <div style={{
              width: 50, height: 50, borderRadius: 13,
              background: 'linear-gradient(135deg, #2563eb 0%, #6366f1 100%)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 28px rgba(99,102,241,0.45), 0 4px 16px rgba(0,0,0,0.5)',
            }}>
              <Shield size={26} color="white" />
            </div>
            <div>
              <div style={{
                fontSize: 20, fontWeight: 800, color: '#f1f5f9',
                letterSpacing: '0.06em',
              }}>
                THREAT ENGINE
              </div>
              <div style={{
                fontSize: 10, color: '#818cf8', fontWeight: 700,
                letterSpacing: '0.15em', textTransform: 'uppercase',
              }}>
                Cloud Security Platform
              </div>
            </div>
          </div>

          {/* Headline */}
          <h1 style={{
            fontSize: 38, fontWeight: 800, color: '#f1f5f9',
            lineHeight: 1.15, marginBottom: 18, letterSpacing: '-0.01em',
          }}>
            Protect your cloud<br />
            <span style={{
              background: 'linear-gradient(90deg, #60a5fa, #818cf8)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>
              from every angle
            </span>
          </h1>

          <p style={{
            fontSize: 14, color: '#94a3b8', lineHeight: 1.7,
            marginBottom: 44, maxWidth: 340,
          }}>
            Enterprise CSPM for multi-cloud environments. Continuously monitor
            compliance, detect threats, and remediate risks before they become breaches.
          </p>

          {/* Features */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 18, marginBottom: 52 }}>
            {FEATURES.map(({ icon: Icon, label, desc }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                <div style={{
                  width: 38, height: 38, borderRadius: 10, flexShrink: 0,
                  backgroundColor: 'rgba(99,102,241,0.12)',
                  border: '1px solid rgba(99,102,241,0.25)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  marginTop: 1,
                }}>
                  <Icon size={17} color="#818cf8" />
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0', marginBottom: 2 }}>{label}</div>
                  <div style={{ fontSize: 12, color: '#64748b' }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Stats bar */}
          <div style={{
            display: 'flex', gap: 0,
            paddingTop: 28, borderTop: '1px solid rgba(99,102,241,0.15)',
          }}>
            {STATS.map(({ value, label }, i) => (
              <div key={label} style={{
                flex: 1, textAlign: 'center',
                paddingRight: i < STATS.length - 1 ? 0 : 0,
                borderRight: i < STATS.length - 1 ? '1px solid rgba(99,102,241,0.15)' : 'none',
              }}>
                <div style={{
                  fontSize: 26, fontWeight: 800, color: '#f1f5f9',
                  background: 'linear-gradient(135deg, #60a5fa, #818cf8)',
                  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
                }}>
                  {value}
                </div>
                <div style={{ fontSize: 11, color: '#475569', fontWeight: 600, marginTop: 2 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Right login panel ────────────────────────────────────────────────── */}
      <div style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px 48px',
        backgroundColor: '#070b14',
      }}>
        <div style={{ width: '100%', maxWidth: 420 }}>
          {/* Heading */}
          <div style={{ marginBottom: 36 }}>
            <h2 style={{ fontSize: 26, fontWeight: 700, color: '#f1f5f9', marginBottom: 6 }}>
              Welcome back
            </h2>
            <p style={{ fontSize: 14, color: '#475569' }}>
              Sign in to your security dashboard
            </p>
          </div>

          {/* Error */}
          {error && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '12px 16px', borderRadius: 10, marginBottom: 22,
              backgroundColor: 'rgba(239,68,68,0.08)',
              border: '1px solid rgba(239,68,68,0.25)',
              color: '#f87171', fontSize: 14,
            }}>
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            {/* Email */}
            <div>
              <label style={{
                display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b',
                marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase',
              }}>
                Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onFocus={() => setFocusedField('email')}
                onBlur={() => setFocusedField(null)}
                placeholder="admin@company.com"
                disabled={isLoading}
                autoComplete="email"
                style={{
                  width: '100%', padding: '13px 16px', borderRadius: 10,
                  backgroundColor: '#0d1117',
                  border: `1.5px solid ${focusedField === 'email' ? '#3b82f6' : '#1e2d3d'}`,
                  color: '#f1f5f9', fontSize: 15, outline: 'none',
                  transition: 'border-color 0.2s', boxSizing: 'border-box',
                }}
              />
            </div>

            {/* Password */}
            <div>
              <label style={{
                display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b',
                marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase',
              }}>
                Password
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  onFocus={() => setFocusedField('password')}
                  onBlur={() => setFocusedField(null)}
                  placeholder="••••••••••••"
                  disabled={isLoading}
                  autoComplete="current-password"
                  style={{
                    width: '100%', padding: '13px 48px 13px 16px', borderRadius: 10,
                    backgroundColor: '#0d1117',
                    border: `1.5px solid ${focusedField === 'password' ? '#3b82f6' : '#1e2d3d'}`,
                    color: '#f1f5f9', fontSize: 15, outline: 'none',
                    transition: 'border-color 0.2s', boxSizing: 'border-box',
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: 'absolute', right: 14, top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: '#475569', padding: 4,
                    display: 'flex', alignItems: 'center',
                  }}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Remember me */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <input
                id="remember"
                type="checkbox"
                checked={rememberMe}
                onChange={e => setRememberMe(e.target.checked)}
                disabled={isLoading}
                style={{
                  width: 16, height: 16,
                  accentColor: '#3b82f6',
                  cursor: 'pointer',
                }}
              />
              <label htmlFor="remember" style={{ fontSize: 13, color: '#64748b', cursor: 'pointer' }}>
                Stay signed in for 7 days
              </label>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={isLoading}
              style={{
                width: '100%', padding: '14px', borderRadius: 10, border: 'none',
                background: isLoading
                  ? '#1d2d44'
                  : 'linear-gradient(135deg, #2563eb 0%, #4f46e5 100%)',
                color: 'white', fontSize: 15, fontWeight: 700,
                cursor: isLoading ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                transition: 'opacity 0.2s, box-shadow 0.2s',
                letterSpacing: '0.01em', marginTop: 6,
                boxShadow: isLoading ? 'none' : '0 0 24px rgba(37,99,235,0.35)',
                opacity: isLoading ? 0.65 : 1,
              }}
            >
              {isLoading ? (
                <>
                  <div style={{
                    width: 15, height: 15, borderRadius: '50%',
                    border: '2px solid rgba(255,255,255,0.25)',
                    borderTopColor: 'white',
                    animation: 'spin 0.65s linear infinite',
                  }} />
                  Authenticating…
                </>
              ) : (
                <>
                  <Lock size={15} />
                  Sign In Securely
                  <ChevronRight size={15} />
                </>
              )}
            </button>
          </form>

          {/* Forgot password */}
          <div style={{ textAlign: 'right', marginTop: -8 }}>
            <Link href="/auth/forgot-password" style={{ fontSize: 13, color: '#6366f1', textDecoration: 'none' }}>
              Forgot password?
            </Link>
          </div>

          {/* Divider */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, margin: '22px 0' }}>
            <div style={{ flex: 1, height: 1, backgroundColor: '#1e2d3d' }} />
            <span style={{ fontSize: 11, color: '#334155', fontWeight: 600, letterSpacing: '0.08em' }}>OR</span>
            <div style={{ flex: 1, height: 1, backgroundColor: '#1e2d3d' }} />
          </div>

          {/* Google button */}
          <button
            type="button"
            onClick={handleGoogleLogin}
            disabled={isLoading}
            style={{
              width: '100%', padding: '13px', borderRadius: 10,
              backgroundColor: '#0d1117',
              border: '1.5px solid #1e2d3d',
              color: '#e2e8f0', fontSize: 14, fontWeight: 600,
              cursor: isLoading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
              transition: 'border-color 0.2s', marginBottom: 10,
            }}
          >
            {/* Google G */}
            <svg width="17" height="17" viewBox="0 0 48 48">
              <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.2l6.7-6.7C35.8 2.5 30.3 0 24 0 14.6 0 6.5 5.5 2.5 13.5l7.8 6C12.2 13.2 17.6 9.5 24 9.5z"/>
              <path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.2-.4-4.7H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8C43.7 37.7 46.5 31.5 46.5 24.5z"/>
              <path fill="#FBBC05" d="M10.3 28.5A14.5 14.5 0 0 1 9.5 24c0-1.6.3-3.1.8-4.5l-7.8-6A23.9 23.9 0 0 0 0 24c0 3.9.9 7.5 2.5 10.8l7.8-6.3z"/>
              <path fill="#34A853" d="M24 48c6.3 0 11.6-2.1 15.4-5.6l-7.5-5.8c-2.1 1.4-4.8 2.3-7.9 2.3-6.4 0-11.8-3.7-13.7-9l-7.8 6C6.5 42.5 14.6 48 24 48z"/>
            </svg>
            Continue with Google
          </button>

          {/* SSO button */}
          <button
            type="button"
            onClick={handleSamlLogin}
            disabled={isLoading}
            style={{
              width: '100%', padding: '13px', borderRadius: 10,
              backgroundColor: '#0d1117',
              border: '1.5px solid #1e2d3d',
              color: '#94a3b8', fontSize: 14, fontWeight: 600,
              cursor: isLoading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
              transition: 'border-color 0.2s, color 0.2s',
            }}
          >
            <Shield size={16} style={{ color: '#6366f1' }} />
            Continue with SSO / SAML
          </button>

          {/* Sign up link */}
          <p style={{ textAlign: 'center', marginTop: 24, fontSize: 14, color: '#475569' }}>
            Don&apos;t have an account?{' '}
            <Link href="/auth/signup" style={{ color: '#6366f1', fontWeight: 600, textDecoration: 'none' }}>
              Create account
            </Link>
          </p>

          {/* Security note */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            gap: 6, marginTop: 20,
          }}>
            <CheckCircle size={12} style={{ color: '#22c55e', flexShrink: 0 }} />
            <p style={{ fontSize: 12, color: '#334155', textAlign: 'center' }}>
              Secured with HTTPS · Session tokens expire automatically
            </p>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        input::placeholder { color: #334155; }
        @media (max-width: 768px) {
          aside { display: none; }
        }
      `}</style>
    </div>
  );
}
