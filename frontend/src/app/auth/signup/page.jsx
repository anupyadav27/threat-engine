'use client';

import { useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Mail, ArrowRight, Lock } from 'lucide-react';

export default function SignupPage() {
  const router = useRouter();
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [focused, setFocused] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    const t = token.trim();
    if (!t) { setError('Enter your invite code to continue.'); return; }
    router.push(`/auth/invite/${encodeURIComponent(t)}`);
  };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: '#070b14', padding: '40px 20px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", sans-serif',
    }}>
      <div style={{ width: '100%', maxWidth: 420 }}>

        {/* Logo */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 40 }}>
          <img src="https://d1fp5dwui44wle.cloudfront.net/logo.svg" alt="Onam Security" style={{ width: 160, objectFit: 'contain' }} />
        </div>

        {/* Lock icon */}
        <div style={{
          width: 56, height: 56, borderRadius: '50%', marginBottom: 24,
          backgroundColor: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Lock size={24} style={{ color: '#818cf8' }} />
        </div>

        <h2 style={{ fontSize: 24, fontWeight: 700, color: '#f1f5f9', marginBottom: 8 }}>
          Invite-only access
        </h2>
        <p style={{ fontSize: 14, color: '#475569', marginBottom: 28, lineHeight: 1.6 }}>
          Threat Engine is available by invitation only. Enter your invite code below, or ask your
          platform administrator to send you an invite link.
        </p>

        {error && (
          <div style={{
            padding: '11px 14px', borderRadius: 10, marginBottom: 20, fontSize: 13,
            backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
            color: '#f87171',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <label style={{
            display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b',
            marginBottom: 7, letterSpacing: '0.08em', textTransform: 'uppercase',
          }}>
            Invite code
          </label>
          <div style={{ position: 'relative', marginBottom: 14 }}>
            <Mail size={14} style={{
              position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)',
              color: '#475569', pointerEvents: 'none',
            }} />
            <input
              type="text"
              value={token}
              onChange={e => { setToken(e.target.value); setError(''); }}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              placeholder="Paste your invite code…"
              autoComplete="off"
              style={{
                width: '100%', padding: '12px 16px 12px 38px', borderRadius: 10, outline: 'none',
                backgroundColor: '#0d1117', color: '#f1f5f9', fontSize: 14, boxSizing: 'border-box',
                border: `1.5px solid ${focused ? '#3b82f6' : '#1e2d3d'}`,
                transition: 'border-color 0.2s',
              }}
            />
          </div>

          <button
            type="submit"
            style={{
              width: '100%', padding: '13px', borderRadius: 10, border: 'none',
              background: 'linear-gradient(135deg,#2563eb,#4f46e5)',
              color: 'white', fontSize: 15, fontWeight: 700, cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              boxShadow: '0 0 24px rgba(37,99,235,0.3)',
            }}
          >
            Continue with invite
            <ArrowRight size={15} />
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: 28 }}>
          <Link href="/auth/login" style={{ fontSize: 14, color: '#475569', textDecoration: 'none' }}>
            Already have an account?{' '}
            <span style={{ color: '#6366f1', fontWeight: 600 }}>Sign in</span>
          </Link>
        </div>

        <p style={{ textAlign: 'center', marginTop: 40, fontSize: 12, color: '#1e2d3d' }}>
          Need access? Contact your organization administrator.
        </p>
      </div>
      <style>{`input::placeholder { color: #334155; }`}</style>
    </div>
  );
}
