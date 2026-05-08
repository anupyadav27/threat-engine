'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, Cloud, Users, CheckCircle, ArrowRight, Building2, Key } from 'lucide-react';

const API_BASE = process.env.NEXT_PUBLIC_AUTH_URL || process.env.NEXT_PUBLIC_API_BASE || '';

const STEPS = [
  { id: 1, label: 'Welcome',       icon: Shield },
  { id: 2, label: 'Your Team',     icon: Building2 },
  { id: 3, label: 'Cloud Account', icon: Cloud },
  { id: 4, label: 'Invite Team',   icon: Users },
  { id: 5, label: 'All Done',      icon: CheckCircle },
];

function StepDot({ step, current }) {
  const done    = step.id < current;
  const active  = step.id === current;
  const Icon    = step.icon;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <div style={{
        width: 44, height: 44, borderRadius: '50%',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: done
          ? 'linear-gradient(135deg,#22c55e,#16a34a)'
          : active
            ? 'linear-gradient(135deg,#2563eb,#4f46e5)'
            : '#0d1117',
        border: `2px solid ${done ? '#22c55e' : active ? '#3b82f6' : '#1e2d3d'}`,
        boxShadow: active ? '0 0 20px rgba(37,99,235,0.35)' : 'none',
        transition: 'all 0.25s',
      }}>
        {done ? <CheckCircle size={20} color="white" /> : <Icon size={20} color={active ? 'white' : '#475569'} />}
      </div>
      <span style={{ fontSize: 11, color: active ? '#94a3b8' : '#475569', fontWeight: active ? 600 : 400 }}>
        {step.label}
      </span>
    </div>
  );
}

function ProgressBar({ current }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0, marginBottom: 48 }}>
      {STEPS.map((s, i) => (
        <div key={s.id} style={{ display: 'flex', alignItems: 'center' }}>
          <StepDot step={s} current={current} />
          {i < STEPS.length - 1 && (
            <div style={{
              width: 48, height: 2, margin: '0 4px', marginBottom: 20,
              background: s.id < current ? '#22c55e' : '#1e2d3d',
              transition: 'background 0.3s',
            }} />
          )}
        </div>
      ))}
    </div>
  );
}

function Step1Welcome({ onNext }) {
  return (
    <div style={{ textAlign: 'center', maxWidth: 440, margin: '0 auto' }}>
      <div style={{
        width: 72, height: 72, borderRadius: 20, margin: '0 auto 24px',
        background: 'linear-gradient(135deg,#2563eb,#6366f1)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        boxShadow: '0 0 40px rgba(99,102,241,0.4)',
      }}>
        <Shield size={36} color="white" />
      </div>
      <h2 style={{ fontSize: 30, fontWeight: 800, color: '#f1f5f9', marginBottom: 14 }}>
        Welcome to Threat Engine
      </h2>
      <p style={{ fontSize: 15, color: '#64748b', lineHeight: 1.7, marginBottom: 36 }}>
        Let&apos;s get your cloud security platform set up in a few quick steps.
        This takes about 5 minutes.
      </p>
      <PrimaryBtn onClick={onNext}>Get started <ArrowRight size={16} /></PrimaryBtn>
    </div>
  );
}

function Step2Team({ onNext, onSkip }) {
  const [name, setName] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const handleSave = async () => {
    if (!name.trim()) { onNext(); return; }
    setSaving(true);
    setError('');
    try {
      const meResp = await fetch(`${API_BASE}/api/auth/me/`, { credentials: 'include' });
      const me = await meResp.json();
      const tenantId = me?.tenants?.[0]?.tenant_id;
      if (tenantId) {
        await fetch(`${API_BASE}/api/v1/tenants/${tenantId}/`, {
          method: 'PATCH',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name.trim() }),
        });
      }
    } catch {
      setError('Could not save team name — you can update it later in Settings.');
    }
    setSaving(false);
    onNext();
  };

  return (
    <div style={{ maxWidth: 440, margin: '0 auto' }}>
      <h2 style={{ fontSize: 24, fontWeight: 800, color: '#f1f5f9', marginBottom: 8 }}>Name your team</h2>
      <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.7, marginBottom: 28 }}>
        This will appear in reports and shared views across your organisation.
      </p>
      <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
        Organisation name
      </label>
      <input
        type="text" value={name} onChange={e => setName(e.target.value)}
        placeholder="e.g. Acme Security Team"
        onKeyDown={e => e.key === 'Enter' && handleSave()}
        style={{
          width: '100%', padding: '13px 16px', borderRadius: 10,
          backgroundColor: '#0d1117', border: '1.5px solid #1e2d3d',
          color: '#f1f5f9', fontSize: 15, outline: 'none', boxSizing: 'border-box', marginBottom: 8,
        }}
      />
      {error && <p style={{ fontSize: 12, color: '#f87171', marginBottom: 12 }}>{error}</p>}
      <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
        <PrimaryBtn onClick={handleSave} disabled={saving} style={{ flex: 1 }}>
          {saving ? 'Saving…' : 'Continue'} <ArrowRight size={15} />
        </PrimaryBtn>
        <GhostBtn onClick={onSkip}>Skip</GhostBtn>
      </div>
    </div>
  );
}

function Step3CloudAccount({ onNext, onSkip }) {
  const router = useRouter();
  return (
    <div style={{ maxWidth: 440, margin: '0 auto' }}>
      <h2 style={{ fontSize: 24, fontWeight: 800, color: '#f1f5f9', marginBottom: 8 }}>Connect a cloud account</h2>
      <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.7, marginBottom: 28 }}>
        Add your first AWS, Azure, GCP, or other cloud account so Threat Engine can
        start scanning for misconfigurations and threats.
      </p>
      <div style={{
        padding: 20, borderRadius: 12, border: '1.5px solid #1e2d3d',
        backgroundColor: '#0d1117', marginBottom: 24,
        display: 'flex', alignItems: 'center', gap: 14,
      }}>
        <div style={{
          width: 44, height: 44, borderRadius: 10, flexShrink: 0,
          background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.2)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Key size={20} color="#818cf8" />
        </div>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0', marginBottom: 3 }}>
            Supports all major providers
          </div>
          <div style={{ fontSize: 12, color: '#475569' }}>
            AWS, Azure, GCP, OCI, AliCloud, IBM Cloud, Kubernetes
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', gap: 10 }}>
        <PrimaryBtn onClick={() => router.push('/onboarding/wizard')} style={{ flex: 1 }}>
          Add cloud account <ArrowRight size={15} />
        </PrimaryBtn>
        <GhostBtn onClick={onNext}>Skip for now</GhostBtn>
      </div>
    </div>
  );
}

function Step4Invite({ onNext, onSkip }) {
  const [email, setEmail] = useState('');
  const [sent, setSent]   = useState(false);
  const [sending, setSending] = useState(false);

  const handleInvite = async () => {
    if (!email.trim()) { onNext(); return; }
    setSending(true);
    try {
      const meResp = await fetch(`${API_BASE}/api/auth/me/`, { credentials: 'include' });
      const me = await meResp.json();
      const tenantId = me?.tenants?.[0]?.tenant_id;
      if (tenantId) {
        await fetch('/gateway/api/v1/invites/', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email.trim(), tenant_id: tenantId, role: 'viewer' }),
        });
        setSent(true);
      }
    } catch { /* non-fatal */ }
    setSending(false);
  };

  return (
    <div style={{ maxWidth: 440, margin: '0 auto' }}>
      <h2 style={{ fontSize: 24, fontWeight: 800, color: '#f1f5f9', marginBottom: 8 }}>Invite your team</h2>
      <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.7, marginBottom: 28 }}>
        Add a colleague to start collaborating on security findings.
      </p>
      {sent ? (
        <div style={{
          padding: '16px 20px', borderRadius: 10,
          background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)',
          display: 'flex', gap: 10, marginBottom: 20,
        }}>
          <CheckCircle size={16} color="#22c55e" style={{ flexShrink: 0, marginTop: 1 }} />
          <span style={{ fontSize: 14, color: '#86efac' }}>Invite sent to {email}!</span>
        </div>
      ) : (
        <>
          <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            Team member email
          </label>
          <input
            type="email" value={email} onChange={e => setEmail(e.target.value)}
            placeholder="colleague@company.com"
            style={{
              width: '100%', padding: '13px 16px', borderRadius: 10,
              backgroundColor: '#0d1117', border: '1.5px solid #1e2d3d',
              color: '#f1f5f9', fontSize: 15, outline: 'none', boxSizing: 'border-box', marginBottom: 16,
            }}
          />
          <button
            onClick={handleInvite} disabled={sending || !email}
            style={{
              width: '100%', padding: '13px', borderRadius: 10, border: 'none',
              background: sending || !email ? '#1e2d3d' : 'rgba(99,102,241,0.15)',
              border: '1.5px solid rgba(99,102,241,0.3)',
              color: '#a5b4fc', fontSize: 14, fontWeight: 600, cursor: sending || !email ? 'not-allowed' : 'pointer',
              marginBottom: 10,
            }}
          >
            {sending ? 'Sending…' : 'Send invite'}
          </button>
        </>
      )}
      <div style={{ display: 'flex', gap: 10 }}>
        <PrimaryBtn onClick={onNext} style={{ flex: 1 }}>
          Continue <ArrowRight size={15} />
        </PrimaryBtn>
        {!sent && <GhostBtn onClick={onSkip}>Skip</GhostBtn>}
      </div>
    </div>
  );
}

function Step5Done() {
  const router = useRouter();
  return (
    <div style={{ textAlign: 'center', maxWidth: 440, margin: '0 auto' }}>
      <div style={{
        width: 72, height: 72, borderRadius: '50%', margin: '0 auto 24px',
        background: 'linear-gradient(135deg,#22c55e,#16a34a)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        boxShadow: '0 0 40px rgba(34,197,94,0.35)',
      }}>
        <CheckCircle size={36} color="white" />
      </div>
      <h2 style={{ fontSize: 28, fontWeight: 800, color: '#f1f5f9', marginBottom: 14 }}>
        You&apos;re all set!
      </h2>
      <p style={{ fontSize: 15, color: '#64748b', lineHeight: 1.7, marginBottom: 36 }}>
        Your Threat Engine workspace is ready. Head to the dashboard to see your
        security posture and start exploring findings.
      </p>
      <PrimaryBtn onClick={() => router.push('/dashboard')} style={{ width: '100%' }}>
        Go to dashboard <ArrowRight size={16} />
      </PrimaryBtn>
    </div>
  );
}

function PrimaryBtn({ children, onClick, disabled, style = {} }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: '13px 20px', borderRadius: 10, border: 'none',
        background: disabled ? '#1d2d44' : 'linear-gradient(135deg,#2563eb,#4f46e5)',
        color: 'white', fontSize: 14, fontWeight: 700,
        cursor: disabled ? 'not-allowed' : 'pointer',
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 8,
        boxShadow: disabled ? 'none' : '0 0 20px rgba(37,99,235,0.3)',
        opacity: disabled ? 0.6 : 1,
        ...style,
      }}
    >
      {children}
    </button>
  );
}

function GhostBtn({ children, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '13px 20px', borderRadius: 10, border: '1.5px solid #1e2d3d',
        background: 'none', color: '#475569', fontSize: 14, fontWeight: 600,
        cursor: 'pointer',
      }}
    >
      {children}
    </button>
  );
}

export default function GettingStartedPage() {
  const [step, setStep] = useState(1);
  const next = () => setStep(s => Math.min(s + 1, STEPS.length));

  // Clear the onboarding_pending cookie on first render so the middleware
  // won't redirect the user back here on subsequent navigations.
  useEffect(() => {
    document.cookie = 'onboarding_pending=; max-age=0; path=/; samesite=lax';
  }, []);

  return (
    <div style={{
      minHeight: '100vh', backgroundColor: '#070b14',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif',
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', padding: '40px 24px',
    }}>
      <div style={{ width: '100%', maxWidth: 680 }}>
        <div style={{
          padding: '48px', borderRadius: 20,
          background: 'linear-gradient(160deg,#0f172a 0%,#0c1220 100%)',
          border: '1px solid rgba(99,102,241,0.15)',
          boxShadow: '0 0 60px rgba(0,0,0,0.6)',
        }}>
          <ProgressBar current={step} />
          {step === 1 && <Step1Welcome onNext={next} />}
          {step === 2 && <Step2Team onNext={next} onSkip={next} />}
          {step === 3 && <Step3CloudAccount onNext={next} onSkip={next} />}
          {step === 4 && <Step4Invite onNext={next} onSkip={next} />}
          {step === 5 && <Step5Done />}
        </div>

        <p style={{ textAlign: 'center', fontSize: 12, color: '#334155', marginTop: 20 }}>
          Step {step} of {STEPS.length}
        </p>
      </div>
    </div>
  );
}
