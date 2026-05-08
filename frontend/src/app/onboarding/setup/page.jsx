'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield, Building2, KeyRound, Users, Cloud, CheckCircle, ArrowRight, ArrowLeft,
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { useTenant } from '@/lib/tenant-context';
import { fetchFromCspm } from '@/lib/api';

// ─── Step metadata ─────────────────────────────────────────────────────────────

const STEPS = [
  { id: 1, label: 'Welcome',       icon: Shield },
  { id: 2, label: 'Workspace',     icon: Building2 },
  { id: 3, label: 'SSO',           icon: KeyRound },
  { id: 4, label: 'Invite Team',   icon: Users },
  { id: 5, label: 'Cloud Account', icon: Cloud },
  { id: 6, label: 'Done',          icon: CheckCircle },
];

const TOTAL = STEPS.length;

// ─── Shared button components ──────────────────────────────────────────────────

function PrimaryBtn({ children, onClick, disabled, style = {} }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: '13px 24px',
        borderRadius: 10,
        border: 'none',
        background: disabled
          ? 'var(--bg-tertiary)'
          : 'linear-gradient(135deg, #2563eb, #4f46e5)',
        color: disabled ? 'var(--text-muted)' : '#ffffff',
        fontSize: 14,
        fontWeight: 700,
        cursor: disabled ? 'not-allowed' : 'pointer',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        boxShadow: disabled ? 'none' : '0 0 20px rgba(37,99,235,0.3)',
        opacity: disabled ? 0.6 : 1,
        transition: 'opacity 0.2s',
        ...style,
      }}
    >
      {children}
    </button>
  );
}

function GhostBtn({ children, onClick, style = {} }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '13px 20px',
        borderRadius: 10,
        border: '1.5px solid var(--border-secondary)',
        background: 'none',
        color: 'var(--text-muted)',
        fontSize: 14,
        fontWeight: 600,
        cursor: 'pointer',
        transition: 'color 0.15s, border-color 0.15s',
        ...style,
      }}
    >
      {children}
    </button>
  );
}

function LinkBtn({ children, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: 'none',
        border: 'none',
        color: 'var(--text-muted)',
        fontSize: 13,
        cursor: 'pointer',
        textDecoration: 'underline',
        padding: 0,
      }}
    >
      {children}
    </button>
  );
}

function InputField({ label, type = 'text', value, onChange, placeholder, autoFocus }) {
  return (
    <div style={{ marginBottom: 20 }}>
      {label && (
        <label style={{
          display: 'block',
          fontSize: 11,
          fontWeight: 700,
          color: 'var(--text-muted)',
          marginBottom: 8,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
        }}>
          {label}
        </label>
      )}
      <input
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoFocus={autoFocus}
        style={{
          width: '100%',
          padding: '13px 16px',
          borderRadius: 10,
          backgroundColor: 'var(--bg-input)',
          border: '1.5px solid var(--border-secondary)',
          color: 'var(--text-primary)',
          fontSize: 15,
          outline: 'none',
          boxSizing: 'border-box',
        }}
      />
    </div>
  );
}

function ErrorNote({ msg }) {
  if (!msg) return null;
  return (
    <p style={{ fontSize: 12, color: 'var(--accent-danger)', marginBottom: 12, marginTop: -8 }}>
      {msg}
    </p>
  );
}

// ─── Progress indicator ────────────────────────────────────────────────────────

function ProgressDots({ current }) {
  const pct = Math.round(((current - 1) / (TOTAL - 1)) * 100);
  return (
    <div style={{ marginBottom: 40 }}>
      {/* Label */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 10,
      }}>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 500 }}>
          Step {current} of {TOTAL}
        </span>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {STEPS[current - 1].label}
        </span>
      </div>
      {/* Track */}
      <div style={{
        height: 4,
        borderRadius: 2,
        backgroundColor: 'var(--border-primary)',
        overflow: 'hidden',
      }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          background: 'linear-gradient(90deg, #2563eb, #6366f1)',
          borderRadius: 2,
          transition: 'width 0.35s ease',
        }} />
      </div>
      {/* Dots */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        marginTop: 10,
      }}>
        {STEPS.map((s) => {
          const done   = s.id < current;
          const active = s.id === current;
          return (
            <div key={s.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
              <div style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: done
                  ? '#22c55e'
                  : active
                    ? '#3b82f6'
                    : 'var(--border-secondary)',
                transition: 'background 0.25s',
              }} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Navigation row (Back + Skip) ─────────────────────────────────────────────

function NavRow({ step, onBack, onSkip, skipLabel = 'Skip', children }) {
  return (
    <div style={{ marginTop: 28 }}>
      {children}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: step > 1 ? 'space-between' : 'flex-end',
        marginTop: 16,
      }}>
        {step > 1 && (
          <button
            onClick={onBack}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              fontSize: 13,
              cursor: 'pointer',
              padding: 0,
            }}
          >
            <ArrowLeft size={14} /> Back
          </button>
        )}
        {onSkip && (
          <LinkBtn onClick={onSkip}>{skipLabel}</LinkBtn>
        )}
      </div>
    </div>
  );
}

// ─── Step 1: Welcome ───────────────────────────────────────────────────────────

function Step1Welcome({ onNext }) {
  const { user } = useAuth();
  const firstName = user?.name?.split(' ')[0] || user?.email?.split('@')[0] || 'there';

  return (
    <div style={{ textAlign: 'center', maxWidth: 440, margin: '0 auto' }}>
      <div style={{
        width: 72,
        height: 72,
        borderRadius: 20,
        margin: '0 auto 28px',
        background: 'linear-gradient(135deg, #2563eb, #6366f1)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        boxShadow: '0 0 40px rgba(99,102,241,0.35)',
      }}>
        <Shield size={34} color="white" />
      </div>

      <h2 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 12 }}>
        Welcome to Threat Engine CSPM
      </h2>

      {user && (
        <p style={{ fontSize: 14, color: 'var(--accent-primary)', marginBottom: 8, fontWeight: 600 }}>
          Hello, {firstName}!
        </p>
      )}

      <p style={{ fontSize: 15, color: 'var(--text-secondary)', lineHeight: 1.75, marginBottom: 36 }}>
        Let&apos;s get your cloud security platform set up in a few quick steps.
        This takes about 5 minutes.
      </p>

      <PrimaryBtn onClick={onNext} style={{ minWidth: 180 }}>
        Get Started <ArrowRight size={16} />
      </PrimaryBtn>
    </div>
  );
}

// ─── Step 2: Company / Workspace Setup ────────────────────────────────────────

function Step2Workspace({ onNext, onBack, onSkip }) {
  const { user } = useAuth();
  const { activeTenant } = useTenant();

  const [workspaceName, setWorkspaceName] = useState(activeTenant?.tenant_name || '');
  const [contactEmail, setContactEmail]   = useState(user?.email || '');
  const [saving, setSaving]               = useState(false);
  const [error, setError]                 = useState('');

  const handleContinue = async () => {
    setSaving(true);
    setError('');

    const tenantId = activeTenant?.tenant_id;
    if (tenantId && (workspaceName.trim() || contactEmail.trim())) {
      try {
        const payload = {};
        if (workspaceName.trim()) payload.name = workspaceName.trim();
        if (contactEmail.trim())  payload.contact_email = contactEmail.trim();

        const result = await fetchFromCspm(`/api/v1/tenants/${tenantId}/`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        });

        if (result?.error) {
          // Non-fatal — log and continue
          console.warn('Workspace update warning:', result.error);
        }
      } catch (err) {
        console.warn('Workspace update warning:', err);
        setError('Could not save workspace details — you can update them later in Settings.');
      }
    }

    setSaving(false);
    onNext();
  };

  return (
    <div style={{ maxWidth: 440, margin: '0 auto' }}>
      <h2 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
        Company Setup
      </h2>
      <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 28 }}>
        Set your workspace name and contact email. These appear in reports and alerts.
      </p>

      <InputField
        label="Workspace Name"
        value={workspaceName}
        onChange={e => setWorkspaceName(e.target.value)}
        placeholder="e.g. Acme Security Team"
        autoFocus
      />
      <InputField
        label="Contact Email"
        type="email"
        value={contactEmail}
        onChange={e => setContactEmail(e.target.value)}
        placeholder="security@company.com"
      />
      <ErrorNote msg={error} />

      <NavRow step={2} onBack={onBack} onSkip={onSkip} skipLabel="Skip for now">
        <div style={{ display: 'flex', gap: 10 }}>
          <PrimaryBtn onClick={handleContinue} disabled={saving} style={{ flex: 1 }}>
            {saving ? 'Saving…' : 'Continue'} <ArrowRight size={15} />
          </PrimaryBtn>
        </div>
      </NavRow>
    </div>
  );
}

// ─── Step 3: Configure SSO ────────────────────────────────────────────────────

const SSO_OPTIONS = [
  { value: 'google',  label: 'Google OAuth',     desc: 'Sign in with Google Workspace' },
  { value: 'oidc',    label: 'OIDC',             desc: 'OpenID Connect provider' },
  { value: 'saml',    label: 'SAML 2.0',         desc: 'Enterprise SAML identity provider' },
  { value: 'skip',    label: 'Skip for now',      desc: 'Configure SSO later in Settings' },
];

function Step3SSO({ onNext, onBack, onSkip }) {
  const [selected, setSelected] = useState('skip');

  const handleContinue = () => {
    onNext();
  };

  return (
    <div style={{ maxWidth: 440, margin: '0 auto' }}>
      <h2 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
        Configure SSO
      </h2>
      <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 28 }}>
        Set up single sign-on for your team. This is optional and can be configured later.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 20 }}>
        {SSO_OPTIONS.map(opt => (
          <label
            key={opt.value}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 14,
              padding: '14px 16px',
              borderRadius: 10,
              border: `1.5px solid ${selected === opt.value ? 'var(--accent-primary)' : 'var(--border-secondary)'}`,
              backgroundColor: selected === opt.value ? 'rgba(59,130,246,0.06)' : 'var(--bg-input)',
              cursor: 'pointer',
              transition: 'border-color 0.15s, background 0.15s',
            }}
          >
            <input
              type="radio"
              name="sso"
              value={opt.value}
              checked={selected === opt.value}
              onChange={() => setSelected(opt.value)}
              style={{ accentColor: 'var(--accent-primary)' }}
            />
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
                {opt.label}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                {opt.desc}
              </div>
            </div>
          </label>
        ))}
      </div>

      {selected !== 'skip' && (
        <div style={{
          padding: '14px 16px',
          borderRadius: 10,
          backgroundColor: 'rgba(59,130,246,0.06)',
          border: '1px solid rgba(59,130,246,0.2)',
          marginBottom: 16,
        }}>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: 0 }}>
            SSO can be configured in <strong>Settings &rarr; Identity Providers</strong> after setup.
          </p>
        </div>
      )}

      <NavRow step={3} onBack={onBack} onSkip={onSkip} skipLabel="Skip">
        <PrimaryBtn onClick={handleContinue} style={{ width: '100%' }}>
          Continue <ArrowRight size={15} />
        </PrimaryBtn>
      </NavRow>
    </div>
  );
}

// ─── Step 4: Invite Team ──────────────────────────────────────────────────────

const ROLE_OPTIONS = [
  { value: 'analyst', label: 'Analyst' },
  { value: 'viewer',  label: 'Viewer' },
];

function InviteRow({ entry, onChange, onRemove, showRemove }) {
  return (
    <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
      <input
        type="email"
        value={entry.email}
        onChange={e => onChange({ ...entry, email: e.target.value })}
        placeholder="colleague@company.com"
        style={{
          flex: 1,
          padding: '11px 14px',
          borderRadius: 8,
          backgroundColor: 'var(--bg-input)',
          border: '1.5px solid var(--border-secondary)',
          color: 'var(--text-primary)',
          fontSize: 14,
          outline: 'none',
        }}
      />
      <select
        value={entry.role}
        onChange={e => onChange({ ...entry, role: e.target.value })}
        style={{
          padding: '11px 10px',
          borderRadius: 8,
          backgroundColor: 'var(--bg-input)',
          border: '1.5px solid var(--border-secondary)',
          color: 'var(--text-primary)',
          fontSize: 14,
          outline: 'none',
          cursor: 'pointer',
        }}
      >
        {ROLE_OPTIONS.map(r => (
          <option key={r.value} value={r.value}>{r.label}</option>
        ))}
      </select>
      {showRemove && (
        <button
          onClick={onRemove}
          style={{
            padding: '0 10px',
            borderRadius: 8,
            border: '1.5px solid var(--border-secondary)',
            background: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            fontSize: 18,
            lineHeight: 1,
          }}
          title="Remove"
        >
          &times;
        </button>
      )}
    </div>
  );
}

function Step4Invite({ onNext, onBack, onSkip }) {
  const { activeTenant } = useTenant();
  const [rows, setRows]   = useState([{ email: '', role: 'analyst' }]);
  const [sent, setSent]   = useState([]);
  const [sending, setSending] = useState(false);

  const updateRow = useCallback((idx, updated) => {
    setRows(prev => prev.map((r, i) => i === idx ? updated : r));
  }, []);

  const removeRow = useCallback((idx) => {
    setRows(prev => prev.filter((_, i) => i !== idx));
  }, []);

  const addRow = () => {
    setRows(prev => [...prev, { email: '', role: 'analyst' }]);
  };

  const sendInvites = async () => {
    const toSend = rows.filter(r => r.email.trim());
    if (toSend.length === 0) { onNext(); return; }

    setSending(true);
    const results = [];
    for (const row of toSend) {
      try {
        const body = {
          email: row.email.trim(),
          tenant_id: activeTenant?.tenant_id,
          role: row.role,
        };
        const res = await fetch('/gateway/api/v1/invites/', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        results.push({ email: row.email, ok: res.ok });
      } catch {
        results.push({ email: row.email, ok: false });
      }
    }
    setSent(results);
    setSending(false);
  };

  const allSent = sent.length > 0;

  return (
    <div style={{ maxWidth: 440, margin: '0 auto' }}>
      <h2 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
        Invite Team Members
      </h2>
      <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 24 }}>
        Add colleagues to collaborate on security findings. This step is optional.
      </p>

      {!allSent ? (
        <>
          {rows.map((row, idx) => (
            <InviteRow
              key={idx}
              entry={row}
              onChange={updated => updateRow(idx, updated)}
              onRemove={() => removeRow(idx)}
              showRemove={rows.length > 1}
            />
          ))}

          <button
            onClick={addRow}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--accent-primary)',
              fontSize: 13,
              cursor: 'pointer',
              padding: 0,
              marginBottom: 20,
            }}
          >
            + Add another
          </button>
        </>
      ) : (
        <div style={{
          padding: '16px 20px',
          borderRadius: 10,
          background: 'rgba(34,197,94,0.08)',
          border: '1px solid rgba(34,197,94,0.2)',
          marginBottom: 20,
        }}>
          {sent.map((s, i) => (
            <div key={i} style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              marginBottom: i < sent.length - 1 ? 6 : 0,
            }}>
              <CheckCircle size={14} color={s.ok ? '#22c55e' : '#f87171'} />
              <span style={{ fontSize: 13, color: s.ok ? '#86efac' : 'var(--accent-danger)' }}>
                {s.ok ? `Invite sent to ${s.email}` : `Could not invite ${s.email} — try again in Settings`}
              </span>
            </div>
          ))}
        </div>
      )}

      <NavRow step={4} onBack={onBack} onSkip={onSkip} skipLabel="Continue without inviting">
        <div style={{ display: 'flex', gap: 10 }}>
          {!allSent ? (
            <PrimaryBtn
              onClick={sendInvites}
              disabled={sending || rows.every(r => !r.email.trim())}
              style={{ flex: 1 }}
            >
              {sending ? 'Sending…' : 'Send Invites'} {!sending && <ArrowRight size={15} />}
            </PrimaryBtn>
          ) : (
            <PrimaryBtn onClick={onNext} style={{ flex: 1 }}>
              Continue <ArrowRight size={15} />
            </PrimaryBtn>
          )}
        </div>
      </NavRow>
    </div>
  );
}

// ─── Step 5: Connect Cloud Account ────────────────────────────────────────────

const CLOUD_PROVIDERS = [
  { value: 'aws',   label: 'AWS',   color: '#FF9900', desc: 'Amazon Web Services' },
  { value: 'azure', label: 'Azure', color: '#0078D4', desc: 'Microsoft Azure' },
  { value: 'gcp',   label: 'GCP',   color: '#4285F4', desc: 'Google Cloud Platform' },
];

function Step5CloudAccount({ onNext, onBack, onSkip }) {
  const [selected, setSelected] = useState('aws');
  const router = useRouter();

  return (
    <div style={{ maxWidth: 440, margin: '0 auto' }}>
      <h2 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
        Connect Cloud Account
      </h2>
      <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 24 }}>
        Choose your primary cloud provider to get started. You can add more accounts later.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 24 }}>
        {CLOUD_PROVIDERS.map(p => (
          <label
            key={p.value}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 14,
              padding: '14px 16px',
              borderRadius: 10,
              border: `1.5px solid ${selected === p.value ? p.color : 'var(--border-secondary)'}`,
              backgroundColor: selected === p.value ? `${p.color}10` : 'var(--bg-input)',
              cursor: 'pointer',
              transition: 'border-color 0.15s, background 0.15s',
            }}
          >
            <input
              type="radio"
              name="cloud"
              value={p.value}
              checked={selected === p.value}
              onChange={() => setSelected(p.value)}
              style={{ accentColor: p.color }}
            />
            <div style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              backgroundColor: `${p.color}20`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}>
              <span style={{ fontSize: 10, fontWeight: 800, color: p.color }}>{p.label}</span>
            </div>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{p.label}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{p.desc}</div>
            </div>
          </label>
        ))}
      </div>

      <div style={{
        padding: '14px 16px',
        borderRadius: 10,
        backgroundColor: 'rgba(59,130,246,0.06)',
        border: '1px solid rgba(59,130,246,0.2)',
        marginBottom: 4,
      }}>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: 0 }}>
          You can connect your first cloud account after setup in the{' '}
          <button
            onClick={() => router.push('/onboarding')}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--accent-primary)',
              cursor: 'pointer',
              padding: 0,
              fontSize: 13,
              fontWeight: 600,
              textDecoration: 'underline',
            }}
          >
            Onboarding section
          </button>
          .
        </p>
      </div>

      <NavRow step={5} onBack={onBack} onSkip={onSkip} skipLabel="Skip for now">
        <PrimaryBtn onClick={onNext} style={{ width: '100%' }}>
          Continue <ArrowRight size={15} />
        </PrimaryBtn>
      </NavRow>
    </div>
  );
}

// ─── Step 6: All Done ─────────────────────────────────────────────────────────

function Step6Done({ onBack }) {
  const router = useRouter();

  const finish = (path) => {
    // Mark wizard complete so AppShell won't redirect again this session
    if (typeof window !== 'undefined') {
      sessionStorage.setItem('cspm_wizard_checked', 'done');
    }
    router.push(path);
  };

  return (
    <div style={{ textAlign: 'center', maxWidth: 440, margin: '0 auto' }}>
      <div style={{
        width: 80,
        height: 80,
        borderRadius: '50%',
        margin: '0 auto 28px',
        background: 'linear-gradient(135deg, #22c55e, #16a34a)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        boxShadow: '0 0 40px rgba(34,197,94,0.35)',
      }}>
        <CheckCircle size={38} color="white" />
      </div>

      <h2 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 14 }}>
        Your workspace is ready!
      </h2>
      <p style={{ fontSize: 15, color: 'var(--text-secondary)', lineHeight: 1.75, marginBottom: 36 }}>
        Threat Engine CSPM is set up and ready to protect your cloud infrastructure.
        Start by exploring the dashboard or connecting your first cloud account.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <PrimaryBtn onClick={() => finish('/dashboard')} style={{ width: '100%' }}>
          Go to Dashboard <ArrowRight size={16} />
        </PrimaryBtn>
        <GhostBtn onClick={() => finish('/onboarding')} style={{ width: '100%' }}>
          Connect a Cloud Account
        </GhostBtn>
      </div>

      <div style={{ marginTop: 20 }}>
        <button
          onClick={onBack}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            fontSize: 13,
            cursor: 'pointer',
            padding: 0,
          }}
        >
          <ArrowLeft size={14} /> Back
        </button>
      </div>
    </div>
  );
}

// ─── Root wizard page ─────────────────────────────────────────────────────────

export default function OnboardingSetupPage() {
  const [step, setStep] = useState(1);

  const next = useCallback(() => setStep(s => Math.min(s + 1, TOTAL)), []);
  const back = useCallback(() => setStep(s => Math.max(s - 1, 1)), []);

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: 'var(--bg-primary)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '40px 24px',
    }}>
      {/* Branding strip */}
      <div style={{ marginBottom: 32, textAlign: 'center' }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 10,
          marginBottom: 8,
        }}>
          <div style={{
            width: 32,
            height: 32,
            borderRadius: 8,
            background: 'linear-gradient(135deg, #2563eb, #6366f1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <Shield size={18} color="white" />
          </div>
          <span style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)' }}>
            Threat Engine CSPM
          </span>
        </div>
      </div>

      {/* Wizard card */}
      <div style={{
        width: '100%',
        maxWidth: 620,
        padding: '48px 52px',
        borderRadius: 20,
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-primary)',
        boxShadow: '0 4px 40px rgba(0,0,0,0.25)',
      }}>
        <ProgressDots current={step} />

        {step === 1 && <Step1Welcome onNext={next} />}
        {step === 2 && <Step2Workspace onNext={next} onBack={back} onSkip={next} />}
        {step === 3 && <Step3SSO onNext={next} onBack={back} onSkip={next} />}
        {step === 4 && <Step4Invite onNext={next} onBack={back} onSkip={next} />}
        {step === 5 && <Step5CloudAccount onNext={next} onBack={back} onSkip={next} />}
        {step === 6 && <Step6Done onBack={back} />}
      </div>

      {/* Footer */}
      <p style={{ marginTop: 24, fontSize: 12, color: 'var(--text-muted)' }}>
        Threat Engine CSPM &mdash; Multi-Cloud Security Posture Management
      </p>
    </div>
  );
}
