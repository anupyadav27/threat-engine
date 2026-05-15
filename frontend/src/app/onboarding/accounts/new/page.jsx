'use client';

/**
 * /onboarding/accounts/new — Multi-step onboarding wizard (story onboarding-D8)
 *
 * Steps:
 *   1. account-type  — Cloud / Vulnerability / SecOps / Database / Middleware
 *   2. provider      — CSP icon grid (cloud_csp only) or VCS selector
 *   3. credentials   — Catalog-driven form (from /src/config/credential-fields.json)
 *   4. validate      — Polls validation-status endpoint; pass → continue, fail → back
 *   5. complete      — Summary + "Trigger First Scan" button
 *
 * Wizard state is persisted to sessionStorage so a browser refresh does not
 * lose progress. It is cleared on completion or cancel.
 *
 * Security:
 *   - Password fields rendered as type="password" — never plaintext
 *   - No credentials written to console.log
 *   - Tenant ID comes from auth context (useTenant), never hardcoded
 *   - Gateway API calls use platform cookie auth (credentials: 'include')
 */

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Check, ChevronRight, ChevronLeft, X,
  Cloud, Shield, Code2, Database, Cpu,
  Eye, EyeOff, Play, Loader2, Copy, CheckCircle2,
} from 'lucide-react';
import { useTenant } from '@/lib/tenant-context';
import { postToEngine } from '@/lib/api';
import WizardStepper from '@/components/onboarding/WizardStepper';
import ProviderSelector from '@/components/onboarding/ProviderSelector';
import ValidationStatus from '@/components/onboarding/ValidationStatus';
import AgentInstallStep from '@/components/onboarding/AgentInstallStep';
import ScheduleModal from '@/components/onboarding/ScheduleModal';
import credentialFields from '@/config/credential-fields.json';
import {
  saveWizardState,
  loadWizardState,
  clearWizardState,
  INITIAL_WIZARD_STATE,
} from '@/lib/wizard-state';

// ── Step constants ────────────────────────────────────────────────────────────

const STEPS = [
  'account-type',
  'provider',
  'credentials',
  'validate',
  'complete',
];

const STEP_LABELS = {
  'account-type': 'Account Type',
  'provider':     'Provider',
  'credentials':  'Credentials',
  'validate':     'Validate',
  'complete':     'Complete',
};

// ── Account-type options ──────────────────────────────────────────────────────

const ACCOUNT_TYPE_OPTIONS = [
  {
    key: 'cloud_csp',
    icon: <Cloud className="w-6 h-6" />,
    label: 'Cloud (CSP)',
    desc: 'AWS, Azure, GCP, OCI, AliCloud, IBM, Kubernetes',
    color: '#3b82f6',
  },
  {
    key: 'vulnerability',
    icon: <Shield className="w-6 h-6" />,
    label: 'Vulnerability Agent',
    desc: 'Agent-based CVE scanning and SBOM inventory',
    color: '#8b5cf6',
  },
  {
    key: 'code_security',
    icon: <Code2 className="w-6 h-6" />,
    label: 'SecOps / Code',
    desc: 'SAST, DAST, IaC scanning via GitHub, GitLab, Bitbucket',
    color: '#10b981',
  },
  {
    key: 'database',
    icon: <Database className="w-6 h-6" />,
    label: 'Database',
    desc: 'PostgreSQL, MySQL, SQL Server, MongoDB, Oracle',
    color: '#f59e0b',
  },
  {
    key: 'middleware',
    icon: <Cpu className="w-6 h-6" />,
    label: 'Middleware',
    desc: 'Application middleware security monitoring (agent)',
    color: '#ef4444',
  },
];

// VCS providers for code_security
const VCS_PROVIDERS = [
  { key: 'github',      name: 'GitHub',         color: '#24292E', bg: 'rgba(36,41,46,0.12)' },
  { key: 'gitlab',      name: 'GitLab',         color: '#FC6D26', bg: 'rgba(252,109,38,0.12)' },
  { key: 'bitbucket',   name: 'Bitbucket',      color: '#0052CC', bg: 'rgba(0,82,204,0.12)' },
  { key: 'azure_devops',name: 'Azure DevOps',   color: '#0078D4', bg: 'rgba(0,120,212,0.12)' },
];

// DB providers for database
const DB_PROVIDERS = [
  { key: 'postgres', name: 'PostgreSQL', color: '#336791', bg: 'rgba(51,103,145,0.12)' },
  { key: 'mysql',    name: 'MySQL',      color: '#4479A1', bg: 'rgba(68,121,161,0.12)' },
  { key: 'mssql',    name: 'SQL Server', color: '#CC2927', bg: 'rgba(204,41,39,0.12)' },
  { key: 'mongodb',  name: 'MongoDB',    color: '#47A248', bg: 'rgba(71,162,72,0.12)' },
  { key: 'oracle',   name: 'Oracle DB',  color: '#C74634', bg: 'rgba(199,70,52,0.12)' },
];

// ── Credential Field Components ───────────────────────────────────────────────

function PasswordInput({ field, value, onChange }) {
  const [show, setShow] = useState(false);
  return (
    <div className="relative">
      <input
        type={show ? 'text' : 'password'}
        value={value || ''}
        placeholder={field.placeholder || ''}
        required={field.required}
        autoComplete="new-password"
        onChange={e => onChange(field.key, e.target.value)}
        className="w-full px-3 py-2 pr-10 text-sm rounded-lg border outline-none transition-colors"
        style={{
          backgroundColor: 'var(--bg-tertiary)',
          borderColor: 'var(--border-primary)',
          color: 'var(--text-primary)',
        }}
      />
      <button
        type="button"
        tabIndex={-1}
        onClick={() => setShow(s => !s)}
        className="absolute right-2.5 top-1/2 -translate-y-1/2 hover:opacity-70 transition-opacity"
        style={{ color: 'var(--text-muted)' }}
        aria-label={show ? 'Hide' : 'Show'}
      >
        {show ? <EyeOff size={15} /> : <Eye size={15} />}
      </button>
    </div>
  );
}

function CatalogField({ field, value, onChange }) {
  const label = (
    <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
      {field.label}
      {field.required && <span className="ml-1 text-red-400">*</span>}
    </label>
  );

  if (field.type === 'textarea') {
    return (
      <div>
        {label}
        <textarea
          value={value || ''}
          placeholder={field.placeholder || ''}
          required={field.required}
          rows={6}
          onChange={e => onChange(field.key, e.target.value)}
          className="w-full px-3 py-2 text-sm rounded-lg border outline-none transition-colors font-mono resize-y"
          style={{
            backgroundColor: 'var(--bg-tertiary)',
            borderColor: 'var(--border-primary)',
            color: 'var(--text-primary)',
            minHeight: '120px',
          }}
        />
      </div>
    );
  }

  if (field.type === 'password') {
    return (
      <div>
        {label}
        <PasswordInput field={field} value={value} onChange={onChange} />
      </div>
    );
  }

  // Default: text
  return (
    <div>
      {label}
      <input
        type="text"
        value={value || ''}
        placeholder={field.placeholder || ''}
        required={field.required}
        onChange={e => onChange(field.key, e.target.value)}
        className="w-full px-3 py-2 text-sm rounded-lg border outline-none transition-colors"
        style={{
          backgroundColor: 'var(--bg-tertiary)',
          borderColor: 'var(--border-primary)',
          color: 'var(--text-primary)',
        }}
      />
    </div>
  );
}

// ── CatalogCredentialForm ─────────────────────────────────────────────────────

function CatalogCredentialForm({ accountType, provider, onSubmit, submitting }) {
  const [values, setValues] = useState({});
  const [errors, setErrors] = useState({});

  // Fields come exclusively from the JSON catalog — no hardcoding
  const catalogEntry = credentialFields[accountType]?.[provider];
  const fields = catalogEntry?.fields ?? [];

  const handleChange = useCallback((key, val) => {
    setValues(v => ({ ...v, [key]: val }));
    setErrors(e => ({ ...e, [key]: undefined }));
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    // Validate required fields
    const newErrors = {};
    for (const f of fields) {
      if (f.required && !values[f.key]?.toString().trim()) {
        newErrors[f.key] = `${f.label} is required`;
      }
    }
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    // Never log credential values
    onSubmit(values);
  };

  if (fields.length === 0) {
    return (
      <div className="text-sm py-4" style={{ color: 'var(--text-muted)' }}>
        No credential fields required for this provider.
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4" noValidate>
      {fields.map(field => (
        <div key={field.key}>
          <CatalogField field={field} value={values[field.key]} onChange={handleChange} />
          {errors[field.key] && (
            <p className="mt-1 text-xs text-red-400">{errors[field.key]}</p>
          )}
        </div>
      ))}

      <button
        type="submit"
        disabled={submitting}
        className="w-full py-2.5 rounded-lg text-sm font-medium transition-opacity disabled:opacity-50 flex items-center justify-center gap-2"
        style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
      >
        {submitting
          ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</>
          : 'Save Credentials'}
      </button>
    </form>
  );
}

// ── VcsProviderSelector ───────────────────────────────────────────────────────

function SimpleProviderGrid({ providers, selected, onChange }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
      {providers.map(p => {
        const isSel = selected === p.key;
        return (
          <button
            key={p.key}
            type="button"
            onClick={() => onChange(p.key)}
            className="relative text-left rounded-xl border p-4 transition-all hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-blue-500"
            style={{
              backgroundColor: isSel ? p.bg : 'var(--bg-card)',
              borderColor: isSel ? p.color : 'var(--border-primary)',
              borderWidth: isSel ? '2px' : '1px',
            }}
          >
            {isSel && (
              <span
                className="absolute top-2 right-2 w-5 h-5 rounded-full flex items-center justify-center"
                style={{ backgroundColor: p.color }}
              >
                <Check size={11} color="white" />
              </span>
            )}
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center mb-2 text-xs font-bold"
              style={{ backgroundColor: p.bg, color: p.color }}
            >
              {p.name.slice(0, 3).toUpperCase()}
            </div>
            <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
              {p.name}
            </div>
          </button>
        );
      })}
    </div>
  );
}


// ── Schedule Step ─────────────────────────────────────────────────────────────

function ScheduleStep({ accountId, tenantId, onSkip, onScheduled }) {
  const [mode, setMode] = useState('default'); // default | adhoc
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const handleSave = async () => {
    if (mode === 'adhoc') {
      onSkip();
      return;
    }
    setSaving(true);
    setError('');
    try {
      const resp = await fetch('/gateway/api/v1/schedules/', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          account_id: accountId,
          tenant_id: tenantId,
          cron_expression: '0 2 * * 0', // Weekly Sunday 02:00 UTC
          engines_requested: ['discovery', 'check'],
          enabled: true,
        }),
      });
      if (!resp.ok) {
        const d = await resp.json().catch(() => ({}));
        throw new Error(d.detail || `Server error ${resp.status}`);
      }
      onScheduled();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        Choose how you want this account to be scanned.
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {[
          {
            key: 'default',
            title: 'Default (Weekly)',
            desc: 'Scan automatically every Sunday at 02:00 UTC. Recommended for most accounts.',
            color: 'var(--accent-primary)',
          },
          {
            key: 'adhoc',
            title: 'Adhoc / Manual',
            desc: 'No automatic schedule. Trigger scans manually from the account list.',
            color: '#6b7280',
          },
        ].map(opt => {
          const isSel = mode === opt.key;
          return (
            <button
              key={opt.key}
              type="button"
              onClick={() => setMode(opt.key)}
              className="text-left rounded-xl border p-4 transition-all hover:scale-[1.01] focus:outline-none"
              style={{
                backgroundColor: isSel ? 'rgba(59,130,246,0.08)' : 'var(--bg-card)',
                borderColor: isSel ? 'rgba(59,130,246,0.5)' : 'var(--border-primary)',
                borderWidth: isSel ? '2px' : '1px',
              }}
            >
              <div className="flex items-start gap-2">
                <div
                  className="w-4 h-4 rounded-full border-2 mt-0.5 flex-shrink-0 flex items-center justify-center"
                  style={{
                    borderColor: isSel ? 'var(--accent-primary)' : 'var(--border-primary)',
                  }}
                >
                  {isSel && (
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: 'var(--accent-primary)' }}
                    />
                  )}
                </div>
                <div>
                  <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    {opt.title}
                  </div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    {opt.desc}
                  </div>
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {error && (
        <div
          className="text-xs p-3 rounded-lg border"
          style={{
            borderColor: 'rgba(239,68,68,0.3)',
            backgroundColor: 'rgba(239,68,68,0.08)',
            color: '#f87171',
          }}
        >
          {error}
        </div>
      )}

      <button
        onClick={handleSave}
        disabled={saving}
        className="w-full py-2.5 rounded-lg text-sm font-medium transition-opacity disabled:opacity-50 flex items-center justify-center gap-2"
        style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
      >
        {saving
          ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</>
          : mode === 'adhoc' ? 'Skip — I\'ll schedule later' : 'Save Schedule & Continue'}
      </button>
    </div>
  );
}

// ── CompletionStep ────────────────────────────────────────────────────────────

function CompletionStep({ state, onRunNow }) {
  const [running, setRunning] = useState(false);
  const [scanRunId, setScanRunId] = useState(null);

  const handleRunNow = async () => {
    setRunning(true);
    try {
      const resp = await fetch('/gateway/api/v1/scans/run-now', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ account_id: state.accountId }),
      });
      if (!resp.ok) throw new Error(`Server error ${resp.status}`);
      const data = await resp.json();
      setScanRunId(data.scan_run_id || data.run_id);
      if (onRunNow) onRunNow(data);
    } catch (_) {
      // Best-effort — don't block user
    } finally {
      setRunning(false);
    }
  };

  const providerLabel = state.provider
    ? state.provider.toUpperCase()
    : state.accountType;

  return (
    <div className="space-y-5">
      <div
        className="flex items-center gap-3 p-4 rounded-xl border"
        style={{
          borderColor: 'rgba(34,197,94,0.35)',
          backgroundColor: 'rgba(34,197,94,0.08)',
        }}
      >
        <CheckCircle2 className="w-8 h-8 flex-shrink-0" style={{ color: '#22c55e' }} />
        <div>
          <div className="text-base font-semibold" style={{ color: '#22c55e' }}>
            Account onboarded successfully
          </div>
          <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Your account is ready. You can trigger the first scan now or wait for the schedule.
          </div>
        </div>
      </div>

      {/* Account summary */}
      <div
        className="rounded-xl border p-4 space-y-2"
        style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}
      >
        <div className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
          Account Summary
        </div>
        {[
          { label: 'Account Name', value: state.accountName || 'My Account' },
          { label: 'Type', value: state.accountType },
          { label: 'Provider', value: providerLabel },
          { label: 'Account ID', value: state.accountId || '—' },
        ].map(row => (
          <div key={row.label} className="flex justify-between items-center text-sm">
            <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
            <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{row.value}</span>
          </div>
        ))}
      </div>

      {scanRunId && (
        <div
          className="text-xs p-3 rounded-lg border"
          style={{
            borderColor: 'rgba(59,130,246,0.3)',
            backgroundColor: 'rgba(59,130,246,0.08)',
            color: 'var(--accent-primary)',
          }}
        >
          Scan triggered — run ID: <span className="font-mono">{scanRunId}</span>
        </div>
      )}

      <div className="flex gap-2">
        <button
          onClick={handleRunNow}
          disabled={running || !!scanRunId}
          className="flex-1 py-2.5 rounded-lg text-sm font-medium transition-opacity disabled:opacity-50 flex items-center justify-center gap-2"
          style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
        >
          {running
            ? <><Loader2 className="w-4 h-4 animate-spin" /> Triggering…</>
            : scanRunId
            ? <><Check className="w-4 h-4" /> Scan Triggered</>
            : <><Play className="w-4 h-4" /> Trigger First Scan</>}
        </button>
      </div>
    </div>
  );
}

// ── Main Wizard Page ──────────────────────────────────────────────────────────

export default function NewAccountWizardPage() {
  const router = useRouter();
  const { activeTenant } = useTenant();

  const [wizardState, setWizardStateRaw] = useState(INITIAL_WIZARD_STATE);
  const [submitting, setSubmitting]   = useState(false);
  const [apiError, setApiError]       = useState('');
  const [validationPassed, setValidationPassed] = useState(false);
  const [agentConnected, setAgentConnected] = useState(false);

  // Load persisted state on mount
  useEffect(() => {
    const saved = loadWizardState();
    if (saved) setWizardStateRaw(saved);
  }, []);

  // Persist state whenever it changes
  const setWizardState = useCallback((updater) => {
    setWizardStateRaw(prev => {
      const next = typeof updater === 'function' ? updater(prev) : updater;
      saveWizardState(next);
      return next;
    });
  }, []);

  const tenantId = activeTenant?.tenant_id;
  const currentStepIdx = STEPS.indexOf(wizardState.step);

  // ── Navigation helpers ──────────────────────────────────────────────────────

  function goTo(step) {
    setWizardState(s => ({ ...s, step }));
    setApiError('');
  }

  async function goNext() {
    // Determine next step based on current context
    const current = wizardState.step;
    const isAgentType = ['vulnerability', 'middleware'].includes(wizardState.accountType);

    if (current === 'account-type') {
      // Skip provider selection for agent-based types
      if (isAgentType) {
        // For agent types, create the account now so accountId is ready
        // before the install panel needs to call agent-token.
        if (!wizardState.accountId) {
          await createAgentAccount();
        } else {
          goTo('credentials');
        }
      } else {
        goTo('provider');
      }
    } else if (current === 'provider') {
      goTo('credentials');
    } else if (current === 'credentials') {
      // Agent types skip validate; go straight to complete
      if (isAgentType) {
        goTo('complete');
      } else {
        goTo('validate');
      }
    } else if (current === 'validate') {
      goTo('complete');
    }
  }

  /**
   * Create the cloud account for agent-based types (vulnerability / middleware).
   * Called once when the user clicks "Next" on the account-type step.
   * The accountId is stored in wizard state so AgentInstallStep can use it.
   */
  async function createAgentAccount() {
    if (!tenantId) {
      setApiError('No active tenant — please select a workspace first.');
      return;
    }
    setSubmitting(true);
    setApiError('');
    try {
      const resp = await fetch('/gateway/api/v1/cloud-accounts', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          account_name: wizardState.accountName || `${wizardState.accountType} Account`,
          account_type: wizardState.accountType,
          provider: 'agent',
          tenant_id: tenantId,
        }),
      });
      if (!resp.ok) {
        const d = await resp.json().catch(() => ({}));
        throw new Error(d.detail || `Failed to create account (${resp.status})`);
      }
      const { account_id } = await resp.json();
      setWizardState(s => ({ ...s, accountId: account_id }));
      goTo('credentials');
    } catch (e) {
      setApiError(e.message || 'An error occurred creating the account.');
    } finally {
      setSubmitting(false);
    }
  }

  function goBack() {
    const current = wizardState.step;
    if (current === 'provider')     goTo('account-type');
    else if (current === 'credentials') {
      const agentTypes = ['vulnerability', 'middleware'];
      goTo(agentTypes.includes(wizardState.accountType) ? 'account-type' : 'provider');
    }
    else if (current === 'validate')  goTo('credentials');
    else if (current === 'complete')  goTo('validate');
  }

  function handleCancel() {
    clearWizardState();
    router.push('/onboarding');
  }

  // ── Step 1: account-type selection ─────────────────────────────────────────

  function handleSelectAccountType(key) {
    setWizardState(s => ({
      ...s,
      accountType: key,
      provider: null,
    }));
  }

  // ── Step 2: provider selection ──────────────────────────────────────────────

  function handleSelectProvider(key) {
    setWizardState(s => ({ ...s, provider: key }));
  }

  // ── Step 3: credentials form submit ────────────────────────────────────────

  async function handleCredentialsSubmit(credValues) {
    if (!tenantId) {
      setApiError('No active tenant — please select a workspace first.');
      return;
    }

    setSubmitting(true);
    setApiError('');

    try {
      // 1. Create the cloud account
      const createResp = await fetch('/gateway/api/v1/cloud-accounts', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          account_name: wizardState.accountName || `${wizardState.provider || wizardState.accountType} Account`,
          account_type: wizardState.accountType,
          provider: wizardState.provider,
          tenant_id: tenantId,
        }),
      });

      if (!createResp.ok) {
        const d = await createResp.json().catch(() => ({}));
        throw new Error(d.detail || `Failed to create account (${createResp.status})`);
      }

      const { account_id } = await createResp.json();

      // 2. Store credentials
      const credResp = await fetch(`/gateway/api/v1/cloud-accounts/${account_id}/credentials`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credValues), // Do NOT log credValues
      });

      if (!credResp.ok) {
        const d = await credResp.json().catch(() => ({}));
        throw new Error(d.detail || `Failed to save credentials (${credResp.status})`);
      }

      setWizardState(s => ({ ...s, accountId: account_id }));
      goNext(); // advance to 'validate'
    } catch (e) {
      setApiError(e.message || 'An error occurred saving credentials.');
    } finally {
      setSubmitting(false);
    }
  }

  // ── Step 4: validation callbacks ───────────────────────────────────────────

  function handleValidationPass() {
    setValidationPassed(true);
  }

  function handleValidationFail(msg) {
    setWizardState(s => ({
      ...s,
      validationStatus: 'fail',
      validationError: msg,
    }));
  }

  function handleReEnterCredentials() {
    setValidationPassed(false);
    setWizardState(s => ({
      ...s,
      validationStatus: null,
      validationError: null,
      // Keep accountId so we can PATCH credentials instead of creating a new account
    }));
    goTo('credentials');
  }

  // ── Derived visible steps (skip 'provider' for agent types) ────────────────

  const agentTypes = ['vulnerability', 'middleware'];
  const visibleSteps = wizardState.accountType && agentTypes.includes(wizardState.accountType)
    ? STEPS.filter(s => s !== 'provider')
    : STEPS;

  const visibleIdx = visibleSteps.indexOf(wizardState.step);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Page header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Add Cloud Account
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Step {visibleIdx + 1} of {visibleSteps.length} — {STEP_LABELS[wizardState.step]}
          </p>
        </div>
        <button
          onClick={handleCancel}
          className="flex items-center gap-1.5 text-sm hover:opacity-70 transition-opacity"
          style={{ color: 'var(--text-muted)' }}
        >
          <X size={16} /> Cancel
        </button>
      </div>

      {/* Step indicator */}
      <WizardStepper steps={visibleSteps} currentStep={wizardState.step} />

      {/* Card */}
      <div
        className="rounded-2xl border p-6 space-y-6"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >

        {/* ── Step 1: Account Type ── */}
        {wizardState.step === 'account-type' && (
          <div className="space-y-5">
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                What type of account do you want to add?
              </h2>
              <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                Select the account type that matches your infrastructure.
              </p>
            </div>

            {/* Account name */}
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                Account Name <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                value={wizardState.accountName}
                placeholder="e.g. Production AWS, Dev GCP"
                onChange={e => setWizardState(s => ({ ...s, accountName: e.target.value }))}
                className="w-full px-3 py-2 text-sm rounded-lg border outline-none"
                style={{
                  backgroundColor: 'var(--bg-tertiary)',
                  borderColor: 'var(--border-primary)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>

            {/* Type grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {ACCOUNT_TYPE_OPTIONS.map(opt => {
                const isSel = wizardState.accountType === opt.key;
                return (
                  <button
                    key={opt.key}
                    type="button"
                    onClick={() => handleSelectAccountType(opt.key)}
                    className="relative text-left rounded-xl border p-4 transition-all hover:scale-[1.01] focus:outline-none focus:ring-2 focus:ring-blue-500"
                    style={{
                      backgroundColor: isSel
                        ? `${opt.color}10`
                        : 'var(--bg-tertiary)',
                      borderColor: isSel ? opt.color : 'var(--border-primary)',
                      borderWidth: isSel ? '2px' : '1px',
                    }}
                  >
                    {isSel && (
                      <span
                        className="absolute top-2 right-2 w-5 h-5 rounded-full flex items-center justify-center"
                        style={{ backgroundColor: opt.color }}
                      >
                        <Check size={11} color="white" />
                      </span>
                    )}
                    <div
                      className="mb-2"
                      style={{ color: isSel ? opt.color : 'var(--text-muted)' }}
                    >
                      {opt.icon}
                    </div>
                    <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                      {opt.label}
                    </div>
                    <div className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>
                      {opt.desc}
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Next */}
            <div className="flex justify-end">
              <button
                onClick={goNext}
                disabled={!wizardState.accountType || !wizardState.accountName.trim()}
                className="flex items-center gap-1.5 px-5 py-2.5 rounded-lg text-sm font-medium transition-opacity disabled:opacity-40"
                style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
              >
                Next <ChevronRight size={15} />
              </button>
            </div>
          </div>
        )}

        {/* ── Step 2: Provider ── */}
        {wizardState.step === 'provider' && (
          <div className="space-y-5">
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                {wizardState.accountType === 'cloud_csp' && 'Select your cloud provider'}
                {wizardState.accountType === 'code_security' && 'Select your version control system'}
                {wizardState.accountType === 'database' && 'Select your database engine'}
              </h2>
              <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                Choose the provider to configure credential fields.
              </p>
            </div>

            {wizardState.accountType === 'cloud_csp' && (
              <ProviderSelector
                selected={wizardState.provider}
                onChange={handleSelectProvider}
              />
            )}

            {wizardState.accountType === 'code_security' && (
              <SimpleProviderGrid
                providers={VCS_PROVIDERS}
                selected={wizardState.provider}
                onChange={handleSelectProvider}
              />
            )}

            {wizardState.accountType === 'database' && (
              <SimpleProviderGrid
                providers={DB_PROVIDERS}
                selected={wizardState.provider}
                onChange={handleSelectProvider}
              />
            )}

            <div className="flex justify-between">
              <button
                onClick={goBack}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm border hover:opacity-80 transition-opacity"
                style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              >
                <ChevronLeft size={15} /> Back
              </button>
              <button
                onClick={goNext}
                disabled={!wizardState.provider}
                className="flex items-center gap-1.5 px-5 py-2.5 rounded-lg text-sm font-medium transition-opacity disabled:opacity-40"
                style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
              >
                Next <ChevronRight size={15} />
              </button>
            </div>
          </div>
        )}

        {/* ── Step 3: Credentials ── */}
        {wizardState.step === 'credentials' && (
          <div className="space-y-5">
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                {['vulnerability', 'middleware'].includes(wizardState.accountType)
                  ? 'Install the Onam Security Agent'
                  : 'Enter Credentials'}
              </h2>
              <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                {['vulnerability', 'middleware'].includes(wizardState.accountType)
                  ? 'Generate a secure install command and run it on your target host. The agent registers automatically.'
                  : 'Credentials are stored encrypted in AWS Secrets Manager. Never logged or exposed in the UI.'}
              </p>
            </div>

            {apiError && (
              <div
                className="text-xs p-3 rounded-lg border"
                style={{
                  borderColor: 'rgba(239,68,68,0.3)',
                  backgroundColor: 'rgba(239,68,68,0.08)',
                  color: '#f87171',
                }}
              >
                {apiError}
              </div>
            )}

            {/* Agent-based types: AgentInstallStep (D9) */}
            {['vulnerability', 'middleware'].includes(wizardState.accountType) ? (
              <AgentInstallStep
                accountId={wizardState.accountId}
                onConnected={() => {
                  setAgentConnected(true);
                  // AC7: auto-advance to complete after 3-second display delay
                  setTimeout(() => goTo('complete'), 3500);
                }}
              />
            ) : (
              <CatalogCredentialForm
                accountType={wizardState.accountType}
                provider={wizardState.provider}
                onSubmit={handleCredentialsSubmit}
                submitting={submitting}
              />
            )}

            <div className="flex justify-between">
              <button
                onClick={goBack}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm border hover:opacity-80 transition-opacity"
                style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              >
                <ChevronLeft size={15} /> Back
              </button>
              {/* Agent types: skip/continue button always available (AC8 — agent not required) */}
              {['vulnerability', 'middleware'].includes(wizardState.accountType) && (
                <button
                  onClick={() => goTo('complete')}
                  className="flex items-center gap-1.5 px-5 py-2.5 rounded-lg text-sm font-medium"
                  style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
                >
                  {agentConnected ? 'Continue to Schedule Setup' : 'Skip — Continue Later'}
                  <ChevronRight size={15} />
                </button>
              )}
            </div>
          </div>
        )}

        {/* ── Step 4: Validate ── */}
        {wizardState.step === 'validate' && (
          <div className="space-y-5">
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                Validating Credentials
              </h2>
              <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                CSPM is verifying your credentials against the cloud provider API.
              </p>
            </div>

            <ValidationStatus
              accountId={wizardState.accountId}
              onPass={handleValidationPass}
              onFail={handleValidationFail}
              onReEnter={handleReEnterCredentials}
            />

            {validationPassed && (
              <div className="flex justify-end">
                <button
                  onClick={goNext}
                  className="flex items-center gap-1.5 px-5 py-2.5 rounded-lg text-sm font-medium"
                  style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
                >
                  Continue to Schedule Setup <ChevronRight size={15} />
                </button>
              </div>
            )}
          </div>
        )}

        {/* ── Step 5: Complete ── */}
        {wizardState.step === 'complete' && (
          <div className="space-y-5">
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                Account Setup Complete
              </h2>
            </div>

            {/* Schedule sub-step — inline ScheduleModal (AC9) */}
            <div
              className="rounded-xl border p-4"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}
            >
              <div className="text-xs font-semibold mb-3" style={{ color: 'var(--text-muted)' }}>
                Configure Scan Schedule
              </div>
              <ScheduleModal
                inlineMode
                account={{
                  account_id: wizardState.accountId,
                  account_type: wizardState.accountType,
                  provider: wizardState.provider,
                  tenant_id: tenantId,
                }}
                existingSchedule={null}
                onClose={() => {}}
                onSaved={() => {
                  clearWizardState();
                  router.push('/onboarding');
                }}
              />
            </div>

            {/* Account summary */}
            <CompletionStep
              state={wizardState}
              onRunNow={() => {}}
            />

            <div className="flex justify-end pt-2">
              <button
                onClick={() => {
                  clearWizardState();
                  router.push('/onboarding');
                }}
                className="flex items-center gap-1.5 px-5 py-2.5 rounded-lg text-sm font-medium border hover:opacity-80 transition-opacity"
                style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              >
                Back to Account List
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
