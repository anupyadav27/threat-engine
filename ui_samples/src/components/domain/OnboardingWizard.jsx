'use client';
/**
 * OnboardingWizard — 5-step cloud account onboarding
 *
 * Step 1: Select tenant workspace, account name, provider + auth method
 * Step 2: Enter credentials (fields per provider)
 * Step 3: Validate — auto-runs, shows progress + result
 * Step 4: Configure scan schedule (presets, engines, regions, notifications)
 * Step 5: Summary — review everything, launch
 *
 * API calls (onboarding engine):
 *   POST  /api/v1/cloud-accounts                        → create account record
 *   POST  /api/v1/cloud-accounts/{id}/credentials       → store + validate creds
 *   POST  /api/v1/schedules                             → create schedule
 */

import { useState } from 'react';
import {
  ChevronDown, Download, X, CheckCircle2, XCircle, Loader2,
  Calendar, Clock, Globe, Layers, Bell, ChevronRight,
} from 'lucide-react';
import { postToEngine, getFromEngine } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';

// ── Provider catalogue ────────────────────────────────────────────────────────

const PROVIDERS = {
  aws:      { name: 'AWS',      full: 'Amazon Web Services',         color: '#FF9900' },
  azure:    { name: 'Azure',    full: 'Microsoft Azure',             color: '#0078D4' },
  gcp:      { name: 'GCP',      full: 'Google Cloud Platform',       color: '#4285F4' },
  oci:      { name: 'OCI',      full: 'Oracle Cloud Infrastructure', color: '#F80000' },
  alicloud: { name: 'AliCloud', full: 'Alibaba Cloud',               color: '#FF6A00' },
  ibm:      { name: 'IBM',      full: 'IBM Cloud',                   color: '#1F70C1' },
  k8s:      { name: 'K8s',      full: 'Kubernetes Cluster',          color: '#326CE5' },
};

// ── Auth methods + credential fields per provider ─────────────────────────────

const AUTH_METHODS = {
  aws: [
    { value: 'iam_role',   label: 'IAM Role (Recommended)', desc: 'Cross-account assume role — most secure' },
    { value: 'access_key', label: 'Access Keys',             desc: 'Static access key pair' },
  ],
  azure:    [{ value: 'service_principal', label: 'Service Principal', desc: 'Azure AD app registration' }],
  gcp:      [{ value: 'service_account',   label: 'Service Account',   desc: 'GCP service account JSON key' }],
  oci:      [{ value: 'api_key',           label: 'API Key',           desc: 'OCI user API key pair' }],
  alicloud: [{ value: 'access_key',        label: 'Access Key',        desc: 'Alibaba Cloud access key pair' }],
  ibm:      [{ value: 'api_key',           label: 'API Key',           desc: 'IBM Cloud API key' }],
  k8s:      [{ value: 'kubeconfig',        label: 'Kubeconfig',        desc: 'Kubernetes cluster config' }],
};

const CREDENTIAL_FIELDS = {
  aws_iam_role: [
    { key: 'account_id',  label: 'AWS Account ID', placeholder: '123456789012',                        secret: false },
    { key: 'role_arn',    label: 'Role ARN',        placeholder: 'arn:aws:iam::123456789012:role/Name', secret: false },
    { key: 'external_id', label: 'External ID',     placeholder: 'Optional — leave blank if not set',   secret: false, optional: true },
  ],
  aws_access_key: [
    { key: 'access_key_id',     label: 'Access Key ID',     placeholder: 'AKIA…', secret: false },
    { key: 'secret_access_key', label: 'Secret Access Key', placeholder: '••••',  secret: true  },
  ],
  azure_service_principal: [
    { key: 'subscription_id', label: 'Subscription ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', secret: false },
    { key: 'tenant_id',       label: 'Azure Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', secret: false },
    { key: 'client_id',       label: 'Client (App) ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', secret: false },
    { key: 'client_secret',   label: 'Client Secret',   placeholder: '••••',                                 secret: true  },
  ],
  gcp_service_account: [
    { key: 'project_id',          label: 'Project ID',              placeholder: 'my-gcp-project', secret: false },
    { key: 'service_account_key', label: 'Service Account Key JSON', placeholder: 'Paste JSON…',    secret: true, textarea: true },
  ],
  oci_api_key: [
    { key: 'tenancy_ocid', label: 'Tenancy OCID', placeholder: 'ocid1.tenancy.oc1…', secret: false },
    { key: 'user_ocid',    label: 'User OCID',    placeholder: 'ocid1.user.oc1…',    secret: false },
    { key: 'fingerprint',  label: 'Fingerprint',  placeholder: 'xx:xx:xx:…',          secret: false },
    { key: 'private_key',  label: 'Private Key',  placeholder: '-----BEGIN RSA…',     secret: true, textarea: true },
  ],
  alicloud_access_key: [
    { key: 'access_key_id',     label: 'Access Key ID',     placeholder: 'LTAI…', secret: false },
    { key: 'access_key_secret', label: 'Access Key Secret', placeholder: '••••',  secret: true  },
  ],
  ibm_api_key: [
    { key: 'api_key',    label: 'API Key',    placeholder: '••••', secret: true  },
    { key: 'account_id', label: 'Account ID', placeholder: 'IBM Cloud account ID', secret: false },
  ],
  k8s_kubeconfig: [
    { key: 'kubeconfig', label: 'Kubeconfig YAML', placeholder: 'apiVersion: v1\nkind: Config\n…', secret: true, textarea: true },
  ],
};

function getFields(provider, authMethod) {
  return CREDENTIAL_FIELDS[`${provider}_${authMethod}`] || [];
}

// ── Schedule config constants ─────────────────────────────────────────────────

const CRON_PRESETS = [
  { key: 'hourly',    label: 'Every Hour',          cron: '0 * * * *',   desc: 'Runs at the top of every hour' },
  { key: 'daily',     label: 'Daily at 2 AM UTC',   cron: '0 2 * * *',   desc: 'Once a day, every day' },
  { key: 'weekly',    label: 'Weekly (Sunday 2 AM)',  cron: '0 2 * * 0',   desc: 'Recommended for most accounts' },
  { key: 'bi_weekly', label: 'Every 2 Weeks',        cron: '0 2 * * 1/2', desc: 'Every other Monday at 2 AM' },
  { key: 'monthly',   label: 'Monthly (1st, 2 AM)',  cron: '0 2 1 * *',   desc: 'First of each month' },
  { key: 'custom',    label: 'Custom cron…',          cron: '',            desc: 'Enter your own cron expression' },
];

const ALL_ENGINES = ['discovery', 'check', 'inventory', 'threat', 'compliance', 'iam', 'datasec'];
const ENGINE_LABELS = {
  discovery:  { label: 'Discovery',   desc: 'Enumerate cloud resources' },
  check:      { label: 'Check',       desc: 'Evaluate compliance rules' },
  inventory:  { label: 'Inventory',   desc: 'Normalize + track assets' },
  threat:     { label: 'Threat',      desc: 'MITRE ATT&CK mapping' },
  compliance: { label: 'Compliance',  desc: 'Framework reports (CIS, NIST…)' },
  iam:        { label: 'IAM',         desc: 'IAM posture analysis' },
  datasec:    { label: 'Data Sec',    desc: 'Data classification & security' },
};

const COMMON_TIMEZONES = [
  'UTC', 'America/New_York', 'America/Chicago', 'America/Los_Angeles',
  'Europe/London', 'Europe/Berlin', 'Asia/Kolkata', 'Asia/Tokyo',
  'Asia/Singapore', 'Australia/Sydney',
];

// ── Reusable field ────────────────────────────────────────────────────────────

function Field({ def, value, onChange }) {
  const base = 'w-full px-3 py-2 rounded-lg text-sm outline-none transition-colors';
  const style = { backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' };

  return (
    <div>
      <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        {def.label}
        {def.optional && <span className="ml-1 text-xs font-normal" style={{ color: 'var(--text-muted)' }}>(optional)</span>}
      </label>
      {def.textarea ? (
        <textarea rows={4} value={value || ''} onChange={e => onChange(def.key, e.target.value)}
          placeholder={def.placeholder} className={`${base} resize-none font-mono text-xs`} style={style} />
      ) : (
        <input type={def.secret ? 'password' : 'text'} value={value || ''} onChange={e => onChange(def.key, e.target.value)}
          placeholder={def.placeholder} className={base} style={style} />
      )}
    </div>
  );
}

// ── Step 1: Provider selection ────────────────────────────────────────────────

function Step1({ form, setForm }) {
  const { tenants } = useTenant();

  return (
    <div className="space-y-5">
      {/* Tenant */}
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
          Workspace <span className="text-red-400">*</span>
        </label>
        <div className="relative">
          <select value={form.tenantId} onChange={e => setForm(f => ({ ...f, tenantId: e.target.value }))}
            className="w-full px-3 py-2 rounded-lg text-sm outline-none appearance-none"
            style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }}>
            <option value="">Select workspace…</option>
            {tenants.map(t => <option key={t.tenant_id} value={t.tenant_id}>{t.tenant_name}</option>)}
          </select>
          <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
        </div>
      </div>

      {/* Account name */}
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
          Account Name <span className="text-red-400">*</span>
        </label>
        <input type="text" value={form.accountName} onChange={e => setForm(f => ({ ...f, accountName: e.target.value }))}
          placeholder="e.g. Production AWS, Dev Azure"
          className="w-full px-3 py-2 rounded-lg text-sm outline-none"
          style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }} />
      </div>

      {/* Provider grid */}
      <div>
        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
          Cloud Provider <span className="text-red-400">*</span>
        </label>
        <div className="grid grid-cols-4 gap-2">
          {Object.entries(PROVIDERS).map(([key, p]) => {
            const selected = form.provider === key;
            return (
              <button key={key} onClick={() => setForm(f => ({ ...f, provider: key, authMethod: '' }))}
                className="flex flex-col items-center gap-1.5 p-3 rounded-lg text-center transition-all"
                style={{
                  border: `2px solid ${selected ? p.color : 'var(--border-primary)'}`,
                  backgroundColor: selected ? `${p.color}18` : 'var(--bg-tertiary)',
                }}>
                <span className="text-xs font-bold" style={{ color: selected ? p.color : 'var(--text-secondary)' }}>{p.name}</span>
                <span className="text-[9px] leading-tight" style={{ color: 'var(--text-muted)' }}>{p.full}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Auth method */}
      {form.provider && (
        <div>
          <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
            Authentication Method <span className="text-red-400">*</span>
          </label>
          <div className="space-y-2">
            {AUTH_METHODS[form.provider]?.map(m => {
              const selected = form.authMethod === m.value;
              return (
                <button key={m.value} onClick={() => setForm(f => ({ ...f, authMethod: m.value }))}
                  className="w-full flex items-start gap-3 p-3 rounded-lg text-left transition-all"
                  style={{ border: `2px solid ${selected ? 'var(--accent-primary)' : 'var(--border-primary)'}`, backgroundColor: selected ? 'rgba(59,130,246,0.08)' : 'var(--bg-tertiary)' }}>
                  <div className={`mt-0.5 w-4 h-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center ${selected ? 'border-blue-500' : 'border-gray-500'}`}>
                    {selected && <div className="w-2 h-2 rounded-full bg-blue-500" />}
                  </div>
                  <div>
                    <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{m.label}</div>
                    <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{m.desc}</div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Step 2: Credential fields ─────────────────────────────────────────────────

function Step2({ form, setForm }) {
  const fields   = getFields(form.provider, form.authMethod);
  const provider = PROVIDERS[form.provider];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
          {provider?.name} — {AUTH_METHODS[form.provider]?.find(m => m.value === form.authMethod)?.label}
        </span>
      </div>

      {form.provider === 'aws' && form.authMethod === 'iam_role' && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
          style={{ backgroundColor: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)', color: 'var(--text-secondary)' }}>
          <span className="flex-1">Create the IAM role in your AWS account first.</span>
          <button onClick={() => window.open('/onboarding/api/v1/cloud-accounts/aws/cloudformation-template', '_blank')}
            className="flex items-center gap-1 text-blue-400 hover:text-blue-300 font-medium flex-shrink-0">
            <Download className="w-3 h-3" /> CloudFormation template
          </button>
        </div>
      )}

      {fields.map(def => (
        <Field key={def.key} def={def} value={form.credentials[def.key]}
          onChange={(k, v) => setForm(f => ({ ...f, credentials: { ...f.credentials, [k]: v } }))} />
      ))}
    </div>
  );
}

// ── Step 3: Validation progress ───────────────────────────────────────────────

function Step3({ steps, result, form }) {
  const provider = PROVIDERS[form.provider];

  return (
    <div className="space-y-5">
      <div className="space-y-2">
        {steps.map((s, i) => (
          <div key={i} className="flex items-center gap-3">
            <div className="w-5 h-5 flex-shrink-0 flex items-center justify-center">
              {s.status === 'done'    && <CheckCircle2 className="w-5 h-5 text-green-400" />}
              {s.status === 'running' && <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />}
              {s.status === 'error'   && <XCircle className="w-5 h-5 text-red-400" />}
              {s.status === 'pending' && <div className="w-4 h-4 rounded-full" style={{ border: '2px solid var(--border-primary)' }} />}
            </div>
            <span className="text-sm" style={{
              color: s.status === 'done' ? 'var(--text-primary)' :
                     s.status === 'running' ? 'var(--accent-primary)' :
                     s.status === 'error' ? '#f87171' : 'var(--text-muted)'
            }}>
              {s.label}
              {s.detail && <span className="ml-2 text-xs" style={{ color: 'var(--text-muted)' }}>{s.detail}</span>}
            </span>
          </div>
        ))}
      </div>

      {result && (
        <div className="p-4 rounded-lg" style={{
          backgroundColor: result.success ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
          border: `1px solid ${result.success ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`,
        }}>
          <p className="text-sm font-medium" style={{ color: result.success ? '#4ade80' : '#f87171' }}>
            {result.success ? `✅ ${provider?.name} account validated` : '❌ Validation failed'}
          </p>
          {result.account_number && (
            <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
              Account ID detected: <span className="font-mono font-medium">{result.account_number}</span>
            </p>
          )}
          {!result.success && result.message && (
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{result.message}</p>
          )}
          {!result.success && result.errors?.length > 0 && (
            <ul className="mt-2 space-y-0.5">
              {result.errors.map((e, i) => <li key={i} className="text-xs text-red-400">• {e}</li>)}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

// ── Step 4: Schedule configuration ───────────────────────────────────────────

function Step4({ schedule, setSchedule }) {
  const selectedPreset = CRON_PRESETS.find(p => p.cron === schedule.cron_expression && p.key !== 'custom') || CRON_PRESETS.find(p => p.key === 'custom');
  const [preset, setPreset] = useState(selectedPreset?.key || 'weekly');

  function selectPreset(key) {
    setPreset(key);
    const p = CRON_PRESETS.find(x => x.key === key);
    if (p && p.key !== 'custom') setSchedule(s => ({ ...s, cron_expression: p.cron }));
  }

  function toggleEngine(eng) {
    setSchedule(s => ({
      ...s,
      engines_requested: s.engines_requested.includes(eng)
        ? s.engines_requested.filter(e => e !== eng)
        : [...s.engines_requested, eng],
    }));
  }

  return (
    <div className="space-y-5">
      {/* Frequency presets */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Clock className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>Scan Frequency</span>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {CRON_PRESETS.map(p => (
            <button key={p.key} onClick={() => selectPreset(p.key)}
              className="flex flex-col gap-0.5 p-3 rounded-lg text-left transition-all"
              style={{
                border: `2px solid ${preset === p.key ? 'var(--accent-primary)' : 'var(--border-primary)'}`,
                backgroundColor: preset === p.key ? 'rgba(59,130,246,0.08)' : 'var(--bg-tertiary)',
              }}>
              <span className="text-sm font-medium" style={{ color: preset === p.key ? 'var(--accent-primary)' : 'var(--text-primary)' }}>
                {p.label}
              </span>
              <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{p.desc}</span>
            </button>
          ))}
        </div>

        {/* Custom cron input */}
        {preset === 'custom' && (
          <div className="mt-3">
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Cron Expression</label>
            <input type="text" value={schedule.cron_expression}
              onChange={e => setSchedule(s => ({ ...s, cron_expression: e.target.value }))}
              placeholder="0 2 * * 0  (min hour dom month dow)"
              className="w-full px-3 py-2 rounded-lg text-sm font-mono outline-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }} />
          </div>
        )}
      </div>

      {/* Timezone */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Globe className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>Timezone</span>
        </div>
        <div className="relative">
          <select value={schedule.timezone} onChange={e => setSchedule(s => ({ ...s, timezone: e.target.value }))}
            className="w-full px-3 py-2 rounded-lg text-sm outline-none appearance-none"
            style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }}>
            {COMMON_TIMEZONES.map(tz => <option key={tz} value={tz}>{tz}</option>)}
          </select>
          <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
        </div>
      </div>

      {/* Engines to run */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Layers className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>Engines to Run</span>
        </div>
        <div className="grid grid-cols-2 gap-1.5">
          {ALL_ENGINES.map(eng => {
            const enabled = schedule.engines_requested.includes(eng);
            const info = ENGINE_LABELS[eng];
            return (
              <button key={eng} onClick={() => toggleEngine(eng)}
                className="flex items-start gap-2 p-2.5 rounded-lg text-left transition-all"
                style={{
                  border: `1px solid ${enabled ? 'rgba(59,130,246,0.4)' : 'var(--border-primary)'}`,
                  backgroundColor: enabled ? 'rgba(59,130,246,0.06)' : 'var(--bg-tertiary)',
                }}>
                <div className={`mt-0.5 w-3.5 h-3.5 rounded flex-shrink-0 flex items-center justify-center text-white text-[9px] font-bold ${enabled ? 'bg-blue-500' : ''}`}
                  style={{ border: enabled ? 'none' : '1px solid var(--border-primary)' }}>
                  {enabled && '✓'}
                </div>
                <div>
                  <div className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{info.label}</div>
                  <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{info.desc}</div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Notifications */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Bell className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>Notifications</span>
        </div>
        <div className="space-y-2">
          {[
            { key: 'notify_on_failure', label: 'Notify on scan failure' },
            { key: 'notify_on_success', label: 'Notify on scan success' },
          ].map(({ key, label }) => (
            <label key={key} className="flex items-center gap-2.5 cursor-pointer">
              <input type="checkbox" checked={schedule[key]} onChange={e => setSchedule(s => ({ ...s, [key]: e.target.checked }))}
                className="w-4 h-4 rounded" />
              <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Enable / Disable toggle */}
      <div className="flex items-center justify-between pt-1">
        <div>
          <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Enable schedule</div>
          <div className="text-xs" style={{ color: 'var(--text-muted)' }}>Disable to save config without activating</div>
        </div>
        <button onClick={() => setSchedule(s => ({ ...s, enabled: !s.enabled }))}
          className="relative w-11 h-6 rounded-full transition-colors flex-shrink-0"
          style={{ backgroundColor: schedule.enabled ? 'var(--accent-primary)' : 'var(--bg-tertiary)', border: '1px solid var(--border-primary)' }}>
          <span className="absolute top-0.5 w-5 h-5 rounded-full bg-white transition-all shadow-sm"
            style={{ left: schedule.enabled ? '22px' : '2px' }} />
        </button>
      </div>
    </div>
  );
}

// ── Step 5: Summary ───────────────────────────────────────────────────────────

function Step5({ form, schedule, accountId, result, launching, launchError }) {
  const provider = PROVIDERS[form.provider];
  const authLabel = AUTH_METHODS[form.provider]?.find(m => m.value === form.authMethod)?.label;
  const freqPreset = CRON_PRESETS.find(p => p.cron === schedule.cron_expression)?.label || schedule.cron_expression;

  const sections = [
    {
      icon: '☁️',
      title: 'Cloud Account',
      rows: [
        { label: 'Account Name', value: form.accountName },
        { label: 'Provider', value: `${provider?.name} — ${provider?.full}` },
        { label: 'Auth Method', value: authLabel },
        result?.account_number && { label: 'Account ID', value: result.account_number, mono: true },
        { label: 'Account Record', value: accountId?.slice(0, 8) + '…', mono: true },
      ].filter(Boolean),
    },
    {
      icon: '📅',
      title: 'Scan Schedule',
      rows: [
        { label: 'Frequency', value: freqPreset },
        { label: 'Cron', value: schedule.cron_expression, mono: true },
        { label: 'Timezone', value: schedule.timezone },
        { label: 'Status', value: schedule.enabled ? 'Enabled' : 'Disabled (paused)' },
      ],
    },
    {
      icon: '⚙️',
      title: 'Engines',
      rows: [{ label: 'Selected', value: schedule.engines_requested.map(e => ENGINE_LABELS[e]?.label).join(', ') }],
    },
  ];

  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        Review your configuration. Clicking <strong>Launch</strong> will save the schedule and activate scanning.
      </p>

      {sections.map(sec => (
        <div key={sec.title} className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--border-primary)' }}>
          <div className="flex items-center gap-2 px-4 py-2.5" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <span>{sec.icon}</span>
            <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{sec.title}</span>
          </div>
          <div className="divide-y" style={{ divideColor: 'var(--border-primary)' }}>
            {sec.rows.map((row, i) => (
              <div key={i} className="flex items-start justify-between px-4 py-2 gap-4">
                <span className="text-xs flex-shrink-0 w-28" style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                <span className={`text-xs text-right ${row.mono ? 'font-mono' : ''}`} style={{ color: 'var(--text-secondary)' }}>{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      ))}

      {launchError && (
        <div className="px-4 py-3 rounded-lg text-sm text-red-400" style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)' }}>
          {launchError}
        </div>
      )}

      {launching && (
        <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-muted)' }}>
          <Loader2 className="w-4 h-4 animate-spin text-blue-400" /> Saving schedule and activating…
        </div>
      )}
    </div>
  );
}

// ── Wizard shell ──────────────────────────────────────────────────────────────

const STEP_LABELS = ['Select Provider', 'Credentials', 'Validate', 'Schedule', 'Summary'];

export default function OnboardingWizard({ onComplete = () => {}, onCancel = () => {} }) {
  const { customerId } = useTenant();

  const [step, setStep] = useState(1);
  const [form, setForm] = useState({
    tenantId:    '',
    accountName: '',
    provider:    '',
    authMethod:  '',
    credentials: {},
  });
  const [schedule, setSchedule] = useState({
    cron_expression:  '0 2 * * 0',
    timezone:         'UTC',
    enabled:          true,
    engines_requested: [...ALL_ENGINES],
    notify_on_failure: true,
    notify_on_success: false,
  });

  // Step 3 state
  const [validationSteps, setValidationSteps] = useState([]);
  const [result, setResult] = useState(null);
  const [accountId, setAccountId] = useState(null);

  // Step 5 state
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState(null);

  function updateVStep(i, patch) {
    setValidationSteps(prev => prev.map((s, idx) => idx === i ? { ...s, ...patch } : s));
  }

  async function runValidation() {
    const steps = [
      { label: 'Creating account record…', status: 'running' },
      { label: `Connecting to ${PROVIDERS[form.provider]?.name}…`, status: 'pending' },
      { label: 'Validating credentials…', status: 'pending' },
    ];
    setValidationSteps(steps);
    setResult(null);

    try {
      const created = await postToEngine('onboarding', '/api/v1/cloud-accounts', {
        customer_id:  customerId,
        tenant_id:    form.tenantId,
        account_name: form.accountName,
        provider:     form.provider,
      });

      if (created.error || !created.account_id) {
        updateVStep(0, { status: 'error', detail: created.error || 'No account_id returned' });
        setResult({ success: false, message: created.error || 'Failed to create account', errors: [] });
        return;
      }

      const aid = created.account_id;
      setAccountId(aid);
      updateVStep(0, { status: 'done', detail: `ID: ${aid.slice(0, 8)}…` });
      updateVStep(1, { status: 'running' });

      const credResult = await postToEngine('onboarding', `/api/v1/cloud-accounts/${aid}/credentials`, {
        credential_type: form.authMethod,
        credentials:     form.credentials,
      });

      updateVStep(1, { status: 'done' });
      updateVStep(2, { status: 'running' });
      await new Promise(r => setTimeout(r, 400));
      updateVStep(2, { status: credResult.success ? 'done' : 'error' });
      setResult(credResult);

    } catch (err) {
      setResult({ success: false, message: err.message || 'Unexpected error', errors: [] });
    }
  }

  async function handleLaunch() {
    setLaunching(true);
    setLaunchError(null);
    try {
      const sched = await postToEngine('onboarding', '/api/v1/schedules', {
        account_id:        accountId,
        tenant_id:         form.tenantId,
        customer_id:       customerId,
        schedule_name:     `${form.accountName} — ${schedule.cron_expression}`,
        cron_expression:   schedule.cron_expression,
        timezone:          schedule.timezone,
        enabled:           schedule.enabled,
        engines_requested: schedule.engines_requested,
        notify_on_failure: schedule.notify_on_failure,
        notify_on_success: schedule.notify_on_success,
      });

      if (sched.error) throw new Error(sched.error);

      onComplete({
        accountId,
        scheduleId: sched.schedule_id,
        provider:   form.provider,
        accountName: form.accountName,
      });
    } catch (err) {
      setLaunchError(err.message || 'Failed to save schedule');
    } finally {
      setLaunching(false);
    }
  }

  async function handleNext() {
    if (step === 1) {
      if (!form.tenantId || !form.accountName.trim() || !form.provider || !form.authMethod) return;
      setStep(2);
    } else if (step === 2) {
      const allFilled = getFields(form.provider, form.authMethod)
        .filter(f => !f.optional)
        .every(f => form.credentials[f.key]?.trim());
      if (!allFilled) return;
      setStep(3);
      await runValidation();
    } else if (step === 3 && result?.success) {
      setStep(4);
    } else if (step === 4) {
      setStep(5);
    }
  }

  const step1Valid = form.tenantId && form.accountName.trim() && form.provider && form.authMethod;
  const step2Valid = getFields(form.provider, form.authMethod)
    .filter(f => !f.optional)
    .every(f => form.credentials[f.key]?.trim());
  const step4Valid = schedule.engines_requested.length > 0 && schedule.cron_expression.trim();

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
      <div className="rounded-xl w-full max-w-2xl shadow-2xl flex flex-col max-h-[90vh]"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b"
          style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Add Cloud Account</h2>
          <button onClick={onCancel} className="p-1 rounded hover:bg-white/10">
            <X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          </button>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-0 px-6 py-3 border-b overflow-x-auto" style={{ borderColor: 'var(--border-primary)' }}>
          {STEP_LABELS.map((label, i) => {
            const n = i + 1;
            const done   = n < step;
            const active = n === step;
            return (
              <div key={n} className="flex items-center flex-shrink-0">
                <div className="flex items-center gap-1.5">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${done ? 'bg-green-500 text-white' : active ? 'bg-blue-500 text-white' : 'text-gray-500'}`}
                    style={{ border: done || active ? 'none' : '2px solid var(--border-primary)' }}>
                    {done ? '✓' : n}
                  </div>
                  <span className="text-xs font-medium whitespace-nowrap" style={{ color: active ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    {label}
                  </span>
                </div>
                {i < STEP_LABELS.length - 1 && (
                  <ChevronRight className="w-3.5 h-3.5 mx-1.5 flex-shrink-0" style={{ color: 'var(--border-primary)' }} />
                )}
              </div>
            );
          })}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {step === 1 && <Step1 form={form} setForm={setForm} />}
          {step === 2 && <Step2 form={form} setForm={setForm} />}
          {step === 3 && <Step3 steps={validationSteps} result={result} form={form} />}
          {step === 4 && <Step4 schedule={schedule} setSchedule={setSchedule} />}
          {step === 5 && (
            <Step5
              form={form}
              schedule={schedule}
              accountId={accountId}
              result={result}
              launching={launching}
              launchError={launchError}
            />
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          {/* Left: Cancel + Back */}
          <div className="flex gap-2">
            <button onClick={onCancel} className="px-4 py-2 rounded-lg text-sm"
              style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
              Cancel
            </button>
            {step > 1 && step < 3 && (
              <button onClick={() => setStep(s => s - 1)} className="px-4 py-2 rounded-lg text-sm"
                style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                ← Back
              </button>
            )}
            {(step === 4 || step === 5) && (
              <button onClick={() => setStep(s => s - 1)} className="px-4 py-2 rounded-lg text-sm"
                style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                ← Back
              </button>
            )}
          </div>

          {/* Right: Primary action */}
          <div className="flex gap-2">
            {step === 1 && (
              <button onClick={handleNext} disabled={!step1Valid}
                className="px-5 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-40"
                style={{ backgroundColor: 'var(--accent-primary)' }}>
                Next →
              </button>
            )}
            {step === 2 && (
              <button onClick={handleNext} disabled={!step2Valid}
                className="px-5 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-40"
                style={{ backgroundColor: 'var(--accent-primary)' }}>
                Validate Credentials →
              </button>
            )}
            {step === 3 && result?.success && (
              <button onClick={handleNext}
                className="px-5 py-2 rounded-lg text-sm font-medium text-white"
                style={{ backgroundColor: 'var(--accent-primary)' }}>
                Configure Schedule →
              </button>
            )}
            {step === 3 && result && !result.success && (
              <button onClick={() => { setStep(2); setResult(null); }}
                className="px-5 py-2 rounded-lg text-sm font-medium"
                style={{ color: 'var(--text-primary)', border: '1px solid var(--border-primary)' }}>
                ← Fix Credentials
              </button>
            )}
            {step === 4 && (
              <button onClick={handleNext} disabled={!step4Valid}
                className="px-5 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-40"
                style={{ backgroundColor: 'var(--accent-primary)' }}>
                Review Summary →
              </button>
            )}
            {step === 5 && (
              <button onClick={handleLaunch} disabled={launching}
                className="px-5 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-60 flex items-center gap-2"
                style={{ backgroundColor: '#22c55e' }}>
                {launching && <Loader2 className="w-4 h-4 animate-spin" />}
                {launching ? 'Launching…' : '🚀 Launch'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
