'use client';
/**
 * OnboardingWizard — cloud account onboarding (cloud_csp primary flow)
 *
 * The wizard is cloud-first: it always onboards a Cloud Provider account
 * (AWS, Azure, GCP, OCI, AliCloud, IBM, K8s).  After launch, dormant
 * capability records for Vulnerability, Database, Code Security, and
 * Middleware are auto-provisioned so the user can activate them later
 * without re-entering workspace/tenant context.
 *
 * Flow: 1 (workspace + provider) → 2 (credentials) → 3 (validate)
 *       → 4 (schedule) → 5 (summary + launch)
 */

import { useState, useEffect } from 'react';
import {
  ChevronDown, Download, X, CheckCircle2, XCircle, Loader2,
  Calendar, Clock, Globe, Layers, Bell, ChevronRight, Copy, Check,
  Plus, ArrowLeft,
} from 'lucide-react';
import { postToEngine, getFromEngine, patchToEngine } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';
import { TenantTypeSelector } from '@/components/onboarding/TenantTypeSelector';

const ENV_OPTIONS_WZ = [
  { value: 'production',  label: 'Production',  color: '#ef4444' },
  { value: 'staging',     label: 'Staging',     color: '#f97316' },
  { value: 'development', label: 'Development', color: '#3b82f6' },
  { value: 'test',        label: 'Test',        color: '#6b7280' },
];

// ── Account type catalogue ────────────────────────────────────────────────────

const ACCOUNT_TYPE_OPTIONS = [
  { key: 'cloud_csp',      icon: '☁️',  label: 'Cloud Provider',   desc: 'AWS, Azure, GCP, OCI, AliCloud, IBM, K8s' },
  { key: 'vulnerability',  icon: '🔍',  label: 'Vulnerability',    desc: 'Agent-based CVE scanning & SBOM' },
  { key: 'code_security',  icon: '🔒',  label: 'SecOps / Code',    desc: 'SAST, DAST, IaC scanning via Git repo' },
  { key: 'database',       icon: '🗄️', label: 'Database',         desc: 'PostgreSQL, MySQL, SQL Server, MongoDB, Oracle' },
  { key: 'middleware',     icon: '⚙️',  label: 'Middleware',       desc: 'Application middleware security monitoring' },
];

const AGENT_ACCOUNT_TYPES = new Set(['vulnerability', 'middleware']);

// ── Provider catalogue (static fallback — overridden by API data at runtime) ─

const CLOUD_PROVIDERS = {
  aws:      { name: 'AWS',      full: 'Amazon Web Services',         color: '#FF9900' },
  azure:    { name: 'Azure',    full: 'Microsoft Azure',             color: '#0078D4' },
  gcp:      { name: 'GCP',      full: 'Google Cloud Platform',       color: '#4285F4' },
  oci:      { name: 'OCI',      full: 'Oracle Cloud Infrastructure', color: '#F80000' },
  alicloud: { name: 'AliCloud', full: 'Alibaba Cloud',               color: '#FF6A00' },
  ibm:      { name: 'IBM',      full: 'IBM Cloud',                   color: '#1F70C1' },
  k8s:      { name: 'K8s',      full: 'Kubernetes Cluster',          color: '#326CE5' },
};

const DB_PROVIDERS = {
  postgres: { name: 'PostgreSQL', full: 'Self-hosted PostgreSQL', color: '#336791' },
  mysql:    { name: 'MySQL',      full: 'Self-hosted MySQL',      color: '#4479A1' },
  mssql:    { name: 'SQL Server', full: 'Microsoft SQL Server',   color: '#CC2927' },
  mongodb:  { name: 'MongoDB',    full: 'Self-hosted MongoDB',    color: '#47A248' },
  oracle:   { name: 'Oracle DB',  full: 'Oracle Database',        color: '#C74634' },
};

const VCS_PROVIDERS = {
  github:    { name: 'GitHub',    full: 'GitHub Repository',    color: '#24292E' },
  gitlab:    { name: 'GitLab',    full: 'GitLab Repository',    color: '#FC6D26' },
  bitbucket: { name: 'Bitbucket', full: 'Bitbucket Repository', color: '#0052CC' },
};

const VCS_PROVIDER_SET = new Set(Object.keys(VCS_PROVIDERS));

const PROVIDERS_FALLBACK = {
  ...CLOUD_PROVIDERS,
  ...DB_PROVIDERS,
  ...VCS_PROVIDERS,
  git:   { name: 'Git',   full: 'Git Repository',       color: '#F05032' },
  agent: { name: 'Agent', full: 'Agent-based scanning', color: '#8B5CF6' },
};

// Provider brand colors — keyed by logo_key / provider string.
// Used when building PROVIDERS map from API data.
const PROVIDER_COLORS = {
  aws: '#FF9900', azure: '#0078D4', gcp: '#4285F4', oci: '#F80000',
  alicloud: '#FF6A00', ibm: '#1F70C1', k8s: '#326CE5',
  postgres: '#336791', mysql: '#4479A1', mssql: '#CC2927',
  mongodb: '#47A248', oracle: '#C74634',
  github: '#24292E', gitlab: '#FC6D26', bitbucket: '#0052CC',
  agent: '#8B5CF6', git: '#F05032',
};

const DB_PROVIDER_SET = new Set(Object.keys(DB_PROVIDERS));

// ── Helpers to build wizard maps from API response rows ───────────────────────

function buildProvidersMap(apiRows) {
  if (!apiRows?.length) return PROVIDERS_FALLBACK;
  const map = { git: PROVIDERS_FALLBACK.git }; // keep legacy alias
  for (const row of apiRows) {
    const fallback = PROVIDERS_FALLBACK[row.provider] || {};
    map[row.provider] = {
      name:  fallback.name  || row.display_name,
      full:  row.description || fallback.full || row.display_name,
      color: PROVIDER_COLORS[row.logo_key || row.provider] || '#6b7280',
    };
  }
  return map;
}

function buildAccountTypeOptions(apiRows) {
  if (!apiRows?.length) return ACCOUNT_TYPE_OPTIONS;
  const ICON_MAP = {
    cloud_csp: '☁️', vulnerability: '🔍', code_security: '🔒',
    database: '🗄️', middleware: '⚙️',
  };
  return apiRows.map(row => ({
    key:  row.account_type,
    icon: ICON_MAP[row.account_type] || '📦',
    label: row.display_name,
    desc:  row.description || '',
  }));
}

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
  postgres: [{ value: 'username_password', label: 'Username / Password', desc: 'Direct DB credentials' }],
  mysql:    [{ value: 'username_password', label: 'Username / Password', desc: 'Direct DB credentials' }],
  mssql:    [{ value: 'username_password', label: 'Username / Password', desc: 'Direct DB credentials' }],
  mongodb:  [{ value: 'connection_string', label: 'Connection URI',       desc: 'mongodb:// or mongodb+srv:// URI' }],
  oracle:   [{ value: 'username_password', label: 'Username / Password', desc: 'Direct DB credentials' }],
  git: [
    { value: 'pat_token', label: 'Personal Access Token', desc: 'GitHub / GitLab / Bitbucket PAT' },
    { value: 'ssh_key',   label: 'SSH Key',               desc: 'Deploy key (read-only access)' },
  ],
  // VCS providers — same auth methods, kept separate for per-provider field customisation
  github: [
    { value: 'pat_token', label: 'Personal Access Token', desc: 'GitHub PAT with repo:read scope' },
    { value: 'ssh_key',   label: 'SSH Key',               desc: 'GitHub deploy key (read-only)' },
  ],
  gitlab: [
    { value: 'pat_token', label: 'Personal Access Token', desc: 'GitLab PAT with read_repository scope' },
    { value: 'ssh_key',   label: 'SSH Key',               desc: 'GitLab deploy key (read-only)' },
  ],
  bitbucket: [
    { value: 'pat_token', label: 'Personal Access Token', desc: 'Bitbucket App Password with Repository Read' },
    { value: 'ssh_key',   label: 'SSH Key',               desc: 'Bitbucket access key (read-only)' },
  ],
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
  postgres_username_password: [
    { key: 'host',     label: 'Host',     placeholder: '192.168.1.10 or db.internal', secret: false },
    { key: 'port',     label: 'Port',     placeholder: '5432',                         secret: false },
    { key: 'dbname',   label: 'Database', placeholder: 'postgres',                     secret: false },
    { key: 'username', label: 'Username', placeholder: 'postgres',                     secret: false },
    { key: 'password', label: 'Password', placeholder: '••••',                         secret: true  },
    { key: 'ssl_mode', label: 'SSL Mode', placeholder: 'prefer (disable/allow/require/verify-full)', secret: false, optional: true },
  ],
  mysql_username_password: [
    { key: 'host',     label: 'Host',     placeholder: '192.168.1.10 or db.internal', secret: false },
    { key: 'port',     label: 'Port',     placeholder: '3306',                         secret: false },
    { key: 'dbname',   label: 'Database', placeholder: 'mysql',                        secret: false },
    { key: 'username', label: 'Username', placeholder: 'root',                         secret: false },
    { key: 'password', label: 'Password', placeholder: '••••',                         secret: true  },
  ],
  mssql_username_password: [
    { key: 'host',     label: 'Host',     placeholder: '192.168.1.10 or db.internal', secret: false },
    { key: 'port',     label: 'Port',     placeholder: '1433',                         secret: false },
    { key: 'dbname',   label: 'Database', placeholder: 'master',                       secret: false },
    { key: 'username', label: 'Username', placeholder: 'sa',                           secret: false },
    { key: 'password', label: 'Password', placeholder: '••••',                         secret: true  },
    { key: 'instance', label: 'Instance', placeholder: 'SQLEXPRESS (optional)',        secret: false, optional: true },
  ],
  mongodb_connection_string: [
    { key: 'uri', label: 'Connection URI', placeholder: 'mongodb://username:password@host:27017/dbname', secret: true },
  ],
  oracle_username_password: [
    { key: 'host',         label: 'Host',         placeholder: '192.168.1.10 or db.internal', secret: false },
    { key: 'port',         label: 'Port',         placeholder: '1521',                         secret: false },
    { key: 'service_name', label: 'Service Name', placeholder: 'ORCL or XE',                  secret: false },
    { key: 'username',     label: 'Username',     placeholder: 'system',                       secret: false },
    { key: 'password',     label: 'Password',     placeholder: '••••',                         secret: true  },
  ],
  git_pat_token: [
    { key: 'repo_url',    label: 'Repository URL', placeholder: 'https://github.com/org/repo', secret: false },
    { key: 'pat_token',   label: 'Personal Access Token', placeholder: 'ghp_…',               secret: true  },
    { key: 'branch',      label: 'Branch',         placeholder: 'main (default)',               secret: false, optional: true },
  ],
  git_ssh_key: [
    { key: 'repo_url',    label: 'Repository URL', placeholder: 'git@github.com:org/repo.git', secret: false },
    { key: 'private_key', label: 'SSH Private Key', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----…', secret: true, textarea: true },
    { key: 'branch',      label: 'Branch',          placeholder: 'main (default)',              secret: false, optional: true },
  ],
  // GitHub
  github_pat_token: [
    { key: 'repo_url',       label: 'Repository URL',        placeholder: 'https://github.com/org/repo', secret: false },
    { key: 'pat_token',      label: 'Personal Access Token', placeholder: 'ghp_…',                       secret: true  },
    { key: 'default_branch', label: 'Default Branch',        placeholder: 'main',                        secret: false, optional: true },
  ],
  github_ssh_key: [
    { key: 'repo_url',       label: 'Repository URL',  placeholder: 'git@github.com:org/repo.git',          secret: false },
    { key: 'private_key',    label: 'SSH Private Key', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----…', secret: true, textarea: true },
    { key: 'default_branch', label: 'Default Branch',  placeholder: 'main',                                 secret: false, optional: true },
  ],
  // GitLab
  gitlab_pat_token: [
    { key: 'repo_url',       label: 'Repository URL',        placeholder: 'https://gitlab.com/group/project', secret: false },
    { key: 'pat_token',      label: 'Personal Access Token', placeholder: 'glpat-…',                          secret: true  },
    { key: 'default_branch', label: 'Default Branch',        placeholder: 'main',                             secret: false, optional: true },
  ],
  gitlab_ssh_key: [
    { key: 'repo_url',       label: 'Repository URL',  placeholder: 'git@gitlab.com:group/project.git',      secret: false },
    { key: 'private_key',    label: 'SSH Private Key', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----…',  secret: true, textarea: true },
    { key: 'default_branch', label: 'Default Branch',  placeholder: 'main',                                  secret: false, optional: true },
  ],
  // Bitbucket
  bitbucket_pat_token: [
    { key: 'repo_url',       label: 'Repository URL',  placeholder: 'https://bitbucket.org/workspace/repo',  secret: false },
    { key: 'pat_token',      label: 'App Password',    placeholder: 'ATBBxxxxxxxxxxxxxxxx',                  secret: true  },
    { key: 'default_branch', label: 'Default Branch',  placeholder: 'main',                                  secret: false, optional: true },
  ],
  bitbucket_ssh_key: [
    { key: 'repo_url',       label: 'Repository URL',  placeholder: 'git@bitbucket.org:workspace/repo.git',  secret: false },
    { key: 'private_key',    label: 'SSH Private Key', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----…',  secret: true, textarea: true },
    { key: 'default_branch', label: 'Default Branch',  placeholder: 'main',                                  secret: false, optional: true },
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

const ALL_ENGINES    = ['discovery', 'check', 'inventory', 'threat', 'compliance', 'iam', 'datasec'];
const DB_ENGINES     = ['dbsec'];
const SECOPS_ENGINES = ['secops'];
const VULN_ENGINES   = ['vulnerability'];
const ENGINE_LABELS  = {
  discovery:     { label: 'Discovery',     desc: 'Enumerate cloud resources' },
  check:         { label: 'Check',         desc: 'Evaluate compliance rules' },
  inventory:     { label: 'Inventory',     desc: 'Normalize + track assets' },
  threat:        { label: 'Threat',        desc: 'MITRE ATT&CK mapping' },
  compliance:    { label: 'Compliance',    desc: 'Framework reports (CIS, NIST…)' },
  iam:           { label: 'IAM',           desc: 'IAM posture analysis' },
  datasec:       { label: 'Data Sec',      desc: 'Data classification & security' },
  dbsec:         { label: 'DB Security',   desc: 'CIS DB benchmark checks' },
  secops:        { label: 'SecOps',        desc: 'SAST / DAST / IaC scanning' },
  vulnerability: { label: 'Vulnerability', desc: 'CVE scanning & SBOM analysis' },
};

const COMMON_TIMEZONES = [
  'UTC', 'America/New_York', 'America/Chicago', 'America/Los_Angeles',
  'Europe/London', 'Europe/Berlin', 'Asia/Kolkata', 'Asia/Tokyo',
  'Asia/Singapore', 'Australia/Sydney',
];

// ── Step configuration per account type ──────────────────────────────────────

function getStepConfig(accountType) {
  if (AGENT_ACCOUNT_TYPES.has(accountType)) {
    return [
      { n: 1, label: 'Account Setup' },
      { n: 2, label: 'Install Agent' },
      { n: 4, label: 'Schedule' },
      { n: 5, label: 'Summary' },
    ];
  }
  return [
    { n: 1, label: 'Account Setup' },
    { n: 2, label: accountType === 'code_security' ? 'Repository' : 'Credentials' },
    { n: 3, label: 'Validate' },
    { n: 4, label: 'Schedule' },
    { n: 5, label: 'Summary' },
  ];
}

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

// ── Step 1: Account type + provider selection ─────────────────────────────────

function Step1({ form, setForm, onWorkspaceCreated, localTenants, providers, accountTypeOptions, activateMode }) {
  const isAgentType      = AGENT_ACCOUNT_TYPES.has(form.accountType);
  const isCodeSecurity   = form.accountType === 'code_security';
  const showCloudOrDb    = form.accountType === 'cloud_csp' || form.accountType === 'database';
  const showProviders    = showCloudOrDb || isCodeSecurity;

  // Derive sub-maps from the full providers map
  const cloudKeys  = ['aws','azure','gcp','oci','alicloud','ibm','k8s'];
  const dbKeys     = ['postgres','mysql','mssql','mongodb','oracle'];
  const vcsKeys    = ['github','gitlab','bitbucket'];
  const cloudMap   = Object.fromEntries(cloudKeys.filter(k => providers[k]).map(k => [k, providers[k]]));
  const dbMap      = Object.fromEntries(dbKeys.filter(k => providers[k]).map(k => [k, providers[k]]));
  const vcsMap     = Object.fromEntries(vcsKeys.filter(k => providers[k]).map(k => [k, providers[k]]));
  const providerMap = form.accountType === 'database' ? dbMap
    : isCodeSecurity ? vcsMap
    : cloudMap;

  function selectType(key) {
    setForm(f => ({ ...f, accountType: key, provider: '', authMethod: '', credentials: {} }));
  }

  const DORMANT_LABELS = { vulnerability: 'Vulnerability Scanner', database: 'Database Security', code_security: 'Code Security', middleware: 'Middleware Monitor' };

  return (
    <div className="space-y-5">
      {/* Activate-mode banner — replaces workspace + account name when configuring a dormant account */}
      {activateMode && (
        <div className="flex items-start gap-3 p-3 rounded-lg"
          style={{ backgroundColor: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.2)' }}>
          <span className="text-base">⚙️</span>
          <div>
            <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
              Configuring {DORMANT_LABELS[form.accountType] || form.accountType}
            </p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Account: <span className="font-medium">{form.accountName}</span>
              {' · '}Select your provider and enter credentials below.
            </p>
          </div>
        </div>
      )}

      {/* Tenant — hidden in activate mode (pre-filled) */}
      {!activateMode && <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
          Workspace <span className="text-red-400">*</span>
        </label>
        <div className="relative">
          <select value={form.tenantId}
            onChange={e => {
              if (e.target.value === '__new__') { onWorkspaceCreated('__open__'); return; }
              setForm(f => ({ ...f, tenantId: e.target.value }));
            }}
            className="w-full px-3 py-2 rounded-lg text-sm outline-none appearance-none"
            style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }}>
            <option value="">Select workspace…</option>
            {localTenants.map(t => <option key={t.tenant_id} value={t.tenant_id}>{t.tenant_name}</option>)}
            <option value="__new__">＋ New Workspace…</option>
          </select>
          <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
        </div>
        {localTenants.length === 0 && (
          <p className="text-xs mt-1.5" style={{ color: 'var(--text-muted)' }}>
            Don&apos;t have a workspace?{' '}
            <button type="button" onClick={() => onWorkspaceCreated('__open__')}
              className="font-medium hover:underline" style={{ color: 'var(--accent-primary)' }}>
              Add workspace
            </button>
          </p>
        )}
      </div>}

      {/* Account name — hidden in activate mode (pre-filled) */}
      {!activateMode && (
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
          Account Name <span className="text-red-400">*</span>
        </label>
        <input type="text" value={form.accountName} onChange={e => setForm(f => ({ ...f, accountName: e.target.value }))}
          placeholder="e.g. Production AWS, Dev GCP, Staging Azure"
          className="w-full px-3 py-2 rounded-lg text-sm outline-none"
          style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }} />
      </div>
      )}

      {/* Provider grid — cloud provider selection */}
      {showProviders && (
        <div>
          <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
            {form.accountType === 'database'
              ? 'Database Engine'
              : isCodeSecurity
                ? 'VCS Platform'
                : 'Cloud Provider'} <span className="text-red-400">*</span>
          </label>
          <div className={`grid gap-2 ${isCodeSecurity ? 'grid-cols-3' : 'grid-cols-4'}`}>
            {Object.entries(providerMap).map(([key, p]) => {
              const selected = form.provider === key;
              return (
                <button key={key}
                  onClick={() => setForm(f => ({ ...f, provider: key, authMethod: '', credentials: {} }))}
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
      )}

      {/* Auth method — shown once a provider is selected (covers cloud_csp, database, and code_security) */}
      {showProviders && form.provider && (
        <div>
          <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
            {isCodeSecurity ? 'Git Authentication Method' : 'Authentication Method'} <span className="text-red-400">*</span>
          </label>
          <div className="space-y-2">
            {(AUTH_METHODS[form.provider] || []).map(m => {
              const selected = form.authMethod === m.value;
              const accentColor = isCodeSecurity ? (providers[form.provider]?.color || 'var(--accent-primary)') : 'var(--accent-primary)';
              return (
                <button key={m.value} onClick={() => setForm(f => ({ ...f, authMethod: m.value, credentials: {} }))}
                  className="w-full flex items-start gap-3 p-3 rounded-lg text-left transition-all"
                  style={{
                    border: `2px solid ${selected ? accentColor : 'var(--border-primary)'}`,
                    backgroundColor: selected ? `${accentColor}12` : 'var(--bg-tertiary)',
                  }}>
                  <div className="mt-0.5 w-4 h-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center"
                    style={{ borderColor: selected ? accentColor : 'var(--border-primary)' }}>
                    {selected && <div className="w-2 h-2 rounded-full" style={{ backgroundColor: accentColor }} />}
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

// ── Step 2: Credential fields (cloud_csp / database / code_security) ─────────

const DEFAULT_BRANCH_PATTERN = /^[a-zA-Z0-9._/-]{1,128}$/;

function Step2({ form, setForm, providers }) {
  const fields      = getFields(form.provider, form.authMethod);
  const provider    = providers[form.provider];
  const isVcs       = VCS_PROVIDER_SET.has(form.provider);
  const provColor   = provider?.color || '#F05032';

  // Separate default_branch out of the field list (rendered below all other fields)
  const mainFields   = fields.filter(f => f.key !== 'default_branch');
  const hasBranch    = fields.some(f => f.key === 'default_branch');

  const [branchError, setBranchError] = useState('');

  function handleBranchChange(v) {
    const val = v || '';
    if (val && !DEFAULT_BRANCH_PATTERN.test(val)) {
      setBranchError('Only letters, numbers, dots, dashes, underscores and slashes (max 128 chars)');
    } else {
      setBranchError('');
    }
    setForm(f => ({ ...f, credentials: { ...f.credentials, default_branch: val || 'main' } }));
  }

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

      {(isVcs || form.provider === 'git') && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg text-xs"
          style={{ backgroundColor: `${provColor}0F`, border: `1px solid ${provColor}33`, color: 'var(--text-secondary)' }}>
          <span>The scanner will clone your repository and run SAST / IaC / dependency checks. Grant read-only access.</span>
        </div>
      )}

      {mainFields.map(def => (
        <Field key={def.key} def={def} value={form.credentials[def.key]}
          onChange={(k, v) => setForm(f => ({ ...f, credentials: { ...f.credentials, [k]: v } }))} />
      ))}

      {hasBranch && (
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
            Default Branch <span className="ml-1 text-xs font-normal" style={{ color: 'var(--text-muted)' }}>(optional)</span>
          </label>
          <input
            type="text"
            value={form.credentials.default_branch || 'main'}
            onChange={e => handleBranchChange(e.target.value)}
            placeholder="main"
            className="w-full px-3 py-2 rounded-lg text-sm outline-none transition-colors"
            style={{ backgroundColor: 'var(--bg-tertiary)', border: `1px solid ${branchError ? '#f87171' : 'var(--border-primary)'}`, color: 'var(--text-primary)' }}
          />
          {branchError && <p className="mt-1 text-xs text-red-400">{branchError}</p>}
        </div>
      )}
    </div>
  );
}

// ── Step 2 (agent types): Agent setup — create account + issue token ──────────

function AgentSetupStep({ form, customerId, accountId, setAccountId, agentToken, setAgentToken, accountTypeOptions, preExistingAccountId }) {
  const [phase, setPhase]   = useState('creating'); // creating | ready | error
  const [error, setError]   = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function setup() {
      try {
        let aid = preExistingAccountId || accountId;

        if (!aid) {
          // Normal flow: create account record
          const created = await postToEngine('gateway', '/api/v1/cloud-accounts', {
            customer_id:  customerId,
            tenant_id:    form.tenantId,
            account_name: form.accountName,
            account_type: form.accountType,
            provider:     'agent',
          });
          if (cancelled) return;
          if (created.error || !created.account_id) {
            setError(created.error || 'Failed to create account');
            setPhase('error');
            return;
          }
          aid = created.account_id;
          setAccountId(aid);
        } else {
          // Activate mode: account already exists, just re-issue the token
          if (!cancelled) setAccountId(aid);
        }

        if (cancelled) return;

        // Issue agent bootstrap token
        const tokenResp = await postToEngine('gateway', `/api/v1/cloud-accounts/${aid}/agent-token`, {
          account_id:  aid,
          customer_id: customerId,
          tenant_id:   form.tenantId,
        });
        if (cancelled) return;
        if (tokenResp.error) {
          setError(tokenResp.error);
          setPhase('error');
          return;
        }
        setAgentToken(tokenResp);
        setPhase('ready');
      } catch (err) {
        if (!cancelled) { setError(err.message || 'Unexpected error'); setPhase('error'); }
      }
    }
    setup();
    return () => { cancelled = true; };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function copyCommand() {
    navigator.clipboard.writeText(agentToken?.install_command || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const typeLabel = accountTypeOptions.find(o => o.key === form.accountType)?.label || form.accountType;

  if (phase === 'creating') {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-10">
        <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Creating account and generating install token…</p>
      </div>
    );
  }

  if (phase === 'error') {
    return (
      <div className="p-4 rounded-lg" style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)' }}>
        <p className="text-sm font-medium text-red-400">Failed to set up agent account</p>
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Success banner */}
      <div className="flex items-center gap-3 p-3 rounded-lg"
        style={{ backgroundColor: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.25)' }}>
        <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0" />
        <div>
          <p className="text-sm font-medium text-green-400">{typeLabel} account created</p>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Account ID: <span className="font-mono">{accountId?.slice(0, 8)}…</span>
            {' · '}Token expires in <span className="font-medium">{agentToken?.token_expires_in ? Math.round(agentToken.token_expires_in / 60) : 30} minutes</span>
          </p>
        </div>
      </div>

      {/* Instructions */}
      <div>
        <p className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
          Run this command on your target host to install and register the agent:
        </p>
        <div className="relative">
          <pre className="text-xs font-mono p-4 rounded-lg overflow-x-auto leading-relaxed"
            style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: '#86efac' }}>
            {agentToken?.install_command}
          </pre>
          <button onClick={copyCommand}
            className="absolute top-2 right-2 p-1.5 rounded flex items-center gap-1 text-xs transition-all"
            style={{
              backgroundColor: copied ? 'rgba(34,197,94,0.15)' : 'var(--bg-card)',
              border: `1px solid ${copied ? 'rgba(34,197,94,0.4)' : 'var(--border-primary)'}`,
              color: copied ? '#4ade80' : 'var(--text-muted)',
            }}>
            {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>

      {/* What happens next */}
      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>What happens next</p>
        {[
          { icon: '1', text: 'Run the command above on your host — the agent installs and phones home.' },
          { icon: '2', text: 'The token is valid for 15 minutes for initial registration only.' },
          { icon: '3', text: 'After registration, the agent receives a 30-day session token automatically.' },
          { icon: '4', text: 'Configure a scan schedule in the next step. First scan runs immediately after agent activates.' },
        ].map(({ icon, text }) => (
          <div key={icon} className="flex items-start gap-2.5">
            <span className="w-5 h-5 rounded-full text-xs font-bold flex-shrink-0 flex items-center justify-center mt-0.5"
              style={{ backgroundColor: 'rgba(139,92,246,0.15)', color: '#a78bfa' }}>{icon}</span>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{text}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Step 3: Validation progress ───────────────────────────────────────────────

function Step3({ steps, result, form, providers }) {
  const provider = providers[form.provider];

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

// Engines that always run — not shown as toggleable options in the UI
const ALWAYS_ON_ENGINES = new Set(['discovery', 'check']);

function Step4({ schedule, setSchedule, accountType }) {
  const engineMap = {
    cloud_csp:     ALL_ENGINES,
    database:      DB_ENGINES,
    code_security: SECOPS_ENGINES,
    secops:        SECOPS_ENGINES,   // legacy alias
    vulnerability: VULN_ENGINES,
    middleware:    VULN_ENGINES,
  };
  const allEnginesForType  = engineMap[accountType] || ALL_ENGINES;
  // discovery + check always run — hide from the toggle UI; show as a note instead
  const availableEngines   = allEnginesForType.filter(e => !ALWAYS_ON_ENGINES.has(e));

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
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>Engines to Run</span>
          </div>
          {allEnginesForType.some(e => ALWAYS_ON_ENGINES.has(e)) && (
            <span className="text-[10px] px-2 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(59,130,246,0.08)', color: 'var(--text-muted)', border: '1px solid var(--border-primary)' }}>
              Discovery &amp; Check always run
            </span>
          )}
        </div>
        <div className="grid grid-cols-2 gap-1.5">
          {availableEngines.map(eng => {
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

function Step5({ form, schedule, accountId, result, launching, launchError, providers, accountTypeOptions }) {
  const provider    = providers[form.provider];
  const typeOption  = accountTypeOptions.find(o => o.key === form.accountType);
  const isAgent        = AGENT_ACCOUNT_TYPES.has(form.accountType);
  const isCodeSecurity = form.accountType === 'code_security';
  const isSecops       = isCodeSecurity; // alias — wizard uses code_security internally
  const authLabel   = AUTH_METHODS[form.provider]?.find(m => m.value === form.authMethod)?.label;
  const freqPreset  = CRON_PRESETS.find(p => p.cron === schedule.cron_expression)?.label || schedule.cron_expression;

  const sections = [
    {
      icon:  typeOption?.icon || '☁️',
      title: `${typeOption?.label || 'Cloud'} Account`,
      rows: [
        { label: 'Account Name',  value: form.accountName },
        { label: 'Account Type',  value: typeOption?.label },
        !isAgent && { label: 'Provider',   value: provider ? `${provider.name} — ${provider.full}` : '—' },
        !isAgent && !isSecops && { label: 'Auth Method', value: authLabel || '—' },
        isSecops && { label: 'Git Auth',   value: authLabel || '—' },
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
      rows: [{ label: 'Selected', value: schedule.engines_requested.map(e => ENGINE_LABELS[e]?.label).join(', ') || '—' }],
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

export default function OnboardingWizard({ onComplete = () => {}, onCancel = () => {}, initialConfig = null }) {
  const { customerId } = useTenant();

  // initialConfig = { accountId, accountType, accountName, tenantId } when activating a dormant account
  const isActivateAgentType = !!(initialConfig && AGENT_ACCOUNT_TYPES.has(initialConfig.accountType));

  const [step, setStep] = useState(isActivateAgentType ? 2 : 1);
  const [form, setForm] = useState({
    tenantId:    initialConfig?.tenantId    || '',
    accountName: initialConfig?.accountName || '',
    accountType: initialConfig ? initialConfig.accountType : 'cloud_csp',
    provider:    '',
    authMethod:  '',
    credentials: {},
  });

  // ── Inline workspace creation state ──────────────────────────────────────────
  const [localTenants, setLocalTenants]         = useState([]);
  const [showCreateWS, setShowCreateWS]         = useState(false);
  const [createdWorkspace, setCreatedWorkspace] = useState(null);

  // ── Reference data loaded via gateway (gateway adds X-Auth-Context → engine accepts) ──
  const [apiProviders, setApiProviders]       = useState(null);
  const [apiAccountTypes, setApiAccountTypes] = useState(null);

  // Derived maps — fall back to static constants while loading or on error
  const PROVIDERS       = apiProviders     ? buildProvidersMap(apiProviders)          : PROVIDERS_FALLBACK;
  const acctTypeOptions = apiAccountTypes  ? buildAccountTypeOptions(apiAccountTypes) : ACCOUNT_TYPE_OPTIONS;

  // Load tenants + reference data via the API gateway (not direct engine calls).
  // Gateway path /gateway/api/v1/... validates the session cookie and injects
  // X-Auth-Context before forwarding to the engine — so the engine accepts it.
  useEffect(() => {
    if (!customerId) return;
    getFromEngine('gateway', '/api/v1/tenants', { customer_id: customerId })
      .then(d => setLocalTenants(d?.tenants || []))
      .catch(() => {});
    getFromEngine('gateway', '/api/v1/onboarding/providers')
      .then(d => { if (Array.isArray(d)) setApiProviders(d); })
      .catch(() => {});
    getFromEngine('gateway', '/api/v1/onboarding/account-types')
      .then(d => { if (Array.isArray(d)) setApiAccountTypes(d); })
      .catch(() => {});
  }, [customerId]);

  function handleWorkspaceSignal(signal) {
    if (signal === '__open__') setShowCreateWS(true);
  }

  async function handleCreateWorkspace(wsForm) {
    const res = await postToEngine('gateway', '/api/v1/tenants', {
      customer_id:        customerId,
      tenant_name:        wsForm.tenant_name.trim(),
      tenant_description: wsForm.tenant_description?.trim() || undefined,
      tenant_type:        wsForm.tenant_type,
      environment:        wsForm.environment,
    });
    if (res.error) throw new Error(res.error);
    const newT = res;
    setLocalTenants(prev => [newT, ...prev]);
    setCreatedWorkspace(newT);
    setShowCreateWS(false);
    return newT;
  }

  const isAgentType    = AGENT_ACCOUNT_TYPES.has(form.accountType);
  const isCodeSecurity = form.accountType === 'code_security';
  const isSecops       = isCodeSecurity; // wizard uses code_security internally
  const isDbAccount    = DB_PROVIDER_SET.has(form.provider);

  const defaultEngines = {
    cloud_csp:     ALL_ENGINES,
    database:      DB_ENGINES,
    code_security: SECOPS_ENGINES,
    secops:        SECOPS_ENGINES,   // legacy alias
    vulnerability: VULN_ENGINES,
    middleware:    VULN_ENGINES,
  };

  const [schedule, setSchedule] = useState({
    cron_expression:   '0 2 * * 0',
    timezone:          'UTC',
    enabled:           true,
    engines_requested: [...(defaultEngines[initialConfig?.accountType] || ALL_ENGINES)],
    notify_on_failure: true,
    notify_on_success: false,
  });

  // Step 3 state (validation flow — CSP / DB / secops)
  const [validationSteps, setValidationSteps] = useState([]);
  const [result, setResult]                   = useState(null);
  const [accountId, setAccountId]             = useState(initialConfig?.accountId || null);

  // Step 2 state (agent flow)
  const [agentToken, setAgentToken] = useState(null);

  // Step 5 state
  const [launching, setLaunching]   = useState(false);
  const [launchError, setLaunchError] = useState(null);

  // Step indicator config
  const stepConfig = getStepConfig(form.accountType);

  function updateVStep(i, patch) {
    setValidationSteps(prev => prev.map((s, idx) => idx === i ? { ...s, ...patch } : s));
  }

  async function runValidation() {
    const providerLabel   = PROVIDERS[form.provider]?.name || form.provider;
    const connectingLabel = isCodeSecurity ? `Connecting to ${providerLabel} repository…` : `Connecting to ${providerLabel}…`;
    const steps = [
      { label: 'Creating account record…', status: 'running' },
      { label: connectingLabel,            status: 'pending' },
      { label: 'Validating credentials…',  status: 'pending' },
    ];
    setValidationSteps(steps);
    setResult(null);

    try {
      const isVcs = VCS_PROVIDER_SET.has(form.provider);

      // In activate mode accountId is already set — skip account creation
      let aid = accountId;

      // Activate mode: patch provider onto the dormant account before storing credentials
      if (aid && form.provider) {
        await patchToEngine('gateway', `/api/v1/cloud-accounts/${aid}`, { provider: form.provider });
      }

      if (!aid) {
        // Normal flow: create the account record first
        const accountPayload = isVcs
          ? {
              customer_id:     customerId,
              tenant_id:       form.tenantId,
              account_name:    form.accountName,
              account_type:    'code_security',
              provider:        form.provider,
              credential_type: form.authMethod,
              auth_config: {
                repo_url:       form.credentials.repo_url || '',
                default_branch: form.credentials.default_branch || 'main',
                vcs_platform:   form.provider,
                scan_types:     ['sast'],
              },
            }
          : {
              customer_id:  customerId,
              tenant_id:    form.tenantId,
              account_name: form.accountName,
              account_type: form.accountType,
              provider:     form.provider,
            };

        const created = await postToEngine('gateway', '/api/v1/cloud-accounts', accountPayload);

        if (created.error || !created.account_id) {
          updateVStep(0, { status: 'error', detail: created.error || 'No account_id returned' });
          setResult({ success: false, message: created.error || 'Failed to create account', errors: [] });
          return;
        }

        aid = created.account_id;
        setAccountId(aid);
      }

      updateVStep(0, { status: 'done', detail: `ID: ${aid.slice(0, 8)}…` });
      updateVStep(1, { status: 'running' });

      const credResult = await postToEngine('gateway', `/api/v1/cloud-accounts/${aid}/credentials`, {
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
      const isVcs = VCS_PROVIDER_SET.has(form.provider);

      const schedPayload = {
        account_id:        accountId,             // UUID from POST /cloud-accounts
        tenant_id:         form.tenantId,
        customer_id:       customerId,
        schedule_name:     `${form.accountName} — ${schedule.cron_expression}`,
        cron_expression:   schedule.cron_expression,
        timezone:          schedule.timezone,
        enabled:           schedule.enabled,
        engines_requested: schedule.engines_requested,
        notify_on_failure: schedule.notify_on_failure,
        notify_on_success: schedule.notify_on_success,
        ...(isVcs && {
          // VCS scan trigger — pass branch; repo_url resolved server-side from auth_config
          branch: form.credentials.default_branch || 'main',
        }),
      };

      const sched = await postToEngine('gateway', '/api/v1/schedules', schedPayload);

      if (sched.error) throw new Error(sched.error);

      // Auto-provision dormant capability accounts — only for new cloud_csp accounts, not activate mode.
      if (!initialConfig) Promise.allSettled([
        { type: 'vulnerability', provider: 'agent',    label: 'Vulnerability Scanner' },
        { type: 'database',      provider: 'postgres', label: 'Database Security' },
        { type: 'code_security', provider: 'github',   label: 'Code Security' },
        { type: 'middleware',    provider: 'agent',    label: 'Middleware Monitor' },
      ].map(cap =>
        postToEngine('gateway', '/api/v1/cloud-accounts', {
          customer_id:   customerId,
          tenant_id:     form.tenantId,
          account_name:  `${form.accountName} — ${cap.label}`,
          account_type:  cap.type,
          provider:      cap.provider,
        })
      ));

      onComplete({
        accountId,
        scheduleId:  sched.schedule_id,
        accountType: form.accountType,
        provider:    form.provider,
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
      if (!step1Valid) return;
      // Pre-set engines for account type
      setSchedule(s => ({ ...s, engines_requested: [...(defaultEngines[form.accountType] || ALL_ENGINES)] }));
      setStep(2);
    } else if (step === 2) {
      if (isAgentType) {
        // Agent setup happens in the AgentSetupStep component itself.
        // accountId is set by AgentSetupStep via setAccountId.
        // Skip step 3, go directly to schedule.
        setStep(4);
      } else {
        // cloud_csp / database / secops: validate credentials
        const allFilled = getFields(form.provider, form.authMethod)
          .filter(f => !f.optional)
          .every(f => form.credentials[f.key]?.trim());
        if (!allFilled) return;
        setStep(3);
        await runValidation();
      }
    } else if (step === 3 && result?.success) {
      setStep(4);
    } else if (step === 4) {
      setStep(5);
    }
  }

  // Validation rules for the Next button
  const step1Valid = initialConfig
    ? !!(form.provider && form.authMethod)  // workspace + name pre-filled from initialConfig
    : !!(form.tenantId && form.accountName.trim() && form.provider && form.authMethod);

  const step2Valid = isAgentType
    ? true  // agent setup auto-runs; button always enabled to proceed
    : getFields(form.provider, form.authMethod)
        .filter(f => !f.optional)
        .every(f => form.credentials[f.key]?.trim());

  const step4Valid = schedule.engines_requested.length > 0 && schedule.cron_expression.trim();

  const ACTIVATE_LABELS = { vulnerability: 'Vulnerability Scanner', database: 'Database Security', code_security: 'Code Security', middleware: 'Middleware Monitor' };
  const wizardTitle = initialConfig
    ? `Configure ${ACTIVATE_LABELS[form.accountType] || form.accountType}`
    : form.provider
      ? `Connect ${PROVIDERS[form.provider]?.name || 'Cloud'} Account`
      : 'Connect Cloud Account';

  // Display index for the step indicator (position in stepConfig array)
  function displayIndex(n) {
    return stepConfig.findIndex(s => s.n === n);
  }
  const currentDisplayIndex = displayIndex(step);

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
      <div className="rounded-xl w-full max-w-2xl shadow-2xl flex flex-col max-h-[90vh]"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b"
          style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
            {wizardTitle}
          </h2>
          <button onClick={onCancel} className="p-1 rounded hover:bg-white/10">
            <X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          </button>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-0 px-6 py-3 border-b overflow-x-auto" style={{ borderColor: 'var(--border-primary)' }}>
          {stepConfig.map((sc, i) => {
            const done   = currentDisplayIndex > i;
            const active = currentDisplayIndex === i;
            return (
              <div key={sc.n} className="flex items-center flex-shrink-0">
                <div className="flex items-center gap-1.5">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${done ? 'bg-green-500 text-white' : active ? 'bg-blue-500 text-white' : 'text-gray-500'}`}
                    style={{ border: done || active ? 'none' : '2px solid var(--border-primary)' }}>
                    {done ? '✓' : i + 1}
                  </div>
                  <span className="text-xs font-medium whitespace-nowrap" style={{ color: active ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    {sc.label}
                  </span>
                </div>
                {i < stepConfig.length - 1 && (
                  <ChevronRight className="w-3.5 h-3.5 mx-1.5 flex-shrink-0" style={{ color: 'var(--border-primary)' }} />
                )}
              </div>
            );
          })}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {step === 1 && (
            <Step1 form={form} setForm={setForm}
              localTenants={localTenants}
              onWorkspaceCreated={handleWorkspaceSignal}
              providers={PROVIDERS}
              accountTypeOptions={acctTypeOptions}
              activateMode={!!initialConfig} />
          )}

          {step === 2 && isAgentType && (
            <AgentSetupStep
              form={form}
              customerId={customerId}
              accountId={accountId}
              setAccountId={setAccountId}
              agentToken={agentToken}
              setAgentToken={setAgentToken}
              accountTypeOptions={acctTypeOptions}
              preExistingAccountId={initialConfig?.accountId}
            />
          )}

          {step === 2 && !isAgentType && <Step2 form={form} setForm={setForm} providers={PROVIDERS} />}

          {step === 3 && <Step3 steps={validationSteps} result={result} form={form} providers={PROVIDERS} />}

          {step === 4 && (
            <Step4
              schedule={schedule}
              setSchedule={setSchedule}
              accountType={form.accountType}
            />
          )}

          {step === 5 && (
            <Step5
              form={form}
              schedule={schedule}
              accountId={accountId}
              result={result}
              launching={launching}
              launchError={launchError}
              providers={PROVIDERS}
              accountTypeOptions={acctTypeOptions}
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
            {step > 1 && step !== 3 && (
              <button
                onClick={() => {
                  // Agent types: from step 4 go back to step 2; from step 5 go back to step 4
                  if (isAgentType && step === 4) { setStep(2); return; }
                  setStep(s => s - 1);
                }}
                className="px-4 py-2 rounded-lg text-sm"
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
            {step === 2 && !isAgentType && (
              <button onClick={handleNext} disabled={!step2Valid}
                className="px-5 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-40"
                style={{ backgroundColor: 'var(--accent-primary)' }}>
                {isCodeSecurity ? 'Validate Repository →' : 'Validate Credentials →'}
              </button>
            )}
            {step === 2 && isAgentType && (
              <button onClick={handleNext} disabled={!accountId}
                className="px-5 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-40"
                style={{ backgroundColor: 'var(--accent-primary)' }}>
                Configure Schedule →
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

      {/* ── Inline: Create Workspace modal ──────────────────────────────────── */}
      {showCreateWS && (
        <InlineCreateWorkspace
          onClose={() => setShowCreateWS(false)}
          onCreate={handleCreateWorkspace}
        />
      )}

      {/* ── Inline: Workspace created confirmation ───────────────────────────── */}
      {createdWorkspace && (
        <WorkspaceCreatedConfirmation
          workspace={createdWorkspace}
          onSelectAndContinue={() => {
            setForm(f => ({ ...f, tenantId: createdWorkspace.tenant_id }));
            setCreatedWorkspace(null);
          }}
          onCreateAnother={() => {
            setCreatedWorkspace(null);
            setShowCreateWS(true);
          }}
        />
      )}
    </div>
  );
}

// ── Inline workspace creation (layered over wizard) ───────────────────────────
function InlineCreateWorkspace({ onClose, onCreate }) {
  const [wsForm, setWsForm] = useState({
    tenant_name: '', tenant_description: '', tenant_type: 'cloud', environment: 'production',
  });
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!wsForm.tenant_name.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await onCreate(wsForm);
    } catch (err) {
      setError(err.message || 'Failed to create workspace');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70">
      <div className="rounded-xl w-full max-w-md shadow-2xl flex flex-col max-h-[90vh]"
        style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center gap-3 p-6 pb-5 flex-shrink-0">
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10"
            title="Back to add account">
            <ArrowLeft className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          </button>
          <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
            New Workspace
          </h3>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col flex-1 min-h-0">
        <div className="flex-1 overflow-y-auto px-6 space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Workspace Name <span className="text-red-400">*</span>
            </label>
            <input type="text" value={wsForm.tenant_name} autoFocus required
              onChange={e => setWsForm(f => ({ ...f, tenant_name: e.target.value }))}
              placeholder="e.g. Production, Dev, APAC"
              className="w-full px-3 py-2 rounded-lg text-sm outline-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }} />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Environment</label>
            <div className="grid grid-cols-2 gap-2">
              {ENV_OPTIONS_WZ.map(opt => (
                <button key={opt.value} type="button"
                  onClick={() => setWsForm(f => ({ ...f, environment: opt.value }))}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all"
                  style={{
                    border: `1px solid ${wsForm.environment === opt.value ? opt.color : 'var(--border-primary)'}`,
                    backgroundColor: wsForm.environment === opt.value ? opt.color + '18' : 'var(--bg-tertiary)',
                    color: wsForm.environment === opt.value ? opt.color : 'var(--text-secondary)',
                  }}>
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: opt.color }} />
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          <TenantTypeSelector value={wsForm.tenant_type} onChange={v => setWsForm(f => ({ ...f, tenant_type: v }))} />

          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Description <span className="text-xs font-normal" style={{ color: 'var(--text-tertiary)' }}>(optional)</span>
            </label>
            <textarea rows={2} value={wsForm.tenant_description}
              onChange={e => setWsForm(f => ({ ...f, tenant_description: e.target.value }))}
              placeholder="Purpose of this workspace"
              className="w-full px-3 py-2 rounded-lg text-sm outline-none resize-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }} />
          </div>

          {error && <p className="text-sm text-red-400 bg-red-500/10 px-3 py-2 rounded-lg">{error}</p>}
        </div>

        <div className="flex justify-between px-6 py-4 border-t flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
            <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg text-sm"
              style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
              ← Back
            </button>
            <button type="submit" disabled={saving || !wsForm.tenant_name.trim()}
              className="px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
              style={{ backgroundColor: 'var(--accent-primary)' }}>
              {saving ? 'Creating…' : 'Create Workspace'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Workspace created — success confirmation with "use it" or "create another" ──
function WorkspaceCreatedConfirmation({ workspace, onSelectAndContinue, onCreateAnother }) {
  const envOpt = ENV_OPTIONS_WZ.find(e => e.value === workspace.environment) || ENV_OPTIONS_WZ[0];
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70">
      <div className="rounded-xl p-6 w-full max-w-sm shadow-2xl text-center max-h-[90vh] overflow-y-auto"
        style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
        <div className="w-14 h-14 rounded-full bg-green-500/15 flex items-center justify-center mx-auto mb-4">
          <CheckCircle2 className="w-7 h-7 text-green-400" />
        </div>
        <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
          Workspace Created
        </h3>
        <p className="text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>
          <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>{workspace.tenant_name}</span> is ready.
        </p>
        <span className="inline-block px-2 py-0.5 rounded text-xs font-medium mb-5"
          style={{ backgroundColor: envOpt.color + '18', color: envOpt.color }}>{envOpt.label}</span>

        <div className="space-y-2">
          <button onClick={onSelectAndContinue}
            className="w-full py-2.5 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--accent-primary)' }}>
            Use this workspace → Continue adding account
          </button>
          <button onClick={onCreateAnother}
            className="w-full py-2 rounded-lg text-sm font-medium"
            style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
            <Plus className="w-3.5 h-3.5 inline mr-1" />Create another workspace
          </button>
        </div>
      </div>
    </div>
  );
}
