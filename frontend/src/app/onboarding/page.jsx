'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import {
  Plus, AlertTriangle, Play, Loader2,
  Calendar, Zap, Building2, X, RefreshCw, ChevronRight,
  Trash2, Square, CheckSquare, ShieldCheck,
} from 'lucide-react';
import { getFromEngine, postToEngine, patchToEngine, deleteFromEngine, fetchView } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';
import { useAuth } from '@/lib/auth-context';
import { useToast } from '@/lib/toast-context';
import DataTable from '@/components/shared/DataTable';
import ScanRunDetailModal from '@/components/domain/ScanRunDetailModal';
import ScheduleModal from '@/components/onboarding/ScheduleModal';
import { TenantTypeSelector } from '@/components/onboarding/TenantTypeSelector';

const SCAN_TRIGGER_ROLES = ['tenant_admin', 'org_admin', 'platform_admin'];
const SCAN_ALL_ROLES     = ['org_admin', 'platform_admin'];
const CAN_MANAGE_ROLES   = ['tenant_admin', 'org_admin', 'platform_admin'];
const CAN_DELETE_ROLES   = ['org_admin', 'platform_admin'];

const ENV_OPTIONS = [
  { value: 'production',  label: 'Production',  color: '#ef4444' },
  { value: 'staging',     label: 'Staging',     color: '#f97316' },
  { value: 'development', label: 'Development', color: '#3b82f6' },
  { value: 'test',        label: 'Test',        color: '#6b7280' },
];

const TYPE_COLORS = {
  cloud_csp:     { bg: 'rgba(59,130,246,0.12)',  color: '#60a5fa' },
  vulnerability: { bg: 'rgba(245,158,11,0.12)',  color: '#fbbf24' },
  code_security: { bg: 'rgba(139,92,246,0.12)',  color: '#a78bfa' },
  database:      { bg: 'rgba(20,184,166,0.12)',  color: '#2dd4bf' },
  middleware:    { bg: 'rgba(236,72,153,0.12)',   color: '#f472b6' },
};

const TYPE_LABELS = {
  cloud_csp:     'Cloud CSP',
  vulnerability: 'Vulnerability',
  code_security: 'Code Security',
  database:      'Database',
  middleware:    'Middleware',
};

const PROVIDER_COLORS = {
  AWS: '#FF9900', AZURE: '#0078D4', GCP: '#4285F4', OCI: '#F80000',
  ALICLOUD: '#FF6A00', IBM: '#1F70C1', K8S: '#326CE5',
  POSTGRES: '#336791', MYSQL: '#4479A1', MSSQL: '#CC2927',
  MONGODB: '#47A248', ORACLE: '#C74634',
  GITHUB: '#24292E', GITLAB: '#FC6D26', BITBUCKET: '#0052CC',
  AGENT: '#8B5CF6',
};

// ── 3-Step Journey Stepper ────────────────────────────────────────────────────
function JourneyStepper({ steps }) {
  return (
    <div className="rounded-xl border overflow-hidden"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="grid grid-cols-3">
        {steps.map((step, i) => {
          const isComplete = step.status === 'complete';
          const isCurrent  = step.status === 'current';
          const isPending  = step.status === 'pending';
          const accentCol  = isComplete ? '#10b981' : isCurrent ? '#3b82f6' : '#64748b';
          const isClickable = !!(step.href || step.onClick);

          const inner = (
            <div className={`flex items-center gap-3 px-5 py-4 w-full transition-opacity ${isClickable ? 'hover:opacity-80 cursor-pointer' : ''}`}>
              {/* Number badge — always shows the number, color indicates state */}
              <div className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-base flex-shrink-0"
                style={{
                  backgroundColor: isComplete ? 'rgba(16,185,129,0.15)' : isCurrent ? 'rgba(59,130,246,0.15)' : 'var(--bg-tertiary)',
                  color: accentCol,
                  border: `2px solid ${accentCol}`,
                }}>
                {step.number}
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold leading-tight"
                  style={{ color: isPending ? '#64748b' : 'var(--text-primary)' }}>
                  {step.label}
                </p>
                <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--text-tertiary)' }}>
                  {step.sublabel}
                </p>
              </div>
              {isClickable && (
                <ChevronRight className="w-4 h-4 flex-shrink-0" style={{ color: accentCol }} />
              )}
            </div>
          );

          const borderStyle = { borderRight: i < steps.length - 1 ? '1px solid var(--border-primary)' : 'none' };

          if (step.href) {
            return (
              <Link key={step.id} href={step.href} className="block" style={borderStyle}>
                {inner}
              </Link>
            );
          }
          if (step.onClick) {
            return (
              <button key={step.id} type="button" onClick={step.onClick} className="w-full text-left" style={borderStyle}>
                {inner}
              </button>
            );
          }
          return (
            <div key={step.id} style={borderStyle}>{inner}</div>
          );
        })}
      </div>
    </div>
  );
}

// ── Create Workspace Modal ────────────────────────────────────────────────────
function CreateWorkspaceModal({ customerId, onClose, onCreated }) {
  const [form, setForm] = useState({
    tenant_name: '', tenant_description: '', tenant_type: 'cloud', environment: 'production',
  });
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!form.tenant_name.trim()) return;
    setSaving(true);
    setError(null);
    const res = await postToEngine('onboarding', '/api/v1/tenants', {
      customer_id:        customerId,
      tenant_name:        form.tenant_name.trim(),
      tenant_description: form.tenant_description.trim() || undefined,
      tenant_type:        form.tenant_type,
      environment:        form.environment,
    });
    setSaving(false);
    if (res.error) { setError(res.error); return; }
    onCreated(res);
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="rounded-xl p-6 w-full max-w-md shadow-2xl"
        style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Create Workspace</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/10">
            <X className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Workspace Name <span className="text-red-400">*</span>
            </label>
            <input type="text" value={form.tenant_name}
              onChange={e => setForm(f => ({ ...f, tenant_name: e.target.value }))}
              placeholder="e.g. APAC Production, Dev, Staging"
              className="w-full px-3 py-2 rounded-lg text-sm outline-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }}
              required autoFocus />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Environment</label>
            <div className="grid grid-cols-2 gap-2">
              {ENV_OPTIONS.map(opt => (
                <button key={opt.value} type="button"
                  onClick={() => setForm(f => ({ ...f, environment: opt.value }))}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all"
                  style={{
                    border: `1px solid ${form.environment === opt.value ? opt.color : 'var(--border-primary)'}`,
                    backgroundColor: form.environment === opt.value ? opt.color + '18' : 'var(--bg-tertiary)',
                    color: form.environment === opt.value ? opt.color : 'var(--text-secondary)',
                  }}>
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: opt.color }} />
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
          <TenantTypeSelector value={form.tenant_type} onChange={v => setForm(f => ({ ...f, tenant_type: v }))} />
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Description <span className="text-xs font-normal" style={{ color: 'var(--text-tertiary)' }}>(optional)</span>
            </label>
            <textarea rows={2} value={form.tenant_description}
              onChange={e => setForm(f => ({ ...f, tenant_description: e.target.value }))}
              placeholder="Purpose of this workspace"
              className="w-full px-3 py-2 rounded-lg text-sm outline-none resize-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' }} />
          </div>
          {error && <p className="text-sm text-red-400 bg-red-500/10 px-3 py-2 rounded-lg">{error}</p>}
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg text-sm"
              style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>Cancel</button>
            <button type="submit" disabled={saving || !form.tenant_name.trim()}
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

// ── Delete confirmation modal ──────────────────────────────────────────────────
function DeleteAccountModal({ account, onClose, onDeleted }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleDelete() {
    setBusy(true);
    setError(null);
    const res = await deleteFromEngine('onboarding', `/api/v1/cloud-accounts/${account.accountId}`);
    setBusy(false);
    if (res?.error) { setError(res.error); return; }
    onDeleted(account.accountId);
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="rounded-xl p-6 w-full max-w-sm shadow-2xl"
        style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-red-500/15 flex items-center justify-center shrink-0">
            <Trash2 className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <p className="font-semibold" style={{ color: 'var(--text-primary)' }}>Delete Account</p>
            <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>{account.name}</p>
          </div>
        </div>
        <p className="text-sm mb-5" style={{ color: 'var(--text-secondary)' }}>
          This will remove the account and all associated scan data. This action cannot be undone.
        </p>
        {error && <p className="text-sm text-red-400 bg-red-500/10 px-3 py-2 rounded-lg mb-4">{error}</p>}
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm"
            style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>Cancel</button>
          <button onClick={handleDelete} disabled={busy}
            className="px-4 py-2 rounded-lg text-sm font-medium text-white bg-red-600 hover:bg-red-700 disabled:opacity-50">
            {busy ? 'Deleting…' : 'Delete Account'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Bulk Delete confirmation ────────────────────────────────────────────────────
function BulkDeleteModal({ count, onClose, onConfirm, busy }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="rounded-xl p-6 w-full max-w-sm shadow-2xl"
        style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-red-500/15 flex items-center justify-center shrink-0">
            <Trash2 className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <p className="font-semibold" style={{ color: 'var(--text-primary)' }}>Delete {count} Account{count !== 1 ? 's' : ''}</p>
            <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>This cannot be undone</p>
          </div>
        </div>
        <p className="text-sm mb-5" style={{ color: 'var(--text-secondary)' }}>
          All selected accounts and their associated scan data will be permanently removed.
        </p>
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm"
            style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>Cancel</button>
          <button onClick={onConfirm} disabled={busy}
            className="px-4 py-2 rounded-lg text-sm font-medium text-white bg-red-600 hover:bg-red-700 disabled:opacity-50">
            {busy ? 'Deleting…' : `Delete ${count}`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function WorkspaceOnboardingPage() {
  const { customerId, activeTenant } = useTenant();
  const { role } = useAuth();
  const toast = useToast();
  const router = useRouter();

  const [loading, setLoading]               = useState(true);
  const [accounts, setAccounts]             = useState([]);
  const [tenants, setTenants]               = useState([]);
  const [schedules, setSchedules]           = useState([]);
  const [runningFor, setRunningFor]         = useState({});
  const [pausingFor, setPausingFor]         = useState({});
  const [scanAllBusy, setScanAllBusy]       = useState(false);
  const [selectedRunId, setSelectedRunId]   = useState(null);
  const [scheduleModal, setScheduleModal]   = useState(null);
  const [deleteModal, setDeleteModal]       = useState(null);
  const [showCreateWS, setShowCreateWS]     = useState(false);
  const [selected, setSelected]             = useState(new Set());
  const [bulkRunBusy, setBulkRunBusy]       = useState(false);
  const [showBulkDelete, setShowBulkDelete] = useState(false);
  const [bulkDeleteBusy, setBulkDeleteBusy] = useState(false);

  const canTriggerScan = SCAN_TRIGGER_ROLES.includes(role);
  const canScanAll     = SCAN_ALL_ROLES.includes(role);
  const canManage      = CAN_MANAGE_ROLES.includes(role);
  const canDelete      = CAN_DELETE_ROLES.includes(role);

  const loadData = useCallback(async () => {
    setLoading(true);
    const tenantId = activeTenant?.tenant_id;
    const qp = tenantId ? `?tenant_id=${tenantId}` : '';
    try {
      const [accountsData, schedsData, tenantsData] = await Promise.all([
        fetchView('onboarding/cloud_accounts', {}),
        getFromEngine('onboarding', `/api/v1/schedules${qp}&limit=200`),
        customerId ? getFromEngine('onboarding', '/api/v1/tenants', { customer_id: customerId }) : Promise.resolve({}),
      ]);

      const raw = accountsData?.accounts || (Array.isArray(accountsData) ? accountsData : []);
      setAccounts(raw.map(a => ({
        id:              a.accountId  || a.account_id,
        accountId:       a.accountId  || a.account_id,
        name:            a.accountName || a.account_name || a.account_id,
        provider:        (a.provider || 'aws').toUpperCase(),
        accountType:     a.accountCategory || a.accountType || a.account_type || 'cloud_csp',
        tenantId:        a.tenantId || a.tenant_id,
        tenantName:      a.tenantName || a.tenant_name || '—',
        tenantEnv:       a.tenantEnvironment || a.tenant_environment || 'production',
        resources:       a.regionsCount || a.resources || 0,
        findings:        a.totalFindings || a.findings || 0,
        lastScan:        a.lastScanAt || a.last_scan_at,
        credRef:         a.credentialRef || a.credential_ref || '',
        credStatus:      (a.credentialValidationStatus || a.credential_validation_status) === 'valid' ? 'Valid'
          : (a.credentialValidationStatus || a.credential_validation_status) === 'expired' ? 'Expired'
          : 'Pending',
        accountStatus:   a.accountStatus || a.account_status || 'active',
        onboardingStatus: a.onboardingStatus || a.account_onboarding_status || 'pending',
      })));
      setSchedules(schedsData?.schedules || []);
      setTenants(tenantsData?.tenants || []);
    } catch (err) {
      console.warn('Error loading workspace onboarding data:', err);
    } finally {
      setLoading(false);
    }
  }, [activeTenant, customerId]);

  useEffect(() => { loadData(); }, [loadData]);

  // ── Journey step status ──────────────────────────────────────────────────────
  const hasWorkspace = tenants.length > 0 || !!activeTenant;
  const hasAccount   = accounts.length > 0;
  const hasVerified  = accounts.some(a => a.credStatus === 'Valid');

  const journeySteps = [
    {
      id: 'workspace', number: 1, label: 'Workspace Onboarding',
      sublabel: hasWorkspace
        ? `${tenants.length} workspace${tenants.length !== 1 ? 's' : ''} active — click to add more`
        : 'No workspace yet — click to create',
      status: hasWorkspace ? 'complete' : 'current',
      onClick: () => setShowCreateWS(true),
    },
    {
      id: 'account', number: 2, label: 'Account Onboarding',
      sublabel: hasAccount
        ? `${accounts.length} account${accounts.length !== 1 ? 's' : ''} added — click to add more`
        : 'Click to add cloud, agent, or DB accounts',
      status: hasAccount ? 'complete' : hasWorkspace ? 'current' : 'pending',
      href: '/onboarding/wizard',
    },
    {
      id: 'scan', number: 3, label: 'Scan / Schedule',
      sublabel: hasVerified ? 'Credentials verified — ready to scan' : 'Configure schedules and run scans',
      status: hasVerified ? 'complete' : hasAccount ? 'current' : 'pending',
      href: '/scans',
    },
  ];

  // ── Scan helpers ─────────────────────────────────────────────────────────────
  async function handleRunNow(accountId) {
    setRunningFor(p => ({ ...p, [accountId]: true }));
    try {
      const result = await postToEngine('gateway', '/api/v1/scans/run-now', { account_id: accountId });
      if (result.error) { toast.error(`Failed: ${result.error}`); return; }
      if (result.scan_run_id) { setSelectedRunId(result.scan_run_id); toast.success('Scan queued'); }
    } catch { toast.error('Failed to trigger scan.'); }
    finally { setRunningFor(p => ({ ...p, [accountId]: false })); }
  }

  async function handleScanAll() {
    if (!canScanAll) return;
    setScanAllBusy(true);
    try {
      const result = await postToEngine('gateway', '/api/v1/scans/run-all', { tenant_id: activeTenant?.tenant_id });
      if (result.error) { toast.error(`Scan All failed: ${result.error}`); return; }
      const n = result.triggered?.length ?? result.triggered_count ?? 0;
      toast.success(`Triggered ${n} account${n !== 1 ? 's' : ''}`);
    } catch { toast.error('Scan All failed.'); }
    finally { setScanAllBusy(false); }
  }

  async function handleBulkRun() {
    if (selected.size === 0 || !canTriggerScan) return;
    setBulkRunBusy(true);
    let ok = 0;
    await Promise.all([...selected].map(async id => {
      setRunningFor(p => ({ ...p, [id]: true }));
      try {
        const r = await postToEngine('gateway', '/api/v1/scans/run-now', { account_id: id });
        if (!r.error) ok++;
      } finally {
        setRunningFor(p => ({ ...p, [id]: false }));
      }
    }));
    setBulkRunBusy(false);
    setSelected(new Set());
    toast.success(`Triggered ${ok} of ${selected.size} account${selected.size !== 1 ? 's' : ''}`);
  }

  async function handleBulkDelete() {
    if (!canDelete || selected.size === 0) return;
    setBulkDeleteBusy(true);
    let ok = 0;
    await Promise.all([...selected].map(async id => {
      try {
        const r = await deleteFromEngine('onboarding', `/api/v1/cloud-accounts/${id}`);
        if (!r?.error) ok++;
      } catch { /* continue */ }
    }));
    setBulkDeleteBusy(false);
    setShowBulkDelete(false);
    setSelected(new Set());
    setAccounts(prev => prev.filter(a => !selected.has(a.id) || ok === 0));
    loadData();
    toast.success(`Deleted ${ok} account${ok !== 1 ? 's' : ''}`);
  }

  async function handlePause(accountId) {
    setPausingFor(p => ({ ...p, [accountId]: true }));
    try {
      const acct = accounts.find(a => a.id === accountId);
      const newStatus = acct?.accountStatus === 'inactive' ? 'active' : 'inactive';
      const result = await patchToEngine('onboarding', `/api/v1/cloud-accounts/${accountId}`, { account_status: newStatus });
      if (result.error) { toast.error(`Failed: ${result.error}`); return; }
      setAccounts(prev => prev.map(a => a.id === accountId ? { ...a, accountStatus: newStatus } : a));
      toast.success(newStatus === 'inactive' ? 'Account paused' : 'Account resumed');
    } catch { toast.error('Failed to update account.'); }
    finally { setPausingFor(p => ({ ...p, [accountId]: false })); }
  }

  function handleEditSchedule(e, row) {
    e.stopPropagation();
    const existingSchedule = schedules.find(s => s.account_id === row.accountId) || null;
    setScheduleModal({
      account: { account_id: row.accountId, account_type: row.accountType, provider: row.provider?.toLowerCase(), tenant_id: activeTenant?.tenant_id },
      existingSchedule,
    });
  }

  const refreshSchedules = useCallback(async () => {
    const qp = activeTenant?.tenant_id ? `?tenant_id=${activeTenant.tenant_id}` : '';
    const d = await getFromEngine('onboarding', `/api/v1/schedules${qp}&limit=200`).catch(() => null);
    if (d) setSchedules(d?.schedules || []);
  }, [activeTenant]);

  // ── Row selection ────────────────────────────────────────────────────────────
  const allIds = accounts.map(a => a.id);
  const allSelected = allIds.length > 0 && allIds.every(id => selected.has(id));

  function toggleAll() { setSelected(allSelected ? new Set() : new Set(allIds)); }
  function toggleOne(id) {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  // ── Columns — order: select | Workspace | Account | Account Types | Provider | Status | Running Readiness | Scan
  const columns = [
    {
      id: 'select',
      header: () => (
        <button onClick={toggleAll} className="p-0.5 rounded hover:bg-white/10">
          {allSelected
            ? <CheckSquare className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
            : <Square className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />}
        </button>
      ),
      cell: info => {
        const id = info.row.original.id;
        return (
          <button onClick={e => { e.stopPropagation(); toggleOne(id); }} className="p-0.5 rounded hover:bg-white/10">
            {selected.has(id)
              ? <CheckSquare className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
              : <Square className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />}
          </button>
        );
      },
    },
    {
      accessorKey: 'tenantName',
      header: 'Workspace',
      cell: info => {
        const row = info.row.original;
        const env = ENV_OPTIONS.find(e => e.value === row.tenantEnv);
        return (
          <div className="flex items-center gap-1.5">
            <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
            {env && (
              <span className="px-1.5 py-0.5 rounded text-xs font-medium"
                style={{ backgroundColor: env.color + '18', color: env.color }}>
                {env.label}
              </span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'name',
      header: 'Account',
      cell: info => (
        <Link href={`/onboarding/accounts/${info.row.original.id}`}
          style={{ color: 'var(--accent-primary)' }} className="font-medium hover:underline">
          {info.getValue()}
        </Link>
      ),
    },
    {
      accessorKey: 'accountType',
      header: 'Account Types',
      cell: info => {
        const t = info.getValue();
        const s = TYPE_COLORS[t] || { bg: 'rgba(100,116,139,0.12)', color: '#94a3b8' };
        return (
          <span className="px-2 py-0.5 rounded text-xs font-medium"
            style={{ backgroundColor: s.bg, color: s.color }}>
            {TYPE_LABELS[t] || t}
          </span>
        );
      },
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: info => {
        const p = info.getValue();
        const c = PROVIDER_COLORS[p?.toUpperCase()] || '#666';
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold"
            style={{ backgroundColor: c + '20', color: c }}>
            {p}
          </span>
        );
      },
    },
    {
      accessorKey: 'accountStatus',
      header: 'Status',
      cell: info => {
        const row = info.row.original;
        const isPaused = row.accountStatus === 'inactive';
        const pausing  = pausingFor[row.id];

        if (!canManage) {
          return (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
              style={{
                backgroundColor: isPaused ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)',
                color: isPaused ? '#f59e0b' : '#10b981',
              }}>
              <span className="w-1.5 h-1.5 rounded-full"
                style={{ backgroundColor: isPaused ? '#f59e0b' : '#10b981' }} />
              {isPaused ? 'Paused' : 'Active'}
            </span>
          );
        }

        return (
          <button onClick={e => { e.stopPropagation(); handlePause(row.id); }} disabled={pausing}
            title={isPaused ? 'Click to resume' : 'Click to pause'}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-all hover:opacity-80 disabled:opacity-40"
            style={{
              backgroundColor: isPaused ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)',
              color: isPaused ? '#f59e0b' : '#10b981',
              border: `1px solid ${isPaused ? 'rgba(245,158,11,0.3)' : 'rgba(16,185,129,0.3)'}`,
            }}>
            {pausing
              ? <Loader2 className="w-3 h-3 animate-spin" />
              : <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: isPaused ? '#f59e0b' : '#10b981' }} />}
            {isPaused ? 'Paused' : 'Active'}
          </button>
        );
      },
    },
    {
      accessorKey: 'credStatus',
      header: 'Running Readiness',
      cell: info => {
        const s = info.getValue();
        const cfg = {
          Valid:   { color: '#10b981', bg: 'rgba(16,185,129,0.1)',  icon: <ShieldCheck className="w-3 h-3" />, label: 'Ready' },
          Expired: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   icon: <AlertTriangle className="w-3 h-3" />, label: 'Expired' },
          Pending: { color: '#f97316', bg: 'rgba(249,115,22,0.1)',  icon: <AlertTriangle className="w-3 h-3" />, label: 'Pending' },
        }[s] || { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', label: s, icon: null };
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold"
            style={{ backgroundColor: cfg.bg, color: cfg.color }}>
            {cfg.icon}
            {cfg.label}
          </span>
        );
      },
    },
    {
      id: 'scan',
      header: 'Scan',
      cell: info => {
        const row = info.row.original;
        const busy     = runningFor[row.id];
        const hasSched = schedules.some(s => s.account_id === row.accountId);
        const isPaused = row.accountStatus === 'inactive';
        return (
          <div className="flex items-center gap-1">
            <button onClick={e => handleEditSchedule(e, row)}
              className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium hover:opacity-80"
              style={{ backgroundColor: 'rgba(139,92,246,0.1)', color: '#8b5cf6', border: '1px solid rgba(139,92,246,0.25)' }}>
              <Calendar className="w-3 h-3" />
              {hasSched ? 'Sched' : '+Sched'}
            </button>
            {canTriggerScan && !isPaused && (
              <button onClick={e => { e.stopPropagation(); handleRunNow(row.id); }} disabled={busy}
                className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium hover:opacity-80 disabled:opacity-40"
                style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: 'var(--accent-primary)', border: '1px solid rgba(59,130,246,0.25)' }}>
                {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                {busy ? '…' : 'Run'}
              </button>
            )}
            {canDelete && (
              <button onClick={e => { e.stopPropagation(); setDeleteModal(row); }}
                title="Delete account"
                className="flex items-center px-2 py-1 rounded text-xs hover:opacity-80"
                style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.25)' }}>
                <Trash2 className="w-3 h-3" />
              </button>
            )}
          </div>
        );
      },
    },
  ];

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Workspace Onboarding</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Connect cloud, agent, database, and code accounts to start scanning
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={loadData} disabled={loading} className="p-2 rounded-lg hover:bg-white/5 disabled:opacity-50" title="Refresh">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} style={{ color: 'var(--text-secondary)' }} />
          </button>
          {canScanAll && (
            <button onClick={handleScanAll} disabled={scanAllBusy}
              className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50"
              style={{ backgroundColor: 'rgba(34,197,94,0.12)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.3)' }}>
              {scanAllBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              {scanAllBusy ? 'Scanning…' : 'Scan All'}
            </button>
          )}
          {canManage && (
            <Link href="/onboarding/wizard"
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium"
              style={{ backgroundColor: 'var(--accent-primary)' }}>
              <Plus className="w-4 h-4" /> Add Account
            </Link>
          )}
        </div>
      </div>

      {/* 3-Step Journey Stepper */}
      <JourneyStepper steps={journeySteps} />

      {/* No-workspace callout */}
      {!hasWorkspace && canManage && (
        <div className="rounded-xl border border-dashed p-6 flex items-center justify-between"
          style={{ borderColor: 'var(--accent-primary)', backgroundColor: 'rgba(59,130,246,0.04)' }}>
          <div className="flex items-center gap-4">
            <Building2 className="w-8 h-8" style={{ color: 'var(--accent-primary)' }} />
            <div>
              <p className="font-semibold" style={{ color: 'var(--text-primary)' }}>Start with a Workspace</p>
              <p className="text-sm mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                Workspaces group your cloud accounts. Create one before adding accounts.
              </p>
            </div>
          </div>
          <button onClick={() => setShowCreateWS(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium shrink-0"
            style={{ backgroundColor: 'var(--accent-primary)' }}>
            <Plus className="w-4 h-4" /> Create Workspace
          </button>
        </div>
      )}

      {/* Accounts table with bulk toolbar */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Accounts</h2>
          <div className="flex items-center gap-2">
            {selected.size > 0 && canDelete && (
              <button onClick={() => setShowBulkDelete(true)} disabled={bulkDeleteBusy}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>
                <Trash2 className="w-3.5 h-3.5" />
                Delete ({selected.size})
              </button>
            )}
            {selected.size > 0 && canTriggerScan && (
              <button onClick={handleBulkRun} disabled={bulkRunBusy}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                style={{ backgroundColor: 'rgba(59,130,246,0.12)', color: 'var(--accent-primary)', border: '1px solid rgba(59,130,246,0.3)' }}>
                {bulkRunBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                Run Selected ({selected.size})
              </button>
            )}
            {canManage && !hasWorkspace && (
              <button onClick={() => setShowCreateWS(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium"
                style={{ backgroundColor: 'rgba(59,130,246,0.08)', color: 'var(--accent-primary)', border: '1px solid rgba(59,130,246,0.25)' }}>
                <Plus className="w-3.5 h-3.5" /> New Workspace
              </button>
            )}
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{accounts.length} total</span>
          </div>
        </div>
        <DataTable data={accounts} columns={columns} pageSize={10} loading={loading}
          emptyMessage="No accounts yet — click Add Account to get started" />
      </div>

      {/* Modals */}
      {showCreateWS && (
        <CreateWorkspaceModal customerId={customerId}
          onClose={() => setShowCreateWS(false)}
          onCreated={t => { setTenants(prev => [t, ...prev]); loadData(); }} />
      )}
      {deleteModal && (
        <DeleteAccountModal account={deleteModal}
          onClose={() => setDeleteModal(null)}
          onDeleted={id => { setAccounts(prev => prev.filter(a => a.id !== id)); setDeleteModal(null); }} />
      )}
      {showBulkDelete && (
        <BulkDeleteModal count={selected.size}
          busy={bulkDeleteBusy}
          onClose={() => setShowBulkDelete(false)}
          onConfirm={handleBulkDelete} />
      )}
      {selectedRunId && <ScanRunDetailModal scanRunId={selectedRunId} onClose={() => setSelectedRunId(null)} />}
      {scheduleModal && (
        <ScheduleModal account={scheduleModal.account} existingSchedule={scheduleModal.existingSchedule}
          onClose={() => setScheduleModal(null)}
          onSaved={() => { setScheduleModal(null); refreshSchedules(); }} />
      )}
    </div>
  );
}
