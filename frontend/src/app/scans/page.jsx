'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  Play, RefreshCw, ChevronDown, CheckCircle2, XCircle,
  Loader2, Clock, Zap, ExternalLink, Building2, Database,
  Code, Cloud, Shield,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import { getFromEngine, postToEngine, fetchView } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';
import { useAuth } from '@/lib/auth-context';
import { useToast } from '@/lib/toast-context';
import ScanRunDetailModal from '@/components/domain/ScanRunDetailModal';

// ── Helpers ───────────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  completed: { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',   icon: CheckCircle2, label: 'Completed' },
  running:   { color: '#3b82f6', bg: 'rgba(59,130,246,0.1)',  icon: Loader2,      label: 'Running',  spin: true },
  pending:   { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', icon: Clock,        label: 'Pending' },
  failed:    { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   icon: XCircle,      label: 'Failed' },
  cancelled: { color: '#f97316', bg: 'rgba(249,115,22,0.1)',  icon: XCircle,      label: 'Cancelled' },
};

const PROVIDER_COLORS = {
  aws: '#FF9900', azure: '#0078D4', gcp: '#4285F4', oci: '#F80000',
  alicloud: '#FF6A00', ibm: '#1F70C1', k8s: '#326CE5',
  postgres: '#336791', mysql: '#4479A1', mssql: '#CC2927',
  mongodb: '#47A248', oracle: '#C74634',
  github: '#24292E', gitlab: '#FC6D26', bitbucket: '#0052CC',
  agent: '#8B5CF6',
};

const SCAN_TYPE_CONFIG = {
  config:        { label: 'Config Scan',       color: '#60a5fa', bg: 'rgba(96,165,250,0.1)',  icon: Shield },
  cdr:           { label: 'CDR Scan',          color: '#f472b6', bg: 'rgba(244,114,182,0.1)', icon: Shield },
  vulnerability: { label: 'Vulnerability Scan',color: '#fbbf24', bg: 'rgba(251,191,36,0.1)',  icon: Shield },
  code_security: { label: 'Code Security',     color: '#a78bfa', bg: 'rgba(167,139,250,0.1)', icon: Code },
  database:      { label: 'DB Security',       color: '#2dd4bf', bg: 'rgba(45,212,191,0.1)',  icon: Database },
  full:          { label: 'Full Scan',         color: '#22c55e', bg: 'rgba(34,197,94,0.1)',   icon: Cloud },
  manual:        { label: 'Manual',            color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', icon: Play },
};

function deriveScanType(enginesRequested = [], triggerType = '') {
  const engines = new Set(enginesRequested.map(e => e.toLowerCase()));
  if (engines.has('cdr'))           return 'cdr';
  if (engines.has('vulnerability')) return 'vulnerability';
  if (engines.has('secops'))        return 'code_security';
  if (engines.has('dbsec'))         return 'database';
  if (engines.has('discovery') && engines.has('check') && enginesRequested.length >= 5) return 'full';
  if (engines.has('discovery') || engines.has('check')) return 'config';
  if (triggerType === 'manual') return 'manual';
  return 'config';
}

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  const Icon = cfg.icon;
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
      style={{ backgroundColor: cfg.bg, color: cfg.color }}>
      <Icon className={`w-3 h-3 ${cfg.spin ? 'animate-spin' : ''}`} />
      {cfg.label}
    </span>
  );
}

function ScanTypeBadge({ engines, triggerType }) {
  const type = deriveScanType(engines, triggerType);
  const cfg  = SCAN_TYPE_CONFIG[type] || SCAN_TYPE_CONFIG.manual;
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
      style={{ backgroundColor: cfg.bg, color: cfg.color }}>
      {cfg.label}
    </span>
  );
}

function EngineBar({ enginesRequested = [], enginesCompleted = [], engineStatuses = {} }) {
  if (!enginesRequested.length) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {enginesRequested.map(eng => {
        const done   = enginesCompleted.includes(eng);
        const status = engineStatuses?.[eng]?.status || (done ? 'completed' : 'pending');
        const color  = status === 'completed' ? '#22c55e' : status === 'failed' ? '#ef4444' : status === 'running' ? '#3b82f6' : '#64748b';
        return (
          <span key={eng} className="px-1.5 py-0.5 rounded text-[10px] font-mono"
            style={{ backgroundColor: `${color}18`, color, border: `1px solid ${color}30` }}>
            {eng}
          </span>
        );
      })}
    </div>
  );
}

function fmtDuration(started, completed) {
  if (!started) return '—';
  const end = completed ? new Date(completed) : new Date();
  const sec = Math.floor((end - new Date(started)) / 1000);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60), s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function fmtRelative(ts) {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts);
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(ts).toLocaleDateString();
}

// ── Run Now modal ─────────────────────────────────────────────────────────────

function RunNowModal({ accounts, schedules, onClose, onLaunched }) {
  const [accountId, setAccountId]   = useState('');
  const [scheduleId, setScheduleId] = useState('');
  const [launching, setLaunching]   = useState(false);
  const [error, setError]           = useState(null);

  const filteredSchedules = schedules.filter(s => !accountId || s.account_id === accountId);

  async function handleRun() {
    if (!scheduleId) { setError('Select a schedule to run'); return; }
    setLaunching(true);
    setError(null);
    try {
      const result = await postToEngine('gateway', `/api/v1/schedules/${scheduleId}/run-now`, {});
      if (result.error) throw new Error(result.error);
      onLaunched(result.scan_run_id);
      onClose();
    } catch (e) {
      setError(e.message || 'Failed to trigger scan');
    } finally {
      setLaunching(false);
    }
  }

  const inputStyle = {
    backgroundColor: 'var(--bg-tertiary)',
    border: '1px solid var(--border-primary)',
    color: 'var(--text-primary)',
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
      <div className="rounded-xl w-full max-w-md shadow-2xl flex flex-col max-h-[90vh]"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Run Scan Now</h2>
          <button onClick={onClose} className="text-xs px-2 py-1 rounded hover:opacity-70" style={{ color: 'var(--text-muted)' }}>✕</button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Filter by Account (optional)</label>
            <div className="relative">
              <select value={accountId} onChange={e => { setAccountId(e.target.value); setScheduleId(''); }}
                className="w-full px-3 py-2 rounded-lg text-sm outline-none appearance-none" style={inputStyle}>
                <option value="">All accounts</option>
                {accounts.map(a => {
                  const id   = a.accountId || a.account_id;
                  const name = a.accountName || a.account_name || id;
                  return <option key={id} value={id}>{name} ({a.provider})</option>;
                })}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Schedule <span className="text-red-400">*</span>
            </label>
            <div className="relative">
              <select value={scheduleId} onChange={e => setScheduleId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg text-sm outline-none appearance-none" style={inputStyle}>
                <option value="">Select schedule…</option>
                {filteredSchedules.map(s => (
                  <option key={s.schedule_id} value={s.schedule_id}>
                    {s.account_name} — {s.cron_expression} ({s.enabled ? 'enabled' : 'disabled'})
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
            </div>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="flex justify-end gap-2 px-5 py-4 border-t flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm"
            style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>Cancel</button>
          <button onClick={handleRun} disabled={!scheduleId || launching}
            className="px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-40 flex items-center gap-2"
            style={{ backgroundColor: 'var(--accent-primary)' }}>
            {launching && <Loader2 className="w-4 h-4 animate-spin" />}
            {launching ? 'Launching…' : '▶ Run Now'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 8000;
const SCAN_ALL_ROLES   = ['org_admin', 'platform_admin'];

export default function ScansPage() {
  const { customerId, activeTenant } = useTenant();
  const { role } = useAuth();
  const toast    = useToast();
  const router   = useRouter();

  const tenantId = activeTenant?.tenant_id;

  const [runs, setRuns]               = useState([]);
  const [accounts, setAccounts]       = useState([]);
  const [schedules, setSchedules]     = useState([]);
  const [loading, setLoading]         = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [showRunModal, setShowRunModal] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [scanAllBusy, setScanAllBusy] = useState(false);

  const canScanAll = SCAN_ALL_ROLES.includes(role);

  // Build account lookup map: account_id → { tenantName, accountType, provider }
  const accountMap = Object.fromEntries(
    accounts.map(a => [
      a.accountId || a.account_id,
      {
        tenantName:  a.tenantName  || a.tenant_name  || '—',
        tenantEnv:   a.tenantEnvironment || a.tenant_environment || 'production',
        accountType: a.accountCategory  || a.accountType || a.account_type || 'cloud_csp',
      },
    ])
  );

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (tenantId)     params.set('tenant_id',  tenantId);
      if (customerId)   params.set('customer_id', customerId);
      if (statusFilter) params.set('status',      statusFilter);

      const [runsData, accsData, schedsData] = await Promise.all([
        getFromEngine('gateway', `/api/v1/scan-runs?${params}`),
        fetchView('onboarding/cloud_accounts', { limit: 200 }),
        getFromEngine('gateway', `/api/v1/schedules?limit=200${tenantId ? `&tenant_id=${tenantId}` : ''}`),
      ]);

      setRuns(runsData?.scan_runs || []);
      setAccounts(accsData?.accounts || []);
      setSchedules(schedsData?.schedules || []);
    } catch (e) {
      if (!silent) console.error('Failed to load scans:', e);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [tenantId, customerId, statusFilter]);

  useEffect(() => { load(); }, [load]);

  // Poll every 8s while scans are running
  useEffect(() => {
    const hasRunning = runs.some(r => r.overall_status === 'running' || r.overall_status === 'pending');
    if (!hasRunning) return;
    const t = setInterval(() => load(true), POLL_INTERVAL_MS);
    return () => clearInterval(t);
  }, [runs, load]);

  function handleLaunched(scanRunId) {
    toast?.success?.(`Scan triggered — ID: ${scanRunId?.slice(0, 8)}…`);
    setTimeout(() => load(), 1500);
  }

  async function handleScanAll() {
    if (!canScanAll) return;
    setScanAllBusy(true);
    try {
      const result = await postToEngine('gateway', '/api/v1/scans/run-all', { tenant_id: tenantId });
      if (result.error) { toast?.error?.(`Scan All failed: ${result.error}`); return; }
      const triggered = result.triggered?.length ?? result.triggered_count ?? 0;
      const skipped   = result.skipped?.length  ?? result.skipped_count  ?? 0;
      toast?.success?.(`Triggered: ${triggered} account${triggered !== 1 ? 's' : ''}, Skipped: ${skipped} inactive`);
      setTimeout(() => load(), 1500);
    } catch { toast?.error?.('Scan All failed. Please try again.'); }
    finally { setScanAllBusy(false); }
  }

  // Summary stats
  const stats = {
    total:     runs.length,
    running:   runs.filter(r => r.overall_status === 'running').length,
    completed: runs.filter(r => r.overall_status === 'completed').length,
    failed:    runs.filter(r => r.overall_status === 'failed').length,
  };

  // ── Table columns ────────────────────────────────────────────────────────────
  // Columns: Workspace | Account | Account Type | Provider | Scan Type | Status | Engines | Duration | Started | Actions

  const ENV_COLORS = { production: '#ef4444', staging: '#f97316', development: '#3b82f6', test: '#6b7280' };
  const TYPE_COLORS = {
    cloud_csp:     { bg: 'rgba(59,130,246,0.12)',  color: '#60a5fa', label: 'Cloud CSP' },
    vulnerability: { bg: 'rgba(245,158,11,0.12)',  color: '#fbbf24', label: 'Vulnerability' },
    code_security: { bg: 'rgba(139,92,246,0.12)',  color: '#a78bfa', label: 'Code Security' },
    database:      { bg: 'rgba(20,184,166,0.12)',  color: '#2dd4bf', label: 'Database' },
    middleware:    { bg: 'rgba(236,72,153,0.12)',   color: '#f472b6', label: 'Middleware' },
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Scan History</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            All scan runs across workspaces and accounts — pipeline-level tracking
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => load()} className="p-2 rounded-lg hover:opacity-70"
            style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }} title="Refresh">
            <RefreshCw className="w-4 h-4" />
          </button>
          {canScanAll && (
            <button onClick={handleScanAll} disabled={scanAllBusy}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
              style={{ backgroundColor: 'rgba(34,197,94,0.12)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.3)' }}>
              {scanAllBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
              Scan All
            </button>
          )}
          <button onClick={() => setShowRunModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--accent-primary)' }}>
            <Play className="w-3.5 h-3.5" /> Run Now
          </button>
        </div>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total',     value: stats.total,     color: 'var(--text-secondary)', filter: '' },
          { label: 'Running',   value: stats.running,   color: '#3b82f6', filter: 'running' },
          { label: 'Completed', value: stats.completed, color: '#22c55e', filter: 'completed' },
          { label: 'Failed',    value: stats.failed,    color: '#ef4444', filter: 'failed' },
        ].map(s => (
          <button key={s.label} onClick={() => setStatusFilter(s.filter)}
            className="rounded-lg p-3 text-left transition-all hover:opacity-80"
            style={{
              backgroundColor: 'var(--bg-card)',
              border: `1px solid ${statusFilter === s.filter ? s.color : 'var(--border-primary)'}`,
            }}>
            <div className="text-xl font-bold" style={{ color: s.color }}>{s.value}</div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{s.label}</div>
          </button>
        ))}
      </div>

      {/* Status filter pills */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Filter:</span>
        {['', 'running', 'completed', 'failed', 'pending'].map(s => (
          <button key={s} onClick={() => setStatusFilter(s)}
            className="px-3 py-1 rounded-full text-xs transition-all"
            style={{
              backgroundColor: statusFilter === s ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
              color: statusFilter === s ? 'white' : 'var(--text-secondary)',
            }}>
            {s || 'All'}
          </button>
        ))}
        {runs.some(r => r.overall_status === 'running') && (
          <span className="flex items-center gap-1 text-xs text-blue-400 ml-auto">
            <Loader2 className="w-3 h-3 animate-spin" /> Live
          </span>
        )}
      </div>

      {/* Scan history table */}
      <div className="rounded-xl overflow-x-auto" style={{ border: '1px solid var(--border-primary)', backgroundColor: 'var(--bg-card)' }}>
        <table className="w-full text-sm min-w-[960px]">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              {[
                'Workspace', 'Account', 'Account Type', 'Provider',
                'Scan Type', 'Status', 'Engines', 'Duration', 'Started', 'Scan ID', '',
              ].map(h => (
                <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold whitespace-nowrap"
                  style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={11} className="px-4 py-8 text-center">
                <Loader2 className="w-5 h-5 animate-spin mx-auto" style={{ color: 'var(--text-muted)' }} />
              </td></tr>
            ) : runs.length === 0 ? (
              <tr><td colSpan={11} className="px-4 py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                No scan runs found. Click <strong>Run Now</strong> to trigger your first scan.
              </td></tr>
            ) : runs.map(run => {
              const acct     = accountMap[run.account_id] || {};
              const envColor = ENV_COLORS[acct.tenantEnv] || '#6b7280';
              const typeInfo = TYPE_COLORS[acct.accountType] || { bg: 'rgba(148,163,184,0.1)', color: '#94a3b8', label: acct.accountType || '—' };
              const provCol  = PROVIDER_COLORS[run.provider?.toLowerCase()] || '#666';
              return (
                <tr key={run.scan_run_id}
                  onClick={() => setSelectedRunId(run.scan_run_id)}
                  className="cursor-pointer hover:opacity-80 transition-opacity"
                  style={{ borderBottom: '1px solid var(--border-primary)' }}>

                  {/* Workspace */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <Building2 className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--text-muted)' }} />
                      <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
                        {acct.tenantName || '—'}
                      </span>
                      {acct.tenantEnv && acct.tenantEnv !== '—' && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded"
                          style={{ backgroundColor: envColor + '18', color: envColor }}>
                          {acct.tenantEnv}
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Account */}
                  <td className="px-4 py-3 text-xs max-w-[140px]" style={{ color: 'var(--text-secondary)' }}>
                    <span className="truncate block" title={run.account_name || run.account_id}>
                      {run.account_name || run.account_id?.slice(0, 8) || '—'}
                    </span>
                  </td>

                  {/* Account Type */}
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
                      style={{ backgroundColor: typeInfo.bg, color: typeInfo.color }}>
                      {typeInfo.label}
                    </span>
                  </td>

                  {/* Provider */}
                  <td className="px-4 py-3">
                    {run.provider ? (
                      <span className="text-xs font-semibold px-2 py-0.5 rounded"
                        style={{ backgroundColor: provCol + '20', color: provCol }}>
                        {run.provider.toUpperCase()}
                      </span>
                    ) : (
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>
                    )}
                  </td>

                  {/* Scan Type */}
                  <td className="px-4 py-3">
                    <ScanTypeBadge engines={run.engines_requested || []} triggerType={run.trigger_type} />
                  </td>

                  {/* Status */}
                  <td className="px-4 py-3">
                    <StatusBadge status={run.overall_status} />
                  </td>

                  {/* Engines */}
                  <td className="px-4 py-3 max-w-[180px]">
                    <EngineBar
                      enginesRequested={run.engines_requested || []}
                      enginesCompleted={run.engines_completed || []}
                      engineStatuses={run.engine_statuses || {}}
                    />
                  </td>

                  {/* Duration */}
                  <td className="px-4 py-3 text-xs font-mono whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                    {fmtDuration(run.started_at, run.completed_at)}
                  </td>

                  {/* Started */}
                  <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                    {fmtRelative(run.started_at)}
                  </td>

                  {/* Scan ID */}
                  <td className="px-4 py-3">
                    <span className="font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}
                      title={run.scan_run_id}>
                      {run.scan_run_id?.slice(0, 8)}…
                    </span>
                  </td>

                  {/* Pipeline link */}
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={() => router.push(`/scans/${run.scan_run_id}`)}
                      className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium hover:opacity-80 whitespace-nowrap"
                      style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: 'var(--accent-primary)', border: '1px solid rgba(59,130,246,0.25)' }}
                      title="View pipeline progress">
                      <ExternalLink className="w-3 h-3" />
                      {run.overall_status === 'running' || run.overall_status === 'pending' ? 'Progress' : 'Pipeline'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Modals */}
      {showRunModal && (
        <RunNowModal
          accounts={accounts}
          schedules={schedules}
          onClose={() => setShowRunModal(false)}
          onLaunched={handleLaunched}
        />
      )}
      {selectedRunId && (
        <ScanRunDetailModal
          scanRunId={selectedRunId}
          onClose={() => setSelectedRunId(null)}
        />
      )}
    </div>
  );
}
