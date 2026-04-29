'use client';

import { useState, useEffect, useCallback } from 'react';
import { Play, RefreshCw, ChevronDown, CheckCircle2, XCircle, Loader2, Clock, Calendar, Layers } from 'lucide-react';
import { getFromEngine, postToEngine } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';
import { useToast } from '@/lib/toast-context';
import ScanRunDetailModal from '@/components/domain/ScanRunDetailModal';

// ── Status helpers ────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  completed: { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',  icon: CheckCircle2, label: 'Completed' },
  running:   { color: '#3b82f6', bg: 'rgba(59,130,246,0.1)', icon: Loader2,       label: 'Running',   spin: true },
  pending:   { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)',icon: Clock,         label: 'Pending' },
  failed:    { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  icon: XCircle,       label: 'Failed' },
  cancelled: { color: '#f97316', bg: 'rgba(249,115,22,0.1)', icon: XCircle,       label: 'Cancelled' },
};

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

function EngineBar({ enginesRequested = [], enginesCompleted = [], engineStatuses = {} }) {
  if (!enginesRequested.length) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {enginesRequested.map(eng => {
        const done    = enginesCompleted.includes(eng);
        const status  = engineStatuses?.[eng]?.status || (done ? 'completed' : 'pending');
        const color   = status === 'completed' ? '#22c55e' : status === 'failed' ? '#ef4444' : status === 'running' ? '#3b82f6' : '#64748b';
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
  const { customerId, activeTenant } = useTenant();
  const [accountId, setAccountId] = useState('');
  const [scheduleId, setScheduleId] = useState('');
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState(null);

  const filteredSchedules = schedules.filter(s => !accountId || s.account_id === accountId);

  async function handleRun() {
    if (!scheduleId) { setError('Select a schedule to run'); return; }
    setLaunching(true);
    setError(null);
    try {
      const result = await postToEngine('onboarding', `/api/v1/schedules/${scheduleId}/run-now`, {});
      if (result.error) throw new Error(result.error);
      onLaunched(result.scan_run_id);
      onClose();
    } catch (e) {
      setError(e.message || 'Failed to trigger scan');
    } finally {
      setLaunching(false);
    }
  }

  const inputStyle = { backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50">
      <div className="rounded-xl w-full max-w-md shadow-2xl" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Run Scan Now</h2>
          <button onClick={onClose} className="text-xs px-2 py-1 rounded hover:opacity-70" style={{ color: 'var(--text-muted)' }}>✕</button>
        </div>
        <div className="px-5 py-4 space-y-4">
          {/* Account filter */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Filter by Account (optional)</label>
            <div className="relative">
              <select value={accountId} onChange={e => { setAccountId(e.target.value); setScheduleId(''); }}
                className="w-full px-3 py-2 rounded-lg text-sm outline-none appearance-none" style={inputStyle}>
                <option value="">All accounts</option>
                {accounts.map(a => <option key={a.account_id} value={a.account_id}>{a.account_name} ({a.provider})</option>)}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
            </div>
          </div>

          {/* Schedule */}
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
        <div className="flex justify-end gap-2 px-5 py-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>Cancel</button>
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

export default function ScansPage() {
  const { customerId, activeTenant } = useTenant();
  const toast = useToast();

  const [runs, setRuns]         = useState([]);
  const [accounts, setAccounts] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [showRunModal, setShowRunModal] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState(null);

  const tenantId = activeTenant?.tenant_id;

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (tenantId)   params.set('tenant_id',   tenantId);
      if (customerId) params.set('customer_id',  customerId);
      if (statusFilter) params.set('status', statusFilter);

      const [runsData, accsData, schedsData] = await Promise.all([
        getFromEngine('onboarding', `/api/v1/scan-runs?${params}`),
        getFromEngine('onboarding', `/api/v1/cloud-accounts?limit=200${tenantId ? `&tenant_id=${tenantId}` : ''}`),
        getFromEngine('onboarding', `/api/v1/schedules?limit=200${tenantId ? `&tenant_id=${tenantId}` : ''}`),
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

  // Poll every 8s to refresh running scans
  useEffect(() => {
    const hasRunning = runs.some(r => r.overall_status === 'running' || r.overall_status === 'pending');
    if (!hasRunning) return;
    const t = setInterval(() => load(true), POLL_INTERVAL_MS);
    return () => clearInterval(t);
  }, [runs, load]);

  function handleLaunched(scanRunId) {
    toast?.success?.(`Scan triggered — ID: ${scanRunId.slice(0, 8)}…`);
    setTimeout(() => load(), 1500);
  }

  // Summary stats
  const stats = {
    total:     runs.length,
    running:   runs.filter(r => r.overall_status === 'running').length,
    completed: runs.filter(r => r.overall_status === 'completed').length,
    failed:    runs.filter(r => r.overall_status === 'failed').length,
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Scan Runs</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Scheduled and manual scan history — pipeline-level tracking
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => load()} className="p-2 rounded-lg hover:opacity-70" style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }} title="Refresh">
            <RefreshCw className="w-4 h-4" />
          </button>
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
          { label: 'Total',     value: stats.total,     color: 'var(--text-secondary)' },
          { label: 'Running',   value: stats.running,   color: '#3b82f6' },
          { label: 'Completed', value: stats.completed, color: '#22c55e' },
          { label: 'Failed',    value: stats.failed,    color: '#ef4444' },
        ].map(s => (
          <button key={s.label}
            onClick={() => setStatusFilter(s.label === 'Total' ? '' : s.label.toLowerCase())}
            className="rounded-lg p-3 text-left transition-all hover:opacity-80"
            style={{
              backgroundColor: 'var(--bg-card)',
              border: `1px solid ${statusFilter === s.label.toLowerCase() ? s.color : 'var(--border-primary)'}`,
            }}>
            <div className="text-xl font-bold" style={{ color: s.color }}>{s.value}</div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{s.label}</div>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Status:</span>
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

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-primary)', backgroundColor: 'var(--bg-card)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              {['Scan Run ID', 'Account', 'Provider', 'Trigger', 'Status', 'Engines', 'Duration', 'Started'].map(h => (
                <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} className="px-4 py-8 text-center">
                <Loader2 className="w-5 h-5 animate-spin mx-auto" style={{ color: 'var(--text-muted)' }} />
              </td></tr>
            ) : runs.length === 0 ? (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                No scan runs found. Click <strong>Run Now</strong> to trigger your first scan.
              </td></tr>
            ) : runs.map(run => (
              <tr key={run.scan_run_id}
                onClick={() => setSelectedRunId(run.scan_run_id)}
                className="cursor-pointer hover:opacity-80 transition-opacity"
                style={{ borderBottom: '1px solid var(--border-primary)' }}>
                <td className="px-4 py-3">
                  <span className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {run.scan_run_id?.slice(0, 8)}…
                  </span>
                </td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
                  {run.account_name || run.account_id?.slice(0, 8) || '—'}
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-medium px-1.5 py-0.5 rounded"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                    {run.provider?.toUpperCase() || '—'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs px-1.5 py-0.5 rounded"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                    {run.trigger_type || 'manual'}
                  </span>
                </td>
                <td className="px-4 py-3"><StatusBadge status={run.overall_status} /></td>
                <td className="px-4 py-3">
                  <EngineBar
                    enginesRequested={run.engines_requested || []}
                    enginesCompleted={run.engines_completed || []}
                    engineStatuses={run.engine_statuses || {}}
                  />
                </td>
                <td className="px-4 py-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                  {fmtDuration(run.started_at, run.completed_at)}
                </td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                  {fmtRelative(run.started_at)}
                </td>
              </tr>
            ))}
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
