'use client';
/**
 * ScanRunDetailModal — shows full pipeline status for a single scan run.
 *
 * Polls GET /api/v1/scan-runs/{id}/status every 5s while status is running/pending.
 * Click any row to close.
 */

import { useEffect, useState, useCallback } from 'react';
import { X, CheckCircle2, XCircle, Loader2, Clock, AlertTriangle, ChevronRight } from 'lucide-react';
import { getFromEngine } from '@/lib/api';

const ENGINE_META = {
  discovery:  { icon: '🔍', desc: 'Enumerate cloud resources' },
  check:      { icon: '✅', desc: 'Evaluate compliance rules' },
  inventory:  { icon: '📦', desc: 'Normalize + track assets' },
  threat:     { icon: '⚡', desc: 'MITRE ATT&CK mapping' },
  compliance: { icon: '📋', desc: 'Framework reports' },
  iam:        { icon: '🔐', desc: 'IAM posture analysis' },
  datasec:    { icon: '🗄️',  desc: 'Data classification' },
};

const PIPELINE_ORDER = ['discovery', 'check', 'inventory', 'threat', 'compliance', 'iam', 'datasec'];

function engineStatus(eng, run) {
  if (!run) return 'pending';
  const s = run.engine_statuses?.[eng]?.status;
  if (s) return s;
  if ((run.engines_completed || []).includes(eng)) return 'completed';
  if (run.overall_status === 'running') {
    // heuristic: first engine that isn't completed is likely running
    const req = run.engines_requested || [];
    const done = run.engines_completed || [];
    const firstPending = req.find(e => !done.includes(e));
    if (firstPending === eng) return 'running';
  }
  return 'pending';
}

function EngineRow({ name, run }) {
  const status   = engineStatus(name, run);
  const meta     = ENGINE_META[name] || { icon: '⚙️', desc: '' };
  const details  = run?.engine_statuses?.[name] || {};

  const iconEl = status === 'completed'
    ? <CheckCircle2 className="w-5 h-5 text-green-400" />
    : status === 'failed'
    ? <XCircle className="w-5 h-5 text-red-400" />
    : status === 'running'
    ? <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
    : <div className="w-5 h-5 rounded-full" style={{ border: '2px solid var(--border-primary)' }} />;

  const color = status === 'completed' ? '#22c55e' :
                status === 'failed'    ? '#ef4444' :
                status === 'running'   ? '#3b82f6' : 'var(--text-muted)';

  return (
    <div className="flex items-center gap-3 px-4 py-3 border-b last:border-b-0"
      style={{ borderColor: 'var(--border-primary)' }}>
      {/* Status icon */}
      <div className="flex-shrink-0">{iconEl}</div>

      {/* Engine name + desc */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <span>{meta.icon}</span>
          <span className="text-sm font-medium capitalize" style={{ color: 'var(--text-primary)' }}>{name}</span>
        </div>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{meta.desc}</p>
      </div>

      {/* Status + metrics */}
      <div className="text-right flex-shrink-0">
        <span className="text-xs font-medium capitalize" style={{ color }}>{status}</span>
        {details.findings != null && (
          <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {details.findings.toLocaleString()} findings
          </div>
        )}
        {details.duration_seconds != null && (
          <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            {details.duration_seconds}s
          </div>
        )}
        {details.error && (
          <div className="text-[10px] text-red-400 max-w-32 truncate" title={details.error}>{details.error}</div>
        )}
      </div>
    </div>
  );
}

function fmtDuration(started, completed) {
  if (!started) return null;
  const end = completed ? new Date(completed) : new Date();
  const sec = Math.floor((end - new Date(started)) / 1000);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60), s = sec % 60;
  return m < 60 ? `${m}m ${s}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

const OVERALL_STYLE = {
  completed: { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',  label: 'Completed' },
  running:   { color: '#3b82f6', bg: 'rgba(59,130,246,0.1)', label: 'Running' },
  pending:   { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)',label: 'Pending' },
  failed:    { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  label: 'Failed' },
};

export default function ScanRunDetailModal({ scanRunId, onClose }) {
  const [run, setRun]         = useState(null);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async (silent = false) => {
    if (!scanRunId) return;
    if (!silent) setLoading(true);
    try {
      const data = await getFromEngine('onboarding', `/api/v1/scan-runs/${scanRunId}`);
      setRun(data);
    } catch (e) {
      console.error('scan run fetch error:', e);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [scanRunId]);

  useEffect(() => { fetch(); }, [fetch]);

  // Poll while running
  useEffect(() => {
    if (!run) return;
    if (run.overall_status !== 'running' && run.overall_status !== 'pending') return;
    const t = setInterval(() => fetch(true), 5000);
    return () => clearInterval(t);
  }, [run, fetch]);

  const overallStyle = OVERALL_STYLE[run?.overall_status] || OVERALL_STYLE.pending;
  const enginesInOrder = run
    ? [...PIPELINE_ORDER.filter(e => (run.engines_requested || []).includes(e)),
       ...(run.engines_requested || []).filter(e => !PIPELINE_ORDER.includes(e))]
    : [];

  const duration = fmtDuration(run?.started_at, run?.completed_at);
  const started  = run?.started_at ? new Date(run.started_at).toLocaleString() : '—';

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="rounded-xl w-full max-w-xl shadow-2xl flex flex-col max-h-[88vh]"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}
        onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-start justify-between px-5 py-4 border-b"
          style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Scan Run</span>
              {run?.overall_status && (
                <span className="text-xs px-2 py-0.5 rounded font-medium"
                  style={{ backgroundColor: overallStyle.bg, color: overallStyle.color }}>
                  {overallStyle.label}
                  {run.overall_status === 'running' && <Loader2 className="inline w-3 h-3 animate-spin ml-1" />}
                </span>
              )}
            </div>
            <code className="text-[11px] font-mono mt-0.5 block" style={{ color: 'var(--text-muted)' }}>{scanRunId}</code>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/10">
            <X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          </button>
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-muted)' }} />
          </div>
        ) : !run ? (
          <div className="flex-1 flex items-center justify-center py-12 text-sm" style={{ color: 'var(--text-muted)' }}>
            Scan run not found
          </div>
        ) : (
          <>
            {/* Metadata */}
            <div className="grid grid-cols-2 gap-px bg-border" style={{ backgroundColor: 'var(--border-primary)' }}>
              {[
                { label: 'Account',   value: run.account_name || run.account_id?.slice(0,8) || '—' },
                { label: 'Provider',  value: run.provider?.toUpperCase() || '—' },
                { label: 'Trigger',   value: run.trigger_type || 'manual' },
                { label: 'Scan Type', value: run.scan_type || 'full' },
                { label: 'Started',   value: started },
                { label: 'Duration',  value: duration || '—' },
              ].map(({ label, value }) => (
                <div key={label} className="px-4 py-2.5" style={{ backgroundColor: 'var(--bg-card)' }}>
                  <div className="text-[10px] font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</div>
                  <div className="text-xs mt-0.5 font-medium" style={{ color: 'var(--text-secondary)' }}>{value}</div>
                </div>
              ))}
            </div>

            {/* Engine pipeline */}
            <div className="flex-1 overflow-y-auto">
              <div className="px-4 py-2.5 border-b flex items-center gap-1.5"
                style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Pipeline</span>
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  {(run.engines_completed || []).length}/{(run.engines_requested || []).length} engines done
                </span>
              </div>
              {enginesInOrder.map((eng, i) => (
                <div key={eng} className="flex items-center">
                  {i > 0 && (
                    <div className="absolute ml-8 -mt-2 w-0.5 h-2 bg-border" style={{ backgroundColor: 'var(--border-primary)' }} />
                  )}
                  <EngineRow name={eng} run={run} />
                </div>
              ))}
              {enginesInOrder.length === 0 && (
                <div className="px-4 py-4 text-sm text-center" style={{ color: 'var(--text-muted)' }}>No engines configured</div>
              )}
            </div>

            {/* Error details */}
            {run.overall_status === 'failed' && run.error_details && Object.keys(run.error_details).length > 0 && (
              <div className="px-4 py-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                <div className="flex items-center gap-1.5 mb-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                  <span className="text-xs font-semibold text-red-400">Error Details</span>
                </div>
                <pre className="text-[10px] font-mono rounded p-2 overflow-x-auto"
                  style={{ backgroundColor: 'rgba(239,68,68,0.06)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>
                  {JSON.stringify(run.error_details, null, 2)}
                </pre>
              </div>
            )}

            {/* Results summary */}
            {run.overall_status === 'completed' && run.results_summary && Object.keys(run.results_summary).length > 0 && (
              <div className="px-4 py-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                <div className="text-xs font-semibold mb-2" style={{ color: 'var(--text-secondary)' }}>Results Summary</div>
                <div className="grid grid-cols-3 gap-2">
                  {Object.entries(run.results_summary).map(([k, v]) => (
                    <div key={k} className="rounded p-2 text-center" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                      <div className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>{typeof v === 'number' ? v.toLocaleString() : v}</div>
                      <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{k.replace(/_/g, ' ')}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Footer */}
            <div className="flex justify-end px-4 py-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm"
                style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                Close
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
