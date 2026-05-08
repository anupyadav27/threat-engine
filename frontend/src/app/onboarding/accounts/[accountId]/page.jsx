'use client';
/**
 * Account Detail Page — /onboarding/accounts/[accountId]
 *
 * Tabs:
 *   Overview     — identity, status, credential summary
 *   Schedule     — active schedule + edit inline
 *   Scan History — recent scan_runs for this account
 *   Credentials  — re-validate, credential type/ref
 *   Log Sources  — CIEM log source config (CloudTrail, VPC Flow, etc.)
 */

import { useState, useEffect, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, RefreshCw, Play, Loader2, CheckCircle2, XCircle,
  Clock, Calendar, Shield, Key, Layers, Radio, AlertTriangle,
  Edit2, Save, X, ChevronDown, Plus, Trash2,
} from 'lucide-react';
import { getFromEngine, postToEngine } from '@/lib/api';
import ScanRunDetailModal from '@/components/domain/ScanRunDetailModal';

// ── Helpers ───────────────────────────────────────────────────────────────────

const PROVIDER_COLORS = {
  aws: '#FF9900', azure: '#0078D4', gcp: '#4285F4',
  oci: '#F80000', alicloud: '#FF6A00', ibm: '#1F70C1', k8s: '#326CE5',
};

function Badge({ label, color, bg }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
      style={{ color, backgroundColor: bg || `${color}18` }}>
      {label}
    </span>
  );
}

function statusColor(s) {
  return s === 'valid' || s === 'active' || s === 'completed' ? '#22c55e'
       : s === 'invalid' || s === 'failed' || s === 'deleted'  ? '#ef4444'
       : s === 'running' || s === 'pending'                     ? '#3b82f6'
       : '#94a3b8';
}

function fmtDate(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

function fmtRelative(ts) {
  if (!ts) return 'Never';
  const m = Math.floor((Date.now() - new Date(ts)) / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(ts).toLocaleDateString();
}

function Row({ label, value, mono = false, children }) {
  return (
    <div className="flex items-start justify-between py-2.5 border-b last:border-b-0"
      style={{ borderColor: 'var(--border-primary)' }}>
      <span className="text-xs w-36 flex-shrink-0" style={{ color: 'var(--text-muted)' }}>{label}</span>
      {children || (
        <span className={`text-xs text-right ${mono ? 'font-mono' : ''}`} style={{ color: 'var(--text-secondary)' }}>
          {value ?? '—'}
        </span>
      )}
    </div>
  );
}

function Section({ title, icon: Icon, children }) {
  return (
    <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-primary)' }}>
      <div className="flex items-center gap-2 px-4 py-3 border-b"
        style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
        {Icon && <Icon className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />}
        <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{title}</span>
      </div>
      <div className="px-4 divide-y" style={{ divideColor: 'var(--border-primary)', backgroundColor: 'var(--bg-card)' }}>
        {children}
      </div>
    </div>
  );
}

// ── Tab: Overview ─────────────────────────────────────────────────────────────

function TabOverview({ account }) {
  const provColor = PROVIDER_COLORS[account.provider] || '#6366f1';
  return (
    <div className="grid grid-cols-2 gap-4">
      <Section title="Account Identity" icon={Shield}>
        <Row label="Account Name"  value={account.account_name} />
        <Row label="Account ID"    value={account.account_id}   mono />
        <Row label="Account #"     value={account.account_number || 'Not detected'} mono />
        <Row label="Tenant"        value={account.tenant_name || account.tenant_id} />
        <Row label="Customer"      value={account.customer_id} mono />
        <Row label="Provider">
          <Badge label={account.provider?.toUpperCase()} color={provColor} />
        </Row>
        <Row label="Hierarchy"     value={account.account_hierarchy_name} />
      </Section>

      <Section title="Status" icon={Radio}>
        <Row label="Account Status">
          <Badge label={account.account_status} color={statusColor(account.account_status)} />
        </Row>
        <Row label="Onboarding">
          <Badge label={account.account_onboarding_status} color={statusColor(account.account_onboarding_status)} />
        </Row>
        <Row label="Credential">
          <Badge label={account.credential_validation_status} color={statusColor(account.credential_validation_status)} />
        </Row>
        <Row label="Validated At"  value={fmtDate(account.credential_validated_at)} />
        <Row label="Last Scan"     value={fmtRelative(account.last_scan_at)} />
        <Row label="Created"       value={fmtDate(account.created_at)} />
        <Row label="Updated"       value={fmtDate(account.updated_at)} />
      </Section>

      {account.credential_validation_message && (
        <div className="col-span-2 px-4 py-3 rounded-lg text-xs"
          style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)', color: 'var(--text-muted)' }}>
          <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>Validation message: </span>
          {account.credential_validation_message}
        </div>
      )}
    </div>
  );
}

// ── Tab: Schedule ─────────────────────────────────────────────────────────────

const CRON_PRESETS = [
  { key: 'hourly',    label: 'Every Hour',         cron: '0 * * * *'   },
  { key: 'daily',     label: 'Daily (2 AM UTC)',    cron: '0 2 * * *'   },
  { key: 'weekly',    label: 'Weekly (Sun 2 AM)',   cron: '0 2 * * 0'   },
  { key: 'bi_weekly', label: 'Every 2 Weeks',       cron: '0 2 * * 1/2' },
  { key: 'monthly',   label: 'Monthly (1st 2 AM)',  cron: '0 2 1 * *'   },
];
const ALL_ENGINES = ['discovery','check','inventory','threat','compliance','iam','datasec'];

function TabSchedule({ account }) {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [editing, setEditing]     = useState(null);   // schedule being edited
  const [saving, setSaving]       = useState(false);
  const [runningId, setRunningId] = useState(null);
  const [selectedRunId, setSelectedRunId] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    const d = await getFromEngine('onboarding', `/api/v1/schedules?account_id=${account.account_id}`);
    setSchedules(d?.schedules || []);
    setLoading(false);
  }, [account.account_id]);

  useEffect(() => { load(); }, [load]);

  async function handleToggle(sched) {
    const endpoint = sched.enabled ? 'disable' : 'enable';
    await postToEngine('onboarding', `/api/v1/schedules/${sched.schedule_id}/${endpoint}`, {});
    load();
  }

  async function handleRunNow(sched) {
    setRunningId(sched.schedule_id);
    try {
      const r = await postToEngine('onboarding', `/api/v1/schedules/${sched.schedule_id}/run-now`, {});
      if (r.scan_run_id) setSelectedRunId(r.scan_run_id);
    } finally {
      setRunningId(null);
    }
  }

  async function handleSave() {
    setSaving(true);
    try {
      const cron = CRON_PRESETS.find(p => p.key === editing._preset)?.cron || editing.cron_expression;
      await postToEngine('onboarding', `/api/v1/schedules/${editing.schedule_id}`, {
        ...editing, cron_expression: cron,
      }, 'PATCH');
      setEditing(null);
      load();
    } finally {
      setSaving(false);
    }
  }

  const inputStyle = { backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' };

  if (loading) return <div className="py-8 flex justify-center"><Loader2 className="w-5 h-5 animate-spin" style={{ color: 'var(--text-muted)' }} /></div>;

  return (
    <div className="space-y-4">
      {schedules.length === 0 && (
        <div className="py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
          No schedules configured. Add a schedule in the onboarding wizard.
        </div>
      )}

      {schedules.map(sched => (
        <div key={sched.schedule_id} className="rounded-xl overflow-hidden"
          style={{ border: `1px solid ${editing?.schedule_id === sched.schedule_id ? 'var(--accent-primary)' : 'var(--border-primary)'}` }}>

          {/* Schedule header */}
          <div className="flex items-center justify-between px-4 py-3 border-b"
            style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
            <div className="flex items-center gap-2">
              <Calendar className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
              <code className="text-xs font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>
                {sched.cron_expression}
              </code>
              <Badge label={sched.enabled ? 'Enabled' : 'Disabled'}
                color={sched.enabled ? '#22c55e' : '#94a3b8'} />
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => handleRunNow(sched)} disabled={!!runningId}
                className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium"
                style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: 'var(--accent-primary)', border: '1px solid rgba(59,130,246,0.25)' }}>
                {runningId === sched.schedule_id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                Run Now
              </button>
              <button onClick={() => handleToggle(sched)}
                className="px-2.5 py-1 rounded text-xs"
                style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                {sched.enabled ? 'Disable' : 'Enable'}
              </button>
              <button onClick={() => setEditing(editing?.schedule_id === sched.schedule_id ? null : { ...sched, _preset: CRON_PRESETS.find(p => p.cron === sched.cron_expression)?.key || 'custom' })}
                className="p-1.5 rounded hover:opacity-70"
                style={{ color: 'var(--text-muted)', border: '1px solid var(--border-primary)' }}>
                <Edit2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Schedule details */}
          {editing?.schedule_id !== sched.schedule_id ? (
            <div className="px-4 divide-y" style={{ divideColor: 'var(--border-primary)' }}>
              <Row label="Next Run"     value={fmtDate(sched.next_run_at)} />
              <Row label="Last Run"     value={fmtDate(sched.last_run_at)} />
              <Row label="Timezone"     value={sched.timezone} />
              <Row label="Run Count"    value={`${sched.run_count} total (${sched.success_count} ✓, ${sched.failure_count} ✗)`} />
              <Row label="Engines">
                <div className="flex flex-wrap gap-1 justify-end">
                  {(sched.engines_requested || []).map(e => (
                    <span key={e} className="px-1.5 py-0.5 rounded text-[10px] font-mono"
                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)', border: '1px solid var(--border-primary)' }}>
                      {e}
                    </span>
                  ))}
                </div>
              </Row>
              <Row label="Notify on Failure" value={sched.notify_on_failure ? 'Yes' : 'No'} />
              <Row label="Notify on Success" value={sched.notify_on_success ? 'Yes' : 'No'} />
            </div>
          ) : (
            /* Edit form */
            <div className="px-4 py-4 space-y-4">
              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>Frequency</label>
                <div className="grid grid-cols-3 gap-2">
                  {[...CRON_PRESETS, { key: 'custom', label: 'Custom…', cron: '' }].map(p => (
                    <button key={p.key} onClick={() => setEditing(e => ({ ...e, _preset: p.key, cron_expression: p.cron || e.cron_expression }))}
                      className="px-2 py-1.5 rounded text-xs text-center transition-all"
                      style={{
                        border: `1px solid ${editing._preset === p.key ? 'var(--accent-primary)' : 'var(--border-primary)'}`,
                        backgroundColor: editing._preset === p.key ? 'rgba(59,130,246,0.08)' : 'var(--bg-tertiary)',
                        color: editing._preset === p.key ? 'var(--accent-primary)' : 'var(--text-secondary)',
                      }}>
                      {p.label}
                    </button>
                  ))}
                </div>
                {editing._preset === 'custom' && (
                  <input type="text" value={editing.cron_expression}
                    onChange={e => setEditing(s => ({ ...s, cron_expression: e.target.value }))}
                    placeholder="0 2 * * 0" className="mt-2 w-full px-3 py-2 rounded-lg text-xs font-mono outline-none" style={inputStyle} />
                )}
              </div>

              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>Engines</label>
                <div className="flex flex-wrap gap-1.5">
                  {ALL_ENGINES.map(eng => {
                    const on = (editing.engines_requested || []).includes(eng);
                    return (
                      <button key={eng} onClick={() => setEditing(s => ({
                        ...s,
                        engines_requested: on ? s.engines_requested.filter(e => e !== eng) : [...(s.engines_requested || []), eng]
                      }))}
                        className="px-2 py-1 rounded text-xs font-mono transition-all"
                        style={{
                          border: `1px solid ${on ? 'rgba(59,130,246,0.4)' : 'var(--border-primary)'}`,
                          backgroundColor: on ? 'rgba(59,130,246,0.08)' : 'var(--bg-tertiary)',
                          color: on ? 'var(--accent-primary)' : 'var(--text-muted)',
                        }}>
                        {eng}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={editing.notify_on_failure}
                    onChange={e => setEditing(s => ({ ...s, notify_on_failure: e.target.checked }))} />
                  <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Notify on failure</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={editing.notify_on_success}
                    onChange={e => setEditing(s => ({ ...s, notify_on_success: e.target.checked }))} />
                  <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Notify on success</span>
                </label>
              </div>

              <div className="flex gap-2 justify-end pt-1">
                <button onClick={() => setEditing(null)} className="px-3 py-1.5 rounded text-xs"
                  style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                  Cancel
                </button>
                <button onClick={handleSave} disabled={saving}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium text-white disabled:opacity-50"
                  style={{ backgroundColor: 'var(--accent-primary)' }}>
                  {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                  Save
                </button>
              </div>
            </div>
          )}
        </div>
      ))}

      {selectedRunId && <ScanRunDetailModal scanRunId={selectedRunId} onClose={() => setSelectedRunId(null)} />}
    </div>
  );
}

// ── Tab: Scan History ─────────────────────────────────────────────────────────

const STATUS_CFG = {
  completed: { color: '#22c55e', icon: CheckCircle2 },
  running:   { color: '#3b82f6', icon: Loader2, spin: true },
  pending:   { color: '#94a3b8', icon: Clock },
  failed:    { color: '#ef4444', icon: XCircle },
};

function TabScanHistory({ account }) {
  const [runs, setRuns]       = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    getFromEngine('onboarding', `/api/v1/scan-runs?account_id=${account.account_id}&limit=20`)
      .then(d => setRuns(d?.scan_runs || []))
      .finally(() => setLoading(false));
  }, [account.account_id]);

  if (loading) return <div className="py-8 flex justify-center"><Loader2 className="w-5 h-5 animate-spin" style={{ color: 'var(--text-muted)' }} /></div>;
  if (!runs.length) return <div className="py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No scan runs yet.</div>;

  return (
    <>
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-primary)' }}>
        <table className="w-full text-xs">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              {['Scan Run', 'Trigger', 'Status', 'Engines Done', 'Duration', 'Started'].map(h => (
                <th key={h} className="px-4 py-2.5 text-left font-semibold" style={{ color: 'var(--text-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {runs.map(run => {
              const cfg = STATUS_CFG[run.overall_status] || STATUS_CFG.pending;
              const Icon = cfg.icon;
              const done = (run.engines_completed || []).length;
              const total = (run.engines_requested || []).length;
              const sec = run.started_at && run.completed_at
                ? Math.floor((new Date(run.completed_at) - new Date(run.started_at)) / 1000) : null;
              const dur = sec == null ? '—' : sec < 60 ? `${sec}s` : `${Math.floor(sec/60)}m ${sec%60}s`;
              return (
                <tr key={run.scan_run_id} onClick={() => setSelected(run.scan_run_id)}
                  className="cursor-pointer hover:opacity-80" style={{ borderBottom: '1px solid var(--border-primary)' }}>
                  <td className="px-4 py-2.5 font-mono" style={{ color: 'var(--text-muted)' }}>
                    {run.scan_run_id?.slice(0, 8)}…
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--text-muted)' }}>{run.trigger_type || 'manual'}</td>
                  <td className="px-4 py-2.5">
                    <span className="flex items-center gap-1" style={{ color: cfg.color }}>
                      <Icon className={`w-3.5 h-3.5 ${cfg.spin ? 'animate-spin' : ''}`} />
                      {run.overall_status}
                    </span>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--text-secondary)' }}>{done}/{total}</td>
                  <td className="px-4 py-2.5 font-mono" style={{ color: 'var(--text-muted)' }}>{dur}</td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--text-muted)' }}>{fmtRelative(run.started_at)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {selected && <ScanRunDetailModal scanRunId={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

// ── Tab: Credentials ──────────────────────────────────────────────────────────

function TabCredentials({ account, onRefresh }) {
  const [validating, setValidating] = useState(false);
  const [result, setResult]         = useState(null);

  async function handleRevalidate() {
    setValidating(true);
    setResult(null);
    try {
      const r = await postToEngine('onboarding', `/api/v1/cloud-accounts/${account.account_id}/validate-credentials`, {});
      setResult(r);
      onRefresh();
    } finally {
      setValidating(false);
    }
  }

  return (
    <div className="space-y-4">
      <Section title="Credential Configuration" icon={Key}>
        <Row label="Type"         value={account.credential_type} />
        <Row label="Secret Ref"   value={account.credential_ref} mono />
        <Row label="Status">
          <Badge label={account.credential_validation_status}
            color={statusColor(account.credential_validation_status)} />
        </Row>
        <Row label="Validated At" value={fmtDate(account.credential_validated_at)} />
        {account.credential_validation_message && (
          <Row label="Message" value={account.credential_validation_message} />
        )}
      </Section>

      <div className="flex items-center justify-between px-1">
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Re-validates credentials stored in AWS Secrets Manager against the live cloud provider.
        </p>
        <button onClick={handleRevalidate} disabled={validating}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
          style={{ backgroundColor: 'var(--accent-primary)' }}>
          {validating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
          {validating ? 'Validating…' : 'Re-validate'}
        </button>
      </div>

      {result && (
        <div className="px-4 py-3 rounded-lg text-sm"
          style={{
            backgroundColor: result.success ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
            border: `1px solid ${result.success ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`,
            color: result.success ? '#4ade80' : '#f87171',
          }}>
          {result.success ? '✅ ' : '❌ '}{result.message}
          {result.account_number && (
            <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              Account #: <code>{result.account_number}</code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Tab: Log Sources ──────────────────────────────────────────────────────────

const LOG_TYPES = [
  { key: 'cloudtrail',  label: 'CloudTrail',    desc: 'API activity logs' },
  { key: 'vpc_flow',    label: 'VPC Flow',       desc: 'Network traffic logs' },
  { key: 'alb',         label: 'ALB Access',     desc: 'Load balancer access logs' },
  { key: 'waf',         label: 'WAF',            desc: 'Web application firewall logs' },
  { key: 's3_access',   label: 'S3 Access',      desc: 'S3 bucket access logs' },
  { key: 'dns',         label: 'Route53 DNS',    desc: 'DNS query logs' },
  { key: 'cloudfront',  label: 'CloudFront',     desc: 'CDN access logs' },
  { key: 'rds_audit',   label: 'RDS Audit',      desc: 'Database audit logs' },
];

function TabLogSources({ account, onRefresh }) {
  const [sources, setSources]   = useState(account.log_sources || {});
  const [saving, setSaving]     = useState(false);
  const [saved, setSaved]       = useState(false);

  function addEntry(type) {
    setSources(s => ({ ...s, [type]: [...(s[type] || []), { bucket: '', prefix: '' }] }));
  }

  function removeEntry(type, idx) {
    setSources(s => {
      const arr = [...(s[type] || [])];
      arr.splice(idx, 1);
      const next = { ...s };
      if (arr.length) next[type] = arr; else delete next[type];
      return next;
    });
  }

  function updateEntry(type, idx, field, val) {
    setSources(s => {
      const arr = [...(s[type] || [])];
      arr[idx] = { ...arr[idx], [field]: val };
      return { ...s, [type]: arr };
    });
  }

  async function handleSave() {
    setSaving(true);
    try {
      await postToEngine('onboarding', `/api/v1/cloud-accounts/${account.account_id}/log-sources`, sources, 'PUT');
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      onRefresh();
    } finally {
      setSaving(false);
    }
  }

  const inputStyle = { backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)', color: 'var(--text-primary)' };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Configure S3 bucket locations for CIEM log collection.
          Leave empty to use auto-discovery mode.
        </p>
        <button onClick={handleSave} disabled={saving}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
          style={{ backgroundColor: saved ? '#22c55e' : 'var(--accent-primary)' }}>
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          {saving ? 'Saving…' : saved ? 'Saved ✓' : 'Save'}
        </button>
      </div>

      {LOG_TYPES.map(lt => (
        <div key={lt.key} className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border-primary)' }}>
          <div className="flex items-center justify-between px-4 py-2.5 border-b"
            style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
            <div>
              <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{lt.label}</span>
              <span className="ml-2 text-xs" style={{ color: 'var(--text-muted)' }}>{lt.desc}</span>
            </div>
            <button onClick={() => addEntry(lt.key)}
              className="flex items-center gap-1 px-2 py-1 rounded text-xs"
              style={{ color: 'var(--accent-primary)', border: '1px solid rgba(59,130,246,0.3)' }}>
              <Plus className="w-3 h-3" /> Add
            </button>
          </div>
          <div className="px-4 py-2 space-y-2" style={{ backgroundColor: 'var(--bg-card)' }}>
            {(sources[lt.key] || []).length === 0 ? (
              <p className="text-xs py-1.5" style={{ color: 'var(--text-muted)' }}>
                Auto-discovery — no manual source configured
              </p>
            ) : (sources[lt.key] || []).map((entry, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <input type="text" value={entry.bucket} onChange={e => updateEntry(lt.key, idx, 'bucket', e.target.value)}
                  placeholder="s3-bucket-name"
                  className="flex-1 px-2 py-1.5 rounded text-xs outline-none" style={inputStyle} />
                <input type="text" value={entry.prefix || ''} onChange={e => updateEntry(lt.key, idx, 'prefix', e.target.value)}
                  placeholder="prefix/ (optional)"
                  className="w-36 px-2 py-1.5 rounded text-xs outline-none" style={inputStyle} />
                <button onClick={() => removeEntry(lt.key, idx)} className="p-1 rounded hover:opacity-70" style={{ color: '#ef4444' }}>
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Page shell ────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'overview',     label: 'Overview',     icon: Shield },
  { id: 'schedule',     label: 'Schedule',     icon: Calendar },
  { id: 'scan-history', label: 'Scan History', icon: Clock },
  { id: 'credentials',  label: 'Credentials',  icon: Key },
  { id: 'log-sources',  label: 'Log Sources',  icon: Layers },
];

export default function AccountDetailPage() {
  const { accountId } = useParams();
  const router        = useRouter();

  const [account, setAccount] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  const loadAccount = useCallback(async () => {
    try {
      const data = await getFromEngine('onboarding', `/api/v1/cloud-accounts/${accountId}`);
      setAccount(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [accountId]);

  useEffect(() => { loadAccount(); }, [loadAccount]);

  if (loading) return (
    <div className="flex items-center justify-center py-20">
      <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-muted)' }} />
    </div>
  );

  if (!account) return (
    <div className="flex flex-col items-center py-20 gap-3">
      <AlertTriangle className="w-8 h-8 text-red-400" />
      <p style={{ color: 'var(--text-secondary)' }}>Account not found</p>
      <button onClick={() => router.push('/onboarding')} className="text-sm" style={{ color: 'var(--accent-primary)' }}>
        ← Back to accounts
      </button>
    </div>
  );

  const provColor = PROVIDER_COLORS[account.provider] || '#6366f1';

  return (
    <div className="space-y-5">
      {/* Breadcrumb + header */}
      <div className="flex items-start justify-between">
        <div>
          <button onClick={() => router.push('/onboarding')}
            className="flex items-center gap-1.5 text-xs mb-2 hover:opacity-70"
            style={{ color: 'var(--text-muted)' }}>
            <ArrowLeft className="w-3.5 h-3.5" /> Cloud Accounts
          </button>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center font-bold text-xs"
              style={{ backgroundColor: `${provColor}20`, color: provColor, border: `1px solid ${provColor}40` }}>
              {account.provider?.toUpperCase().slice(0, 2)}
            </div>
            <div>
              <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
                {account.account_name}
              </h1>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                {account.account_number || account.account_id}
                {account.tenant_name && <span> · {account.tenant_name}</span>}
              </p>
            </div>
          </div>
        </div>
        <button onClick={loadAccount} className="p-2 rounded-lg hover:opacity-70"
          style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Status strip */}
      <div className="flex items-center gap-3 flex-wrap">
        {[
          { label: 'Account',     value: account.account_status },
          { label: 'Onboarding',  value: account.account_onboarding_status },
          { label: 'Credentials', value: account.credential_validation_status },
        ].map(({ label, value }) => (
          <div key={label} className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
            <span>{label}:</span>
            <Badge label={value || '—'} color={statusColor(value)} />
          </div>
        ))}
        {account.last_scan_at && (
          <div className="text-xs ml-auto" style={{ color: 'var(--text-muted)' }}>
            Last scan: <span style={{ color: 'var(--text-secondary)' }}>{fmtRelative(account.last_scan_at)}</span>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b" style={{ borderColor: 'var(--border-primary)' }}>
        {TABS.map(t => {
          const Icon = t.icon;
          const active = activeTab === t.id;
          return (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium transition-colors border-b-2 -mb-px"
              style={{
                borderColor: active ? 'var(--accent-primary)' : 'transparent',
                color: active ? 'var(--accent-primary)' : 'var(--text-muted)',
              }}>
              <Icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'overview'     && <TabOverview    account={account} />}
        {activeTab === 'schedule'     && <TabSchedule    account={account} />}
        {activeTab === 'scan-history' && <TabScanHistory account={account} />}
        {activeTab === 'credentials'  && <TabCredentials account={account} onRefresh={loadAccount} />}
        {activeTab === 'log-sources'  && <TabLogSources  account={account} onRefresh={loadAccount} />}
      </div>
    </div>
  );
}
