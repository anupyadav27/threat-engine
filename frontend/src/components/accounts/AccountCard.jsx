'use client';

import { useState } from 'react';
import { Play, Calendar, Clock, CheckCircle2, XCircle, AlertCircle, Loader2 } from 'lucide-react';
import { PROVIDER_COLORS } from '@/lib/catalog';
import ScheduleModal from '@/components/onboarding/ScheduleModal';

const STATUS_STYLES = {
  active:      { icon: CheckCircle2, color: '#22c55e', label: 'Active' },
  inactive:    { icon: AlertCircle,  color: '#f59e0b', label: 'Inactive' },
  error:       { icon: XCircle,      color: '#ef4444', label: 'Error' },
  validating:  { icon: Loader2,      color: '#60a5fa', label: 'Validating' },
  pending:     { icon: Clock,        color: '#94a3b8', label: 'Pending' },
};

const DORMANT_META = {
  vulnerability: { icon: '🔍', label: 'Vulnerability Scanner', desc: 'Agent-based CVE scanning & SBOM' },
  database:      { icon: '🗄️', label: 'Database Security',     desc: 'CIS benchmark checks for DB engines' },
  code_security: { icon: '🔒', label: 'Code Security',         desc: 'SAST / DAST / IaC scanning via Git' },
  middleware:    { icon: '⚙️', label: 'Middleware Monitor',    desc: 'Application middleware security' },
};

function isDormantAccount(account) {
  if (account.account_type === 'cloud_csp') return false;
  const cvs = account.credentialValidationStatus || account.credential_validation_status;
  return !cvs || cvs === 'pending' || cvs === 'not_configured';
}

// ── Dormant capability card ───────────────────────────────────────────────────

function DormantCard({ account, onConfigure }) {
  const meta = DORMANT_META[account.account_type] || { icon: '📦', label: account.account_type, desc: '' };

  return (
    <div
      className="rounded-xl border p-4 space-y-3 transition-shadow"
      style={{
        backgroundColor: 'var(--bg-card)',
        borderColor: 'rgba(148,163,184,0.2)',
        borderStyle: 'dashed',
        opacity: 0.82,
      }}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center text-base flex-shrink-0"
            style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)' }}
          >
            {meta.icon}
          </div>
          <div className="min-w-0">
            <div className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
              {account.accountName || account.account_name || meta.label}
            </div>
            <div className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>
              {meta.label}
            </div>
          </div>
        </div>
        <span
          className="text-[10px] px-2 py-0.5 rounded-full font-medium flex-shrink-0"
          style={{
            backgroundColor: 'rgba(148,163,184,0.1)',
            color: '#94a3b8',
            border: '1px solid rgba(148,163,184,0.2)',
          }}
        >
          Not Configured
        </span>
      </div>

      {/* Description */}
      <p className="text-xs leading-relaxed" style={{ color: 'var(--text-muted)' }}>
        {meta.desc}. Provisioned automatically — configure credentials to activate scanning.
      </p>

      {/* Configure button */}
      <div className="pt-1 border-t" style={{ borderColor: 'var(--border-primary)' }}>
        <button
          onClick={() => onConfigure?.(account)}
          className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs rounded-lg font-medium hover:opacity-90 transition-opacity"
          style={{
            backgroundColor: 'rgba(139,92,246,0.12)',
            color: '#a78bfa',
            border: '1px solid rgba(139,92,246,0.25)',
          }}
        >
          Configure →
        </button>
      </div>
    </div>
  );
}

// ── Active account card ───────────────────────────────────────────────────────

export default function AccountCard({ account, onRefresh, onConfigure }) {
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [runningNow, setRunningNow] = useState(false);
  const [runMsg, setRunMsg] = useState('');

  if (isDormantAccount(account)) {
    return <DormantCard account={account} onConfigure={onConfigure} />;
  }

  const providerColor = PROVIDER_COLORS[account.provider] || '#6366f1';
  const accountStatus = account.accountStatus || account.account_status;
  const statusStyle = STATUS_STYLES[accountStatus] || STATUS_STYLES.pending;
  const StatusIcon = statusStyle.icon;
  const accountId   = account.accountId   || account.account_id;
  const accountName = account.accountName || account.account_name;
  const lastScanAt  = account.lastScanAt  || account.last_scan_at;

  const handleRunNow = async () => {
    setRunningNow(true);
    setRunMsg('');
    try {
      const resp = await fetch(`/gateway/api/v1/cloud-accounts/${accountId}/scan`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!resp.ok) throw new Error(`Error ${resp.status}`);
      setRunMsg('Scan triggered');
      if (onRefresh) setTimeout(onRefresh, 1500);
    } catch (e) {
      setRunMsg(e.message || 'Failed');
    } finally {
      setRunningNow(false);
      setTimeout(() => setRunMsg(''), 4000);
    }
  };

  return (
    <div
      className="rounded-xl border p-4 space-y-3 hover:shadow-md transition-shadow"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0"
            style={{ backgroundColor: `${providerColor}20`, color: providerColor }}
          >
            {account.provider?.toUpperCase().slice(0, 3)}
          </div>
          <div className="min-w-0">
            <div className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
              {accountName || accountId}
            </div>
            <div className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>
              {accountId}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1 flex-shrink-0">
          <StatusIcon
            size={14}
            style={{ color: statusStyle.color }}
            className={accountStatus === 'validating' ? 'animate-spin' : ''}
          />
          <span className="text-[11px] font-medium" style={{ color: statusStyle.color }}>
            {statusStyle.label}
          </span>
        </div>
      </div>

      {/* Meta row */}
      <div className="flex items-center gap-2 flex-wrap">
        <span
          className="text-[10px] px-1.5 py-0.5 rounded font-medium"
          style={{ backgroundColor: `${providerColor}15`, color: providerColor }}
        >
          {account.provider?.toUpperCase()}
        </span>
        <span
          className="text-[10px] px-1.5 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}
        >
          {account.account_type}
        </span>
        {lastScanAt && (
          <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            Last scan: {new Date(lastScanAt).toLocaleDateString()}
          </span>
        )}
      </div>

      {/* Schedule info */}
      {account.schedule && (
        <div className="flex items-center gap-1.5 text-[11px]" style={{ color: 'var(--text-muted)' }}>
          <Calendar size={11} />
          <span>{account.schedule.cron_expression}</span>
          {!account.schedule.enabled && (
            <span
              className="px-1 rounded text-[9px]"
              style={{ backgroundColor: 'rgba(245,158,11,0.15)', color: '#fbbf24' }}
            >
              paused
            </span>
          )}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex items-center gap-1.5 pt-1 border-t" style={{ borderColor: 'var(--border-primary)' }}>
        <button
          onClick={handleRunNow}
          disabled={runningNow || accountStatus === 'validating'}
          className="flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg font-medium disabled:opacity-40 hover:opacity-80 transition-opacity"
          style={{ backgroundColor: 'rgba(59,130,246,0.15)', color: 'var(--accent-primary)' }}
        >
          {runningNow ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
          Run Now
        </button>

        <button
          onClick={() => setShowScheduleModal(true)}
          className="flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border hover:opacity-80 transition-opacity"
          style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
        >
          <Calendar size={11} />
          {account.schedule ? 'Edit Schedule' : 'Add Schedule'}
        </button>

        {runMsg && (
          <span
            className="text-[11px] ml-auto"
            style={{ color: runMsg === 'Scan triggered' ? '#22c55e' : '#ef4444' }}
          >
            {runMsg}
          </span>
        )}
      </div>

      {/* Schedule modal */}
      {showScheduleModal && (
        <ScheduleModal
          account={account}
          existingSchedule={account.schedule}
          onClose={() => setShowScheduleModal(false)}
          onSaved={() => { setShowScheduleModal(false); if (onRefresh) onRefresh(); }}
        />
      )}
    </div>
  );
}
