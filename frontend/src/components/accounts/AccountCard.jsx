'use client';

import { useState } from 'react';
import { Play, Calendar, Clock, CheckCircle2, XCircle, AlertCircle, Loader2, MoreHorizontal } from 'lucide-react';
import { PROVIDER_COLORS } from '@/lib/catalog';
import ScheduleModal from '@/components/onboarding/ScheduleModal';

const STATUS_STYLES = {
  active:      { icon: CheckCircle2,  color: '#22c55e',  label: 'Active' },
  inactive:    { icon: AlertCircle,   color: '#f59e0b',  label: 'Inactive' },
  error:       { icon: XCircle,       color: '#ef4444',  label: 'Error' },
  validating:  { icon: Loader2,       color: '#60a5fa',  label: 'Validating' },
  pending:     { icon: Clock,         color: '#94a3b8',  label: 'Pending' },
};

export default function AccountCard({ account, onRefresh }) {
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [runningNow, setRunningNow] = useState(false);
  const [runMsg, setRunMsg] = useState('');

  const providerColor = PROVIDER_COLORS[account.provider] || '#6366f1';
  const statusStyle = STATUS_STYLES[account.account_status] || STATUS_STYLES.pending;
  const StatusIcon = statusStyle.icon;

  const handleRunNow = async () => {
    setRunningNow(true);
    setRunMsg('');
    try {
      const resp = await fetch(`/gateway/api/v1/cloud-accounts/${account.account_id}/scan`, {
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
              {account.account_name || account.account_id}
            </div>
            <div className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>
              {account.account_id}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1 flex-shrink-0">
          <StatusIcon
            size={14}
            style={{ color: statusStyle.color }}
            className={account.account_status === 'validating' ? 'animate-spin' : ''}
          />
          <span className="text-[11px] font-medium" style={{ color: statusStyle.color }}>
            {statusStyle.label}
          </span>
        </div>
      </div>

      {/* Meta row */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] px-1.5 py-0.5 rounded font-medium"
          style={{ backgroundColor: `${providerColor}15`, color: providerColor }}>
          {account.provider?.toUpperCase()}
        </span>
        <span className="text-[10px] px-1.5 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
          {account.account_type}
        </span>
        {account.last_scan_at && (
          <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            Last scan: {new Date(account.last_scan_at).toLocaleDateString()}
          </span>
        )}
      </div>

      {/* Schedule info */}
      {account.schedule && (
        <div className="flex items-center gap-1.5 text-[11px]" style={{ color: 'var(--text-muted)' }}>
          <Calendar size={11} />
          <span>{account.schedule.cron_expression}</span>
          {!account.schedule.enabled && (
            <span className="px-1 rounded text-[9px]" style={{ backgroundColor: 'rgba(245,158,11,0.15)', color: '#fbbf24' }}>paused</span>
          )}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex items-center gap-1.5 pt-1 border-t" style={{ borderColor: 'var(--border-primary)' }}>
        <button
          onClick={handleRunNow}
          disabled={runningNow || account.account_status === 'validating'}
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
          <span className="text-[11px] ml-auto" style={{ color: runMsg === 'Scan triggered' ? '#22c55e' : '#ef4444' }}>
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
