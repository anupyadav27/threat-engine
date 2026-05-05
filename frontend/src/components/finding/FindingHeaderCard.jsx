'use client';

import { useState } from 'react';
import { UserPlus, RefreshCw, EyeOff, Download, ChevronDown, ChevronUp, Loader2 } from 'lucide-react';
import SeverityBadge from '@/components/shared/SeverityBadge';
import SlaStatusBadge from '@/components/shared/SlaStatusBadge';
import { fetchApi } from '@/lib/api';
import { emit } from '@/lib/telemetry';
import { ENGINE_META } from './engine-meta';

// MUST match BFF StatusUpdateRequest Literal in shared/api_gateway/bff/views/_schemas.py
const STATUS_OPTIONS = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'SUPPRESSED', 'FALSE_POSITIVE'];
const formatStatus = (s) => (s || '').replace(/_/g, ' ').toLowerCase();

function MetaCell({ label, value }) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
        {label}
      </span>
      <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
        {value || '—'}
      </span>
    </div>
  );
}

function RiskGauge({ score }) {
  const pct = Math.max(0, Math.min(100, Number(score) || 0));
  const color = pct >= 80 ? '#ef4444' : pct >= 60 ? '#f97316' : pct >= 40 ? '#eab308' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div className="relative w-12 h-12">
        <svg viewBox="0 0 36 36" className="w-12 h-12">
          <path
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            fill="none"
            stroke="var(--border-primary)"
            strokeWidth="3"
          />
          <path
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            fill="none"
            stroke={color}
            strokeWidth="3"
            strokeDasharray={`${pct},100`}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center text-xs font-bold" style={{ color }}>
          {pct}
        </div>
      </div>
      <div className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
        Risk
      </div>
    </div>
  );
}

export default function FindingHeaderCard({ header, engine, id }) {
  const [descExpanded, setDescExpanded] = useState(false);
  const [statusMenuOpen, setStatusMenuOpen] = useState(false);
  const [statusBusy, setStatusBusy] = useState(false);
  const [currentStatus, setCurrentStatus] = useState((header?.status || 'OPEN').toUpperCase());

  const meta = ENGINE_META[engine];

  // CP-2 B2: status PATCH goes through BFF, not direct to engine.
  async function changeStatus(newStatus) {
    if (newStatus === currentStatus || statusBusy) return;
    setStatusBusy(true);
    setStatusMenuOpen(false);
    const prev = currentStatus;
    setCurrentStatus(newStatus); // optimistic
    const res = await fetchApi(`/api/v1/views/finding/${engine}/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status: newStatus }),
    });
    setStatusBusy(false);
    if (res?.error) {
      setCurrentStatus(prev); // rollback
      emit('finding.action', { engine, finding_id: id, action: 'status', outcome: 'error' });
    } else {
      emit('finding.action', { engine, finding_id: id, action: 'status', outcome: 'success' });
    }
  }

  function exportJson() {
    try {
      const blob = new Blob([JSON.stringify(header, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `finding-${engine}-${id}.json`;
      a.click();
      URL.revokeObjectURL(url);
      emit('finding.action', { engine, finding_id: id, action: 'export', outcome: 'success' });
    } catch (err) {
      emit('finding.action', { engine, finding_id: id, action: 'export', outcome: 'error' });
    }
  }

  return (
    <div
      className="sticky top-0 z-20 rounded-lg border p-4"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      {/* Row 1: badges + risk */}
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <SeverityBadge severity={header?.severity || 'info'} />
        <span
          className="px-2 py-0.5 rounded text-xs font-medium"
          style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
        >
          {currentStatus}
        </span>
        {meta && (
          <span
            className="px-2 py-0.5 rounded text-xs font-medium"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-muted)' }}
          >
            {meta.label}
          </span>
        )}
        {header?.ruleId && (
          <a
            href={`/rules/${encodeURIComponent(header.ruleId)}`}
            className="px-2 py-0.5 rounded text-xs font-mono"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--accent-primary)' }}
          >
            {header.ruleId}
          </a>
        )}
        <div className="ml-auto">
          <RiskGauge score={header?.riskScore} />
        </div>
      </div>

      {/* Row 2: title + description */}
      <h1 className="text-lg font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
        {header?.title || 'Untitled finding'}
      </h1>
      {header?.description && (
        <div className="mb-3">
          <p
            className={`text-sm ${descExpanded ? '' : 'line-clamp-2'}`}
            style={{ color: 'var(--text-muted)' }}
          >
            {header.description}
          </p>
          <button
            onClick={() => setDescExpanded((v) => !v)}
            className="text-xs mt-1 inline-flex items-center gap-1"
            style={{ color: 'var(--accent-primary)' }}
          >
            {descExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            {descExpanded ? 'Show less' : 'Show more'}
          </button>
        </div>
      )}

      {/* Row 3: metadata grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-3">
        <MetaCell label="Provider" value={header?.provider} />
        <MetaCell label="Account" value={header?.accountId} />
        <MetaCell label="Region" value={header?.region} />
        <div className="flex flex-col">
          <span className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            Resource
          </span>
          {header?.resourceUid ? (
            <a
              href={`/inventory/${encodeURIComponent(header.resourceUid)}`}
              className="text-sm font-medium truncate"
              style={{ color: 'var(--accent-primary)' }}
              title={header.resourceUid}
              onClick={() =>
                emit('finding.pivot_click', {
                  engine,
                  finding_id: id,
                  pivot_type: 'asset',
                  target_id: header.resourceUid,
                })
              }
            >
              {header.resourceUid}
            </a>
          ) : (
            <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
              —
            </span>
          )}
        </div>
        <MetaCell label="First seen" value={header?.firstSeenAt} />
        <MetaCell label="Last seen" value={header?.lastSeenAt} />
      </div>

      {header?.slaStatus && (
        <div className="mb-3">
          <SlaStatusBadge status={header.slaStatus} daysInfo={header.slaDaysInfo} />
        </div>
      )}

      {/* Row 4: action bar */}
      <div className="flex flex-wrap items-center gap-2 justify-end pt-2 border-t" style={{ borderColor: 'var(--border-primary)' }}>
        <button
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-sm"
          style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
          onClick={() =>
            emit('finding.action', { engine, finding_id: id, action: 'assign', outcome: 'click' })
          }
        >
          <UserPlus className="w-4 h-4" /> Assign
        </button>
        <div className="relative">
          <button
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-sm"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
            onClick={() => setStatusMenuOpen((v) => !v)}
            disabled={statusBusy}
          >
            {statusBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            Change Status
          </button>
          {statusMenuOpen && (
            <div
              className="absolute right-0 mt-1 rounded border shadow-lg z-30 min-w-[180px]"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
            >
              {STATUS_OPTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => changeStatus(s)}
                  className="block w-full text-left px-3 py-1.5 text-sm hover:opacity-80"
                  style={{
                    color: 'var(--text-primary)',
                    backgroundColor: s === currentStatus ? 'var(--bg-secondary)' : 'transparent',
                  }}
                >
                  {formatStatus(s)}
                </button>
              ))}
            </div>
          )}
        </div>
        <button
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-sm"
          style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
          onClick={() =>
            emit('finding.action', { engine, finding_id: id, action: 'suppress', outcome: 'click' })
          }
        >
          <EyeOff className="w-4 h-4" /> Suppress
        </button>
        <button
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-sm"
          style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
          onClick={exportJson}
        >
          <Download className="w-4 h-4" /> Export JSON
        </button>
      </div>
    </div>
  );
}
