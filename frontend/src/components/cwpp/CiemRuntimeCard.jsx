'use client';

import { useRouter } from 'next/navigation';
import { Activity, AlertTriangle } from 'lucide-react';
import SeverityBadge from '@/components/shared/SeverityBadge';

const SEV_CHIP = {
  critical: { bg: '#ef444420', color: '#ef4444', label: 'Critical' },
  high:     { bg: '#f9731620', color: '#f97316', label: 'High' },
  medium:   { bg: '#eab30820', color: '#eab308', label: 'Medium' },
  low:      { bg: '#64748b20', color: '#94a3b8', label: 'Low' },
};

function SevChip({ level, count }) {
  const cfg = SEV_CHIP[level];
  if (!cfg || count === 0) return null;
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium"
      style={{ backgroundColor: cfg.bg, color: cfg.color }}
    >
      {count} {cfg.label}
    </span>
  );
}

export default function CiemRuntimeCard({ ciemRuntimeEvents, accountId }) {
  const router = useRouter();
  const events = ciemRuntimeEvents || {};
  const { count = 0, critical = 0, high = 0, medium = 0, low = 0,
          link_available = false, sample_findings = [] } = events;

  const unavailable = !link_available && count === 0;
  const noEvents    = link_available && count === 0;

  function handleViewTimeline() {
    const params = new URLSearchParams({ filter: 'action_category:runtime' });
    if (accountId) params.append('account', accountId);
    router.push(`/ciem?${params.toString()}`);
  }

  return (
    <div className="bg-slate-800 rounded-xl p-4 mb-4 border border-indigo-800">
      <div className="flex items-center gap-2 mb-3">
        <Activity className="w-4 h-4 text-indigo-400" />
        <span className="text-sm font-semibold text-slate-200">
          CIEM Behavioral Events
        </span>
      </div>

      {unavailable && (
        <div className="flex items-center gap-2 text-slate-400 text-sm">
          <AlertTriangle className="w-4 h-4" />
          CIEM engine unavailable
        </div>
      )}

      {!unavailable && noEvents && (
        <p className="text-sm text-slate-400">No CIEM runtime events detected</p>
      )}

      {!unavailable && !noEvents && (
        <>
          <div className="flex items-baseline gap-2 mb-3">
            <span className="text-2xl font-bold text-slate-100">{count}</span>
            <span className="text-sm text-slate-400">behavioral event{count !== 1 ? 's' : ''} detected</span>
          </div>

          <div className="flex flex-wrap gap-1.5 mb-3">
            <SevChip level="critical" count={critical} />
            <SevChip level="high"     count={high} />
            <SevChip level="medium"   count={medium} />
            <SevChip level="low"      count={low} />
          </div>

          {sample_findings.length > 0 && (
            <div className="space-y-2 mb-3">
              {sample_findings.map((f, i) => (
                <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-slate-700/50">
                  <SeverityBadge severity={f.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-slate-200 truncate">{f.title || '—'}</p>
                    {f.actor_principal && (
                      <p className="text-xs text-slate-400 font-mono truncate">{f.actor_principal}</p>
                    )}
                    {f.event_time && (
                      <p className="text-xs text-slate-500">{f.event_time}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          <button
            onClick={handleViewTimeline}
            className="text-sm text-indigo-400 hover:text-indigo-300 transition-colors"
          >
            View Full Behavioral Timeline in CIEM →
          </button>
        </>
      )}
    </div>
  );
}
