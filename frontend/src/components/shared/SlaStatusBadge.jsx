'use client';

/**
 * SlaStatusBadge — pill showing SLA compliance status.
 *
 * @param {{ status: 'breached'|'at_risk'|'ok', daysInfo?: string }} props
 */
export default function SlaStatusBadge({ status, daysInfo }) {
  const config = {
    breached: { label: 'SLA Breached', bg: 'rgba(239,68,68,0.12)', text: '#ef4444', dot: '#ef4444' },
    at_risk:  { label: 'At Risk',      bg: 'rgba(249,115,22,0.12)', text: '#f97316', dot: '#f97316' },
    ok:       { label: 'On Track',     bg: 'rgba(34,197,94,0.12)',  text: '#22c55e', dot: '#22c55e' },
  }[status] || { label: status, bg: 'rgba(100,100,100,0.1)', text: '#888', dot: '#888' };

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap"
      style={{ backgroundColor: config.bg, color: config.text }}
    >
      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: config.dot }} />
      {config.label}
      {daysInfo && <span className="opacity-70 ml-0.5">({daysInfo})</span>}
    </span>
  );
}
