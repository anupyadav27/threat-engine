'use client';

import { useState, useMemo } from 'react';

const SEV_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#38bdf8',
};

function fmtTs(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function BehavioralTimeline({ findings }) {
  const [tooltip, setTooltip] = useState(null);

  const sorted = useMemo(() => {
    if (!findings?.length) return [];
    return [...findings].sort((a, b) => new Date(a.event_time || 0) - new Date(b.event_time || 0));
  }, [findings]);

  if (!sorted.length) {
    return (
      <div className="rounded-xl border p-4 flex items-center justify-center h-24 text-sm"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', color: 'var(--text-tertiary)' }}>
        No timeline events
      </div>
    );
  }

  const first = new Date(sorted[0].event_time || 0).getTime();
  const last  = new Date(sorted[sorted.length - 1].event_time || 0).getTime();
  const span  = Math.max(last - first, 1);

  const MARGIN = 24;
  const svgW = Math.max(600, sorted.length * 24);
  const svgH = 80;
  const plotW = svgW - MARGIN * 2;
  const midY = 40;

  const xOf = (ts) => MARGIN + ((new Date(ts || 0).getTime() - first) / span) * plotW;

  const l2Groups = {};
  sorted.forEach(f => {
    if (f.rule_source === 'log_correlation' && f.rule_id) {
      if (!l2Groups[f.rule_id]) l2Groups[f.rule_id] = [];
      l2Groups[f.rule_id].push(f);
    }
  });

  return (
    <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
        Behavioral Timeline
      </div>
      <div className="overflow-x-auto relative">
        <svg width={svgW} height={svgH} style={{ display: 'block', minWidth: svgW }}>
          {/* Baseline */}
          <line x1={MARGIN} y1={midY} x2={svgW - MARGIN} y2={midY} stroke="#334155" strokeWidth={2} />

          {/* L2 group brackets */}
          {Object.entries(l2Groups).map(([ruleId, events]) => {
            if (events.length < 2) return null;
            const xs = events.map(e => xOf(e.event_time));
            const x0 = Math.min(...xs);
            const x1 = Math.max(...xs);
            const bracketY = midY - 18;
            const shortId = ruleId.split('_').slice(-1)[0] || ruleId.slice(0, 8);
            return (
              <g key={ruleId}>
                <line x1={x0} y1={bracketY + 6} x2={x0} y2={bracketY} stroke="#f97316" strokeWidth={1.5} />
                <line x1={x0} y1={bracketY} x2={x1} y2={bracketY} stroke="#f97316" strokeWidth={1.5} />
                <line x1={x1} y1={bracketY} x2={x1} y2={bracketY + 6} stroke="#f97316" strokeWidth={1.5} />
                <text
                  x={(x0 + x1) / 2}
                  y={bracketY - 3}
                  textAnchor="middle"
                  style={{ fontSize: 9, fill: '#f97316', fontFamily: 'monospace' }}>
                  {shortId}
                </text>
              </g>
            );
          })}

          {/* Finding dots */}
          {sorted.map((f, i) => {
            const cx = xOf(f.event_time);
            const isL3 = f.rule_source === 'baseline';
            const fill = isL3 ? '#a855f7' : (SEV_COLOR[f.severity] || '#64748b');

            return (
              <g key={i}>
                <circle
                  cx={cx}
                  cy={midY}
                  r={5}
                  fill={fill}
                  stroke={isL3 ? '#7e22ce' : 'none'}
                  strokeWidth={1.5}
                  style={{ cursor: 'pointer' }}
                  onMouseEnter={e => {
                    const rect = e.currentTarget.getBoundingClientRect();
                    setTooltip({ x: rect.left, y: rect.top, f });
                  }}
                  onMouseLeave={() => setTooltip(null)}
                />
                {isL3 && (
                  <text
                    x={cx}
                    y={midY - 9}
                    textAnchor="middle"
                    style={{ fontSize: 9, fill: '#a855f7', fontFamily: 'inherit', fontWeight: 700 }}>
                    σ
                  </text>
                )}
              </g>
            );
          })}
        </svg>

        {/* Tooltip */}
        {tooltip && (
          <div
            className="fixed z-50 pointer-events-none rounded-lg border px-3 py-2 text-xs shadow-xl"
            style={{
              top: tooltip.y - 100,
              left: tooltip.x,
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
              color: 'var(--text-primary)',
              minWidth: 220,
            }}>
            <div className="font-semibold mb-1" style={{ color: SEV_COLOR[tooltip.f.severity] || '#64748b' }}>
              {tooltip.f.severity?.toUpperCase()} — {tooltip.f.rule_source}
            </div>
            <div className="text-[10px] mb-1" style={{ color: 'var(--text-muted)' }}>{fmtTs(tooltip.f.event_time)}</div>
            {tooltip.f.operation && <div><span style={{ color: 'var(--text-secondary)' }}>Op:</span> {tooltip.f.operation}</div>}
            {tooltip.f.service   && <div><span style={{ color: 'var(--text-secondary)' }}>Service:</span> {tooltip.f.service}</div>}
            {tooltip.f.resource_name && <div className="truncate max-w-[200px]"><span style={{ color: 'var(--text-secondary)' }}>Resource:</span> {tooltip.f.resource_name}</div>}
            {tooltip.f.outcome   && <div><span style={{ color: 'var(--text-secondary)' }}>Outcome:</span> {tooltip.f.outcome}</div>}
          </div>
        )}
      </div>

      {/* Time range labels */}
      <div className="flex justify-between mt-1">
        <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{fmtTs(sorted[0]?.event_time)}</span>
        <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{fmtTs(sorted[sorted.length - 1]?.event_time)}</span>
      </div>
    </div>
  );
}
