'use client';

import { useState } from 'react';

const SEV_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
};

const CELL_W = 36;
const CELL_H = 28;
const PAD_LEFT = 110;
const PAD_TOP  = 32;
const PAD_BOTTOM = 8;

export default function IdentityRiskHeatmap({ matrix, accounts, principalTypes, onCellClick }) {
  const [tooltip, setTooltip] = useState(null);

  if (!accounts?.length || !principalTypes?.length) {
    return (
      <div className="rounded-xl border p-4 flex items-center justify-center h-48 text-sm"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', color: 'var(--text-tertiary)' }}>
        No heatmap data
      </div>
    );
  }

  const svgW = PAD_LEFT + accounts.length * CELL_W + 16;
  const svgH = PAD_TOP  + principalTypes.length * CELL_H + PAD_BOTTOM + 28;

  const cellFor = (accountId, ptype) =>
    matrix.find(c => c.account_id === accountId && c.principal_type === ptype);

  return (
    <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="text-xs font-semibold mb-3 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
        Identity Risk by Account &times; Type
      </div>
      <div className="relative overflow-x-auto">
        <svg width={svgW} height={svgH} style={{ display: 'block' }}>
          {/* Y-axis labels (principal types) */}
          {principalTypes.map((ptype, ri) => (
            <text
              key={ptype}
              x={PAD_LEFT - 8}
              y={PAD_TOP + ri * CELL_H + CELL_H / 2 + 4}
              textAnchor="end"
              style={{ fontSize: 10, fill: 'var(--text-secondary)', fontFamily: 'inherit' }}>
              {ptype}
            </text>
          ))}

          {/* X-axis labels (account short) */}
          {accounts.map((acct, ci) => (
            <text
              key={acct}
              x={PAD_LEFT + ci * CELL_W + CELL_W / 2}
              y={PAD_TOP - 8}
              textAnchor="middle"
              style={{ fontSize: 9, fill: 'var(--text-muted)', fontFamily: 'monospace' }}>
              ...{String(acct).slice(-6)}
            </text>
          ))}

          {/* Grid cells */}
          {principalTypes.map((ptype, ri) =>
            accounts.map((acct, ci) => {
              const cell = cellFor(acct, ptype);
              const maxSev = cell?.max_severity;
              const fill = SEV_COLOR[maxSev] || '#1e293b';
              const x = PAD_LEFT + ci * CELL_W;
              const y = PAD_TOP  + ri * CELL_H;

              return (
                <rect
                  key={`${acct}-${ptype}`}
                  x={x + 2}
                  y={y + 2}
                  width={CELL_W - 4}
                  height={CELL_H - 4}
                  rx={3}
                  fill={fill}
                  opacity={cell ? 0.85 : 0.3}
                  style={{ cursor: cell ? 'pointer' : 'default' }}
                  onMouseEnter={cell ? (e) => {
                    const rect = e.currentTarget.getBoundingClientRect();
                    setTooltip({
                      x: rect.left,
                      y: rect.top,
                      account: acct,
                      ptype,
                      cell,
                    });
                  } : undefined}
                  onMouseLeave={() => setTooltip(null)}
                  onClick={cell ? () => onCellClick?.(acct, ptype) : undefined}
                />
              );
            })
          )}
        </svg>

        {/* Hover tooltip */}
        {tooltip && (
          <div
            className="fixed z-50 pointer-events-none rounded-lg border px-3 py-2 text-xs shadow-xl"
            style={{
              top: tooltip.y - 80,
              left: tooltip.x,
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
              color: 'var(--text-primary)',
              minWidth: 200,
            }}>
            <div className="font-mono text-[10px] mb-1" style={{ color: 'var(--text-muted)' }}>
              ...{String(tooltip.account).slice(-12)} / {tooltip.ptype}
            </div>
            {['critical', 'high', 'medium', 'low'].map(sev => {
              const count = tooltip.cell?.[`${sev}_count`] ?? tooltip.cell?.[sev] ?? 0;
              if (!count) return null;
              return (
                <div key={sev} className="flex gap-1.5 items-center">
                  <span style={{ color: SEV_COLOR[sev], fontWeight: 700 }}>{count}</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{sev}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex gap-3 mt-3 flex-wrap">
        {Object.entries(SEV_COLOR).map(([sev, color]) => (
          <div key={sev} className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: color }} />
            <span className="text-[10px] capitalize" style={{ color: 'var(--text-muted)' }}>{sev}</span>
          </div>
        ))}
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: '#1e293b', border: '1px solid #334155' }} />
          <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>None</span>
        </div>
      </div>
    </div>
  );
}
