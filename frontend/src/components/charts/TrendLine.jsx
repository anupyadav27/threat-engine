'use client';

import { useState, useMemo } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, ReferenceLine,
} from 'recharts';

/**
 * TrendLine — multi-series line chart with per-engine toggle chips.
 *
 * Click any engine chip to show/hide that line.
 * Shift-click to isolate a single engine (hide all others).
 * Click again to restore all.
 */
export default function TrendLine({
  data           = [],
  dataKeys       = [],
  colors         = ['#3b82f6','#10b981','#f97316','#ef4444','#f59e0b','#0ea5e9','#a78bfa','#8b5cf6'],
  labels         = [],
  height         = 300,
  yDomain        = [0, 100],
  yTicks         = [0, 25, 50, 75, 100],
  yLabel         = 'Score',
  xInterval      = 6,
  referenceLines = [
    { y: 75, color: '#22c55e', label: 'Good ≥75' },
    { y: 50, color: '#f97316', label: 'Fair ≥50' },
  ],
}) {
  /* Set of hidden series keys */
  const [hidden, setHidden] = useState(new Set());

  /* Last data point value per key — shown in toggle chips */
  const latestValues = useMemo(() => {
    if (!data.length) return {};
    const last = data[data.length - 1];
    return Object.fromEntries(dataKeys.map(k => [k, last?.[k] ?? null]));
  }, [data, dataKeys]);

  const toggle = (key, e) => {
    if (e?.shiftKey) {
      /* Shift-click: isolate this engine, or restore all if already isolated */
      const isIsolated = hidden.size === dataKeys.length - 1 && !hidden.has(key);
      if (isIsolated) {
        setHidden(new Set());
      } else {
        setHidden(new Set(dataKeys.filter(k => k !== key)));
      }
      return;
    }
    setHidden(prev => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        /* Don't hide the last visible series */
        if (next.size < dataKeys.length - 1) next.add(key);
      }
      return next;
    });
  };

  const resetAll = () => setHidden(new Set());

  /* Custom tooltip — only shows visible series */
  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    const visible = payload.filter(p => !hidden.has(p.dataKey));
    if (!visible.length) return null;
    return (
      <div className="rounded-lg border px-3 py-2 text-xs shadow-xl"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', minWidth: 148 }}>
        <p className="font-semibold mb-1.5" style={{ color: 'var(--text-muted)' }}>{label}</p>
        {visible
          .slice().sort((a, b) => b.value - a.value)
          .map((p, i) => (
            <div key={i} className="flex items-center justify-between gap-4 py-0.5">
              <span className="flex items-center gap-1.5" style={{ color: 'var(--text-secondary)' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: p.color, display: 'inline-block', flexShrink: 0 }} />
                {p.name}
              </span>
              <span className="font-bold tabular-nums" style={{ color: p.color }}>{p.value}</span>
            </div>
          ))}
      </div>
    );
  };

  const scoreColor = v => v >= 75 ? '#22c55e' : v >= 50 ? '#f97316' : '#ef4444';

  /* ── When only one series: show a static info row instead of toggle chips ── */
  const isSingleSeries = dataKeys.length === 1;

  return (
    <div>
      {isSingleSeries ? (
        /* Single-series: compact label row with latest value */
        <div className="flex items-center gap-2 mb-3">
          <span style={{
            width: 10, height: 10, borderRadius: '50%',
            backgroundColor: colors[0],
            display: 'inline-block', flexShrink: 0,
            boxShadow: `0 0 5px ${colors[0]}80`,
          }} />
          <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
            {labels[0] || dataKeys[0]}
          </span>
          {latestValues[dataKeys[0]] != null && (
            <>
              <span style={{ color: 'var(--border-primary)' }}>·</span>
              <span className="text-xs font-bold tabular-nums"
                style={{ color: scoreColor(latestValues[dataKeys[0]]) }}>
                {latestValues[dataKeys[0]]} / 100
              </span>
              <span className="text-xs px-1.5 py-0.5 rounded font-bold"
                style={{
                  backgroundColor: `${scoreColor(latestValues[dataKeys[0]])}18`,
                  color: scoreColor(latestValues[dataKeys[0]]),
                  fontSize: '9px',
                }}>
                {latestValues[dataKeys[0]] >= 75 ? 'Good' : latestValues[dataKeys[0]] >= 50 ? 'Fair' : 'Poor'}
              </span>
            </>
          )}
          <span className="ml-auto text-xs" style={{ color: 'var(--text-muted)', fontSize: '10px' }}>
            30-day rolling average
          </span>
        </div>
      ) : (
        /* Multi-series: toggle chips ── */
        <div className="flex flex-wrap items-center gap-2 mb-3">
          {dataKeys.map((key, idx) => {
            const isHidden  = hidden.has(key);
            const color     = colors[idx % colors.length];
            const label     = labels[idx] || key;
            const latest    = latestValues[key];
            const latColor  = latest != null ? scoreColor(latest) : 'var(--text-muted)';

            return (
              <button
                key={key}
                onClick={e => toggle(key, e)}
                title="Click to toggle · Shift+click to isolate"
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium transition-all select-none"
                style={{
                  borderColor:       isHidden ? 'var(--border-primary)' : color,
                  backgroundColor:   isHidden ? 'transparent'           : `${color}15`,
                  color:             isHidden ? 'var(--text-muted)'      : 'var(--text-primary)',
                  opacity:           isHidden ? 0.45                     : 1,
                }}>
                {/* Colour swatch */}
                <span style={{
                  width: 8, height: 8, borderRadius: '50%',
                  backgroundColor: isHidden ? 'var(--border-primary)' : color,
                  flexShrink: 0,
                }} />
                {label}
                {/* Latest score badge */}
                {latest != null && !isHidden && (
                  <span className="font-bold tabular-nums ml-0.5" style={{ color: latColor }}>
                    {latest}
                  </span>
                )}
              </button>
            );
          })}

          {/* Reset link — only shown when something is hidden */}
          {hidden.size > 0 && (
            <button
              onClick={resetAll}
              className="text-xs px-2 py-1 rounded-full border transition-colors"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}>
              Show all ×
            </button>
          )}

          <span className="ml-auto text-xs" style={{ color: 'var(--text-muted)' }}>
            shift+click to isolate
          </span>
        </div>
      )}

      {/* ── Chart ── */}
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 8, right: 16, left: 0, bottom: 4 }}>
          <CartesianGrid
            horizontal strokeDasharray="3 3"
            stroke="var(--border-primary)" vertical={false}
          />

          <XAxis
            dataKey="date"
            interval={xInterval}
            tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: 'var(--border-primary)' }}
            dy={6}
          />

          <YAxis
            domain={yDomain}
            ticks={yTicks}
            tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={32}
            label={{
              value: yLabel,
              angle: -90,
              position: 'insideLeft',
              offset: 12,
              style: { fill: 'var(--text-muted)', fontSize: 10, letterSpacing: '0.05em', textTransform: 'uppercase' },
            }}
          />

          {referenceLines.map(({ y, color, label }) => (
            <ReferenceLine key={y} y={y}
              stroke={color} strokeDasharray="4 4" strokeOpacity={0.35}
              label={{ value: label, position: 'insideTopRight', fill: color, fontSize: 9, fontWeight: 700, opacity: 0.55 }}
            />
          ))}

          <Tooltip
            content={<CustomTooltip />}
            cursor={{ stroke: 'rgba(148,163,184,0.12)', strokeWidth: 1.5 }}
          />

          {/* No built-in Legend — replaced by toggle chips above */}

          {dataKeys.map((key, idx) => (
            <Line
              key={key}
              type="monotone"
              dataKey={key}
              name={labels[idx] || key}
              stroke={colors[idx % colors.length]}
              strokeWidth={hidden.has(key) ? 0 : 1.8}
              dot={false}
              activeDot={hidden.has(key) ? false : { r: 4, strokeWidth: 0 }}
              hide={hidden.has(key)}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
