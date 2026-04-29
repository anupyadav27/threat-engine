'use client';

/**
 * KpiSparkCard — Threat-detection style KPI card with inline sparkline.
 *
 * Matches the visual style of threats/page.jsx KPI strip:
 *   - Translucent colored border + subtle glow shadow
 *   - Large metric value with optional suffix
 *   - Inline delta badge (auto-colours green/red based on direction)
 *   - One-line context subtitle
 *   - Mini SVG sparkline with 8w / 4w / Now tick labels
 *
 * Props:
 *   label      string       Card title
 *   value      number|string  Main metric
 *   color      string       Hex accent color (e.g. '#ef4444')
 *   suffix     string       Appended to value (e.g. '/100', '%')
 *   delta      number|null  Change vs baseline (positive = grew, negative = shrank)
 *   deltaGood  'up'|'down'  Which direction is healthy (default 'down')
 *   deltaSuffix string      Appended to delta (e.g. '%')
 *   sub        string       Context / subtitle line
 *   sparkData  number[]     8–10 data points for sparkline
 *   extra      ReactNode    Optional content between subtitle and sparkline
 */
export default function KpiSparkCard({
  label,
  value,
  color,
  suffix    = '',
  delta     = null,
  deltaGood = 'down',
  deltaSuffix = '',
  sub       = '',
  sparkData = [],
  extra     = null,
}) {
  const improved   = delta === null ? true : (deltaGood === 'up' ? delta >= 0 : delta <= 0);
  const deltaColor = delta === null ? null : (improved ? '#10b981' : '#ef4444');
  const deltaSign  = delta !== null && delta > 0 ? '+' : '';

  return (
    <div style={{
      backgroundColor: 'var(--bg-card)',
      border:          `1px solid ${color}38`,
      borderRadius:    10,
      padding:         '12px 14px',
      boxShadow:       `0 4px 20px ${color}14`,
      display:         'flex',
      flexDirection:   'column',
    }}>
      {/* ── Label ── */}
      <div style={{
        fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
        marginBottom: 4, letterSpacing: '0.01em',
      }}>
        {label}
      </div>

      {/* ── Value + suffix + delta badge ── */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 2 }}>
        <span style={{
          fontSize: 28, fontWeight: 900, color, lineHeight: 1,
          fontVariantNumeric: 'tabular-nums',
        }}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>
        {suffix && (
          <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--text-muted)' }}>
            {suffix}
          </span>
        )}
        {delta !== null && (
          <span style={{
            fontSize: 11, fontWeight: 700, padding: '1px 6px', borderRadius: 4,
            backgroundColor: `${deltaColor}1a`, color: deltaColor,
          }}>
            {deltaSign}{delta}{deltaSuffix}
          </span>
        )}
      </div>

      {/* ── Subtitle ── */}
      {sub && (
        <div style={{
          fontSize: 11, color: 'var(--text-tertiary)',
          marginBottom: (sparkData.length >= 2 || extra) ? 6 : 0,
        }}>
          {sub}
        </div>
      )}

      {/* ── Extra slot (e.g. progress bar) ── */}
      {extra}

      {/* ── Sparkline ── */}
      {sparkData.length >= 2 && <KpiSparkline values={sparkData} color={color} n={sparkData.length} />}
    </div>
  );
}

// ── Inline sparkline (pure SVG, no Recharts dependency) ───────────────────────
function KpiSparkline({ values, color, n }) {
  const W = 120, H = 38, PAD_T = 4, PAD_B = 18, PAD_X = 4;
  const min   = Math.min(...values);
  const max   = Math.max(...values);
  const range = max - min || 1;

  const pts = values.map((v, i) => [
    PAD_X + (i / (n - 1)) * (W - PAD_X * 2),
    PAD_T + (1 - (v - min) / range) * (H - PAD_T - PAD_B),
  ]);

  const line = pts.map((p, i) => (i === 0 ? `M${p[0]},${p[1]}` : `L${p[0]},${p[1]}`)).join(' ');
  const area = `${line} L${pts[n-1][0]},${H - PAD_B} L${pts[0][0]},${H - PAD_B} Z`;
  const gid  = `ksc-${color.replace(/[^a-z0-9]/gi, '')}`;

  const midIdx = Math.floor((n - 1) / 2);
  const ticks = [
    { idx: 0,      label: `${n - 1}w`, anchor: 'start' },
    { idx: midIdx, label: `${Math.round((n - 1) / 2)}w`, anchor: 'middle' },
    { idx: n - 1,  label: 'Now',       anchor: 'end'   },
  ];

  return (
    <svg width={W} height={H} style={{ display: 'block', overflow: 'visible' }}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor={color} stopOpacity="0.22" />
          <stop offset="100%" stopColor={color} stopOpacity="0.01" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gid})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" />
      {ticks.map(({ idx, label, anchor }) => (
        <text key={label}
          x={pts[idx][0]} y={H - 2}
          textAnchor={anchor}
          style={{ fontSize: 9, fill: 'var(--text-muted)', fontFamily: 'inherit' }}>
          {label}
        </text>
      ))}
    </svg>
  );
}
