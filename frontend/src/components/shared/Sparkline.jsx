'use client';

/**
 * CspmSparkline — shared inline SVG sparkline used across all engine pages.
 *
 * Tick labels are rendered as HTML (not SVG text) so they never distort
 * when the SVG stretches horizontally with preserveAspectRatio="none".
 *
 * Props:
 *   data     - number[]  (required)
 *   color    - string    accent hex/rgb
 *   height   - number    SVG height (default 52)
 *   showArea - boolean   area gradient fill (default true)
 *   ticks    - [{ idx, label }] | null  — x-axis labels rendered as HTML
 *   period   - string | null   — small badge top-right (SVG)
 */
export default function CspmSparkline({
  data,
  color,
  height = 52,
  showArea = true,
  ticks = null,
  period = null,
}) {
  if (!data || data.length < 2) return null;

  const chartH = height;
  const VW     = 200;    // internal coordinate space width

  const mn  = Math.min(...data);
  const mx  = Math.max(...data);
  const rng = mx - mn || 1;

  const px = i => (i / (data.length - 1)) * VW;
  const py = v => chartH - ((v - mn) / rng) * (chartH - 8) - 3;

  const pts   = data.map((v, i) => `${px(i).toFixed(2)},${py(v).toFixed(2)}`).join(' ');
  const lx    = px(data.length - 1);
  const ly    = py(data[data.length - 1]);
  const gradId = `spark-${color.replace(/[^a-z0-9]/gi, '')}`;
  const areaD  = `M0,${chartH} ${data.map((v, i) => `L${px(i).toFixed(2)},${py(v).toFixed(2)}`).join(' ')} L${lx.toFixed(2)},${chartH} Z`;

  // Convert viewBox x position (0..VW) to a CSS percentage for HTML tick labels
  const pct = i => `${((i / (data.length - 1)) * 100).toFixed(2)}%`;

  return (
    <div style={{ position: 'relative' }}>
      <svg
        viewBox={`0 0 ${VW} ${chartH}`}
        width="100%"
        height={chartH}
        preserveAspectRatio="none"
        style={{ display: 'block', overflow: 'visible' }}
      >
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor={color} stopOpacity={0.28} />
            <stop offset="100%" stopColor={color} stopOpacity={0.01} />
          </linearGradient>
        </defs>

        {/* dashed baseline */}
        <line x1={0} y1={chartH} x2={VW} y2={chartH}
          stroke="var(--border-primary)" strokeWidth={1} strokeDasharray="2,3" />

        {/* area fill */}
        {showArea && <path d={areaD} fill={`url(#${gradId})`} />}

        {/* line */}
        <polyline points={pts} fill="none" stroke={color}
          strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" />

        {/* end-point dot */}
        <circle cx={lx} cy={ly} r={2.5} fill={color}
          stroke="var(--bg-card)" strokeWidth={1.5} />

        {/* period badge — stays in SVG, top-right */}
        {period && (
          <text x={VW} y={9} textAnchor="end"
            style={{ fontSize: 8, fill: color, opacity: 0.65, fontFamily: 'inherit', fontWeight: 700 }}>
            {period}
          </text>
        )}
      </svg>

      {/* Tick labels as HTML — never distorted by SVG scaling */}
      {ticks && (
        <div style={{ position: 'relative', height: 14, marginTop: 2 }}>
          {ticks.map(({ idx, label }, ti) => (
            <span key={idx} style={{
              position: 'absolute',
              left: pct(idx),
              transform: ti === 0 ? 'none' : ti === ticks.length - 1 ? 'translateX(-100%)' : 'translateX(-50%)',
              fontSize: 9,
              color: 'var(--text-muted)',
              whiteSpace: 'nowrap',
              lineHeight: 1,
            }}>
              {label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
