'use client';

const AXES = [
  { id: 'containers', angleDeg: 90 },
  { id: 'images',     angleDeg: 162 },
  { id: 'hosts',      angleDeg: 234 },
  { id: 'serverless', angleDeg: 306 },
  { id: 'runtime',    angleDeg: 18 },
];

function polarToSvg(angleDeg, r) {
  const rad = (angleDeg * Math.PI) / 180;
  return {
    x: r * Math.cos(rad),
    y: -r * Math.sin(rad),
  };
}

function buildPolygonPoints(axes, maxR, scores) {
  return axes
    .map(({ id, angleDeg }) => {
      const score = scores[id] ?? 0;
      const r = (score / 100) * maxR;
      const { x, y } = polarToSvg(angleDeg, r);
      return `${x},${y}`;
    })
    .join(' ');
}

function buildMaxPoints(axes, maxR) {
  return axes
    .map(({ angleDeg }) => {
      const { x, y } = polarToSvg(angleDeg, maxR);
      return `${x},${y}`;
    })
    .join(' ');
}

function labelAnchor(x) {
  if (x > 5) return 'start';
  if (x < -5) return 'end';
  return 'middle';
}

function labelOffset(angleDeg) {
  const rad = (angleDeg * Math.PI) / 180;
  const x = Math.cos(rad);
  const y = -Math.sin(rad);
  return { dx: x * 14, dy: y * 14 + 4 };
}

export default function WorkloadRadarChart({ workloads = [], onWorkloadClick, size = 400 }) {
  const maxR = (size / 2) - 40;

  const scoreMap = {};
  const nameMap = {};
  for (const w of workloads) {
    scoreMap[w.id] = w.posture_score ?? 0;
    nameMap[w.id] = w.name || w.id;
  }

  const overallScore =
    workloads.length > 0
      ? Math.round(workloads.reduce((s, w) => s + (w.posture_score ?? 0), 0) / workloads.length)
      : null;

  const posPoints = buildPolygonPoints(AXES, maxR, scoreMap);
  const maxPoints = buildMaxPoints(AXES, maxR);

  return (
    <svg
      width={size}
      height={size}
      viewBox="-220 -220 440 440"
      style={{ overflow: 'visible' }}
    >
      {AXES.map(({ id, angleDeg }) => {
        const tip = polarToSvg(angleDeg, maxR);
        const score = scoreMap[id] ?? 0;
        const name = nameMap[id] || id;
        const anchor = labelAnchor(tip.x);
        const off = labelOffset(angleDeg);
        const labelX = tip.x + off.dx;
        const labelY = tip.y + off.dy;

        return (
          <g key={id}>
            <line
              x1={0} y1={0}
              x2={tip.x} y2={tip.y}
              stroke="#334155"
              strokeWidth={1}
              strokeDasharray="4 4"
            />
            <text
              x={labelX}
              y={labelY - 8}
              textAnchor={anchor}
              fontSize={11}
              fill="#94a3b8"
              style={{ cursor: onWorkloadClick ? 'pointer' : 'default', userSelect: 'none' }}
              onClick={() => onWorkloadClick && onWorkloadClick(id)}
            >
              {name}
            </text>
            <text
              x={labelX}
              y={labelY + 5}
              textAnchor={anchor}
              fontSize={10}
              fill="#64748b"
              style={{ cursor: onWorkloadClick ? 'pointer' : 'default', userSelect: 'none' }}
              onClick={() => onWorkloadClick && onWorkloadClick(id)}
            >
              {score}
            </text>
          </g>
        );
      })}

      <polygon
        points={maxPoints}
        fill="none"
        stroke="#1e293b"
        strokeWidth={1}
        strokeDasharray="4 4"
      />

      <polygon
        points={posPoints}
        fill="rgba(99,102,241,0.2)"
        stroke="#6366f1"
        strokeWidth={2}
      />

      {overallScore !== null && (
        <>
          <text
            x={0} y={-8}
            textAnchor="middle"
            fontSize={18}
            fontWeight="bold"
            fill="#e2e8f0"
          >
            {overallScore}
          </text>
          <text
            x={0} y={10}
            textAnchor="middle"
            fontSize={9}
            fill="#64748b"
          >
            CWPP Score
          </text>
        </>
      )}
    </svg>
  );
}
