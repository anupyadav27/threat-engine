'use client';

import { useMemo } from 'react';

/**
 * GaugeChart Component
 * SVG-based semi-circle gauge chart for score visualization
 * Displays score 0-100 with dynamic coloring based on value
 *
 * @param {Object} props
 * @param {number} props.score - Score value 0-100
 * @param {string} props.label - Label to display below gauge
 * @param {number} [props.size] - Gauge size in pixels, defaults to 120
 * @returns {JSX.Element}
 */
export default function GaugeChart({ score = 0, label = '', size = 120 }) {
  const validScore = Math.max(0, Math.min(100, score));

  const gaugeColor = useMemo(() => {
    if (validScore >= 80) return 'rgb(74, 222, 128)'; // green-400
    if (validScore >= 60) return 'rgb(250, 204, 21)'; // yellow-400
    if (validScore >= 40) return 'rgb(251, 146, 60)'; // orange-400
    return 'rgb(239, 68, 68)'; // red-400
  }, [validScore]);

  const radius = size / 2 - 10;
  const circumference = Math.PI * radius;
  const strokeDashoffset = circumference * (1 - validScore / 100);

  // SVG dimensions
  const svgSize = size;
  const centerX = size / 2;
  const centerY = size / 2;

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size / 2 }}>
        <svg width={svgSize} height={size / 2} className="overflow-visible">
          {/* Background arc */}
          <path
            d={`M ${centerX - radius},${centerY} A ${radius},${radius} 0 0,1 ${centerX + radius},${centerY}`}
            fill="none"
            stroke="var(--border-secondary)"
            strokeWidth="8"
            strokeLinecap="round"
          />
          {/* Value arc */}
          <path
            d={`M ${centerX - radius},${centerY} A ${radius},${radius} 0 0,1 ${centerX + radius},${centerY}`}
            fill="none"
            stroke={gaugeColor}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            style={{
              transition: 'stroke-dashoffset 0.6s ease-in-out',
              transformOrigin: `${centerX}px ${centerY}px`
            }}
          />
          {/* Score + /100 as a single inline unit — no split lines */}
          <text
            x={centerX}
            y={centerY - 6}
            textAnchor="middle"
            dominantBaseline="middle"
          >
            <tspan
              fontSize="22"
              fontWeight="700"
              fill="var(--text-primary)"
            >{validScore}</tspan><tspan
              fontSize="10"
              fill="var(--text-tertiary)"
              dx="2"
              dy="6"
            >/100</tspan>
          </text>
        </svg>
      </div>
      {label && (
        <p style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium text-center">
          {label}
        </p>
      )}
    </div>
  );
}
