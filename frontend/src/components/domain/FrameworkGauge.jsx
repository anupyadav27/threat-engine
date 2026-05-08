'use client';

import GaugeChart from '@/components/charts/GaugeChart';

/**
 * FrameworkGauge Component
 * Compact card combining GaugeChart with compliance framework information
 * Displays framework name, compliance score, and control passing ratio
 *
 * @param {Object} props
 * @param {string} props.name - Framework name (e.g., 'CIS Benchmarks')
 * @param {number} props.score - Compliance score 0-100
 * @param {number} props.totalControls - Total number of controls
 * @param {number} props.passedControls - Number of passed controls
 * @returns {JSX.Element}
 */
export default function FrameworkGauge({
  name = 'Framework',
  score = 0,
  totalControls = 0,
  passedControls = 0
}) {
  const controlRatio = totalControls > 0
    ? `${passedControls}/${totalControls}`
    : '0/0';

  const passedPercentage = totalControls > 0
    ? Math.round((passedControls / totalControls) * 100)
    : 0;

  return (
    <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="rounded-xl p-4 border w-48 inline-block transition-colors duration-200">
      <div className="flex flex-col items-center gap-3">
        {/* Gauge Chart */}
        <div className="w-full flex justify-center">
          <GaugeChart score={score} size={100} />
        </div>

        {/* Framework Info */}
        <div style={{ borderTopColor: 'var(--border-primary)' }} className="w-full text-center border-t pt-3 transition-colors duration-200">
          <h4 style={{ color: 'var(--text-primary)' }} className="text-sm font-medium truncate">
            {name}
          </h4>
          <div className="mt-2">
            <p style={{ color: 'var(--text-tertiary)' }} className="text-xs">
              Controls Passed
            </p>
            <p style={{ color: 'var(--text-secondary)' }} className="text-sm font-semibold mt-1">
              {controlRatio}
            </p>
            <div style={{ backgroundColor: 'var(--bg-tertiary)' }} className="mt-2 w-full rounded h-1 overflow-hidden transition-colors duration-200">
              <div
                className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-300"
                style={{ width: `${passedPercentage}%` }}
              />
            </div>
            <p style={{ color: 'var(--text-muted)' }} className="text-xs mt-1">
              {passedPercentage}% Compliant
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
