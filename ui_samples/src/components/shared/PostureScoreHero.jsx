'use client';

import GaugeChart from '@/components/charts/GaugeChart';
import { TrendingUp, TrendingDown, AlertTriangle } from 'lucide-react';

const DOMAIN_LABELS = {
  iam:        'IAM',
  compliance: 'Compliance',
  threats:    'Threats',
  misconfigs: 'Misconfigs',
  dataSec:    'Data Sec',
};

const DOMAIN_COLORS = {
  iam:        '#f97316',
  compliance: '#22c55e',
  threats:    '#ef4444',
  misconfigs: '#eab308',
  dataSec:    '#3b82f6',
};

/**
 * PostureScoreHero — full-width security posture score card.
 *
 * @param {{
 *   score: number,
 *   prevScore: number,
 *   delta: number,
 *   status: string,
 *   criticalActions: number,
 *   domainScores: Record<string,number>,
 * }} props
 */
export default function PostureScoreHero({ score, prevScore, delta, status, criticalActions, domainScores }) {
  const isImproving = delta >= 0;
  const statusColor = score >= 75 ? '#22c55e' : score >= 50 ? '#f97316' : '#ef4444';

  return (
    <div
      className="rounded-xl p-6 border transition-colors duration-200"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      <div className="flex flex-col lg:flex-row items-center gap-8">

        {/* Left — gauge + score */}
        <div className="flex flex-col items-center gap-2 flex-shrink-0">
          <GaugeChart score={score} size={160} label="Overall Posture" />
          <div className="flex items-center gap-1.5 mt-1">
            {isImproving
              ? <TrendingUp className="w-4 h-4" style={{ color: '#22c55e' }} />
              : <TrendingDown className="w-4 h-4" style={{ color: '#ef4444' }} />}
            <span
              className="text-sm font-semibold"
              style={{ color: isImproving ? '#22c55e' : '#ef4444' }}
            >
              {isImproving ? '+' : ''}{delta} pts from last week
            </span>
          </div>
          <span
            className="text-xs px-2 py-0.5 rounded font-semibold mt-0.5"
            style={{ backgroundColor: `${statusColor}20`, color: statusColor }}
          >
            {status} Posture
          </span>
        </div>

        {/* Middle — domain scores */}
        <div className="flex-1 w-full">
          <p className="text-sm font-semibold mb-4" style={{ color: 'var(--text-secondary)' }}>
            Security Domain Breakdown
          </p>
          <div className="space-y-3">
            {Object.entries(domainScores || {}).map(([key, val]) => {
              const color = DOMAIN_COLORS[key] || '#888';
              const label = DOMAIN_LABELS[key] || key;
              const barColor = val >= 75 ? '#22c55e' : val >= 50 ? '#f97316' : '#ef4444';
              return (
                <div key={key} className="flex items-center gap-3">
                  <span className="text-xs w-24 flex-shrink-0" style={{ color: 'var(--text-secondary)' }}>
                    {label}
                  </span>
                  <div className="flex-1 h-2 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{ width: `${val}%`, backgroundColor: barColor }}
                    />
                  </div>
                  <span className="text-xs font-semibold w-8 text-right" style={{ color: barColor }}>
                    {val}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right — quick stats */}
        <div
          className="flex-shrink-0 rounded-lg p-4 border text-center w-44"
          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
        >
          <AlertTriangle className="w-8 h-8 mx-auto mb-2" style={{ color: '#f97316' }} />
          <p className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>{criticalActions}</p>
          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>Critical actions needed</p>
          <p className="text-xs mt-3" style={{ color: 'var(--text-muted)' }}>
            Score:{' '}
            <span className="font-semibold" style={{ color: statusColor }}>{score}/100</span>
          </p>
        </div>
      </div>
    </div>
  );
}
