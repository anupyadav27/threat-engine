'use client';

import { TrendingUp, TrendingDown } from 'lucide-react';

/**
 * MetricCell — single metric cell inside a MetricStrip group.
 *
 * Props:
 *   label         — all-caps label string
 *   value         — display value (number or string)
 *   valueColor    — optional hex color override for value text
 *   delta         — signed number for trend (e.g. -23, +8)
 *   deltaGoodDown — if true, a negative delta is green (good)
 *   context       — small grey subtext (e.g. "vs last 7d", "internet-facing")
 *   noTrend       — if true, hides delta arrow entirely; shows context as plain text
 */
function MetricCell({ label, value, valueColor, delta, deltaGoodDown, context, noTrend }) {
  const deltaGood =
    delta != null ? (deltaGoodDown ? delta < 0 : delta > 0) : null;
  const deltaColor = deltaGood ? 'var(--accent-success)' : 'var(--accent-danger)';

  return (
    <div style={{ minWidth: 80, flexShrink: 0 }}>
      <p
        style={{
          color: 'var(--text-muted)',
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          marginBottom: 2,
          whiteSpace: 'nowrap',
        }}
      >
        {label}
      </p>
      <p
        style={{
          color: valueColor || 'var(--text-primary)',
          fontSize: 22,
          fontWeight: 800,
          lineHeight: 1.15,
          marginBottom: 2,
        }}
      >
        {value ?? '—'}
      </p>
      {!noTrend && delta != null ? (
        <span
          style={{
            color: deltaColor,
            fontSize: 11,
            display: 'flex',
            alignItems: 'center',
            gap: 2,
            whiteSpace: 'nowrap',
          }}
        >
          {deltaGood ? (
            <TrendingDown className="w-3 h-3" />
          ) : (
            <TrendingUp className="w-3 h-3" />
          )}
          {delta > 0 ? `+${delta}` : delta}
          {context ? ` ${context}` : ''}
        </span>
      ) : context ? (
        <p
          style={{
            color: 'var(--text-tertiary)',
            fontSize: 11,
            marginTop: 1,
            whiteSpace: 'nowrap',
          }}
        >
          {context}
        </p>
      ) : null}
    </div>
  );
}

/**
 * MetricStrip — compact 2-group horizontal metric strip for page KPIs.
 *
 * Usage:
 *   <MetricStrip groups={[
 *     {
 *       label: '🔴 RISK POSTURE',
 *       color: '#ef4444',
 *       cells: [
 *         { label: 'CRITICAL + HIGH', value: 487, valueColor: '#ef4444', delta: -23, deltaGoodDown: true, context: 'vs last 7d' },
 *         { label: 'INTERNET EXPOSED', value: 142, valueColor: '#f97316', context: 'publicly reachable' },
 *         { label: 'WORST FRAMEWORK', value: '69%', valueColor: '#ef4444', noTrend: true, context: 'HIPAA' },
 *       ],
 *     },
 *     {
 *       label: '🔵 OPERATIONS & COVERAGE',
 *       color: '#3b82f6',
 *       cells: [
 *         { label: 'MEAN TIME TO REMEDIATE', value: '4.2d', delta: -0.8, deltaGoodDown: true, context: 'avg all severities' },
 *         { label: 'REMEDIATION SLA', value: '91.2%', valueColor: '#22c55e', delta: +1.3, context: 'fixed within target' },
 *         { label: 'MONITORED ACCOUNTS', value: '4 / 6', valueColor: '#ef4444', noTrend: true, context: '2 credential issue' },
 *       ],
 *     },
 *   ]} />
 */
export default function MetricStrip({ groups = [], className = '' }) {
  return (
    <div
      className={`rounded-xl border overflow-hidden mb-6 ${className}`}
      style={{
        display: 'flex',
        backgroundColor: 'var(--bg-card)',
        borderColor: 'var(--border-primary)',
      }}
    >
      {groups.map((g, gi) => (
        <div
          key={gi}
          style={{
            flex: 1,
            padding: '14px 20px',
            borderLeft: gi > 0 ? '1px solid var(--border-primary)' : 'none',
            borderTop: `3px solid ${g.color}`,
          }}
        >
          {/* Group label */}
          <p
            style={{
              color: g.color,
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              marginBottom: 12,
            }}
          >
            {g.label}
          </p>

          {/* Metric cells */}
          <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap' }}>
            {(g.cells || []).map((c, ci) => (
              <MetricCell key={ci} {...c} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
