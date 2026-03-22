'use client';

import { TrendingUp, TrendingDown } from 'lucide-react';

/**
 * KPI Card component for displaying key metrics.
 *
 * @component
 * @param {Object} props - Component props
 * @param {string} props.title - Card title/label
 * @param {string|number} props.value - Main value to display
 * @param {string} [props.subtitle] - Optional subtitle or description
 * @param {JSX.Element} [props.icon] - Optional icon element
 * @param {Object} [props.trend] - Optional trend data
 * @param {number} props.trend.value - Percentage change value
 * @param {'up'|'down'} props.trend.direction - Trend direction
 * @param {string} [props.color='blue'] - Optional color class (without 'text-' prefix)
 * @returns {JSX.Element}
 */
export default function KpiCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  color = 'blue',
}) {
  // Map color shorthand to full Tailwind class names
  const colorMap = {
    blue: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
    green: { bg: 'bg-green-500/20', text: 'text-green-400' },
    red: { bg: 'bg-red-500/20', text: 'text-red-400' },
    orange: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
    purple: { bg: 'bg-purple-500/20', text: 'text-purple-400' },
    yellow: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  };

  const selectedColor = colorMap[color] || colorMap.blue;
  const isTrendingUp = trend?.direction === 'up';
  const trendColor = isTrendingUp ? 'text-green-400' : 'text-red-400';

  return (
    <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="rounded-xl p-6 border hover:border-opacity-75 transition-colors duration-200">
      {/* Top Row: Icon & Title */}
      <div className="flex items-start justify-between mb-4">
        {icon && (
          <div className={`p-3 rounded-lg ${selectedColor.bg}`}>
            <div className={selectedColor.text}>{icon}</div>
          </div>
        )}
        <div className="flex-1 ml-4">
          <p style={{ color: 'var(--text-tertiary)' }} className="text-sm font-medium">{title}</p>
        </div>
      </div>

      {/* Main Value */}
      <div className="mb-4">
        <p style={{ color: 'var(--text-primary)' }} className="text-3xl font-bold">{value}</p>
      </div>

      {/* Bottom: Subtitle or Trend */}
      <div className="flex items-center gap-2">
        {trend ? (
          <>
            {isTrendingUp ? (
              <TrendingUp className={`w-4 h-4 ${trendColor}`} />
            ) : (
              <TrendingDown className={`w-4 h-4 ${trendColor}`} />
            )}
            <span className={`text-sm font-medium ${trendColor}`}>
              {isTrendingUp ? '+' : ''}{trend.value}%
            </span>
          </>
        ) : (
          <p style={{ color: 'var(--text-muted)' }} className="text-sm">{subtitle}</p>
        )}
      </div>
    </div>
  );
}
