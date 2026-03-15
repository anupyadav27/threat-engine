'use client';

import { useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip
} from 'recharts';
import { SEVERITY_COLORS, SEVERITY_LABELS } from '@/lib/constants';

/**
 * SeverityDonut Component
 * Displays severity distribution as a donut chart with center text showing total count
 *
 * @param {Object} props
 * @param {Object} props.data - Severity data { critical, high, medium, low }
 * @param {number} props.data.critical - Critical count
 * @param {number} props.data.high - High count
 * @param {number} props.data.medium - Medium count
 * @param {number} props.data.low - Low count
 * @param {string} [props.title] - Optional chart title
 * @returns {JSX.Element}
 */
export default function SeverityDonut({ data, title = 'Severity Distribution' }) {
  const chartData = useMemo(() => {
    return [
      {
        name: SEVERITY_LABELS.critical,
        value: data.critical || 0,
        severity: 'critical'
      },
      {
        name: SEVERITY_LABELS.high,
        value: data.high || 0,
        severity: 'high'
      },
      {
        name: SEVERITY_LABELS.medium,
        value: data.medium || 0,
        severity: 'medium'
      },
      {
        name: SEVERITY_LABELS.low,
        value: data.low || 0,
        severity: 'low'
      }
    ];
  }, [data]);

  const total = useMemo(() => {
    return chartData.reduce((sum, item) => sum + item.value, 0);
  }, [chartData]);

  const customLabelContent = () => {
    return (
      <g>
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="text-xl font-bold"
          fill="var(--text-primary)"
        >
          {total}
        </text>
        <text
          x="50%"
          y="55%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="text-xs"
          fill="var(--text-tertiary)"
        >
          Total
        </text>
      </g>
    );
  };

  const CustomLegend = (props) => {
    const { payload } = props;
    return (
      <div className="flex flex-wrap justify-center gap-4 mt-4">
        {payload?.map((entry, index) => {
          const item = chartData[index];
          return (
            <div key={`legend-${entry.value}`} className="flex items-center gap-2">
              <div
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: entry.color }}
              />
              <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
                {entry.value}: {item?.value || 0}
              </span>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="rounded-xl p-4 border transition-colors duration-200">
      {title && (
        <h3 style={{ color: 'var(--text-primary)' }} className="text-sm font-semibold mb-4">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={90}
            paddingAngle={2}
            dataKey="value"
            label={false}
          >
            {chartData.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={SEVERITY_COLORS[entry.severity]}
              />
            ))}
            {customLabelContent()}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
              borderRadius: '0.5rem',
              color: 'var(--text-primary)'
            }}
            cursor={{ fill: 'rgba(59, 130, 246, 0.1)' }}
            formatter={(value) => value.toLocaleString()}
          />
        </PieChart>
      </ResponsiveContainer>
      <CustomLegend payload={chartData.map((item) => ({
        value: item.name,
        color: SEVERITY_COLORS[item.severity]
      }))} />
    </div>
  );
}
