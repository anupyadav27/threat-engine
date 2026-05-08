'use client';

/**
 * Severity Badge component for displaying severity levels.
 *
 * @component
 * @param {Object} props - Component props
 * @param {'critical'|'high'|'medium'|'low'|'info'} props.severity - Severity level
 * @returns {JSX.Element}
 */
export default function SeverityBadge({ severity = 'info' }) {
  const severityMap = {
    critical: {
      bg: 'bg-red-500/20',
      text: 'text-red-400',
      label: 'Critical',
    },
    high: {
      bg: 'bg-orange-500/20',
      text: 'text-orange-400',
      label: 'High',
    },
    medium: {
      bg: 'bg-yellow-500/20',
      text: 'text-yellow-400',
      label: 'Medium',
    },
    low: {
      bg: 'bg-blue-500/20',
      text: 'text-blue-400',
      label: 'Low',
    },
    info: {
      bg: 'bg-slate-500/20',
      text: 'text-slate-400',
      label: 'Info',
    },
  };

  const config = severityMap[severity] || severityMap.info;

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.bg} ${config.text}`}
    >
      {config.label}
    </span>
  );
}
