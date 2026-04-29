'use client';

/**
 * Status Indicator component displaying a colored dot with label.
 *
 * @component
 * @param {Object} props - Component props
 * @param {'running'|'completed'|'failed'|'pending'|'pass'|'fail'} props.status - Status type
 * @returns {JSX.Element}
 */
export default function StatusIndicator({ status = 'pending' }) {
  const statusMap = {
    running: {
      dotColor: 'bg-blue-400',
      animation: 'animate-pulse',
      label: 'Running',
    },
    completed: {
      dotColor: 'bg-green-400',
      animation: '',
      label: 'Completed',
    },
    pass: {
      dotColor: 'bg-green-400',
      animation: '',
      label: 'Pass',
    },
    failed: {
      dotColor: 'bg-red-400',
      animation: '',
      label: 'Failed',
    },
    fail: {
      dotColor: 'bg-red-400',
      animation: '',
      label: 'Fail',
    },
    pending: {
      dotColor: 'bg-yellow-400',
      animation: '',
      label: 'Pending',
    },
  };

  const config = statusMap[status] || statusMap.pending;

  return (
    <div className="flex items-center gap-2">
      <div className={`w-2 h-2 rounded-full ${config.dotColor} ${config.animation}`} />
      <span style={{ color: 'var(--text-secondary)' }} className="text-sm">{config.label}</span>
    </div>
  );
}
