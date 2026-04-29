'use client';

import { useState } from 'react';
import { X, AlertTriangle, AlertCircle, Info, ShieldAlert } from 'lucide-react';

/**
 * AlertBanner — dismissible callout strip.
 *
 * @param {{
 *   severity?: 'critical'|'warning'|'info',
 *   title: string,
 *   description?: string,
 *   items?: Array<{ label: string, link?: string, count?: number }>,
 *   action?: { label: string, onClick: () => void },
 *   dismissible?: boolean,
 * }} props
 */
export default function AlertBanner({
  severity = 'warning',
  title,
  description,
  items = [],
  action,
  dismissible = true,
}) {
  const [dismissed, setDismissed] = useState(false);
  if (dismissed) return null;

  const config = {
    critical: {
      bg: 'rgba(239,68,68,0.08)',
      border: 'rgba(239,68,68,0.35)',
      text: '#ef4444',
      Icon: ShieldAlert,
    },
    warning: {
      bg: 'rgba(249,115,22,0.08)',
      border: 'rgba(249,115,22,0.35)',
      text: '#f97316',
      Icon: AlertTriangle,
    },
    info: {
      bg: 'rgba(59,130,246,0.08)',
      border: 'rgba(59,130,246,0.35)',
      text: '#3b82f6',
      Icon: Info,
    },
  }[severity];

  const { Icon } = config;

  return (
    <div
      className="flex items-start gap-3 px-4 py-3 rounded-lg border transition-colors duration-200"
      style={{ backgroundColor: config.bg, borderColor: config.border }}
    >
      <Icon className="w-5 h-5 flex-shrink-0 mt-0.5" style={{ color: config.text }} />

      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold" style={{ color: config.text }}>{title}</p>
        {description && (
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{description}</p>
        )}
        {items.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-2">
            {items.map((item, idx) => (
              <span
                key={idx}
                className="text-xs px-2 py-0.5 rounded font-medium cursor-pointer hover:opacity-80"
                style={{ backgroundColor: config.bg, color: config.text, border: `1px solid ${config.border}` }}
                onClick={item.link ? () => window.location.href = item.link : undefined}
              >
                {item.count !== undefined && <strong>{item.count} </strong>}
                {item.label}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 flex-shrink-0">
        {action && (
          <button
            onClick={action.onClick}
            className="text-xs font-semibold px-3 py-1 rounded hover:opacity-80 transition-opacity"
            style={{ backgroundColor: config.text, color: '#fff' }}
          >
            {action.label}
          </button>
        )}
        {dismissible && (
          <button
            onClick={() => setDismissed(true)}
            className="p-0.5 rounded hover:opacity-60 transition-opacity"
            style={{ color: config.text }}
            title="Dismiss"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}
