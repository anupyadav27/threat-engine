'use client';

import { CheckCircle2, XCircle, AlertTriangle, RefreshCw } from 'lucide-react';

export default function ValidationResult({ status, account, error, missingPermissions, onRetry }) {
  if (status === 'validating') {
    return (
      <div className="flex flex-col items-center gap-3 py-8">
        <RefreshCw className="w-8 h-8 animate-spin" style={{ color: 'var(--accent-primary)' }} />
        <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>Validating credentials…</div>
      </div>
    );
  }

  if (status === 'valid') {
    return (
      <div className="space-y-3">
        <div className="flex items-center gap-3 p-4 rounded-xl border" style={{ borderColor: 'rgba(34,197,94,0.3)', backgroundColor: 'rgba(34,197,94,0.08)' }}>
          <CheckCircle2 className="w-6 h-6 flex-shrink-0" style={{ color: '#22c55e' }} />
          <div>
            <div className="text-sm font-semibold" style={{ color: '#22c55e' }}>Credentials validated successfully</div>
            {account?.detected_account_id && (
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                Detected account: <span className="font-mono">{account.detected_account_id}</span>
              </div>
            )}
            {account?.detected_name && (
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                {account.detected_name}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (status === 'invalid') {
    return (
      <div className="space-y-3">
        <div className="flex items-start gap-3 p-4 rounded-xl border" style={{ borderColor: 'rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.08)' }}>
          <XCircle className="w-5 h-5 flex-shrink-0 mt-0.5" style={{ color: '#ef4444' }} />
          <div>
            <div className="text-sm font-semibold" style={{ color: '#ef4444' }}>Validation failed</div>
            {error && <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{error}</div>}
          </div>
        </div>

        {missingPermissions?.length > 0 && (
          <div className="p-3 rounded-lg border" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}>
            <div className="flex items-center gap-1.5 mb-2">
              <AlertTriangle size={13} style={{ color: '#fbbf24' }} />
              <span className="text-xs font-semibold" style={{ color: '#fbbf24' }}>Missing permissions</span>
            </div>
            <ul className="space-y-1">
              {missingPermissions.map((p, i) => (
                <li key={i} className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                  • {p}
                </li>
              ))}
            </ul>
          </div>
        )}

        {onRetry && (
          <button
            onClick={onRetry}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border hover:opacity-80 transition-opacity"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
          >
            <RefreshCw size={12} /> Try again
          </button>
        )}
      </div>
    );
  }

  return null;
}
