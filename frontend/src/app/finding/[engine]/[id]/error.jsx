'use client';

import { useEffect } from 'react';
import { AlertTriangle } from 'lucide-react';

/**
 * Error boundary for /finding/[engine]/[id].
 * Surfaces correlation_id from the BFF error envelope when available so
 * support can trace the request.
 */
export default function FindingError({ error, reset }) {
  useEffect(() => {
    console.error('[finding-detail] error', error);
  }, [error]);

  const correlationId = error?.correlationId || error?.cause?.correlationId || null;
  const traceId = error?.traceId || error?.cause?.traceId || null;

  return (
    <div className="p-8 max-w-2xl mx-auto">
      <div
        className="rounded-lg p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--accent-danger)',
          color: 'var(--text-primary)',
        }}
      >
        <div className="flex items-center gap-3 mb-3">
          <AlertTriangle className="w-6 h-6" style={{ color: 'var(--accent-danger)' }} />
          <h2 className="text-lg font-semibold">Failed to load finding</h2>
        </div>
        <p className="text-sm mb-4" style={{ color: 'var(--text-muted)' }}>
          {error?.message || 'An unexpected error occurred while loading this finding.'}
        </p>
        {(correlationId || traceId) && (
          <div
            className="text-xs font-mono p-3 rounded mb-4"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-muted)' }}
          >
            {correlationId && (
              <div>
                correlation_id: <span style={{ color: 'var(--text-primary)' }}>{correlationId}</span>
              </div>
            )}
            {traceId && (
              <div>
                trace_id: <span style={{ color: 'var(--text-primary)' }}>{traceId}</span>
              </div>
            )}
          </div>
        )}
        <button
          onClick={reset}
          className="px-4 py-2 rounded text-sm font-medium"
          style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
        >
          Try again
        </button>
      </div>
    </div>
  );
}
