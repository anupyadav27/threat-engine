'use client';

import { useEffect, useState } from 'react';
import { getFromEngine } from '@/lib/api';

// Validate finding_id is a UUID before making the engine call
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function StepBadge({ n }) {
  return (
    <span className="flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold"
      style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
      {n}
    </span>
  );
}

function MitreBadge({ technique }) {
  if (!technique) return null;
  return (
    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
      style={{ backgroundColor: 'rgba(249,115,22,0.12)', color: '#f97316' }}>
      {technique}
    </span>
  );
}

function AnomalyBadge({ score }) {
  if (!score || score <= 0) return null;
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? '#ef4444' : pct >= 60 ? '#f97316' : '#eab308';
  return (
    <span className="text-[10px] font-medium px-1.5 py-0.5 rounded"
      style={{ backgroundColor: 'rgba(239,68,68,0.08)', color }}>
      anomaly {pct}%
    </span>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-3 animate-pulse">
      {[1, 2, 3].map(i => (
        <div key={i} className="flex items-start gap-3">
          <div className="w-6 h-6 rounded-full flex-shrink-0" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="flex-1 space-y-1.5 pt-0.5">
            <div className="h-3 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', width: '60%' }} />
            <div className="h-2.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', width: '80%' }} />
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Shows the ordered event chain for L2 correlation findings.
 * Only renders for findings with rule_source === 'log_correlation'.
 */
export default function CorrelationTimeline({ findingId }) {
  const [steps,   setSteps]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);

  useEffect(() => {
    if (!findingId) { setLoading(false); return; }

    if (!UUID_RE.test(findingId)) {
      setError('Invalid finding ID');
      setLoading(false);
      return;
    }

    let cancelled = false;
    setSteps([]);
    setError(null);
    setLoading(true);

    getFromEngine('cdr', `/api/v1/cdr/findings/${findingId}/timeline`)
      .then(data => {
        if (cancelled) return;
        if (data?.error) {
          setError(data.error);
        } else {
          const raw = data?.contributing_steps || [];
          setSteps([...raw].sort((a, b) => a.step - b.step));
        }
      })
      .catch(() => { if (!cancelled) setError('Failed to load timeline'); })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [findingId]);

  if (loading) return <LoadingSkeleton />;

  if (error) {
    return (
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Timeline unavailable: {error}
      </p>
    );
  }

  if (steps.length === 0) {
    return (
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        No step detail available for this finding.
      </p>
    );
  }

  return (
    <div className="space-y-0">
      {steps.map((step, idx) => {
        const time   = step.event_time ? new Date(step.event_time).toLocaleTimeString() : '—';
        const actor  = (step.actor_principal || '').split('/').pop() || step.actor_principal || '—';
        const target = (step.resource_uid    || '').split('/').pop() || step.resource_uid    || '';
        const isLast = idx === steps.length - 1;

        return (
          <div key={idx} className="relative flex items-start gap-3">
            {/* vertical connector line */}
            {!isLast && (
              <div className="absolute left-3 top-7 bottom-0 w-px"
                style={{ backgroundColor: 'var(--border-primary)' }} />
            )}

            <StepBadge n={step.step ?? idx + 1} />

            <div className={`flex-1 pb-4 ${isLast ? '' : ''}`}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
                  {step.operation || 'Unknown operation'}
                </span>
                <MitreBadge technique={step.mitre_technique} />
                <AnomalyBadge score={step.anomaly_score} />
              </div>

              <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{time}</span>
                {actor && (
                  <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{actor}</span>
                )}
                {step.source_ip && (
                  <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                    {step.source_ip}
                  </span>
                )}
                {target && (
                  <span className="text-xs font-mono truncate max-w-[140px]" style={{ color: 'var(--text-muted)' }}>
                    {target}
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
