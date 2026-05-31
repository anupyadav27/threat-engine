'use client';

/**
 * AttackStory — step-by-step attack narrative rendered below the canvas strip.
 *
 * Props:
 *   steps  {Array}  — steps[] from the detail fetchView response
 *
 * Security: policy_statement is NEVER shown here. Edge type label used instead.
 *           credential_ref never rendered anywhere.
 */

import { useState } from 'react';
import { Zap, ChevronDown, ChevronUp } from 'lucide-react';
import styles from './attack-paths.module.css';

const SEV_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#6b7280',
};

function worstSeverity(step) {
  if (step.cves?.length > 0) {
    // Use severity from worst CVE by EPSS
    return step.cves[0].severity || 'high';
  }
  if (step.misconfigs?.length > 0) {
    return step.misconfigs[0].severity || 'medium';
  }
  if (step.cdr_actor_active) return 'critical';
  return 'low';
}

function StepRow({ step, index, isLast }) {
  const sev = worstSeverity(step);
  const sevColor = SEV_COLOR[sev] || '#6b7280';

  // Worst finding badge content
  const worstCve = step.cves?.length > 0
    ? [...step.cves].sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0))[0]
    : null;
  const worstMisconfig = step.misconfigs?.length > 0 ? step.misconfigs[0] : null;

  // Traversal reason or fallback
  const reason = step.traversal_reason?.slice(0, 100)
    || (step.edge_to_next ? `Accesses via ${step.edge_to_next.replace(/_/g, ' ')}` : null);

  // Edge label between hops (from current step to next)
  const edgeLabel = step.edge_to_next
    ? step.edge_to_next.replace(/_/g, ' ').toUpperCase()
    : null;

  const nodeName = (step.node_name || step.node_uid || '').slice(0, 30);

  return (
    <div>
      <div className={styles.storyStep}>
        {/* Hop circle */}
        <div
          className={styles.hopCircle}
          style={{ color: sevColor, borderColor: `${sevColor}60`, backgroundColor: `${sevColor}10` }}
        >
          {index + 1}
        </div>

        {/* Step content */}
        <div className="flex-1 min-w-0 space-y-1">
          {/* Node name + type */}
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="text-[11px] font-semibold truncate"
              style={{ color: 'rgba(255,255,255,0.9)' }}
              title={step.node_name || step.node_uid}
            >
              {nodeName}
            </span>
            {step.node_type && (
              <span
                className="text-[9px] font-bold px-1.5 py-0.5 rounded flex-shrink-0 uppercase"
                style={{ backgroundColor: 'rgba(255,255,255,0.07)', color: 'var(--text-secondary)' }}
              >
                {step.node_type.split('.').pop()}
              </span>
            )}
            {isLast && (
              <span
                className="text-[8px] font-bold px-1.5 py-0.5 rounded-full flex-shrink-0"
                style={{ backgroundColor: 'rgba(168,85,247,0.18)', color: '#a855f7' }}
              >
                CROWN JEWEL
              </span>
            )}
          </div>

          {/* Traversal reason */}
          {reason && (
            <p
              className="text-[10px] italic leading-snug"
              style={{ color: 'rgba(255,255,255,0.45)' }}
            >
              {reason}
            </p>
          )}

          {/* Worst finding badge */}
          <div className="flex items-center gap-2 flex-wrap">
            {worstCve ? (
              <span
                className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded"
                style={{
                  backgroundColor: 'rgba(239,68,68,0.15)',
                  color: '#f87171',
                  border: '1px solid rgba(239,68,68,0.3)',
                }}
              >
                {worstCve.cve_id}
                {worstCve.epss != null && (
                  <span style={{ fontWeight: 400, marginLeft: 4, color: '#fca5a5' }}>
                    EPSS {(worstCve.epss * 100).toFixed(1)}%
                  </span>
                )}
              </span>
            ) : worstMisconfig ? (
              <span
                className="text-[9px] font-medium px-1.5 py-0.5 rounded"
                style={{
                  backgroundColor: `${SEV_COLOR[worstMisconfig.severity] || '#6b7280'}15`,
                  color: SEV_COLOR[worstMisconfig.severity] || '#6b7280',
                  border: `1px solid ${SEV_COLOR[worstMisconfig.severity] || '#6b7280'}30`,
                }}
              >
                {worstMisconfig.severity?.toUpperCase()} — {(worstMisconfig.title || worstMisconfig.rule_id || '').slice(0, 40)}
              </span>
            ) : null}

            {/* CDR ACTIVE badge */}
            {step.cdr_actor_active && (
              <span
                className="flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded animate-pulse"
                style={{ backgroundColor: 'rgba(239,68,68,0.18)', color: '#ef4444' }}
              >
                <Zap style={{ width: 8, height: 8 }} /> CDR ACTIVE
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Edge label between hops */}
      {!isLast && edgeLabel && (
        <div
          className="flex items-center gap-1.5 pl-8 py-1"
          style={{ color: 'rgba(255,255,255,0.3)' }}
        >
          <div className="w-4 h-px" style={{ backgroundColor: 'rgba(255,255,255,0.15)' }} />
          <span className="text-[8px] font-bold uppercase tracking-widest">
            {edgeLabel.slice(0, 20)}
          </span>
        </div>
      )}
    </div>
  );
}

// ── AttackStory ───────────────────────────────────────────────────────────────

const COLLAPSE_THRESHOLD = 6;
const HEAD_COUNT = 3;
const TAIL_COUNT = 1;

export default function AttackStory({ steps = [] }) {
  const [expanded, setExpanded] = useState(false);

  if (steps.length === 0) {
    return (
      <p className="text-[11px] text-center py-4" style={{ color: 'var(--text-secondary)' }}>
        No step data available.
      </p>
    );
  }

  const isLong = steps.length > COLLAPSE_THRESHOLD;
  const hiddenCount = steps.length - HEAD_COUNT - TAIL_COUNT;

  // Decide which steps to render
  let visible;
  let tailSteps = [];
  if (!isLong || expanded) {
    visible = steps;
  } else {
    visible = steps.slice(0, HEAD_COUNT);
    tailSteps = steps.slice(steps.length - TAIL_COUNT);
  }

  return (
    <div>
      <p
        className="text-[9px] font-bold uppercase tracking-wide mb-3"
        style={{ color: 'var(--text-secondary)' }}
      >
        Attack Story
      </p>

      <div>
        {visible.map((step, i) => (
          <StepRow
            key={`step-${step.node_uid || i}-${i}`}
            step={step}
            index={i}
            isLast={i === steps.length - 1 && (expanded || !isLong)}
          />
        ))}

        {/* Expander for long paths */}
        {isLong && !expanded && (
          <>
            <button
              onClick={() => setExpanded(true)}
              className="flex items-center gap-2 py-2 pl-8 text-[10px] font-medium hover:opacity-80 transition-opacity"
              style={{ color: 'var(--text-secondary)' }}
            >
              <ChevronDown style={{ width: 12, height: 12 }} />
              {hiddenCount} more hop{hiddenCount !== 1 ? 's' : ''}
            </button>

            {/* Always show last step (tail) */}
            {tailSteps.map((step, i) => (
              <StepRow
                key={`tail-${step.node_uid || i}`}
                step={step}
                index={steps.length - TAIL_COUNT + i}
                isLast={i === tailSteps.length - 1}
              />
            ))}
          </>
        )}

        {isLong && expanded && (
          <button
            onClick={() => setExpanded(false)}
            className="flex items-center gap-2 py-2 pl-8 text-[10px] font-medium hover:opacity-80 transition-opacity"
            style={{ color: 'var(--text-secondary)' }}
          >
            <ChevronUp style={{ width: 12, height: 12 }} />
            Collapse
          </button>
        )}
      </div>
    </div>
  );
}
