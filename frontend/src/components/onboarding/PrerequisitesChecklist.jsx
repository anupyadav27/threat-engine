'use client';

import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';

function PrereqItem({ step, index }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border rounded-lg overflow-hidden" style={{ borderColor: 'var(--border-primary)' }}>
      <button
        onClick={() => step.detail && setExpanded(e => !e)}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:opacity-80 transition-opacity"
        style={{ backgroundColor: 'var(--bg-card)' }}
      >
        <span
          className="flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold mt-0.5"
          style={{ backgroundColor: 'rgba(59,130,246,0.15)', color: 'var(--accent-primary)' }}
        >
          {index + 1}
        </span>
        <span className="flex-1 text-sm" style={{ color: 'var(--text-primary)' }}>
          {step.step}
        </span>
        {step.detail && (
          <span className="flex-shrink-0 mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </span>
        )}
      </button>
      {expanded && step.detail && (
        <div
          className="px-4 pb-3 pt-0 text-xs border-t"
          style={{ color: 'var(--text-muted)', borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}
        >
          {step.detail}
        </div>
      )}
    </div>
  );
}

export default function PrerequisitesChecklist({ authModel }) {
  if (!authModel?.admin_prerequisites?.length) {
    return (
      <div className="text-sm py-4" style={{ color: 'var(--text-muted)' }}>
        No prerequisites required for this authentication method.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 mb-3">
        <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
          Before you start
        </div>
        <span
          className="text-[10px] px-1.5 py-0.5 rounded"
          style={{ backgroundColor: 'rgba(245,158,11,0.15)', color: '#fbbf24' }}
        >
          Complete these steps in your cloud console
        </span>
      </div>
      {authModel.admin_prerequisites.map((prereq, idx) => (
        <PrereqItem key={idx} step={prereq} index={idx} />
      ))}
    </div>
  );
}
