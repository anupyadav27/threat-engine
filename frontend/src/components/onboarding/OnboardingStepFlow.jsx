'use client';

import { CheckCircle, Circle } from 'lucide-react';

export default function OnboardingStepFlow({ steps = [] }) {
  if (!steps.length) return null;
  return (
    <div className="flex items-start gap-0 mb-4">
      {steps.map((step, idx) => (
        <div key={idx} className="flex items-center flex-1">
          <div className="flex flex-col items-center">
            <div className="flex items-center justify-center w-8 h-8 rounded-full border-2"
              style={{
                borderColor: step.done ? 'var(--accent-primary)' : 'var(--border-primary)',
                backgroundColor: step.done ? 'var(--accent-primary)' : 'transparent',
              }}>
              {step.done
                ? <CheckCircle className="w-4 h-4 text-white" />
                : <span className="text-xs font-bold" style={{ color: 'var(--text-muted)' }}>{idx + 1}</span>
              }
            </div>
            <span className="text-xs mt-1 text-center max-w-[80px]" style={{ color: step.done ? 'var(--text-primary)' : 'var(--text-muted)' }}>
              {step.label}
            </span>
          </div>
          {idx < steps.length - 1 && (
            <div className="flex-1 h-0.5 mb-5 mx-1" style={{ backgroundColor: step.done ? 'var(--accent-primary)' : 'var(--border-primary)' }} />
          )}
        </div>
      ))}
    </div>
  );
}
