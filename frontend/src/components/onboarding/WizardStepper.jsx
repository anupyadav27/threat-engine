'use client';

import { Check } from 'lucide-react';

const STEP_LABELS = {
  SELECT_TECHNOLOGY:       'Select Technology',
  SELECT_AUTH_METHOD:      'Auth Method',
  SHOW_PREREQUISITES:      'Prerequisites',
  CREDENTIAL_FORM:         'Credentials',
  VALIDATE:                'Validate',
  ATTACH_SCHEDULE:         'Schedule',
  GENERATE_TOKEN:          'Generate Token',
  SHOW_INSTALL_COMMAND:    'Install Agent',
  WAITING_FOR_AGENT:       'Awaiting Agent',
};

export default function WizardStepper({ steps, currentStep }) {
  const currentIdx = steps.indexOf(currentStep);

  return (
    <div className="flex items-center gap-0 mb-8">
      {steps.map((step, idx) => {
        const done    = idx < currentIdx;
        const active  = idx === currentIdx;
        const pending = idx > currentIdx;

        return (
          <div key={step} className="flex items-center flex-1 min-w-0">
            {/* Circle */}
            <div className="flex flex-col items-center flex-shrink-0">
              <div
                className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-semibold transition-colors"
                style={{
                  backgroundColor: done ? 'var(--accent-primary)' : active ? 'rgba(59,130,246,0.2)' : 'var(--bg-tertiary)',
                  border: `2px solid ${done || active ? 'var(--accent-primary)' : 'var(--border-primary)'}`,
                  color: done ? 'white' : active ? 'var(--accent-primary)' : 'var(--text-muted)',
                }}
              >
                {done ? <Check size={12} /> : idx + 1}
              </div>
              <span
                className="mt-1 text-[10px] text-center leading-tight max-w-[60px]"
                style={{ color: active ? 'var(--accent-primary)' : done ? 'var(--text-secondary)' : 'var(--text-muted)' }}
              >
                {STEP_LABELS[step] || step}
              </span>
            </div>

            {/* Connector line */}
            {idx < steps.length - 1 && (
              <div
                className="flex-1 h-0.5 mx-1 mb-4 transition-colors"
                style={{ backgroundColor: done ? 'var(--accent-primary)' : 'var(--border-primary)' }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
