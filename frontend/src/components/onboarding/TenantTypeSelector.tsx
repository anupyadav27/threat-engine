'use client';

/**
 * TenantTypeSelector — step inside the Create Workspace modal.
 *
 * Displays three workspace types (cloud / vulnerability / secops) as
 * a card-grid selector. The selected value is forwarded to the parent
 * via onChange; the POST body must include tenant_type (AC1, AC2, AC3).
 */

import React from 'react';
import { Cloud, ShieldAlert, GitBranch } from 'lucide-react';

export type TenantType = 'cloud' | 'vulnerability' | 'secops';

interface TenantTypeOption {
  value: TenantType;
  label: string;
  description: string;
  Icon: React.FC<{ size?: number; className?: string }>;
}

const TENANT_TYPES: TenantTypeOption[] = [
  {
    value: 'cloud',
    label: 'Cloud Security',
    description: 'AWS, Azure, GCP, OCI, AliCloud accounts',
    Icon: Cloud,
  },
  {
    value: 'vulnerability',
    label: 'Vulnerability Scanning',
    description: 'Agent-based vulnerability scanning',
    Icon: ShieldAlert,
  },
  {
    value: 'secops',
    label: 'SecOps / Code Security',
    description: 'Git repositories and IaC scanning',
    Icon: GitBranch,
  },
];

interface Props {
  value: TenantType;
  onChange: (value: TenantType) => void;
}

export function TenantTypeSelector({ value, onChange }: Props) {
  return (
    <div className="space-y-2">
      <label
        className="block text-sm font-medium"
        style={{ color: 'var(--text-secondary)' }}
      >
        Workspace Type <span className="text-red-400">*</span>
      </label>
      <div className="grid grid-cols-1 gap-2">
        {TENANT_TYPES.map(({ value: typeVal, label, description, Icon }) => {
          const selected = value === typeVal;
          return (
            <button
              key={typeVal}
              type="button"
              onClick={() => onChange(typeVal)}
              className="flex items-start gap-3 w-full text-left px-3 py-3 rounded-lg transition-all"
              style={{
                backgroundColor: selected
                  ? 'rgba(99,102,241,0.12)'
                  : 'var(--bg-tertiary)',
                border: `1px solid ${selected ? 'var(--accent-primary)' : 'var(--border-primary)'}`,
                outline: 'none',
              }}
            >
              <span
                className="mt-0.5 flex-shrink-0 p-1 rounded"
                style={{
                  backgroundColor: selected
                    ? 'rgba(99,102,241,0.2)'
                    : 'var(--bg-secondary)',
                  color: selected ? 'var(--accent-primary)' : 'var(--text-muted)',
                }}
              >
                <Icon size={14} />
              </span>
              <span className="flex-1 min-w-0">
                <span
                  className="block text-sm font-medium"
                  style={{ color: 'var(--text-primary)' }}
                >
                  {label}
                </span>
                <span
                  className="block text-xs mt-0.5"
                  style={{ color: 'var(--text-tertiary)' }}
                >
                  {description}
                </span>
              </span>
              {/* Selection indicator */}
              <span
                className="mt-0.5 flex-shrink-0 w-4 h-4 rounded-full border-2 flex items-center justify-center"
                style={{
                  borderColor: selected
                    ? 'var(--accent-primary)'
                    : 'var(--border-primary)',
                  backgroundColor: selected
                    ? 'var(--accent-primary)'
                    : 'transparent',
                }}
              >
                {selected && (
                  <span
                    className="block w-1.5 h-1.5 rounded-full"
                    style={{ backgroundColor: 'white' }}
                  />
                )}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
