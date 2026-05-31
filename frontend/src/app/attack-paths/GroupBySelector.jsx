'use client';

/**
 * GroupBySelector — dropdown with 5 grouping dimensions.
 *
 * Props:
 *   value     {string}    — currently selected groupBy key
 *   onChange  {function}  — called with new groupBy string
 */

import { ChevronDown } from 'lucide-react';

const GROUP_BY_OPTIONS = [
  { value: 'severity',    label: 'Severity' },
  { value: 'crown_jewel', label: 'Crown Jewel' },
  { value: 'entry_point', label: 'Entry Point' },
  { value: 'technique',   label: 'Attack Technique' },
  { value: 'cdr_status',  label: 'CDR Status' },
];

export default function GroupBySelector({ value, onChange }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] font-medium flex-shrink-0" style={{ color: 'var(--text-secondary)' }}>
        Group by
      </span>
      <div className="relative">
        <select
          value={value}
          onChange={e => onChange(e.target.value)}
          className="appearance-none text-[11px] font-semibold px-3 py-1.5 pr-7 rounded-lg border cursor-pointer focus:outline-none"
          style={{
            backgroundColor: 'var(--bg-secondary)',
            borderColor: 'rgba(255,255,255,0.12)',
            color: 'var(--text-primary)',
          }}
        >
          {GROUP_BY_OPTIONS.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
        <ChevronDown
          className="absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none"
          style={{ width: 11, height: 11, color: 'var(--text-secondary)' }}
        />
      </div>
    </div>
  );
}
