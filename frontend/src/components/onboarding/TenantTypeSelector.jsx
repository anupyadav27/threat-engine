'use client';

const TENANT_TYPES = [
  { value: 'enterprise', label: 'Enterprise' },
  { value: 'smb',        label: 'SMB' },
  { value: 'startup',    label: 'Startup' },
];

export function TenantTypeSelector({ value, onChange }) {
  return (
    <div>
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        Tenant Type
      </label>
      <select
        value={value || ''}
        onChange={e => onChange?.(e.target.value)}
        className="w-full rounded-xl border px-3 py-2.5 text-sm bg-transparent focus:outline-none"
        style={{ borderColor: 'var(--border-primary)', color: 'var(--text-primary)', backgroundColor: 'var(--bg-primary)' }}
      >
        <option value="">Select type…</option>
        {TENANT_TYPES.map(t => (
          <option key={t.value} value={t.value}>{t.label}</option>
        ))}
      </select>
    </div>
  );
}

export default TenantTypeSelector;
