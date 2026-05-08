'use client';

import { ACCOUNT_TYPES, CATALOG_BY_TENANT_TYPE, getProviderColor } from '@/lib/catalog';

const TENANT_TYPE_LABELS = {
  cloud:         'Cloud Providers',
  secops:        'Code & Repository',
  vulnerability: 'Vulnerability Scanning',
  database:      'Database',
  middleware:    'Middleware',
};

// Provider icon abbreviations for display
const PROVIDER_ABBR = {
  aws:         'AWS', azure:       'Azure', gcp:        'GCP',
  oci:         'OCI', alicloud:    'AliCloud', ibm:     'IBM',
  k8s:         'K8s', github:      'GitHub', gitlab:    'GitLab',
  bitbucket:   'Bitbucket', azure_devops: 'ADO',
  agent:       '⚡', database:    '🗄️', middleware: '⚙️',
};

function ProviderTile({ accountType, selected, onClick }) {
  const color = getProviderColor(accountType.provider);
  const abbr  = PROVIDER_ABBR[accountType.provider] || accountType.provider.toUpperCase();

  return (
    <button
      onClick={() => onClick(accountType.id)}
      className="flex flex-col items-center gap-2 p-3 rounded-xl border-2 transition-all hover:scale-105"
      style={{
        borderColor: selected ? color : 'var(--border-primary)',
        backgroundColor: selected ? `${color}18` : 'var(--bg-card)',
        minWidth: 90,
      }}
    >
      <div
        className="w-10 h-10 rounded-lg flex items-center justify-center text-sm font-bold"
        style={{ backgroundColor: `${color}20`, color }}
      >
        {abbr.length <= 3 ? abbr : abbr.slice(0, 2)}
      </div>
      <span
        className="text-[11px] font-medium text-center leading-tight"
        style={{ color: selected ? color : 'var(--text-secondary)' }}
      >
        {accountType.label}
      </span>
      {accountType.is_agent && (
        <span className="text-[9px] px-1 py-0.5 rounded" style={{ backgroundColor: 'rgba(139,92,246,0.15)', color: '#a78bfa' }}>
          AGENT
        </span>
      )}
    </button>
  );
}

export default function TechnologyGrid({ selectedId, onSelect, filterTenantType }) {
  const groups = filterTenantType
    ? { [filterTenantType]: CATALOG_BY_TENANT_TYPE[filterTenantType] || [] }
    : CATALOG_BY_TENANT_TYPE;

  return (
    <div className="space-y-6">
      {Object.entries(groups).map(([tenantType, types]) => (
        <div key={tenantType}>
          <div className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
            {TENANT_TYPE_LABELS[tenantType] || tenantType}
          </div>
          <div className="flex flex-wrap gap-3">
            {types.map(at => (
              <ProviderTile
                key={at.id}
                accountType={at}
                selected={selectedId === at.id}
                onClick={onSelect}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
