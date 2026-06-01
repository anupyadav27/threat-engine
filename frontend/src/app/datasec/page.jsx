'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Database, AlertTriangle, Globe, Fingerprint,
  ShieldCheck, Lock,
} from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import { subscribeRefresh, emitRefresh } from '@/lib/refreshBus';
import EngineShell from '@/components/shared/EngineShell';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';

// ── Palette ───────────────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
  blue: '#3b82f6', teal: '#14b8a6', purple: '#8b5cf6',
};

// Canonical datasec modules — sourced from engines/datasec/config/rule_module_mapping.yaml
// and rule YAML data_security.modules[] field, stored as datasec_modules[] on findings
const MODULE_LABELS = {
  data_protection_encryption: 'Data Protection & Encryption',
  data_access_governance:     'Access Governance',
  data_activity_monitoring:   'Activity Monitoring',
  data_residency:             'Data Residency',
  data_compliance:            'Data Compliance',
  data_classification:        'Data Classification',
  // aliases from rule metadata YAMLs
  encryption:                 'Data Protection & Encryption',
  encryption_at_rest:         'Data Protection & Encryption',
  sensitive_data_protection:  'Data Protection & Encryption',
  access_control:             'Access Governance',
  public_access_prevention:   'Access Governance',
  audit_logging:              'Activity Monitoring',
  data_access_governance:     'Access Governance',
  // posture_category fallbacks (BFF normalised field)
  data_protection:            'Data Compliance',
  dlp:                        'Data Compliance',
};

function resolveModule(f) {
  // Primary: datasec_modules[] set by FindingEnricher from rule_metadata.data_security.modules
  const mods = f.datasec_modules || f.data_security_modules || [];
  if (mods.length) return MODULE_LABELS[mods[0]] || mods[0].replace(/_/g, ' ');
  // Fallback: posture_category / domain from check engine
  const raw = f.posture_category || f.domain || f.security_domain || '';
  return MODULE_LABELS[raw.toLowerCase()] || raw.replace(/_/g, ' ') || 'Other';
}

// ── KPI Card ──────────────────────────────────────────────────────────────────
function KpiCard({ label, value, color, icon: Icon }) {
  return (
    <div className="flex items-center gap-3 px-5 py-4 rounded-xl border"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
        style={{ backgroundColor: `${color}18` }}>
        <Icon className="w-4.5 h-4.5" style={{ color }} />
      </div>
      <div>
        <p className="text-2xl font-bold leading-none mb-0.5" style={{ color }}>{value ?? '—'}</p>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</p>
      </div>
    </div>
  );
}

// ── Asset cell: icon + name + type ────────────────────────────────────────────
function AssetCell({ uid, type, provider }) {
  const icon =
    /s3|bucket/.test(type)     ? '🪣'
    : /rds|database/.test(type) ? '🗄️'
    : /ec2|instance/.test(type) ? '🖥️'
    : /lambda/.test(type)       ? 'λ'
    : /iam/.test(type)          ? '🔑'
    : '📦';
  const name = uid ? (uid.split('/').pop() || uid.split(':').pop() || uid) : '—';
  const cleanType = (type || '').replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ');
  return (
    <div className="flex items-center gap-2 min-w-0">
      <span className="text-sm shrink-0 leading-none">{icon}</span>
      <div className="min-w-0">
        <p className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }} title={uid}>
          {name}
        </p>
        <p className="text-[10px] mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>
          {cleanType || '—'}
        </p>
      </div>
    </div>
  );
}

// ── Module badge ──────────────────────────────────────────────────────────────
function ModuleBadge({ value }) {
  const v = (value || '').toLowerCase();
  const style =
    v.includes('encrypt')       ? { bg: 'rgba(59,130,246,0.15)',  color: '#60a5fa' }
    : v.includes('dlp')          ? { bg: 'rgba(239,68,68,0.15)',   color: '#f87171' }
    : v.includes('data protect') ? { bg: 'rgba(245,158,11,0.15)',  color: '#fbbf24' }
    : v.includes('class')        ? { bg: 'rgba(139,92,246,0.15)',  color: '#a78bfa' }
    : v.includes('access')       ? { bg: 'rgba(20,184,166,0.15)',  color: '#2dd4bf' }
    : v.includes('residency')    ? { bg: 'rgba(99,102,241,0.15)',  color: '#818cf8' }
    : v.includes('backup')       ? { bg: 'rgba(16,185,129,0.15)',  color: '#34d399' }
    : { bg: 'var(--bg-tertiary)', color: 'var(--text-muted)' };
  return (
    <span className="text-xs font-medium px-2 py-0.5 rounded"
      style={{ backgroundColor: style.bg, color: style.color }}>
      {value || '—'}
    </span>
  );
}

// ── Columns ───────────────────────────────────────────────────────────────────
const COLUMNS = [
  {
    accessorKey: 'severity',
    header: 'Severity',
    size: 90,
    cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
  },
  {
    accessorKey: 'module',
    header: 'Module',
    size: 150,
    cell: ({ getValue }) => <ModuleBadge value={getValue()} />,
  },
  {
    accessorKey: 'title',
    header: 'Config Finding',
    size: 260,
    cell: ({ getValue, row }) => (
      <div className="min-w-0">
        <p className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }}
          title={getValue()}>
          {getValue() || row.original.rule_id || '—'}
        </p>
        <code className="text-[10px] block truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>
          {row.original.rule_id || ''}
        </code>
      </div>
    ),
  },
  {
    accessorKey: 'resource_uid',
    header: 'Asset',
    size: 200,
    cell: ({ getValue, row }) => (
      <AssetCell
        uid={getValue()}
        type={row.original.resource_type}
        provider={row.original.provider}
      />
    ),
  },
  {
    accessorKey: 'account_id',
    header: 'Account',
    size: 150,
    cell: ({ getValue, row }) => {
      const p = (row.original.provider || 'aws').toLowerCase();
      const cls =
        p === 'aws'   ? 'bg-orange-500/15 text-orange-400'
        : p === 'gcp' ? 'bg-blue-500/15 text-blue-400'
        : 'bg-sky-500/15 text-sky-400';
      return (
        <div className="flex items-center gap-2 min-w-0">
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ${cls}`}>
            {p.toUpperCase()}
          </span>
          <code className="text-xs truncate" style={{ color: 'var(--text-secondary)' }}>
            {getValue() || '—'}
          </code>
        </div>
      );
    },
  },
  {
    accessorKey: 'region',
    header: 'Region',
    size: 110,
    cell: ({ getValue }) => (
      <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
        {getValue() || '—'}
      </span>
    ),
  },
  {
    accessorKey: 'risk_score',
    header: 'Risk',
    size: 80,
    cell: ({ getValue }) => {
      const v = getValue();
      if (v == null) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
      const color = v >= 75 ? C.critical : v >= 50 ? C.high : v >= 25 ? C.medium : C.low;
      return (
        <div className="flex items-center gap-1.5">
          <div className="w-10 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            <div className="h-full rounded-full" style={{ width: `${v}%`, backgroundColor: color }} />
          </div>
          <span className="text-xs font-bold" style={{ color }}>{v}</span>
        </div>
      );
    },
  },
  {
    accessorKey: 'is_internet_exposed',
    header: 'Exposed',
    size: 80,
    cell: ({ getValue }) => {
      const v = getValue();
      return v
        ? <div className="flex items-center gap-1"><Globe className="w-3 h-3" style={{ color: C.critical }} /><span className="text-xs font-medium" style={{ color: C.critical }}>Yes</span></div>
        : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>No</span>;
    },
  },
  {
    accessorKey: 'status',
    header: 'Status',
    size: 70,
    cell: ({ getValue }) => {
      const v = getValue() || 'FAIL';
      return (
        <span className={`text-xs font-bold px-2 py-0.5 rounded ${v === 'FAIL' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
          {v}
        </span>
      );
    },
  },
];

// ── Page ──────────────────────────────────────────────────────────────────────
export default function DataSecurityPage() {
  const { data, loading, error, refetch } = useViewFetch('datasec');
  useEffect(() => subscribeRefresh(() => refetch()), [refetch]);

  const [selectedFinding, setSelectedFinding] = useState(null);

  // Merge datasec findings + DLP into one pool, deduplicated
  const allFindings = useMemo(() => {
    const raw = [...(data?.findings || []), ...(data?.dlp || [])];
    const seen = new Set();
    return raw
      .filter(f => {
        const k = f.finding_id || (f.rule_id + (f.resource_uid || ''));
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .map(f => ({ ...f, module: resolveModule(f) }));
  }, [data]);

  // KPIs
  const kpis = useMemo(() => {
    let critical = 0, exposed = 0;
    const modules = new Set();
    const assets  = new Set();
    allFindings.forEach(f => {
      if ((f.severity || '').toLowerCase() === 'critical') critical++;
      if (f.is_internet_exposed) exposed++;
      modules.add(f.module);
      assets.add(f.resource_uid || f.resource_id);
    });
    return {
      total:    allFindings.length,
      assets:   assets.size,
      critical,
      exposed,
      modules:  modules.size,
    };
  }, [allFindings]);

  return (
    <EngineShell
      icon={Database}
      title="Data Security"
      description={`${kpis.total} config findings · ${kpis.assets} assets · ${kpis.modules} modules`}
      onRefresh={() => emitRefresh()}
      refreshing={loading}
    >
      <div className="space-y-5">

        {/* ── KPIs ── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <KpiCard label="Total Findings"    value={kpis.total}    color={C.blue}     icon={Database}      />
          <KpiCard label="Critical"          value={kpis.critical} color={C.critical} icon={AlertTriangle}  />
          <KpiCard label="Affected Assets"   value={kpis.assets}   color={C.purple}   icon={Fingerprint}   />
          <KpiCard label="Exposed Resources" value={kpis.exposed}  color={C.high}     icon={Globe}         />
        </div>

        {/* ── Unified findings table ── */}
        {/* GroupBy picker (built into DataTable toolbar) lets user switch between
            Module, Asset, Severity, Provider — no separate tabs needed */}
        <div className="rounded-xl border overflow-hidden"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <DataTable
            data={allFindings}
            columns={COLUMNS}
            loading={loading}
            pageSize={25}
            defaultDensity="compact"
            persistenceKey="datasec-unified"
            initialGroupBy="module"
            emptyMessage={error ? 'Failed to load findings.' : 'No data security findings found.'}
            onRowClick={row => setSelectedFinding(row?.original ?? row)}
          />
        </div>

      </div>

      {/* ── Detail panel ── */}
      {selectedFinding && (
        <FindingDetailPanel
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          context={{ engine: 'datasec' }}
        />
      )}
    </EngineShell>
  );
}
