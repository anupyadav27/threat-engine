'use client';

import { useState, useMemo } from 'react';
import {
  AlertTriangle, ShieldAlert, ShieldCheck, Shield,
  Search, SlidersHorizontal, RefreshCw,
} from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import { subscribeRefresh } from '@/lib/refreshBus';
import DataTable from '@/components/shared/DataTable';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';
import SeverityBadge from '@/components/shared/SeverityBadge';

// ── Palette ───────────────────────────────────────────────────────────────────
const SEV_COLOR = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};
const STATUS_COLOR = { FAIL: '#ef4444', PASS: '#22c55e' };

// ── KPI Stat Card ─────────────────────────────────────────────────────────────
function StatCard({ label, value, color, icon: Icon }) {
  return (
    <div className="flex items-center gap-3 px-5 py-4 rounded-xl border"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
        style={{ backgroundColor: `${color}18` }}>
        <Icon className="w-4.5 h-4.5" style={{ color }} />
      </div>
      <div>
        <p className="text-xl font-bold leading-none mb-0.5" style={{ color }}>{value ?? '—'}</p>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</p>
      </div>
    </div>
  );
}

// ── Filter Chip ───────────────────────────────────────────────────────────────
function FilterChip({ label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className="px-3 py-1.5 rounded-full text-xs font-medium border transition-all"
      style={{
        backgroundColor: active ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
        color: active ? '#fff' : 'var(--text-secondary)',
        borderColor: active ? 'var(--accent-primary)' : 'var(--border-primary)',
      }}>
      {label}
    </button>
  );
}

// ── Column definitions ────────────────────────────────────────────────────────
const COLUMNS = [
  {
    accessorKey: 'severity',
    header: 'Severity',
    size: 90,
    cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
  },
  {
    accessorKey: 'title',
    header: 'Finding',
    size: 260,
    cell: ({ getValue, row }) => (
      <div className="min-w-0">
        <p className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }} title={getValue()}>
          {getValue() || row.original.rule_id || '—'}
        </p>
        {row.original.rule_id && (
          <code className="text-[10px] block truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {row.original.rule_id}
          </code>
        )}
      </div>
    ),
  },
  {
    accessorKey: 'resource_type',
    header: 'Resource Type',
    size: 140,
    cell: ({ getValue }) => (
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {(getValue() || '').replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ') || '—'}
      </span>
    ),
  },
  {
    accessorKey: 'provider',
    header: 'Cloud',
    size: 70,
    cell: ({ getValue }) => (
      <span className="text-xs font-medium px-2 py-0.5 rounded"
        style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
        {(getValue() || 'AWS').toUpperCase()}
      </span>
    ),
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
    accessorKey: 'account_id',
    header: 'Account',
    size: 140,
    cell: ({ getValue }) => (
      <code className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {getValue() || '—'}
      </code>
    ),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    size: 80,
    cell: ({ getValue }) => {
      const v = getValue() || 'FAIL';
      return (
        <span className="text-xs font-bold px-2 py-0.5 rounded"
          style={{ backgroundColor: `${STATUS_COLOR[v] || '#888'}20`, color: STATUS_COLOR[v] || '#888' }}>
          {v}
        </span>
      );
    },
  },
  {
    accessorKey: 'risk_score',
    header: 'Risk',
    size: 70,
    cell: ({ getValue }) => {
      const score = getValue();
      if (score == null) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
      const color = score >= 75 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#eab308' : '#22c55e';
      return (
        <div className="flex items-center gap-1.5">
          <div className="w-12 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            <div className="h-full rounded-full" style={{ width: `${Math.min(score, 100)}%`, backgroundColor: color }} />
          </div>
          <span className="text-xs font-bold" style={{ color }}>{score}</span>
        </div>
      );
    },
  },
  {
    accessorKey: 'first_seen_at',
    header: 'First Seen',
    size: 100,
    cell: ({ getValue }) => {
      const v = getValue();
      return (
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
          {v ? new Date(v).toLocaleDateString() : '—'}
        </span>
      );
    },
  },
];

const SEV_FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low'];

// ── Page ──────────────────────────────────────────────────────────────────────
export default function InvestigationPage() {
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [sevFilter, setSevFilter]             = useState('All');
  const [statusFilter, setStatusFilter]       = useState('All');

  // Fetch unified findings from misconfig BFF (threat-enriched check findings)
  const { data, loading, error, refetch } = useViewFetch('misconfig');
  subscribeRefresh(refetch);

  const findings = useMemo(() => data?.findings || [], [data]);

  // KPI counts
  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
    findings.forEach(f => {
      const s = (f.severity || '').toLowerCase();
      if (c[s] !== undefined) c[s]++;
    });
    return c;
  }, [findings]);

  // Apply severity + status filters
  const filtered = useMemo(() => {
    let rows = findings;
    if (sevFilter !== 'All') {
      rows = rows.filter(f => (f.severity || '').toLowerCase() === sevFilter.toLowerCase());
    }
    if (statusFilter !== 'All') {
      rows = rows.filter(f => (f.status || 'FAIL') === statusFilter);
    }
    return rows;
  }, [findings, sevFilter, statusFilter]);

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="max-w-screen-2xl mx-auto px-6 py-6 space-y-6">

        {/* ── Page Header ── */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center"
                style={{ backgroundColor: 'rgba(239,68,68,0.12)' }}>
                <ShieldAlert className="w-5 h-5" style={{ color: '#ef4444' }} />
              </div>
              <div>
                <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
                  Investigation
                </h1>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                  {counts.total.toLocaleString()} findings across all engines
                </p>
              </div>
            </div>
          </div>
          <button
            onClick={refetch}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border hover:opacity-75 transition-opacity"
            style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>

        {/* ── KPI Row ── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Critical"   value={counts.critical} color="#ef4444" icon={AlertTriangle} />
          <StatCard label="High"       value={counts.high}     color="#f97316" icon={ShieldAlert} />
          <StatCard label="Medium"     value={counts.medium}   color="#eab308" icon={Shield} />
          <StatCard label="Low"        value={counts.low}      color="#22c55e" icon={ShieldCheck} />
        </div>

        {/* ── Filter Bar ── */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 mr-2">
            <SlidersHorizontal className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Severity</span>
          </div>
          {SEV_FILTERS.map(s => (
            <FilterChip key={s} label={s} active={sevFilter === s} onClick={() => setSevFilter(s)} />
          ))}
          <div className="w-px h-5 mx-2" style={{ backgroundColor: 'var(--border-primary)' }} />
          <div className="flex items-center gap-1.5 mr-2">
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Status</span>
          </div>
          {['All', 'FAIL', 'PASS'].map(s => (
            <FilterChip key={s} label={s} active={statusFilter === s} onClick={() => setStatusFilter(s)} />
          ))}
        </div>

        {/* ── Data Table ── */}
        <div className="rounded-xl border overflow-hidden"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <DataTable
            data={filtered}
            columns={COLUMNS}
            loading={loading}
            pageSize={25}
            emptyMessage={error ? 'Failed to load findings.' : 'No findings match the current filters.'}
            defaultDensity="compact"
            persistenceKey="investigation"
            onRowClick={(row) => {
              const finding = row?.original ?? row;
              setSelectedFinding(finding);
            }}
          />
        </div>
      </div>

      {/* ── Finding Detail Panel (slide-in) ── */}
      {selectedFinding && (
        <FindingDetailPanel
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          context={{ engine: selectedFinding.engine || 'check' }}
        />
      )}
    </div>
  );
}
