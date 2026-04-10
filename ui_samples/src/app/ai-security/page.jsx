'use client';

import { useState, useEffect, useMemo } from 'react';
import { Brain } from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';

// ── Colours ───────────────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
  emerald: '#10b981', amber: '#f59e0b',
};

const MODULE_COLORS = {
  model_security:    '#8b5cf6',
  endpoint_security: '#3b82f6',
  prompt_security:   '#ef4444',
  data_pipeline:     '#06b6d4',
  ai_governance:     '#10b981',
  access_control:    '#f59e0b',
};

const MODULE_LABELS = {
  model_security:    'Model Security',
  endpoint_security: 'Endpoint Security',
  prompt_security:   'Prompt Security',
  data_pipeline:     'Data Pipeline',
  ai_governance:     'AI Governance',
  access_control:    'Access Control',
};

// ── Category badge ────────────────────────────────────────────────────────────
function CategoryBadge({ value }) {
  const v = (value || '').toLowerCase();
  const colorMap = {
    model_security:    { bg: 'rgba(139,92,246,0.15)', color: '#a78bfa' },
    endpoint_security: { bg: 'rgba(59,130,246,0.15)',  color: '#60a5fa' },
    prompt_security:   { bg: 'rgba(239,68,68,0.15)',   color: '#f87171' },
    data_pipeline:     { bg: 'rgba(6,182,212,0.15)',   color: '#22d3ee' },
    ai_governance:     { bg: 'rgba(16,185,129,0.15)',  color: '#34d399' },
    access_control:    { bg: 'rgba(245,158,11,0.15)',  color: '#fbbf24' },
  };
  const { bg = 'var(--bg-tertiary)', color = 'var(--text-muted)' } = colorMap[v] || {};
  return (
    <span className="text-xs px-2 py-0.5 rounded font-medium" style={{ backgroundColor: bg, color }}>
      {MODULE_LABELS[v] || value || '—'}
    </span>
  );
}

// ── Overview tab: coverage + module scores ─────────────────────────────────────
function OverviewContent({ coverage, modules }) {
  const coverageItems = [
    { label: 'VPC Isolation',   pct: coverage.vpc_isolation_pct      || 0 },
    { label: 'Enc. at Rest',    pct: coverage.encryption_rest_pct    || 0 },
    { label: 'Enc. Transit',    pct: coverage.encryption_transit_pct || 0 },
    { label: 'Model Cards',     pct: coverage.model_card_pct         || 0 },
    { label: 'Monitoring',      pct: coverage.monitoring_pct         || 0 },
    { label: 'Guardrails',      pct: coverage.guardrails_pct         || 0 },
  ];

  return (
    <div className="space-y-4">
      {/* Coverage metrics */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12,
        padding: '14px 16px', borderRadius: 10,
        background: 'var(--bg-secondary)', border: '1px solid var(--border-primary)',
      }}>
        {coverageItems.map(item => {
          const col = item.pct >= 70 ? C.emerald : item.pct >= 40 ? C.amber : C.critical;
          return (
            <div key={item.label}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                {item.label}
              </div>
              <div style={{ fontSize: 22, fontWeight: 900, color: col, lineHeight: 1,
                fontVariantNumeric: 'tabular-nums' }}>
                {item.pct}%
              </div>
              <div style={{ height: 3, borderRadius: 2, backgroundColor: 'var(--bg-tertiary)',
                overflow: 'hidden', marginTop: 5 }}>
                <div style={{ width: `${item.pct}%`, height: '100%', borderRadius: 2,
                  backgroundColor: col, opacity: 0.85 }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Module scores */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '4px 24px',
        padding: '12px 16px', borderRadius: 10,
        background: 'var(--bg-secondary)', border: '1px solid var(--border-primary)',
      }}>
        <div style={{ gridColumn: '1 / -1', fontSize: 11, fontWeight: 700, color: 'var(--text-muted)',
          textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
          Module Scores
        </div>
        {modules.map(m => {
          const col  = MODULE_COLORS[m.key] || '#6366f1';
          const scCol = (m.score || 0) >= 70 ? C.emerald : (m.score || 0) >= 50 ? C.amber : C.critical;
          return (
            <div key={m.key} style={{ display: 'flex', alignItems: 'center', gap: 8,
              padding: '5px 0', borderBottom: '1px solid var(--border-primary)' }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, backgroundColor: col, flexShrink: 0 }} />
              <span style={{ flex: 1, fontSize: 12, color: 'var(--text-secondary)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {m.name || MODULE_LABELS[m.key] || m.key}
              </span>
              <span style={{ fontSize: 13, fontWeight: 700, color: scCol,
                fontVariantNumeric: 'tabular-nums' }}>
                {m.score || 0}%
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 4, flexShrink: 0 }}>
                {m.findings || 0} findings
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function AiSecurityPage() {
  const [data, setData]                     = useState({});
  const [loading, setLoading]               = useState(true);
  const [error, setError]                   = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetchView('ai-security', {
      provider: provider || undefined,
      account:  account  || undefined,
      region:   region   || undefined,
    })
      .then(d => { setData(d || {}); if (d?.error) setError(d.error); })
      .catch(e => setError(e?.message || 'Failed to load AI security data'))
      .finally(() => setLoading(false));
  }, [provider, account, region]);

  // ── Derived data ───────────────────────────────────────────────────────────
  const pageContext = useMemo(() => {
    const ctx = data.pageContext || {};
    const serverTabs = ctx.tabs || [];
    const hasOverview = serverTabs.some(t => t.id === 'overview');
    return {
      ...ctx,
      tabs: hasOverview ? serverTabs : [{ id: 'overview', label: 'Overview' }, ...serverTabs],
    };
  }, [data.pageContext]);

  const kpiGroups = data.kpiGroups || [];
  const findings  = data.findings  || [];
  const inventory = data.inventory || [];
  const shadowAi  = data.shadowAi?.items || [];
  const modules   = data.modules   || [];
  const coverage  = data.coverage  || {};

  // ── Column definitions ────────────────────────────────────────────────────
  const findingsColumns = [
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: i => (
        <span className="text-xs font-bold" style={{ color: 'var(--accent-primary)' }}>
          {i.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'account_id',
      header: 'Account',
      cell: i => (
        <span className="text-xs font-mono">
          {i.getValue() || i.row.original.account || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'region',
      header: 'Region',
      cell: i => <span className="text-xs">{i.getValue() || '—'}</span>,
    },
    {
      accessorKey: 'resource_type',
      header: 'Service',
      cell: i => (
        <span className="text-xs px-1.5 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {i.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'rule_id',
      header: 'Rule ID',
      cell: i => (
        <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
          {i.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'title',
      header: 'Finding',
      cell: i => (
        <span className="text-xs" style={{ color: 'var(--text-primary)' }}>
          {i.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: i => <SeverityBadge severity={i.getValue()} />,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: i => {
        const s = (i.getValue() || '').toUpperCase();
        return (
          <span style={{ fontSize: 11, fontWeight: 700, color: s === 'PASS' ? C.emerald : C.critical }}>
            {s}
          </span>
        );
      },
    },
    {
      accessorKey: 'category',
      header: 'Module',
      cell: i => <CategoryBadge value={i.getValue()} />,
    },
  ];

  const inventoryColumns = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: i => <span className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue() || '—'}</span>,
    },
    {
      accessorKey: 'service',
      header: 'Service',
      cell: i => (
        <span className="text-xs px-1.5 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {i.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'type',
      header: 'Type',
      cell: i => <span className="text-xs">{i.getValue() || '—'}</span>,
    },
    {
      accessorKey: 'region',
      header: 'Region',
      cell: i => <span className="text-xs">{i.getValue() || '—'}</span>,
    },
    {
      accessorKey: 'account',
      header: 'Account',
      cell: i => <span className="text-xs font-mono">{i.getValue() || '—'}</span>,
    },
    {
      accessorKey: 'public',
      header: 'Public',
      cell: i => i.getValue()
        ? <span style={{ color: C.critical, fontSize: 11, fontWeight: 700 }}>Yes</span>
        : <span style={{ color: C.emerald, fontSize: 11 }}>No</span>,
    },
    {
      accessorKey: 'guardrails',
      header: 'Guardrails',
      cell: i => i.getValue()
        ? <span style={{ color: C.emerald, fontSize: 11, fontWeight: 700 }}>Yes</span>
        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>No</span>,
    },
    {
      accessorKey: 'risk_score',
      header: 'Risk',
      cell: i => {
        const v = i.getValue() || 0;
        const col = v >= 7 ? C.critical : v >= 4 ? C.amber : C.emerald;
        return <span style={{ fontWeight: 700, color: col, fontSize: 12 }}>{v}</span>;
      },
    },
  ];

  const shadowColumns = [
    {
      accessorKey: 'service',
      header: 'Service',
      cell: i => (
        <span className="text-xs px-1.5 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {i.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'operation',
      header: 'Details',
      cell: i => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{i.getValue() || '—'}</span>,
    },
    {
      accessorKey: 'actor',
      header: 'Actor',
      cell: i => <span className="text-xs font-mono">{i.getValue() || '—'}</span>,
    },
    {
      accessorKey: 'calls',
      header: 'Calls',
      cell: i => <span className="text-xs font-bold">{i.getValue() ?? 0}</span>,
    },
    {
      accessorKey: 'last_seen',
      header: 'Last Seen',
      cell: i => <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{i.getValue() || '—'}</span>,
    },
  ];

  // ── Filters ────────────────────────────────────────────────────────────────
  const commonFilters = [
    {
      key: 'provider', label: 'Cloud Platform',
      options: [{ value: 'AWS', label: 'AWS' }, { value: 'AZURE', label: 'Azure' }, { value: 'GCP', label: 'GCP' }],
    },
    {
      key: 'severity', label: 'Severity',
      options: [
        { value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' },
        { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' },
      ],
    },
    {
      key: 'status', label: 'Status',
      options: [{ value: 'FAIL', label: 'FAIL' }, { value: 'PASS', label: 'PASS' }],
    },
  ];

  const extraFilters = [
    {
      key: 'category', label: 'Module',
      options: Object.entries(MODULE_LABELS).map(([v, l]) => ({ value: v, label: l })),
    },
  ];

  // ── Tab data ───────────────────────────────────────────────────────────────
  const tabData = useMemo(() => ({
    overview: {
      renderTab: () => <OverviewContent coverage={coverage} modules={modules} />,
    },
    findings: {
      data: findings,
      columns: findingsColumns,
      filters: commonFilters,
      extraFilters,
      searchPlaceholder: 'Search by rule, resource, title...',
    },
    inventory: {
      data: inventory,
      columns: inventoryColumns,
      searchPlaceholder: 'Search by name, service, type...',
    },
    shadow_ai: {
      data: shadowAi,
      columns: shadowColumns,
      searchPlaceholder: 'Search shadow AI detections...',
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [findings, inventory, shadowAi, modules, coverage]);

  // ── Row click → FindingDetailPanel (findings only) ────────────────────────
  const handleRowClick = (row) => {
    const f = row?.original || row;
    if (f?.rule_id || f?.finding_id) setSelectedFinding(f);
  };

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <>
      <PageLayout
        icon={Brain}
        pageContext={pageContext}
        kpiGroups={kpiGroups}
        tabData={tabData}
        loading={loading}
        error={error}
        onRowClick={handleRowClick}
        topNav
      />
      <FindingDetailPanel
        finding={selectedFinding}
        open={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </>
  );
}
