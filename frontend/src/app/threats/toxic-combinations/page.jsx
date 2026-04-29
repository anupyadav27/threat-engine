'use client';

import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { ChevronRight, ChevronDown, ChevronUp, AlertTriangle, Shield, ExternalLink } from 'lucide-react';
import { fetchView } from '@/lib/api';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';
import { useGlobalFilter } from '@/lib/global-filter-context';

const toxicColor = (s) => (s >= 80 ? '#ef4444' : s >= 60 ? '#f97316' : s >= 40 ? '#eab308' : '#22c55e');

const shortName = (uid) => {
  if (!uid) return 'N/A';
  const last = uid.split('/').pop() || uid.split(':').pop() || uid;
  return last.length > 40 ? last.slice(0, 37) + '\u2026' : last;
};

function SectionLabel({ children }) {
  return <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>{children}</p>;
}

function ExpandedDetail({ row }) {
  const ruleNames = row.ruleNames || [];
  const categories = row.categories || [];
  const detectionIds = row.detectionIds || [];
  const empty = ruleNames.length === 0 && categories.length === 0 && detectionIds.length === 0;

  return (
    <div className="px-6 py-4 space-y-4 border-t" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
      {ruleNames.length > 0 && (<div><SectionLabel>Rule Names</SectionLabel>
        {ruleNames.map((n, i) => <p key={i} className="text-xs" style={{ color: 'var(--text-secondary)' }}>{n}</p>)}
      </div>)}
      {categories.length > 0 && (<div><SectionLabel>Categories</SectionLabel>
        <div className="flex flex-wrap gap-1.5">
          {categories.map((c, i) => <span key={i} className="text-xs px-2 py-1 rounded font-medium" style={{ backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)' }}>{c}</span>)}
        </div>
      </div>)}
      {detectionIds.length > 0 && (<div><SectionLabel>Detections ({detectionIds.length})</SectionLabel>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 max-h-48 overflow-y-auto">
          {detectionIds.map((did, i) => (
            <a key={i} href={`/ui/threats/${did}`} className="flex items-center gap-2 text-xs px-3 py-2 rounded hover:opacity-80 transition-opacity" style={{ backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
              <span className="font-mono truncate">{did}</span>
              <ExternalLink className="w-3 h-3 flex-shrink-0 opacity-50" />
            </a>
          ))}
        </div>
      </div>)}
      {empty && <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No additional detail available for this combination.</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------
function useColumns(expandedRows, toggleRow) {
  return useMemo(() => [
    {
      id: 'expand', header: '', size: 40,
      cell: ({ row }) => {
        const id = row.original.id;
        return (
          <button onClick={(e) => { e.stopPropagation(); toggleRow(id); }} style={{ color: 'var(--text-muted)' }}>
            {expandedRows.has(id) ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        );
      },
    },
    {
      accessorKey: 'provider', header: 'Provider', size: 80,
      cell: ({ getValue }) => {
        const p = (getValue() || 'AWS').toUpperCase();
        return (
          <span className="text-xs px-2 py-0.5 rounded-full font-medium" style={{
            backgroundColor: p === 'AWS' ? 'rgba(255,153,0,0.12)' : p === 'AZURE' ? 'rgba(0,120,212,0.12)' : 'rgba(66,133,244,0.12)',
            color: p === 'AWS' ? '#FF9900' : p === 'AZURE' ? '#0078D4' : '#4285F4',
          }}>{p}</span>
        );
      },
    },
    {
      accessorKey: 'accountId', header: 'Account', size: 130,
      cell: ({ getValue }) => <span className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>{getValue() || '-'}</span>,
    },
    {
      accessorKey: 'region', header: 'Region', size: 120,
      cell: ({ getValue }) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{getValue() || '-'}</span>,
    },
    {
      accessorKey: 'resourceName', header: 'Resource', size: 260,
      cell: ({ row }) => {
        const item = row.original;
        return (
          <div className="space-y-1">
            <a href={`/ui/inventory/architecture?resource_uid=${encodeURIComponent(item.resourceUid || '')}`} className="text-sm font-medium hover:underline block truncate" style={{ color: 'var(--accent-primary)' }} title={item.resourceUid}>
              {item.resourceName || shortName(item.resourceUid)}
            </a>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
              {item.resourceType || '-'}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: 'threatCount', header: 'Threats', size: 80,
      cell: ({ getValue }) => {
        const count = getValue() || 0;
        return (
          <span className="text-xs font-bold px-2.5 py-1 rounded-full" style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
            {count}
          </span>
        );
      },
    },
    {
      accessorKey: 'severity', header: 'Severity', size: 100,
      cell: ({ getValue }) => <SeverityBadge severity={getValue() || 'info'} />,
    },
    {
      accessorKey: 'toxicityScore', header: 'Toxicity Score', size: 150,
      cell: ({ getValue }) => {
        const score = Number(getValue()) || 0;
        const color = toxicColor(score);
        return (
          <div className="flex items-center gap-2">
            <div className="w-16 h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)' }}>
              <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
            </div>
            <span className="text-xs font-bold tabular-nums" style={{ color }}>{score}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'mitreTechniques', header: 'MITRE Techniques', size: 200,
      cell: ({ row }) => {
        const techniques = row.original.mitreTechniques || [];
        if (techniques.length === 0) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>-</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {techniques.slice(0, 3).map((t) => (
              <code key={t} className="text-[10px] px-1.5 py-0.5 rounded font-mono" style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
                {t}
              </code>
            ))}
            {techniques.length > 3 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
                +{techniques.length - 3}
              </span>
            )}
          </div>
        );
      },
    },
  ], [expandedRows, toggleRow]);
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function ToxicCombinationsPage() {
  const { account } = useGlobalFilter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);
  const [expandedRows, setExpandedRows] = useState(new Set());

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      const result = await fetchView('threats/toxic-combinations');
      if (cancelled) return;
      result?.error ? setError(result.error) : setData(result);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [account]);

  const kpi = data?.kpi ?? {};
  const combinations = useMemo(() => {
    const items = data?.toxicCombinations ?? [];
    return [...items].sort((a, b) => (b.toxicityScore ?? 0) - (a.toxicityScore ?? 0));
  }, [data]);

  const toggleRow = useCallback((id) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }, []);

  const columns = useColumns(expandedRows, toggleRow);

  const handleRowClick = useCallback((row) => {
    if (row?.resourceUid) window.location.href = `/ui/inventory/architecture?resource_uid=${encodeURIComponent(row.resourceUid)}`;
  }, []);

  const renderExpandedRow = useCallback((row) => {
    if (!expandedRows.has(row.id)) return null;
    return <ExpandedDetail row={row} />;
  }, [expandedRows]);

  const metricGroups = useMemo(() => [
    {
      label: 'TOXIC RISK', color: 'var(--accent-danger)',
      cells: [
        { label: 'TOTAL COMBOS', value: kpi.total ?? 0, noTrend: true, context: 'compound scenarios' },
        { label: 'CRITICAL', value: kpi.critical ?? 0, valueColor: '#ef4444', noTrend: true, context: 'highest severity' },
      ],
    },
    {
      label: 'EXPOSURE', color: '#eab308',
      cells: [
        { label: 'HIGH', value: kpi.high ?? 0, valueColor: '#f97316', noTrend: true, context: 'high severity combos' },
        { label: 'AVG THREATS / RESOURCE', value: kpi.avgThreatsPerCombo ?? 0, noTrend: true, context: 'mean per resource' },
      ],
    },
  ], [kpi]);

  return (
    <div className="space-y-4">
      {/* Header + Breadcrumb */}
      <div>
        <div className="flex items-center gap-2 text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
          <a href="/ui/threats" className="hover:underline" style={{ color: 'var(--text-secondary)' }}>Threats</a>
          <ChevronRight className="w-3 h-3" />
          <span style={{ color: 'var(--text-primary)' }}>Toxic Threat Combos</span>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Toxic Threat Combos</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Resources with multiple overlapping threats that amplify compound risk.
        </p>
      </div>

      <ThreatsSubNav />

      {loading && (
        <div className="space-y-4">
          <div className="h-[100px] rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
          <LoadingSkeleton rows={8} cols={4} />
        </div>
      )}

      {!loading && error && (
        <div className="rounded-xl p-5 border" style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.3)' }}>
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Failed to load toxic combinations</p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
            </div>
          </div>
        </div>
      )}

      {!loading && !error && (
        <>
          <MetricStrip groups={metricGroups} />

          {combinations.length === 0 ? (
            <EmptyState
              icon={<Shield className="w-12 h-12" />}
              title="No Toxic Threat Combos"
              description="Run a threat scan to identify compound risk scenarios. Toxic combinations emerge when multiple threats overlap on a single resource."
            />
          ) : (
            <DataTable
              data={combinations}
              columns={columns}
              pageSize={15}
              onRowClick={handleRowClick}
              renderExpandedRow={renderExpandedRow}
              emptyMessage="No toxic combinations match your search."
            />
          )}
        </>
      )}
    </div>
  );
}
