'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { ChevronRight, ChevronDown, ChevronUp, AlertTriangle, Network, Globe, GlobeLock, ExternalLink, ArrowRight } from 'lucide-react';
import * as LucideIcons from 'lucide-react';
import { getServiceIcon } from '@/lib/inventory-taxonomy';
import { fetchView } from '@/lib/api';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';
import { useGlobalFilter } from '@/lib/global-filter-context';

const riskColor = (s) => (s >= 80 ? '#ef4444' : s >= 60 ? '#f97316' : s >= 40 ? '#eab308' : '#22c55e');

const shortName = (uid) => {
  if (!uid) return 'N/A';
  const last = uid.split('/').pop() || uid.split(':').pop() || uid;
  return last.length > 40 ? last.slice(0, 37) + '\u2026' : last;
};

// ---------------------------------------------------------------------------
// Expanded row detail — depth distribution + reachable resources
// ---------------------------------------------------------------------------
// Resolve a Lucide icon by name string
function IconByName({ name, size = 16, color, className = '' }) {
  const Icon = LucideIcons[name] || LucideIcons.Box;
  return <Icon size={size} color={color} className={className} />;
}

// Infer resource type from ARN for icon lookup
function arnToType(arn) {
  if (!arn) return '';
  // arn:aws:SERVICE:region:account:TYPE/name or arn:aws:SERVICE:...
  const parts = arn.split(':');
  if (parts.length >= 3) {
    const svc = parts[2]; // e.g. 'iam', 's3', 'lambda', 'ec2'
    const resource = parts[5] || '';
    const subtype = resource.split('/')[0]; // e.g. 'role', 'instance', 'function'
    // Try exact match first, then service-level fallback
    return `${svc}.${subtype}` || svc;
  }
  return '';
}

// Build chain paths from path_edges (BFS edges with from/to/hop)
function buildChains(edges, sourceUid) {
  if (!edges || edges.length === 0) return [];
  // Build adjacency from edges
  const adj = {};
  for (const e of edges) {
    if (!adj[e.from]) adj[e.from] = [];
    adj[e.from].push(e);
  }
  // DFS to enumerate all root→leaf paths
  const chains = [];
  const dfs = (node, path) => {
    const children = adj[node];
    if (!children || children.length === 0) {
      if (path.length > 0) chains.push([...path]);
      return;
    }
    for (const edge of children) {
      path.push(edge);
      dfs(edge.to, path);
      path.pop();
    }
  };
  dfs(sourceUid, []);
  return chains.slice(0, 10); // Cap at 10 chains
}

// Single node chip with Lucide icon
function NodeChip({ uid, isSource }) {
  const type = arnToType(uid);
  const icon = getServiceIcon(type);
  const bg = isSource ? 'rgba(59,130,246,0.12)' : 'rgba(239,68,68,0.06)';
  const border = isSource ? 'rgba(59,130,246,0.4)' : 'rgba(239,68,68,0.25)';
  const iconColor = isSource ? '#3b82f6' : '#ef4444';
  const Wrapper = isSource ? 'div' : 'a';
  const props = isSource ? {} : { href: `/ui/inventory/architecture?resource_uid=${encodeURIComponent(uid)}` };

  return (
    <Wrapper {...props} className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md transition-all hover:opacity-90"
      style={{ backgroundColor: bg, border: `1px solid ${border}` }}>
      <div className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0" style={{ backgroundColor: isSource ? 'rgba(59,130,246,0.2)' : 'rgba(239,68,68,0.15)' }}>
        <IconByName name={icon} size={13} color={iconColor} />
      </div>
      <div className="min-w-0">
        <span className="text-[11px] font-mono block truncate" style={{ color: 'var(--text-secondary)', maxWidth: 150 }}>{shortName(uid)}</span>
        {type && <span className="text-[8px]" style={{ color: 'var(--text-muted)' }}>{type.split('.')[0]}</span>}
      </div>
    </Wrapper>
  );
}

// Horizontal chain-based blast graph: a→b→d, a→c→e
function BlastRadiusGraph({ resourceUid, resourceName, resourceType, reachable, pathEdges }) {
  const chains = useMemo(() => buildChains(pathEdges || [], resourceUid), [pathEdges, resourceUid]);
  const hasChains = chains.length > 0;

  // Fallback: if no path_edges, show flat layout or "no connectivity"
  if (!hasChains) {
    if (reachable.length === 0) {
      return (
        <div className="flex items-center gap-3 px-4 py-3" style={{ background: 'rgba(15,15,25,0.25)', borderRadius: 8 }}>
          <NodeChip uid={resourceUid} isSource />
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>No connectivity paths detected — isolated resource</span>
        </div>
      );
    }
    const shown = reachable.slice(0, 6);
    return (
      <div className="flex flex-wrap items-center gap-2 px-4 py-3" style={{ background: 'rgba(15,15,25,0.25)', borderRadius: 8 }}>
        <NodeChip uid={resourceUid} isSource />
        <ArrowRight size={16} style={{ color: 'var(--text-muted)' }} />
        {shown.map((arn, i) => <NodeChip key={i} uid={arn} />)}
        {reachable.length > 6 && <span className="text-xs ml-1" style={{ color: 'var(--text-muted)' }}>+{reachable.length - 6} more</span>}
      </div>
    );
  }

  return (
    <div className="space-y-1.5 px-4 py-3" style={{ background: 'rgba(15,15,25,0.25)', borderRadius: 8, overflowX: 'auto' }}>
      {chains.map((chain, ci) => (
        <div key={ci} className="flex items-center gap-1.5 flex-wrap">
          <NodeChip uid={resourceUid} isSource />
          {chain.map((edge, ei) => (
            <span key={ei} className="contents">
              <div className="flex flex-col items-center flex-shrink-0 gap-0.5">
                <span className="text-[8px] font-medium px-1 rounded" style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: '#3b82f6' }}>hop {edge.hop || ei + 1}</span>
                <ArrowRight size={14} style={{ color: 'var(--text-muted)' }} />
                <span className="text-[8px] leading-none" style={{ color: 'var(--text-muted)' }}>{edge.relationship_type || ''}</span>
              </div>
              <NodeChip uid={edge.to} />
            </span>
          ))}
        </div>
      ))}
      {reachable.length > chains.reduce((s, c) => s + c.length, 0) && (
        <div className="text-[10px] pt-1" style={{ color: 'var(--text-muted)' }}>
          {chains.length} path{chains.length > 1 ? 's' : ''} · {reachable.length} connected resource{reachable.length !== 1 ? 's' : ''} · max {Math.max(...chains.map(c => c.length))} hop{Math.max(...chains.map(c => c.length)) !== 1 ? 's' : ''}
        </div>
      )}
    </div>
  );
}

function ExpandedDetail({ row }) {
  const reachable = row.reachableResources || [];

  // Group reachable resources by service category
  const grouped = useMemo(() => {
    const groups = {};
    for (const arn of reachable) {
      const type = arnToType(arn);
      const svc = type.split('.')[0] || 'other';
      if (!groups[svc]) groups[svc] = { icon: getServiceIcon(type), items: [] };
      groups[svc].items.push(arn);
    }
    return Object.entries(groups).sort((a, b) => b[1].items.length - a[1].items.length);
  }, [reachable]);

  return (
    <div className="px-6 py-4 space-y-4 border-t" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
      {/* Summary row */}
      <div className="flex flex-wrap gap-4 text-xs">
        <div><span style={{ color: 'var(--text-muted)' }}>Rule: </span><span style={{ color: 'var(--text-primary)' }}>{row.ruleName || '-'}</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>Verdict: </span><span style={{ color: 'var(--text-primary)' }}>{row.verdict || '-'}</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>Hops: </span><span className="font-bold" style={{ color: '#3b82f6' }}>{row.maxHops ?? 0}</span></div>
        <div><span style={{ color: 'var(--text-muted)' }}>Connected: </span><span className="font-bold" style={{ color: '#ef4444' }}>{row.reachableCount ?? 0}</span></div>
        <a href={`/ui/threats/${row.detectionId}`} className="ml-auto hover:underline" style={{ color: 'var(--accent-primary)' }}>View Detection →</a>
      </div>

      {/* Horizontal flow graph */}
      <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border-primary)' }}>
        <BlastRadiusGraph resourceUid={row.resourceUid} resourceName={row.resourceName || shortName(row.resourceUid)} resourceType={row.resourceType} reachable={reachable} pathEdges={row.pathEdges} />
      </div>

      {/* Reachable resources grouped by category */}
      {grouped.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
            Reachable Resources by Category ({reachable.length})
          </p>
          <div className="space-y-2">
            {grouped.map(([svc, { icon, items }]) => (
              <div key={svc}>
                <div className="flex items-center gap-1.5 mb-1">
                  <IconByName name={icon} size={13} color="var(--text-secondary)" />
                  <span className="text-[11px] font-medium" style={{ color: 'var(--text-secondary)' }}>{svc.toUpperCase()}</span>
                  <span className="text-[10px] px-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-card)', color: 'var(--text-muted)' }}>{items.length}</span>
                </div>
                <div className="flex flex-wrap gap-1 pl-5">
                  {items.map((arn, i) => (
                    <a key={i} href={`/ui/inventory/architecture?resource_uid=${encodeURIComponent(arn)}`}
                      className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded hover:opacity-80 transition-opacity font-mono truncate"
                      style={{ backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)', maxWidth: 220 }}
                      title={arn}>
                      {shortName(arn)}
                      <ExternalLink className="w-2.5 h-2.5 flex-shrink-0 opacity-40" />
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
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
        const id = row.original.detectionId;
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
      accessorKey: 'severity', header: 'Severity', size: 100,
      cell: ({ getValue }) => <SeverityBadge severity={getValue() || 'info'} />,
    },
    {
      accessorKey: 'riskScore', header: 'Risk Score', size: 130,
      cell: ({ getValue }) => {
        const score = Number(getValue()) || 0;
        const color = riskColor(score);
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
      accessorKey: 'maxHops', header: 'Hops', size: 90,
      cell: ({ row }) => {
        const hops = Number(row.original.maxHops) || 0;
        const reachable = Number(row.original.reachableCount) || 0;
        if (hops === 0 && reachable === 0) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>;
        return (
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-bold tabular-nums" style={{ color: hops > 0 ? '#3b82f6' : 'var(--text-muted)' }}>{hops}</span>
            <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>hop{hops !== 1 ? 's' : ''}</span>
            {reachable > 0 && <span className="text-[10px] px-1 rounded" style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: '#3b82f6' }}>{reachable} connected</span>}
          </div>
        );
      },
    },
    {
      accessorKey: 'isInternetReachable', header: 'Internet', size: 80,
      cell: ({ getValue }) => getValue()
        ? <Globe className="w-4 h-4 text-red-400" title="Internet exposed" />
        : <GlobeLock className="w-4 h-4" style={{ color: 'var(--text-muted)' }} title="Not exposed" />,
    },
  ], [expandedRows, toggleRow]);
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function BlastRadiusPage() {
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
      const result = await fetchView('threats/blast-radius');
      if (cancelled) return;
      result?.error ? setError(result.error) : setData(result);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [account]);

  const kpi = data?.kpi ?? {};
  const blastItems = useMemo(() => {
    const items = data?.blastItems ?? [];
    return [...items].sort((a, b) => (b.maxHops ?? 0) - (a.maxHops ?? 0) || (b.reachableCount ?? 0) - (a.reachableCount ?? 0));
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
    if (row?.detectionId) window.location.href = `/ui/threats/${row.detectionId}`;
  }, []);

  const renderExpandedRow = useCallback((row) => {
    if (!expandedRows.has(row.detectionId)) return null;
    return <ExpandedDetail row={row} />;
  }, [expandedRows]);

  const metricGroups = useMemo(() => [
    {
      label: 'BLAST RADIUS', color: 'var(--accent-danger)',
      cells: [
        { label: 'TOTAL DETECTIONS', value: kpi.totalDetections ?? 0, noTrend: true, context: 'with blast analysis' },
        { label: 'WITH BLAST RADIUS', value: kpi.detectionsWithBlast ?? 0, valueColor: '#f97316', noTrend: true, context: 'have reachable resources' },
      ],
    },
    {
      label: 'DOWNSTREAM IMPACT', color: 'var(--accent-primary)',
      cells: [
        { label: 'TOTAL REACHABLE', value: kpi.totalReachable ?? 0, noTrend: true, context: 'downstream resources' },
        { label: 'INTERNET EXPOSED', value: kpi.internetExposed ?? 0, valueColor: '#ef4444', noTrend: true, context: 'publicly reachable' },
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
          <span style={{ color: 'var(--text-primary)' }}>Blast Radius</span>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Blast Radius</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Downstream impact analysis for threat detections — how far a compromise can spread.
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
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Failed to load blast radius data</p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
            </div>
          </div>
        </div>
      )}

      {!loading && !error && (
        <>
          <MetricStrip groups={metricGroups} />
          {blastItems.length === 0 ? (
            <EmptyState
              icon={<Network className="w-12 h-12" />}
              title="No Blast Radius Data"
              description="Run a threat scan with blast radius analysis enabled. Detections with downstream reachable resources will appear here."
            />
          ) : (
            <DataTable
              data={blastItems}
              columns={columns}
              pageSize={15}
              onRowClick={handleRowClick}
              renderExpandedRow={renderExpandedRow}
              emptyMessage="No blast radius detections match your search."
            />
          )}
        </>
      )}
    </div>
  );
}
