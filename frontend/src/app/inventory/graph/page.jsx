'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  Network, ShieldAlert, AlertTriangle, Box, Server, Database,
  Cpu, HardDrive, KeyRound, Lock, Globe, Eye, Link2, Layers,
  ArrowRight, Filter, ExternalLink, RotateCcw,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import EmptyState from '@/components/shared/EmptyState';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function severityColor(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return '#ef4444';
    case 'high':     return '#f97316';
    case 'medium':   return '#eab308';
    case 'low':      return '#22c55e';
    default:         return '#94a3b8';
  }
}

function typeIcon(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('lambda') || t.includes('function')) return Cpu;
  if (t.includes('s3') || t.includes('bucket') || t.includes('storage')) return HardDrive;
  if (t.includes('rds') || t.includes('database') || t.includes('db')) return Database;
  if (t.includes('iam') || t.includes('role') || t.includes('policy')) return KeyRound;
  if (t.includes('kms') || t.includes('key') || t.includes('vault')) return Lock;
  if (t.includes('vpc') || t.includes('network') || t.includes('subnet')) return Network;
  if (t.includes('finding') || t.includes('threat')) return ShieldAlert;
  if (t.includes('internet')) return Globe;
  return Server;
}

function extractService(type) {
  const t = (type || '').toLowerCase();
  const parts = t.split('.');
  return parts[0] || type;
}

// Derive provider from ARN or node ID
function deriveProvider(id) {
  if (!id) return 'aws';
  if (id.startsWith('arn:aws')) return 'aws';
  if (id.startsWith('arn:azure') || id.includes('/providers/Microsoft')) return 'azure';
  if (id.startsWith('projects/') || id.includes('googleapis')) return 'gcp';
  if (id.includes('ocid1')) return 'oci';
  if (id.includes('alicloud') || id.includes('acs:')) return 'alicloud';
  if (id.startsWith('k8s:') || id.includes('/namespaces/')) return 'k8s';
  return 'aws';
}

export default function SecurityRelationshipGraphPage() {
  const router = useRouter();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterProvider, setFilterProvider] = useState('');
  const [filterType, setFilterType] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const result = await fetchView('threats/graph');
        if (!cancelled) {
          if (result?.error) setError(result.error);
          else setData(result);
        }
      } catch (err) {
        if (!cancelled) setError(err?.message || 'Failed to load security graph');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const nodes = useMemo(() => {
    if (!data) return [];
    return (data.nodes || []).map(n => ({
      ...n,
      provider: n.provider || deriveProvider(n.id),
      service: extractService(n.type),
    }));
  }, [data]);

  const links = useMemo(() => data?.links || [], [data]);
  const kpi = useMemo(() => data?.kpi || {}, [data]);

  // Relationship type counts
  const edgeCounts = useMemo(() => {
    const counts = {};
    links.forEach(l => {
      const t = l.type || l.edge_kind || 'RELATED';
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [links]);

  // Unique providers and services for filters
  const providers = useMemo(() => [...new Set(nodes.map(n => n.provider))].filter(Boolean).sort(), [nodes]);
  const services = useMemo(() => [...new Set(nodes.map(n => n.service))].filter(Boolean).sort(), [nodes]);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    let result = nodes;
    if (filterSeverity) result = result.filter(n => (n.severity || '').toLowerCase() === filterSeverity);
    if (filterProvider) result = result.filter(n => n.provider === filterProvider);
    if (filterType) result = result.filter(n => n.service === filterType);
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      result = result.filter(n =>
        (n.label || n.id || '').toLowerCase().includes(q) ||
        (n.type || '').toLowerCase().includes(q)
      );
    }
    return result.sort((a, b) => {
      const so = SEVERITY_ORDER;
      return (so[a.severity] ?? 99) - (so[b.severity] ?? 99);
    });
  }, [nodes, filterSeverity, filterProvider, filterType, searchTerm]);

  // Connection count per node (incoming + outgoing)
  const connCount = useMemo(() => {
    const counts = {};
    links.forEach(l => {
      counts[l.source] = (counts[l.source] || 0) + 1;
      counts[l.target] = (counts[l.target] || 0) + 1;
    });
    return counts;
  }, [links]);

  // Top connected nodes
  const topConnected = useMemo(() => {
    return [...nodes]
      .map(n => ({ ...n, connections: connCount[n.id] || 0 }))
      .filter(n => n.connections > 0)
      .sort((a, b) => b.connections - a.connections)
      .slice(0, 10);
  }, [nodes, connCount]);

  const resetFilters = () => {
    setFilterSeverity('');
    setFilterProvider('');
    setFilterType('');
    setSearchTerm('');
  };

  const kpiItems = [
    { label: 'Resources', value: kpi.nodes || nodes.length, icon: Box },
    { label: 'Relationships', value: kpi.edges || links.length, icon: Link2 },
    { label: 'Internet Exposed', value: kpi.internetExposed || 0, icon: Globe },
    { label: 'Avg Risk Score', value: kpi.avgRisk ? `${kpi.avgRisk}/100` : '0', icon: ShieldAlert },
  ];

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="flex gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="flex-1 h-20 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
          ))}
        </div>
        <LoadingSkeleton rows={10} cols={5} />
      </div>
    );
  }

  if (error) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title="Graph data unavailable"
        description={error}
        actionLabel="Go to Threat Graph"
        onAction={() => router.push('/attack-paths')}
      />
    );
  }

  if (!nodes.length) {
    return (
      <EmptyState
        icon={Network}
        title="No security relationships found"
        description="Run a discovery scan to populate the security relationship graph."
        actionLabel="View Threat Graph"
        onAction={() => router.push('/attack-paths')}
      />
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <Network className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Security Relationship Graph
          </h1>
          <a
            href="/attack-paths"
            className="ml-auto flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border"
            style={{ color: 'var(--accent-primary)', borderColor: 'var(--accent-primary)' }}
          >
            <ExternalLink className="w-3.5 h-3.5" />
            Full D3 Graph
          </a>
        </div>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Neo4j Aura security relationship graph — {nodes.length.toLocaleString()} resources, {links.length.toLocaleString()} relationships across all CSPs.
        </p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {kpiItems.map(item => {
          const Icon = item.icon;
          return (
            <div key={item.label} className="rounded-lg p-4 flex items-start gap-3"
              style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
              <Icon className="w-5 h-5 mt-0.5 flex-shrink-0" style={{ color: 'var(--accent-primary)' }} />
              <div>
                <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{item.label}</div>
                <div className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>{item.value}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Relationship type breakdown + Top connected */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Relationship types */}
        <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
            <Link2 className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
            Relationship Types
          </h3>
          <div className="space-y-2">
            {edgeCounts.slice(0, 8).map(([type, count]) => {
              const max = edgeCounts[0]?.[1] || 1;
              const pct = Math.round((count / max) * 100);
              return (
                <div key={type} className="flex items-center gap-2">
                  <span className="text-xs font-mono w-32 truncate" style={{ color: 'var(--text-secondary)' }}>{type}</span>
                  <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: 'var(--accent-primary)' }} />
                  </div>
                  <span className="text-xs tabular-nums w-10 text-right" style={{ color: 'var(--text-muted)' }}>
                    {count.toLocaleString()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top connected nodes */}
        <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
            <Layers className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
            Most Connected Resources
          </h3>
          <div className="space-y-1.5">
            {topConnected.map(n => {
              const Icon = typeIcon(n.type);
              return (
                <div key={n.id} className="flex items-center gap-2">
                  <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: severityColor(n.severity) }} />
                  <span className="text-xs flex-1 truncate" style={{ color: 'var(--text-primary)' }}>
                    {n.label || n.id?.split('/').pop() || n.id}
                  </span>
                  <span className="text-xs tabular-nums px-1.5 py-0.5 rounded-full"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                    {n.connections}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-tertiary)' }}>
          <Filter className="w-3.5 h-3.5" /> Filter:
        </div>
        <input
          placeholder="Search resources..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          className="px-2 py-1 text-xs rounded border outline-none"
          style={{
            backgroundColor: 'var(--bg-secondary)',
            borderColor: 'var(--border-primary)',
            color: 'var(--text-primary)',
            width: '180px',
          }}
        />
        <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}
          className="px-2 py-1 text-xs rounded border outline-none"
          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
          <option value="">All severities</option>
          {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filterProvider} onChange={e => setFilterProvider(e.target.value)}
          className="px-2 py-1 text-xs rounded border outline-none"
          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
          <option value="">All CSPs</option>
          {providers.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
        </select>
        <select value={filterType} onChange={e => setFilterType(e.target.value)}
          className="px-2 py-1 text-xs rounded border outline-none"
          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
          <option value="">All services</option>
          {services.slice(0, 30).map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {(filterSeverity || filterProvider || filterType || searchTerm) && (
          <button onClick={resetFilters} className="flex items-center gap-1 text-xs px-2 py-1 rounded border"
            style={{ color: 'var(--text-tertiary)', borderColor: 'var(--border-primary)' }}>
            <RotateCcw className="w-3 h-3" /> Reset
          </button>
        )}
        <span className="ml-auto text-xs" style={{ color: 'var(--text-muted)' }}>
          {filteredNodes.length.toLocaleString()} / {nodes.length.toLocaleString()} nodes
        </span>
      </div>

      {/* Node table */}
      <div className="rounded-lg overflow-hidden border" style={{ borderColor: 'var(--border-primary)' }}>
        <table className="w-full text-xs">
          <thead>
            <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-primary)' }}>
              {['Resource', 'Type', 'CSP', 'Region', 'Risk', 'Severity', 'Threats', 'Connections', ''].map(h => (
                <th key={h} className="px-3 py-2 text-left font-medium" style={{ color: 'var(--text-secondary)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredNodes.slice(0, 100).map((n, i) => {
              const Icon = typeIcon(n.type);
              const conns = connCount[n.id] || 0;
              return (
                <tr key={n.id || i}
                  onClick={() => router.push(`/inventory/${encodeURIComponent(n.id)}`)}
                  className="cursor-pointer transition-colors hover:bg-opacity-50"
                  style={{
                    borderBottom: '1px solid var(--border-primary)',
                    backgroundColor: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.backgroundColor = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'}
                >
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: severityColor(n.severity) }} />
                      <span className="truncate max-w-[200px]" style={{ color: 'var(--text-primary)' }}>
                        {n.label || n.id?.split('/').pop() || n.id}
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded"
                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                      {n.type || '—'}
                    </span>
                  </td>
                  <td className="px-3 py-2 uppercase font-mono" style={{ color: 'var(--text-secondary)' }}>
                    {n.provider || '—'}
                  </td>
                  <td className="px-3 py-2" style={{ color: 'var(--text-secondary)' }}>
                    {n.region || n.accountId?.slice(0, 12) || '—'}
                  </td>
                  <td className="px-3 py-2 tabular-nums font-medium" style={{ color: (n.riskScore || 0) >= 70 ? '#ef4444' : (n.riskScore || 0) >= 40 ? '#f97316' : 'var(--text-primary)' }}>
                    {n.riskScore ?? '—'}
                  </td>
                  <td className="px-3 py-2">
                    {n.severity ? <SeverityBadge severity={n.severity} /> : '—'}
                  </td>
                  <td className="px-3 py-2 tabular-nums" style={{ color: (n.threatCount || 0) > 0 ? '#f97316' : 'var(--text-muted)' }}>
                    {n.threatCount ?? '—'}
                  </td>
                  <td className="px-3 py-2 tabular-nums" style={{ color: conns > 5 ? 'var(--accent-primary)' : 'var(--text-secondary)' }}>
                    {conns}
                  </td>
                  <td className="px-3 py-2">
                    <ArrowRight className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {filteredNodes.length > 100 && (
          <div className="px-4 py-2 text-xs text-center" style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-tertiary)' }}>
            Showing 100 of {filteredNodes.length.toLocaleString()} — use filters to narrow results
          </div>
        )}
      </div>
    </div>
  );
}
