'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield,
  AlertTriangle,
  Activity,
  Zap,
  ChevronDown,
  ChevronUp,
  Target,
  Globe,
  CheckCircle,
  ExternalLink,
  Search,
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { SEVERITY_COLORS, SEVERITY_ORDER, CLOUD_PROVIDERS } from '@/lib/constants';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import DataTable from '@/components/shared/DataTable';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';


// ── Helpers ────────────────────────────────────────────────────────────────────

function relativeTime(dateStr) {
  if (!dateStr) return '—';
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  const days = Math.floor(hours / 24);
  if (hours < 1) return 'Just now';
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

const PROVIDER_COLORS = {
  AWS: '#f97316', Azure: '#3b82f6', GCP: '#eab308',
  OCI: '#8b5cf6', AliCloud: '#ff6a00', IBM: '#1f70c1',
};

function riskColor(score) {
  if (score >= 85) return '#ef4444';
  if (score >= 70) return '#f97316';
  if (score >= 50) return '#eab308';
  return '#22c55e';
}

/** MITRE compact cell — severity-based heat */
function mitreCellBg(severity, count) {
  const base = severity === 'critical'
    ? { r: 239, g: 68, b: 68 }
    : severity === 'high'
      ? { r: 249, g: 115, b: 22 }
      : { r: 234, g: 179, b: 8 };
  const a = 0.1 + Math.min(count / 15, 1) * 0.25;
  return `rgba(${base.r},${base.g},${base.b},${a})`;
}

const THREAT_STATUS = {
  active: { dot: '#ef4444', label: 'Active', animation: 'animate-pulse' },
  investigating: { dot: '#f97316', label: 'Investigating', animation: 'animate-pulse' },
  resolved: { dot: '#22c55e', label: 'Resolved', animation: '' },
  suppressed: { dot: '#6b7280', label: 'Suppressed', animation: '' },
  'false-positive': { dot: '#6b7280', label: 'False Positive', animation: '' },
};

const TABLE_TABS = [
  { key: 'all', label: 'All' },
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'attackPath', label: 'Has Attack Path' },
  { key: 'unassigned', label: 'Unassigned' },
];

function Section({ children, error, title }) {
  if (error) {
    return (
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
          <div>
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>Failed to load {title || 'section'}</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

// ── Inline Trend Chart (no external component dependency) ────────────────────

const AXIS_TICK = { fill: 'var(--text-tertiary)', fontSize: 11 };

function TrendChartInline({ data }) {
  if (!data || data.length === 0) return null;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 8, right: 12, left: -10, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" />
        <XAxis dataKey="date" tick={AXIS_TICK} stroke="var(--border-primary)" tickFormatter={(v) => v?.slice(5)} />
        <YAxis tick={AXIS_TICK} stroke="var(--border-primary)" />
        <Tooltip
          contentStyle={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
            borderRadius: '0.5rem',
            boxShadow: '0 4px 6px rgba(0,0,0,0.3)',
            color: 'var(--text-primary)',
            fontSize: 12,
          }}
        />
        <Legend
          wrapperStyle={{ paddingTop: 0, fontSize: 11 }}
          formatter={(val) => <span style={{ color: 'var(--text-tertiary)', textTransform: 'capitalize' }}>{val}</span>}
        />
        <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} />
        <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} />
        <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={1.5} dot={false} />
        <Line type="monotone" dataKey="low" stroke="#3b82f6" strokeWidth={1.5} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}


// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ThreatsPage() {
  const router = useRouter();
  const { provider, account, region, filterSummary } = useGlobalFilter();

  // ── Data state ────────────────────────────────────────────────────────────
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [kpi, setKpi] = useState(null);
  const [threats, setThreats] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [mitreMatrix, setMitreMatrix] = useState({});

  // ── UI state ────────────────────────────────────────────────────────────
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('all');
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [mitreCollapsed, setMitreCollapsed] = useState(false);

  // ── Fetch ─────────────────────────────────────────────────────────────
  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchView('threats', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.kpi) setKpi(data.kpi);
        if (data.threats) setThreats(data.threats);
        if (data.trendData) setTrendData(data.trendData);
        if (data.mitreMatrix) setMitreMatrix(data.mitreMatrix);
      } catch (err) {
        console.warn('[threats] fetch error:', err);
        setError('Failed to load threats data');
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [provider, account, region]);

  // ── Computed stats ──────────────────────────────────────────────────────
  const stats = useMemo(() => {
    if (kpi) return kpi;
    return {
      total: threats.length,
      critical: threats.filter((t) => t.severity === 'critical').length,
      high: threats.filter((t) => t.severity === 'high').length,
      medium: threats.filter((t) => t.severity === 'medium').length,
      low: threats.filter((t) => t.severity === 'low').length,
      active: threats.filter((t) => t.status === 'active').length,
      unassigned: threats.filter((t) => !t.assignee).length,
      avgRiskScore: threats.length
        ? Math.round(threats.reduce((s, t) => s + (t.riskScore || 0), 0) / threats.length)
        : 0,
      deltas: {},
    };
  }, [kpi, threats]);

  // ── MITRE flat list for compact grid ───────────────────────────────────
  const mitreTactics = useMemo(() => {
    return Object.entries(mitreMatrix).map(([tactic, techniques]) => ({
      tactic,
      techniques: (techniques || []).sort((a, b) => (b.count || 0) - (a.count || 0)),
      totalCount: (techniques || []).reduce((s, t) => s + (t.count || 0), 0),
    }));
  }, [mitreMatrix]);

  const totalMitreTechniques = useMemo(() => {
    return mitreTactics.reduce((s, t) => s + t.techniques.length, 0);
  }, [mitreTactics]);

  // ── Filtered threats ───────────────────────────────────────────────────
  const filteredThreats = useMemo(() => {
    let result = threats;
    if (selectedTechnique) {
      result = result.filter((t) => t.mitreTechnique === selectedTechnique);
    }
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      result = result.filter((t) =>
        (t.title || '').toLowerCase().includes(s) ||
        (t.mitreTechnique || '').toLowerCase().includes(s) ||
        (t.resourceType || '').toLowerCase().includes(s) ||
        (t.account || '').toLowerCase().includes(s) ||
        (t.region || '').toLowerCase().includes(s) ||
        (t.provider || '').toLowerCase().includes(s) ||
        (t.threat_category || '').toLowerCase().includes(s)
      );
    }
    switch (activeTab) {
      case 'critical': result = result.filter((t) => t.severity === 'critical'); break;
      case 'high': result = result.filter((t) => t.severity === 'high'); break;
      case 'attackPath': result = result.filter((t) => t.hasAttackPath === true); break;
      case 'unassigned': result = result.filter((t) => !t.assignee); break;
    }
    return [...result].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
  }, [threats, searchTerm, activeTab, selectedTechnique]);

  // ── Table columns ─────────────────────────────────────────────────────
  const columns = useMemo(() => [
    {
      accessorKey: 'provider',
      header: 'Provider',
      size: 85,
      cell: (info) => {
        const p = info.getValue();
        if (!p) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>;
        const color = PROVIDER_COLORS[p] || '#6b7280';
        return (
          <span className="text-xs font-semibold px-2 py-0.5 rounded-full whitespace-nowrap" style={{ backgroundColor: `${color}20`, color }}>
            {p}
          </span>
        );
      },
    },
    {
      accessorKey: 'account',
      header: 'Account',
      size: 120,
      cell: (info) => (
        <span className="text-xs font-mono whitespace-nowrap" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'resourceType',
      header: 'Service',
      size: 100,
      cell: (info) => {
        const val = info.getValue();
        if (!val) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>;
        return (
          <span className="text-xs px-2 py-0.5 rounded whitespace-nowrap" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
            {val}
          </span>
        );
      },
    },
    {
      accessorKey: 'region',
      header: 'Region',
      size: 110,
      cell: (info) => (
        <span className="text-xs whitespace-nowrap" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'title',
      header: 'Threat',
      cell: (info) => {
        const row = info.row.original;
        const findingCount = row.finding_count || row.affected_resources || 0;
        return (
          <div>
            <div className="flex items-center gap-2">
              <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</div>
              {findingCount > 0 && (
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full tabular-nums" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                  {findingCount} {findingCount === 1 ? 'finding' : 'findings'}
                </span>
              )}
            </div>
            <div className="flex flex-wrap gap-1 mt-1">
              {row.mitreTechnique && (
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: 'rgba(59,130,246,0.12)', color: '#60a5fa' }}>
                  {row.mitreTechnique}
                </span>
              )}
              {row.threat_category && (
                <span className="text-[10px] font-medium px-1.5 py-0.5 rounded" style={{ backgroundColor: 'rgba(139,92,246,0.10)', color: '#a78bfa' }}>
                  {row.threat_category.replace(/_/g, ' ')}
                </span>
              )}
              {row.isInternetExposed && (
                <span className="inline-flex items-center gap-0.5 text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: 'rgba(239,68,68,0.10)', color: '#ef4444' }}>
                  <Globe className="w-2.5 h-2.5" /> Exposed
                </span>
              )}
              {row.hasAttackPath && (
                <span className="inline-flex items-center gap-0.5 text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: 'rgba(249,115,22,0.12)', color: '#f97316' }}>
                  <Zap className="w-2.5 h-2.5" /> Attack Path
                </span>
              )}
              {row.remediationSteps?.length > 0 && (
                <span className="inline-flex items-center gap-0.5 text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: 'rgba(34,197,94,0.12)', color: '#22c55e' }}>
                  <CheckCircle className="w-2.5 h-2.5" /> Fix
                </span>
              )}
            </div>
          </div>
        );
      },
    },
    {
      accessorKey: 'riskScore',
      header: 'Risk',
      size: 90,
      cell: (info) => {
        const score = info.getValue() || 0;
        const color = riskColor(score);
        return (
          <div className="flex items-center gap-2">
            <div className="w-12 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
            </div>
            <span className="text-xs font-bold tabular-nums w-6" style={{ color }}>{score}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 95,
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'lastSeen',
      header: 'Last Seen',
      size: 100,
      cell: (info) => (
        <span className="text-xs whitespace-nowrap" style={{ color: 'var(--text-tertiary)' }}>
          {relativeTime(info.getValue() || info.row.original.detected)}
        </span>
      ),
    },
  ], []);

  // ── Tab counts ─────────────────────────────────────────────────────────
  const tabCounts = useMemo(() => {
    let base = threats;
    if (selectedTechnique) base = base.filter((t) => t.mitreTechnique === selectedTechnique);
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      base = base.filter((t) => (t.title || '').toLowerCase().includes(s) || (t.mitreTechnique || '').toLowerCase().includes(s));
    }
    return {
      all: base.length,
      critical: base.filter((t) => t.severity === 'critical').length,
      high: base.filter((t) => t.severity === 'high').length,
      attackPath: base.filter((t) => t.hasAttackPath === true).length,
      unassigned: base.filter((t) => !t.assignee).length,
    };
  }, [threats, searchTerm, selectedTechnique]);

  // ── Loading ────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="space-y-4">
        <div className="space-y-2">
          <div className="h-8 w-64 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-4 w-96 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        </div>
        <div className="h-20 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }} />
        <div className="grid grid-cols-2 gap-4">
          <div className="h-52 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }} />
          <div className="h-52 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }} />
        </div>
        <LoadingSkeleton rows={8} cols={6} />
      </div>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      {/* Error banner */}
      {error && (
        <div className="rounded-lg p-3 border flex items-center gap-3" style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: '#ef4444' }}>
          <AlertTriangle className="w-4 h-4 flex-shrink-0" style={{ color: '#ef4444' }} />
          <p className="text-sm" style={{ color: '#ef4444' }}>{error}</p>
        </div>
      )}

      {/* ── HEADER ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Threat Detection
          </h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
            MITRE ATT&CK mapped threats across your cloud environment
          </p>
        </div>
      </div>

      <ThreatsSubNav />

      {/* Technique filter chip */}
      {selectedTechnique && (
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm" style={{ backgroundColor: 'rgba(59,130,246,0.08)', borderColor: 'rgba(59,130,246,0.3)' }}>
          <Target className="w-3.5 h-3.5" style={{ color: '#60a5fa' }} />
          <span style={{ color: '#60a5fa' }}>
            Filtered: <strong>{selectedTechnique}</strong>
          </span>
          <button onClick={() => setSelectedTechnique(null)} className="ml-auto text-xs font-medium px-2 py-0.5 rounded hover:opacity-75" style={{ color: '#60a5fa' }}>
            Clear
          </button>
        </div>
      )}

      {/* ── METRIC STRIP ───────────────────────────────────────────────── */}
      <MetricStrip groups={[
        {
          label: '🔴 THREAT SEVERITY',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'TOTAL', value: (stats.total ?? 0).toLocaleString(), valueColor: 'var(--text-primary)', context: 'detected findings' },
            { label: 'CRITICAL', value: stats.critical ?? 0, valueColor: 'var(--severity-critical)', delta: stats.deltas?.critical?.value ?? null, deltaGoodDown: true, context: stats.deltas?.critical ? 'vs last 7d' : 'immediate action' },
            { label: 'HIGH', value: stats.high ?? 0, valueColor: 'var(--severity-high)', delta: stats.deltas?.high?.value ?? null, deltaGoodDown: true, context: stats.deltas?.high ? 'vs last 7d' : 'needs attention' },
            { label: 'RISK SCORE', value: stats.avgRiskScore ?? 0, valueColor: riskColor(stats.avgRiskScore || 0), noTrend: true, context: 'average' },
          ],
        },
        {
          label: '🟡 OPERATIONS',
          color: '#eab308',
          cells: [
            { label: 'ACTIVE', value: stats.active ?? 0, valueColor: stats.active > 0 ? 'var(--severity-high)' : 'var(--accent-success)', context: 'open' },
            { label: 'UNASSIGNED', value: stats.unassigned ?? 0, valueColor: stats.unassigned > 0 ? 'var(--severity-high)' : 'var(--accent-success)', context: 'needs triage' },
            { label: 'MITRE', value: `${totalMitreTechniques}`, noTrend: true, context: `${mitreTactics.length} tactics` },
          ],
        },
      ]} />

      {/* ── ROW 2: TREND (narrow) + MITRE (wide) ────────────────────── */}
      <div className="grid gap-4" style={{ gridTemplateColumns: 'minmax(0, 5fr) minmax(0, 7fr)' }}>
        {/* 30-Day Trend — compact */}
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
            30-Day Threat Trend
          </h3>
          <div style={{ height: 180 }}>
            {trendData.length > 0 ? (
              <TrendChartInline data={trendData} />
            ) : (
              <div className="h-full flex items-center justify-center">
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No trend data available</p>
              </div>
            )}
          </div>
        </div>

        {/* MITRE ATT&CK Compact Grid */}
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                MITRE ATT&CK Coverage
              </h3>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium" style={{ backgroundColor: 'rgba(59,130,246,0.12)', color: '#60a5fa' }}>
                {totalMitreTechniques} techniques
              </span>
            </div>
            {mitreTactics.length > 0 && (
              <button onClick={() => setMitreCollapsed((v) => !v)} className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {mitreCollapsed ? 'Expand' : 'Collapse'}
              </button>
            )}
          </div>

          {mitreTactics.length === 0 ? (
            <div className="h-40 flex items-center justify-center">
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No MITRE mappings detected</p>
            </div>
          ) : mitreCollapsed ? (
            /* Collapsed: single-row summary */
            <div className="flex flex-wrap gap-1.5">
              {mitreTactics.map(({ tactic, totalCount }) => (
                <span
                  key={tactic}
                  className="text-[10px] font-medium px-2 py-1 rounded-md"
                  style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
                >
                  {tactic} <strong style={{ color: 'var(--text-primary)' }}>{totalCount}</strong>
                </span>
              ))}
            </div>
          ) : (
            /* Expanded: compact grid — taller to show more techniques */
            <div className="overflow-x-auto overflow-y-auto" style={{ maxHeight: 260 }}>
              <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${Math.min(mitreTactics.length, 8)}, minmax(110px, 1fr))` }}>
                {mitreTactics.map(({ tactic, techniques }) => (
                  <div key={tactic}>
                    <p className="text-[9px] font-bold uppercase tracking-wider mb-1.5 truncate" style={{ color: 'var(--text-muted)' }}>
                      {tactic}
                    </p>
                    <div className="space-y-1">
                      {techniques.slice(0, 5).map((tech) => {
                        const isSelected = selectedTechnique === tech.id;
                        return (
                          <div
                            key={tech.id}
                            onClick={() => setSelectedTechnique(isSelected ? null : tech.id)}
                            className="px-2 py-1 rounded cursor-pointer transition-all text-[10px]"
                            style={{
                              backgroundColor: mitreCellBg(tech.severity || 'medium', tech.count || 0),
                              border: isSelected ? '1px solid var(--accent-primary)' : '1px solid transparent',
                            }}
                          >
                            <div className="flex items-center justify-between gap-1">
                              <span className="font-mono font-bold truncate" style={{ color: 'var(--accent-primary)' }}>
                                {tech.id}
                              </span>
                              <span className="font-bold tabular-nums flex-shrink-0" style={{ color: SEVERITY_COLORS[tech.severity] || '#eab308' }}>
                                {tech.count}
                              </span>
                            </div>
                            <p className="truncate mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{tech.name}</p>
                          </div>
                        );
                      })}
                      {techniques.length > 5 && (
                        <p className="text-[9px] text-center" style={{ color: 'var(--text-muted)' }}>
                          +{techniques.length - 5} more
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── THREATS TABLE (hero section) ───────────────────────────────── */}
      <div className="rounded-xl border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        {/* Tab bar + search */}
        <div className="flex items-center justify-between px-4 pt-3 pb-0 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-0.5 overflow-x-auto">
            {TABLE_TABS.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className="px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors relative"
                style={{ color: activeTab === tab.key ? 'var(--accent-primary)' : 'var(--text-muted)' }}
              >
                {tab.label}
                <span className="ml-1 text-xs tabular-nums" style={{ color: 'var(--text-tertiary)' }}>
                  ({tabCounts[tab.key] ?? 0})
                </span>
                {activeTab === tab.key && (
                  <div className="absolute bottom-0 left-0 right-0 h-0.5 rounded-full" style={{ backgroundColor: 'var(--accent-primary)' }} />
                )}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2 pb-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Search threats..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-xs rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500"
                style={{
                  backgroundColor: 'var(--bg-tertiary)',
                  borderColor: 'var(--border-primary)',
                  color: 'var(--text-primary)',
                  width: 200,
                }}
              />
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="p-4">
          <DataTable
            data={filteredThreats}
            columns={columns}
            pageSize={25}
            onRowClick={(threat) => router.push(`/threats/${threat.id}`)}
            loading={false}
            emptyMessage="No threats match the selected filters"
          />
        </div>
      </div>
    </div>
  );
}
