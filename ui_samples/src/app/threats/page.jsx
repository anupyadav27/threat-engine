'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield,
  AlertTriangle,
  Zap,
  Target,
  Globe,
  CheckCircle,
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { SEVERITY_COLORS } from '@/lib/constants';
import SeverityBadge from '@/components/shared/SeverityBadge';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';
import PageLayout from '@/components/shared/PageLayout';
import InsightRow from '@/components/shared/InsightRow';


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


// ── Inline Trend Chart ────────────────────────────────────────────────────────

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


// ── MITRE Compact Grid (extracted for InsightRow) ─────────────────────────────

function MitreCompactGrid({ mitreTactics, totalMitreTechniques, selectedTechnique, onSelectTechnique }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div>
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
          <button onClick={() => setCollapsed((v) => !v)} className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {collapsed ? 'Expand' : 'Collapse'}
          </button>
        )}
      </div>

      {mitreTactics.length === 0 ? (
        <div className="h-40 flex items-center justify-center">
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No MITRE mappings detected</p>
        </div>
      ) : collapsed ? (
        <div className="flex flex-wrap gap-1.5">
          {mitreTactics.map(({ tactic, totalCount }) => (
            <span key={tactic} className="text-[10px] font-medium px-2 py-1 rounded-md"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
              {tactic} <strong style={{ color: 'var(--text-primary)' }}>{totalCount}</strong>
            </span>
          ))}
        </div>
      ) : (
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
                        onClick={() => onSelectTechnique(isSelected ? null : tech.id)}
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
  );
}


// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ThreatsPage() {
  const router = useRouter();
  const { provider, account, region } = useGlobalFilter();

  // ── Data state ────────────────────────────────────────────────────────────
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [kpi, setKpi] = useState(null);
  const [threats, setThreats] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [mitreMatrix, setMitreMatrix] = useState({});

  // ── UI state ────────────────────────────────────────────────────────────
  const [selectedTechnique, setSelectedTechnique] = useState(null);

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

  // ── Unique values helper ──────────────────────────────────────────────
  const uniqueVals = useCallback((key) => {
    return [...new Set(threats.map(t => t[key]).filter(Boolean))].sort();
  }, [threats]);

  // ── Base threats (technique-filtered) ─────────────────────────────────
  const baseThreats = useMemo(() => {
    let result = threats;
    if (selectedTechnique) {
      result = result.filter((t) => t.mitreTechnique === selectedTechnique);
    }
    return [...result].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
  }, [threats, selectedTechnique]);

  // ── Primary filters ─────────────────────────────────────────────────────
  const primaryFilters = useMemo(() => {
    const f = [
      { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
    ];
    const statusVals = uniqueVals('status');
    if (statusVals.length > 0) f.push({ key: 'status', label: 'Status', options: statusVals });
    const providerVals = uniqueVals('provider');
    if (providerVals.length > 0) f.push({ key: 'provider', label: 'Provider', options: providerVals });
    const accountVals = uniqueVals('account');
    if (accountVals.length > 0) f.push({ key: 'account', label: 'Account', options: accountVals });
    const regionVals = uniqueVals('region');
    if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
    const categoryVals = uniqueVals('threat_category');
    if (categoryVals.length > 0) f.push({ key: 'threat_category', label: 'Category', options: categoryVals });
    return f;
  }, [threats, uniqueVals]);

  // ── Extra filters ────────────────────────────────────────────────────────
  const extraFilters = useMemo(() => {
    const extras = [];
    const ruleVals = uniqueVals('rule_id');
    if (ruleVals.length > 0) extras.push({ key: 'rule_id', label: 'Rule', options: ruleVals });
    const techVals = uniqueVals('mitreTechnique');
    if (techVals.length > 0) extras.push({ key: 'mitreTechnique', label: 'MITRE Technique', options: techVals });
    const tacticVals = uniqueVals('mitreTactic');
    if (tacticVals.length > 0) extras.push({ key: 'mitreTactic', label: 'MITRE Tactic', options: tacticVals });
    return extras;
  }, [threats, uniqueVals]);

  // ── Group-by options ──────────────────────────────────────────────────
  const groupByOptions = useMemo(() => [
    { key: 'severity', label: 'Severity' },
    { key: 'status', label: 'Status' },
    { key: 'provider', label: 'Provider' },
    { key: 'account', label: 'Account' },
    { key: 'region', label: 'Region' },
    { key: 'resourceType', label: 'Service' },
    { key: 'threat_category', label: 'Category' },
    { key: 'mitreTechnique', label: 'MITRE Technique' },
  ], []);

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

  // ── Tab definitions with counts ───────────────────────────────────────
  const tabDefs = useMemo(() => [
    { id: 'all', label: 'All', count: baseThreats.length },
    { id: 'critical', label: 'Critical', count: baseThreats.filter(t => t.severity === 'critical').length },
    { id: 'high', label: 'High', count: baseThreats.filter(t => t.severity === 'high').length },
    { id: 'attackPath', label: 'Has Attack Path', count: baseThreats.filter(t => t.hasAttackPath === true).length },
    { id: 'unassigned', label: 'Unassigned', count: baseThreats.filter(t => !t.assignee).length },
  ], [baseThreats]);

  // ── Tab data: each tab gets pre-filtered data ─────────────────────────
  const tabData = useMemo(() => {
    const shared = { columns, filters: primaryFilters, extraFilters, groupByOptions };
    return {
      all: { ...shared, data: baseThreats },
      critical: { ...shared, data: baseThreats.filter(t => t.severity === 'critical') },
      high: { ...shared, data: baseThreats.filter(t => t.severity === 'high') },
      attackPath: { ...shared, data: baseThreats.filter(t => t.hasAttackPath === true) },
      unassigned: { ...shared, data: baseThreats.filter(t => !t.assignee) },
    };
  }, [baseThreats, columns, primaryFilters, extraFilters, groupByOptions]);

  // ── Page context ──────────────────────────────────────────────────────
  const pageContext = useMemo(() => ({
    title: 'Threat Detection',
    brief: 'MITRE ATT&CK mapped threats across your cloud environment',
    details: [
      'Review critical and high-severity threats first for immediate action',
      'Use the MITRE grid to identify technique clusters and attack patterns',
      'Assign unresolved threats to team members for triage',
    ],
    tabs: tabDefs,
  }), [tabDefs]);

  // ── KPI groups ────────────────────────────────────────────────────────
  const kpiGroups = useMemo(() => [
    {
      title: 'Threat Severity',
      items: [
        { label: 'Total', value: stats.total ?? 0 },
        { label: 'Critical', value: stats.critical ?? 0 },
        { label: 'High', value: stats.high ?? 0 },
        { label: 'Risk Score', value: stats.avgRiskScore ?? 0, suffix: 'avg' },
      ],
    },
    {
      title: 'Operations',
      items: [
        { label: 'Active', value: stats.active ?? 0 },
        { label: 'Unassigned', value: stats.unassigned ?? 0 },
        { label: 'MITRE Techniques', value: totalMitreTechniques },
      ],
    },
  ], [stats, totalMitreTechniques]);

  // ── Insight Row: trend chart (left) + MITRE grid (right) ──────────────
  const insightRowContent = useMemo(() => (
    <InsightRow
      ratio="5fr 7fr"
      left={
        <div>
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
      }
      right={
        <MitreCompactGrid
          mitreTactics={mitreTactics}
          totalMitreTechniques={totalMitreTechniques}
          selectedTechnique={selectedTechnique}
          onSelectTechnique={setSelectedTechnique}
        />
      }
    />
  ), [trendData, mitreTactics, totalMitreTechniques, selectedTechnique]);

  // ── Row click handler ─────────────────────────────────────────────────
  const handleRowClick = useCallback((row) => {
    const threat = row?.original || row;
    if (threat?.id) router.push(`/threats/${threat.id}`);
  }, [router]);

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
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

      <PageLayout
        icon={Shield}
        pageContext={pageContext}
        kpiGroups={kpiGroups}
        insightRow={insightRowContent}
        tabData={tabData}
        loading={loading}
        error={error}
        defaultTab="all"
        onRowClick={handleRowClick}
      />
    </div>
  );
}
