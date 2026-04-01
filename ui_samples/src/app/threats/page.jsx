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
import { AreaChart, Area, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { SEVERITY_COLORS } from '@/lib/constants';
import SeverityBadge from '@/components/shared/SeverityBadge';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';
import PageLayout from '@/components/shared/PageLayout';
import InsightRow from '@/components/shared/InsightRow';

const MOCK_THREAT_TREND = [
  { date: 'Jan 6',  critical: 10, high: 32, medium: 18, low: 5 },
  { date: 'Jan 13', critical: 12, high: 34, medium: 21, low: 6 },
  { date: 'Jan 20', critical: 15, high: 31, medium: 19, low: 4 },
  { date: 'Jan 27', critical: 11, high: 29, medium: 22, low: 7 },
  { date: 'Feb 3',  critical: 14, high: 33, medium: 20, low: 5 },
  { date: 'Feb 10', critical: 9,  high: 27, medium: 17, low: 4 },
  { date: 'Feb 17', critical: 11, high: 25, medium: 15, low: 3 },
  { date: 'Feb 24', critical: 8,  high: 22, medium: 13, low: 3 },
  { date: 'Mar 3',  critical: 7,  high: 21, medium: 12, low: 2 },
  { date: 'Mar 10', critical: 4,  high: 18, medium: 10, low: 2 },
];

// Sparkline data per KPI card (10 weekly points)
const THREAT_SPARKLINES = {
  total:       [40, 45, 52, 48, 60, 56, 51, 47, 43, 40],
  critical:    [12, 15, 11, 14,  9, 11,  8,  7,  5,  4],
  high:        [32, 34, 31, 33, 27, 25, 22, 21, 19, 18],
  riskScore:   [51, 54, 50, 56, 48, 49, 47, 46, 44, 48],
  attackPaths: [7, 9, 8, 11, 10, 12, 10, 9, 9, 9],
  active:      [18, 22, 20, 24, 19, 21, 18, 17, 16, 15],
};

const SPARK_TICKS = [
  { idx: 0, label: '8w' },
  { idx: 4, label: '4w' },
  { idx: 9, label: 'Now' },
];

// colour palette
const TC = {
  critical: '#ef4444',
  orange:   '#f97316',
  amber:    '#eab308',
  sky:      '#38bdf8',
  violet:   '#8b5cf6',
  emerald:  '#10b981',
};


// ── Threat Sparkline (pure SVG) ────────────────────────────────────────────────
function ThreatSparkline({ values = [], color = '#60a5fa', ticks = [] }) {
  const W = 120, H = 38, PAD_T = 4, PAD_B = ticks.length ? 18 : 6, PAD_X = 4;
  const min = Math.min(...values), max = Math.max(...values);
  const range = max - min || 1;
  const n = values.length;
  const pts = values.map((v, i) => [
    PAD_X + (i / (n - 1)) * (W - PAD_X * 2),
    PAD_T + (1 - (v - min) / range) * (H - PAD_T - PAD_B),
  ]);
  const line = pts.map((p, i) => (i === 0 ? `M${p[0]},${p[1]}` : `L${p[0]},${p[1]}`)).join(' ');
  const area = `${line} L${pts[n-1][0]},${H - PAD_B} L${pts[0][0]},${H - PAD_B} Z`;
  const gradId = `tsg-${color.replace('#','')}`;
  return (
    <svg width={W} height={H} style={{ display:'block', overflow:'visible' }}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor={color} stopOpacity="0.22" />
          <stop offset="100%" stopColor={color} stopOpacity="0.01" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gradId})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      {ticks.map(({ idx, label }) => idx < n && (
        <text key={label}
          x={pts[idx][0]} y={H - 2}
          textAnchor={idx === 0 ? 'start' : idx === n - 1 ? 'end' : 'middle'}
          style={{ fontSize: 9, fill: 'var(--text-muted)', fontFamily: 'inherit' }}>
          {label}
        </text>
      ))}
    </svg>
  );
}

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
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 4 }}>
        <defs>
          <linearGradient id="gc" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.18}/>
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="gh" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#f97316" stopOpacity={0.15}/>
            <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="gm" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#eab308" stopOpacity={0.12}/>
            <stop offset="95%" stopColor="#eab308" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="gl" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.10}/>
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
        <XAxis dataKey="date" tick={AXIS_TICK} stroke="rgba(255,255,255,0.08)"
          tickFormatter={(v) => {
            if (!v) return '';
            // ISO date "2026-01-13" → "Jan 13"
            if (v.includes('-') && v.length >= 10) {
              const d = new Date(v);
              return d.toLocaleDateString('en-US', { month:'short', day:'numeric' });
            }
            return v; // already "Jan 13"
          }}
          interval="preserveStartEnd" />
        <YAxis tick={AXIS_TICK} stroke="rgba(255,255,255,0.08)" />
        <Tooltip
          contentStyle={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
            borderRadius: '0.5rem',
            boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
            color: 'var(--text-primary)',
            fontSize: 12,
          }}
        />
        <Legend
          wrapperStyle={{ paddingTop: 4, fontSize: 11 }}
          formatter={(val) => <span style={{ color: 'var(--text-tertiary)', textTransform: 'capitalize' }}>{val}</span>}
        />
        <Area type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} fill="url(#gc)" dot={false} />
        <Area type="monotone" dataKey="high"     stroke="#f97316" strokeWidth={2} fill="url(#gh)" dot={false} />
        <Area type="monotone" dataKey="medium"   stroke="#eab308" strokeWidth={1.5} fill="url(#gm)" dot={false} />
        <Area type="monotone" dataKey="low"      stroke="#3b82f6" strokeWidth={1.5} fill="url(#gl)" dot={false} />
      </AreaChart>
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
    { id: 'overview',   label: 'Overview' },
    { id: 'all', label: 'All', count: baseThreats.length },
    { id: 'critical', label: 'Critical', count: baseThreats.filter(t => t.severity === 'critical').length },
    { id: 'high', label: 'High', count: baseThreats.filter(t => t.severity === 'high').length },
    { id: 'attackPath', label: 'Has Attack Path', count: baseThreats.filter(t => t.hasAttackPath === true).length },
    { id: 'unassigned', label: 'Unassigned', count: baseThreats.filter(t => !t.assignee).length },
  ], [baseThreats]);

  // ── Tab data: each tab gets pre-filtered data ─────────────────────────
  const tabData = useMemo(() => {
    return {
      all: { columns, data: baseThreats },
      critical: { columns, data: baseThreats.filter(t => t.severity === 'critical') },
      high: { columns, data: baseThreats.filter(t => t.severity === 'high') },
      attackPath: { columns, data: baseThreats.filter(t => t.hasAttackPath === true) },
      unassigned: { columns, data: baseThreats.filter(t => !t.assignee) },
    };
  }, [baseThreats, columns]);

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

  // ── Custom KPI strip ─────────────────────────────────────────────────
  const attackPathCount = useMemo(() => baseThreats.filter(t => t.hasAttackPath).length, [baseThreats]);
  const resolvedCount   = useMemo(() => threats.filter(t => t.status === 'resolved').length, [threats]);

  const kpiStripNode = useMemo(() => (
    <div style={{ display:'grid', gridTemplateColumns:'repeat(6, minmax(0, 1fr))', gap:10, marginBottom:16 }}>

      {/* Total Threats */}
      <div style={{ borderRadius:10, padding:'12px 14px',
        backgroundColor:'var(--bg-card)',
        border:'1px solid rgba(96,165,250,0.22)',
        boxShadow:'0 4px 20px rgba(96,165,250,0.08)' }}>
        <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:4, letterSpacing:'0.01em' }}>Total Threats</div>
        <div style={{ display:'flex', alignItems:'baseline', gap:6, marginBottom:2 }}>
          <span style={{ fontSize:28, fontWeight:900, color:'var(--text-primary)', lineHeight:1 }}>{stats.total ?? 40}</span>
          <span style={{ fontSize:11, fontWeight:700, padding:'1px 6px', borderRadius:4,
            backgroundColor:'rgba(239,68,68,0.12)', color:'#ef4444' }}>↓ 6.2%</span>
        </div>
        <div style={{ fontSize:11, color:'var(--text-tertiary)', marginBottom:6 }}>vs last 8 scans</div>
        <ThreatSparkline values={THREAT_SPARKLINES.total} color={TC.sky} ticks={SPARK_TICKS} />
      </div>

      {/* Critical */}
      <div style={{ borderRadius:10, padding:'12px 14px',
        backgroundColor:'var(--bg-card)',
        border:'1px solid rgba(239,68,68,0.22)',
        boxShadow:'0 4px 20px rgba(239,68,68,0.10)' }}>
        <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:4 }}>Critical</div>
        <div style={{ display:'flex', alignItems:'baseline', gap:6, marginBottom:2 }}>
          <span style={{ fontSize:28, fontWeight:900, color:TC.critical, lineHeight:1 }}>{stats.critical ?? 4}</span>
          <span style={{ fontSize:11, fontWeight:700, padding:'1px 6px', borderRadius:4,
            backgroundColor:'rgba(239,68,68,0.12)', color:'#ef4444' }}>↓ 67%</span>
        </div>
        <div style={{ fontSize:11, color:'var(--text-tertiary)', marginBottom:6 }}>from 12 peak · 8 scans</div>
        <ThreatSparkline values={THREAT_SPARKLINES.critical} color={TC.critical} ticks={SPARK_TICKS} />
      </div>

      {/* High */}
      <div style={{ borderRadius:10, padding:'12px 14px',
        backgroundColor:'var(--bg-card)',
        border:'1px solid rgba(249,115,22,0.22)',
        boxShadow:'0 4px 20px rgba(249,115,22,0.08)' }}>
        <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:4 }}>High Severity</div>
        <div style={{ display:'flex', alignItems:'baseline', gap:6, marginBottom:2 }}>
          <span style={{ fontSize:28, fontWeight:900, color:TC.orange, lineHeight:1 }}>{stats.high ?? 5}</span>
          <span style={{ fontSize:11, fontWeight:700, padding:'1px 6px', borderRadius:4,
            backgroundColor:'rgba(249,115,22,0.12)', color:TC.orange }}>↓ 44%</span>
        </div>
        <div style={{ fontSize:11, color:'var(--text-tertiary)', marginBottom:6 }}>from 34 peak · 8 scans</div>
        <ThreatSparkline values={THREAT_SPARKLINES.high} color={TC.orange} ticks={SPARK_TICKS} />
      </div>

      {/* Avg Risk Score */}
      <div style={{ borderRadius:10, padding:'12px 14px',
        backgroundColor:'var(--bg-card)',
        border:'1px solid rgba(234,179,8,0.22)',
        boxShadow:'0 4px 20px rgba(234,179,8,0.08)' }}>
        <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:4 }}>Avg Risk Score</div>
        <div style={{ display:'flex', alignItems:'baseline', gap:4, marginBottom:2 }}>
          <span style={{ fontSize:28, fontWeight:900, color:TC.amber, lineHeight:1 }}>{stats.avgRiskScore ?? 47}</span>
          <span style={{ fontSize:13, color:'var(--text-muted)' }}>/100</span>
        </div>
        <div style={{ fontSize:11, color:'var(--text-tertiary)', marginBottom:6 }}>Medium-High risk band</div>
        <div style={{ height:4, borderRadius:2, backgroundColor:'var(--bg-tertiary)', marginBottom:8 }}>
          <div style={{ height:'100%', borderRadius:2, width:`${stats.avgRiskScore ?? 47}%`,
            background:`linear-gradient(90deg, ${TC.emerald}, ${TC.amber})` }} />
        </div>
        <ThreatSparkline values={THREAT_SPARKLINES.riskScore} color={TC.amber} ticks={SPARK_TICKS} />
      </div>

      {/* Attack Paths */}
      <div style={{ borderRadius:10, padding:'12px 14px',
        backgroundColor:'var(--bg-card)',
        boxShadow:'0 4px 20px rgba(139,92,246,0.08)',
        border:'1px solid rgba(139,92,246,0.22)' }}>
        <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:4 }}>Attack Paths</div>
        <div style={{ display:'flex', alignItems:'baseline', gap:6, marginBottom:2 }}>
          <span style={{ fontSize:28, fontWeight:900, color:TC.violet, lineHeight:1 }}>{attackPathCount}</span>
          <span style={{ fontSize:11, fontWeight:700, padding:'1px 6px', borderRadius:4,
            backgroundColor:'rgba(139,92,246,0.14)', color:TC.violet }}>⚡ Active</span>
        </div>
        <div style={{ fontSize:11, color:'var(--text-tertiary)', marginBottom:6 }}>
          MITRE: <strong style={{ color:'var(--text-secondary)', fontWeight:700 }}>{totalMitreTechniques} techniques</strong>
        </div>
        <ThreatSparkline values={THREAT_SPARKLINES.attackPaths} color={TC.violet} ticks={SPARK_TICKS} />
      </div>

      {/* Active / Resolved */}
      <div style={{ borderRadius:10, padding:'12px 14px',
        backgroundColor:'var(--bg-card)',
        boxShadow:'0 4px 20px rgba(16,185,129,0.08)',
        border:'1px solid rgba(16,185,129,0.22)' }}>
        <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:4 }}>Active Threats</div>
        <div style={{ display:'flex', alignItems:'baseline', gap:6, marginBottom:6 }}>
          <span style={{ fontSize:28, fontWeight:900, color:TC.emerald, lineHeight:1 }}>{stats.active ?? 15}</span>
          <span style={{ fontSize:11, fontWeight:700, padding:'1px 6px', borderRadius:4,
            backgroundColor:'rgba(16,185,129,0.12)', color:TC.emerald }}>↓ 17%</span>
        </div>
        <div style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}>
          <span style={{ fontSize:11, color:'var(--text-tertiary)' }}>Resolved</span>
          <span style={{ fontSize:11, fontWeight:700, color:TC.emerald }}>{resolvedCount}</span>
        </div>
        <div style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
          <span style={{ fontSize:11, color:'var(--text-tertiary)' }}>Unassigned</span>
          <span style={{ fontSize:11, fontWeight:700, color:TC.amber }}>{stats.unassigned ?? 31}</span>
        </div>
        <ThreatSparkline values={THREAT_SPARKLINES.active} color={TC.emerald} ticks={SPARK_TICKS} />
      </div>

    </div>
  ), [stats, attackPathCount, resolvedCount, totalMitreTechniques]);

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
            <TrendChartInline data={trendData.length > 0 ? trendData : MOCK_THREAT_TREND} />
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

      {/* ── Page heading ── */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Shield className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>{pageContext.title}</h1>
          </div>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{pageContext.brief}</p>
        </div>
      </div>

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
        kpiGroups={[]}
        tabData={{ overview: { renderTab: () => <>{kpiStripNode}{insightRowContent}</> }, ...tabData }}
        loading={loading}
        error={error}
        defaultTab="overview"
        onRowClick={handleRowClick}
        hideHeader
        topNav
      />
    </div>
  );
}
