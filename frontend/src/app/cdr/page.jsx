'use client';

import { useState, useMemo, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Eye } from 'lucide-react';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { useViewFetch } from '@/lib/use-view-fetch';
import { subscribeRefresh, emitRefresh } from '@/lib/refreshBus';
import { fetchView } from '@/lib/api';
import EngineShell from '@/components/shared/EngineShell';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
import KpiCard from '@/components/shared/KpiCard';
import IdentityRiskHeatmap from '@/components/cdr/IdentityRiskHeatmap';
import CorrelationTimeline from '@/components/cdr/CorrelationTimeline';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';
import DataTable from '@/components/shared/DataTable';

const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  emerald:  '#10b981',
  amber:    '#f59e0b',
  purple:   '#8b5cf6',
  indigo:   '#6366f1',
};

function CiemDonut({ slices, size = 150 }) {
  const total = slices.reduce((s, x) => s + x.value, 0) || 1;
  const cx = size / 2, cy = size / 2;
  const r  = size / 2 - 8;
  const ir = r * 0.58;
  const gapA   = (2.5 / 360) * 2 * Math.PI;
  const labelR = (r + ir) / 2;
  let angle = -Math.PI / 2;

  const paths = slices.filter(s => s.value > 0).map(s => {
    const pct   = Math.round((s.value / total) * 100);
    const sweep = Math.max((s.value / total) * 2 * Math.PI - gapA, 0.001);
    const a0 = angle + gapA / 2, a1 = a0 + sweep;
    const mid = (a0 + a1) / 2;
    const large = sweep > Math.PI ? 1 : 0;
    const d = [
      `M ${cx + r  * Math.cos(a0)} ${cy + r  * Math.sin(a0)}`,
      `A ${r}  ${r}  0 ${large} 1 ${cx + r  * Math.cos(a1)} ${cy + r  * Math.sin(a1)}`,
      `L ${cx + ir * Math.cos(a1)} ${cy + ir * Math.sin(a1)}`,
      `A ${ir} ${ir} 0 ${large} 0 ${cx + ir * Math.cos(a0)} ${cy + ir * Math.sin(a0)}`,
      'Z',
    ].join(' ');
    angle += sweep + gapA;
    return { ...s, d, pct, mid };
  });

  return (
    <svg width={size} height={size} style={{ flexShrink: 0, display: 'block' }}>
      <circle cx={cx} cy={cy} r={(r + ir) / 2}
        fill="none" stroke="var(--border-primary)" strokeWidth={r - ir} />
      {paths.map((p, i) => <path key={i} d={p.d} fill={p.color} opacity={0.9} />)}
      {paths.map((p, i) => p.pct >= 8 && (
        <text key={`l${i}`}
          x={cx + labelR * Math.cos(p.mid)} y={cy + labelR * Math.sin(p.mid) + 4}
          textAnchor="middle"
          style={{ fontSize: 10, fontWeight: 700, fill: '#fff', fontFamily: 'inherit', pointerEvents: 'none' }}>
          {p.pct}%
        </text>
      ))}
    </svg>
  );
}

function IdentityRiskTable({ identities, filters, onIdentityClick }) {
  const filtered = useMemo(() => {
    if (!filters?.account && !filters?.principalType) return identities;
    return identities.filter(id => {
      const matchAccount = !filters.account || id.account_id === filters.account;
      const matchType    = !filters.principalType || id.actor_principal_type === filters.principalType || id.actorPrincipalType === filters.principalType;
      return matchAccount && matchType;
    });
  }, [identities, filters]);

  const TYPE_BADGE = {
    iam_role:        'bg-blue-950 text-blue-300 border-blue-800',
    iam_user:        'bg-green-950 text-green-300 border-green-800',
    service_account: 'bg-orange-950 text-orange-300 border-orange-800',
    root:            'bg-red-950 text-red-300 border-red-800',
  };

  const columns = useMemo(() => [
    {
      accessorKey: 'actor_principal',
      header: 'Identity',
      cell: ({ getValue }) => (
        <span className="font-mono text-xs" style={{ color: 'var(--text-primary)' }}>
          {(getValue() || '').split('/').pop() || getValue()}
        </span>
      ),
    },
    {
      id: 'actorPrincipalType',
      accessorKey: 'actorPrincipalType',
      header: 'Type',
      size: 130,
      cell: ({ getValue, row }) => {
        const t = getValue() || row.original?.actor_principal_type || 'unknown';
        const cls = TYPE_BADGE[t] || 'bg-slate-800 text-slate-300 border-slate-700';
        return (
          <span className={`inline-flex items-center text-[10px] font-semibold px-1.5 py-0.5 rounded-full border ${cls}`}>
            {t}
          </span>
        );
      },
    },
    {
      accessorKey: 'risk_score',
      header: 'Risk',
      size: 70,
      cell: ({ getValue }) => {
        const v = getValue() || 0;
        const color = v >= 80 ? C.critical : v >= 50 ? C.high : v >= 20 ? C.medium : C.low;
        return <span style={{ color, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{v}</span>;
      },
    },
    {
      id: 'l2Findings',
      accessorKey: 'l2Findings',
      header: 'L2',
      size: 60,
      cell: ({ getValue, row }) => {
        const v = getValue() ?? row.original?.l2_findings ?? 0;
        if (!v) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
        return (
          <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-orange-950 text-orange-400 border border-orange-800">
            {v}
          </span>
        );
      },
    },
    {
      id: 'l3Findings',
      accessorKey: 'l3Findings',
      header: 'L3',
      size: 60,
      cell: ({ getValue, row }) => {
        const v = getValue() ?? row.original?.l3_findings ?? 0;
        if (!v) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
        return (
          <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800">
            {v}
          </span>
        );
      },
    },
    {
      accessorKey: 'total_findings',
      header: 'Total',
      size: 70,
    },
    {
      accessorKey: 'critical',
      header: 'Crit',
      size: 60,
      cell: ({ getValue }) => (
        <span style={{ color: getValue() > 0 ? C.critical : 'var(--text-muted)', fontWeight: getValue() > 0 ? 700 : 400 }}>
          {getValue() || 0}
        </span>
      ),
    },
    {
      accessorKey: 'services_used',
      header: 'Services',
      size: 80,
    },
  ], []);

  return (
    <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="px-4 py-3 border-b flex items-center justify-between"
        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
          Identity Risk
        </span>
        {(filters?.account || filters?.principalType) && (
          <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(99,102,241,0.1)', color: '#818cf8' }}>
            filtered · {filtered.length} of {identities.length}
          </span>
        )}
      </div>
      <div className="p-3">
        <DataTable
          data={filtered}
          columns={columns}
          pageSize={10}
          emptyMessage="No identities found"
          onRowClick={(row) => {
            const principal = row.actor_principal || row.principal;
            if (principal) onIdentityClick?.(principal);
          }}
        />
      </div>
    </div>
  );
}

export default function CiemPage() {
  const router = useRouter();
  const { data, loading, error, refetch } = useViewFetch('cdr');
  const [heatmapData, setHeatmapData]     = useState({ matrix: [], accounts: [], principal_types: [] });
  const [filters, setFilters]             = useState({});
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => subscribeRefresh(() => refetch()), [refetch]);

  const totalFindings    = data.totalFindings  || 0;
  const rulesTriggered   = data.rulesTriggered  || 0;
  const uniqueActors     = data.uniqueActors    || 0;
  const l2Findings       = data.l2Findings      || 0;
  const l3Findings       = data.l3Findings      || 0;
  const severityBreakdown = data.severityBreakdown || [];

  const topCritical  = data.topCritical  || [];
  const identities   = data.identities   || [];
  const topRules     = data.topRules     || [];
  const logSources   = data.logSources   || [];
  const seqDetect    = data.sequenceDetections || { findings: [], total: 0, has_critical: false };
  const sequenceFindings = seqDetect.findings || [];

  useEffect(() => {
    fetchView('cdr/heatmap').then(result => {
      if (!result?.error) setHeatmapData(result || { matrix: [], accounts: [], principal_types: [] });
    });
  }, []);

  const detectionCoverage = useMemo(() => {
    if (!logSources.length) return 0;
    const active = logSources.filter(s => s.active || s.status === 'active').length;
    return Math.round((active / logSources.length) * 100);
  }, [logSources]);

  const sevCounts = {};
  severityBreakdown.forEach(s => { sevCounts[s.severity] = s.count; });

  const kpiNums = useMemo(() => {
    const g0 = data.kpiGroups?.[0]?.items || [];
    const get = (arr, lbl) =>
      arr.find(x => x.label?.toLowerCase() === lbl.toLowerCase())?.value ?? 0;
    return {
      posture_score:      data.postureScore || get(g0, 'Posture Score') || 0,
      total_findings:     totalFindings,
      critical:           sevCounts.critical || get(g0, 'Critical'),
      high:               sevCounts.high     || get(g0, 'High'),
      medium:             sevCounts.medium   || get(g0, 'Medium'),
      low:                sevCounts.low      || get(g0, 'Low'),
      identities_at_risk: uniqueActors       || get(g0, 'Identities at Risk'),
      rules_triggered:    rulesTriggered     || get(g0, 'Rules Triggered'),
    };
  }, [data.kpiGroups, data.postureScore, totalFindings, uniqueActors, rulesTriggered, severityBreakdown]);

  const activeScanTrend = useMemo(() =>
    (data.scanTrend || []).map(d => ({ ...d, passRate: d.pass_rate ?? d.passRate ?? 0 })),
    [data.scanTrend]
  );

  const insightStrip = useMemo(() => {
    const {
      posture_score, total_findings, critical, high, medium, low,
      identities_at_risk,
    } = kpiNums;

    const scoreColor = posture_score >= 70 ? C.emerald : posture_score >= 50 ? C.amber : C.critical;

    const donutSlices = [
      { label: 'Critical', value: critical, color: C.critical },
      { label: 'High',     value: high,     color: C.high     },
      { label: 'Medium',   value: medium,   color: C.medium   },
      { label: 'Low',      value: low,      color: C.low      },
    ];

    const first = activeScanTrend[0] || {};
    const last  = activeScanTrend[activeScanTrend.length - 1] || {};

    const TrendTooltip = ({ active, payload, label }) => {
      if (!active || !payload?.length) return null;
      const d = payload[0]?.payload;
      if (!d) return null;
      return (
        <div style={{
          backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)',
          borderRadius: 10, padding: '12px 14px', minWidth: 190,
          boxShadow: '0 6px 24px rgba(0,0,0,0.20)',
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8,
            borderBottom: '1px solid var(--border-primary)', paddingBottom: 6 }}>{label}</div>
          {[
            { label: 'Critical', value: d.critical, color: C.critical },
            { label: 'High',     value: d.high,     color: C.high     },
            { label: 'Medium',   value: d.medium,   color: C.medium   },
          ].map(s => (
            <div key={s.label} style={{ marginBottom: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 5,
                  fontSize: 11, color: 'var(--text-secondary)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, backgroundColor: s.color, display: 'inline-block' }} />
                  {s.label}
                </span>
                <span style={{ fontSize: 12, fontWeight: 700, color: s.color }}>{s.value}</span>
              </div>
            </div>
          ))}
        </div>
      );
    };

    return (
      <div className="space-y-4">
        {/* KPI strip — 4 cards */}
        <div className="grid grid-cols-4 gap-3">
          <KpiCard
            title="Identities at Risk"
            value={identities_at_risk}
            subtitle={`${critical} critical · ${high} high`}
            color="red"
          />
          <KpiCard
            title="L2 Correlation Findings"
            value={l2Findings}
            subtitle="Correlated event chains"
            color="orange"
          />
          <KpiCard
            title="L3 Anomaly Findings"
            value={l3Findings}
            subtitle="Baseline deviation"
            color="purple"
          />
          <KpiCard
            title="Detection Coverage"
            value={`${detectionCoverage}%`}
            subtitle={`${logSources.filter(s => s.active || s.status === 'active').length}/${logSources.length} sources active`}
            color={detectionCoverage >= 80 ? 'green' : detectionCoverage >= 50 ? 'orange' : 'red'}
          />
        </div>

        {/* Insight row: donut + trend */}
        <div className="flex gap-3 items-stretch" style={{ minHeight: 220 }}>
          <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
          }}>
            <div className="flex items-center justify-between mb-2">
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                Findings by Severity
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                {total_findings.toLocaleString()} total
              </span>
            </div>
            <div className="flex items-center gap-4" style={{ flex: 1 }}>
              <div style={{ position: 'relative', flexShrink: 0 }}>
                <CiemDonut slices={donutSlices} size={130} />
                <div style={{
                  position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
                  alignItems: 'center', justifyContent: 'center', pointerEvents: 'none',
                }}>
                  <div style={{ fontSize: 20, fontWeight: 900, color: 'var(--text-primary)', lineHeight: 1 }}>
                    {total_findings.toLocaleString()}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 3 }}>findings</div>
                </div>
              </div>
              <div className="flex-1 space-y-1.5" style={{ minWidth: 0 }}>
                {donutSlices.map(s => {
                  const pct = Math.round((s.value / (total_findings || 1)) * 100);
                  return (
                    <div key={s.label}>
                      <div className="flex items-center justify-between mb-0.5">
                        <div className="flex items-center gap-1.5">
                          <div style={{ width: 8, height: 8, borderRadius: 2, backgroundColor: s.color, flexShrink: 0 }} />
                          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{s.label}</span>
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, color: s.color }}>{s.value.toLocaleString()}</span>
                      </div>
                      <div style={{ height: 2, borderRadius: 2, backgroundColor: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                        <div style={{ width: `${pct}%`, height: '100%', borderRadius: 2, backgroundColor: s.color, opacity: 0.85 }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)', minWidth: 0,
          }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
              CDR Posture Trend
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
              {first.date ?? '—'} – {last.date ?? '—'} · {activeScanTrend.length} scans
            </div>
            <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
              <div style={{ position: 'absolute', inset: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={activeScanTrend}
                    margin={{ top: 4, right: 10, left: -14, bottom: 0 }} barCategoryGap="28%">
                    <CartesianGrid vertical={false} strokeDasharray="3 3"
                      stroke="var(--border-primary)" opacity={0.5} />
                    <XAxis dataKey="date"
                      tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
                      axisLine={false} tickLine={false} />
                    <YAxis yAxisId="count"
                      tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
                      axisLine={false} tickLine={false} width={24} />
                    <YAxis yAxisId="rate" orientation="right" domain={[0, 100]}
                      tick={{ fontSize: 10, fill: C.emerald, fontFamily: 'inherit' }}
                      axisLine={false} tickLine={false} width={28}
                      tickFormatter={v => `${v}%`} />
                    <ReferenceLine yAxisId="rate" y={80} stroke={C.emerald}
                      strokeDasharray="5 3" strokeOpacity={0.45} />
                    <RechartsTip content={<TrendTooltip />} />
                    <Bar yAxisId="count" dataKey="medium"   stackId="s" fill={C.medium}   opacity={0.7} />
                    <Bar yAxisId="count" dataKey="high"     stackId="s" fill={C.high}     opacity={0.7} />
                    <Bar yAxisId="count" dataKey="critical" stackId="s" fill={C.critical} opacity={0.8} radius={[3,3,0,0]} />
                    <Line yAxisId="rate" type="monotone" dataKey="passRate"
                      stroke={C.emerald} strokeWidth={2.5}
                      dot={{ r: 3, fill: C.emerald, strokeWidth: 0 }}
                      activeDot={{ r: 5, fill: C.emerald }} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>

        {/* Two-panel: heatmap (2/5) + identity table (3/5) */}
        <div className="grid grid-cols-5 gap-4">
          <div className="col-span-2">
            <IdentityRiskHeatmap
              matrix={heatmapData.matrix ?? []}
              accounts={heatmapData.accounts ?? []}
              principalTypes={heatmapData.principal_types ?? []}
              onCellClick={(account, principalType) => setFilters({ account, principalType })}
            />
            {(filters.account || filters.principalType) && (
              <button
                onClick={() => setFilters({})}
                className="mt-2 text-xs hover:opacity-75 transition-opacity"
                style={{ color: '#818cf8' }}>
                Clear filter
              </button>
            )}
          </div>
          <div className="col-span-3">
            <IdentityRiskTable
              identities={identities}
              filters={filters}
              onIdentityClick={(principal) => router.push(`/cdr/identity/${encodeURIComponent(principal)}`)}
            />
          </div>
        </div>
      </div>
    );
  }, [kpiNums, l2Findings, l3Findings, detectionCoverage, activeScanTrend, identities, heatmapData, filters, logSources, router]);

  const criticalColumns = [
    { accessorKey: 'severity', header: 'Severity', cell: ({ getValue }) => <SeverityBadge severity={getValue()} /> },
    { accessorKey: 'title', header: 'Detection' },
    { accessorKey: 'rule_id', header: 'Rule', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{getValue()}</span>
    )},
    { accessorKey: 'actor_principal', header: 'Actor', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{(getValue() || '').split('/').pop() || '-'}</span>
    )},
    { accessorKey: 'resource_uid', header: 'Resource', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{(getValue() || '').split('/').pop() || '-'}</span>
    )},
    { accessorKey: 'event_time', header: 'Time', cell: ({ getValue }) => getValue() ? new Date(getValue()).toLocaleString() : '-' },
  ];

  const detectionColumns = [
    { accessorKey: 'rule_id', header: 'Rule ID', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{getValue()}</span>
    )},
    { accessorKey: 'severity', header: 'Severity', cell: ({ getValue }) => <SeverityBadge severity={getValue()} /> },
    { accessorKey: 'title', header: 'Title' },
    { accessorKey: 'finding_count', header: 'Findings' },
    { accessorKey: 'rule_source', header: 'Level', cell: ({ getValue }) => {
      const v = getValue();
      const label = v === 'log_correlation' ? 'L2' : v === 'baseline' ? 'L3' : 'L1';
      const cls   = v === 'log_correlation' ? 'bg-orange-950 text-orange-400 border-orange-800'
                  : v === 'baseline'         ? 'bg-purple-950 text-purple-400 border-purple-800'
                  : 'bg-slate-800 text-slate-400 border-slate-700';
      return (
        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${cls}`}>{label}</span>
      );
    }},
    { accessorKey: 'unique_actors', header: 'Actors' },
    { accessorKey: 'unique_resources', header: 'Resources' },
  ];

  const eventColumns = [
    { accessorKey: 'source_type', header: 'Log Source' },
    { accessorKey: 'source_bucket', header: 'Location' },
    { accessorKey: 'source_region', header: 'Region' },
    { accessorKey: 'event_count', header: 'Events' },
    { accessorKey: 'earliest', header: 'First Event', cell: ({ getValue }) => getValue() ? new Date(getValue()).toLocaleString() : '-' },
    { accessorKey: 'latest', header: 'Last Event', cell: ({ getValue }) => getValue() ? new Date(getValue()).toLocaleString() : '-' },
  ];

  const SEQUENCE_LABELS = {
    RULE_S3_EXFIL:        'S3 Data Exfiltration',
    RULE_IDENTITY_PIVOT:  'Identity Pivot Chain',
    RULE_SECRETS_STAGING: 'Secrets Staging',
    RULE_COMPUTE_HIJACK:  'Compute Hijack',
  };

  const sequenceColumns = [
    {
      accessorKey: 'rule_id',
      header: 'Pattern',
      cell: ({ getValue }) => (
        <span className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>
          {SEQUENCE_LABELS[getValue()] || getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
    },
    {
      accessorKey: 'actor_principal',
      header: 'Actor',
      cell: ({ getValue }) => (
        <span className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>
          {(getValue() || '').split('/').pop() || getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'resource_uid',
      header: 'Target',
      cell: ({ getValue }) => (
        <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
          {(getValue() || '').split('/').pop() || getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'first_seen_at',
      header: 'Detected',
      cell: ({ getValue }) => getValue() ? new Date(getValue()).toLocaleString() : '—',
    },
  ];

  const pageContext = {
    title: 'CDR — Log Analysis',
    brief: 'Cloud log collection, threat detection, and identity risk analysis',
    tabs: [
      { id: 'overview',    label: 'Overview',        count: topCritical.length      },
      { id: 'detections',  label: 'Detection Rules', count: topRules.length         },
      { id: 'events',      label: 'Log Sources',     count: logSources.length       },
      ...(sequenceFindings.length > 0 ? [
        { id: 'sequences', label: 'Sequences', count: sequenceFindings.length },
      ] : []),
    ],
  };

  const tabData = useMemo(() => ({
    overview:   { data: topCritical,       columns: criticalColumns   },
    detections: { data: topRules,          columns: detectionColumns  },
    events:     { data: logSources,        columns: eventColumns      },
    ...(sequenceFindings.length > 0 ? {
      sequences: { data: sequenceFindings, columns: sequenceColumns   },
    } : {}),
  }), [topCritical, topRules, logSources, sequenceFindings]);

  return (
    <EngineShell
      icon={Eye}
      title={pageContext.title}
      description={pageContext.brief}
      details={pageContext.details}
      onRefresh={() => emitRefresh()}
      refreshing={loading}
    >
      <PageLayout
        icon={Eye}
        pageContext={pageContext}
        kpiGroups={[]}
        insightRow={insightStrip || null}
        tabData={tabData}
        persistenceKey="cdr"
        loading={loading}
        error={error}
        defaultTab="overview"
        hideHeader
        topNav
        onRowClick={(row) => setSelectedFinding(row)}
      />
      {selectedFinding && (
        <FindingDetailPanel
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          context={{
            engine: 'cdr',
            renderExtra: (f) =>
              f.rule_source === 'log_correlation' && f.finding_id ? (
                <section>
                  <h3 className="text-xs font-semibold uppercase tracking-wider mb-3"
                    style={{ color: 'var(--text-muted)' }}>
                    Attack Sequence ({f.rule_source})
                  </h3>
                  <CorrelationTimeline findingId={f.finding_id} />
                </section>
              ) : null,
          }}
        />
      )}
    </EngineShell>
  );
}
