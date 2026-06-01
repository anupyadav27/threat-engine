'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Shield, KeyRound, CheckCircle, AlertTriangle,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from 'recharts';
import { useViewFetch } from '@/lib/use-view-fetch';
import { subscribeRefresh, emitRefresh } from '@/lib/refreshBus';
import EngineShell from '@/components/shared/EngineShell';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
import KpiSparkCard from '@/components/shared/KpiSparkCard';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';
import PivotLink from '@/components/shared/PivotLink';
import { buildUniversalColumns, LastAccessCell } from '@/components/shared/EngineTableCells';
import { getEngineModules } from '@/lib/engine-modules';


const C = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
  sky: '#38bdf8', amber: '#f59e0b', emerald: '#10b981', indigo: '#6366f1',
};

// Single source of truth — engine-modules.js
const IAM_MODULES = getEngineModules('iam');
const MODULE_LABELS = Object.fromEntries(Object.entries(IAM_MODULES).map(([k, v]) => [k, v.label]));

function inferIdentityType(f) {
  if (f.identity_type) return f.identity_type;
  const uid = (f.resource_uid || f.identity_name || '').toLowerCase();
  const rt  = (f.resource_type || '').toLowerCase();

  if (/root/.test(uid + rt))                                             return 'Root';
  if (/:user\//.test(uid) || /iam[._]user|ad[._]user/.test(rt))         return 'IAM User';
  if (/:role\//.test(uid) || /iam[._]role/.test(rt))                    return 'IAM Role';
  if (/service[._]account|service[._]principal/.test(rt + uid))         return 'Service Account';
  if (/managed[._]identity/.test(rt))                                   return 'Managed Identity';
  if (/iam[._]group|ad[._]group/.test(rt))                              return 'Group';

  // Resource-config types are not identities — skip module fallback for them
  if (/bigquery|pubsub|cloud.?sql|spanner|keyvault|secrets.?store|private.?ca|storage.?table|storage.?blob|dataset|cluster|catalog/.test(rt))
    return '—';

  // Module fallback for clear identity types only
  const mod = f.iam_module || '';
  if (mod === 'access_keys')      return 'IAM User';
  if (mod === 'service_accounts') return 'Service Account';
  if (mod === 'role_management')  return 'IAM Role';

  if (f.identity_name) return 'Identity';
  return '—';
}

function inferIamModule(f) {
  const rule = (f.rule_id || '').toLowerCase();
  const rt   = (f.resource_type || '').toLowerCase();
  if (/priv|escalat|passrole|assume/.test(rule)) return 'least_privilege';
  if (/access.key|key.rotat/.test(rule))          return 'access_keys';
  if (/\bmfa\b/.test(rule))                        return 'mfa';
  if (/password/.test(rule))                       return 'password_policy';
  if (/service.account/.test(rule + rt))           return 'service_accounts';
  if (/\brole\b/.test(rule + rt))                  return 'role_management';
  return 'access_control';
}

// ── Pure-SVG severity donut ──
function IamDonut({ slices, size = 160 }) {
  const total = slices.reduce((s, x) => s + x.value, 0) || 1;
  const cx = size / 2, cy = size / 2;
  const r  = size / 2 - 8;
  const ir = r * 0.58;
  const gapA = (2.5 / 360) * 2 * Math.PI;
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
      {paths.map((p, i) => <path key={i} d={p.d} fill={p.color} opacity={0.88} />)}
      {paths.map((p, i) => p.pct >= 8 && (
        <text key={`l${i}`}
          x={cx + labelR * Math.cos(p.mid)} y={cy + labelR * Math.sin(p.mid) + 4}
          textAnchor="middle"
          style={{ fontSize: 9, fontWeight: 700, fill: '#fff', fontFamily: 'inherit', pointerEvents: 'none' }}>
          {p.pct}%
        </text>
      ))}
    </svg>
  );
}


export default function IamSecurityPage() {
  const { data, loading, error, refetch } = useViewFetch('iam');
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => subscribeRefresh(() => refetch()), [refetch]);

  const handleRowClick = (row) => {
    const finding = row?.original || row;
    if (finding) setSelectedFinding(finding);
  };

  // Single source: all 3 tabs read from data.findings.
  // Normalizes both new enriched format and old raw gateway format.
  const rawFindings = useMemo(() => {
    let base = data.findings || [];
    // Old BFF also returned separate arrays — merge them if findings is empty
    if (base.length === 0) {
      const merged = [];
      for (const f of (data.identities          || [])) merged.push({ ...f, iam_module: f.iam_module || 'access_control'  });
      for (const f of (data.roles               || [])) merged.push({ ...f, iam_module: f.iam_module || 'role_management'  });
      for (const f of (data.accessKeys          || [])) merged.push({ ...f, iam_module: f.iam_module || 'access_keys'      });
      for (const f of (data.privilegeEscalation || [])) merged.push({ ...f, iam_module: f.iam_module || 'least_privilege'  });
      base = merged;
    }
    // Enrich: flatten finding_data + derive iam_module from iam_modules[] if needed
    return base.map(f => {
      const fd  = f.finding_data || {};
      const mod = f.iam_module || (Array.isArray(f.iam_modules) && f.iam_modules[0]) || inferIamModule(f);
      const enriched = {
        ...f,
        iam_module:       mod,
        identity_type:    f.identity_type    || fd.identity_type    || '',
        title:            f.title            || fd.title            || fd.description?.slice(0, 80) || f.rule_id || '',
        description:      f.description      || fd.description      || '',
        remediation:      f.remediation      || fd.remediation      || '',
        identity_name:    f.identity_name    || fd.identity_name    || fd.user || fd.role_name || fd.identity || '',
        technique:        f.technique        || fd.technique        || '',
        target_privilege: f.target_privilege || fd.target_privilege || '',
      };
      // Pre-compute so DataTable accessorKey path also works
      if (!enriched.identity_type) enriched.identity_type = inferIdentityType(enriched);
      return enriched;
    });
  }, [data]);


  // ── Derive KPI numbers ──
  const kpiNums = useMemo(() => {
    const g0 = data.kpiGroups?.[0]?.items || [];
    const g1 = data.kpiGroups?.[1]?.items || [];
    const get = (arr, lbl) =>
      arr.find(x => x.label?.toLowerCase() === lbl.toLowerCase())?.value ?? null;
    return {
      critical:       get(g0, 'Critical')       ?? 0,
      high:           get(g0, 'High')            ?? 0,
      medium:         get(g0, 'Medium')          ?? 0,
      low:            0,
      posture_score:  get(g0, 'Posture Score')   ?? 0,
      total_findings: get(g0, 'Total Findings')  ?? rawFindings.length,
      identityCount:  get(g1, 'Identities')      ?? 0,
      keys_to_rotate: get(g1, 'Keys to Rotate')  ?? 0,
    };
  }, [data.kpiGroups, rawFindings.length]);

  const activeScanTrend = useMemo(() => data.scanTrend || [], [data.scanTrend]);

  // ── KPI Strip ──
  const kpiStripNode = useMemo(() => {
    const { critical, high, medium, low, posture_score, total_findings,
            identityCount, keys_to_rotate } = kpiNums;

    const sparkPS = activeScanTrend.map(d => d.pass_rate          ?? 0);
    const sparkTF = activeScanTrend.map(d => d.total              ?? 0);
    const sparkIR = activeScanTrend.map(d => d.identities_at_risk ?? 0);
    const sparkKR = activeScanTrend.map(d => d.keys_to_rotate     ?? 0);

    const scoreColor = posture_score >= 70 ? C.emerald : posture_score >= 50 ? C.amber : C.critical;

    const donutSlices = [
      { label: 'Critical', value: critical, color: C.critical },
      { label: 'High',     value: high,     color: C.high     },
      { label: 'Medium',   value: medium,   color: C.medium   },
      { label: 'Low',      value: low,      color: C.low      },
    ];

    const chartLast  = activeScanTrend[activeScanTrend.length - 1] || {};
    const chartFirst = activeScanTrend[0] || {};

    const chartSeries = [
      { key: 'no_mfa',         label: 'No MFA',         color: C.critical,
        value: chartLast.no_mfa         ?? 0,
        delta: (chartLast.no_mfa         ?? 0) - (chartFirst.no_mfa         ?? 0), good: 'down' },
      { key: 'overprivileged', label: 'Overprivileged', color: C.high,
        value: chartLast.overprivileged ?? 0,
        delta: (chartLast.overprivileged ?? 0) - (chartFirst.overprivileged ?? 0), good: 'down' },
      { key: 'safe',           label: 'Secure',         color: C.emerald,
        value: chartLast.safe           ?? 0,
        delta: (chartLast.safe           ?? 0) - (chartFirst.safe           ?? 0), good: 'up'   },
    ];

    const totalRiskΔ = ((chartLast.no_mfa ?? 0) + (chartLast.overprivileged ?? 0)) -
                       ((chartFirst.no_mfa ?? 0) + (chartFirst.overprivileged ?? 0));

    const ChartTooltip = ({ active, payload, label }) => {
      if (!active || !payload?.length) return null;
      const tot = payload.reduce((s, p) => s + (p.value || 0), 0);
      return (
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)',
          borderRadius: 8, padding: '10px 12px', minWidth: 160, boxShadow: '0 4px 16px rgba(0,0,0,0.18)' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6 }}>{label}</div>
          {[...payload].reverse().map((p, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center',
              justifyContent: 'space-between', gap: 12, marginBottom: 3 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5,
                color: 'var(--text-secondary)', fontSize: 12 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2,
                  backgroundColor: p.color, display: 'inline-block' }} />
                {p.name}
              </span>
              <span style={{ fontWeight: 700, fontSize: 13, color: p.color,
                fontVariantNumeric: 'tabular-nums' }}>{p.value}</span>
            </div>
          ))}
          <div style={{ borderTop: '1px solid var(--border-primary)', marginTop: 5, paddingTop: 5,
            display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Total identities</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
              fontVariantNumeric: 'tabular-nums' }}>{tot}</span>
          </div>
        </div>
      );
    };

    return (
      <div className="flex gap-3 items-stretch" style={{ minHeight: 260 }}>

        {/* 2×2 KPI tiles */}
        <div style={{
          flex: 1, display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: 8, minWidth: 0,
        }}>
          <KpiSparkCard label="Posture Score"   value={posture_score}  color={scoreColor} suffix="/100"
            sub={`${medium} medium · ${low} low risk`} sparkData={sparkPS}
            delta={sparkPS[sparkPS.length-1] - sparkPS[0]} deltaGood="up" />
          <KpiSparkCard label="Total Findings"  value={total_findings} color={C.high}
            sub={`${critical} critical · ${high} high`} sparkData={sparkTF}
            delta={sparkTF[sparkTF.length-1] - sparkTF[0]} deltaGood="down" />
          <KpiSparkCard label="Identities"      value={identityCount}  color={C.sky}
            sub={`${chartLast.overprivileged ?? 0} overprivileged · ${chartLast.no_mfa ?? 0} no MFA`} sparkData={sparkIR}
            delta={sparkIR[sparkIR.length-1] - sparkIR[0]} deltaGood="up" />
          <KpiSparkCard label="Keys to Rotate"  value={keys_to_rotate} color={C.amber}
            sub="Exceed 90-day rotation policy" sparkData={sparkKR}
            delta={sparkKR[sparkKR.length-1] - sparkKR[0]} deltaGood="down" />
        </div>

        {/* Severity Donut */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)',
          minWidth: 0, overflow: 'hidden',
        }}>
          <div className="flex items-center justify-between mb-0.5">
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
              Findings by Severity
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
              {total_findings.toLocaleString()} total
            </span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 10 }}>
            Identity risk · severity breakdown
          </div>
          <div className="flex items-center gap-4 flex-1">
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <IamDonut slices={donutSlices} size={160} />
              <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
                <div style={{ fontSize: 26, fontWeight: 900, color: 'var(--text-primary)', lineHeight: 1 }}>
                  {total_findings.toLocaleString()}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>findings</div>
              </div>
            </div>
            <div className="flex-1 space-y-2" style={{ minWidth: 0 }}>
              {donutSlices.map(s => {
                const pct = Math.round((s.value / (total_findings || 1)) * 100);
                return (
                  <div key={s.label}>
                    <div className="flex items-center justify-between mb-0.5">
                      <div className="flex items-center gap-1.5">
                        <div style={{ width: 9, height: 9, borderRadius: 2, backgroundColor: s.color, flexShrink: 0 }} />
                        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{s.label}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span style={{ fontSize: 13, fontWeight: 700, color: s.color }}>{s.value.toLocaleString()}</span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{pct}%</span>
                      </div>
                    </div>
                    <div style={{ height: 3, borderRadius: 2, backgroundColor: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%', borderRadius: 2,
                        backgroundColor: s.color, opacity: 0.85 }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Identity Risk Trend */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)',
          minWidth: 0, overflow: 'hidden',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between',
            alignItems: 'flex-start', marginBottom: 2 }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                Identity Risk Trend
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 1 }}>
                {chartFirst.date ?? '—'} – {chartLast.date ?? '—'} · {activeScanTrend.length} scans
              </div>
            </div>
            <span style={{
              fontSize: 11, fontWeight: 700, padding: '3px 8px', borderRadius: 20,
              backgroundColor: totalRiskΔ <= 0 ? `${C.emerald}18` : `${C.critical}18`,
              color: totalRiskΔ <= 0 ? C.emerald : C.critical, whiteSpace: 'nowrap',
            }}>
              {totalRiskΔ <= 0 ? '↓' : '↑'} {Math.abs(totalRiskΔ)} risk {totalRiskΔ <= 0 ? 'resolved' : 'added'}
            </span>
          </div>

          <div style={{ display: 'flex', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
            {[...chartSeries].reverse().map(s => {
              const improved = s.good === 'down' ? s.delta <= 0 : s.delta >= 0;
              const dColor   = improved ? C.emerald : C.critical;
              return (
                <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2,
                    backgroundColor: s.color, display: 'inline-block', opacity: 0.9 }} />
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{s.label}</span>
                  <span style={{ fontSize: 13, fontWeight: 800, color: s.color,
                    fontVariantNumeric: 'tabular-nums' }}>{s.value}</span>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '1px 5px', borderRadius: 10,
                    backgroundColor: `${dColor}18`, color: dColor }}>
                    {s.delta > 0 ? '+' : ''}{s.delta}
                  </span>
                </div>
              );
            })}
          </div>

          <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
            <div style={{ position: 'absolute', inset: 0 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activeScanTrend} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
                  <defs>
                    {chartSeries.map(s => (
                      <linearGradient key={s.key} id={`ig-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%"   stopColor={s.color} stopOpacity={0.70} />
                        <stop offset="100%" stopColor={s.color} stopOpacity={0.18} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid vertical={false} strokeDasharray="3 3"
                    stroke="var(--border-primary)" opacity={0.5} />
                  <XAxis dataKey="date"
                    tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
                    axisLine={false} tickLine={false} interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
                    axisLine={false} tickLine={false} width={28} />
                  <Tooltip content={<ChartTooltip />} />
                  {chartSeries.map(s => (
                    <Area key={s.key} type="monotone" dataKey={s.key} name={s.label}
                      stackId="stack" stroke={s.color} strokeWidth={1.5}
                      fill={`url(#ig-${s.key})`} />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8,
            paddingTop: 8, borderTop: '1px solid var(--border-primary)' }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Secure identities</span>
            <span style={{ fontSize: 11, fontWeight: 700, fontVariantNumeric: 'tabular-nums', color: C.emerald }}>
              {chartLast.safe ?? 0} / {chartLast.total ?? 0}
              <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 4 }}>
                ({chartLast.total > 0 ? Math.round(((chartLast.safe ?? 0) / chartLast.total) * 100) : 0}%)
              </span>
            </span>
          </div>
        </div>

      </div>
    );
  }, [kpiNums, activeScanTrend]);

  // ── Finding columns — universal + IAM identity extra column ──
  const findingColumns = useMemo(() => buildUniversalColumns('iam', [
    {
      id: 'identity',
      header: 'Identity',
      size: 170,
      accessorFn: row => row.identity_name || row.resource_uid?.split('/').pop() || '',
      cell: (info) => {
        const row = info.row.original;
        const name = info.getValue() || '—';
        const type = row.identity_type || inferIdentityType(row);
        return (
          <div className="flex flex-col gap-0.5 min-w-0">
            <span className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)', maxWidth: 150 }}
              title={name}>{name}</span>
            {type && type !== '—' && (
              <span className="text-[10px] px-1.5 py-0.5 rounded self-start"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{type}</span>
            )}
          </div>
        );
      },
    },
    {
      id: 'last_access',
      header: 'Last Access',
      size: 88,
      accessorFn: row => row.last_accessed || row.last_access_date || row.last_used_date || '',
      cell: ({ row }) => <LastAccessCell row={row.original} />,
    },
  ]), []);

  const tabData = useMemo(() => ({
    findings: {
      data: rawFindings,
      columns: findingColumns,
      initialColumnVisibility: { region: false, rule_id: false, resource_uid: false, provider: false },
      initialGroupBy: 'module',
      filters: [
        { key: 'severity',      label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
        { key: 'iam_module',    label: 'Module',   options: Object.keys(MODULE_LABELS)            },
        { key: 'status',        label: 'Status',   options: ['FAIL', 'PASS']                       },
      ],
      searchPlaceholder: 'Search by identity, finding, account…',
    },
  }), [rawFindings, findingColumns]);

  const pageContext = {
    title: (data.pageContext || {}).title || 'IAM Security',
    brief: (data.pageContext || {}).brief  || 'Identity and access management posture across cloud accounts.',
    tabs: [
      { id: 'findings', label: 'Findings', count: rawFindings.length },
    ],
  };

  return (
    <EngineShell
      icon={KeyRound}
      title={pageContext.title}
      description={pageContext.brief}
      onRefresh={() => emitRefresh()}
      refreshing={loading}
    >
      <PageLayout
        icon={Shield}
        pageContext={pageContext}
        kpiGroups={[]}
        insightRow={kpiStripNode || null}
        tabData={tabData}
        persistenceKey="iam"
        loading={loading}
        error={error}
        defaultTab="findings"
        onRowClick={handleRowClick}
        hideHeader
        topNav
      />

      <FindingDetailPanel
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        context={{
          engine: 'iam',
          hideTabs: ['relationships', 'resource'],
          allFindings: rawFindings,
          moduleLabels: MODULE_LABELS,
        }}
      />
    </EngineShell>
  );
}
