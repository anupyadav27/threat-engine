'use client';

import { useState, useEffect, useMemo } from 'react';
import { Eye, RefreshCw, Info, ChevronDown } from 'lucide-react';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
import KpiSparkCard from '@/components/shared/KpiSparkCard';

// ── Demo fallback data (shown when backend returns no data) ───────────────────
const DEMO_CIEM_TOP_CRITICAL = [
  { severity: 'critical', title: 'Root account login without MFA detected', rule_id: 'CIEM-L1-001', actor_principal: 'arn:aws:iam::123456789012:root', resource_uid: 'arn:aws:iam::123456789012:root', event_time: '2026-04-01T02:14:33Z' },
  { severity: 'critical', title: 'IAM role privilege escalation via PassRole', rule_id: 'CIEM-L2-007', actor_principal: 'arn:aws:iam::123456789012:user/admin-deploy', resource_uid: 'arn:aws:iam::123456789012:role/AdminRole', event_time: '2026-03-31T18:47:10Z' },
  { severity: 'critical', title: 'Anomalous mass S3 GetObject from new IP', rule_id: 'CIEM-L3-022', actor_principal: 'arn:aws:iam::123456789012:user/svc-data-pipeline', resource_uid: 'arn:aws:s3:::prod-customer-data', event_time: '2026-03-31T09:22:05Z' },
  { severity: 'high', title: 'CloudTrail disabled in eu-west-1 production', rule_id: 'CIEM-L1-014', actor_principal: 'arn:aws:iam::234567890123:user/ops-automation', resource_uid: 'arn:aws:cloudtrail:eu-west-1:234567890123:trail/main', event_time: '2026-03-30T14:05:55Z' },
  { severity: 'high', title: 'Unusual cross-account role assumption chain', rule_id: 'CIEM-L2-031', actor_principal: 'arn:aws:iam::234567890123:role/CrossAccountDeploy', resource_uid: 'arn:aws:iam::123456789012:role/ProdAdminRole', event_time: '2026-03-29T22:11:40Z' },
  { severity: 'high', title: 'SecretsManager bulk retrieval by CI/CD principal', rule_id: 'CIEM-L1-019', actor_principal: 'arn:aws:iam::123456789012:role/CICDAutomation', resource_uid: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/*', event_time: '2026-03-29T06:33:17Z' },
];

const DEMO_CIEM_IDENTITIES = [
  { actor_principal: 'arn:aws:iam::123456789012:user/admin-deploy',      risk_score: 94, total_findings: 18, critical: 3, high: 7, rules_triggered: 12, services_used: 9, resources_touched: 47 },
  { actor_principal: 'arn:aws:iam::123456789012:user/svc-data-pipeline', risk_score: 87, total_findings: 15, critical: 2, high: 8, rules_triggered: 11, services_used: 6, resources_touched: 38 },
  { actor_principal: 'arn:aws:iam::234567890123:role/CrossAccountDeploy',risk_score: 79, total_findings: 11, critical: 1, high: 6, rules_triggered: 8,  services_used: 5, resources_touched: 21 },
  { actor_principal: 'arn:aws:iam::123456789012:role/CICDAutomation',    risk_score: 72, total_findings: 9,  critical: 1, high: 4, rules_triggered: 7,  services_used: 4, resources_touched: 18 },
  { actor_principal: 'arn:aws:iam::123456789012:user/ops-automation',    risk_score: 65, total_findings: 7,  critical: 0, high: 5, rules_triggered: 5,  services_used: 4, resources_touched: 14 },
  { actor_principal: 'arn:aws:iam::345678901234:user/dev-lead-jsmith',   risk_score: 48, total_findings: 5,  critical: 0, high: 2, rules_triggered: 4,  services_used: 3, resources_touched: 9  },
  { actor_principal: 'arn:aws:iam::234567890123:role/DataScienceRole',   risk_score: 37, total_findings: 4,  critical: 0, high: 1, rules_triggered: 3,  services_used: 2, resources_touched: 7  },
  { actor_principal: 'arn:aws:iam::345678901234:user/readonly-auditor',  risk_score: 12, total_findings: 1,  critical: 0, high: 0, rules_triggered: 1,  services_used: 1, resources_touched: 2  },
];

const DEMO_CIEM_TOP_RULES = [
  { rule_id: 'CIEM-L1-001', severity: 'critical', title: 'Root account MFA not enabled',               finding_count: 3,  rule_source: 'baseline',    unique_actors: 1, unique_resources: 1  },
  { rule_id: 'CIEM-L2-007', severity: 'critical', title: 'IAM privilege escalation via PassRole',      finding_count: 8,  rule_source: 'correlation', unique_actors: 4, unique_resources: 6  },
  { rule_id: 'CIEM-L3-022', severity: 'high',     title: 'Anomalous bulk S3 data access',              finding_count: 12, rule_source: 'baseline',    unique_actors: 3, unique_resources: 14 },
  { rule_id: 'CIEM-L1-014', severity: 'high',     title: 'CloudTrail logging disabled in region',      finding_count: 5,  rule_source: 'baseline',    unique_actors: 2, unique_resources: 3  },
  { rule_id: 'CIEM-L2-031', severity: 'high',     title: 'Cross-account role assumption chain',        finding_count: 7,  rule_source: 'correlation', unique_actors: 3, unique_resources: 5  },
  { rule_id: 'CIEM-L1-019', severity: 'medium',   title: 'SecretsManager bulk retrieval detected',     finding_count: 4,  rule_source: 'baseline',    unique_actors: 2, unique_resources: 9  },
];

const DEMO_CIEM_LOG_SOURCES = [
  { source_type: 'CloudTrail',   source_bucket: 's3://prod-cloudtrail-logs-123456789012', source_region: 'us-east-1', event_count: 284710, earliest: '2026-03-01T00:00:00Z', latest: '2026-04-01T06:00:00Z' },
  { source_type: 'VPC Flow Logs',source_bucket: 's3://prod-vpc-flow-logs-123456789012',  source_region: 'us-east-1', event_count: 1823450, earliest: '2026-03-01T00:00:00Z', latest: '2026-04-01T06:00:00Z' },
  { source_type: 'CloudTrail',   source_bucket: 's3://prod-cloudtrail-logs-234567890123', source_region: 'eu-west-1', event_count: 91340, earliest: '2026-03-10T00:00:00Z', latest: '2026-04-01T05:45:00Z' },
  { source_type: 'GuardDuty',    source_bucket: 'GuardDuty Findings',                    source_region: 'us-east-1', event_count: 1247,   earliest: '2026-03-01T00:00:00Z', latest: '2026-04-01T06:00:00Z' },
  { source_type: 'CloudTrail',   source_bucket: 's3://prod-cloudtrail-logs-345678901234', source_region: 'us-west-2', event_count: 47890, earliest: '2026-03-15T00:00:00Z', latest: '2026-04-01T04:30:00Z' },
];

// ── Colour palette ─────────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  sky:      '#38bdf8',
  amber:    '#f59e0b',
  emerald:  '#10b981',
  indigo:   '#6366f1',
  purple:   '#8b5cf6',
  teal:     '#14b8a6',
};

// ── Enriched scan trend ────────────────────────────────────────────────────────
const CIEM_SCAN_TREND = [
  { date: 'Jan 13', passRate: 38, critical: 8, high: 16, medium: 14, total: 62, overprivileged: 38, detections: 24 },
  { date: 'Jan 20', passRate: 41, critical: 7, high: 15, medium: 13, total: 56, overprivileged: 35, detections: 21 },
  { date: 'Jan 27', passRate: 40, critical: 8, high: 16, medium: 13, total: 57, overprivileged: 37, detections: 19 },
  { date: 'Feb 3',  passRate: 44, critical: 7, high: 14, medium: 12, total: 52, overprivileged: 33, detections: 22 },
  { date: 'Feb 10', passRate: 47, critical: 6, high: 13, medium: 12, total: 48, overprivileged: 31, detections: 17 },
  { date: 'Feb 17', passRate: 51, critical: 6, high: 12, medium: 11, total: 45, overprivileged: 29, detections: 15 },
  { date: 'Feb 24', passRate: 54, critical: 5, high: 11, medium: 10, total: 40, overprivileged: 27, detections: 13 },
  { date: 'Mar 3',  passRate: 57, critical: 5, high: 11, medium: 10, total: 38, overprivileged: 26, detections: 11 },
];

// ── Module scores ──────────────────────────────────────────────────────────────
const CIEM_MODULE_SCORES = [
  { module: 'Log Collection',    pass: 18, total: 25, color: C.indigo   },
  { module: 'Rule Detection',    pass: 24, total: 30, color: C.sky      },
  { module: 'Identity Risk',     pass: 11, total: 20, color: C.critical },
  { module: 'Correlation Engine',pass:  8, total: 15, color: C.amber    },
  { module: 'Anomaly Detection', pass:  6, total: 12, color: C.purple   },
  { module: 'Threat Intel',      pass: 14, total: 20, color: C.teal     },
];

// ── KPI fallback ───────────────────────────────────────────────────────────────
const CIEM_KPI_FALLBACK = {
  posture_score:  57,
  total_findings: 312,
  critical: 5, high: 89, medium: 142, low: 76,
  identities_at_risk: 26,
  rules_triggered: 47,
};

const CIEM_SPARKLINES = {
  posture_score:      [38, 41, 40, 44, 47, 51, 54, 57],
  total_findings:     [380, 365, 370, 355, 340, 328, 318, 312],
  identities_at_risk: [42, 39, 41, 37, 34, 31, 29, 26],
  rules_triggered:    [62, 58, 60, 56, 53, 51, 49, 47],
};

// ── Pure-SVG severity donut ────────────────────────────────────────────────────
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


export default function CiemPage() {
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState(null);
  const [data, setData]               = useState({});
  const [detailsOpen, setDetailsOpen] = useState(false);

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('ciem', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load CIEM data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  // ── Extract data ──
  const totalFindings = data.totalFindings || 0;
  const rulesTriggered = data.rulesTriggered || 0;
  const uniqueActors = data.uniqueActors || 0;
  const l2Findings = data.l2Findings || 0;
  const l3Findings = data.l3Findings || 0;
  const severityBreakdown = data.severityBreakdown || [];

  const rawTopCritical = data.topCritical || [];
  const rawIdentities  = data.identities  || [];
  const rawTopRules    = data.topRules    || [];
  const rawLogSources  = data.logSources  || [];

  const topCritical = rawTopCritical.length ? rawTopCritical : DEMO_CIEM_TOP_CRITICAL;
  const identities  = rawIdentities.length  ? rawIdentities  : DEMO_CIEM_IDENTITIES;
  const topRules    = rawTopRules.length    ? rawTopRules    : DEMO_CIEM_TOP_RULES;
  const logSources  = rawLogSources.length  ? rawLogSources  : DEMO_CIEM_LOG_SOURCES;

  // ── Severity counts ──
  const sevCounts = {};
  severityBreakdown.forEach(s => { sevCounts[s.severity] = s.count; });

  // ── Derive KPI numbers ──
  const kpiNums = useMemo(() => {
    const g0 = data.kpiGroups?.[0]?.items || [];
    const g1 = data.kpiGroups?.[1]?.items || [];
    const get = (arr, lbl) =>
      arr.find(x => x.label?.toLowerCase() === lbl.toLowerCase())?.value ?? null;

    const criticalVal = sevCounts.critical || get(g0, 'Critical') || CIEM_KPI_FALLBACK.critical;
    const highVal     = sevCounts.high     || get(g0, 'High')     || CIEM_KPI_FALLBACK.high;
    const mediumVal   = sevCounts.medium   || get(g0, 'Medium')   || CIEM_KPI_FALLBACK.medium;
    const lowVal      = sevCounts.low      || get(g0, 'Low')      || CIEM_KPI_FALLBACK.low;

    return {
      posture_score:      get(g0, 'Posture Score')     ?? CIEM_KPI_FALLBACK.posture_score,
      total_findings:     totalFindings                || CIEM_KPI_FALLBACK.total_findings,
      critical:           criticalVal,
      high:               highVal,
      medium:             mediumVal,
      low:                lowVal,
      identities_at_risk: uniqueActors                 || CIEM_KPI_FALLBACK.identities_at_risk,
      rules_triggered:    rulesTriggered               || CIEM_KPI_FALLBACK.rules_triggered,
    };
  }, [data.kpiGroups, totalFindings, uniqueActors, rulesTriggered, severityBreakdown]);

  // ── Live scan trend (falls back to static if BFF returns < 2 points) ──
  const activeScanTrend = useMemo(() => {
    if (data.scanTrend?.length >= 2) {
      return data.scanTrend.map(d => ({
        ...d,
        passRate: d.pass_rate ?? d.passRate ?? 0,
      }));
    }
    return CIEM_SCAN_TREND;
  }, [data.scanTrend]);

  // ── Insight strip (single row: 2×2 KPIs | Donut+Modules | Trend) ──
  const insightStrip = useMemo(() => {
    const {
      posture_score, total_findings, critical, high, medium, low,
      identities_at_risk, rules_triggered,
    } = kpiNums;

    const scoreColor = posture_score >= 70 ? C.emerald
                     : posture_score >= 50 ? C.amber
                     : C.critical;

    const tile = (label, value, color, suffix = '', sub = '', sparkData = [], delta = null, deltaGood = 'down') => (
      <KpiSparkCard
        key={label}
        label={label}
        value={value}
        color={color}
        suffix={suffix}
        sub={sub}
        sparkData={sparkData}
        delta={delta}
        deltaGood={deltaGood}
      />
    );

    const donutSlices = [
      { label: 'Critical', value: critical, color: C.critical },
      { label: 'High',     value: high,     color: C.high     },
      { label: 'Medium',   value: medium,   color: C.medium   },
      { label: 'Low',      value: low,      color: C.low      },
    ];

    const sparkPS = activeScanTrend.map(d => d.passRate         ?? 0);
    const sparkTF = activeScanTrend.map(d => d.total            ?? 0);
    const sparkIR = activeScanTrend.map(d => d.identities_at_risk ?? 0);
    const sparkRT = activeScanTrend.map(d => d.rules_triggered  ?? 0);

    const first = activeScanTrend[0];
    const last  = activeScanTrend[activeScanTrend.length - 1];
    const rateΔ  = last.passRate  - first.passRate;
    const critΔ  = last.critical  - first.critical;
    const highΔ  = last.high      - first.high;
    const totalΔ = last.total     - first.total;

    const statPill = (label, value, delta, goodDir) => {
      const improved = goodDir === 'up' ? delta >= 0 : delta <= 0;
      const dc   = improved ? C.emerald : C.critical;
      const sign = delta > 0 ? '+' : '';
      return (
        <div key={label} style={{
          flex: 1, backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-primary)', borderRadius: 8,
          padding: '8px 10px',
        }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>
            {label}
          </div>
          <div style={{ fontSize: 20, fontWeight: 900, color: 'var(--text-primary)',
            lineHeight: 1, fontVariantNumeric: 'tabular-nums', marginBottom: 3 }}>
            {value}
          </div>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 20,
            backgroundColor: `${dc}18`, color: dc,
          }}>{sign}{delta}{label === 'Pass Rate' ? '%' : ''}</span>
        </div>
      );
    };

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
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
            marginBottom: 8, borderBottom: '1px solid var(--border-primary)', paddingBottom: 6 }}>
            {label}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Detection Rate</span>
            <span style={{ fontSize: 18, fontWeight: 900, color: C.emerald,
              fontVariantNumeric: 'tabular-nums' }}>{d.passRate}%</span>
          </div>
          {[
            { label: 'Critical', value: d.critical, color: C.critical },
            { label: 'High',     value: d.high,     color: C.high     },
            { label: 'Medium',   value: d.medium,   color: C.medium   },
          ].map(s => (
            <div key={s.label} style={{ marginBottom: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 5,
                  fontSize: 11, color: 'var(--text-secondary)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2,
                    backgroundColor: s.color, display: 'inline-block' }} />
                  {s.label}
                </span>
                <span style={{ fontSize: 12, fontWeight: 700, color: s.color,
                  fontVariantNumeric: 'tabular-nums' }}>{s.value}</span>
              </div>
              <div style={{ height: 3, borderRadius: 2, backgroundColor: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                <div style={{ width: `${Math.round((s.value / (d.total || 1)) * 100)}%`,
                  height: '100%', borderRadius: 2, backgroundColor: s.color, opacity: 0.85 }} />
              </div>
            </div>
          ))}
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8,
            paddingTop: 6, borderTop: '1px solid var(--border-primary)' }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Total detections</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
              fontVariantNumeric: 'tabular-nums' }}>{d.total}</span>
          </div>
        </div>
      );
    };

    return (
      <div className="flex gap-3 items-stretch" style={{ minHeight: 260 }}>

        {/* ── Col 1: 2×2 KPI tiles ── */}
        <div style={{
          flex: 1, display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: 8, minWidth: 0,
        }}>
          {tile('Posture Score',      posture_score,      scoreColor, '/100', `${medium} medium · ${low} low risk`,           sparkPS, sparkPS[sparkPS.length - 1] - sparkPS[0], 'up'  )}
          {tile('Total Findings',     total_findings,     C.high,     '',     `${critical} critical · ${high} high`,           sparkTF, sparkTF[sparkTF.length - 1] - sparkTF[0], 'down')}
          {tile('Identities at Risk', identities_at_risk, C.critical, '',     `${l2Findings} L2 correlations · ${l3Findings} L3 anomalies`, sparkIR, sparkIR[sparkIR.length - 1] - sparkIR[0], 'down')}
          {tile('Rules Triggered',    rules_triggered,    C.purple,   '',     'Across all detection levels',                  sparkRT, sparkRT[sparkRT.length - 1] - sparkRT[0], 'down')}
        </div>

        {/* ── Col 2: Findings by Severity donut + Module Scores ── */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
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
            Identity threat · severity breakdown
          </div>

          <div className="flex items-center gap-4" style={{ flex: 1 }}>
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <CiemDonut slices={donutSlices} size={150} />
              <div style={{
                position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', pointerEvents: 'none',
              }}>
                <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--text-primary)', lineHeight: 1 }}>
                  {total_findings.toLocaleString()}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>findings</div>
              </div>
            </div>
            <div className="flex-1 space-y-2" style={{ minWidth: 0 }}>
              {donutSlices.map(s => {
                const pct = Math.round((s.value / (total_findings || 1)) * 100);
                return (
                  <div key={s.label}>
                    <div className="flex items-center justify-between mb-0.5">
                      <div className="flex items-center gap-1.5">
                        <div style={{ width: 9, height: 9, borderRadius: 2,
                          backgroundColor: s.color, flexShrink: 0 }} />
                        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{s.label}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span style={{ fontSize: 13, fontWeight: 700, color: s.color }}>
                          {s.value.toLocaleString()}
                        </span>
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

          {/* Module Scores — compact 2-col list */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 16px',
            marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border-primary)',
          }}>
            {CIEM_MODULE_SCORES.map(m => {
              const pct = Math.round((m.pass / m.total) * 100);
              const col = pct >= 70 ? C.emerald : pct >= 50 ? C.amber : C.critical;
              return (
                <div key={m.module} style={{ display: 'flex', alignItems: 'center',
                  gap: 6, padding: '3px 0', borderBottom: '1px solid var(--border-primary)' }}>
                  <span style={{ width: 7, height: 7, borderRadius: 2,
                    backgroundColor: col, flexShrink: 0 }} />
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)', flex: 1,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {m.module}
                  </span>
                  <div style={{ width: 32, height: 3, borderRadius: 2,
                    backgroundColor: 'var(--bg-tertiary)', flexShrink: 0, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%',
                      borderRadius: 2, backgroundColor: col }} />
                  </div>
                  <span style={{ fontSize: 11, fontWeight: 700, color: col,
                    flexShrink: 0, fontVariantNumeric: 'tabular-nums', width: 28, textAlign: 'right' }}>
                    {pct}%
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Col 3: CIEM Posture Trend (ComposedChart) ── */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)', minWidth: 0,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', marginBottom: 8 }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                CIEM Posture Trend
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                {first.date} – {last.date} · {CIEM_SCAN_TREND.length} scans
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {[
                { label: 'Critical',   color: C.critical },
                { label: 'High',       color: C.high     },
                { label: 'Medium',     color: C.medium   },
                { label: 'Detect Rate',color: C.emerald  },
              ].map(s => (
                <span key={s.label} style={{ display: 'flex', alignItems: 'center',
                  gap: 4, fontSize: 10, color: 'var(--text-muted)' }}>
                  <span style={{ width: 8, height: s.label === 'Detect Rate' ? 2 : 8,
                    borderRadius: s.label === 'Detect Rate' ? 1 : 2,
                    backgroundColor: s.color, display: 'inline-block' }} />
                  {s.label}
                </span>
              ))}
            </div>
          </div>

          {/* 4-stat summary strip */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
            {statPill('Detect Rate', `${last.passRate}%`, rateΔ,  'up'  )}
            {statPill('Critical',    last.critical,       critΔ,  'down')}
            {statPill('High',        last.high,           highΔ,  'down')}
            {statPill('Total',       last.total,          totalΔ, 'down')}
          </div>

          {/* Composed chart — fills remaining height */}
          <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
            <div style={{ position: 'absolute', inset: 0 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={activeScanTrend}
                  margin={{ top: 6, right: 10, left: -14, bottom: 0 }} barCategoryGap="28%">
                  <defs>
                    {[
                      { id: 'cc', color: C.critical },
                      { id: 'ch', color: C.high     },
                      { id: 'cm', color: C.medium   },
                    ].map(g => (
                      <linearGradient key={g.id} id={g.id} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%"   stopColor={g.color} stopOpacity={0.95} />
                        <stop offset="100%" stopColor={g.color} stopOpacity={0.55} />
                      </linearGradient>
                    ))}
                  </defs>
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
                    strokeDasharray="5 3" strokeOpacity={0.45}
                    label={{ value: 'Target', position: 'insideTopRight',
                      fontSize: 9, fill: C.emerald, opacity: 0.7 }} />
                  <RechartsTip content={<TrendTooltip />} />
                  <Bar yAxisId="count" dataKey="medium"   name="Medium"   stackId="s" fill={`url(#cm)`} radius={[0,0,0,0]} />
                  <Bar yAxisId="count" dataKey="high"     name="High"     stackId="s" fill={`url(#ch)`} radius={[0,0,0,0]} />
                  <Bar yAxisId="count" dataKey="critical" name="Critical" stackId="s" fill={`url(#cc)`} radius={[3,3,0,0]} />
                  <Line yAxisId="rate" type="monotone" dataKey="passRate" name="Detect Rate"
                    stroke={C.emerald} strokeWidth={2.5}
                    dot={{ r: 3, fill: C.emerald, strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: C.emerald, stroke: 'var(--bg-card)', strokeWidth: 2 }} />
                </ComposedChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

      </div>
    );
  }, [kpiNums, l2Findings, l3Findings, activeScanTrend]);

  // ── Page context ──
  const pageContext = {
    title: 'CIEM \u2014 Log Analysis',
    brief: 'Cloud log collection, threat detection, and identity risk analysis',
    tabs: [
      { id: 'overview',    label: 'Overview',         count: topCritical.length },
      { id: 'identities',  label: 'Identity Risk',    count: identities.length  },
      { id: 'detections',  label: 'Detection Rules',  count: topRules.length    },
      { id: 'events',      label: 'Log Sources',      count: logSources.length  },
    ],
  };

  // ── Column definitions ──
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

  const identityColumns = [
    { accessorKey: 'actor_principal', header: 'Identity', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{(getValue() || '').split('/').pop()}</span>
    )},
    { accessorKey: 'risk_score', header: 'Risk', cell: ({ getValue }) => {
      const v = getValue() || 0;
      const color = v >= 80 ? '#ef4444' : v >= 50 ? '#f97316' : v >= 20 ? '#eab308' : '#22c55e';
      return <span style={{ color, fontWeight: 700 }}>{v}</span>;
    }},
    { accessorKey: 'total_findings', header: 'Findings' },
    { accessorKey: 'critical', header: 'Critical', cell: ({ getValue }) => (
      <span style={{ color: getValue() > 0 ? '#ef4444' : 'var(--text-muted)', fontWeight: getValue() > 0 ? 700 : 400 }}>{getValue() || 0}</span>
    )},
    { accessorKey: 'high', header: 'High', cell: ({ getValue }) => (
      <span style={{ color: getValue() > 0 ? '#f97316' : 'var(--text-muted)', fontWeight: getValue() > 0 ? 700 : 400 }}>{getValue() || 0}</span>
    )},
    { accessorKey: 'rules_triggered', header: 'Rules' },
    { accessorKey: 'services_used', header: 'Services' },
    { accessorKey: 'resources_touched', header: 'Resources' },
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
      const label = v === 'correlation' ? 'L2' : v === 'baseline' ? 'L3' : 'L1';
      return <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: '0.75rem', background: 'var(--bg-tertiary)' }}>{label}</span>;
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

  // ── Build tabData ──
  const tabData = useMemo(() => ({
    overview:   { data: topCritical, columns: criticalColumns  },
    identities: { data: identities,  columns: identityColumns  },
    detections: { data: topRules,    columns: detectionColumns },
    events:     { data: logSources,  columns: eventColumns     },
  }), [topCritical, identities, topRules, logSources]);

  return (
    <div className="space-y-5">

      {/* ── Heading ── */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Eye className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
              {pageContext.title}
            </h1>
          </div>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {pageContext.brief}
          </p>
        </div>
        <button onClick={() => window.location.reload()}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-opacity hover:opacity-80"
          style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* ── Insight strip (KPIs + Donut + Trend) ── */}
      {/* ── PageLayout: tabs + table ── */}
      <PageLayout
        icon={Eye}
        pageContext={pageContext}
        kpiGroups={[]}
        insightRow={insightStrip || null}
        tabData={tabData}
        loading={false}
        error={error}
        defaultTab="overview"
        hideHeader
        topNav
      />
    </div>
  );
}
