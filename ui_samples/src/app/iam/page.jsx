'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Shield, KeyRound, CheckCircle, AlertTriangle,
  ChevronDown, Info, RefreshCw,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
import KpiSparkCard from '@/components/shared/KpiSparkCard';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';

// ── Demo fallback data (shown when backend returns no data) ───────────────────
const DEMO_IAM_IDENTITIES = [
  { username: 'admin-deploy-user',   type: 'User',            account: '123456789012', policies: 14, severity: 'critical', risk_score: 91, mfa: false },
  { username: 'svc-data-pipeline',   type: 'Service Account', account: '123456789012', policies: 22, severity: 'critical', risk_score: 87, mfa: false },
  { username: 'dev-lead-jsmith',     type: 'User',            account: '234567890123', policies: 9,  severity: 'high',     risk_score: 73, mfa: true  },
  { username: 'ci-cd-automation',    type: 'Service Account', account: '123456789012', policies: 18, severity: 'high',     risk_score: 68, mfa: false },
  { username: 'analytics-reader',    type: 'User',            account: '345678901234', policies: 4,  severity: 'medium',   risk_score: 44, mfa: true  },
  { username: 'ops-oncall-role',     type: 'Role',            account: '123456789012', policies: 7,  severity: 'medium',   risk_score: 39, mfa: true  },
  { username: 'backup-restore-svc',  type: 'Service Account', account: '234567890123', policies: 11, severity: 'low',      risk_score: 22, mfa: true  },
  { username: 'readonly-auditor',    type: 'User',            account: '345678901234', policies: 2,  severity: 'low',      risk_score: 11, mfa: true  },
];

const DEMO_IAM_ROLES = [
  { name: 'AdminFullAccess',       type: 'Role', rule_id: 'IAM-R-001', severity: 'critical', status: 'FAIL', account_id: '123456789012', region: 'us-east-1' },
  { name: 'CrossAccountDeploy',    type: 'Role', rule_id: 'IAM-R-002', severity: 'critical', status: 'FAIL', account_id: '123456789012', region: 'us-east-1' },
  { name: 'EC2InstanceProfileProd',type: 'Role', rule_id: 'IAM-R-003', severity: 'high',     status: 'FAIL', account_id: '234567890123', region: 'us-west-2' },
  { name: 'LambdaExecutionRole',   type: 'Role', rule_id: 'IAM-R-004', severity: 'high',     status: 'FAIL', account_id: '123456789012', region: 'us-east-1' },
  { name: 'DataScienceNotebook',   type: 'Role', rule_id: 'IAM-R-005', severity: 'medium',   status: 'FAIL', account_id: '345678901234', region: 'eu-west-1' },
  { name: 'ReadOnlyReporting',     type: 'Role', rule_id: 'IAM-R-006', severity: 'low',      status: 'PASS', account_id: '345678901234', region: 'eu-west-1' },
];

const DEMO_IAM_ACCESS_KEYS = [
  { user: 'admin-deploy-user', type: 'Access Key', rule_id: 'IAM-K-001', severity: 'critical', status: 'FAIL', account_id: '123456789012', region: 'global' },
  { user: 'svc-data-pipeline', type: 'Access Key', rule_id: 'IAM-K-002', severity: 'high',     status: 'FAIL', account_id: '123456789012', region: 'global' },
  { user: 'ci-cd-automation',  type: 'Access Key', rule_id: 'IAM-K-003', severity: 'high',     status: 'FAIL', account_id: '234567890123', region: 'global' },
  { user: 'dev-lead-jsmith',   type: 'Access Key', rule_id: 'IAM-K-004', severity: 'medium',   status: 'FAIL', account_id: '234567890123', region: 'global' },
  { user: 'analytics-reader',  type: 'Access Key', rule_id: 'IAM-K-005', severity: 'low',      status: 'PASS', account_id: '345678901234', region: 'global' },
];

const DEMO_IAM_PRIVESC = [
  { name: 'User → AdminRole via iam:PassRole',          type: 'Attack Path', rule_id: 'IAM-P-001', severity: 'critical', status: 'FAIL', account_id: '123456789012', region: 'us-east-1' },
  { name: 'SvcAccount → S3:* via inline policy attach', type: 'Attack Path', rule_id: 'IAM-P-002', severity: 'critical', status: 'FAIL', account_id: '123456789012', region: 'us-east-1' },
  { name: 'Lambda → RDS admin via wildcard resource',   type: 'Attack Path', rule_id: 'IAM-P-003', severity: 'high',     status: 'FAIL', account_id: '234567890123', region: 'us-west-2' },
  { name: 'CI/CD Role → secrets:GetSecretValue *',      type: 'Attack Path', rule_id: 'IAM-P-004', severity: 'high',     status: 'FAIL', account_id: '123456789012', region: 'us-east-1' },
];

// ── Color palette ──
const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  sky:      '#38bdf8',
  amber:    '#f59e0b',
  emerald:  '#10b981',
  indigo:   '#6366f1',
};

// ── Scan trend: total identities + risk subsets ──
const IAM_SCAN_TREND = [
  { date: 'Jan 13', total: 148, overprivileged: 47, no_mfa: 23 },
  { date: 'Jan 20', total: 151, overprivileged: 44, no_mfa: 21 },
  { date: 'Jan 27', total: 154, overprivileged: 42, no_mfa: 20 },
  { date: 'Feb 3',  total: 156, overprivileged: 41, no_mfa: 18 },
  { date: 'Feb 10', total: 158, overprivileged: 39, no_mfa: 17 },
  { date: 'Feb 17', total: 159, overprivileged: 37, no_mfa: 16 },
  { date: 'Feb 24', total: 160, overprivileged: 35, no_mfa: 14 },
  { date: 'Mar 3',  total: 160, overprivileged: 34, no_mfa: 13 },
].map(d => ({
  ...d,
  // "safe" = identities with no known risk (remainder after risk layers)
  safe: Math.max(0, d.total - d.overprivileged - d.no_mfa),
}));

// ── KPI fallback ──
const IAM_KPI_FALLBACK = {
  critical: 3, high: 193, medium: 372, low: 0,
  posture_score: 31, total_findings: 568,
  identities: 160, keys_to_rotate: 34,
  overprivileged: 34, no_mfa: 13,
};

const IAM_SPARKLINES = {
  posture_score:  [22, 24, 25, 26, 27, 28, 29, 31],
  total_findings: [620, 608, 598, 592, 585, 578, 572, 568],
  identities:     [155, 156, 157, 158, 158, 159, 160, 160],
  keys_to_rotate: [52, 49, 47, 44, 42, 39, 37, 34],
};

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


// ── IAM Finding / Identity Detail Panel ─────────────────────────────────────
const IAM_ISSUE_MAP = {
  critical: [
    'No MFA enabled on root or privileged account',
    'Access key not rotated in 90+ days',
    'Inline policy grants full administrative privileges (*:*)',
    'Cross-account trust without condition keys',
  ],
  high: [
    'Console access without MFA enforcement',
    'Unused credentials active for 45+ days',
    'Role trust policy allows all principals (*)',
    'Service account with human-equivalent permissions',
  ],
  medium: [
    'Password policy does not meet minimum requirements',
    'Permissions boundary not attached to privileged role',
    'CloudTrail not capturing IAM events in all regions',
    'Access Analyzer findings unresolved for 30+ days',
  ],
  low: [
    'Access key last used over 60 days ago',
    'Role has no permission boundary',
    'User belongs to more than 10 groups',
  ],
};

const IAM_REMEDIATION_MAP = {
  critical: 'Immediately revoke or rotate credentials. Enable MFA on all privileged accounts. Replace wildcard policies with least-privilege alternatives scoped to specific resources and actions.',
  high: 'Enable MFA for console access. Review and remove unused credentials. Restrict role trust policies to specific principals with condition keys (aws:PrincipalArn, aws:SourceAccount).',
  medium: 'Update account password policy to enforce complexity and rotation. Attach permission boundaries to all privileged roles. Ensure CloudTrail is enabled across all regions.',
  low: 'Review and deactivate unused access keys. Consolidate group memberships. Apply permission boundaries to limit effective permissions.',
};

export default function IamSecurityPage() {
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [data, setData]           = useState({});
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [selectedIdentity, setSelectedIdentity] = useState(null);

  const handleRowClick = (row) => {
    const identity = row?.original || row;
    if (identity) setSelectedIdentity(identity);
  };

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true); setError(null);
      try {
        const result = await fetchView('iam', {
          provider: provider || undefined,
          account:  account  || undefined,
          region:   region   || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load IAM data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  const rawIdentities          = data.identities          || [];
  const rawFindings            = data.findings            || [];
  const rawRoles               = data.roles               || [];
  const rawAccessKeys          = data.accessKeys          || [];
  const rawPrivilegeEscalation = data.privilegeEscalation || [];

  const identities          = rawIdentities.length          ? rawIdentities          : DEMO_IAM_IDENTITIES;
  const roles               = rawRoles.length               ? rawRoles               : DEMO_IAM_ROLES;
  const accessKeys          = rawAccessKeys.length          ? rawAccessKeys          : DEMO_IAM_ACCESS_KEYS;
  const privilegeEscalation = rawPrivilegeEscalation.length ? rawPrivilegeEscalation : DEMO_IAM_PRIVESC;

  // ── Derive KPI numbers ──
  const kpiNums = useMemo(() => {
    const g0 = data.kpiGroups?.[0]?.items || [];
    const g1 = data.kpiGroups?.[1]?.items || [];
    const get = (arr, lbl) =>
      arr.find(x => x.label?.toLowerCase() === lbl.toLowerCase())?.value ?? null;

    return {
      critical:      get(g0, 'Critical')       ?? IAM_KPI_FALLBACK.critical,
      high:          get(g0, 'High')            ?? IAM_KPI_FALLBACK.high,
      medium:        get(g0, 'Medium')          ?? IAM_KPI_FALLBACK.medium,
      low:           0,
      posture_score: get(g0, 'Posture Score')  ?? IAM_KPI_FALLBACK.posture_score,
      total_findings:get(g0, 'Total Findings') ?? IAM_KPI_FALLBACK.total_findings,
      identityCount: get(g1, 'Identities')     ?? (identities.length || IAM_KPI_FALLBACK.identities),
      keys_to_rotate:get(g1, 'Keys to Rotate') ?? IAM_KPI_FALLBACK.keys_to_rotate,
      mfa_adoption:  get(g1, 'MFA Adoption')   ?? 100,
    };
  }, [data.kpiGroups, identities]);

  // ── Active scan trend: live from BFF or static fallback ──────────────
  const activeScanTrend = useMemo(
    () => (data.scanTrend?.length >= 2 ? data.scanTrend : IAM_SCAN_TREND),
    [data.scanTrend],
  );

  // ── KPI Strip — 2×2 grid · Donut · Trend chart all in ONE row ──
  const kpiStripNode = useMemo(() => {
    const { critical, high, medium, low, posture_score, total_findings,
            identityCount, keys_to_rotate } = kpiNums;

    // Live sparklines derived from scan trend — all 4 KPI tiles now use real data
    const sparkPS = activeScanTrend.map(d => d.pass_rate          ?? 0);
    const sparkTF = activeScanTrend.map(d => d.total              ?? 0);
    const sparkIR = activeScanTrend.map(d => d.identities_at_risk ?? 0);
    const sparkKR = activeScanTrend.map(d => d.keys_to_rotate     ?? 0);

    const scoreColor = posture_score >= 70 ? C.emerald
                     : posture_score >= 50 ? C.amber
                     : C.critical;

    const donutSlices = [
      { label: 'Critical', value: critical, color: C.critical },
      { label: 'High',     value: high,     color: C.high     },
      { label: 'Medium',   value: medium,   color: C.medium   },
      { label: 'Low',      value: low,      color: C.low      },
    ];

    const chartLast = activeScanTrend[activeScanTrend.length - 1];

    // KPI tile — KpiSparkCard with translucent border, glow, sparkline, delta
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

    // ── Trend chart deltas ──
    const chartFirst = activeScanTrend[0];
    const noMfaΔ = (chartLast.no_mfa ?? 0) - (chartFirst.no_mfa ?? 0);
    const overΔ  = (chartLast.overprivileged ?? 0) - (chartFirst.overprivileged ?? 0);
    const safeΔ  = chartLast.safe - chartFirst.safe;
    const totalRiskΔ = (chartLast.no_mfa + chartLast.overprivileged) -
                       (chartFirst.no_mfa + chartFirst.overprivileged);

    const chartSeries = [
      { key: 'no_mfa',         label: 'No MFA',           color: C.critical,
        value: chartLast.no_mfa,         delta: noMfaΔ, good: 'down' },
      { key: 'overprivileged', label: 'Overprivileged',   color: C.high,
        value: chartLast.overprivileged, delta: overΔ,  good: 'down' },
      { key: 'safe',           label: 'Secure',           color: C.emerald,
        value: chartLast.safe,           delta: safeΔ,  good: 'up'   },
    ];

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

        {/* ── Row 1: 4 KPI tiles in a single horizontal row ── */}
        <div style={{
          flex: 1, display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: 8, minWidth: 0,
        }}>
          {tile('Posture Score',   posture_score,  scoreColor, '/100', `${medium} medium · ${low} low risk`,  sparkPS, sparkPS[sparkPS.length - 1] - sparkPS[0],  'up'  )}
          {tile('Total Findings', total_findings, C.high,    '',     `${critical} critical · ${high} high`,  sparkTF, sparkTF[sparkTF.length - 1] - sparkTF[0], 'down')}
          {tile('Identities',     identityCount,  C.sky,     '',     `${chartLast.overprivileged} overprivileged · ${chartLast.no_mfa} no MFA`, sparkIR, sparkIR[sparkIR.length - 1] - sparkIR[0], 'up')}
          {tile('Keys to Rotate', keys_to_rotate, C.amber,  '',     'Exceed 90-day rotation policy', sparkKR, sparkKR[sparkKR.length - 1] - sparkKR[0], 'down')}
        </div>

        {/* ── Findings by Severity Donut ── */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)',
          minWidth: 0, overflow: 'hidden',
        }}>
          {/* Header */}
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

          {/* Donut + legend side-by-side */}
          <div className="flex items-center gap-4 flex-1">
            {/* Donut */}
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <IamDonut slices={donutSlices} size={160} />
              <div style={{
                position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', pointerEvents: 'none',
              }}>
                <div style={{ fontSize: 26, fontWeight: 900, color: 'var(--text-primary)', lineHeight: 1 }}>
                  {total_findings.toLocaleString()}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>findings</div>
              </div>
            </div>

            {/* Progress-bar legend */}
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
        </div>

        {/* ── Identity Risk Trend — merged stacked area ── */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)',
          minWidth: 0, overflow: 'hidden',
        }}>

          {/* ── Header row ── */}
          <div style={{ display: 'flex', justifyContent: 'space-between',
            alignItems: 'flex-start', marginBottom: 2 }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                Identity Risk Trend
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 1 }}>
                {chartFirst.date} – {chartLast.date} · {activeScanTrend.length} scans
              </div>
            </div>
            {/* Overall risk delta summary badge */}
            <span style={{
              fontSize: 11, fontWeight: 700, padding: '3px 8px', borderRadius: 20,
              backgroundColor: totalRiskΔ <= 0 ? `${C.emerald}18` : `${C.critical}18`,
              color: totalRiskΔ <= 0 ? C.emerald : C.critical,
              whiteSpace: 'nowrap',
            }}>
              {totalRiskΔ <= 0 ? '↓' : '↑'} {Math.abs(totalRiskΔ)} risk {totalRiskΔ <= 0 ? 'resolved' : 'added'}
            </span>
          </div>

          {/* ── Per-series legend with current value + delta pill ── */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
            {[...chartSeries].reverse().map(s => {
              const improved = s.good === 'down' ? s.delta <= 0 : s.delta >= 0;
              const dColor   = improved ? C.emerald : C.critical;
              const dSign    = s.delta > 0 ? '+' : '';
              return (
                <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2,
                    backgroundColor: s.color, display: 'inline-block', opacity: 0.9 }} />
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{s.label}</span>
                  <span style={{ fontSize: 13, fontWeight: 800, color: s.color,
                    fontVariantNumeric: 'tabular-nums' }}>{s.value}</span>
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: '1px 5px', borderRadius: 10,
                    backgroundColor: `${dColor}18`, color: dColor,
                  }}>{dSign}{s.delta}</span>
                </div>
              );
            })}
          </div>

          {/* ── Stacked Area Chart — fills remaining height ── */}
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
                  <YAxis
                    tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
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

          {/* ── Bottom summary bar ── */}
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8,
            paddingTop: 8, borderTop: '1px solid var(--border-primary)' }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Secure identities
            </span>
            <span style={{ fontSize: 11, fontWeight: 700, fontVariantNumeric: 'tabular-nums',
              color: C.emerald }}>
              {chartLast.safe} / {chartLast.total}
              <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 4 }}>
                ({Math.round((chartLast.safe / chartLast.total) * 100)}%)
              </span>
            </span>
          </div>
        </div>

      </div>
    );
  }, [kpiNums, activeScanTrend]);

  // ── Column definitions ──
  const overviewColumns = [
    { accessorKey: 'username', header: 'Identity', size: 180 },
    {
      accessorKey: 'type', header: 'Type', size: 110,
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'account', header: 'Account', size: 140 },
    { accessorKey: 'policies', header: 'Findings', size: 80 },
    {
      accessorKey: 'severity', header: 'Severity', size: 100,
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'risk_score', header: 'Risk', size: 100,
      cell: (info) => {
        const score = info.getValue();
        const color = score >= 75 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#eab308' : '#22c55e';
        return (
          <div className="flex items-center gap-2">
            <div className="w-14 h-1.5 rounded-full"
              style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full"
                style={{ width: `${score}%`, backgroundColor: color }} />
            </div>
            <span className="text-xs font-bold" style={{ color }}>{score}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'mfa', header: 'MFA', size: 60,
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-red-400" />,
    },
  ];

  const findingsColumns = useMemo(() => [
    {
      accessorKey: 'provider', header: 'Provider', size: 70,
      cell: (info) => info.getValue()?.toUpperCase() || '—',
    },
    { accessorKey: 'account_id', header: 'Account', size: 130,
      cell: (info) => info.getValue() || info.row.original.account || '—' },
    { accessorKey: 'region', header: 'Region', size: 110 },
    {
      accessorKey: 'service', header: 'Service', size: 110,
      cell: (info) => info.getValue() || info.row.original.network_layer || info.row.original.encryption_domain || info.row.original.container_service || info.row.original.db_service || '—',
    },
    { accessorKey: 'rule_id', header: 'Rule ID', size: 130,
      cell: (info) => <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{info.getValue() || '—'}</span> },
    {
      accessorKey: 'title', header: 'Finding', size: 260,
      cell: (info) => {
        const row = info.row.original;
        const v = info.getValue() || row.rule_id || '—';
        return <span className="text-xs leading-tight">{v}</span>;
      },
    },
    { accessorKey: 'severity', header: 'Severity', size: 90,
      cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    {
      accessorKey: 'status', header: 'Status', size: 75,
      cell: (info) => {
        const v = info.getValue(), fail = v === 'FAIL';
        return <span className={`text-xs px-2 py-0.5 rounded ${fail ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{v}</span>;
      },
    },
    {
      accessorKey: 'resource_uid', header: 'Resource', size: 200,
      cell: (info) => {
        const v = info.getValue() || info.row.original.resource_id || '—';
        return <span className="font-mono text-xs truncate block max-w-[180px]" title={v}>{v.split('/').pop() || v}</span>;
      },
    },
    {
      accessorKey: 'resource_type', header: 'Type', size: 120,
      cell: (info) => info.getValue() ? (
        <span className="text-xs px-2 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ) : null,
    },
    {
      accessorKey: 'risk_score', header: 'Risk', size: 80,
      cell: (info) => {
        const s = info.getValue(); if (s == null) return '—';
        const color = s >= 75 ? '#ef4444' : s >= 50 ? '#f97316' : s >= 25 ? '#eab308' : '#22c55e';
        return <span className="text-xs font-bold" style={{ color }}>{s}</span>;
      },
    },
    {
      accessorKey: 'posture_category', header: 'Category', size: 120,
      cell: (info) => info.getValue()
        ? <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{info.getValue().replace(/_/g, ' ')}</span>
        : null,
    },
  ], []);

  const accessKeyColumns = [
    { accessorKey: 'user',       header: 'Name',     size: 180 },
    {
      accessorKey: 'type', header: 'Type', size: 110,
      cell: (info) => info.getValue() ? (
        <span className="text-xs px-2 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ) : null,
    },
    { accessorKey: 'rule_id',    header: 'Rule',     size: 100 },
    { accessorKey: 'severity',   header: 'Severity', size: 100,
      cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    {
      accessorKey: 'status', header: 'Status', size: 80,
      cell: (info) => {
        const v = info.getValue(), fail = v === 'FAIL';
        return <span className={`text-xs px-2 py-0.5 rounded ${fail ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{v}</span>;
      },
    },
    { accessorKey: 'account_id', header: 'Account', size: 140 },
    { accessorKey: 'region',     header: 'Region',  size: 100 },
  ];

  const findingsData = rawFindings.length ? rawFindings : identities;

  const serviceOptions = useMemo(() =>
    [...new Set((rawFindings || []).map(f => f.service || f.network_layer || '').filter(Boolean))].sort(),
  [rawFindings]);

  const tabData = useMemo(() => ({
    overview: { renderTab: () => null },
    findings: {
      data: findingsData,
      columns: rawFindings.length ? findingsColumns : overviewColumns,
      filters: [
        { key: 'provider', label: 'Cloud Platform', options: ['aws', 'azure', 'gcp'] },
        { key: 'severity',  label: 'Severity',       options: ['critical', 'high', 'medium', 'low'] },
        { key: 'status',    label: 'Status',          options: ['FAIL', 'PASS'] },
        { key: 'service',   label: 'Service',         options: serviceOptions },
      ],
      extraFilters: [
        { key: 'region',        label: 'Region',        options: [] },
        { key: 'account_id',    label: 'Account',       options: [] },
        { key: 'resource_type', label: 'Resource Type', options: [] },
      ],
      searchPlaceholder: 'Search by rule, resource, title...',
    },
  }), [findingsData, rawFindings, findingsColumns, overviewColumns, serviceOptions]);

  const pageContext = {
    title: (data.pageContext || {}).title || 'IAM Security',
    brief:  (data.pageContext || {}).brief  || 'Identity and access management posture across cloud accounts. Monitors roles, access keys, MFA adoption, and privilege escalation paths.',
    tabs: [
      { id: 'overview', label: 'Overview' },
      { id: 'findings', label: 'Findings', count: findingsData.length },
    ],
  };

  return (
    <div className="space-y-5">

      {/* ── Heading ── */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <KeyRound className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
              {pageContext.title}
            </h1>
          </div>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {pageContext.brief}
          </p>
          {pageContext.details?.length > 0 && (
            <>
              <button onClick={() => setDetailsOpen(d => !d)}
                className="flex items-center gap-1 text-xs mt-1 hover:underline"
                style={{ color: 'var(--accent-primary)' }}>
                <Info className="w-3.5 h-3.5" />
                {detailsOpen ? 'Hide' : 'Best practices'}
                <ChevronDown className={`w-3.5 h-3.5 transition-transform ${detailsOpen ? 'rotate-180' : ''}`} />
              </button>
              {detailsOpen && (
                <ul className="mt-2 ml-4 space-y-1 text-xs list-disc"
                  style={{ color: 'var(--text-tertiary)' }}>
                  {pageContext.details.map((d, i) => <li key={i}>{d}</li>)}
                </ul>
              )}
            </>
          )}
        </div>
        <button onClick={() => window.location.reload()}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-opacity hover:opacity-80"
          style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* ── PageLayout: tabs + table ── */}
      <PageLayout
        icon={Shield}
        pageContext={pageContext}
        kpiGroups={[]}
        insightRow={kpiStripNode || null}
        tabData={tabData}
        loading={false}
        error={error}
        defaultTab="overview"
        onRowClick={handleRowClick}
        hideHeader
        topNav
      />

      {/* Identity detail drawer */}
      <FindingDetailPanel finding={selectedIdentity} onClose={() => setSelectedIdentity(null)} />
    </div>
  );
}
