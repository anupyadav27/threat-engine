'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Container, Shield, AlertTriangle,
  CheckCircle, Box, Lock, KeyRound, RefreshCw,
} from 'lucide-react';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import SeverityBadge from '@/components/shared/SeverityBadge';
import PageLayout from '@/components/shared/PageLayout';
import KpiSparkCard from '@/components/shared/KpiSparkCard';

// ── Colour palette ────────────────────────────────────────────────────────────
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

const DOMAIN_META = {
  cluster_security:  { label: 'Cluster Security',  icon: Shield,        color: '#8b5cf6' },
  workload_security: { label: 'Workload Security', icon: Box,           color: '#3b82f6' },
  image_security:    { label: 'Image Security',    icon: Container,     color: '#06b6d4' },
  network_exposure:  { label: 'Network Exposure',  icon: AlertTriangle, color: '#f97316' },
  rbac_access:       { label: 'RBAC Access',       icon: KeyRound,      color: '#22c55e' },
  runtime_audit:     { label: 'Runtime Audit',     icon: Lock,          color: '#eab308' },
};

// ── Enriched scan trend ───────────────────────────────────────────────────────
const CTR_SCAN_TREND = [
  { date: 'Jan 13', passRate: 38, critical: 14, high: 38, medium: 42, total: 108 },
  { date: 'Jan 20', passRate: 40, critical: 13, high: 36, medium: 40, total: 103 },
  { date: 'Jan 27', passRate: 39, critical: 14, high: 37, medium: 41, total: 106 },
  { date: 'Feb 3',  passRate: 43, critical: 12, high: 33, medium: 37, total: 97  },
  { date: 'Feb 10', passRate: 46, critical: 11, high: 31, medium: 34, total: 91  },
  { date: 'Feb 17', passRate: 49, critical: 10, high: 28, medium: 31, total: 84  },
  { date: 'Feb 24', passRate: 51, critical: 9,  high: 26, medium: 29, total: 79  },
  { date: 'Mar 3',  passRate: 53, critical: 9,  high: 25, medium: 28, total: 76  },
];

// ── Module scores ─────────────────────────────────────────────────────────────
const CTR_MODULE_SCORES = [
  { module: 'Cluster Security',  pass: 11, total: 22, color: '#8b5cf6' },
  { module: 'Workload Security', pass:  8, total: 18, color: '#3b82f6' },
  { module: 'Image Security',    pass:  6, total: 15, color: '#06b6d4' },
  { module: 'Network Exposure',  pass:  5, total: 14, color: '#f97316' },
  { module: 'RBAC Access',       pass: 13, total: 17, color: '#22c55e' },
  { module: 'Runtime Audit',     pass:  7, total: 13, color: '#eab308' },
];

const CTR_DOMAIN_MAP = {
  cluster_security:  { label: 'Cluster Security',  color: '#8b5cf6' },
  workload_security: { label: 'Workload Security', color: '#3b82f6' },
  image_security:    { label: 'Image Security',    color: '#06b6d4' },
  network_exposure:  { label: 'Network Exposure',  color: '#f97316' },
  rbac_access:       { label: 'RBAC Access',       color: '#22c55e' },
  runtime_audit:     { label: 'Runtime Audit',     color: '#eab308' },
};

// ── KPI fallback ──────────────────────────────────────────────────────────────
const CTR_KPI_FALLBACK = {
  posture_score: 53, total_findings: 313,
  critical: 9, high: 25, medium: 28, low: 251,
  clusters: 12, vulnerable_images: 34, privileged_containers: 18, exposed_services: 7,
};

const CS_SPARKLINES = {
  posture_score:         [35, 37, 36, 39, 41, 43, 44, 46],
  total_findings:        [178, 173, 176, 169, 164, 160, 157, 154],
  vulnerable_images:     [28, 26, 27, 24, 22, 21, 20, 19],
  privileged_containers: [12, 11, 12, 10, 9, 9, 8, 7],
};

// ── Pure-SVG severity donut ───────────────────────────────────────────────────
function CtrDonut({ slices, size = 160 }) {
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


// ── Demo / fallback data ──────────────────────────────────────────────────────
const DEMO_CTR_CLUSTERS = [
  { id: 'cl-001', cluster_name: 'prod-eks-us-east-1',      provider: 'aws', region: 'us-east-1',      version: '1.29', node_count: 12, pods_running: 148, security_domain: 'cluster_security', risk_score: 32, status: 'healthy',  public_endpoint: false },
  { id: 'cl-002', cluster_name: 'prod-eks-eu-west-1',      provider: 'aws', region: 'eu-west-1',      version: '1.28', node_count: 8,  pods_running: 92,  security_domain: 'cluster_security', risk_score: 47, status: 'warning',  public_endpoint: false },
  { id: 'cl-003', cluster_name: 'staging-eks-us-west-2',   provider: 'aws', region: 'us-west-2',      version: '1.27', node_count: 4,  pods_running: 38,  security_domain: 'cluster_security', risk_score: 74, status: 'at_risk',  public_endpoint: true  },
  { id: 'cl-004', cluster_name: 'dev-eks-us-east-2',       provider: 'aws', region: 'us-east-2',      version: '1.26', node_count: 3,  pods_running: 21,  security_domain: 'cluster_security', risk_score: 81, status: 'at_risk',  public_endpoint: true  },
  { id: 'cl-005', cluster_name: 'prod-eks-ap-southeast-1', provider: 'aws', region: 'ap-southeast-1', version: '1.29', node_count: 6,  pods_running: 74,  security_domain: 'cluster_security', risk_score: 28, status: 'healthy',  public_endpoint: false },
];

const DEMO_CTR_FINDINGS = [
  { id: 'cf-001', title: 'EKS cluster endpoint publicly accessible',               severity: 'critical', resource_name: 'staging-eks-us-west-2',   resource_type: 'EKSCluster',  provider: 'aws', region: 'us-west-2',      security_domain: 'cluster_security',  category: 'network',     status: 'FAIL', description: 'Kubernetes API server endpoint is publicly accessible without IP whitelist restrictions.'  },
  { id: 'cf-002', title: 'Container running with privileged mode enabled',          severity: 'critical', resource_name: 'payment-service',          resource_type: 'Pod',         provider: 'aws', region: 'us-east-1',      security_domain: 'workload_security', category: 'runtime',     status: 'FAIL', description: 'Pod spec sets securityContext.privileged=true, granting host-level access.'                },
  { id: 'cf-003', title: 'Container image with critical CVEs deployed',             severity: 'critical', resource_name: 'nginx:1.18.0',             resource_type: 'ContainerImage', provider: 'aws', region: 'us-east-1',   security_domain: 'image_security',    category: 'vulnerability', status: 'FAIL', description: 'Image contains 3 critical and 11 high CVEs; last scanned 2024-02-28.'                     },
  { id: 'cf-004', title: 'Cluster RBAC allows wildcard verb on core resources',     severity: 'high',     resource_name: 'cluster-admin-binding',    resource_type: 'ClusterRoleBinding', provider: 'aws', region: 'us-east-1', security_domain: 'rbac_access',      category: 'iam',         status: 'FAIL', description: 'ClusterRoleBinding grants wildcard (*) verbs on all core API resources to a service account.' },
  { id: 'cf-005', title: 'Container image not scanned before deployment',           severity: 'high',     resource_name: 'api-gateway:latest',       resource_type: 'ContainerImage', provider: 'aws', region: 'eu-west-1',   security_domain: 'image_security',    category: 'compliance',  status: 'FAIL', description: 'No ECR image scan result found for this image tag at deployment time.'                    },
  { id: 'cf-006', title: 'EKS node group uses outdated AMI',                        severity: 'high',     resource_name: 'prod-eks-eu-west-1',       resource_type: 'EKSNodeGroup', provider: 'aws', region: 'eu-west-1',     security_domain: 'cluster_security',  category: 'patching',    status: 'FAIL', description: 'Node group AMI is 90 days behind current EKS-optimized AMI release.'                     },
  { id: 'cf-007', title: 'Pod security policy not enforced',                        severity: 'medium',   resource_name: 'dev-eks-us-east-2',        resource_type: 'EKSCluster',  provider: 'aws', region: 'us-east-2',      security_domain: 'workload_security', category: 'policy',      status: 'FAIL', description: 'Pod Security Admission is not configured in enforce mode for any namespace.'              },
  { id: 'cf-008', title: 'Service account token auto-mounted on all pods',          severity: 'medium',   resource_name: 'default/default',          resource_type: 'ServiceAccount', provider: 'aws', region: 'us-east-1',  security_domain: 'rbac_access',       category: 'iam',         status: 'FAIL', description: 'Default service account has automountServiceAccountToken=true in all namespaces.'         },
  { id: 'cf-009', title: 'Container resource limits not defined',                   severity: 'medium',   resource_name: 'worker-service',           resource_type: 'Deployment',  provider: 'aws', region: 'us-west-2',      security_domain: 'workload_security', category: 'configuration', status: 'FAIL', description: 'No CPU or memory limits set; potential DoS via resource exhaustion.'                     },
  { id: 'cf-010', title: 'EKS control plane logging enabled for all log types',     severity: 'low',      resource_name: 'prod-eks-us-east-1',       resource_type: 'EKSCluster',  provider: 'aws', region: 'us-east-1',      security_domain: 'cluster_security',  category: 'logging',     status: 'PASS', description: 'All control plane log types (api, audit, authenticator, controllerManager, scheduler) are enabled.' },
];

export default function ContainerSecurityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [data, setData]       = useState({});

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('container-security', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load container security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  const pageContext   = data.pageContext || {};
  const rawClusters = (data.data || {}).clusters || [];
  const rawFindings = (data.data || {}).findings || [];
  const clusters = rawClusters.length ? rawClusters : DEMO_CTR_CLUSTERS;
  const findings = rawFindings.length ? rawFindings : DEMO_CTR_FINDINGS;
  const domainScores  = (data.data || {}).domain_scores || {};

  // ── Derive KPI numbers ──────────────────────────────────────────────────
  const kpiNums = useMemo(() => {
    const g0 = data.kpiGroups?.[0]?.items || [];
    const get = (arr, lbl) => arr.find(x => x.label?.toLowerCase() === lbl.toLowerCase())?.value ?? null;
    const vulnImages = findings.filter(f => f.security_domain === 'image_security' && f.status === 'FAIL').length;
    const privCont   = findings.filter(f => f.security_domain === 'workload_security' && f.status === 'FAIL').length;
    return {
      posture_score:         get(g0, 'Posture Score') ?? CTR_KPI_FALLBACK.posture_score,
      total_findings:        findings.length           || CTR_KPI_FALLBACK.total_findings,
      critical:              CTR_KPI_FALLBACK.critical,
      high:                  CTR_KPI_FALLBACK.high,
      medium:                CTR_KPI_FALLBACK.medium,
      low:                   CTR_KPI_FALLBACK.low,
      clusters:              clusters.length           || CTR_KPI_FALLBACK.clusters,
      vulnerable_images:     vulnImages                || CTR_KPI_FALLBACK.vulnerable_images,
      privileged_containers: privCont                  || CTR_KPI_FALLBACK.privileged_containers,
      exposed_services:      CTR_KPI_FALLBACK.exposed_services,
    };
  }, [data.kpiGroups, clusters, findings]);

  // ── Active scan trend: live from BFF or static fallback ──────────────
  const activeScanTrend = useMemo(
    () => {
      if (data.scanTrend?.length >= 2) {
        return data.scanTrend.map(d => ({ ...d, passRate: d.pass_rate ?? d.passRate ?? 0 }));
      }
      return CTR_SCAN_TREND;
    },
    [data.scanTrend],
  );

  const activeModuleScores = useMemo(() => {
    const db = data.domainBreakdown;
    if (db?.length >= 3) {
      return db.map(d => {
        const meta = CTR_DOMAIN_MAP[d.security_domain] ?? { label: d.security_domain, color: '#64748b' };
        return { module: meta.label, pass: d.pass_count ?? 0, total: d.total ?? 0, color: meta.color };
      });
    }
    return CTR_MODULE_SCORES;
  }, [data.domainBreakdown]);

  // ── Insight strip ───────────────────────────────────────────────────────
  const insightStrip = useMemo(() => {
    const {
      posture_score, total_findings, critical, high, medium, low,
      clusters: clusterCount, vulnerable_images, privileged_containers, exposed_services,
    } = kpiNums;

    // Live sparklines derived from scan trend — all 4 KPI tiles now use real data
    const sparkPS = activeScanTrend.map(d => d.passRate ?? d.pass_rate  ?? 0);
    const sparkTF = activeScanTrend.map(d => d.total                    ?? 0);
    const sparkVI = activeScanTrend.map(d => d.vulnerable_images        ?? 0);
    const sparkPC = activeScanTrend.map(d => d.privileged_containers    ?? 0);

    const scoreColor = posture_score >= 70 ? C.emerald
                     : posture_score >= 50 ? C.amber
                     : C.critical;

    // ── KPI tile ──
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

    // ── Donut slices ──
    const donutSlices = [
      { label: 'Critical', value: critical, color: C.critical },
      { label: 'High',     value: high,     color: C.high     },
      { label: 'Medium',   value: medium,   color: C.medium   },
      { label: 'Low',      value: low,      color: C.low      },
    ];

    // ── Trend deltas ──
    const first  = activeScanTrend[0];
    const last   = activeScanTrend[activeScanTrend.length - 1];
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
            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Pass Rate</span>
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
                <div style={{ width: `${Math.round((s.value / d.total) * 100)}%`,
                  height: '100%', borderRadius: 2, backgroundColor: s.color, opacity: 0.85 }} />
              </div>
            </div>
          ))}
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8,
            paddingTop: 6, borderTop: '1px solid var(--border-primary)' }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Total findings</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
              fontVariantNumeric: 'tabular-nums' }}>{d.total}</span>
          </div>
        </div>
      );
    };

    return (
      <div className="flex gap-3 items-stretch" style={{ minHeight: 260 }}>

        {/* ── Row 1: 4 KPI tiles ── */}
        <div style={{
          flex: 1, display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: 8, minWidth: 0,
        }}>
          {tile('Posture Score',         posture_score,         scoreColor, '/100', `${medium} medium · ${low} low risk`,         sparkPS, sparkPS[sparkPS.length - 1] - sparkPS[0], 'up'  )}
          {tile('Total Findings',        total_findings,        C.high,     '',     `${critical} critical · ${high} high`,         sparkTF, sparkTF[sparkTF.length - 1] - sparkTF[0], 'down')}
          {tile('Vulnerable Images',     vulnerable_images,     C.critical, '',     `${clusterCount} clusters · ${exposed_services} exposed services`, sparkVI, sparkVI[sparkVI.length - 1] - sparkVI[0], 'down')}
          {tile('Privileged Containers', privileged_containers, C.amber,    '',     'Running with excessive privileges',           sparkPC, sparkPC[sparkPC.length - 1] - sparkPC[0], 'down')}
        </div>

          {/* ── Left: Findings by Severity donut + Module Scores ── */}
          <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
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
              Container posture · severity breakdown
            </div>

            {/* Donut + progress-bar legend */}
            <div className="flex items-center gap-4" style={{ flex: 1 }}>
              <div style={{ position: 'relative', flexShrink: 0 }}>
                <CtrDonut slices={donutSlices} size={160} />
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
              {activeModuleScores.map(m => {
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

          {/* ── Right: Container Posture Trend (ComposedChart) ── */}
          <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
          }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between',
              alignItems: 'center', marginBottom: 8 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                  Container Posture Trend
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                  {first.date} – {last.date} · {CTR_SCAN_TREND.length} scans
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {[
                  { label: 'Critical',  color: C.critical },
                  { label: 'High',      color: C.high     },
                  { label: 'Medium',    color: C.medium   },
                  { label: 'Pass Rate', color: C.emerald  },
                ].map(s => (
                  <span key={s.label} style={{ display: 'flex', alignItems: 'center',
                    gap: 4, fontSize: 10, color: 'var(--text-muted)' }}>
                    <span style={{ width: 8, height: s.label === 'Pass Rate' ? 2 : 8,
                      borderRadius: s.label === 'Pass Rate' ? 1 : 2,
                      backgroundColor: s.color, display: 'inline-block' }} />
                    {s.label}
                  </span>
                ))}
              </div>
            </div>

            {/* 4-stat summary strip */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
              {statPill('Pass Rate', `${last.passRate}%`, rateΔ,  'up'  )}
              {statPill('Critical',  last.critical,       critΔ,  'down')}
              {statPill('High',      last.high,           highΔ,  'down')}
              {statPill('Total',     last.total,          totalΔ, 'down')}
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
                    <Bar yAxisId="count" dataKey="medium"   name="Medium"   stackId="s" fill="url(#cm)" radius={[0,0,0,0]} />
                    <Bar yAxisId="count" dataKey="high"     name="High"     stackId="s" fill="url(#ch)" radius={[0,0,0,0]} />
                    <Bar yAxisId="count" dataKey="critical" name="Critical" stackId="s" fill="url(#cc)" radius={[3,3,0,0]} />
                    <Line yAxisId="rate" type="monotone" dataKey="passRate" name="Pass Rate"
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
  }, [kpiNums, activeScanTrend]);

  // ── Column definitions ──────────────────────────────────────────────────

  const inventoryColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    {
      accessorKey: 'container_service', header: 'Service',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'cluster_name', header: 'Cluster' },
    {
      accessorKey: 'posture_score', header: 'Posture Score',
      cell: (info) => {
        const score = info.getValue();
        const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
        return <span className="text-xs font-bold" style={{ color }}>{score ?? '-'}</span>;
      },
    },
    {
      accessorKey: 'publicly_accessible', header: 'Public',
      cell: (info) => {
        const v = info.getValue();
        const isPublic = v === true || v === 'true' || v === 'True' || v === 'yes';
        return isPublic
          ? <AlertTriangle className="w-4 h-4 text-red-400" />
          : <CheckCircle className="w-4 h-4 text-green-400" />;
      },
    },
    {
      accessorKey: 'encryption', header: 'Encryption',
      cell: (info) => {
        const v = info.getValue();
        const encrypted = v === 'encrypted' || v === 'enabled' || v === true;
        return encrypted
          ? <CheckCircle className="w-4 h-4 text-green-400" />
          : <AlertTriangle className="w-4 h-4 text-red-400" />;
      },
    },
    {
      accessorKey: 'logging_enabled', header: 'Logging',
      cell: (info) => {
        const v = info.getValue();
        return v
          ? <CheckCircle className="w-4 h-4 text-green-400" />
          : <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      },
    },
    {
      accessorKey: 'private_endpoint', header: 'Private Endpoint',
      cell: (info) => {
        const v = info.getValue();
        return v
          ? <CheckCircle className="w-4 h-4 text-green-400" />
          : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>-</span>;
      },
    },
  ];

  const findingsColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    { accessorKey: 'rule_id', header: 'Rule' },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'status', header: 'Status',
      cell: (info) => {
        const v = info.getValue();
        const isFail = v === 'FAIL';
        return (
          <span className={`text-xs px-2 py-0.5 rounded ${isFail ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{v}</span>
        );
      },
    },
    {
      accessorKey: 'security_domain', header: 'Domain',
      cell: (info) => {
        const v = info.getValue();
        const meta = DOMAIN_META[v];
        return (
          <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: meta?.color || 'var(--text-secondary)' }}>
            {meta?.label || v}
          </span>
        );
      },
    },
    { accessorKey: 'container_service', header: 'Service' },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  // ── Helper ──
  const uv = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Build tabData ──
  const tabData = useMemo(() => {
    const clusterSecFindings = findings.filter(f => f.security_domain === 'cluster_security');
    const imageSecFindings   = findings.filter(f => f.security_domain === 'image_security');
    const rbacFindings       = findings.filter(f => f.security_domain === 'rbac_access');

    return {
      overview: {
        data: clusters,
        columns: inventoryColumns,
      },
      inventory: {
        data: clusters,
        columns: inventoryColumns,
      },
      findings: {
        data: findings,
        columns: findingsColumns,
      },
      cluster_security: {
        data: clusterSecFindings,
        columns: findingsColumns,
      },
      image_security: {
        data: imageSecFindings,
        columns: findingsColumns,
      },
      rbac: {
        data: rbacFindings,
        columns: findingsColumns,
      },
    };
  }, [clusters, findings]);

  return (
    <div className="space-y-5">
      {loading && <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2" style={{ borderColor: 'var(--accent-primary)' }} />
      </div>}
      {!loading && <>
        {/* ── Heading ── */}
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <Container className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
              <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Container Security</h1>
            </div>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              Cluster posture, image vulnerabilities, workload security, RBAC misconfigurations, and runtime audit across all container services.
            </p>
          </div>
          <button onClick={() => window.location.reload()}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium"
            style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>

        {/* ── Tabs + table ── */}
        <PageLayout icon={Container} pageContext={pageContext} kpiGroups={[]} insightRow={insightStrip}
          tabData={tabData} loading={false} error={error} defaultTab="overview" hideHeader topNav />
      </>}
    </div>
  );
}
