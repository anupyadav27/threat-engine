'use client';

import { useState, useEffect, useMemo } from 'react';
import { Network, AlertTriangle, CheckCircle, RefreshCw, Info, ChevronDown } from 'lucide-react';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
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

// ── Enriched scan trend ───────────────────────────────────────────────────────
const NET_SCAN_TREND = [
  { date: 'Jan 13', passRate: 42, critical: 18, high: 34, medium: 28, total: 89, exposed_ports: 34, open_sgs: 18 },
  { date: 'Jan 20', passRate: 44, critical: 17, high: 33, medium: 27, total: 85, exposed_ports: 32, open_sgs: 17 },
  { date: 'Jan 27', passRate: 43, critical: 18, high: 34, medium: 29, total: 87, exposed_ports: 36, open_sgs: 19 },
  { date: 'Feb 3',  passRate: 46, critical: 16, high: 31, medium: 26, total: 82, exposed_ports: 31, open_sgs: 16 },
  { date: 'Feb 10', passRate: 49, critical: 15, high: 30, medium: 25, total: 78, exposed_ports: 28, open_sgs: 15 },
  { date: 'Feb 17', passRate: 51, critical: 15, high: 29, medium: 25, total: 76, exposed_ports: 26, open_sgs: 14 },
  { date: 'Feb 24', passRate: 52, critical: 14, high: 28, medium: 24, total: 74, exposed_ports: 24, open_sgs: 12 },
  { date: 'Mar 3',  passRate: 53, critical: 14, high: 28, medium: 24, total: 73, exposed_ports: 23, open_sgs: 11 },
];

// ── Module scores ─────────────────────────────────────────────────────────────
const NET_MODULE_SCORES = [
  { module: 'Security Groups',   pass: 14, total: 25, color: C.indigo   },
  { module: 'Internet Exposure', pass:  4, total: 12, color: C.critical },
  { module: 'WAF / DDoS',        pass:  8, total: 13, color: C.sky      },
  { module: 'VPC Topology',      pass: 11, total: 15, color: C.purple   },
  { module: 'DNS Security',      pass:  6, total: 10, color: C.teal     },
  { module: 'Load Balancer',     pass:  9, total: 12, color: C.emerald  },
];

const NET_DOMAIN_MAP = {
  security_groups:   { label: 'Security Groups',   color: '#6366f1' },
  internet_exposure: { label: 'Internet Exposure', color: '#ef4444' },
  waf_protection:    { label: 'WAF / DDoS',        color: '#0ea5e9' },
  vpc_topology:      { label: 'VPC Topology',      color: '#8b5cf6' },
  dns_security:      { label: 'DNS Security',      color: '#14b8a6' },
  load_balancer:     { label: 'Load Balancer',     color: '#10b981' },
};

// ── KPI fallback ──────────────────────────────────────────────────────────────
const NET_KPI_FALLBACK = {
  posture_score: 53, total_findings: 312,
  critical: 14, high: 89, medium: 142, low: 67,
  exposed_resources: 23, internet_exposed: 8, open_sgs: 11, waf_coverage: 62,
};

const NET_SPARKLINES = {
  posture_score:     [42, 44, 43, 46, 49, 51, 52, 53],
  total_findings:    [89, 85, 87, 82, 78, 76, 74, 73],
  exposed_resources: [34, 32, 36, 31, 28, 26, 24, 23],
  waf_coverage:      [54, 56, 55, 58, 60, 61, 62, 62],
};

// ── Pure-SVG severity donut (identical math to IAM) ──────────────────────────
function NetDonut({ slices, size = 160 }) {
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
const DEMO_NET_FINDINGS = [
  { id: 'nf-001', title: 'Security group allows unrestricted SSH access', severity: 'critical', resource_id: 'sg-0a1b2c3d4e5f', resource_type: 'SecurityGroup', provider: 'aws', region: 'us-east-1', status: 'FAIL', finding_type: 'security_groups', description: 'Inbound rule 0.0.0.0/0 on port 22 exposes SSH to the internet.', first_seen: '2024-01-15', last_seen: '2024-03-03' },
  { id: 'nf-002', title: 'Security group allows unrestricted RDP access', severity: 'critical', resource_id: 'sg-0b2c3d4e5f6a', resource_type: 'SecurityGroup', provider: 'aws', region: 'us-west-2', status: 'FAIL', finding_type: 'security_groups', description: 'Inbound rule 0.0.0.0/0 on port 3389 exposes RDP to the internet.', first_seen: '2024-01-18', last_seen: '2024-03-03' },
  { id: 'nf-003', title: 'EC2 instance has public IP and no WAF association', severity: 'high', resource_id: 'i-0c3d4e5f6a7b', resource_type: 'EC2Instance', provider: 'aws', region: 'us-east-1', status: 'FAIL', finding_type: 'internet_exposure', description: 'Instance is internet-accessible with no WAF rule group attached.', first_seen: '2024-02-01', last_seen: '2024-03-03' },
  { id: 'nf-004', title: 'Load balancer listener uses HTTP instead of HTTPS', severity: 'high', resource_id: 'arn:aws:elasticloadbalancing:us-east-1:123456789:loadbalancer/app/prod-alb', resource_type: 'LoadBalancer', provider: 'aws', region: 'us-east-1', status: 'FAIL', finding_type: 'internet_exposure', description: 'ALB listener on port 80 forwards traffic without TLS termination.', first_seen: '2024-01-28', last_seen: '2024-03-03' },
  { id: 'nf-005', title: 'VPC flow logs disabled', severity: 'medium', resource_id: 'vpc-0d4e5f6a7b8c', resource_type: 'VPC', provider: 'aws', region: 'eu-west-1', status: 'FAIL', finding_type: 'vpc_topology', description: 'VPC flow logging is not enabled; network traffic cannot be audited.', first_seen: '2024-02-05', last_seen: '2024-03-03' },
  { id: 'nf-006', title: 'WAF web ACL has no rate-based rules', severity: 'medium', resource_id: 'arn:aws:wafv2:us-east-1:123456789:webacl/prod-waf', resource_type: 'WAFWebACL', provider: 'aws', region: 'us-east-1', status: 'FAIL', finding_type: 'waf_protection', description: 'No rate-based rules are configured; DDoS mitigation is incomplete.', first_seen: '2024-02-10', last_seen: '2024-03-03' },
  { id: 'nf-007', title: 'Subnet routes all traffic through NAT gateway', severity: 'low', resource_id: 'subnet-0e5f6a7b8c9d', resource_type: 'Subnet', provider: 'aws', region: 'us-west-2', status: 'PASS', finding_type: 'vpc_topology', description: 'Private subnet correctly routes outbound traffic through NAT gateway.', first_seen: '2024-01-10', last_seen: '2024-03-03' },
  { id: 'nf-008', title: 'Security group egress unrestricted on all ports', severity: 'medium', resource_id: 'sg-0f6a7b8c9d0e', resource_type: 'SecurityGroup', provider: 'aws', region: 'ap-southeast-1', status: 'FAIL', finding_type: 'security_groups', description: 'Outbound rule 0.0.0.0/0 allows all egress; data exfiltration risk.', first_seen: '2024-02-14', last_seen: '2024-03-03' },
];

const DEMO_NET_SGS = [
  { id: 'sg-001', group_name: 'prod-web-sg',     group_id: 'sg-0a1b2c3d4e5f', provider: 'aws', region: 'us-east-1',      inbound_rules: 3, outbound_rules: 1, attached_resources: 4, risk_level: 'critical', public_exposure: true  },
  { id: 'sg-002', group_name: 'prod-db-sg',      group_id: 'sg-0b2c3d4e5f6a', provider: 'aws', region: 'us-east-1',      inbound_rules: 2, outbound_rules: 1, attached_resources: 2, risk_level: 'low',      public_exposure: false },
  { id: 'sg-003', group_name: 'bastion-sg',      group_id: 'sg-0c3d4e5f6a7b', provider: 'aws', region: 'us-west-2',      inbound_rules: 1, outbound_rules: 1, attached_resources: 1, risk_level: 'high',     public_exposure: true  },
  { id: 'sg-004', group_name: 'internal-app-sg', group_id: 'sg-0d4e5f6a7b8c', provider: 'aws', region: 'eu-west-1',      inbound_rules: 5, outbound_rules: 2, attached_resources: 6, risk_level: 'medium',   public_exposure: false },
  { id: 'sg-005', group_name: 'cache-sg',        group_id: 'sg-0e5f6a7b8c9d', provider: 'aws', region: 'ap-southeast-1', inbound_rules: 1, outbound_rules: 1, attached_resources: 3, risk_level: 'low',      public_exposure: false },
];

const DEMO_NET_EXPOSURE = [
  { id: 'ex-001', resource_name: 'prod-web-01',      resource_type: 'EC2Instance',   provider: 'aws', region: 'us-east-1',      exposure_type: 'direct',          public_ip: '54.23.101.12',  ports_exposed: '22,80,443', risk_score: 92, status: 'FAIL' },
  { id: 'ex-002', resource_name: 'prod-alb',          resource_type: 'LoadBalancer',  provider: 'aws', region: 'us-east-1',      exposure_type: 'load_balancer',   public_ip: '54.23.100.50',  ports_exposed: '80,443',    risk_score: 45, status: 'PASS' },
  { id: 'ex-003', resource_name: 'dev-jump-host',     resource_type: 'EC2Instance',   provider: 'aws', region: 'us-west-2',      exposure_type: 'direct',          public_ip: '44.12.67.88',   ports_exposed: '22,3389',   risk_score: 87, status: 'FAIL' },
  { id: 'ex-004', resource_name: 'staging-rds-proxy', resource_type: 'RDSInstance',   provider: 'aws', region: 'eu-west-1',      exposure_type: 'direct',          public_ip: '18.185.9.23',   ports_exposed: '5432',      risk_score: 78, status: 'FAIL' },
  { id: 'ex-005', resource_name: 'analytics-elb',     resource_type: 'LoadBalancer',  provider: 'aws', region: 'ap-southeast-1', exposure_type: 'load_balancer',   public_ip: '54.251.80.44',  ports_exposed: '443',       risk_score: 20, status: 'PASS' },
];

const DEMO_NET_TOPOLOGY = [
  { id: 'tp-001', source: 'prod-vpc (10.0.0.0/16)',  destination: 'staging-vpc (10.1.0.0/16)',  protocol: 'TCP', port: '5432', direction: 'inbound',  risk_level: 'medium', provider: 'aws', region: 'us-east-1', status: 'FAIL' },
  { id: 'tp-002', source: 'igw-prod',                destination: 'prod-web-subnet',            protocol: 'TCP', port: '443',  direction: 'inbound',  risk_level: 'low',    provider: 'aws', region: 'us-east-1', status: 'PASS' },
  { id: 'tp-003', source: 'prod-private-subnet',     destination: 'nat-gw-prod',                protocol: 'TCP', port: '*',    direction: 'outbound', risk_level: 'low',    provider: 'aws', region: 'us-east-1', status: 'PASS' },
  { id: 'tp-004', source: 'dev-vpc (10.2.0.0/16)',   destination: 'prod-vpc (10.0.0.0/16)',     protocol: 'ALL', port: '*',    direction: 'inbound',  risk_level: 'high',   provider: 'aws', region: 'us-west-2', status: 'FAIL' },
];

const DEMO_NET_WAF = [
  { id: 'waf-001', rule_name: 'AWSManagedRulesCommonRuleSet',      waf_name: 'prod-waf', provider: 'aws', region: 'us-east-1',      action: 'Block',  requests_blocked: 14823, false_positives: 12, status: 'active'   },
  { id: 'waf-002', rule_name: 'AWSManagedRulesSQLiRuleSet',        waf_name: 'prod-waf', provider: 'aws', region: 'us-east-1',      action: 'Block',  requests_blocked: 2341,  false_positives: 3,  status: 'active'   },
  { id: 'waf-003', rule_name: 'AWSManagedRulesAmazonIpReputationList', waf_name: 'prod-waf', provider: 'aws', region: 'us-east-1', action: 'Block',  requests_blocked: 8912,  false_positives: 0,  status: 'active'   },
  { id: 'waf-004', rule_name: 'RateLimitRule-500rpm',               waf_name: 'prod-waf', provider: 'aws', region: 'ap-southeast-1', action: 'Count', requests_blocked: 0,    false_positives: 0,  status: 'inactive' },
];

export default function NetworkSecurityPage() {
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [data, setData]         = useState({});
  const [detailsOpen, setDetailsOpen] = useState(false);

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true); setError(null);
      try {
        const result = await fetchView('network-security', {
          provider: provider || undefined,
          account:  account  || undefined,
          region:   region   || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load network security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  const rawFindings        = (data.data || {}).findings         || [];
  const rawSecurityGroups  = (data.data || {}).security_groups  || [];
  const rawInternetExposure= (data.data || {}).internet_exposure || [];
  const rawTopology        = (data.data || {}).topology         || [];
  const rawWaf             = (data.data || {}).waf              || [];
  const findings         = rawFindings.length         ? rawFindings         : DEMO_NET_FINDINGS;
  const securityGroups   = rawSecurityGroups.length   ? rawSecurityGroups   : DEMO_NET_SGS;
  const internetExposure = rawInternetExposure.length ? rawInternetExposure : DEMO_NET_EXPOSURE;
  const topology         = rawTopology.length         ? rawTopology         : DEMO_NET_TOPOLOGY;
  const waf              = rawWaf.length              ? rawWaf              : DEMO_NET_WAF;

  // ── Derive KPI numbers ──────────────────────────────────────────────────
  const kpiNums = useMemo(() => {
    const g0 = data.kpiGroups?.[0]?.items || [];
    const g1 = data.kpiGroups?.[1]?.items || [];
    const get = (arr, lbl) =>
      arr.find(x => x.label?.toLowerCase() === lbl.toLowerCase())?.value ?? null;
    return {
      posture_score:     get(g0, 'Posture Score')      ?? NET_KPI_FALLBACK.posture_score,
      total_findings:    get(g0, 'Total Findings')     ?? NET_KPI_FALLBACK.total_findings,
      critical:          get(g0, 'Critical')           ?? NET_KPI_FALLBACK.critical,
      high:              get(g0, 'High')               ?? NET_KPI_FALLBACK.high,
      medium:            get(g0, 'Medium')             ?? NET_KPI_FALLBACK.medium,
      low:               get(g0, 'Low')                ?? NET_KPI_FALLBACK.low,
      exposed_resources: get(g1, 'Exposed Resources')  ?? NET_KPI_FALLBACK.exposed_resources,
      internet_exposed:  get(g1, 'Internet Exposed')   ?? NET_KPI_FALLBACK.internet_exposed,
      open_sgs:          get(g1, 'Open SGs')           ?? NET_KPI_FALLBACK.open_sgs,
      waf_coverage:      get(g1, 'WAF Coverage')       ?? NET_KPI_FALLBACK.waf_coverage,
    };
  }, [data.kpiGroups]);

  // ── Active scan trend: live from BFF or static fallback ──────────────
  const activeScanTrend = useMemo(
    () => {
      if (data.scanTrend?.length >= 2) {
        // Normalise field names: engine returns pass_rate, chart expects passRate
        return data.scanTrend.map(d => ({ ...d, passRate: d.pass_rate ?? d.passRate ?? 0 }));
      }
      return NET_SCAN_TREND;
    },
    [data.scanTrend],
  );

  const activeModuleScores = useMemo(() => {
    const db = data.domainBreakdown;
    if (db?.length >= 3) {
      return db.map(d => {
        const meta = NET_DOMAIN_MAP[d.security_domain] ?? { label: d.security_domain, color: '#64748b' };
        return { module: meta.label, pass: d.pass_count ?? 0, total: d.total ?? 0, color: meta.color };
      });
    }
    return NET_MODULE_SCORES;
  }, [data.domainBreakdown]);

  // ── Insight strip ───────────────────────────────────────────────────────
  const insightStrip = useMemo(() => {
    const {
      posture_score, total_findings, critical, high, medium, low,
      exposed_resources, internet_exposed, open_sgs, waf_coverage,
    } = kpiNums;

    const scoreColor = posture_score >= 70 ? C.emerald
                     : posture_score >= 50 ? C.amber
                     : C.critical;

    // ── KPI tile — matches IAM / misconfig style ──
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

    // Live sparklines derived from scan trend
    const sparkPS  = activeScanTrend.map(d => d.passRate ?? d.pass_rate ?? 0);
    const sparkTF  = activeScanTrend.map(d => d.total             ?? 0);
    const sparkER  = activeScanTrend.map(d => d.exposed_resources ?? 0);
    const sparkWAF = activeScanTrend.map(d => d.waf_coverage      ?? 0);

    // ── Trend deltas ──
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

        {/* ── Row 1: 4 KPI tiles in a single horizontal row ── */}
        <div style={{
          flex: 1, display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: 8, minWidth: 0,
        }}>
          {tile('Posture Score',     posture_score,     scoreColor,  '/100', `${medium} medium · ${low} low risk`,            sparkPS, sparkPS[sparkPS.length - 1] - sparkPS[0], 'up'  )}
          {tile('Total Findings',    total_findings,    C.high,      '',     `${critical} critical · ${high} high`,            sparkTF, sparkTF[sparkTF.length - 1] - sparkTF[0], 'down')}
          {tile('Exposed Resources', exposed_resources, C.critical,  '',     `${internet_exposed} internet-exposed · ${open_sgs} open SGs`, sparkER,  sparkER[sparkER.length   - 1] - sparkER[0],  'down')}
          {tile('WAF Coverage',      `${waf_coverage}%`, C.amber,   '',     `${100 - waf_coverage}% resources unprotected`,  sparkWAF, sparkWAF[sparkWAF.length - 1] - sparkWAF[0], 'up'  )}
        </div>

        {/* ── Col 2: Findings by Severity donut + Module Scores ── */}
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
            Network exposure · severity breakdown
          </div>

          {/* Donut + progress-bar legend */}
          <div className="flex items-center gap-4" style={{ flex: 1 }}>
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <NetDonut slices={donutSlices} size={150} />
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

        {/* ── Col 3: Network Posture Trend (ComposedChart) ── */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)', minWidth: 0,
        }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', marginBottom: 8 }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                Network Posture Trend
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                {first.date} – {last.date} · {NET_SCAN_TREND.length} scans
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {[
                { label: 'Critical', color: C.critical },
                { label: 'High',     color: C.high     },
                { label: 'Medium',   color: C.medium   },
                { label: 'Pass Rate',color: C.emerald  },
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
            {statPill('Pass Rate',  `${last.passRate}%`, rateΔ,  'up'  )}
            {statPill('Critical',   last.critical,       critΔ,  'down')}
            {statPill('High',       last.high,           highΔ,  'down')}
            {statPill('Total',      last.total,          totalΔ, 'down')}
          </div>

          {/* Composed chart — fills remaining height */}
          <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
            <div style={{ position: 'absolute', inset: 0 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={activeScanTrend}
                  margin={{ top: 6, right: 10, left: -14, bottom: 0 }} barCategoryGap="28%">
                  <defs>
                    {[
                      { id: 'nc', color: C.critical },
                      { id: 'nh', color: C.high     },
                      { id: 'nm', color: C.medium   },
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
                  <Bar yAxisId="count" dataKey="medium"   name="Medium"   stackId="s" fill={`url(#nm)`} radius={[0,0,0,0]} />
                  <Bar yAxisId="count" dataKey="high"     name="High"     stackId="s" fill={`url(#nh)`} radius={[0,0,0,0]} />
                  <Bar yAxisId="count" dataKey="critical" name="Critical" stackId="s" fill={`url(#nc)`} radius={[3,3,0,0]} />
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
  const findingsColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    { accessorKey: 'rule_id',       header: 'Rule'     },
    {
      accessorKey: 'module', header: 'Module',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'severity',     header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    {
      accessorKey: 'status', header: 'Status',
      cell: (info) => {
        const v = info.getValue(), isFail = v === 'FAIL';
        return <span className={`text-xs px-2 py-0.5 rounded ${isFail ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{v}</span>;
      },
    },
    { accessorKey: 'account_id',   header: 'Account' },
    { accessorKey: 'region',       header: 'Region'  },
    { accessorKey: 'resource_type',header: 'Type'    },
  ];

  const sgColumns = [
    { accessorKey: 'group_name', header: 'Security Group' },
    { accessorKey: 'group_id',   header: 'Group ID'       },
    { accessorKey: 'vpc_id',     header: 'VPC'            },
    {
      accessorKey: 'open_to_internet', header: 'Open to Internet',
      cell: (info) => info.getValue()
        ? <AlertTriangle className="w-4 h-4 text-red-400" />
        : <CheckCircle   className="w-4 h-4 text-green-400" />,
    },
    { accessorKey: 'inbound_rules',  header: 'Inbound Rules'  },
    { accessorKey: 'outbound_rules', header: 'Outbound Rules' },
    { accessorKey: 'severity',       header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    { accessorKey: 'account_id',     header: 'Account' },
    { accessorKey: 'region',         header: 'Region'  },
  ];

  const exposureColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    { accessorKey: 'resource_type', header: 'Type'     },
    {
      accessorKey: 'exposure_type', header: 'Exposure',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400">
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'ports',     header: 'Ports'     },
    { accessorKey: 'protocols', header: 'Protocols' },
    { accessorKey: 'severity',  header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    { accessorKey: 'account_id',header: 'Account'  },
    { accessorKey: 'region',    header: 'Region'   },
  ];

  const topologyColumns = [
    { accessorKey: 'vpc_id',              header: 'VPC'      },
    { accessorKey: 'cidr_block',          header: 'CIDR'     },
    { accessorKey: 'subnets',             header: 'Subnets'  },
    { accessorKey: 'peering_connections', header: 'Peering'  },
    { accessorKey: 'transit_gateways',    header: 'TGW'      },
    { accessorKey: 'internet_gateways',   header: 'IGW'      },
    { accessorKey: 'nat_gateways',        header: 'NAT'      },
    { accessorKey: 'account_id',          header: 'Account'  },
    { accessorKey: 'region',              header: 'Region'   },
  ];

  const wafColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    {
      accessorKey: 'waf_enabled', header: 'WAF',
      cell: (info) => info.getValue()
        ? <CheckCircle   className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-red-400"   />,
    },
    {
      accessorKey: 'shield_enabled', header: 'Shield',
      cell: (info) => info.getValue()
        ? <CheckCircle   className="w-4 h-4 text-green-400"  />
        : <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    },
    { accessorKey: 'web_acl_name', header: 'Web ACL'  },
    { accessorKey: 'rule_count',   header: 'Rules'    },
    { accessorKey: 'severity',     header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    { accessorKey: 'account_id',   header: 'Account'  },
    { accessorKey: 'region',       header: 'Region'   },
  ];

  const tabData = useMemo(() => ({
    overview:         { data: findings,         columns: findingsColumns  },
    findings:         { data: findings,         columns: findingsColumns  },
    security_groups:  { data: securityGroups,   columns: sgColumns        },
    internet_exposure:{ data: internetExposure, columns: exposureColumns  },
    topology:         { data: topology,         columns: topologyColumns  },
    waf:              { data: waf,              columns: wafColumns        },
  }), [findings, securityGroups, internetExposure, topology, waf]);

  const pageContext = data.pageContext || {
    title: 'Network Security',
    brief: 'Network exposure, security group misconfigurations, and internet-facing resource risk across all connected accounts.',
    tabs: [
      { id: 'overview',          label: 'Overview',          count: findings.length          },
      { id: 'security_groups',   label: 'Security Groups',   count: securityGroups.length    },
      { id: 'internet_exposure', label: 'Internet Exposure', count: internetExposure.length  },
      { id: 'topology',          label: 'VPC Topology',      count: topology.length          },
      { id: 'waf',               label: 'WAF / DDoS',        count: waf.length               },
    ],
  };

  return (
    <div className="space-y-5">

      {/* ── Heading ── */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Network className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
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

      {/* ── Tabs + table ── */}
      <PageLayout
        icon={Network}
        pageContext={pageContext}
        kpiGroups={[]}
        insightRow={insightStrip}
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
