import Link from 'next/link';
import {
  Shield,
  Zap,
  Eye,
  AlertTriangle,
  CheckCircle,
  ArrowRight,
  Cloud,
  Lock,
  Database,
  Code2,
  Globe,
  BarChart3,
  ChevronRight,
  Play,
  Activity,
  Layers,
  Search,
  Bell,
  Target,
  GitBranch,
  Server,
  FileText,
  TrendingUp,
  Users,
  Clock,
  Star,
} from 'lucide-react';

// ─── Data ──────────────────────────────────────────────────────────────────

const HERO_STATS = [
  { value: '3,900+', label: 'Findings Detected', color: '#2563eb' },
  { value: '40+',    label: 'Cloud Services',    color: '#7c3aed' },
  { value: '13+',    label: 'Frameworks',         color: '#059669' },
  { value: '99.7%',  label: 'Accuracy',           color: '#0891b2' },
];

const TRUSTED_COMPANIES = [
  'Meridian Health', 'Nexus Capital', 'Stratus Financial',
  'Vertex Technologies', 'Harbor Insurance', 'Pinnacle Energy',
  'Summit Retail', 'Keystone Bank',
];

const PAIN_POINTS = [
  {
    icon: Bell,
    title: 'Reactive, not proactive',
    body: 'Traditional tools alert you after the breach. By then, lateral movement has already begun and the blast radius is expanding.',
    color: '#dc2626',
    panelBg: '#0f0505',
    panelLabel: 'BREACH TIMELINE',
    panelGlow: '#dc2626',
    panelRows: [
      { label: 'Misconfiguration introduced', value: 'Day 0', color: '#64748b' },
      { label: 'First detected by CSPM tool', value: 'Day 11', color: '#f97316' },
      { label: 'Breach contained', value: 'Day 23', color: '#ef4444' },
      { label: 'Average total cost', value: '$4.2M', color: '#ef4444' },
    ],
  },
  {
    icon: Layers,
    title: 'Fragmented visibility',
    body: 'Security teams juggle five or more consoles across AWS, Azure, GCP, and beyond — with no unified context across accounts and regions.',
    color: '#ea580c',
    panelBg: '#0f0800',
    panelLabel: 'ACTIVE TOOL SPRAWL',
    panelGlow: '#ea580c',
    panelRows: [
      { label: 'AWS Security Hub', value: '2,841 findings', color: '#94a3b8' },
      { label: 'Azure Security Center', value: '1,209 findings', color: '#94a3b8' },
      { label: 'GCP Security Command', value: '673 findings', color: '#94a3b8' },
      { label: 'Prisma Cloud + Splunk', value: 'Context lost', color: '#ef4444' },
    ],
  },
  {
    icon: AlertTriangle,
    title: 'Crushing alert fatigue',
    body: 'Hundreds of raw findings with no prioritization. Engineers burn out chasing ghost signals while real threats slip through undetected.',
    color: '#ca8a04',
    panelBg: '#0a0900',
    panelLabel: 'SIGNAL ANALYSIS',
    panelGlow: '#ca8a04',
    panelRows: [
      { label: 'Total alerts per week', value: '4,720', color: '#94a3b8' },
      { label: 'Actionable / real threats', value: '283 (6%)', color: '#22c55e' },
      { label: 'False positives / noise', value: '4,437 (94%)', color: '#ef4444' },
      { label: 'Avg engineer burnout rate', value: '68%', color: '#f97316' },
    ],
  },
];

const HOW_IT_WORKS = [
  {
    step: '01',
    icon: Cloud,
    title: 'Connect',
    subtitle: '30-second onboarding',
    body: 'Link your cloud accounts via read-only IAM roles across AWS, Azure, GCP, OCI, AliCloud, and IBM Cloud. No agents, no code changes, no downtime.',
    color: '#2563eb',
  },
  {
    step: '02',
    icon: Search,
    title: 'Scan',
    subtitle: 'Continuous assessment',
    body: 'Threat Engine enumerates 40+ cloud services, evaluates every resource against 200+ security rules, and maps misconfigurations to MITRE ATT&CK techniques in real time.',
    color: '#7c3aed',
  },
  {
    step: '03',
    icon: Target,
    title: 'Act',
    subtitle: 'Prioritized remediation',
    body: 'Attack-chain context collapses thousands of alerts into a ranked worklist. Each finding ships with one-click remediation guidance and compliance evidence for auditors.',
    color: '#059669',
  },
];

const CAPABILITIES = [
  {
    icon: Shield,
    title: 'Threat Detection',
    badge: 'MITRE ATT&CK',
    badgeColor: '#dc2626',
    body: 'Map every misconfiguration to MITRE ATT&CK cloud techniques. Visualize multi-stage attack chains before adversaries exploit them.',
    color: '#dc2626',
    panelBg: '#0f0505',
    panelLabel: 'THREAT SCAN · LIVE',
    panelStats: [{ v: '12', l: 'Critical' }, { v: '43', l: 'High' }, { v: '3', l: 'Chains' }],
    panelRow: { id: 'TE-001', text: 'S3 → EC2 → ExternalDNS lateral move', sev: 'CRITICAL', color: '#ef4444' },
  },
  {
    icon: Lock,
    title: 'IAM Security',
    badge: '57 Rules',
    badgeColor: '#2563eb',
    body: 'Analyze least-privilege posture across all identities, roles, and policies. Surface overly permissive access paths attackers love most.',
    color: '#2563eb',
    panelBg: '#02050f',
    panelLabel: 'IAM POSTURE · SCAN',
    panelStats: [{ v: '825', l: 'Findings' }, { v: '57', l: 'Rules' }, { v: '14', l: 'No-MFA' }],
    panelRow: { id: 'IAM-042', text: 'Lambda role has AdministratorAccess (*:*)', sev: 'HIGH', color: '#f97316' },
  },
  {
    icon: FileText,
    title: 'Compliance',
    badge: '13+ Frameworks',
    badgeColor: '#059669',
    body: 'Continuous compliance scoring for CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, and SOC 2 — audit-ready evidence at any moment.',
    color: '#059669',
    panelBg: '#010f06',
    panelLabel: 'COMPLIANCE REPORT',
    panelStats: [{ v: '89%', l: 'CIS Score' }, { v: '92%', l: 'NIST' }, { v: '83%', l: 'PCI-DSS' }],
    panelRow: { id: 'CIS-2.1', text: 'S3 Block Public Access not enabled', sev: 'FAIL', color: '#ef4444' },
  },
  {
    icon: Database,
    title: 'Asset Inventory',
    badge: '40+ Services',
    badgeColor: '#0891b2',
    body: 'Complete graph of every cloud asset and its relationships. Detect configuration drift, orphaned resources, and shadow IT across all accounts.',
    color: '#0891b2',
    panelBg: '#01080f',
    panelLabel: 'INVENTORY · LIVE',
    panelStats: [{ v: '18.3K', l: 'Resources' }, { v: '47.2K', l: 'Edges' }, { v: '+4', l: 'Drift' }],
    panelRow: { id: 'DRF-019', text: 'Port 22 opened to 0.0.0.0/0 — 3 changes', sev: 'CRITICAL', color: '#ef4444' },
  },
  {
    icon: Code2,
    title: 'Code Security',
    badge: '14 Languages',
    badgeColor: '#7c3aed',
    body: 'Scan Terraform, CloudFormation, Kubernetes, Helm, Ansible, and 9 more IaC languages. Catch misconfigurations before they reach production.',
    color: '#7c3aed',
    panelBg: '#07030f',
    panelLabel: 'IAC SCAN · PR #247',
    panelStats: [{ v: '3', l: 'Findings' }, { v: '500+', l: 'Rules' }, { v: '<30s', l: 'Scan' }],
    panelRow: { id: 'TE-S3-001', text: 'acl = "public-read" — Public ACL detected', sev: 'HIGH', color: '#f97316' },
  },
  {
    icon: Eye,
    title: 'Data Security',
    badge: '62 Rules',
    badgeColor: '#ea580c',
    body: 'Classify sensitive data stores, detect public exposure, and monitor encryption posture across S3, RDS, DynamoDB, and 30+ storage services.',
    color: '#ea580c',
    panelBg: '#0f0600',
    panelLabel: 'DATA EXPOSURE SCAN',
    panelStats: [{ v: '142', l: 'S3' }, { v: '28', l: 'RDS' }, { v: '3', l: 'PUBLIC' }],
    panelRow: { id: 'DS-031', text: 's3://prod-customer-exports — PUBLIC', sev: 'CRITICAL', color: '#ef4444' },
  },
];

const BIG_STATS = [
  { value: '3,900+', label: 'Security findings analyzed',        color: '#2563eb' },
  { value: '40+',    label: 'Cloud services enumerated',         color: '#7c3aed' },
  { value: '13+',    label: 'Compliance frameworks supported',   color: '#059669' },
  { value: '6',      label: 'Cloud providers in one platform',   color: '#0891b2' },
];

const CLOUDS = [
  { name: 'AWS',       color: '#FF9900', services: 18, resources: '12,450', findings: 1840 },
  { name: 'Azure',     color: '#0078D4', services: 9,  resources: '5,210',  findings: 743  },
  { name: 'GCP',       color: '#4285F4', services: 7,  resources: '1,890',  findings: 312  },
  { name: 'OCI',       color: '#C74634', services: 4,  resources: '540',    findings: 89   },
  { name: 'AliCloud',  color: '#FF6A00', services: 3,  resources: '210',    findings: 41   },
  { name: 'IBM Cloud', color: '#1F70C1', services: 2,  resources: '90',     findings: 18   },
];

const FRAMEWORKS = [
  { name: 'CIS',       color: '#2563eb' },
  { name: 'NIST',      color: '#7c3aed' },
  { name: 'ISO 27001', color: '#059669' },
  { name: 'PCI-DSS',   color: '#0891b2' },
  { name: 'HIPAA',     color: '#ea580c' },
  { name: 'GDPR',      color: '#db2777' },
  { name: 'SOC 2',     color: '#9333ea' },
];

const TESTIMONIALS = [
  {
    quote: 'Threat Engine collapsed our mean-time-to-detect from 11 days to under 4 hours. The attack-chain view alone saved us during a live incident — we knew exactly which lateral paths the attacker had available before they took them.',
    name: 'Sarah Chen',
    title: 'VP of Security Engineering',
    company: 'Nexora Financial',
    tag: 'AWS · Azure',
    tagColor: '#2563eb',
    initials: 'SC',
    avatarGrad: 'linear-gradient(135deg,#2563eb,#7c3aed)',
    stars: 5,
  },
  {
    quote: 'HIPAA compliance used to mean weeks of manual evidence collection before every audit. Now our posture score updates in real time and we export audit-ready reports in one click. Our last SOC 2 audit was the smoothest in company history.',
    name: 'Marcus Okonkwo',
    title: 'Chief Information Security Officer',
    company: 'Arclite Health',
    tag: 'AWS · GCP',
    tagColor: '#059669',
    initials: 'MO',
    avatarGrad: 'linear-gradient(135deg,#059669,#0891b2)',
    stars: 5,
  },
  {
    quote: 'We manage 10,000+ cloud resources across four regions and three providers. Threat Engine gave us a single pane of glass that our previous five-tool stack never could. Alert fatigue dropped 80% in the first month — my team finally sleeps.',
    name: 'Priya Nair',
    title: 'Director of Cloud Security',
    company: 'Vantis Logistics',
    tag: 'AWS · Azure · GCP',
    tagColor: '#7c3aed',
    initials: 'PN',
    avatarGrad: 'linear-gradient(135deg,#7c3aed,#db2777)',
    stars: 5,
  },
];

const BLOG_POSTS = [
  {
    slug: 'cloud-misconfiguration-attack-vector-2026',
    category: 'Threat Intelligence',
    categoryColor: '#dc2626',
    title: 'Cloud Misconfiguration: The #1 Attack Vector in 2026',
    excerpt: 'Over 82% of cloud breaches in 2025 originated from a misconfiguration that was detectable weeks before the incident. Here is what defenders need to know.',
    date: 'March 4, 2026',
    readTime: '8 min read',
    icon: AlertTriangle,
    panelBg: '#0f0505',
    panelLabel: 'THREAT SCAN',
    panelGlow: '#dc2626',
    panelStat: '3,900+ findings',
    panelFindingId: 'TE-001',
    panelFindingText: 'Public S3 bucket — sensitive data exposed',
    panelFindingSev: 'CRITICAL',
    panelFindingColor: '#ef4444',
  },
  {
    slug: 'mitre-attack-cloud-mapping-attack-chains',
    category: 'Detection Engineering',
    categoryColor: '#7c3aed',
    title: 'MITRE ATT&CK for Cloud: Mapping Attack Chains',
    excerpt: 'A practical walkthrough of how adversaries chain Initial Access through Persistence, Lateral Movement, and Exfiltration — and how to detect each technique.',
    date: 'February 25, 2026',
    readTime: '11 min read',
    icon: Target,
    panelBg: '#07030f',
    panelLabel: 'ATT&CK MATRIX',
    panelGlow: '#7c3aed',
    panelStat: '193 techniques',
    panelFindingId: 'TA0005',
    panelFindingText: 'Defense Evasion — Impair Logging (T1562)',
    panelFindingSev: 'CRITICAL',
    panelFindingColor: '#ef4444',
  },
  {
    slug: 'cis-benchmarks-cloud-definitive-guide-2026',
    category: 'Compliance',
    categoryColor: '#059669',
    title: 'CIS Benchmarks for Cloud: The Definitive Guide 2026',
    excerpt: 'Everything you need to automate CIS Level 1 and Level 2 benchmarks across AWS, Azure, and GCP — with continuous evidence collection for auditors.',
    date: 'February 18, 2026',
    readTime: '14 min read',
    icon: FileText,
    panelBg: '#010f06',
    panelLabel: 'COMPLIANCE SCAN',
    panelGlow: '#059669',
    panelStat: '89% CIS score',
    panelFindingId: 'CIS-2.1',
    panelFindingText: 'S3 Block Public Access not enabled',
    panelFindingSev: 'FAIL',
    panelFindingColor: '#ef4444',
  },
];

// ─── Dot pattern SVG background ────────────────────────────────────────────

function DotPattern() {
  return (
    <svg
      aria-hidden="true"
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        opacity: 0.4,
      }}
    >
      <defs>
        <pattern id="dots" x="0" y="0" width="32" height="32" patternUnits="userSpaceOnUse">
          <circle cx="1.5" cy="1.5" r="1.5" fill="rgba(37,99,235,0.3)" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#dots)" />
    </svg>
  );
}

// ─── Floating Stat Card ─────────────────────────────────────────────────────

function HeroStatCard({ stat, delay, style }) {
  return (
    <div
      className="animate-float"
      style={{
        borderRadius: 16,
        padding: '16px 22px',
        minWidth: 148,
        animationDelay: delay,
        background: '#ffffff',
        border: '1px solid #e2e8f0',
        boxShadow: '0 4px 20px rgba(15,23,42,0.08)',
        ...style,
      }}
    >
      <div style={{ fontSize: 28, fontWeight: 800, color: stat.color, lineHeight: 1 }}>
        {stat.value}
      </div>
      <div style={{ fontSize: 13, color: '#64748b', marginTop: 4, fontWeight: 500 }}>
        {stat.label}
      </div>
    </div>
  );
}

// ─── Dashboard Mockup ────────────────────────────────────────────────────────

const MOCK_FINDINGS = [
  { title: 'S3 Bucket Public Access Enabled',   resource: 'prod-assets-bucket',  sev: 'CRITICAL', color: '#ef4444' },
  { title: 'IAM Wildcard Permissions (*)',        resource: 'arn:aws:iam::admin',  sev: 'HIGH',     color: '#f97316' },
  { title: 'RDS Instance Publicly Accessible',   resource: 'prod-mysql-primary',  sev: 'CRITICAL', color: '#ef4444' },
  { title: 'MFA Not Enforced on Root Account',  resource: 'account/root',        sev: 'HIGH',     color: '#f97316' },
  { title: 'Security Group Unrestricted SSH',    resource: 'sg-web-0a3f1d',      sev: 'MEDIUM',   color: '#eab308' },
];

const SEV_COUNTS = [
  { label: 'Critical', count: 12,  color: '#ef4444', bg: '#fef2f2', border: '#fecaca' },
  { label: 'High',     count: 43,  color: '#f97316', bg: '#fff7ed', border: '#fed7aa' },
  { label: 'Medium',   count: 167, color: '#eab308', bg: '#fefce8', border: '#fef08a' },
  { label: 'Low',      count: 891, color: '#3b82f6', bg: '#eff6ff', border: '#bfdbfe' },
];

function DashboardMockup() {
  return (
    <div style={{ position: 'relative' }}>
      {/* Background depth card */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          top: 18,
          right: -18,
          width: '92%',
          height: '95%',
          background: 'linear-gradient(135deg, #eff6ff, #f5f3ff)',
          borderRadius: 16,
          border: '1px solid #bfdbfe',
          zIndex: 0,
        }}
      />

      {/* Main card */}
      <div
        style={{
          position: 'relative',
          zIndex: 1,
          borderRadius: 16,
          overflow: 'hidden',
          boxShadow: '0 24px 64px rgba(15,23,42,0.18), 0 4px 16px rgba(15,23,42,0.08)',
          border: '1px solid #e2e8f0',
          background: '#ffffff',
        }}
      >
        {/* Browser chrome */}
        <div
          style={{
            height: 44,
            background: '#1e293b',
            display: 'flex',
            alignItems: 'center',
            padding: '0 16px',
            gap: 8,
            borderBottom: '1px solid #0f172a',
          }}
        >
          <div style={{ display: 'flex', gap: 6 }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }} />
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#f59e0b' }} />
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#22c55e' }} />
          </div>
          <div
            style={{
              flex: 1,
              marginLeft: 8,
              height: 26,
              borderRadius: 6,
              background: '#0f172a',
              display: 'flex',
              alignItems: 'center',
              padding: '0 12px',
              gap: 6,
            }}
          >
            <Lock size={9} color="#4ade80" />
            <span style={{ fontSize: 10, color: '#94a3b8', fontFamily: 'monospace' }}>
              app.threatengine.io/dashboard
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginLeft: 8, flexShrink: 0 }}>
            <div
              className="animate-pulse-glow"
              style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e' }}
            />
            <span style={{ fontSize: 10, color: '#22c55e', fontWeight: 700 }}>LIVE</span>
          </div>
        </div>

        {/* Dashboard body */}
        <div style={{ background: '#f8fafc', padding: 16 }}>

          {/* Score + severity row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 12, marginBottom: 12 }}>

            {/* Risk score */}
            <div
              style={{
                background: '#ffffff',
                borderRadius: 12,
                padding: '14px 18px',
                border: '1px solid #e2e8f0',
                textAlign: 'center',
                minWidth: 108,
              }}
            >
              <div
                style={{
                  fontSize: 9,
                  color: '#64748b',
                  fontWeight: 700,
                  letterSpacing: '0.08em',
                  marginBottom: 8,
                  textTransform: 'uppercase',
                }}
              >
                Risk Score
              </div>
              <div style={{ fontSize: 38, fontWeight: 900, color: '#0f172a', lineHeight: 1 }}>82</div>
              <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 10 }}>/100</div>
              <div style={{ height: 5, background: '#e2e8f0', borderRadius: 3 }}>
                <div
                  style={{
                    width: '82%',
                    height: '100%',
                    background: 'linear-gradient(90deg, #2563eb, #059669)',
                    borderRadius: 3,
                  }}
                />
              </div>
              <div style={{ fontSize: 9, color: '#059669', marginTop: 6, fontWeight: 700 }}>▲ +12 pts</div>
            </div>

            {/* Severity counts */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
              {SEV_COUNTS.map(({ label, count, color, bg, border }) => (
                <div
                  key={label}
                  style={{
                    background: bg,
                    border: `1px solid ${border}`,
                    borderRadius: 10,
                    padding: '10px 4px',
                    textAlign: 'center',
                  }}
                >
                  <div style={{ fontSize: 22, fontWeight: 900, color, lineHeight: 1 }}>{count}</div>
                  <div
                    style={{
                      fontSize: 9,
                      color: '#64748b',
                      fontWeight: 700,
                      marginTop: 4,
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                    }}
                  >
                    {label}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Findings table */}
          <div
            style={{
              background: '#ffffff',
              borderRadius: 12,
              border: '1px solid #e2e8f0',
              overflow: 'hidden',
              marginBottom: 12,
            }}
          >
            {/* Table header */}
            <div
              style={{
                padding: '9px 14px',
                background: '#f1f5f9',
                borderBottom: '1px solid #e2e8f0',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <AlertTriangle size={11} color="#f97316" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#0f172a' }}>Active Findings</span>
                <span
                  style={{
                    padding: '1px 7px',
                    background: '#fef2f2',
                    color: '#ef4444',
                    border: '1px solid #fecaca',
                    borderRadius: 999,
                    fontSize: 9,
                    fontWeight: 800,
                  }}
                >
                  55
                </span>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                {['AWS', 'Azure', 'GCP'].map((p) => (
                  <span
                    key={p}
                    style={{
                      padding: '2px 7px',
                      background: '#eff6ff',
                      color: '#2563eb',
                      border: '1px solid #bfdbfe',
                      borderRadius: 4,
                      fontSize: 9,
                      fontWeight: 700,
                    }}
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>

            {/* Finding rows */}
            {MOCK_FINDINGS.map(({ title, resource, sev, color }, i) => (
              <div
                key={title}
                style={{
                  padding: '9px 14px',
                  borderBottom: i < MOCK_FINDINGS.length - 1 ? '1px solid #f8fafc' : 'none',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                }}
              >
                <div
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: '50%',
                    background: color,
                    flexShrink: 0,
                  }}
                />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 11,
                      fontWeight: 600,
                      color: '#1e293b',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {title}
                  </div>
                  <div style={{ fontSize: 9, color: '#94a3b8', fontFamily: 'monospace' }}>{resource}</div>
                </div>
                <div
                  style={{
                    padding: '2px 7px',
                    background: `${color}18`,
                    color,
                    border: `1px solid ${color}35`,
                    borderRadius: 4,
                    fontSize: 9,
                    fontWeight: 800,
                    flexShrink: 0,
                  }}
                >
                  {sev}
                </div>
              </div>
            ))}
          </div>

          {/* MITRE ATT&CK tags */}
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 9, color: '#64748b', fontWeight: 700, letterSpacing: '0.06em' }}>
              MITRE ATT&amp;CK:
            </span>
            {[
              { id: 'T1530', name: 'Cloud Storage Object' },
              { id: 'T1078', name: 'Valid Accounts' },
              { id: 'T1190', name: 'Exploit Public App' },
            ].map(({ id, name }) => (
              <span
                key={id}
                style={{
                  padding: '2px 8px',
                  background: '#f5f3ff',
                  color: '#7c3aed',
                  border: '1px solid #ddd6fe',
                  borderRadius: 4,
                  fontSize: 9,
                  fontWeight: 700,
                  whiteSpace: 'nowrap',
                }}
              >
                {id} · {name}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function HomePage() {
  return (
    <main style={{ background: '#ffffff', color: '#0f172a', overflowX: 'hidden' }}>

      {/* ── 1. HERO ─────────────────────────────────────────────────────── */}
      <section
        className="hero-bg"
        style={{
          position: 'relative',
          paddingTop: 112,
          paddingBottom: 96,
          overflow: 'hidden',
        }}
      >
        <DotPattern />

        {/* Animated ring — subtle background depth */}
        <div
          className="animate-spin-slow"
          aria-hidden="true"
          style={{
            position: 'absolute',
            top: '50%',
            left: '30%',
            transform: 'translate(-50%, -50%)',
            width: 600,
            height: 600,
            borderRadius: '50%',
            border: '1px solid rgba(37,99,235,0.08)',
            pointerEvents: 'none',
          }}
        />

        {/* Content split */}
        <div className="container" style={{ position: 'relative' }}>
          <div className="hero-split">

            {/* LEFT: Text + CTAs + stats */}
            <div className="hero-split-text">
              {/* Badge */}
              <div style={{ marginBottom: 24 }}>
                <span className="badge badge-blue">
                  <Activity size={11} />
                  Enterprise CSPM Platform
                </span>
              </div>

              {/* Headline */}
              <h1
                style={{
                  fontSize: 'clamp(36px, 5vw, 68px)',
                  fontWeight: 900,
                  lineHeight: 1.07,
                  letterSpacing: '-0.03em',
                  marginBottom: 24,
                  color: '#0f172a',
                }}
              >
                Stop Cloud Breaches{' '}
                <span className="gradient-text">Before They Start</span>
              </h1>

              {/* Sub-headline */}
              <p
                style={{
                  fontSize: 'clamp(16px, 1.8vw, 20px)',
                  color: '#475569',
                  maxWidth: 520,
                  marginBottom: 40,
                  lineHeight: 1.7,
                }}
              >
                Unified, continuous visibility across every cloud — with attack-chain
                context, AI risk scoring, and one-click remediation that actually ships.
              </p>

              {/* CTAs */}
              <div
                className="hero-cta-row"
                style={{
                  display: 'flex',
                  gap: 14,
                  flexWrap: 'wrap',
                  marginBottom: 52,
                }}
              >
                <Link href="/contact" className="btn-primary" style={{ fontSize: 16, padding: '14px 32px' }}>
                  Request Demo <ArrowRight size={18} />
                </Link>
                <Link href="/platform" className="btn-secondary" style={{ fontSize: 16, padding: '14px 32px' }}>
                  <Play size={16} /> See Platform
                </Link>
              </div>

              {/* Floating stat cards */}
              <div
                className="hero-stat-row"
                style={{
                  display: 'flex',
                  gap: 14,
                  flexWrap: 'wrap',
                }}
              >
                {HERO_STATS.map((stat, i) => (
                  <HeroStatCard
                    key={stat.label}
                    stat={stat}
                    delay={`${i * 0.4}s`}
                  />
                ))}
              </div>
            </div>

            {/* RIGHT: Product dashboard mockup (desktop only) */}
            <div className="hero-split-mock">
              <DashboardMockup />
            </div>
          </div>
        </div>

        {/* Bottom fade */}
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            right: 0,
            height: 80,
            background: 'linear-gradient(to bottom, transparent, #ffffff)',
            pointerEvents: 'none',
          }}
        />
      </section>

      {/* ── 2. TRUSTED BY ───────────────────────────────────────────────── */}
      <section style={{ padding: '40px 0 56px', borderTop: '1px solid #e2e8f0', borderBottom: '1px solid #e2e8f0', background: '#f8fafc' }}>
        <div className="container">
          <p
            style={{
              textAlign: 'center',
              fontSize: 13,
              fontWeight: 600,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: '#94a3b8',
              marginBottom: 28,
            }}
          >
            Trusted by security teams at
          </p>
          <div
            style={{
              display: 'flex',
              gap: 12,
              justifyContent: 'center',
              flexWrap: 'wrap',
              alignItems: 'center',
            }}
          >
            {TRUSTED_COMPANIES.map((name) => (
              <div
                key={name}
                style={{
                  padding: '8px 20px',
                  borderRadius: 8,
                  background: '#ffffff',
                  border: '1px solid #e2e8f0',
                  color: '#475569',
                  fontSize: 14,
                  fontWeight: 600,
                  letterSpacing: '0.02em',
                  transition: 'all 0.2s',
                  boxShadow: '0 1px 4px rgba(15,23,42,0.05)',
                }}
              >
                {name}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── 3. PROBLEM / SOLUTION ────────────────────────────────────────── */}
      <section className="section">
        <div className="container">
          {/* Problem */}
          <div style={{ textAlign: 'center', marginBottom: 64 }}>
            <span className="badge badge-blue" style={{ marginBottom: 20 }}>
              <AlertTriangle size={11} /> The Problem
            </span>
            <h2
              style={{
                fontSize: 'clamp(28px, 4vw, 52px)',
                fontWeight: 800,
                lineHeight: 1.15,
                letterSpacing: '-0.025em',
                maxWidth: 680,
                margin: '0 auto 20px',
                color: '#0f172a',
              }}
            >
              Cloud security is broken.{' '}
              <span className="gradient-text">Here&apos;s why.</span>
            </h2>
            <p style={{ color: '#475569', fontSize: 18, maxWidth: 520, margin: '0 auto' }}>
              Legacy CSPM tools generate noise. They were built for a simpler era.
              The modern threat surface demands something far more intelligent.
            </p>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
              gap: 24,
              marginBottom: 72,
            }}
          >
            {PAIN_POINTS.map(({ icon: Icon, title, body, color, panelBg, panelLabel, panelGlow, panelRows }) => (
              <div
                key={title}
                className="card-hover"
                style={{
                  background: '#ffffff',
                  borderRadius: 16,
                  border: `1px solid ${color}20`,
                  overflow: 'hidden',
                  boxShadow: '0 4px 20px rgba(15,23,42,0.07)',
                }}
              >
                {/* Dark data panel */}
                <div style={{ background: panelBg }}>
                  <div
                    className="flex items-center gap-2 px-4 py-2"
                    style={{ borderBottom: `1px solid ${panelGlow}25`, background: `${panelGlow}08` }}
                  >
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: panelGlow, boxShadow: `0 0 5px ${panelGlow}`, flexShrink: 0, display: 'inline-block' }} />
                    <span style={{ color: panelGlow, fontSize: '9px', fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace' }}>
                      {panelLabel}
                    </span>
                    <span style={{ marginLeft: 'auto', width: 7, height: 7, borderRadius: '50%', background: '#ef4444', opacity: 0.7, flexShrink: 0, display: 'inline-block' }} />
                  </div>
                  {panelRows.map((row) => (
                    <div
                      key={row.label}
                      className="flex items-center justify-between px-4 py-2"
                      style={{ borderBottom: `1px solid ${panelGlow}15` }}
                    >
                      <span style={{ color: '#475569', fontSize: '10px' }}>{row.label}</span>
                      <span style={{ color: row.color, fontSize: '10px', fontWeight: 700, fontFamily: 'monospace' }}>{row.value}</span>
                    </div>
                  ))}
                </div>

                {/* Card content */}
                <div style={{ padding: 28 }}>
                  <div className="flex items-center gap-3" style={{ marginBottom: 16 }}>
                    <div
                      style={{
                        width: 40, height: 40, borderRadius: 10,
                        background: `${color}10`, border: `1px solid ${color}25`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                      }}
                    >
                      <Icon size={20} color={color} />
                    </div>
                    <h3 style={{ fontSize: 17, fontWeight: 700, color: '#0f172a', lineHeight: 1.3 }}>
                      {title}
                    </h3>
                  </div>
                  <p style={{ color: '#475569', lineHeight: 1.7, fontSize: 14 }}>{body}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Solution callout */}
          <div
            className="gradient-border"
            style={{
              borderRadius: 20,
              background: 'linear-gradient(135deg, rgba(37,99,235,0.04) 0%, rgba(124,58,237,0.04) 50%, rgba(8,145,178,0.04) 100%)',
              padding: '48px 40px',
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: 48,
              alignItems: 'center',
              border: '1px solid #e2e8f0',
            }}
          >
            <div>
              <span className="badge badge-green" style={{ marginBottom: 20 }}>
                <CheckCircle size={11} /> The Solution
              </span>
              <h3
                style={{
                  fontSize: 'clamp(22px, 3vw, 36px)',
                  fontWeight: 800,
                  lineHeight: 1.2,
                  marginBottom: 16,
                  letterSpacing: '-0.02em',
                  color: '#0f172a',
                }}
              >
                Threat Engine sees the{' '}
                <span className="gradient-text-green">full attack story</span>
              </h3>
              <p style={{ color: '#475569', lineHeight: 1.75, fontSize: 16, marginBottom: 28 }}>
                Instead of flooding you with raw findings, Threat Engine correlates misconfigurations
                into attack chains, scores risk with full business context, and hands your team
                a ranked worklist — not a spreadsheet.
              </p>
              <Link href="/platform" className="btn-primary">
                Explore the Platform <ArrowRight size={16} />
              </Link>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {[
                { label: 'Proactive attack-chain detection',        icon: Shield,      color: '#059669' },
                { label: 'Unified view across 6 cloud providers',   icon: Globe,       color: '#2563eb' },
                { label: 'Risk-ranked findings — zero noise',       icon: BarChart3,   color: '#7c3aed' },
                { label: 'One-click remediation + audit evidence',  icon: CheckCircle, color: '#0891b2' },
                { label: 'Continuous compliance scoring',           icon: FileText,    color: '#ea580c' },
              ].map(({ label, icon: Icon, color }) => (
                <div
                  key={label}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 14,
                    padding: '14px 18px',
                    borderRadius: 12,
                    background: '#f8fafc',
                    border: '1px solid #e2e8f0',
                  }}
                >
                  <div
                    style={{
                      width: 34,
                      height: 34,
                      borderRadius: 8,
                      background: `${color}12`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    <Icon size={16} color={color} />
                  </div>
                  <span style={{ fontSize: 14, fontWeight: 500, color: '#1e293b' }}>{label}</span>
                  <CheckCircle size={14} color="#059669" style={{ marginLeft: 'auto', flexShrink: 0 }} />
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── 4. HOW IT WORKS ─────────────────────────────────────────────── */}
      <section
        className="section grid-bg"
        style={{ background: '#f8fafc', borderTop: '1px solid #e2e8f0', borderBottom: '1px solid #e2e8f0' }}
      >
        <div className="container">
          <div style={{ textAlign: 'center', marginBottom: 72 }}>
            <span className="badge badge-purple" style={{ marginBottom: 20 }}>
              <Zap size={11} /> How It Works
            </span>
            <h2
              style={{
                fontSize: 'clamp(28px, 4vw, 48px)',
                fontWeight: 800,
                letterSpacing: '-0.025em',
                lineHeight: 1.15,
                color: '#0f172a',
                marginBottom: 16,
              }}
            >
              From zero to protected in{' '}
              <span className="gradient-text">minutes</span>
            </h2>
            <p style={{ color: '#475569', fontSize: 17, maxWidth: 480, margin: '0 auto' }}>
              No agents. No code changes. No downtime. Just connect, scan, and act.
            </p>
          </div>

          {/* Step cards with connector arrows */}
          <div style={{ position: 'relative' }}>
            {/* Connector line (desktop only) */}
            <div
              aria-hidden="true"
              style={{
                position: 'absolute',
                top: 68,
                left: '16.5%',
                right: '16.5%',
                height: 2,
                background: 'linear-gradient(90deg, #2563eb40, #7c3aed40, #05966940)',
                zIndex: 0,
              }}
            />

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: 32,
                position: 'relative',
                zIndex: 1,
              }}
            >
              {HOW_IT_WORKS.map(({ step, icon: Icon, title, subtitle, body, color }, idx) => {
                const metrics = [
                  { value: '30 sec', label: 'to connect first account' },
                  { value: '40+',    label: 'cloud services enumerated' },
                  { value: '1-click', label: 'remediation guidance' },
                ];
                const snippets = [
                  [
                    { text: '✓ AWS account linked', color: '#059669' },
                    { text: '✓ IAM read-only role created', color: '#059669' },
                    { text: '✓ 3 regions discovered', color: '#2563eb' },
                  ],
                  [
                    { text: '⊙ Scanning 18,342 resources…', color: '#7c3aed' },
                    { text: '⊙ Evaluating 200+ rules', color: '#7c3aed' },
                    { text: '⊙ Mapping MITRE ATT&CK', color: '#0891b2' },
                  ],
                  [
                    { text: '↑ 12 Critical — remediate now', color: '#ef4444' },
                    { text: '↑ 43 High — 3 attack chains', color: '#f97316' },
                    { text: '✓ Export SOC 2 evidence', color: '#059669' },
                  ],
                ];
                return (
                  <div
                    key={step}
                    className="card-hover"
                    style={{
                      background: '#ffffff',
                      border: `1px solid ${color}20`,
                      borderRadius: 20,
                      overflow: 'hidden',
                      boxShadow: '0 4px 20px rgba(15,23,42,0.07)',
                      display: 'flex',
                      flexDirection: 'column',
                    }}
                  >
                    {/* Colored top stripe */}
                    <div style={{ height: 3, background: `linear-gradient(90deg, ${color}, ${color}60)` }} />

                    <div style={{ padding: 32, flex: 1, display: 'flex', flexDirection: 'column' }}>
                      {/* Step indicator */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
                        <div
                          style={{
                            width: 44,
                            height: 44,
                            borderRadius: '50%',
                            background: `linear-gradient(135deg, ${color}20, ${color}10)`,
                            border: `2px solid ${color}40`,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0,
                          }}
                        >
                          <Icon size={20} color={color} />
                        </div>
                        <div>
                          <div style={{ fontSize: 11, fontWeight: 700, color, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                            Step {step}
                          </div>
                          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 500 }}>{subtitle}</div>
                        </div>
                        {/* Arrow connector (not on last step) */}
                        {idx < 2 && (
                          <div
                            aria-hidden="true"
                            style={{
                              marginLeft: 'auto',
                              width: 24,
                              height: 24,
                              borderRadius: '50%',
                              background: `${color}12`,
                              border: `1px solid ${color}25`,
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              flexShrink: 0,
                            }}
                          >
                            <ArrowRight size={12} color={color} />
                          </div>
                        )}
                        {idx === 2 && (
                          <div
                            style={{
                              marginLeft: 'auto',
                              padding: '3px 10px',
                              borderRadius: 999,
                              background: '#f0fdf4',
                              border: '1px solid #a7f3d0',
                              fontSize: 10,
                              fontWeight: 700,
                              color: '#059669',
                              flexShrink: 0,
                            }}
                          >
                            DONE
                          </div>
                        )}
                      </div>

                      <h3 style={{ fontSize: 22, fontWeight: 800, marginBottom: 12, color: '#0f172a' }}>
                        {title}
                      </h3>
                      <p style={{ color: '#475569', lineHeight: 1.75, fontSize: 14, marginBottom: 24, flex: 1 }}>
                        {body}
                      </p>

                      {/* Mini terminal/status snippet */}
                      <div
                        style={{
                          borderRadius: 10,
                          overflow: 'hidden',
                          border: `1px solid ${color}15`,
                        }}
                      >
                        <div
                          style={{
                            padding: '7px 12px',
                            background: '#1e293b',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6,
                          }}
                        >
                          <div style={{ display: 'flex', gap: 4 }}>
                            {['#ef4444', '#f59e0b', '#22c55e'].map((c) => (
                              <div key={c} style={{ width: 8, height: 8, borderRadius: '50%', background: c, opacity: 0.7 }} />
                            ))}
                          </div>
                          <span style={{ fontSize: 10, color: '#64748b', fontFamily: 'monospace', marginLeft: 4 }}>
                            threat-engine — live
                          </span>
                        </div>
                        <div style={{ padding: '12px 14px', background: '#0f172a' }}>
                          {snippets[idx].map((line) => (
                            <div
                              key={line.text}
                              style={{
                                fontFamily: 'monospace',
                                fontSize: 11,
                                color: line.color,
                                marginBottom: 4,
                                lineHeight: 1.5,
                              }}
                            >
                              {line.text}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Metric chip */}
                      <div
                        style={{
                          marginTop: 16,
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                          padding: '10px 14px',
                          borderRadius: 10,
                          background: `${color}06`,
                          border: `1px solid ${color}15`,
                        }}
                      >
                        <span style={{ fontSize: 20, fontWeight: 900, color, lineHeight: 1 }}>
                          {metrics[idx].value}
                        </span>
                        <span style={{ fontSize: 12, color: '#64748b' }}>{metrics[idx].label}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {/* ── 5. PLATFORM CAPABILITIES ────────────────────────────────────── */}
      <section className="section">
        <div className="container">
          <div style={{ textAlign: 'center', marginBottom: 64 }}>
            <span className="badge badge-blue" style={{ marginBottom: 20 }}>
              <Layers size={11} /> Platform Capabilities
            </span>
            <h2
              style={{
                fontSize: 'clamp(28px, 4vw, 48px)',
                fontWeight: 800,
                letterSpacing: '-0.025em',
                lineHeight: 1.15,
                marginBottom: 16,
                color: '#0f172a',
              }}
            >
              Everything your team needs.{' '}
              <span className="gradient-text">Nothing they don&apos;t.</span>
            </h2>
            <p style={{ color: '#475569', fontSize: 18, maxWidth: 540, margin: '0 auto' }}>
              Six deeply integrated modules, one unified data model, zero agent overhead.
            </p>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
              gap: 24,
            }}
          >
            {CAPABILITIES.map(({ icon: Icon, title, badge, badgeColor, body, color, panelBg, panelLabel, panelStats, panelRow }) => (
              <div
                key={title}
                className="card-hover"
                style={{
                  background: '#ffffff',
                  border: `1px solid ${color}20`,
                  borderRadius: 20,
                  overflow: 'hidden',
                  boxShadow: '0 4px 20px rgba(15,23,42,0.07)',
                }}
              >
                {/* Dark scan panel header */}
                <div style={{ background: panelBg }}>
                  {/* Label + stats row */}
                  <div
                    className="flex items-center gap-3 px-4 py-2"
                    style={{ borderBottom: `1px solid ${color}20`, background: `${color}08` }}
                  >
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, boxShadow: `0 0 5px ${color}`, flexShrink: 0, display: 'inline-block' }} />
                    <span style={{ color, fontSize: '9px', fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace', flex: 1 }}>
                      {panelLabel}
                    </span>
                    {panelStats.map((s) => (
                      <span key={s.l} style={{ fontSize: '9px', fontFamily: 'monospace', color: '#475569' }}>
                        <span style={{ color, fontWeight: 700 }}>{s.v}</span> {s.l}
                      </span>
                    ))}
                  </div>
                  {/* Finding row */}
                  <div
                    className="flex items-center gap-2 px-4 py-2"
                    style={{ borderLeft: `2px solid ${panelRow.color}` }}
                  >
                    <span style={{ color: '#334155', fontSize: '9px', fontFamily: 'monospace', flexShrink: 0, minWidth: 56 }}>{panelRow.id}</span>
                    <span style={{ color: '#475569', fontSize: '10px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{panelRow.text}</span>
                    <span style={{ fontSize: '8px', fontWeight: 700, padding: '1px 6px', borderRadius: 9999, color: panelRow.color, background: `${panelRow.color}15`, border: `1px solid ${panelRow.color}40`, flexShrink: 0 }}>
                      {panelRow.sev}
                    </span>
                  </div>
                </div>

                {/* Card content */}
                <div style={{ padding: 28 }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
                    <div
                      style={{
                        width: 48, height: 48, borderRadius: 12,
                        background: `${color}12`, border: `1px solid ${color}25`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                      }}
                    >
                      <Icon size={22} color={color} />
                    </div>
                    <div
                      style={{
                        padding: '4px 10px', borderRadius: 6,
                        background: `${badgeColor}10`, border: `1px solid ${badgeColor}25`,
                        fontSize: 11, fontWeight: 700, color: badgeColor,
                        letterSpacing: '0.05em', textTransform: 'uppercase',
                      }}
                    >
                      {badge}
                    </div>
                  </div>
                  <h3 style={{ fontSize: 19, fontWeight: 700, marginBottom: 10, color: '#0f172a' }}>{title}</h3>
                  <p style={{ color: '#475569', lineHeight: 1.7, fontSize: 14, marginBottom: 20 }}>{body}</p>
                  <Link
                    href="/platform"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 600, color, textDecoration: 'none' }}
                  >
                    Learn more <ChevronRight size={14} />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── 6. BIG STATS ─────────────────────────────────────────────────── */}
      <section
        style={{
          padding: '96px 0',
          background: '#eff6ff',
          borderTop: '1px solid #bfdbfe',
          borderBottom: '1px solid #bfdbfe',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Background accent */}
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: 800,
            height: 400,
            background: 'radial-gradient(ellipse, rgba(37,99,235,0.06) 0%, transparent 70%)',
            pointerEvents: 'none',
          }}
        />

        <div className="container" style={{ position: 'relative' }}>
          <div style={{ textAlign: 'center', marginBottom: 64 }}>
            <h2
              style={{
                fontSize: 'clamp(24px, 3.5vw, 42px)',
                fontWeight: 800,
                letterSpacing: '-0.025em',
                color: '#0f172a',
              }}
            >
              Numbers that{' '}
              <span className="gradient-text">tell the story</span>
            </h2>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: 2,
            }}
          >
            {BIG_STATS.map(({ value, label, color }, i) => (
              <div
                key={label}
                style={{
                  textAlign: 'center',
                  padding: '40px 32px',
                  borderRight: i < BIG_STATS.length - 1 ? '1px solid #bfdbfe' : 'none',
                }}
              >
                <div
                  style={{
                    fontSize: 'clamp(42px, 5vw, 64px)',
                    fontWeight: 900,
                    lineHeight: 1,
                    marginBottom: 12,
                    color,
                  }}
                >
                  {value}
                </div>
                <div style={{ color: '#475569', fontSize: 15, fontWeight: 500 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── 7. MULTI-CLOUD ───────────────────────────────────────────────── */}
      <section className="section">
        <div className="container">
          <div className="grid md:grid-cols-2" style={{ gap: 64, alignItems: 'center' }}>
            {/* Left: text */}
            <div>
              <span className="badge badge-blue" style={{ marginBottom: 20 }}>
                <Globe size={11} /> Multi-Cloud Coverage
              </span>
              <h2
                style={{
                  fontSize: 'clamp(26px, 3.5vw, 44px)',
                  fontWeight: 800,
                  letterSpacing: '-0.025em',
                  lineHeight: 1.15,
                  marginBottom: 20,
                  color: '#0f172a',
                }}
              >
                One platform,{' '}
                <span className="gradient-text">every cloud</span>
              </h2>
              <p style={{ color: '#475569', fontSize: 17, lineHeight: 1.75, marginBottom: 32 }}>
                Stop switching consoles. Threat Engine gives you a single pane of glass
                across all six major cloud providers — unified findings, risk scores,
                and compliance evidence in one data model.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[
                  { label: 'Unified identity graph across all providers', color: '#2563eb' },
                  { label: 'Single compliance score spans all accounts', color: '#059669' },
                  { label: 'Cross-cloud attack chain correlation', color: '#dc2626' },
                ].map(({ label, color }) => (
                  <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <CheckCircle size={14} color={color} style={{ flexShrink: 0 }} />
                    <span style={{ fontSize: 14, color: '#475569' }}>{label}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: dark coverage table */}
            <div
              style={{
                borderRadius: 16,
                overflow: 'hidden',
                border: '1px solid #1e293b',
                boxShadow: '0 8px 40px rgba(15,23,42,0.2)',
              }}
            >
              <div
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '10px 20px', background: '#0f172a', borderBottom: '1px solid #1e293b',
                }}
              >
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e', flexShrink: 0 }} />
                <span style={{ color: '#22c55e', fontSize: '10px', fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace', flex: 1 }}>
                  PROVIDER COVERAGE · LIVE
                </span>
                <span style={{ color: '#475569', fontSize: '9px', fontFamily: 'monospace' }}>6 providers · 43 services</span>
              </div>
              <div
                style={{
                  display: 'grid', gridTemplateColumns: '1fr 72px 80px 72px',
                  padding: '6px 20px', background: '#0a0f1a', borderBottom: '1px solid #1e293b',
                }}
              >
                {['Provider', 'Services', 'Resources', 'Findings'].map((h, i) => (
                  <span key={h} style={{ color: '#334155', fontSize: '9px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', textAlign: i > 0 ? 'right' : 'left' }}>{h}</span>
                ))}
              </div>
              {CLOUDS.map(({ name, color, services, resources, findings }) => (
                <div
                  key={name}
                  style={{
                    display: 'grid', gridTemplateColumns: '1fr 72px 80px 72px',
                    padding: '10px 20px', background: '#0a0f1a',
                    borderBottom: '1px solid #1e293b', borderLeft: `2px solid ${color}`,
                    alignItems: 'center',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}80`, flexShrink: 0 }} />
                    <span style={{ color: '#e2e8f0', fontSize: '12px', fontWeight: 700 }}>{name}</span>
                  </div>
                  <span style={{ color: '#94a3b8', fontSize: '11px', fontFamily: 'monospace', textAlign: 'right' }}>{services}</span>
                  <span style={{ color: '#94a3b8', fontSize: '11px', fontFamily: 'monospace', textAlign: 'right' }}>{resources}</span>
                  <span style={{ color: findings > 500 ? '#ef4444' : findings > 100 ? '#f97316' : '#eab308', fontSize: '11px', fontFamily: 'monospace', fontWeight: 700, textAlign: 'right' }}>{findings}</span>
                </div>
              ))}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 20px', background: '#0f172a' }}>
                <span style={{ color: '#334155', fontSize: '10px', fontFamily: 'monospace' }}>unified data model · zero gaps</span>
                <span style={{ color: '#22c55e', fontSize: '10px', fontFamily: 'monospace', fontWeight: 700 }}>● LIVE</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 8. COMPLIANCE FRAMEWORKS ────────────────────────────────────── */}
      <section
        style={{
          padding: '96px 0',
          background: '#f0fdf4',
          borderTop: '1px solid #a7f3d0',
          borderBottom: '1px solid #a7f3d0',
        }}
      >
        <div className="container">
          <div className="grid md:grid-cols-2" style={{ gap: 64, alignItems: 'center' }}>

            {/* Left: Compliance score dashboard */}
            <div
              style={{
                borderRadius: 16,
                overflow: 'hidden',
                border: '1px solid #1e293b',
                boxShadow: '0 8px 40px rgba(15,23,42,0.2)',
              }}
            >
              {/* Header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px', background: '#010f06', borderBottom: '1px solid #064e3b' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#059669', boxShadow: '0 0 6px #059669', flexShrink: 0 }} />
                <span style={{ color: '#059669', fontSize: '10px', fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace', flex: 1 }}>
                  COMPLIANCE DASHBOARD · Q1 2026
                </span>
                <span style={{ fontSize: '9px', fontWeight: 700, padding: '2px 8px', borderRadius: 9999, background: '#05966920', color: '#059669', border: '1px solid #05966940' }}>
                  SOC 2 TYPE II
                </span>
              </div>
              {/* Overall score */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 20, padding: '16px 20px', background: '#010f06', borderBottom: '1px solid #064e3b' }}>
                <div style={{ textAlign: 'center', flexShrink: 0 }}>
                  <div style={{ fontSize: '2.5rem', fontWeight: 900, color: '#059669', lineHeight: 1, fontFamily: 'monospace' }}>89</div>
                  <div style={{ fontSize: '9px', color: '#475569', letterSpacing: '0.04em' }}>/100 OVERALL</div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ height: 6, borderRadius: 3, background: '#064e3b', overflow: 'hidden', marginBottom: 6 }}>
                    <div style={{ width: '89%', height: '100%', background: 'linear-gradient(90deg, #059669, #22c55e)', borderRadius: 3 }} />
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#22c55e', fontSize: '10px', fontFamily: 'monospace' }}>57 passed</span>
                    <span style={{ color: '#ef4444', fontSize: '10px', fontFamily: 'monospace' }}>7 failed</span>
                  </div>
                </div>
              </div>
              {/* Framework scores */}
              {FRAMEWORKS.map(({ name, color }) => {
                const pct = { CIS: 87, NIST: 92, 'ISO 27001': 79, 'PCI-DSS': 83, HIPAA: 91, GDPR: 76, 'SOC 2': 85 }[name] || 80;
                return (
                  <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 20px', background: '#010f06', borderBottom: '1px solid #064e3b' }}>
                    <span style={{ color, fontSize: '11px', fontWeight: 700, minWidth: 76 }}>{name}</span>
                    <div style={{ flex: 1, height: 4, borderRadius: 2, background: '#064e3b', overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2 }} />
                    </div>
                    <span style={{ color, fontSize: '11px', fontFamily: 'monospace', fontWeight: 700, minWidth: 34, textAlign: 'right' }}>{pct}%</span>
                  </div>
                );
              })}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 20px', background: '#010f06' }}>
                <span style={{ color: '#334155', fontSize: '10px', fontFamily: 'monospace' }}>847 evidence records · auto-collected</span>
                <span style={{ color: '#22c55e', fontSize: '10px', fontFamily: 'monospace' }}>Export PDF →</span>
              </div>
            </div>

            {/* Right: text */}
            <div>
              <span className="badge badge-green" style={{ marginBottom: 20 }}>
                <FileText size={11} /> Compliance Coverage
              </span>
              <h2
                style={{
                  fontSize: 'clamp(24px, 3.5vw, 42px)',
                  fontWeight: 800,
                  letterSpacing: '-0.02em',
                  marginBottom: 20,
                  color: '#0f172a',
                  lineHeight: 1.15,
                }}
              >
                Audit-ready for every{' '}
                <span className="gradient-text-green">major framework</span>
              </h2>
              <p style={{ color: '#475569', fontSize: 16, lineHeight: 1.75, marginBottom: 32 }}>
                Continuous evidence collection means your auditors never have to wait.
                Threat Engine maps every finding to its control citation, collects evidence automatically,
                and exports audit packages in one click.
              </p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 28 }}>
                {FRAMEWORKS.map(({ name, color }) => (
                  <span
                    key={name}
                    style={{
                      padding: '6px 16px', borderRadius: 8,
                      background: `${color}10`, border: `1px solid ${color}30`,
                      fontSize: 13, fontWeight: 700, color, letterSpacing: '0.02em',
                    }}
                  >
                    {name}
                  </span>
                ))}
              </div>
              <p style={{ color: '#64748b', fontSize: 13 }}>
                CIS Benchmark levels 1 &amp; 2 included. SOC 2 Type II evidence export built in.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── 9. TESTIMONIALS ──────────────────────────────────────────────── */}
      <section className="section" style={{ background: '#f8fafc', borderTop: '1px solid #e2e8f0', borderBottom: '1px solid #e2e8f0' }}>
        <div className="container">
          <div style={{ textAlign: 'center', marginBottom: 56 }}>
            <span className="badge badge-purple" style={{ marginBottom: 20 }}>
              <Star size={11} /> Customer Stories
            </span>
            <h2
              style={{
                fontSize: 'clamp(26px, 4vw, 44px)',
                fontWeight: 800,
                letterSpacing: '-0.025em',
                lineHeight: 1.15,
                color: '#0f172a',
                maxWidth: 600,
                margin: '0 auto 16px',
              }}
            >
              Trusted by teams who{' '}
              <span className="gradient-text">can&apos;t afford to miss</span>
            </h2>
            <p style={{ color: '#475569', fontSize: 17, maxWidth: 480, margin: '0 auto' }}>
              Security teams at leading enterprises rely on Threat Engine to protect their cloud environments at scale.
            </p>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
              gap: 28,
            }}
          >
            {TESTIMONIALS.map(({ quote, name, title, company, tag, tagColor, initials, avatarGrad, stars }) => (
              <div
                key={name}
                className="card-hover"
                style={{
                  background: '#ffffff',
                  border: '1px solid #e2e8f0',
                  borderRadius: 20,
                  padding: 32,
                  display: 'flex',
                  flexDirection: 'column',
                  boxShadow: '0 4px 20px rgba(15,23,42,0.06)',
                  position: 'relative',
                  overflow: 'hidden',
                }}
              >
                {/* Top accent line */}
                <div
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    height: 3,
                    background: `linear-gradient(90deg, ${tagColor}, ${tagColor}40)`,
                  }}
                />

                {/* Stars */}
                <div style={{ display: 'flex', gap: 3, marginBottom: 20 }}>
                  {Array.from({ length: stars }).map((_, i) => (
                    <Star key={i} size={14} fill="#f59e0b" color="#f59e0b" />
                  ))}
                </div>

                {/* Quote mark */}
                <div
                  style={{
                    fontSize: 48,
                    lineHeight: 1,
                    color: tagColor,
                    opacity: 0.2,
                    fontFamily: 'Georgia, serif',
                    marginBottom: -12,
                  }}
                >
                  &ldquo;
                </div>

                {/* Quote text */}
                <p
                  style={{
                    color: '#334155',
                    fontSize: '14.5px',
                    lineHeight: 1.75,
                    flex: 1,
                    marginBottom: 28,
                    fontStyle: 'italic',
                  }}
                >
                  {quote}
                </p>

                {/* Divider */}
                <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: 24 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                    {/* Avatar */}
                    <div
                      style={{
                        width: 44,
                        height: 44,
                        borderRadius: '50%',
                        background: avatarGrad,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#ffffff',
                        fontSize: 13,
                        fontWeight: 700,
                        flexShrink: 0,
                      }}
                    >
                      {initials}
                    </div>

                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 14, fontWeight: 700, color: '#0f172a' }}>{name}</div>
                      <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>{title}</div>
                      <div style={{ fontSize: 12, fontWeight: 600, color: '#475569', marginTop: 1 }}>{company}</div>
                    </div>

                    <div
                      style={{
                        padding: '4px 10px',
                        borderRadius: 6,
                        background: `${tagColor}10`,
                        border: `1px solid ${tagColor}25`,
                        fontSize: 10,
                        fontWeight: 700,
                        color: tagColor,
                        letterSpacing: '0.04em',
                        whiteSpace: 'nowrap',
                        flexShrink: 0,
                      }}
                    >
                      {tag}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Trust bar */}
          <div
            style={{
              marginTop: 52,
              padding: '24px 32px',
              borderRadius: 16,
              background: 'linear-gradient(135deg, rgba(37,99,235,0.04), rgba(124,58,237,0.04))',
              border: '1px solid #e2e8f0',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 40,
              flexWrap: 'wrap',
            }}
          >
            {[
              { value: '< 4 hrs', label: 'Avg. MTTD reduction', color: '#2563eb' },
              { value: '80%',      label: 'Alert fatigue reduction', color: '#7c3aed' },
              { value: '1-click',  label: 'Audit-ready exports', color: '#059669' },
              { value: '30 sec',   label: 'Time to connect a cloud account', color: '#0891b2' },
            ].map(({ value, label, color }) => (
              <div key={label} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 26, fontWeight: 900, color, lineHeight: 1 }}>{value}</div>
                <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── 10. BLOG PREVIEW ─────────────────────────────────────────────── */}
      <section className="section">
        <div className="container">
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-end',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 20,
              marginBottom: 48,
            }}
          >
            <div>
              <span className="badge badge-purple" style={{ marginBottom: 16 }}>
                <Star size={11} /> From the Blog
              </span>
              <h2
                style={{
                  fontSize: 'clamp(24px, 3vw, 38px)',
                  fontWeight: 800,
                  letterSpacing: '-0.025em',
                  lineHeight: 1.15,
                  color: '#0f172a',
                }}
              >
                Security intelligence,{' '}
                <span className="gradient-text">no paywall</span>
              </h2>
            </div>
            <Link href="/blog" className="btn-secondary" style={{ flexShrink: 0 }}>
              All Articles <ArrowRight size={16} />
            </Link>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
              gap: 24,
            }}
          >
            {BLOG_POSTS.map(({ slug, category, categoryColor, title, excerpt, date, readTime, icon: Icon,
              panelBg, panelLabel, panelGlow, panelStat, panelFindingId, panelFindingText, panelFindingSev, panelFindingColor }) => (
              <Link key={slug} href={`/blog/${slug}`} style={{ textDecoration: 'none', display: 'block', height: '100%' }}>
                <article
                  className="card-hover"
                  style={{
                    background: '#ffffff',
                    border: `1px solid ${categoryColor}20`,
                    borderRadius: 20,
                    overflow: 'hidden',
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    boxShadow: '0 4px 20px rgba(15,23,42,0.07)',
                  }}
                >
                  {/* Dark editorial mini-header */}
                  <div style={{ background: panelBg }}>
                    <div
                      className="flex items-center gap-2 px-4 py-2"
                      style={{ borderBottom: `1px solid ${panelGlow}25`, background: `${panelGlow}08` }}
                    >
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: panelGlow, boxShadow: `0 0 5px ${panelGlow}`, flexShrink: 0, display: 'inline-block' }} />
                      <span style={{ color: panelGlow, fontSize: '9px', fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace', flex: 1 }}>
                        {panelLabel}
                      </span>
                      <span style={{ color: '#475569', fontSize: '9px', fontFamily: 'monospace' }}>{panelStat}</span>
                      <Icon size={11} style={{ color: '#334155', flexShrink: 0 }} />
                    </div>
                    <div
                      className="flex items-center gap-2 px-4 py-2"
                      style={{ borderLeft: `2px solid ${panelFindingColor}` }}
                    >
                      <span style={{ color: '#334155', fontSize: '9px', fontFamily: 'monospace', flexShrink: 0, minWidth: 52 }}>{panelFindingId}</span>
                      <span style={{ color: '#475569', fontSize: '10px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{panelFindingText}</span>
                      <span style={{ fontSize: '8px', fontWeight: 700, padding: '1px 5px', borderRadius: 9999, color: panelFindingColor, background: `${panelFindingColor}15`, border: `1px solid ${panelFindingColor}40`, flexShrink: 0 }}>
                        {panelFindingSev}
                      </span>
                    </div>
                  </div>

                  {/* Card content */}
                  <div style={{ padding: '24px 28px', flex: 1, display: 'flex', flexDirection: 'column' }}>
                    <div
                      style={{
                        display: 'inline-flex', alignItems: 'center', gap: 7,
                        padding: '4px 11px', borderRadius: 999,
                        background: `${categoryColor}10`, border: `1px solid ${categoryColor}25`,
                        marginBottom: 16, alignSelf: 'flex-start',
                      }}
                    >
                      <Icon size={11} color={categoryColor} />
                      <span style={{ fontSize: 10, fontWeight: 700, color: categoryColor, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                        {category}
                      </span>
                    </div>

                    <h3 style={{ fontSize: 17, fontWeight: 700, lineHeight: 1.35, color: '#0f172a', marginBottom: 12, flex: 1 }}>
                      {title}
                    </h3>
                    <p style={{ color: '#475569', fontSize: 13, lineHeight: 1.7, marginBottom: 20, flex: 1 }}>
                      {excerpt}
                    </p>
                    <div
                      style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        paddingTop: 16, borderTop: '1px solid #f1f5f9',
                      }}
                    >
                      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                        <span style={{ fontSize: 11, color: '#64748b', display: 'flex', alignItems: 'center', gap: 4 }}>
                          <Clock size={10} /> {date}
                        </span>
                        <span style={{ width: 3, height: 3, borderRadius: '50%', background: '#cbd5e1' }} />
                        <span style={{ fontSize: 11, color: '#64748b' }}>{readTime}</span>
                      </div>
                      <ChevronRight size={15} color="#2563eb" />
                    </div>
                  </div>
                </article>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ── 10. FINAL CTA ────────────────────────────────────────────────── */}
      <section
        style={{
          padding: '100px 0',
          position: 'relative',
          overflow: 'hidden',
          background: 'linear-gradient(160deg, #060b14 0%, #0d1117 50%, #080d18 100%)',
        }}
      >
        {/* Subtle grid overlay */}
        <div aria-hidden="true" style={{
          position: 'absolute', inset: 0, opacity: 0.04,
          backgroundImage: 'linear-gradient(#3b82f6 1px, transparent 1px), linear-gradient(90deg, #3b82f6 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }} />
        {/* Glow orbs */}
        <div aria-hidden="true" style={{ position: 'absolute', top: -100, left: '20%', width: 500, height: 500, borderRadius: '50%', background: 'radial-gradient(circle, rgba(37,99,235,0.12) 0%, transparent 70%)', pointerEvents: 'none' }} />
        <div aria-hidden="true" style={{ position: 'absolute', bottom: -80, right: '15%', width: 400, height: 400, borderRadius: '50%', background: 'radial-gradient(circle, rgba(124,58,237,0.1) 0%, transparent 70%)', pointerEvents: 'none' }} />

        <div className="container" style={{ position: 'relative' }}>
          {/* Top text — centered */}
          <div style={{ textAlign: 'center', marginBottom: 56 }}>
            <span
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                background: 'rgba(37,99,235,0.12)', border: '1px solid rgba(37,99,235,0.3)',
                borderRadius: 20, padding: '5px 14px', marginBottom: 24,
                fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace',
                color: '#60a5fa', textTransform: 'uppercase',
              }}
            >
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e', display: 'inline-block' }} />
              Live · Continuous · No agents
            </span>

            <h2
              style={{
                fontSize: 'clamp(32px, 5vw, 60px)',
                fontWeight: 900,
                letterSpacing: '-0.03em',
                lineHeight: 1.1,
                maxWidth: 680,
                margin: '0 auto 20px',
                color: '#f1f5f9',
              }}
            >
              Your cloud, protected{' '}
              <span style={{ background: 'linear-gradient(90deg, #3b82f6, #7c3aed)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
                in minutes
              </span>
            </h2>

            <p style={{ color: '#94a3b8', fontSize: 18, maxWidth: 520, margin: '0 auto', lineHeight: 1.65 }}>
              Connect your cloud account and Threat Engine immediately begins scanning — threat detection, compliance, IAM, and inventory all in one platform.
            </p>
          </div>

          {/* Live scan console panel */}
          <div style={{
            maxWidth: 820, margin: '0 auto 52px',
            borderRadius: 16, overflow: 'hidden',
            border: '1px solid rgba(59,130,246,0.2)',
            boxShadow: '0 0 60px rgba(37,99,235,0.15), 0 32px 64px rgba(0,0,0,0.5)',
          }}>
            {/* Console header bar */}
            <div style={{
              background: '#0f172a',
              borderBottom: '1px solid rgba(59,130,246,0.15)',
              padding: '10px 18px',
              display: 'flex', alignItems: 'center', gap: 10,
            }}>
              <div style={{ display: 'flex', gap: 6 }}>
                {['#ef4444','#f59e0b','#22c55e'].map(c => (
                  <span key={c} style={{ width: 10, height: 10, borderRadius: '50%', background: c, display: 'inline-block' }} />
                ))}
              </div>
              <span style={{ flex: 1, textAlign: 'center', color: '#475569', fontSize: 11, fontFamily: 'monospace', letterSpacing: '0.08em' }}>
                threat-engine · scan-console · aws-prod-account
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#22c55e', fontSize: 10, fontFamily: 'monospace', fontWeight: 700 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 4px #22c55e', display: 'inline-block' }} />
                SCANNING
              </span>
            </div>

            {/* Engine scan rows */}
            <div style={{ background: '#080d18' }}>
              {/* Scan status line */}
              <div style={{ padding: '10px 18px', borderBottom: '1px solid rgba(255,255,255,0.04)', display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ color: '#3b82f6', fontFamily: 'monospace', fontSize: 11 }}>$</span>
                <span style={{ color: '#64748b', fontFamily: 'monospace', fontSize: 11 }}>threat-engine scan --account aws-prod --region ap-south-1 --all-engines</span>
              </div>

              {[
                { engine: 'THREAT',     id: 'T-0847', text: 'Privilege escalation path detected · IAM role chain',       sev: 'CRITICAL', color: '#ef4444', icon: '⚡' },
                { engine: 'IAM',        id: 'I-0234', text: 'Root account active session · MFA not enforced',            sev: 'CRITICAL', color: '#ef4444', icon: '🔑' },
                { engine: 'CHECK',      id: 'C-0129', text: 'S3 bucket public read enabled · 12 buckets affected',       sev: 'HIGH',     color: '#f97316', icon: '☁' },
                { engine: 'DATASEC',    id: 'D-0034', text: 'PII data in unencrypted storage · 3 S3 objects flagged',    sev: 'HIGH',     color: '#f97316', icon: '🔒' },
                { engine: 'INVENTORY',  id: 'N-0088', text: 'EC2 instance drift detected · security group modified',      sev: 'MEDIUM',   color: '#eab308', icon: '📦' },
                { engine: 'COMPLIANCE', id: 'F-0011', text: 'CIS Benchmark 2.1.5 failed · CloudTrail not enabled',       sev: 'LOW',      color: '#3b82f6', icon: '📋' },
              ].map(({ engine, id, text, sev, color, icon }, i) => (
                <div
                  key={id}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '9px 18px',
                    borderBottom: i < 5 ? '1px solid rgba(255,255,255,0.03)' : 'none',
                    borderLeft: `2px solid ${color}`,
                  }}
                >
                  <span style={{ fontSize: 12 }}>{icon}</span>
                  <span style={{
                    background: `${color}1a`, border: `1px solid ${color}40`,
                    borderRadius: 4, padding: '1px 6px',
                    color, fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                    letterSpacing: '0.08em', flexShrink: 0,
                  }}>{engine}</span>
                  <span style={{ color: '#64748b', fontSize: 10, fontFamily: 'monospace', flexShrink: 0 }}>{id}</span>
                  <span style={{ color: '#cbd5e1', fontSize: 12, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{text}</span>
                  <span style={{
                    background: `${color}1a`, border: `1px solid ${color}40`,
                    borderRadius: 20, padding: '2px 8px',
                    color, fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                    letterSpacing: '0.06em', flexShrink: 0,
                  }}>{sev}</span>
                </div>
              ))}

              {/* Footer summary */}
              <div style={{
                padding: '10px 18px',
                background: '#0a0f1a',
                borderTop: '1px solid rgba(59,130,246,0.1)',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8,
              }}>
                <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                  {[
                    { value: '3,900', label: 'findings', color: '#ef4444' },
                    { value: '13',    label: 'frameworks', color: '#3b82f6' },
                    { value: '825',   label: 'IAM rules', color: '#7c3aed' },
                    { value: '40+',   label: 'services scanned', color: '#22c55e' },
                  ].map(({ value, label, color }) => (
                    <span key={label} style={{ fontSize: 10, fontFamily: 'monospace', color: '#475569' }}>
                      <span style={{ color, fontWeight: 700 }}>{value}</span> {label}
                    </span>
                  ))}
                </div>
                <span style={{ color: '#22c55e', fontSize: 10, fontFamily: 'monospace' }}>✓ scan complete · 0 agents deployed</span>
              </div>
            </div>
          </div>

          {/* CTAs */}
          <div style={{ display: 'flex', gap: 16, justifyContent: 'center', flexWrap: 'wrap', marginBottom: 36 }}>
            <Link
              href="/contact"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 10,
                background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
                color: '#fff', fontWeight: 700, fontSize: 16,
                padding: '16px 36px', borderRadius: 12,
                border: '1px solid rgba(255,255,255,0.1)',
                boxShadow: '0 8px 32px rgba(37,99,235,0.4)',
                textDecoration: 'none', transition: 'all 0.2s',
              }}
            >
              Request a Demo <ArrowRight size={18} />
            </Link>
            <Link
              href="/platform"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 10,
                background: 'rgba(255,255,255,0.06)', color: '#e2e8f0',
                fontWeight: 600, fontSize: 16, padding: '16px 36px', borderRadius: 12,
                border: '1px solid rgba(255,255,255,0.12)',
                textDecoration: 'none',
              }}
            >
              Explore Platform
            </Link>
          </div>

          {/* Trust signals */}
          <div style={{ display: 'flex', gap: 28, justifyContent: 'center', flexWrap: 'wrap', alignItems: 'center' }}>
            {[
              { icon: Shield, text: 'No agents required' },
              { icon: Clock,  text: '30-second setup'    },
              { icon: Lock,   text: 'Read-only access'   },
              { icon: Users,  text: 'Onboarding support' },
            ].map(({ icon: Icon, text }) => (
              <div key={text} style={{ display: 'flex', alignItems: 'center', gap: 7, color: '#64748b', fontSize: 13, fontWeight: 500 }}>
                <Icon size={13} color="#3b82f6" />
                {text}
              </div>
            ))}
          </div>
        </div>
      </section>

    </main>
  );
}
