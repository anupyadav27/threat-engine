import Link from 'next/link';
import {
  Shield,
  Target,
  Lock,
  BarChart3,
  Globe,
  Code2,
  Cloud,
  CheckCircle2,
  ArrowRight,
  Zap,
  Eye,
  GitBranch,
  AlertTriangle,
  Database,
  FileCode2,
  Layers,
  TrendingUp,
  Users,
  Clock,
  Award,
  Map,
  Network,
  Key,
  FileCheck,
  Search,
  Activity,
} from 'lucide-react';

export const metadata = {
  title: 'Platform — Threat Engine CSPM',
  description:
    'Explore all 6 capabilities of Threat Engine: Threat Detection, IAM Security, Compliance, Asset Inventory, Code Security, and Data Security.',
};

/* ── Reusable sub-components ─────────────────────────────────── */

function SectionBadge({ icon: Icon, label, color = '#2563eb', bg = 'rgba(37,99,235,0.08)' }) {
  return (
    <div
      className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full mb-6"
      style={{ background: bg, border: `1px solid ${color}30` }}
    >
      <Icon size={13} style={{ color }} />
      <span className="text-xs font-semibold uppercase tracking-widest" style={{ color }}>
        {label}
      </span>
    </div>
  );
}

function FeatureCheck({ children }) {
  return (
    <li className="flex items-start gap-3">
      <CheckCircle2
        size={17}
        className="flex-shrink-0 mt-0.5"
        style={{ color: '#10b981' }}
      />
      <span style={{ color: '#475569', fontSize: '0.95rem', lineHeight: '1.6' }}>{children}</span>
    </li>
  );
}

function StatCard({ value, label, color = '#2563eb' }) {
  return (
    <div
      className="card-hover rounded-2xl p-5 text-center"
      style={{ minWidth: 140, background: '#ffffff', border: '1px solid #e2e8f0', boxShadow: '0 2px 8px rgba(15,23,42,0.06)' }}
    >
      <div
        className="text-3xl font-black mb-1"
        style={{ color, fontVariantNumeric: 'tabular-nums' }}
      >
        {value}
      </div>
      <div className="text-xs font-medium uppercase tracking-wide" style={{ color: '#64748b' }}>
        {label}
      </div>
    </div>
  );
}

function StepBadge({ n }) {
  return (
    <div
      className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-bold"
      style={{ background: 'linear-gradient(135deg,#2563eb,#7c3aed)', color: '#fff' }}
    >
      {n}
    </div>
  );
}

function HowItWorksStep({ n, title, desc, dark = false }) {
  return (
    <li className="flex items-start gap-3">
      <StepBadge n={n} />
      <div>
        <div className="text-sm font-semibold mb-0.5" style={{ color: dark ? '#e2e8f0' : '#0f172a' }}>
          {title}
        </div>
        <div className="text-sm" style={{ color: dark ? '#94a3b8' : '#64748b' }}>
          {desc}
        </div>
      </div>
    </li>
  );
}

/* ── Anchor nav items ─────────────────────────────────────────── */
const NAV_ITEMS = [
  { id: 'threat',     label: 'Threat Detection' },
  { id: 'iam',        label: 'IAM Security' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'inventory',  label: 'Asset Inventory' },
  { id: 'secops',     label: 'Code Security' },
  { id: 'datasec',    label: 'Data Security' },
];

/* ── Page ─────────────────────────────────────────────────────── */
export default function PlatformPage() {
  return (
    <>
      {/* ─── HERO ─────────────────────────────────────────────── */}
      <section
        className="hero-bg grid-bg relative overflow-hidden"
        style={{ paddingTop: '140px', paddingBottom: '80px' }}
      >
        {/* Ambient glows */}
        <div
          className="absolute top-0 left-1/4 w-[600px] h-[600px] rounded-full pointer-events-none"
          style={{
            background: 'radial-gradient(circle, rgba(37,99,235,0.08) 0%, transparent 70%)',
            transform: 'translate(-50%,-50%)',
          }}
        />
        <div
          className="absolute top-1/3 right-0 w-[400px] h-[400px] rounded-full pointer-events-none"
          style={{
            background: 'radial-gradient(circle, rgba(124,58,237,0.06) 0%, transparent 70%)',
          }}
        />

        <div className="container relative">
          <div className="text-center max-w-3xl mx-auto">
            <div className="badge badge-blue mb-6">Enterprise Platform</div>

            <h1
              className="text-5xl font-black tracking-tight leading-[1.1] mb-6"
              style={{ color: '#0f172a' }}
            >
              The CSPM Platform Built for{' '}
              <span className="gradient-text">Multi-Cloud Reality</span>
            </h1>

            <p className="text-xl mb-10" style={{ color: '#475569', lineHeight: '1.7' }}>
              Modern enterprises run across AWS, Azure, GCP, OCI, AliCloud, and IBM Cloud
              simultaneously. Threat Engine is the only CSPM platform engineered from the ground up
              to handle that complexity — with unified visibility, consistent policy enforcement, and
              correlated threat intelligence across every account, region, and provider.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-4">
              <Link href="/contact" className="btn-primary">
                Request Demo <ArrowRight size={16} />
              </Link>
              <Link href="#threat" className="btn-secondary">
                Explore Capabilities
              </Link>
            </div>

            {/* Engine overview panel */}
            <div style={{ marginTop: 48, maxWidth: 860, margin: '48px auto 0' }}>
              <div className="rounded-2xl overflow-hidden" style={{ border: '1px solid rgba(37,99,235,0.18)', boxShadow: '0 0 60px rgba(37,99,235,0.1), 0 24px 48px rgba(0,0,0,0.12)' }}>
                {/* Panel header */}
                <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(255,255,255,0.06)', padding: '10px 18px', display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{ display: 'flex', gap: 5 }}>
                    {['#ef4444','#f59e0b','#22c55e'].map(c => <span key={c} style={{ width: 9, height: 9, borderRadius: '50%', background: c, display: 'inline-block' }} />)}
                  </div>
                  <span style={{ flex: 1, textAlign: 'center', color: '#475569', fontSize: 11, fontFamily: 'monospace', letterSpacing: '0.06em' }}>threat-engine · platform-overview · 6 engines active</span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#22c55e', fontSize: 10, fontFamily: 'monospace', fontWeight: 700 }}>
                    <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 4px #22c55e', display: 'inline-block' }} />LIVE
                  </span>
                </div>
                {/* Engine rows grid */}
                <div style={{ background: '#080d18', display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)' }}>
                  {[
                    { name: 'THREAT',     color: '#ef4444', metric: '3,900', unit: 'findings', sub: '50 MITRE techniques',  risk: '82' },
                    { name: 'IAM',        color: '#7c3aed', metric: '825',   unit: 'findings', sub: '57 rules evaluated',   risk: '71' },
                    { name: 'COMPLIANCE', color: '#059669', metric: '87%',   unit: 'avg score', sub: '13 frameworks',       risk: null },
                    { name: 'INVENTORY',  color: '#2563eb', metric: '18.3k', unit: 'assets',   sub: '40+ services · 6 CSPs',risk: null },
                    { name: 'CODE SEC',   color: '#ea580c', metric: '500+',  unit: 'rules',    sub: '14 IaC languages',     risk: null },
                    { name: 'DATA SEC',   color: '#0891b2', metric: '62',    unit: 'rules',    sub: '3 PII stores flagged',  risk: '68' },
                  ].map(({ name, color, metric, unit, sub, risk }, i) => (
                    <div
                      key={name}
                      style={{
                        padding: '14px 18px',
                        borderRight: i % 3 < 2 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                        borderBottom: i < 3 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span style={{ background: `${color}1a`, border: `1px solid ${color}40`, borderRadius: 4, padding: '2px 7px', color, fontSize: 9, fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.08em' }}>{name}</span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#22c55e', fontSize: 9, fontFamily: 'monospace' }}>
                          <span style={{ width: 4, height: 4, borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} />ACTIVE
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
                        <span style={{ color, fontSize: 20, fontWeight: 900, lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{metric}</span>
                        <span style={{ color: '#64748b', fontSize: 10 }}>{unit}</span>
                        {risk && <span style={{ marginLeft: 'auto', color: '#475569', fontSize: 9, fontFamily: 'monospace' }}>risk <span style={{ color }}>{risk}</span></span>}
                      </div>
                      <div style={{ color: '#475569', fontSize: 9, marginTop: 3, fontFamily: 'monospace' }}>{sub}</div>
                    </div>
                  ))}
                </div>
                {/* Footer */}
                <div style={{ background: '#0a0f1a', borderTop: '1px solid rgba(59,130,246,0.1)', padding: '8px 18px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ color: '#475569', fontSize: 10, fontFamily: 'monospace' }}>last scan <span style={{ color: '#94a3b8' }}>4 min ago</span> · next <span style={{ color: '#94a3b8' }}>11 min</span></span>
                  <span style={{ color: '#22c55e', fontSize: 10, fontFamily: 'monospace' }}>✓ 0 agents deployed · read-only access</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── STICKY CAPABILITIES NAV ──────────────────────────── */}
      <div
        className="sticky top-16 z-40"
        style={{
          background: 'rgba(255,255,255,0.97)',
          backdropFilter: 'blur(20px)',
          borderBottom: '1px solid #e2e8f0',
          boxShadow: '0 1px 4px rgba(15,23,42,0.06)',
        }}
      >
        <div className="container">
          <nav className="flex items-center gap-1 overflow-x-auto py-1" style={{ scrollbarWidth: 'none' }}>
            {NAV_ITEMS.map((item) => (
              <a
                key={item.id}
                href={`#${item.id}`}
                className="flex-shrink-0 px-4 py-2.5 rounded-lg text-sm font-medium transition-all no-underline hover:bg-blue-50 hover:text-slate-900"
                style={{ color: '#64748b', whiteSpace: 'nowrap' }}
              >
                {item.label}
              </a>
            ))}
          </nav>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════
          CAPABILITY 1 — THREAT DETECTION
      ═══════════════════════════════════════════════════════ */}
      <section id="threat" className="section" style={{ background: '#ffffff' }}>
        <div className="container">
          <div className="grid lg:grid-cols-2 gap-16 items-start">
            {/* Left — copy */}
            <div>
              <SectionBadge icon={Target} label="Threat Detection" color="#ef4444" bg="rgba(239,68,68,0.08)" />

              <h2 className="text-4xl font-black leading-tight mb-6" style={{ color: '#0f172a' }}>
                Know Exactly What Attackers{' '}
                <span className="gradient-text">See in Your Cloud</span>
              </h2>

              <div className="space-y-4 mb-8" style={{ color: '#475569', lineHeight: '1.75' }}>
                <p>
                  Threat Engine's detection engine maps every finding to the{' '}
                  <strong style={{ color: '#0f172a' }}>MITRE ATT&CK for Cloud</strong> framework,
                  giving your security team the exact adversarial context they need to triage and
                  respond. Instead of noise-filled alert queues, you get a precise risk score from
                  0–100 derived from 15+ contextual factors including exposure, asset sensitivity,
                  blast radius, and historical attack patterns.
                </p>
                <p>
                  The attack chain visualizer connects disparate findings across accounts and
                  services — showing how a misconfigured S3 bucket plus an overly permissive IAM
                  role plus an exposed EC2 instance combine into a viable kill chain. Most CSPM tools
                  report individual findings in isolation; Threat Engine shows you the story.
                </p>
                <p>
                  Cross-account threat correlation ensures that an attacker pivoting between accounts
                  in your AWS Organization doesn't escape detection just because the activity is
                  spread across trust boundaries. Threat Engine maintains a unified threat graph
                  across all accounts in your portfolio.
                </p>
              </div>

              <ul className="space-y-3 mb-10">
                <FeatureCheck>
                  MITRE ATT&CK technique mapping covering 50+ cloud-specific techniques across
                  Initial Access, Execution, Persistence, Privilege Escalation, and Exfiltration
                </FeatureCheck>
                <FeatureCheck>
                  Real-time risk scoring (0–100) driven by 15+ contextual risk factors including
                  asset criticality, internet exposure, lateral movement potential, and data sensitivity
                </FeatureCheck>
                <FeatureCheck>
                  Attack chain visualization — interactively trace how individual misconfiguration
                  findings chain together into viable adversarial paths
                </FeatureCheck>
                <FeatureCheck>
                  Cross-account and cross-region threat correlation within AWS Organizations,
                  Azure Tenants, and GCP Organizations
                </FeatureCheck>
                <FeatureCheck>
                  Automated threat intelligence enrichment with CVE context, known threat actor
                  TTPs, and exploit availability signals
                </FeatureCheck>
                <FeatureCheck>
                  Risk-prioritized alert queue — focus on the 3% of findings that represent 80%
                  of your actual risk exposure
                </FeatureCheck>
                <FeatureCheck>
                  Threat trend analysis across scan cycles — detect when your risk posture is
                  improving or degrading over time
                </FeatureCheck>
                <FeatureCheck>
                  One-click Jira, PagerDuty, and Slack escalation from any threat finding
                </FeatureCheck>
              </ul>

              {/* How it works */}
              <div className="rounded-2xl overflow-hidden" style={{ background: '#0a0f1a', border: '1px solid rgba(239,68,68,0.2)', boxShadow: '0 4px 24px rgba(239,68,68,0.08)' }}>
                <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(239,68,68,0.15)', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 5px #ef4444', display: 'inline-block' }} />
                  <span style={{ color: '#ef4444', fontSize: '10px', fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.1em' }}>HOW IT WORKS · THREAT DETECTION</span>
                </div>
                <div style={{ padding: '16px' }}>
                  <ol className="space-y-4">
                    <HowItWorksStep dark n={1} title="Discovery Scan Ingestion" desc="Raw cloud resource data flows in from the discovery engine covering all enabled providers and accounts." />
                    <HowItWorksStep dark n={2} title="Rule Evaluation & Finding Generation" desc="The check engine evaluates 200+ security rules against each resource, producing PASS/FAIL findings with evidence." />
                    <HowItWorksStep dark n={3} title="MITRE Mapping & Risk Scoring" desc="Each finding is mapped to ATT&CK techniques, enriched with context factors, and assigned a 0–100 risk score." />
                    <HowItWorksStep dark n={4} title="Attack Chain Construction" desc="The threat graph correlates findings across resources to surface multi-step attack paths and blast radius estimates." />
                    <HowItWorksStep dark n={5} title="Alert & Escalation" desc="High-priority threats trigger configured alert channels with full context, assignee routing, and remediation guidance." />
                  </ol>
                </div>
              </div>
            </div>

            {/* Right — stats + visuals */}
            <div className="space-y-5">
              {/* Stats row */}
              <div className="grid grid-cols-3 gap-4">
                <StatCard value="3,900" label="Findings Analyzed" color="#ef4444" />
                <StatCard value="50" label="MITRE Techniques" color="#f97316" />
                <StatCard value="99.7%" label="Detection Accuracy" color="#10b981" />
              </div>

              {/* Attack Chain — production-grade redesign */}
              <div
                className="rounded-2xl overflow-hidden"
                style={{
                  border: '1px solid rgba(239,68,68,0.25)',
                  boxShadow: '0 4px 24px rgba(239,68,68,0.08)',
                }}
              >
                {/* Dark header bar */}
                <div
                  className="flex items-center justify-between px-5 py-3"
                  style={{ background: '#1e293b', borderBottom: '1px solid #0f172a' }}
                >
                  <div className="flex items-center gap-2">
                    <div
                      className="animate-pulse-glow"
                      style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }}
                    />
                    <span
                      style={{ fontSize: 11, fontWeight: 700, color: '#f8fafc', letterSpacing: '0.07em' }}
                    >
                      ACTIVE THREAT CHAIN
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span style={{ fontSize: 10, color: '#64748b', fontFamily: 'monospace' }}>
                      acct/588989875114
                    </span>
                    <span
                      className="badge"
                      style={{
                        background: 'rgba(239,68,68,0.2)',
                        color: '#fca5a5',
                        border: '1px solid rgba(239,68,68,0.4)',
                        fontSize: '10px',
                        padding: '2px 8px',
                      }}
                    >
                      CRITICAL · Risk 94
                    </span>
                  </div>
                </div>

                {/* Chain body */}
                <div className="p-4" style={{ background: '#fffbfb' }}>
                  {[
                    {
                      technique: 'T1530', tactic: 'Initial Access', phase: '01',
                      name: 'S3 Bucket Public Read Enabled',
                      resource: 's3://prod-backup-bucket-5a8b07',
                      finding: '34 objects (3.2 GB) exposed to the public internet',
                      risk: 88, color: '#f97316', icon: Cloud,
                    },
                    {
                      technique: 'T1078', tactic: 'Privilege Escalation', phase: '02',
                      name: 'IAM Role — Wildcard Actions, No Resource Scope',
                      resource: 'arn:aws:iam::588989875114:role/deployment-role',
                      finding: 'Grants s3:* iam:* ec2:* with no resource restriction',
                      risk: 94, color: '#ef4444', icon: Key,
                    },
                    {
                      technique: 'T1537', tactic: 'Exfiltration', phase: '03',
                      name: 'Cross-Account Trust to Unverified External Principal',
                      resource: 'arn:aws:sts::382992847734:assumed-role/*',
                      finding: 'Trust policy permits external account with no condition keys',
                      risk: 96, color: '#dc2626', icon: AlertTriangle,
                    },
                  ].map((node, i) => (
                    <div key={node.technique}>
                      <div
                        className="rounded-xl p-3"
                        style={{ background: '#ffffff', border: `1px solid ${node.color}20` }}
                      >
                        <div className="flex items-start gap-3">
                          {/* Icon */}
                          <div
                            className="rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                            style={{
                              width: 30, height: 30,
                              background: `${node.color}12`,
                              border: `1px solid ${node.color}25`,
                            }}
                          >
                            <node.icon size={13} style={{ color: node.color }} />
                          </div>

                          {/* Content */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-start justify-between gap-2">
                              <span
                                style={{
                                  fontSize: 12, fontWeight: 700, color: '#0f172a',
                                  lineHeight: 1.4, flex: 1,
                                }}
                              >
                                {node.name}
                              </span>
                              {/* Risk score badge */}
                              <span
                                style={{
                                  fontSize: 11, fontWeight: 900, color: node.color,
                                  background: `${node.color}10`,
                                  border: `1px solid ${node.color}25`,
                                  borderRadius: 4, padding: '1px 7px', flexShrink: 0,
                                }}
                              >
                                {node.risk}
                              </span>
                            </div>
                            {/* Resource ARN */}
                            <div
                              style={{
                                fontSize: 9, fontFamily: 'monospace', color: '#94a3b8',
                                marginTop: 3, marginBottom: 4,
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                              }}
                            >
                              {node.resource}
                            </div>
                            {/* Finding */}
                            <div style={{ fontSize: 10, color: '#64748b', lineHeight: 1.4 }}>
                              {node.finding}
                            </div>
                            {/* MITRE badge */}
                            <div className="flex items-center gap-2 mt-2 pt-2" style={{ borderTop: `1px solid ${node.color}12` }}>
                              <span
                                style={{
                                  fontSize: 9, fontWeight: 700, color: node.color,
                                  background: `${node.color}10`,
                                  border: `1px solid ${node.color}25`,
                                  borderRadius: 4, padding: '1px 6px',
                                }}
                              >
                                {node.technique}
                              </span>
                              <span style={{ fontSize: 9, color: '#94a3b8' }}>{node.tactic}</span>
                              <span style={{ fontSize: 9, color: '#cbd5e1' }}>· Phase {node.phase}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                      {/* Connector line */}
                      {i < 2 && (
                        <div className="flex justify-center my-1.5">
                          <div style={{ width: 1, height: 14, background: 'rgba(239,68,68,0.3)' }} />
                        </div>
                      )}
                    </div>
                  ))}

                  {/* Blast radius breakdown */}
                  <div
                    className="mt-3 rounded-xl p-3"
                    style={{ background: '#fef2f2', border: '1px solid rgba(239,68,68,0.2)' }}
                  >
                    <div className="flex items-center gap-1.5 mb-3">
                      <Shield size={11} style={{ color: '#ef4444' }} />
                      <span
                        style={{
                          fontSize: 10, fontWeight: 700, color: '#dc2626',
                          letterSpacing: '0.06em', textTransform: 'uppercase',
                        }}
                      >
                        Blast Radius
                      </span>
                    </div>
                    <div className="grid grid-cols-4 gap-2 text-center">
                      {[
                        { label: 'Accounts',   count: 3  },
                        { label: 'S3 Buckets', count: 7  },
                        { label: 'IAM Roles',  count: 5  },
                        { label: 'EC2',        count: 12 },
                      ].map(({ label, count }) => (
                        <div key={label}>
                          <div
                            style={{ fontSize: 20, fontWeight: 900, color: '#dc2626', lineHeight: 1 }}
                          >
                            {count}
                          </div>
                          <div style={{ fontSize: 9, color: '#94a3b8', marginTop: 3, fontWeight: 600 }}>
                            {label}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* MITRE ATT&CK Coverage — tactic progress bars */}
              <div
                className="rounded-2xl p-5"
                style={{
                  background: '#ffffff',
                  border: '1px solid #e2e8f0',
                  boxShadow: '0 2px 10px rgba(15,23,42,0.04)',
                }}
              >
                <div className="flex items-center justify-between mb-4">
                  <span className="text-sm font-semibold" style={{ color: '#0f172a' }}>
                    MITRE ATT&amp;CK Coverage
                  </span>
                  <span style={{ fontSize: 10, color: '#64748b', fontWeight: 600 }}>
                    50 techniques · 8 tactics
                  </span>
                </div>

                <div className="space-y-2.5">
                  {[
                    { tactic: 'Initial Access',      covered: 8, total: 10 },
                    { tactic: 'Persistence',         covered: 7, total: 9  },
                    { tactic: 'Priv. Escalation',    covered: 9, total: 9  },
                    { tactic: 'Credential Access',   covered: 6, total: 7  },
                    { tactic: 'Discovery',           covered: 7, total: 10 },
                    { tactic: 'Lateral Movement',    covered: 4, total: 7  },
                    { tactic: 'Collection',          covered: 5, total: 6  },
                    { tactic: 'Exfiltration',        covered: 4, total: 5  },
                  ].map(({ tactic, covered, total }) => {
                    const pct = Math.round((covered / total) * 100);
                    const barColor =
                      pct === 100 ? '#059669' :
                      pct >= 70  ? '#10b981' :
                      pct >= 50  ? '#f97316' : '#ef4444';
                    return (
                      <div key={tactic} className="flex items-center gap-3">
                        <div
                          style={{
                            width: 110, fontSize: 10, color: '#475569',
                            fontWeight: 500, flexShrink: 0,
                          }}
                        >
                          {tactic}
                        </div>
                        <div
                          className="flex-1 rounded-full"
                          style={{ height: 5, background: '#f1f5f9' }}
                        >
                          <div
                            className="h-full rounded-full"
                            style={{ width: `${pct}%`, background: barColor }}
                          />
                        </div>
                        <div
                          style={{
                            fontSize: 10, color: '#94a3b8', fontWeight: 600,
                            flexShrink: 0, width: 28, textAlign: 'right',
                          }}
                        >
                          {covered}/{total}
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div
                  className="flex items-center gap-4 mt-4 pt-3"
                  style={{ borderTop: '1px solid #f1f5f9' }}
                >
                  {[
                    { label: '100%', color: '#059669' },
                    { label: '≥70%', color: '#10b981' },
                    { label: '≥50%', color: '#f97316' },
                    { label: '<50%', color: '#ef4444' },
                  ].map(({ label, color }) => (
                    <div key={label} className="flex items-center gap-1.5">
                      <div style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
                      <span style={{ fontSize: 9, color: '#94a3b8' }}>{label}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════════════════════
          CAPABILITY 2 — IAM SECURITY
      ═══════════════════════════════════════════════════════ */}
      <section
        id="iam"
        className="section"
        style={{ background: '#f8fafc' }}
      >
        <div className="container">
          <div className="grid lg:grid-cols-2 gap-16 items-start">
            {/* Left — visual */}
            <div className="space-y-6 order-2 lg:order-1">
              {/* Stats */}
              <div className="grid grid-cols-3 gap-4">
                <StatCard value="57" label="IAM Rules" color="#7c3aed" />
                <StatCard value="825" label="Findings Analyzed" color="#2563eb" />
                <StatCard value="94%" label="Unused Credentials" color="#10b981" />
              </div>

              {/* IAM Category breakdown */}
              <div
                className="rounded-2xl p-6"
                style={{ background: '#ffffff', border: '1px solid rgba(139,92,246,0.2)', boxShadow: '0 2px 10px rgba(15,23,42,0.05)' }}
              >
                <div className="text-sm font-semibold mb-5" style={{ color: '#0f172a' }}>
                  57 Rules Across 8 IAM Categories
                </div>
                <div className="space-y-3">
                  {[
                    { cat: 'Password & Credentials',     rules: 11, pct: 85, color: '#ef4444' },
                    { cat: 'MFA Enforcement',             rules: 8,  pct: 72, color: '#f97316' },
                    { cat: 'Role & Permission Analysis',  rules: 12, pct: 60, color: '#8b5cf6' },
                    { cat: 'Access Key Hygiene',          rules: 9,  pct: 91, color: '#3b82f6' },
                    { cat: 'Cross-Account Trust',         rules: 7,  pct: 45, color: '#06b6d4' },
                    { cat: 'Service-Linked Roles',        rules: 4,  pct: 30, color: '#10b981' },
                    { cat: 'Root Account Activity',       rules: 4,  pct: 95, color: '#ef4444' },
                    { cat: 'Policy Drift Detection',      rules: 2,  pct: 50, color: '#a78bfa' },
                  ].map((row) => (
                    <div key={row.cat}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs" style={{ color: '#64748b' }}>{row.cat}</span>
                        <span className="text-xs font-semibold" style={{ color: row.color }}>
                          {row.rules} rules
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full" style={{ background: '#e2e8f0' }}>
                        <div
                          className="h-full rounded-full"
                          style={{ width: `${row.pct}%`, background: row.color }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Identity Risk Finding — production-grade */}
              <div
                className="rounded-2xl overflow-hidden"
                style={{ background: '#ffffff', border: '1px solid rgba(124,58,237,0.25)', boxShadow: '0 4px 20px rgba(15,23,42,0.08)' }}
              >
                {/* Dark header */}
                <div
                  className="flex items-center justify-between px-4 py-3"
                  style={{ background: '#1e1b4b', borderBottom: '1px solid rgba(124,58,237,0.3)' }}
                >
                  <div className="flex items-center gap-2">
                    <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 6px #ef4444' }} />
                    <span style={{ fontSize: 10, color: '#e2e8f0', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      Identity Risk Finding
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 10, fontWeight: 900, color: '#f87171',
                      background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.35)',
                      borderRadius: 4, padding: '2px 8px',
                    }}
                  >
                    RISK · 78
                  </span>
                </div>

                {/* Identity header */}
                <div className="px-4 py-3" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#0f172a' }}>svc-deployment-prod</div>
                  <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 2 }}>
                    AWS IAM User · Account <span style={{ fontFamily: 'monospace' }}>588989875114</span> · us-east-1
                  </div>
                </div>

                {/* Permission analysis */}
                <div className="px-4 pt-3 pb-2" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 9 }}>
                    Permission Analysis
                  </div>
                  {[
                    { label: '84 permissions granted', pct: 100, color: '#7c3aed' },
                    { label: '12 used in 90 days',      pct: 14,  color: '#3b82f6' },
                    { label: '72 unused — remove',       pct: 86,  color: '#ef4444' },
                  ].map(({ label, pct, color }) => (
                    <div key={label} className="flex items-center gap-2 mb-2">
                      <div style={{ width: 72, height: 4, borderRadius: 2, background: '#f1f5f9', flexShrink: 0 }}>
                        <div style={{ width: `${pct}%`, height: '100%', borderRadius: 2, background: color }} />
                      </div>
                      <span style={{ fontSize: 10, color: '#475569' }}>{label}</span>
                    </div>
                  ))}
                </div>

                {/* Wildcard permissions */}
                <div className="px-4 py-2.5" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 7 }}>
                    Wildcard Permissions Detected
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {['iam:*', 's3:*', 'ec2:*', 'sts:AssumeRole', 'lambda:*'].map((p) => (
                      <span
                        key={p}
                        style={{
                          fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#dc2626',
                          background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.22)',
                          borderRadius: 4, padding: '2px 6px',
                        }}
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Access keys */}
                <div className="px-4 py-2.5" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 7 }}>
                    Access Keys
                  </div>
                  {[
                    { key: 'AKIA5XNP...X7K2', lastUsed: '487 days ago', status: 'STALE',  color: '#ef4444' },
                    { key: 'AKIA3QRT...M9P4', lastUsed: '23 days ago',  status: 'ACTIVE', color: '#10b981' },
                  ].map(({ key, lastUsed, status, color }) => (
                    <div key={key} className="flex items-center justify-between py-1.5">
                      <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#475569' }}>{key}</span>
                      <div className="flex items-center gap-2">
                        <span style={{ fontSize: 9, color: '#94a3b8' }}>{lastUsed}</span>
                        <span
                          style={{
                            fontSize: 9, fontWeight: 700, color,
                            background: `${color}12`, border: `1px solid ${color}28`,
                            borderRadius: 4, padding: '1px 5px',
                          }}
                        >
                          {status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Recommendation */}
                <div className="px-4 py-3" style={{ background: '#f5f3ff' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#7c3aed' }}>Recommendation: </span>
                  <span style={{ fontSize: 10, color: '#5b21b6' }}>
                    Deactivate key AKIA...X7K2. Restrict to 12 actually-used permissions.
                  </span>
                </div>
              </div>
            </div>

            {/* Right — copy */}
            <div className="order-1 lg:order-2">
              <SectionBadge icon={Lock} label="IAM Security" color="#7c3aed" bg="rgba(124,58,237,0.08)" />

              <h2 className="text-4xl font-black leading-tight mb-6" style={{ color: '#0f172a' }}>
                Close the Identity Attack Surface{' '}
                <span className="gradient-text">Before Attackers Find It</span>
              </h2>

              <div className="space-y-4 mb-8" style={{ color: '#475569', lineHeight: '1.75' }}>
                <p>
                  Identity is the new perimeter in cloud environments, and misconfigured IAM is the
                  root cause of the majority of cloud security incidents. Threat Engine evaluates{' '}
                  <strong style={{ color: '#0f172a' }}>57 IAM rules across 8 categories</strong>,
                  covering everything from abandoned access keys and missing MFA to overpermissive
                  wildcard policies and dangerous cross-account trust relationships.
                </p>
                <p>
                  Unlike generic IAM auditing tools, Threat Engine provides{' '}
                  <strong style={{ color: '#0f172a' }}>least-privilege recommendations</strong>{' '}
                  based on observed API call patterns. Rather than flagging an IAM role as
                  "overpermissive" without guidance, we show you the exact permissions actually used
                  in the last 90 days and generate a tightened policy you can apply in one click.
                </p>
                <p>
                  The cross-account trust mapper visualizes complex trust chains across AWS
                  Organizations, revealing exactly which external principals can assume roles in your
                  accounts, and whether any of those relationships are unexpected, unused, or
                  potentially compromised.
                </p>
              </div>

              <ul className="space-y-3 mb-10">
                <FeatureCheck>
                  57 rules across 8 IAM categories — password policy, MFA, access keys, roles,
                  permissions, cross-account trust, root account, and service accounts
                </FeatureCheck>
                <FeatureCheck>
                  Unused credentials detection — automatically surface access keys and console
                  passwords idle for more than a configurable threshold
                </FeatureCheck>
                <FeatureCheck>
                  Overpermissive role analysis with actionable least-privilege policy recommendations
                  derived from actual CloudTrail usage patterns
                </FeatureCheck>
                <FeatureCheck>
                  Cross-account trust relationship mapping — visualize external principal access
                  and flag unexpected trust chains across your entire AWS Organization
                </FeatureCheck>
                <FeatureCheck>
                  MFA enforcement monitoring across all IAM users, with differentiated coverage
                  for console access vs. programmatic access
                </FeatureCheck>
                <FeatureCheck>
                  Root account activity monitoring — alert on any use of root credentials with
                  full CloudTrail context
                </FeatureCheck>
                <FeatureCheck>
                  Policy drift detection — compare current IAM policies against approved baselines
                  and alert on unauthorized changes
                </FeatureCheck>
                <FeatureCheck>
                  Multi-cloud IAM coverage: AWS IAM, Azure RBAC / Entra ID, GCP IAM — unified
                  in a single risk dashboard
                </FeatureCheck>
              </ul>

              <div className="rounded-2xl overflow-hidden" style={{ background: '#0a0f1a', border: '1px solid rgba(124,58,237,0.2)', boxShadow: '0 4px 24px rgba(124,58,237,0.08)' }}>
                <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(124,58,237,0.15)', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#7c3aed', boxShadow: '0 0 5px #7c3aed', display: 'inline-block' }} />
                  <span style={{ color: '#a78bfa', fontSize: '10px', fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.1em' }}>HOW IT WORKS · IAM SECURITY</span>
                </div>
                <div style={{ padding: '16px' }}>
                  <ol className="space-y-4">
                    <HowItWorksStep dark n={1} title="Identity Enumeration" desc="Enumerate all IAM users, roles, groups, policies, and trust relationships across all configured accounts." />
                    <HowItWorksStep dark n={2} title="Usage Analysis" desc="Cross-reference CloudTrail / audit logs to determine actual API usage vs. granted permissions for each principal." />
                    <HowItWorksStep dark n={3} title="Rule Evaluation" desc="Apply all 57 IAM rules to each principal, flagging violations with severity, evidence, and remediation steps." />
                    <HowItWorksStep dark n={4} title="Recommendation Generation" desc="Produce tightened policy JSON and one-click remediation actions for the highest-severity findings." />
                  </ol>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════════════════════
          CAPABILITY 3 — COMPLIANCE
      ═══════════════════════════════════════════════════════ */}
      <section id="compliance" className="section" style={{ background: '#ffffff' }}>
        <div className="container">
          <div className="grid lg:grid-cols-2 gap-16 items-start">
            <div>
              <SectionBadge icon={BarChart3} label="Compliance" color="#059669" bg="rgba(5,150,105,0.08)" />

              <h2 className="text-4xl font-black leading-tight mb-6" style={{ color: '#0f172a' }}>
                Audit-Ready Compliance{' '}
                <span className="gradient-text">Across 13 Frameworks</span>
              </h2>

              <div className="space-y-4 mb-8" style={{ color: '#475569', lineHeight: '1.75' }}>
                <p>
                  Compliance is no longer a once-a-year exercise. Threat Engine automates continuous
                  compliance monitoring against{' '}
                  <strong style={{ color: '#0f172a' }}>13 industry and regulatory frameworks</strong>{' '}
                  — from CIS Benchmarks v3.0 and NIST CSF 2.0 to PCI-DSS v4.0, HIPAA, and GDPR —
                  so you always know your posture before your auditors ask.
                </p>
                <p>
                  Every compliance finding includes the exact control citation, the affected resource,
                  the evidence collected, and the remediation procedure. When it's time for an audit,
                  Threat Engine generates a complete evidence package with timestamped scan data,
                  control coverage maps, and historical trend reports — eliminating weeks of manual
                  evidence collection.
                </p>
                <p>
                  The custom framework builder lets you create proprietary compliance frameworks that
                  reflect your organization's internal security policies, then track your posture
                  against those policies with the same automated rigor as any built-in framework.
                  Multi-account compliance scoring lets leadership see aggregated posture across the
                  entire portfolio, while engineering teams drill into account-level control gaps.
                </p>
              </div>

              <ul className="space-y-3 mb-10">
                <FeatureCheck>
                  13 pre-built frameworks: CIS AWS/Azure/GCP v3, NIST CSF 2.0, ISO 27001:2022,
                  PCI-DSS v4.0, HIPAA, GDPR, SOC 2 Type II, FedRAMP Moderate, CMMC 2.0, CSA CCM v4
                </FeatureCheck>
                <FeatureCheck>
                  500+ controls mapped and continuously evaluated — control-level pass/fail with
                  evidence links, not just a summary percentage
                </FeatureCheck>
                <FeatureCheck>
                  Automated evidence collection packages for audit readiness — export to PDF, CSV,
                  or JSON with full chain of custody
                </FeatureCheck>
                <FeatureCheck>
                  Custom framework builder — define your own controls, map them to existing rules,
                  and track compliance just like any built-in framework
                </FeatureCheck>
                <FeatureCheck>
                  Multi-account compliance scoring with roll-up views for portfolio-level governance
                  and drill-down for engineering teams
                </FeatureCheck>
                <FeatureCheck>
                  Compliance trend reporting — track how scores change between scans to demonstrate
                  remediation velocity to auditors
                </FeatureCheck>
                <FeatureCheck>
                  Control inheritance mapping — understand which technical controls satisfy
                  multiple framework requirements simultaneously
                </FeatureCheck>
                <FeatureCheck>
                  Scheduled compliance reports delivered to email, Slack, or S3 on a configurable
                  cadence for executive and audit committee distribution
                </FeatureCheck>
              </ul>

              <div className="rounded-2xl overflow-hidden" style={{ background: '#0a0f1a', border: '1px solid rgba(5,150,105,0.2)', boxShadow: '0 4px 24px rgba(5,150,105,0.08)' }}>
                <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(5,150,105,0.15)', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#059669', boxShadow: '0 0 5px #059669', display: 'inline-block' }} />
                  <span style={{ color: '#34d399', fontSize: '10px', fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.1em' }}>HOW IT WORKS · COMPLIANCE</span>
                </div>
                <div style={{ padding: '16px' }}>
                  <ol className="space-y-4">
                    <HowItWorksStep dark n={1} title="Control Mapping" desc="Security rules are pre-mapped to controls across all 13 frameworks. One rule evaluation satisfies multiple framework controls simultaneously." />
                    <HowItWorksStep dark n={2} title="Continuous Evaluation" desc="Every scan cycle re-evaluates all in-scope controls, updating compliance scores in near real-time as resources change." />
                    <HowItWorksStep dark n={3} title="Evidence Linking" desc="Each control result links to the raw API response evidence, scan timestamp, and the specific resource evaluated." />
                    <HowItWorksStep dark n={4} title="Report Generation" desc="On-demand or scheduled reports package evidence, scores, and trend data into audit-ready deliverables." />
                  </ol>
                </div>
              </div>
            </div>

            {/* Right — visual */}
            <div className="space-y-6">
              <div className="grid grid-cols-3 gap-4">
                <StatCard value="13" label="Frameworks" color="#10b981" />
                <StatCard value="500+" label="Controls Mapped" color="#06b6d4" />
                <StatCard value="Auto" label="Audit Reports" color="#2563eb" />
              </div>

              {/* Framework grid */}
              <div
                className="rounded-2xl p-6"
                style={{ background: '#ffffff', border: '1px solid rgba(16,185,129,0.2)', boxShadow: '0 2px 10px rgba(15,23,42,0.05)' }}
              >
                <div className="text-sm font-semibold mb-5" style={{ color: '#0f172a' }}>
                  Supported Compliance Frameworks
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { name: 'CIS Benchmarks v3.0',  score: 87, color: '#10b981' },
                    { name: 'NIST CSF 2.0',          score: 92, color: '#3b82f6' },
                    { name: 'ISO 27001:2022',         score: 79, color: '#8b5cf6' },
                    { name: 'PCI-DSS v4.0',           score: 83, color: '#06b6d4' },
                    { name: 'HIPAA',                  score: 91, color: '#10b981' },
                    { name: 'GDPR',                   score: 76, color: '#f97316' },
                    { name: 'SOC 2 Type II',          score: 88, color: '#3b82f6' },
                    { name: 'FedRAMP Moderate',       score: 74, color: '#a78bfa' },
                    { name: 'CMMC 2.0',               score: 81, color: '#06b6d4' },
                    { name: 'CSA CCM v4',             score: 85, color: '#10b981' },
                  ].map((f) => (
                    <div
                      key={f.name}
                      className="p-3 rounded-xl"
                      style={{ background: '#f8fafc', border: '1px solid #e2e8f0' }}
                    >
                      <div className="text-xs font-medium mb-2" style={{ color: '#475569' }}>
                        {f.name}
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1 rounded-full" style={{ background: '#e2e8f0' }}>
                          <div className="h-full rounded-full" style={{ width: `${f.score}%`, background: f.color }} />
                        </div>
                        <span className="text-xs font-bold" style={{ color: f.color }}>
                          {f.score}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Compliance Scan Result — production-grade */}
              <div
                className="rounded-2xl overflow-hidden"
                style={{ background: '#ffffff', border: '1px solid rgba(16,185,129,0.25)', boxShadow: '0 4px 20px rgba(15,23,42,0.08)' }}
              >
                {/* Dark header */}
                <div
                  className="flex items-center justify-between px-4 py-3"
                  style={{ background: '#052e16', borderBottom: '1px solid rgba(16,185,129,0.3)' }}
                >
                  <div className="flex items-center gap-2">
                    <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 6px #10b981' }} />
                    <span style={{ fontSize: 10, color: '#e2e8f0', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      Compliance Scan Result
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 10, fontWeight: 900, color: '#34d399',
                      background: 'rgba(16,185,129,0.15)', border: '1px solid rgba(16,185,129,0.35)',
                      borderRadius: 4, padding: '2px 8px',
                    }}
                  >
                    SOC 2 TYPE II
                  </span>
                </div>

                {/* Score + period */}
                <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div>
                    <div style={{ fontSize: 9, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 4 }}>
                      Overall Score
                    </div>
                    <div className="flex items-end gap-1.5">
                      <span style={{ fontSize: 32, fontWeight: 900, color: '#10b981', lineHeight: 1 }}>89</span>
                      <span style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>/100</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div style={{ fontSize: 9, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 4 }}>
                      Period
                    </div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#0f172a' }}>Q1 2026</div>
                    <div style={{ fontSize: 10, color: '#94a3b8' }}>847 evidence records</div>
                  </div>
                </div>

                {/* Control breakdown */}
                <div className="px-4 pt-3 pb-2" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 8 }}>
                    Control Status — 64 Evaluated
                  </div>
                  <div className="flex items-center gap-2 mb-2">
                    <div style={{ flex: 1, height: 6, borderRadius: 3, background: '#f1f5f9', overflow: 'hidden' }}>
                      <div style={{ width: '89%', height: '100%', background: 'linear-gradient(90deg, #10b981, #059669)' }} />
                    </div>
                    <span style={{ fontSize: 10, fontWeight: 700, color: '#10b981', flexShrink: 0 }}>57 passed</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div style={{ flex: 1, height: 6, borderRadius: 3, background: '#f1f5f9', overflow: 'hidden' }}>
                      <div style={{ width: '11%', height: '100%', background: '#ef4444' }} />
                    </div>
                    <span style={{ fontSize: 10, fontWeight: 700, color: '#ef4444', flexShrink: 0 }}>7 failed</span>
                  </div>
                </div>

                {/* Top failed controls */}
                <div className="px-4 py-2.5" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 7 }}>
                    Top Failed Controls
                  </div>
                  {[
                    { id: 'CC6.1', desc: 'Logical access controls — MFA gaps', sev: 'HIGH' },
                    { id: 'CC7.2', desc: 'System monitoring — CloudTrail disabled', sev: 'HIGH' },
                    { id: 'CC9.2', desc: 'Risk mitigation — unpatched instances', sev: 'MEDIUM' },
                  ].map(({ id, desc, sev }) => (
                    <div key={id} className="flex items-start gap-2 py-1.5" style={{ borderBottom: '1px solid #f8fafc' }}>
                      <span style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#ef4444', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.18)', borderRadius: 3, padding: '1px 5px', flexShrink: 0, marginTop: 1 }}>{id}</span>
                      <span style={{ fontSize: 10, color: '#475569', flex: 1 }}>{desc}</span>
                      <span style={{ fontSize: 9, fontWeight: 700, color: sev === 'HIGH' ? '#f97316' : '#eab308', flexShrink: 0 }}>{sev}</span>
                    </div>
                  ))}
                </div>

                {/* Export CTA */}
                <div className="px-4 py-3" style={{ background: '#f0fdf4' }}>
                  <div className="flex items-center justify-between">
                    <span style={{ fontSize: 10, color: '#059669', fontWeight: 700 }}>
                      <FileCheck size={11} style={{ display: 'inline', marginRight: 4 }} />
                      Evidence package ready to export
                    </span>
                    <span style={{ fontSize: 10, fontWeight: 700, color: '#10b981', background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 6, padding: '3px 10px', cursor: 'pointer' }}>
                      Export PDF →
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════════════════════
          CAPABILITY 4 — ASSET INVENTORY
      ═══════════════════════════════════════════════════════ */}
      <section id="inventory" className="section" style={{ background: '#f8fafc' }}>
        <div className="container">
          <div className="grid lg:grid-cols-2 gap-16 items-start">
            {/* Left — visual */}
            <div className="space-y-6 order-2 lg:order-1">
              <div className="grid grid-cols-3 gap-4">
                <StatCard value="40+" label="Cloud Services" color="#06b6d4" />
                <StatCard value="6" label="Providers" color="#2563eb" />
                <StatCard value="15 min" label="Scan Cycle" color="#10b981" />
              </div>

              {/* Provider coverage — dark terminal panel */}
              <div className="rounded-2xl overflow-hidden" style={{ background: '#0a0f1a', border: '1px solid rgba(6,182,212,0.2)', boxShadow: '0 4px 24px rgba(6,182,212,0.08)' }}>
                <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(6,182,212,0.15)', padding: '10px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#0891b2', boxShadow: '0 0 5px #0891b2', display: 'inline-block' }} />
                    <span style={{ color: '#22d3ee', fontSize: '10px', fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.1em' }}>ASSET INVENTORY · 6 PROVIDERS</span>
                  </div>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#22c55e', fontSize: 9, fontFamily: 'monospace', fontWeight: 700 }}>
                    <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 4px #22c55e', display: 'inline-block' }} />LIVE
                  </span>
                </div>

                <div style={{ padding: '4px 0' }}>
                  {[
                    { csp: 'AWS',      color: '#f97316', services: 18, resources: '12,450', status: 'SCANNING', pct: 95 },
                    { csp: 'Azure',    color: '#3b82f6', services: 9,  resources: '3,210',  status: 'ACTIVE',   pct: 78 },
                    { csp: 'GCP',      color: '#22c55e', services: 7,  resources: '1,890',  status: 'ACTIVE',   pct: 72 },
                    { csp: 'OCI',      color: '#dc2626', services: 4,  resources: '540',    status: 'ACTIVE',   pct: 55 },
                    { csp: 'AliCloud', color: '#f59e0b', services: 3,  resources: '210',    status: 'ACTIVE',   pct: 40 },
                    { csp: 'IBM',      color: '#7c3aed', services: 2,  resources: '90',     status: 'ACTIVE',   pct: 30 },
                  ].map(({ csp, color, services, resources, status, pct }) => (
                    <div key={csp} style={{ padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)', display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7, width: 80, flexShrink: 0 }}>
                        <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, boxShadow: `0 0 4px ${color}`, display: 'inline-block', flexShrink: 0 }} />
                        <span style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 700 }}>{csp}</span>
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                          <span style={{ color: '#475569', fontSize: 9, fontFamily: 'monospace' }}>{services} services · {resources} assets</span>
                          <span style={{ color: pct >= 70 ? '#10b981' : pct >= 50 ? '#f97316' : '#ef4444', fontSize: 9, fontFamily: 'monospace', fontWeight: 700 }}>{pct}%</span>
                        </div>
                        <div style={{ height: 3, background: 'rgba(255,255,255,0.07)', borderRadius: 2 }}>
                          <div style={{ width: `${pct}%`, height: '100%', background: `linear-gradient(90deg, ${color}, ${color}88)`, borderRadius: 2 }} />
                        </div>
                      </div>
                      <span style={{ fontSize: 8, fontFamily: 'monospace', fontWeight: 700, color: status === 'SCANNING' ? '#f59e0b' : '#10b981', background: status === 'SCANNING' ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.1)', border: `1px solid ${status === 'SCANNING' ? 'rgba(245,158,11,0.3)' : 'rgba(16,185,129,0.25)'}`, borderRadius: 4, padding: '2px 6px', flexShrink: 0 }}>
                        {status}
                      </span>
                    </div>
                  ))}
                </div>

                <div style={{ background: '#0f172a', borderTop: '1px solid rgba(6,182,212,0.1)', padding: '8px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: '#475569', fontSize: 9, fontFamily: 'monospace' }}>next scan · <span style={{ color: '#94a3b8' }}>11 min</span></span>
                  <span style={{ color: '#0891b2', fontSize: 10, fontFamily: 'monospace', fontWeight: 700 }}>18,390 total assets</span>
                </div>
              </div>

              {/* Drift Alert — production-grade */}
              <div
                className="rounded-2xl overflow-hidden"
                style={{ background: '#ffffff', border: '1px solid rgba(249,115,22,0.25)', boxShadow: '0 4px 20px rgba(15,23,42,0.08)' }}
              >
                {/* Dark header */}
                <div
                  className="flex items-center justify-between px-4 py-3"
                  style={{ background: '#1c0a00', borderBottom: '1px solid rgba(249,115,22,0.3)' }}
                >
                  <div className="flex items-center gap-2">
                    <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#f97316', boxShadow: '0 0 6px #f97316' }} />
                    <span style={{ fontSize: 10, color: '#e2e8f0', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      Configuration Drift Alert
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 10, fontWeight: 900, color: '#fb923c',
                      background: 'rgba(249,115,22,0.15)', border: '1px solid rgba(249,115,22,0.35)',
                      borderRadius: 4, padding: '2px 8px',
                    }}
                  >
                    3 CHANGES
                  </span>
                </div>

                {/* Scan comparison */}
                <div className="px-4 py-3 flex items-center gap-3" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div className="text-center">
                    <div style={{ fontSize: 9, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Prev Scan</div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#10b981' }}>18,342</div>
                    <div style={{ fontSize: 9, color: '#94a3b8' }}>resources</div>
                  </div>
                  <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, #10b981, #f97316)', borderRadius: 1 }} />
                  <div className="text-center">
                    <div style={{ fontSize: 9, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Now</div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#f97316' }}>18,345</div>
                    <div style={{ fontSize: 9, color: '#94a3b8' }}>+3 changed</div>
                  </div>
                </div>

                {/* Drift changes */}
                <div className="px-4 pt-3 pb-2" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 8 }}>
                    Changed Resources
                  </div>
                  {[
                    { resource: 'sg-0a4f2b1c9d8e7f6', change: 'Port 22 opened to 0.0.0.0/0', sev: 'CRITICAL', color: '#ef4444' },
                    { resource: 'bucket-prod-logs',    change: 'S3 Block Public Access disabled', sev: 'HIGH',     color: '#f97316' },
                    { resource: 'iam-role-ci-deploy',  change: 'AdministratorAccess attached',    sev: 'HIGH',     color: '#f97316' },
                  ].map(({ resource, change, sev, color }) => (
                    <div
                      key={resource}
                      className="flex items-start gap-2 p-2.5 rounded-lg mb-2"
                      style={{ background: `${color}07`, border: `1px solid ${color}18` }}
                    >
                      <AlertTriangle size={11} style={{ color, flexShrink: 0, marginTop: 1 }} />
                      <div className="flex-1 min-w-0">
                        <div style={{ fontSize: 10, fontFamily: 'monospace', fontWeight: 600, color: '#0f172a', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {resource}
                        </div>
                        <div style={{ fontSize: 9, color: '#64748b', marginTop: 1 }}>{change}</div>
                      </div>
                      <span style={{ fontSize: 9, fontWeight: 800, color, flexShrink: 0 }}>{sev}</span>
                    </div>
                  ))}
                </div>

                {/* Relationship graph stats */}
                <div className="px-4 py-2.5" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 8 }}>
                    Relationship Graph
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-center">
                    {[
                      { count: '18.3K', label: 'Nodes' },
                      { count: '47.2K', label: 'Edges' },
                      { count: '369',   label: 'Rules' },
                      { count: '6',     label: 'CSPs' },
                    ].map(({ count, label }) => (
                      <div key={label}>
                        <div style={{ fontSize: 14, fontWeight: 900, color: '#0891b2', lineHeight: 1 }}>{count}</div>
                        <div style={{ fontSize: 9, color: '#94a3b8', marginTop: 2, fontWeight: 600 }}>{label}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Action */}
                <div className="px-4 py-3" style={{ background: '#fff7ed' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#f97316' }}>Auto-Alert: </span>
                  <span style={{ fontSize: 10, color: '#c2410c' }}>
                    Slack notification sent to #security-alerts · Jira ticket SEC-4821 created
                  </span>
                </div>
              </div>
            </div>

            {/* Right — copy */}
            <div className="order-1 lg:order-2">
              <SectionBadge icon={Globe} label="Asset Inventory" color="#0891b2" bg="rgba(8,145,178,0.08)" />

              <h2 className="text-4xl font-black leading-tight mb-6" style={{ color: '#0f172a' }}>
                Complete Visibility Across{' '}
                <span className="gradient-text">Every Cloud Asset</span>
              </h2>

              <div className="space-y-4 mb-8" style={{ color: '#475569', lineHeight: '1.75' }}>
                <p>
                  You cannot secure what you cannot see. Threat Engine's asset inventory engine
                  discovers and catalogs{' '}
                  <strong style={{ color: '#0f172a' }}>40+ cloud service types</strong> across all
                  six supported providers in a continuous 15-minute scan cycle, giving your security
                  team a real-time view of everything running in your environment — including
                  resources provisioned outside your standard IaC pipeline.
                </p>
                <p>
                  Beyond simple enumeration, Threat Engine builds a{' '}
                  <strong style={{ color: '#0f172a' }}>relationship graph</strong> that maps
                  dependencies between resources — which EC2 instances use which security groups,
                  which S3 buckets are exposed through which CloudFront distributions, which RDS
                  instances have which IAM roles attached. This graph powers attack path analysis,
                  blast radius estimation, and impact assessment.
                </p>
                <p>
                  Drift detection compares each scan's snapshot against the previous baseline,
                  surfacing configuration changes that could represent unauthorized modification or
                  security regression. A security group that had port 22 opened to 0.0.0.0/0 between
                  scans is flagged immediately — before your next scheduled audit.
                </p>
              </div>

              <ul className="space-y-3 mb-10">
                <FeatureCheck>
                  Discovery of 40+ cloud service types: compute, storage, networking, databases,
                  serverless, containers, IAM, CDN, DNS, messaging, and more
                </FeatureCheck>
                <FeatureCheck>
                  Unified multi-cloud asset inventory across AWS, Azure, GCP, OCI, AliCloud, and
                  IBM Cloud in a single searchable catalog
                </FeatureCheck>
                <FeatureCheck>
                  Real-time relationship graph — automatically maps dependencies between resources
                  to power blast radius and attack path analysis
                </FeatureCheck>
                <FeatureCheck>
                  Drift detection — compare scan-over-scan snapshots and alert on configuration
                  changes that violate security baselines
                </FeatureCheck>
                <FeatureCheck>
                  Custom tagging and grouping — organize assets by team, application, environment,
                  or any custom taxonomy for targeted reporting
                </FeatureCheck>
                <FeatureCheck>
                  Shadow IT detection — surface resources provisioned outside standard pipelines
                  that exist in your cloud accounts but not your CMDB
                </FeatureCheck>
                <FeatureCheck>
                  Asset lifecycle tracking — monitor resource creation, modification, and deletion
                  events with full audit history
                </FeatureCheck>
                <FeatureCheck>
                  Export to CMDB, ServiceNow, or JIRA via API and native integrations
                </FeatureCheck>
              </ul>

              <div className="rounded-2xl overflow-hidden" style={{ background: '#0a0f1a', border: '1px solid rgba(37,99,235,0.2)', boxShadow: '0 4px 24px rgba(37,99,235,0.08)' }}>
                <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(37,99,235,0.15)', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#2563eb', boxShadow: '0 0 5px #2563eb', display: 'inline-block' }} />
                  <span style={{ color: '#60a5fa', fontSize: '10px', fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.1em' }}>HOW IT WORKS · ASSET INVENTORY</span>
                </div>
                <div style={{ padding: '16px' }}>
                  <ol className="space-y-4">
                    <HowItWorksStep dark n={1} title="Scheduled Discovery" desc="Every 15 minutes, discovery workers fan out across all configured accounts and regions, calling provider APIs to enumerate resources." />
                    <HowItWorksStep dark n={2} title="Normalization" desc="Raw API responses are normalized into a provider-agnostic asset schema, enriched with metadata and classification tags." />
                    <HowItWorksStep dark n={3} title="Relationship Mapping" desc="YAML-defined relationship rules (369 curated rules) link related resources into a graph structure stored in Neo4j." />
                    <HowItWorksStep dark n={4} title="Drift Analysis" desc="Snapshot diffing compares current vs. previous state, triggering alerts for any configuration changes that breach security policy." />
                  </ol>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════════════════════
          CAPABILITY 5 — CODE SECURITY
      ═══════════════════════════════════════════════════════ */}
      <section id="secops" className="section" style={{ background: '#ffffff' }}>
        <div className="container">
          <div className="grid lg:grid-cols-2 gap-16 items-start">
            <div>
              <SectionBadge icon={Code2} label="Code Security" color="#ea580c" bg="rgba(234,88,12,0.08)" />

              <h2 className="text-4xl font-black leading-tight mb-6" style={{ color: '#0f172a' }}>
                Catch Misconfigurations{' '}
                <span className="gradient-text">Before They Reach Production</span>
              </h2>

              <div className="space-y-4 mb-8" style={{ color: '#475569', lineHeight: '1.75' }}>
                <p>
                  Security misconfigurations born in Infrastructure-as-Code are the leading cause of
                  cloud security incidents — and they're entirely preventable. Threat Engine's code
                  security module scans IaC files in{' '}
                  <strong style={{ color: '#0f172a' }}>14 languages and frameworks</strong> with
                  500+ rules, blocking insecure configurations from merging into your default branch
                  through deep CI/CD integration.
                </p>
                <p>
                  Beyond simple syntax checking, Threat Engine performs{' '}
                  <strong style={{ color: '#0f172a' }}>semantic analysis</strong> that understands
                  the runtime implications of your infrastructure code — an S3 bucket defined with
                  <code style={{ color: '#2563eb', fontSize: '0.85em', background: '#eff6ff', padding: '1px 4px', borderRadius: 3 }}> acl = "public-read"</code> is
                  flagged regardless of whether it's Terraform, CloudFormation JSON, or a Pulumi
                  Python program.
                </p>
                <p>
                  Policy-as-Code support through OPA/Conftest allows your security team to encode
                  organizational guardrails as versioned Rego policies that automatically apply to
                  every IaC PR. Engineering teams see inline PR comments with exact line numbers,
                  failing rule descriptions, and remediation snippets — eliminating back-and-forth
                  between security and engineering.
                </p>
              </div>

              <ul className="space-y-3 mb-10">
                <FeatureCheck>
                  14 IaC languages: Terraform HCL, CloudFormation (JSON/YAML), Kubernetes manifests,
                  Helm charts, Dockerfile, AWS CDK, Bicep, ARM templates, Pulumi (Python/TS/Go),
                  Serverless Framework, Crossplane, and Ansible
                </FeatureCheck>
                <FeatureCheck>
                  500+ security rules covering networking, IAM, encryption, logging, access control,
                  and best practice violation detection
                </FeatureCheck>
                <FeatureCheck>
                  Native CI/CD integration: GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket
                  Pipelines, and Azure DevOps — PR-blocking with inline comments
                </FeatureCheck>
                <FeatureCheck>
                  Policy-as-Code via OPA/Conftest — encode organizational guardrails as versioned
                  Rego policies that automatically apply to every IaC change
                </FeatureCheck>
                <FeatureCheck>
                  SAST for infrastructure code — detect hardcoded secrets, API keys, and passwords
                  in IaC files before they reach version control
                </FeatureCheck>
                <FeatureCheck>
                  Module and provider scanning — evaluate third-party Terraform modules and
                  provider plugins for known vulnerabilities
                </FeatureCheck>
                <FeatureCheck>
                  Compliance pre-check — validate IaC against CIS, NIST, and custom frameworks
                  before deployment, giving developers immediate feedback
                </FeatureCheck>
                <FeatureCheck>
                  Suppressions and exceptions management — centrally manage approved exceptions with
                  expiry dates and approval workflows
                </FeatureCheck>
              </ul>

              <div className="rounded-2xl overflow-hidden" style={{ background: '#0a0f1a', border: '1px solid rgba(234,88,12,0.2)', boxShadow: '0 4px 24px rgba(234,88,12,0.08)' }}>
                <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(234,88,12,0.15)', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#ea580c', boxShadow: '0 0 5px #ea580c', display: 'inline-block' }} />
                  <span style={{ color: '#fb923c', fontSize: '10px', fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.1em' }}>HOW IT WORKS · CODE SECURITY</span>
                </div>
                <div style={{ padding: '16px' }}>
                  <ol className="space-y-4">
                    <HowItWorksStep dark n={1} title="PR Trigger" desc="A webhook from GitHub/GitLab triggers the scanner on every pull request that modifies IaC files." />
                    <HowItWorksStep dark n={2} title="Language Detection & Parsing" desc="Files are automatically classified by IaC language and parsed into an AST for semantic analysis." />
                    <HowItWorksStep dark n={3} title="Rule & Policy Evaluation" desc="Built-in rules and custom OPA policies are evaluated against the parsed AST, producing findings with line-level precision." />
                    <HowItWorksStep dark n={4} title="PR Comment & Gate" desc="Findings are posted as inline PR review comments. High-severity findings set a blocking PR status check." />
                  </ol>
                </div>
              </div>
            </div>

            {/* Right — visual */}
            <div className="space-y-6">
              <div className="grid grid-cols-3 gap-4">
                <StatCard value="14" label="IaC Languages" color="#f97316" />
                <StatCard value="500+" label="Security Rules" color="#2563eb" />
                <StatCard value="PR-Block" label="Enforcement" color="#10b981" />
              </div>

              {/* Language support grid */}
              <div
                className="rounded-2xl p-6"
                style={{ background: '#ffffff', border: '1px solid rgba(249,115,22,0.15)', boxShadow: '0 2px 10px rgba(15,23,42,0.05)' }}
              >
                <div className="text-sm font-semibold mb-4" style={{ color: '#0f172a' }}>
                  Supported IaC Languages
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    'Terraform HCL',
                    'CloudFormation JSON',
                    'CloudFormation YAML',
                    'Kubernetes YAML',
                    'Helm Charts',
                    'Dockerfile',
                    'AWS CDK (TS/Python)',
                    'Azure Bicep',
                    'ARM Templates',
                    'Pulumi (Python/TS)',
                    'Serverless Framework',
                    'Crossplane',
                    'Ansible Playbooks',
                    'Kustomize',
                  ].map((lang) => (
                    <div
                      key={lang}
                      className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
                      style={{
                        background: '#fff7ed',
                        border: '1px solid rgba(249,115,22,0.15)',
                        color: '#475569',
                      }}
                    >
                      <FileCode2 size={11} style={{ color: '#f97316', flexShrink: 0 }} />
                      {lang}
                    </div>
                  ))}
                </div>
              </div>

              {/* PR Security Scan — production-grade */}
              <div
                className="rounded-2xl overflow-hidden"
                style={{ background: '#ffffff', border: '1px solid rgba(234,88,12,0.25)', boxShadow: '0 4px 20px rgba(15,23,42,0.08)' }}
              >
                {/* Dark header */}
                <div
                  className="flex items-center justify-between px-4 py-3"
                  style={{ background: '#1c0a00', borderBottom: '1px solid rgba(234,88,12,0.3)' }}
                >
                  <div className="flex items-center gap-2">
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#f97316', boxShadow: '0 0 6px #f97316' }} />
                    <span style={{ fontSize: 11, fontWeight: 700, color: '#fed7aa', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      IaC Security Scan
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span style={{ fontSize: 10, color: '#94a3b8', fontFamily: 'monospace' }}>PR #247</span>
                    <span
                      style={{
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: 'rgba(239,68,68,0.2)',
                        color: '#fca5a5',
                        fontSize: 10,
                        fontWeight: 700,
                        border: '1px solid rgba(239,68,68,0.3)',
                      }}
                    >
                      BLOCKED
                    </span>
                  </div>
                </div>

                {/* File header */}
                <div
                  style={{
                    padding: '10px 14px',
                    background: '#0f172a',
                    borderBottom: '1px solid #1e293b',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  <GitBranch size={11} color="#64748b" />
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#94a3b8' }}>
                    modules/s3/main.tf
                  </span>
                  <span style={{ marginLeft: 'auto', fontSize: 10, color: '#ef4444', fontWeight: 600 }}>3 issues found</span>
                </div>

                {/* Code diff */}
                <div style={{ background: '#0f172a', padding: '8px 0' }}>
                  {[
                    { ln: '10', code: 'resource "aws_s3_bucket" "data_lake" {', type: 'normal' },
                    { ln: '11', code: '  bucket = "prod-analytics-data-lake"', type: 'normal' },
                    { ln: '12', code: '  acl    = "public-read"', type: 'bad', rule: '[TE-S3-001] Public ACL — HIGH · CIS 2.1.5' },
                    { ln: '13', code: '  force_destroy = true', type: 'warn', rule: '[TE-S3-019] Force destroy enabled — MEDIUM' },
                    { ln: '14', code: '', type: 'normal' },
                    { ln: '15', code: '  versioning {', type: 'normal' },
                    { ln: '16', code: '    enabled = false', type: 'bad', rule: '[TE-S3-008] Versioning disabled — MEDIUM · CIS 2.1.3' },
                    { ln: '17', code: '  }', type: 'normal' },
                  ].map(({ ln, code, type, rule }) => (
                    <div key={ln}>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          background: type === 'bad' ? 'rgba(239,68,68,0.12)' : type === 'warn' ? 'rgba(249,115,22,0.1)' : 'transparent',
                          borderLeft: type === 'bad' ? '2px solid #ef4444' : type === 'warn' ? '2px solid #f97316' : '2px solid transparent',
                        }}
                      >
                        <span style={{ width: 28, textAlign: 'right', paddingRight: 8, fontSize: 10, color: '#475569', fontFamily: 'monospace', flexShrink: 0 }}>
                          {ln}
                        </span>
                        <span style={{ fontSize: 11, fontFamily: 'monospace', color: type === 'bad' ? '#fca5a5' : type === 'warn' ? '#fed7aa' : '#94a3b8', padding: '2px 8px', flex: 1 }}>
                          {code}
                        </span>
                      </div>
                      {rule && (
                        <div
                          style={{
                            padding: '4px 8px 4px 30px',
                            background: type === 'bad' ? 'rgba(239,68,68,0.08)' : 'rgba(249,115,22,0.06)',
                            fontSize: 10,
                            color: type === 'bad' ? '#f87171' : '#fb923c',
                            fontFamily: 'sans-serif',
                            borderLeft: type === 'bad' ? '2px solid #ef4444' : '2px solid #f97316',
                          }}
                        >
                          {rule}
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                {/* CI status footer */}
                <div
                  style={{
                    padding: '12px 14px',
                    background: '#fff7ed',
                    borderTop: '1px solid rgba(234,88,12,0.2)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444', flexShrink: 0 }} />
                  <span style={{ fontSize: 11, color: '#92400e', fontWeight: 600 }}>
                    threat-engine/iac-scan — 3 findings block merge
                  </span>
                  <span style={{ marginLeft: 'auto', fontSize: 10, color: '#b45309' }}>Fix required</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════════════════════
          CAPABILITY 6 — DATA SECURITY
      ═══════════════════════════════════════════════════════ */}
      <section id="datasec" className="section" style={{ background: '#f8fafc' }}>
        <div className="container">
          <div className="grid lg:grid-cols-2 gap-16 items-start">
            {/* Left — visual */}
            <div className="space-y-6 order-2 lg:order-1">
              <div className="grid grid-cols-3 gap-4">
                <StatCard value="62" label="Classification Rules" color="#0891b2" />
                <StatCard value="6" label="Data Types" color="#7c3aed" />
                <StatCard value="Global" label="Region Visibility" color="#10b981" />
              </div>

              {/* Data type breakdown */}
              <div
                className="rounded-2xl p-6"
                style={{ background: '#ffffff', border: '1px solid rgba(6,182,212,0.2)', boxShadow: '0 2px 10px rgba(15,23,42,0.05)' }}
              >
                <div className="text-sm font-semibold mb-5" style={{ color: '#0f172a' }}>
                  Data Classification Results
                </div>
                <div className="space-y-3">
                  {[
                    { type: 'PII (Personal Data)',         buckets: 34, risk: 'HIGH',     color: '#ef4444', pct: 80 },
                    { type: 'PHI (Health Records)',         buckets: 12, risk: 'CRITICAL', color: '#ef4444', pct: 90 },
                    { type: 'PCI (Payment Card)',           buckets: 8,  risk: 'CRITICAL', color: '#ef4444', pct: 95 },
                    { type: 'Credentials & Secrets',       buckets: 21, risk: 'HIGH',     color: '#f97316', pct: 85 },
                    { type: 'Intellectual Property',       buckets: 15, risk: 'MEDIUM',   color: '#f97316', pct: 60 },
                    { type: 'Public / Non-Sensitive',      buckets: 89, risk: 'LOW',      color: '#10b981', pct: 10 },
                  ].map((d) => (
                    <div key={d.type}>
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span style={{ color: '#475569' }}>{d.type}</span>
                        <div className="flex items-center gap-2">
                          <span style={{ color: '#94a3b8' }}>{d.buckets} resources</span>
                          <span className="font-bold" style={{ color: d.color }}>{d.risk}</span>
                        </div>
                      </div>
                      <div className="h-1.5 rounded-full" style={{ background: '#e2e8f0' }}>
                        <div className="h-full rounded-full" style={{ width: `${d.pct}%`, background: d.color }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Data Exposure Alert — production-grade */}
              <div
                className="rounded-2xl overflow-hidden"
                style={{ background: '#ffffff', border: '1px solid rgba(8,145,178,0.25)', boxShadow: '0 4px 20px rgba(15,23,42,0.08)' }}
              >
                {/* Dark header */}
                <div
                  className="flex items-center justify-between px-4 py-3"
                  style={{ background: '#0c1a2e', borderBottom: '1px solid rgba(8,145,178,0.3)' }}
                >
                  <div className="flex items-center gap-2">
                    <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#f59e0b', boxShadow: '0 0 6px #f59e0b' }} />
                    <span style={{ fontSize: 10, color: '#e2e8f0', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      Data Exposure Alert
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: 10, fontWeight: 900, color: '#fbbf24',
                      background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.35)',
                      borderRadius: 4, padding: '2px 8px',
                    }}
                  >
                    3 BUCKETS EXPOSED
                  </span>
                </div>

                {/* Exposed resources */}
                <div className="px-4 pt-3 pb-2" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 8 }}>
                    PII-Containing Buckets — Public Access
                  </div>
                  {[
                    { bucket: 's3://prod-customer-exports',  region: 'us-east-1',    records: '1.2M', color: '#ef4444' },
                    { bucket: 's3://analytics-raw-data',     region: 'eu-west-1',    records: '847K', color: '#ef4444' },
                    { bucket: 's3://backup-user-profiles',   region: 'ap-south-1',   records: '203K', color: '#f97316' },
                  ].map(({ bucket, region, records, color }) => (
                    <div
                      key={bucket}
                      className="flex items-center gap-2 p-2.5 rounded-lg mb-2"
                      style={{ background: `${color}07`, border: `1px solid ${color}18` }}
                    >
                      <Database size={11} style={{ color, flexShrink: 0 }} />
                      <div className="flex-1 min-w-0">
                        <div
                          style={{
                            fontSize: 9, fontFamily: 'monospace', fontWeight: 600, color: '#0f172a',
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                          }}
                        >
                          {bucket}
                        </div>
                        <div style={{ fontSize: 9, color: '#94a3b8', marginTop: 1 }}>{region} · {records} records</div>
                      </div>
                      <span
                        style={{
                          fontSize: 9, fontWeight: 700, color,
                          background: `${color}12`, border: `1px solid ${color}28`,
                          borderRadius: 4, padding: '1px 5px', flexShrink: 0,
                        }}
                      >
                        PUBLIC
                      </span>
                    </div>
                  ))}
                </div>

                {/* Encryption posture summary */}
                <div className="px-4 py-2.5" style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: '#64748b', letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 8 }}>
                    Encryption Posture
                  </div>
                  {[
                    { service: 'S3 Buckets',      pct: 79,  encrypted: 142, total: 179 },
                    { service: 'RDS Instances',   pct: 90,  encrypted: 28,  total: 31  },
                    { service: 'EBS Volumes',     pct: 77,  encrypted: 189, total: 247 },
                    { service: 'DynamoDB Tables', pct: 100, encrypted: 44,  total: 44  },
                  ].map(({ service, pct, encrypted, total }) => {
                    const barColor = pct === 100 ? '#10b981' : pct >= 85 ? '#3b82f6' : '#f97316';
                    return (
                      <div key={service} className="flex items-center gap-2 mb-2">
                        <div style={{ width: 88, fontSize: 10, color: '#475569', flexShrink: 0 }}>{service}</div>
                        <div className="flex-1 h-1.5 rounded-full" style={{ background: '#f1f5f9' }}>
                          <div style={{ width: `${pct}%`, height: '100%', borderRadius: 2, background: barColor }} />
                        </div>
                        <span style={{ fontSize: 9, fontWeight: 700, color: barColor, width: 32, textAlign: 'right', flexShrink: 0 }}>
                          {encrypted}/{total}
                        </span>
                      </div>
                    );
                  })}
                </div>

                {/* Recommendation */}
                <div className="px-4 py-3" style={{ background: '#ecfeff' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#0891b2' }}>Action Required: </span>
                  <span style={{ fontSize: 10, color: '#0e7490' }}>
                    Enable S3 Block Public Access on 3 buckets. Encrypt 37 unencrypted S3 volumes.
                  </span>
                </div>
              </div>
            </div>

            {/* Right — copy */}
            <div className="order-1 lg:order-2">
              <SectionBadge icon={Cloud} label="Data Security" color="#0891b2" bg="rgba(8,145,178,0.08)" />

              <h2 className="text-4xl font-black leading-tight mb-6" style={{ color: '#0f172a' }}>
                Know Where Your Sensitive Data Lives{' '}
                <span className="gradient-text">Across Every Region</span>
              </h2>

              <div className="space-y-4 mb-8" style={{ color: '#475569', lineHeight: '1.75' }}>
                <p>
                  Data sprawl is the silent risk in cloud environments. Engineers create buckets,
                  databases, and storage volumes daily — and sensitive data ends up in unexpected
                  places. Threat Engine's data security module applies{' '}
                  <strong style={{ color: '#0f172a' }}>62 classification rules</strong> to
                  automatically discover PII, PHI, PCI, credentials, and intellectual property
                  across S3, RDS, DynamoDB, and other storage services across every region in your
                  cloud accounts.
                </p>
                <p>
                  Encryption posture assessment identifies storage resources that contain sensitive
                  data but lack encryption at rest, encryption in transit, or proper key management
                  — and cross-references those gaps against your compliance framework requirements
                  to produce a prioritized remediation list.
                </p>
                <p>
                  Data residency compliance checking ensures that data classified as subject to
                  geographic restrictions (GDPR, data sovereignty laws) is not inadvertently
                  replicated to non-compliant regions. Cross-region visibility gives you a global
                  map of where sensitive data lives and whether it's crossing jurisdictional
                  boundaries without authorization.
                </p>
              </div>

              <ul className="space-y-3 mb-10">
                <FeatureCheck>
                  62 data classification rules covering PII, PHI, PCI, credentials, IP, and
                  publicly available data across all storage service types
                </FeatureCheck>
                <FeatureCheck>
                  Automated data discovery across S3, RDS (MySQL, PostgreSQL, SQL Server), DynamoDB,
                  Azure Blob Storage, Azure SQL, Google Cloud Storage, and BigQuery
                </FeatureCheck>
                <FeatureCheck>
                  Encryption posture assessment — identify storage with sensitive data that lacks
                  encryption at rest, in transit, or proper KMS key rotation
                </FeatureCheck>
                <FeatureCheck>
                  Data access analytics — surface who and what has access to sensitive data stores,
                  flagging overpermissive access and public exposure
                </FeatureCheck>
                <FeatureCheck>
                  Data residency compliance checking — flag sensitive data crossing jurisdictional
                  boundaries in violation of GDPR, data sovereignty, or internal policy
                </FeatureCheck>
                <FeatureCheck>
                  Cross-region visibility — global map of sensitive data locations updated with
                  every scan cycle
                </FeatureCheck>
                <FeatureCheck>
                  Sensitive data in backup and snapshot stores — extend discovery to RDS snapshots,
                  EBS snapshots, and backup vaults that are often overlooked
                </FeatureCheck>
                <FeatureCheck>
                  Data security posture score per account — measure and track how well each
                  account protects its sensitive data over time
                </FeatureCheck>
              </ul>

              <div className="rounded-2xl overflow-hidden" style={{ background: '#0a0f1a', border: '1px solid rgba(8,145,178,0.2)', boxShadow: '0 4px 24px rgba(8,145,178,0.08)' }}>
                <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(8,145,178,0.15)', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#0891b2', boxShadow: '0 0 5px #0891b2', display: 'inline-block' }} />
                  <span style={{ color: '#22d3ee', fontSize: '10px', fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.1em' }}>HOW IT WORKS · DATA SECURITY</span>
                </div>
                <div style={{ padding: '16px' }}>
                  <ol className="space-y-4">
                    <HowItWorksStep dark n={1} title="Storage Service Enumeration" desc="Discovery enumerates all storage services across every region, collecting metadata including ACLs, encryption config, and access policies." />
                    <HowItWorksStep dark n={2} title="Data Sampling & Classification" desc="Sampled object/row content is analyzed against 62 classification rules using pattern matching and ML-assisted detection." />
                    <HowItWorksStep dark n={3} title="Encryption & Access Analysis" desc="Encryption configuration and access control policies are evaluated for each sensitive data store identified in step 2." />
                    <HowItWorksStep dark n={4} title="Residency & Compliance Mapping" desc="Geographic location of data is cross-referenced against applicable residency requirements and compliance framework controls." />
                  </ol>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── CTA ──────────────────────────────────────────────── */}
      <section style={{ padding: '80px 0', background: 'linear-gradient(160deg, #060b14 0%, #0d1117 60%, #080d18 100%)', position: 'relative', overflow: 'hidden' }}>
        <div aria-hidden="true" style={{ position: 'absolute', inset: 0, opacity: 0.04, backgroundImage: 'linear-gradient(#3b82f6 1px, transparent 1px), linear-gradient(90deg, #3b82f6 1px, transparent 1px)', backgroundSize: '48px 48px' }} />
        <div aria-hidden="true" style={{ position: 'absolute', top: -80, left: '25%', width: 400, height: 400, borderRadius: '50%', background: 'radial-gradient(circle, rgba(37,99,235,0.1) 0%, transparent 70%)', pointerEvents: 'none' }} />
        <div aria-hidden="true" style={{ position: 'absolute', bottom: -60, right: '20%', width: 350, height: 350, borderRadius: '50%', background: 'radial-gradient(circle, rgba(124,58,237,0.08) 0%, transparent 70%)', pointerEvents: 'none' }} />

        <div className="container" style={{ position: 'relative', textAlign: 'center' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(37,99,235,0.12)', border: '1px solid rgba(37,99,235,0.3)', borderRadius: 20, padding: '5px 14px', marginBottom: 24, fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace', color: '#60a5fa', textTransform: 'uppercase' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e', display: 'inline-block' }} />
            Ready to See It Live?
          </span>

          <h2 style={{ fontSize: 'clamp(28px, 4vw, 52px)', fontWeight: 900, letterSpacing: '-0.03em', lineHeight: 1.1, maxWidth: 600, margin: '0 auto 18px', color: '#f1f5f9' }}>
            Request a{' '}
            <span style={{ background: 'linear-gradient(90deg, #3b82f6, #7c3aed)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>Personalized Demo</span>
          </h2>

          <p style={{ color: '#94a3b8', fontSize: 17, maxWidth: 480, margin: '0 auto 36px', lineHeight: 1.65 }}>
            We'll scan a portion of your actual cloud environment during the demo so you see real findings — not a scripted slideshow.
          </p>

          {/* Live demo stats */}
          <div style={{ display: 'flex', gap: 20, justifyContent: 'center', flexWrap: 'wrap', marginBottom: 36 }}>
            {[
              { v: '< 30 sec', l: 'to connect account', color: '#3b82f6' },
              { v: '< 5 min',  l: 'first findings live',  color: '#22c55e' },
              { v: '100%',     l: 'real cloud data',       color: '#7c3aed' },
            ].map(({ v, l, color }) => (
              <div key={l} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '12px 20px', minWidth: 140, textAlign: 'center' }}>
                <div style={{ color, fontSize: 22, fontWeight: 900, lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{v}</div>
                <div style={{ color: '#64748b', fontSize: 11, marginTop: 4 }}>{l}</div>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link href="/contact" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'linear-gradient(135deg, #2563eb, #1d4ed8)', color: '#fff', fontWeight: 700, fontSize: 15, padding: '14px 32px', borderRadius: 12, border: '1px solid rgba(255,255,255,0.1)', boxShadow: '0 8px 28px rgba(37,99,235,0.4)', textDecoration: 'none' }}>
              Request Demo <ArrowRight size={16} />
            </Link>
            <Link href="/pricing" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'rgba(255,255,255,0.06)', color: '#e2e8f0', fontWeight: 600, fontSize: 15, padding: '14px 32px', borderRadius: 12, border: '1px solid rgba(255,255,255,0.12)', textDecoration: 'none' }}>
              View Pricing
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
