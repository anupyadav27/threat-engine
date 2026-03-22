import Link from 'next/link';
import {
  ArrowRight, Shield, CheckCircle2, Cloud, Globe, Building2,
  Code2, Zap, Lock, BarChart3, Database, Server,
  Users, FileCheck, AlertTriangle, Target,
} from 'lucide-react';

export const metadata = {
  title: 'Solutions — Threat Engine CSPM',
  description:
    'Threat Engine CSPM solutions for AWS, Azure, GCP, OCI, Enterprise teams, and DevSecOps pipelines.',
};

function Check({ children }) {
  return (
    <li className="flex items-start gap-2.5">
      <CheckCircle2 size={15} className="flex-shrink-0 mt-0.5" style={{ color: '#10b981' }} />
      <span style={{ color: '#475569', fontSize: '0.9rem', lineHeight: 1.6 }}>{children}</span>
    </li>
  );
}

const SOLUTIONS = [
  {
    id: 'aws',
    label: 'For AWS',
    badge: 'Amazon Web Services',
    color: '#f97316',
    bg: 'rgba(249,115,22,0.06)',
    border: 'rgba(249,115,22,0.15)',
    icon: Cloud,
    headline: 'Complete AWS Security Posture in Minutes',
    sub: 'The most comprehensive AWS CSPM available — covering EC2, S3, IAM, RDS, Lambda, EKS, and 35+ more services with 200+ security rules out of the box.',
    checks: [
      'S3 public access, ACLs, encryption, and replication security',
      'IAM least-privilege analysis across users, roles, and policies',
      'EC2 security groups, public exposure, and patch compliance',
      'RDS encryption, public accessibility, and backup validation',
      'Lambda execution role over-provisioning and code exposure',
      'CloudTrail, Config, and GuardDuty integration status',
      'AWS Organizations multi-account consolidated view',
      'CIS AWS Benchmark v1.4 and v2.0 automated scoring',
    ],
    panelLabel: 'AWS SCAN',
    panelColor: '#f97316',
    panelRows: [
      { id: 'A-0341', text: 'S3 bucket public read · prod-backup-bucket', sev: 'CRITICAL', color: '#ef4444' },
      { id: 'A-0892', text: 'IAM user with admin policy · svc-deploy-bot', sev: 'HIGH', color: '#f97316' },
      { id: 'A-0210', text: 'EC2 SG allows 0.0.0.0/0 on port 22', sev: 'HIGH', color: '#f97316' },
      { id: 'A-0504', text: 'RDS publicly accessible · prod-postgres', sev: 'MEDIUM', color: '#eab308' },
    ],
    stat1: { v: '35+', l: 'Services' }, stat2: { v: '200+', l: 'Rules' }, stat3: { v: 'CIS v2.0', l: 'Benchmark' },
    panel2Label: 'SECURITY POSTURE · AWS',
    panel2Rows: [
      { label: 'Critical findings',  value: '12',   color: '#ef4444', sub: 'S3 public exposure · IAM wildcard actions' },
      { label: 'High severity',      value: '47',   color: '#f97316', sub: 'SG open ports · root access · no MFA' },
      { label: 'CIS AWS v2.0',       value: '87%',  color: '#10b981', sub: '74 of 85 controls passing continuously' },
      { label: 'Services covered',   value: '35+',  color: '#3b82f6', sub: 'EC2, S3, IAM, RDS, Lambda, EKS, and more' },
    ],
  },
  {
    id: 'azure',
    label: 'For Azure',
    badge: 'Microsoft Azure',
    color: '#3b82f6',
    bg: 'rgba(59,130,246,0.06)',
    border: 'rgba(59,130,246,0.15)',
    icon: Globe,
    headline: 'Azure Security at Enterprise Scale',
    sub: 'Unified visibility across Azure subscriptions, resource groups, and Entra ID tenants. Covers storage, compute, network, identity, and PaaS services.',
    checks: [
      'Azure Blob Storage public access and encryption posture',
      'Entra ID (Azure AD) RBAC over-provisioning analysis',
      'VM and VMSS network exposure and patch status',
      'Azure SQL, Cosmos DB, and PostgreSQL security assessment',
      'NSG rule analysis — identify open internet-facing ports',
      'Azure Key Vault access policy and rotation monitoring',
      'CIS Azure Benchmark and MCSB automated scoring',
      'Microsoft Defender for Cloud gap analysis',
    ],
    panelLabel: 'AZURE SCAN',
    panelColor: '#3b82f6',
    panelRows: [
      { id: 'AZ-011', text: 'Blob storage public access · analytics-data', sev: 'CRITICAL', color: '#ef4444' },
      { id: 'AZ-089', text: 'Entra ID MFA disabled for admin account', sev: 'CRITICAL', color: '#ef4444' },
      { id: 'AZ-230', text: 'NSG allows RDP from internet · prod-nsg', sev: 'HIGH', color: '#f97316' },
      { id: 'AZ-450', text: 'Key Vault soft-delete disabled', sev: 'MEDIUM', color: '#eab308' },
    ],
    stat1: { v: '9+', l: 'Services' }, stat2: { v: '127', l: 'Identities Scanned' }, stat3: { v: '91%', l: 'MCSB Score' },
    panel2Label: 'IDENTITY POSTURE · AZURE',
    panel2Rows: [
      { label: 'Entra ID users',     value: '127',  color: '#3b82f6', sub: '29 users without MFA enabled' },
      { label: 'Privileged roles',   value: '18',   color: '#f97316', sub: '4 over-provisioned admin accounts' },
      { label: 'MCSB compliance',    value: '91%',  color: '#10b981', sub: '55 of 60 baseline controls pass' },
      { label: 'NSG rule issues',    value: '7',    color: '#ef4444', sub: 'Internet-facing ports open to 0.0.0.0/0' },
    ],
  },
  {
    id: 'gcp',
    label: 'For GCP',
    badge: 'Google Cloud Platform',
    color: '#22c55e',
    bg: 'rgba(34,197,94,0.06)',
    border: 'rgba(34,197,94,0.15)',
    icon: Server,
    headline: 'Google Cloud Security Without the Blind Spots',
    sub: 'Full coverage of GCP projects, folders, and organizations. IAM, GCS, Compute Engine, Cloud SQL, GKE, and Cloud Functions all assessed continuously.',
    checks: [
      'GCS bucket IAM policies, public access, and encryption',
      'GCP IAM service account key rotation and over-provisioning',
      'Compute Engine firewall rules — internet exposure analysis',
      'Cloud SQL public IP, SSL, and backup configuration',
      'GKE cluster security — RBAC, network policies, node configs',
      'VPC Service Controls and organization policy assessment',
      'CIS GCP Benchmark v2.0 automated scoring',
      'GCP Security Command Center gap analysis',
    ],
    panelLabel: 'GCP SCAN',
    panelColor: '#22c55e',
    panelRows: [
      { id: 'G-0045', text: 'GCS bucket allUsers has Storage Viewer role', sev: 'CRITICAL', color: '#ef4444' },
      { id: 'G-0218', text: 'Service account key > 90 days old', sev: 'HIGH', color: '#f97316' },
      { id: 'G-0334', text: 'Firewall rule allows all egress 0.0.0.0/0', sev: 'MEDIUM', color: '#eab308' },
      { id: 'G-0112', text: 'Cloud SQL instance has no SSL required', sev: 'MEDIUM', color: '#eab308' },
    ],
    stat1: { v: '7+', l: 'Services' }, stat2: { v: 'GKE', l: 'K8s Security' }, stat3: { v: 'CIS v2.0', l: 'Benchmark' },
    panel2Label: 'COMPUTE SECURITY · GCP',
    panel2Rows: [
      { label: 'GKE clusters',       value: '3',    color: '#22c55e', sub: '1 with RBAC disabled · 2 workload identity off' },
      { label: 'Firewall rules',     value: '89',   color: '#f97316', sub: '12 rules allow all-egress to internet' },
      { label: 'Service accounts',   value: '45',   color: '#3b82f6', sub: '8 with owner or editor primitive roles' },
      { label: 'CIS GCP v2.0',       value: '84%',  color: '#10b981', sub: '63 of 75 controls passing continuously' },
    ],
  },
  {
    id: 'oci',
    label: 'For OCI',
    badge: 'Oracle Cloud Infrastructure',
    color: '#dc2626',
    bg: 'rgba(220,38,38,0.06)',
    border: 'rgba(220,38,38,0.15)',
    icon: Database,
    headline: 'OCI Security Visibility, Finally',
    sub: 'Threat Engine is one of the few CSPM platforms with native OCI support — covering compartments, Object Storage, Compute, Autonomous DB, and OCI IAM.',
    checks: [
      'OCI Object Storage visibility settings and pre-authenticated requests',
      'OCI IAM group memberships, policy statements, and admin access',
      'Compute instance public IP exposure and NSG rules',
      'Autonomous Database network access and encryption',
      'VCN security list and network security group analysis',
      'OCI Vault key rotation and secret age monitoring',
      'CIS OCI Foundations Benchmark automated scoring',
      'Tenancy-wide consolidated multi-compartment view',
    ],
    panelLabel: 'OCI SCAN',
    panelColor: '#dc2626',
    panelRows: [
      { id: 'O-0023', text: 'Object Storage bucket public access', sev: 'CRITICAL', color: '#ef4444' },
      { id: 'O-0087', text: 'IAM admin policy not restricted by tenancy', sev: 'HIGH', color: '#f97316' },
      { id: 'O-0156', text: 'Compute instance with public IP · db-host', sev: 'MEDIUM', color: '#eab308' },
      { id: 'O-0201', text: 'Vault key rotation not configured', sev: 'LOW', color: '#3b82f6' },
    ],
    stat1: { v: '4+', l: 'Services' }, stat2: { v: '540', l: 'Resources Found' }, stat3: { v: '79%', l: 'CIS OCI Score' },
    panel2Label: 'COMPARTMENT SCAN · OCI',
    panel2Rows: [
      { label: 'Compartments',       value: '4',    color: '#dc2626', sub: 'Tenancy-wide coverage · all regions' },
      { label: 'Object Storage',     value: '12',   color: '#f97316', sub: '3 buckets with public access enabled' },
      { label: 'IAM policies',       value: '23',   color: '#eab308', sub: '5 policies with overly-broad allow' },
      { label: 'CIS OCI',            value: '79%',  color: '#10b981', sub: '41 of 52 foundation controls passing' },
    ],
  },
  {
    id: 'enterprise',
    label: 'For Enterprises',
    badge: 'Enterprise Teams',
    color: '#7c3aed',
    bg: 'rgba(124,58,237,0.06)',
    border: 'rgba(124,58,237,0.15)',
    icon: Building2,
    headline: 'CSPM Built for Complex Enterprise Environments',
    sub: 'Purpose-built for enterprises with hundreds of accounts, multiple cloud providers, regional compliance requirements, and dedicated security teams.',
    checks: [
      'Unified multi-cloud, multi-account, multi-region dashboard',
      'RBAC for security team roles — analysts, engineers, managers',
      'Compliance audit packs for GDPR, HIPAA, SOC 2, PCI-DSS, ISO 27001',
      'Automated evidence collection and audit-ready export packages',
      'Executive risk score dashboard with trend reporting',
      'SLA-driven alert routing and escalation workflows',
      'SSO/SAML integration with Okta, Azure AD, Ping Identity',
      'Dedicated onboarding and customer success support',
    ],
    panelLabel: 'ENTERPRISE DASHBOARD',
    panelColor: '#7c3aed',
    panelRows: [
      { id: 'E-RISK', text: 'Portfolio risk score: 82/100 · ↓4 from last week', sev: 'SCORE', color: '#7c3aed' },
      { id: 'E-COMP', text: 'SOC 2 Type II: 94% · PCI-DSS: 88% · HIPAA: 91%', sev: 'COMPLY', color: '#22c55e' },
      { id: 'E-ACCT', text: '14 accounts · 3 providers · 18,345 assets tracked', sev: 'SCOPE', color: '#3b82f6' },
      { id: 'E-SLA',  text: 'Critical SLA: 4 hrs · 0 breaches this quarter', sev: 'SLA ✓', color: '#10b981' },
    ],
    stat1: { v: '6', l: 'Cloud Providers' }, stat2: { v: '13+', l: 'Frameworks' }, stat3: { v: '500+', l: 'Controls Mapped' },
    panel2Label: 'PORTFOLIO OVERVIEW · ENTERPRISE',
    panel2Rows: [
      { label: 'AWS posture',        value: '89%',  color: '#10b981', sub: '14 accounts · us-east-1, eu-west-1, ap-south-1' },
      { label: 'Azure posture',      value: '91%',  color: '#10b981', sub: '3 subscriptions · Entra ID consolidated' },
      { label: 'GCP posture',        value: '87%',  color: '#22c55e', sub: '2 organizations · 1,890 assets tracked' },
      { label: 'Open critical',      value: '23',   color: '#ef4444', sub: '↓ down from 41 last week · 4h SLA active' },
    ],
  },
  {
    id: 'devsecops',
    label: 'For DevSecOps',
    badge: 'DevSecOps Teams',
    color: '#ea580c',
    bg: 'rgba(234,88,12,0.06)',
    border: 'rgba(234,88,12,0.15)',
    icon: Code2,
    headline: 'Shift Security Left — Without Slowing Dev Teams Down',
    sub: 'Native CI/CD integration, PR-blocking IaC scanning, and real-time cloud feedback loops that let security scale with engineering velocity.',
    checks: [
      'GitHub, GitLab, Bitbucket, and Azure DevOps PR integration',
      'IaC scanning in 14 languages — Terraform, CDK, CloudFormation, Helm, and more',
      'Inline PR review comments with finding details and remediation snippets',
      'Blocking PR status checks on high-severity findings',
      'OPA/Conftest policy-as-code for custom guardrails',
      'Slack and Jira integration for developer-friendly alerting',
      'API-first — integrate scan results into any internal toolchain',
      'SBOM generation and dependency vulnerability correlation',
    ],
    panelLabel: 'CI/CD GATE',
    panelColor: '#ea580c',
    panelRows: [
      { id: 'PR-247', text: 'modules/s3/main.tf · acl="public-read" · line 3', sev: 'BLOCKED', color: '#ef4444' },
      { id: 'PR-247', text: 'modules/iam/role.tf · wildcard actions allowed', sev: 'BLOCKED', color: '#ef4444' },
      { id: 'PR-247', text: 'k8s/deployment.yaml · privileged container', sev: 'WARN', color: '#f97316' },
      { id: 'PR-247', text: '3 findings · PR merge blocked · fix required', sev: 'GATE', color: '#ea580c' },
    ],
    stat1: { v: '14', l: 'IaC Languages' }, stat2: { v: '500+', l: 'Rules' }, stat3: { v: 'PR-Block', l: 'Enforcement' },
    panel2Label: 'CI/CD METRICS · DEVSECOPS',
    panel2Rows: [
      { label: 'PRs scanned',        value: '247',  color: '#ea580c', sub: 'Last 30 days across all connected repos' },
      { label: 'Blocked merges',     value: '34',   color: '#ef4444', sub: '13.8% block rate · critical severity only' },
      { label: 'IaC findings',       value: '89',   color: '#f97316', sub: 'Across 14 languages · Terraform leads (52%)' },
      { label: 'Mean time to fix',   value: '2.3h', color: '#10b981', sub: 'Avg developer resolution after finding alert' },
    ],
  },
];

export default function SolutionsPage() {
  return (
    <>
      {/* ── HERO ──────────────────────────────────────────────────── */}
      <section
        className="hero-bg grid-bg relative overflow-hidden"
        style={{ paddingTop: '140px', paddingBottom: '80px' }}
      >
        <div className="absolute top-0 left-1/3 w-[500px] h-[500px] rounded-full pointer-events-none" style={{ background: 'radial-gradient(circle, rgba(37,99,235,0.07) 0%, transparent 70%)', transform: 'translate(-50%,-50%)' }} />
        <div className="absolute bottom-0 right-0 w-[400px] h-[400px] rounded-full pointer-events-none" style={{ background: 'radial-gradient(circle, rgba(124,58,237,0.05) 0%, transparent 70%)' }} />

        <div className="container relative">
          <div className="text-center max-w-3xl mx-auto">
            <div className="badge badge-purple mb-6">Solutions</div>
            <h1 className="text-5xl font-black tracking-tight leading-[1.1] mb-6" style={{ color: '#0f172a' }}>
              The Right Security for{' '}
              <span className="gradient-text">Every Cloud Context</span>
            </h1>
            <p className="text-xl mb-10" style={{ color: '#475569', lineHeight: '1.7' }}>
              Whether you're securing a single AWS account or a multi-cloud enterprise environment,
              Threat Engine adapts to your context — delivering relevant findings, the right
              benchmarks, and integrations that fit your workflow.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-4">
              <Link href="/contact" className="btn-primary">
                Get a Demo <ArrowRight size={16} />
              </Link>
              <Link href="/platform" className="btn-secondary">
                Explore Platform
              </Link>
            </div>

            {/* Provider pills */}
            <div className="flex flex-wrap items-center justify-center gap-3 mt-12">
              {[
                { label: 'AWS',     color: '#f97316' },
                { label: 'Azure',   color: '#3b82f6' },
                { label: 'GCP',     color: '#22c55e' },
                { label: 'OCI',     color: '#dc2626' },
                { label: 'AliCloud',color: '#f59e0b' },
                { label: 'IBM',     color: '#7c3aed' },
              ].map(({ label, color }) => (
                <span
                  key={label}
                  style={{ background: `${color}12`, border: `1px solid ${color}30`, borderRadius: 20, padding: '4px 14px', color, fontSize: 12, fontWeight: 700 }}
                >
                  {label}
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── SOLUTION SECTIONS ─────────────────────────────────────── */}
      {SOLUTIONS.map((s, idx) => {
        const Icon = s.icon;
        const isEven = idx % 2 === 0;
        return (
          <section
            key={s.id}
            id={s.id}
            className="section"
            style={{ background: isEven ? '#ffffff' : '#fafafa' }}
          >
            <div className="container">
              <div className="grid lg:grid-cols-2 gap-16 items-start">

                {/* Left — copy */}
                <div className={isEven ? '' : 'lg:order-2'}>
                  <div
                    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full mb-6"
                    style={{ background: s.bg, border: `1px solid ${s.border}` }}
                  >
                    <Icon size={13} style={{ color: s.color }} />
                    <span className="text-xs font-semibold uppercase tracking-widest" style={{ color: s.color }}>
                      {s.badge}
                    </span>
                  </div>

                  <h2 className="text-4xl font-black leading-tight mb-5" style={{ color: '#0f172a' }}>
                    {s.headline}
                  </h2>
                  <p className="text-lg mb-6" style={{ color: '#475569', lineHeight: '1.7' }}>
                    {s.sub}
                  </p>

                  <ul className="space-y-2.5 mb-8">
                    {s.checks.map(c => <Check key={c}>{c}</Check>)}
                  </ul>

                  <div className="flex flex-wrap gap-4">
                    <Link href="/contact" className="btn-primary" style={{ fontSize: 14 }}>
                      See {s.label} Demo <ArrowRight size={14} />
                    </Link>
                    <Link href="/platform" className="btn-secondary" style={{ fontSize: 14 }}>
                      Platform Details
                    </Link>
                  </div>
                </div>

                {/* Right — dark panel */}
                <div className={`space-y-5 ${isEven ? '' : 'lg:order-1'}`}>
                  {/* Stat cards */}
                  <div className="grid grid-cols-3 gap-3">
                    {[s.stat1, s.stat2, s.stat3].map(({ v, l }) => (
                      <div key={l} className="rounded-xl p-4 text-center" style={{ background: '#ffffff', border: '1px solid #e2e8f0', boxShadow: '0 2px 8px rgba(15,23,42,0.06)' }}>
                        <div className="text-2xl font-black mb-1" style={{ color: s.color }}>{v}</div>
                        <div style={{ color: '#64748b', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{l}</div>
                      </div>
                    ))}
                  </div>

                  {/* Dark finding panel */}
                  <div className="rounded-2xl overflow-hidden" style={{ border: `1px solid ${s.color}25`, boxShadow: `0 4px 24px ${s.color}10` }}>
                    {/* Header */}
                    <div className="flex items-center justify-between px-5 py-3" style={{ background: '#0f172a', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                      <div className="flex items-center gap-2">
                        <div style={{ width: 7, height: 7, borderRadius: '50%', background: s.color, boxShadow: `0 0 6px ${s.color}` }} />
                        <span style={{ fontSize: 11, fontWeight: 700, color: '#e2e8f0', letterSpacing: '0.08em', fontFamily: 'monospace' }}>{s.panelLabel}</span>
                      </div>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: '#22c55e', fontFamily: 'monospace', fontWeight: 700 }}>
                        <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 5px #22c55e', display: 'inline-block' }} />LIVE
                      </span>
                    </div>

                    {/* Findings */}
                    <div style={{ background: '#080d18' }}>
                      {s.panelRows.map(({ id, text, sev, color }, i) => (
                        <div
                          key={`${id}-${i}`}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 12,
                            padding: '12px 20px 12px 17px',
                            borderBottom: i < s.panelRows.length - 1 ? '1px solid rgba(255,255,255,0.07)' : 'none',
                            borderLeft: `3px solid ${color}`,
                          }}
                        >
                          <span style={{ color: '#64748b', fontSize: 11, fontFamily: 'monospace', width: 52, flexShrink: 0 }}>{id}</span>
                          <span style={{ color: '#cbd5e1', fontSize: 12, flex: 1, lineHeight: 1.4 }}>{text}</span>
                          <span style={{
                            background: `${color}22`, border: `1px solid ${color}55`,
                            borderRadius: 4, padding: '3px 0', color, fontSize: 10,
                            fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.05em',
                            flexShrink: 0, width: 64, textAlign: 'center',
                          }}>{sev}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Provider analytics panel */}
                  <div className="rounded-2xl overflow-hidden" style={{ background: '#060b14', border: `1px solid ${s.color}22`, boxShadow: `0 4px 20px ${s.color}08` }}>
                    {/* Header */}
                    <div style={{ background: '#0f172a', borderBottom: '1px solid rgba(255,255,255,0.08)', padding: '10px 20px', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 7, height: 7, borderRadius: '50%', background: s.color, boxShadow: `0 0 6px ${s.color}`, display: 'inline-block', flexShrink: 0 }} />
                      <span style={{ color: s.color, fontSize: 11, fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.08em' }}>{s.panel2Label}</span>
                    </div>
                    {/* Rows */}
                    <div style={{ padding: '4px 0' }}>
                      {s.panel2Rows.map(({ label, value, color, sub }, i, arr) => (
                        <div
                          key={label}
                          style={{
                            padding: '12px 20px 12px 17px',
                            borderBottom: i < arr.length - 1 ? '1px solid rgba(255,255,255,0.06)' : 'none',
                            borderLeft: `3px solid ${color}`,
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 4 }}>
                            <span style={{ color: '#94a3b8', fontSize: 12, fontWeight: 600, lineHeight: 1.3 }}>{label}</span>
                            <span style={{ color, fontSize: 18, fontWeight: 900, fontVariantNumeric: 'tabular-nums', lineHeight: 1, marginLeft: 12 }}>{value}</span>
                          </div>
                          <div style={{ color: '#64748b', fontSize: 11, lineHeight: 1.5 }}>{sub}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
        );
      })}

      {/* ── FINAL CTA ─────────────────────────────────────────────── */}
      <section style={{ padding: '80px 0', background: 'linear-gradient(160deg, #060b14 0%, #0d1117 60%, #080d18 100%)', position: 'relative', overflow: 'hidden' }}>
        <div aria-hidden="true" style={{ position: 'absolute', inset: 0, opacity: 0.04, backgroundImage: 'linear-gradient(#3b82f6 1px, transparent 1px), linear-gradient(90deg, #3b82f6 1px, transparent 1px)', backgroundSize: '48px 48px' }} />
        <div aria-hidden="true" style={{ position: 'absolute', top: -100, left: '20%', width: 500, height: 500, borderRadius: '50%', background: 'radial-gradient(circle, rgba(37,99,235,0.1) 0%, transparent 70%)', pointerEvents: 'none' }} />

        <div className="container" style={{ position: 'relative', textAlign: 'center' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(37,99,235,0.12)', border: '1px solid rgba(37,99,235,0.3)', borderRadius: 20, padding: '5px 14px', marginBottom: 24, fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', fontFamily: 'monospace', color: '#60a5fa', textTransform: 'uppercase' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e', display: 'inline-block' }} />
            One Platform · All Clouds
          </span>

          <h2 style={{ fontSize: 'clamp(28px, 4vw, 52px)', fontWeight: 900, letterSpacing: '-0.03em', lineHeight: 1.1, maxWidth: 640, margin: '0 auto 18px', color: '#f1f5f9' }}>
            Connect your cloud in{' '}
            <span style={{ background: 'linear-gradient(90deg, #3b82f6, #7c3aed)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>30 seconds</span>
          </h2>

          <p style={{ color: '#94a3b8', fontSize: 17, maxWidth: 480, margin: '0 auto 36px', lineHeight: 1.65 }}>
            No agents. No code changes. Connect your cloud account and see real findings immediately — across any combination of AWS, Azure, GCP, and OCI.
          </p>

          <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link href="/contact" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'linear-gradient(135deg, #2563eb, #1d4ed8)', color: '#fff', fontWeight: 700, fontSize: 15, padding: '14px 32px', borderRadius: 12, border: '1px solid rgba(255,255,255,0.1)', boxShadow: '0 8px 28px rgba(37,99,235,0.4)', textDecoration: 'none' }}>
              Request a Demo <ArrowRight size={16} />
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
