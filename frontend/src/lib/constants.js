// Cloud Security Posture Management Dashboard Constants

// Empty string = relative URLs (local dev with Next.js rewrites proxying to NLB)
// Full URL = direct calls (production Docker build with baked env vars)
export const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';
export const TENANT_ID = process.env.NEXT_PUBLIC_TENANT_ID || '';

// Default CSP and scan ID for engines that require them (IAM, DataSec)
export const CSP_DEFAULT = 'aws';
export const SCAN_ID_DEFAULT = 'latest';

export const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

export const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info'
};

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export const CLOUD_PROVIDERS = {
  aws:      { name: 'AWS',      color: '#FF9900', bgColor: 'rgba(255,153,0,0.15)',  textColor: '#FF9900'  },
  azure:    { name: 'Azure',    color: '#0078D4', bgColor: 'rgba(0,120,212,0.15)',  textColor: '#0078D4'  },
  gcp:      { name: 'GCP',      color: '#4285F4', bgColor: 'rgba(66,133,244,0.15)', textColor: '#4285F4'  },
  oci:      { name: 'OCI',      color: '#F80000', bgColor: 'rgba(248,0,0,0.15)',    textColor: '#F80000'  },
  alicloud: { name: 'AliCloud', color: '#FF6A00', bgColor: 'rgba(255,106,0,0.15)',  textColor: '#FF6A00'  },
  ibm:      { name: 'IBM',      color: '#1F70C1', bgColor: 'rgba(31,112,193,0.15)', textColor: '#1F70C1'  },
  k8s:      { name: 'K8S',      color: '#326CE5', bgColor: 'rgba(50,108,229,0.15)', textColor: '#326CE5'  },
};

// SLA thresholds by severity (days until breach)
export const SLA_THRESHOLDS = {
  critical: 7,
  high: 14,
  medium: 30,
  low: 90,
};

export const FRAMEWORKS = [
  // CIS — one row; each CSP column shows its own CIS benchmark score
  { id: 'CIS',         name: 'CIS Benchmark',    shortName: 'CIS',       color: '#22c55e', group: 'CIS' },
  // Regulatory
  { id: 'PCI_DSS',     name: 'PCI DSS v4.0.1',   shortName: 'PCI DSS',   color: '#f97316', group: 'Regulatory' },
  { id: 'HIPAA',       name: 'HIPAA',            shortName: 'HIPAA',     color: '#ef4444', group: 'Regulatory' },
  { id: 'GDPR',        name: 'GDPR',             shortName: 'GDPR',      color: '#8b5cf6', group: 'Regulatory' },
  { id: 'SOC2',        name: 'SOC 2',            shortName: 'SOC 2',     color: '#ec4899', group: 'Regulatory' },
  { id: 'ISO27001',    name: 'ISO 27001:2022',   shortName: 'ISO 27001', color: '#06b6d4', group: 'Regulatory' },
  { id: 'CANADA_PBMM', name: 'Canada PBMM',      shortName: 'PBMM',      color: '#dc2626', group: 'Regulatory' },
  { id: 'RBI_BANK',    name: 'RBI Bank',         shortName: 'RBI Bank',  color: '#f59e0b', group: 'Regulatory' },
  { id: 'RBI_NBFC',    name: 'RBI NBFC',         shortName: 'RBI NBFC',  color: '#d97706', group: 'Regulatory' },
  // US Government
  { id: 'NIST',        name: 'NIST 800-53',      shortName: 'NIST',      color: '#3b82f6', group: 'US Gov' },
  { id: 'FedRAMP',     name: 'FedRAMP Moderate', shortName: 'FedRAMP',   color: '#1d4ed8', group: 'US Gov' },
  { id: 'CISA_CE',     name: 'CISA CE',          shortName: 'CISA CE',   color: '#1e3a8a', group: 'US Gov' },
];

export const NAV_ITEMS = [
  { label: 'Dashboard', href: '/dashboard', icon: 'LayoutDashboard' },
  {
    label: 'Inventory',
    href: '/inventory',
    icon: 'Server',
    children: [
      { label: 'Assets',       href: '/inventory' },
      { label: 'Architecture', href: '/inventory/architecture' },
    ],
  },
  {
    label: 'Threats',
    href: '/threats',
    icon: 'AlertTriangle',
    subtitle: 'ATT&CK · Attack Paths',
    accentColor: '#EA580C',
    badgeKey: 'threatCriticalHighCount',
    children: [
      { label: 'Command Room',     href: '/threats' },
      { label: 'ATT&CK Coverage',  href: '/threats/attack-map' },
      { label: 'Graph Explorer',   href: '/threats/graph' },
      { label: 'Trends & Posture', href: '/threats/trends' },
    ],
  },
  {
    label: 'Vulnerabilities',
    href: '/vulnerability',
    icon: 'Bug',
    subtitle: 'VM · CVE · SBOM',
    children: [
      { label: 'Dashboard',    href: '/vulnerability' },
      { label: 'Scans',        href: '/vulnerability/scans' },
      { label: 'CVE Explorer', href: '/vulnerability/cves' },
      { label: 'Agents',       href: '/vulnerability/agents' },
    ],
  },
  { label: 'Risk', href: '/risk', icon: 'Activity', subtitle: 'FAIR Model' },
  {
    label: 'Compliance',
    href: '/compliance',
    icon: 'ClipboardCheck',
    subtitle: 'CIS · NIST · PCI · HIPAA',
    children: [
      { label: 'Frameworks',         href: '/compliance' },
      { label: 'Multi-Cloud Matrix', href: '/compliance/matrix' },
      { label: 'Remediation Queue',  href: '/compliance/remediation' },
    ],
  },

  // ── CLOUD POSTURE ─────────────────────────────────────────────────────────
  { sectionLabel: 'CLOUD POSTURE' },
  {
    label: 'Cloud Posture',
    href: '/misconfig',
    icon: 'Shield',
    subtitle: 'CSPM',
    children: [
      { label: 'Misconfigurations',  href: '/misconfig',          icon: 'ShieldAlert' },
      { label: 'IAM Security',       href: '/iam',                icon: 'KeyRound'    },
      { label: 'Network Security',   href: '/network-security',   icon: 'Network'     },
      { label: 'Encryption',         href: '/encryption',         icon: 'Lock'        },
      { label: 'Container Security', href: '/container-security', icon: 'Container'   },
      { label: 'AI Security',        href: '/ai-security',        icon: 'Brain'       },
    ],
  },

  // ── DETECTION & DATA ──────────────────────────────────────────────────────
  { sectionLabel: 'DETECTION & DATA' },
  { label: 'CDR',  href: '/cdr',  icon: 'Eye',       subtitle: 'Cloud Detection & Response' },
  { label: 'CWPP', href: '/cwpp', icon: 'Container', subtitle: 'Cloud Workload Protection'  },
  {
    label: 'Data Security',
    href: '/datasec',
    icon: 'Lock',
    subtitle: 'DSPM · Database',
    children: [
      { label: 'Data Posture',      href: '/datasec',           icon: 'Lock'     },
      { label: 'Database Security', href: '/database-security', icon: 'Database' },
    ],
  },

  // ── CODE SECURITY ─────────────────────────────────────────────────────────
  { sectionLabel: 'CODE SECURITY' },
  {
    label: 'Code Security',
    href: '/secops',
    icon: 'Code',
    subtitle: 'SAST · SCA · IaC',
    children: [
      { label: 'Overview', href: '/secops',          icon: 'Code'       },
      { label: 'Projects', href: '/secops/projects', icon: 'FileText'   },
      { label: 'Reports',  href: '/secops/reports',  icon: 'ScrollText' },
    ],
  },

  // ── PLATFORM ──────────────────────────────────────────────────────────────
  { sectionLabel: 'PLATFORM' },
  { label: 'Reports', href: '/reports', icon: 'FileText' },
  {
    label: 'Onboarding',
    href: '/onboarding',
    icon: 'UserPlus',
    children: [
      { label: 'Cloud Accounts', href: '/onboarding' },
      { label: 'Users',          href: '/onboarding/users' },
      { label: 'Tenants',        href: '/onboarding/tenants' },
      { label: 'Scans',          href: '/scans' },
    ],
  },
  {
    label: 'Policies',
    href: '/policies',
    icon: 'BookOpen',
    children: [
      { label: 'All Policies',    href: '/policies' },
      { label: 'Rule Management', href: '/rules' },
    ],
  },
  {
    label: 'Settings',
    href: '/settings',
    icon: 'Settings',
    children: [
      { label: 'Platform',      href: '/settings' },
      { label: 'Notifications', href: '/settings/notifications' },
    ],
  },

  // ── ADMINISTRATION ────────────────────────────────────────────────────────
  { sectionLabel: 'ADMINISTRATION' },
  {
    label: 'Admin Dashboard',
    href: '/admin/dashboard',
    icon: 'LayoutGrid',
    permission: 'platform:admin',
    roles: ['platform_admin'],
  },
  {
    label: 'Admin Billing',
    href: '/admin/billing',
    icon: 'DollarSign',
    permission: 'platform:admin',
    roles: ['platform_admin'],
  },
];

// Engine calls route through Next.js rewrites -> NLB -> nginx ingress -> engine.
// Each prefix matches an ingress rule that strips the prefix and forwards to the engine.
// BFF views route through the gateway at /gateway/api/v1/views/{page}.
export const ENGINE_ENDPOINTS = {
  onboarding: '/onboarding',
  discoveries: '/discoveries',
  check: '/check',
  inventory: '/inventory',
  threat: '/threat',
  compliance: '/compliance',
  iam: '/iam',
  datasec: '/datasec',
  secops: '/secops',
  risk: '/risk',
  gateway: '/gateway',
  rule: '/rule',
  vulnerability: '/vulnerability',
  cnapp: '/cnapp',
  cwpp: '/cwpp',
  billing: '/gateway',
  platformAdmin: '/gateway',
};

// Engines that require a paid tier to access.
// UI uses this to grey out nav items and show upgrade tooltip.
export const GATED_ENGINES = {
  datasec:           { requiredTier: 'pro',        label: 'Data Security' },
  secops:            { requiredTier: 'pro',        label: 'Code Security' },
  vulnerability:     { requiredTier: 'pro',        label: 'Vulnerability' },
  'ai-security':     { requiredTier: 'enterprise', label: 'AI Security' },
  encryption:        { requiredTier: 'enterprise', label: 'Encryption' },
  'database-security': { requiredTier: 'enterprise', label: 'Database Security' },
  'container-security': { requiredTier: 'enterprise', label: 'Container Security' },
};
