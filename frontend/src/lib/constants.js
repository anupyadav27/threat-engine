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
  // CIS per-provider benchmarks
  { id: 'CIS_AWS',          name: 'CIS AWS',          shortName: 'CIS AWS',    color: '#FF9900', group: 'CIS' },
  { id: 'CIS_AZURE',        name: 'CIS Azure',         shortName: 'CIS Azure',  color: '#0078D4', group: 'CIS' },
  { id: 'CIS_GCP',          name: 'CIS GCP',           shortName: 'CIS GCP',    color: '#4285F4', group: 'CIS' },
  { id: 'CIS_K8S',          name: 'CIS Kubernetes',    shortName: 'CIS K8S',    color: '#326CE5', group: 'CIS' },
  { id: 'CIS_IBM',          name: 'CIS IBM Cloud',     shortName: 'CIS IBM',    color: '#1F70C1', group: 'CIS' },
  { id: 'CIS_ALICLOUD',     name: 'CIS AliCloud',      shortName: 'CIS Ali',    color: '#FF6A00', group: 'CIS' },
  { id: 'CIS_OCI',          name: 'CIS Oracle Cloud',  shortName: 'CIS OCI',    color: '#F80000', group: 'CIS' },
  // Regulatory
  { id: 'PCI_DSS',          name: 'PCI DSS v4.0.1',    shortName: 'PCI DSS',    color: '#f97316', group: 'Regulatory' },
  { id: 'HIPAA',            name: 'HIPAA',             shortName: 'HIPAA',      color: '#ef4444', group: 'Regulatory' },
  { id: 'GDPR',             name: 'GDPR',              shortName: 'GDPR',       color: '#8b5cf6', group: 'Regulatory' },
  { id: 'SOC2',             name: 'SOC 2',             shortName: 'SOC 2',      color: '#ec4899', group: 'Regulatory' },
  { id: 'ISO27001_2022',    name: 'ISO 27001:2022',    shortName: 'ISO 27001',  color: '#06b6d4', group: 'Regulatory' },
  { id: 'CANADA_PBMM',      name: 'Canada PBMM',       shortName: 'PBMM',       color: '#dc2626', group: 'Regulatory' },
  { id: 'RBI_BANK',         name: 'RBI Bank',          shortName: 'RBI Bank',   color: '#f59e0b', group: 'Regulatory' },
  { id: 'RBI_NBFC',         name: 'RBI NBFC',          shortName: 'RBI NBFC',   color: '#d97706', group: 'Regulatory' },
  // US Government
  { id: 'NIST_800_53',      name: 'NIST 800-53',       shortName: 'NIST 800-53',color: '#3b82f6', group: 'US Gov' },
  { id: 'NIST_800_171',     name: 'NIST 800-171',      shortName: 'NIST 171',   color: '#2563eb', group: 'US Gov' },
  { id: 'FedRAMP_Moderate', name: 'FedRAMP Moderate',  shortName: 'FedRAMP',    color: '#1d4ed8', group: 'US Gov' },
  { id: 'CISA_CE',          name: 'CISA CE',           shortName: 'CISA CE',    color: '#1e3a8a', group: 'US Gov' },
];

export const NAV_ITEMS = [
  { label: 'Dashboard', href: '/dashboard', icon: 'LayoutDashboard' },
  {
    label: 'Inventory',
    href: '/inventory',
    icon: 'Server',
    children: [
      { label: 'Assets', href: '/inventory' },
      { label: 'Architecture', href: '/inventory/architecture' },
      { label: 'Security Graph', href: '/inventory/graph' },
    ],
  },
  {
    label: 'Threats',
    href: '/threats',
    icon: 'AlertTriangle',
    children: [
      { label: 'Detection', href: '/threats' },
      { label: 'Attack Paths', href: '/threats/attack-paths' },
      { label: 'Toxic Threat Combos', href: '/threats/toxic-combinations' },
      { label: 'Graph', href: '/threats/graph' },
      { label: 'Timeline', href: '/threats/timeline' },
    ],
  },
  {
    label: 'Vulnerabilities',
    href: '/vulnerability',
    icon: 'Bug',
    children: [
      { label: 'Dashboard', href: '/vulnerability' },
      { label: 'Scans', href: '/vulnerability/scans' },
      { label: 'CVE Explorer', href: '/vulnerability/cves' },
      { label: 'Agents', href: '/vulnerability/agents' },
    ],
  },
  {
    label: 'Compliance',
    href: '/compliance',
    icon: 'ClipboardCheck',
    children: [
      { label: 'Frameworks', href: '/compliance' },
      { label: 'Multi-Cloud Matrix', href: '/compliance/matrix' },
      { label: 'Remediation Queue', href: '/compliance/remediation' },
    ],
  },
  {
    label: 'Security Posture',
    href: '/misconfig',
    icon: 'Shield',
    children: [
      { label: 'Posture Security', href: '/misconfig', icon: 'ShieldAlert' },
      { label: 'IAM Security', href: '/iam', icon: 'KeyRound' },
      { label: 'Network Security', href: '/network-security', icon: 'Network' },
      { label: 'Data Security', href: '/datasec', icon: 'Lock' },
      { label: 'Encryption', href: '/encryption', icon: 'Lock' },
      { label: 'Database Security', href: '/database-security', icon: 'Database' },
      { label: 'Container Security', href: '/container-security', icon: 'Container' },
      { label: 'AI Security', href: '/ai-security', icon: 'Brain' },
    ],
  },
  { label: 'CIEM', href: '/ciem', icon: 'Eye' },
  {
    label: 'CNAPP',
    href: '/cnapp',
    icon: 'Shield',
    children: [
      { label: 'Unified View', href: '/cnapp', icon: 'Shield' },
      { label: 'CWPP', href: '/cwpp', icon: 'Container' },
    ],
  },
  {
    label: 'Code Security',
    href: '/secops',
    icon: 'Code',
    children: [
      { label: 'SecOps', href: '/secops' },
    ],
  },
  { label: 'Risk', href: '/risk', icon: 'Activity' },
  { label: 'Reports', href: '/reports', icon: 'FileText' },
  // ── separator ──
  { separator: true },
  {
    label: 'Onboarding',
    href: '/onboarding',
    icon: 'UserPlus',
    children: [
      { label: 'Cloud Accounts', href: '/onboarding' },
      { label: 'Users', href: '/onboarding/users' },
      { label: 'Tenants', href: '/onboarding/tenants' },
      { label: 'Scans', href: '/scans' },
    ],
  },
  {
    label: 'Policies',
    href: '/policies',
    icon: 'BookOpen',
    children: [
      { label: 'All Policies', href: '/policies' },
      { label: 'Rule Management', href: '/rules' },
    ],
  },
  {
    label: 'Settings',
    href: '/settings',
    icon: 'Settings',
    children: [
      { label: 'Platform', href: '/settings' },
      { label: 'Notifications', href: '/settings/notifications' },
    ],
  },
  {
    label: 'Billing',
    href: '/billing',
    icon: 'CreditCard',
    permission: 'billing:read',
    roles: ['org_admin', 'tenant_admin'],
  },
  {
    label: 'Admin Dashboard',
    href: '/admin/dashboard',
    icon: 'LayoutGrid',
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
