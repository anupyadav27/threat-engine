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
  gcp:      { name: 'GCP',     color: '#4285F4', bgColor: 'rgba(66,133,244,0.15)', textColor: '#4285F4'  },
  oci:      { name: 'OCI',     color: '#F80000', bgColor: 'rgba(248,0,0,0.15)',    textColor: '#F80000'  },
  alicloud: { name: 'AliCloud',color: '#FF6A00', bgColor: 'rgba(255,106,0,0.15)',  textColor: '#FF6A00'  },
  ibm:      { name: 'IBM',     color: '#1F70C1', bgColor: 'rgba(31,112,193,0.15)', textColor: '#1F70C1'  },
};

// SLA thresholds by severity (days until breach)
export const SLA_THRESHOLDS = {
  critical: 7,
  high: 14,
  medium: 30,
  low: 90,
};

export const FRAMEWORKS = [
  { id: 'cis', name: 'CIS Benchmarks', color: '#10b981' },
  { id: 'nist', name: 'NIST 800-53', color: '#3b82f6' },
  { id: 'pci_dss', name: 'PCI DSS', color: '#f97316' },
  { id: 'hipaa', name: 'HIPAA', color: '#ef4444' },
  { id: 'gdpr', name: 'GDPR', color: '#8b5cf6' },
  { id: 'iso_27001', name: 'ISO 27001', color: '#06b6d4' },
  { id: 'soc2', name: 'SOC 2', color: '#ec4899' }
];

export const NAV_ITEMS = [
  { label: 'Dashboard', href: '/dashboard', icon: 'LayoutDashboard' },
  {
    label: 'Scans',
    href: '/scans',
    icon: 'Radar',
    children: [
      { label: 'Scan History', href: '/scans' },
    ],
  },
  {
    label: 'Inventory',
    href: '/inventory',
    icon: 'Server',
    children: [
      { label: 'Assets', href: '/inventory' },
      { label: 'Architecture', href: '/inventory/architecture' },
    ],
  },
  {
    label: 'Misconfigurations',
    href: '/misconfig',
    icon: 'AlertOctagon',
  },
  {
    label: 'Threats',
    href: '/threats',
    icon: 'ShieldAlert',
    children: [
      { label: 'All Threats', href: '/threats' },
      { label: 'Attack Paths', href: '/threats/attack-paths' },
      { label: 'Blast Radius', href: '/threats/blast-radius' },
      { label: 'Internet Exposed', href: '/threats/internet-exposed' },
      { label: 'Toxic Combos', href: '/threats/toxic-combinations' },
      { label: 'Graph Explorer', href: '/threats/graph' },
      { label: 'Analytics', href: '/threats/analytics' },
      { label: 'Threat Hunting', href: '/threats/hunting' },
    ],
  },
  { label: 'Vulnerabilities', href: '/vulnerabilities', icon: 'Bug' },
  {
    label: 'Compliance',
    href: '/compliance',
    icon: 'ClipboardCheck',
    children: [
      { label: 'Frameworks', href: '/compliance' },
    ],
  },
  { label: 'IAM Security', href: '/iam', icon: 'KeyRound' },
  {
    label: 'Data Security',
    href: '/datasec',
    icon: 'Database',
    children: [
      { label: 'Overview', href: '/datasec' },
      { label: 'Data Lineage', href: '/datasec/lineage' },
    ],
  },
  {
    label: 'Code Security',
    href: '/secops',
    icon: 'Code',
    children: [
      { label: 'Scans', href: '/secops' },
    ],
  },
  { label: 'Reports', href: '/reports', icon: 'FileText' },
  { label: 'Risk', href: '/risk', icon: 'TrendingUp' },
  { label: 'Notifications', href: '/notifications', icon: 'Bell' },
  {
    label: 'Settings',
    href: '/settings',
    icon: 'Settings',
    children: [
      { label: 'Platform Health', href: '/settings' },
      { label: 'Onboarding', href: '/onboarding' },
      { label: 'Add Account', href: '/onboarding/wizard' },
      { label: 'Policies', href: '/policies' },
      { label: 'Create Policy', href: '/policies/add' },
      { label: 'Rule Management', href: '/rules' },
      { label: 'Users', href: '/settings/users' },
      { label: 'Tenants', href: '/settings/tenants' },
      { label: 'Notifications', href: '/settings/notifications' },
    ],
  },
];

// Engine calls route through Next.js rewrites → NLB → nginx ingress → engine.
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
};
