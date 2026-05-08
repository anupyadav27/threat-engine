// Mock data for offline development and testing

// ── Security Posture ─────────────────────────────────────────────────────────

export const MOCK_POSTURE = {
  score: 67,
  prevScore: 61,
  delta: +6,
  status: 'Fair',                    // Poor <50 / Fair 50-74 / Good ≥75
  criticalActions: 23,
  domainScores: {
    iam:         42,
    compliance:  76,
    threats:     58,
    misconfigs:  71,
    dataSec:     63,
  },
};

export const MOCK_DASHBOARD = {
  total_assets: 3121,
  total_threats: 193,
  critical_threats: 4,
  high_threats: 131,
  compliance_score: 78.4,
  open_findings: 847,
  // Week-over-week deltas
  delta_assets: +47,
  delta_threats: +3,
  delta_critical: +1,
  delta_compliance: +2.1,
  delta_findings: -8,
};

export const MOCK_THREATS = [
  { id:'threat-001', title:'Unencrypted S3 bucket',                       severity:'critical', mitre_technique:'T1530', mitre_tactic:'Exfiltration',         status:'active',      affected_assets_count:3,  risk_score:95, provider:'AWS',   account:'prod-account',   region:'us-east-1',  service:'s3',           environment:'prod',    assignee:'Sarah Johnson',  detected:'2026-02-28T10:30:00Z' },
  { id:'threat-002', title:'IAM policy allows public access',              severity:'high',     mitre_technique:'T1087', mitre_tactic:'Reconnaissance',        status:'active',      affected_assets_count:12, risk_score:88, provider:'AWS',   account:'prod-account',   region:'us-east-1',  service:'iam',          environment:'prod',    assignee:'Mike Chen',      detected:'2026-03-01T09:45:00Z' },
  { id:'threat-003', title:'Root account usage detected',                  severity:'high',     mitre_technique:'T1078', mitre_tactic:'Initial Access',        status:'active',      affected_assets_count:1,  risk_score:82, provider:'AWS',   account:'prod-account',   region:'global',     service:'iam',          environment:'prod',    assignee:null,             detected:'2026-03-02T14:22:00Z' },
  { id:'threat-004', title:'Outdated encryption key version',              severity:'medium',   mitre_technique:'T1199', mitre_tactic:'Persistence',           status:'resolved',    affected_assets_count:5,  risk_score:65, provider:'AWS',   account:'staging-account', region:'us-east-1', service:'kms',          environment:'staging', assignee:'Jane Doe',       detected:'2026-02-25T11:10:00Z' },
  { id:'threat-005', title:'CloudTrail logging disabled',                  severity:'high',     mitre_technique:'T1562', mitre_tactic:'Defense Evasion',       status:'active',      affected_assets_count:2,  risk_score:79, provider:'AWS',   account:'prod-account',   region:'ap-south-1', service:'cloudtrail',   environment:'prod',    assignee:'Tom Garcia',     detected:'2026-03-03T08:00:00Z' },
  { id:'threat-006', title:'Overly permissive security group',             severity:'critical', mitre_technique:'T1190', mitre_tactic:'Initial Access',        status:'active',      affected_assets_count:8,  risk_score:92, provider:'AWS',   account:'prod-account',   region:'eu-west-1',  service:'ec2',          environment:'prod',    assignee:'Lisa Wang',      detected:'2026-03-04T16:30:00Z' },
  { id:'threat-007', title:'MFA not enforced on privileged users',         severity:'high',     mitre_technique:'T1556', mitre_tactic:'Credential Access',     status:'active',      affected_assets_count:6,  risk_score:85, provider:'Azure', account:'azure-prod',     region:'eastus',     service:'iam',          environment:'prod',    assignee:null,             detected:'2026-03-04T12:00:00Z' },
  { id:'threat-008', title:'Database backup unencrypted',                  severity:'high',     mitre_technique:'T1537', mitre_tactic:'Exfiltration',          status:'resolved',    affected_assets_count:4,  risk_score:77, provider:'AWS',   account:'prod-account',   region:'ap-south-1', service:'rds',          environment:'prod',    assignee:'Emma Rodriguez', detected:'2026-02-20T09:00:00Z' },
  { id:'threat-009', title:'VPC Flow Logs disabled',                       severity:'medium',   mitre_technique:'T1562', mitre_tactic:'Defense Evasion',       status:'active',      affected_assets_count:3,  risk_score:68, provider:'AWS',   account:'dev-account',    region:'us-east-1',  service:'vpc',          environment:'dev',     assignee:'Kevin Lee',      detected:'2026-03-01T07:00:00Z' },
  { id:'threat-010', title:'API Gateway without authentication',           severity:'critical', mitre_technique:'T1190', mitre_tactic:'Initial Access',        status:'active',      affected_assets_count:2,  risk_score:89, provider:'AWS',   account:'prod-account',   region:'us-east-1',  service:'apigateway',   environment:'prod',    assignee:'David Martinez', detected:'2026-03-05T02:00:00Z' },
  { id:'threat-011', title:'Lambda function with excessive permissions',   severity:'high',     mitre_technique:'T1548', mitre_tactic:'Privilege Escalation',  status:'investigating',affected_assets_count:7, risk_score:80, provider:'AWS',   account:'staging-account', region:'us-east-1', service:'lambda',       environment:'staging', assignee:'Sofia Patel',    detected:'2026-03-04T20:15:00Z' },
  { id:'threat-012', title:'Cross-account role without conditions',        severity:'medium',   mitre_technique:'T1087', mitre_tactic:'Reconnaissance',        status:'active',      affected_assets_count:1,  risk_score:62, provider:'AWS',   account:'prod-account',   region:'us-east-1',  service:'iam',          environment:'prod',    assignee:null,             detected:'2026-03-03T15:00:00Z' },
  { id:'threat-013', title:'Data exfiltration via DNS tunneling',          severity:'critical', mitre_technique:'T1567', mitre_tactic:'Exfiltration',          status:'active',      affected_assets_count:6,  risk_score:95, provider:'GCP',   account:'gcp-prod',       region:'us-central1', service:'dns',         environment:'prod',    assignee:'John Smith',     detected:'2026-03-02T19:33:00Z' },
  { id:'threat-014', title:'Credential stuffing attack on login endpoint', severity:'high',     mitre_technique:'T1110', mitre_tactic:'Credential Access',     status:'active',      affected_assets_count:1,  risk_score:74, provider:'Azure', account:'azure-prod',     region:'westeurope', service:'activedirectory',environment:'prod',  assignee:'Rachel Allen',   detected:'2026-03-05T06:00:00Z' },
  { id:'threat-015', title:'Cryptomining on EC2 instances',                severity:'high',     mitre_technique:'T1496', mitre_tactic:'Impact',                status:'active',      affected_assets_count:12, risk_score:76, provider:'AWS',   account:'dev-account',    region:'us-east-1',  service:'ec2',          environment:'dev',     assignee:null,             detected:'2026-03-03T22:45:00Z' },
];

export const MOCK_ASSETS = [
  {
    resource_uid: 'arn:aws:s3:::production-bucket-001',
    resource_type: 'S3 Bucket',
    service: 's3',
    region: 'us-east-1',
    account_id: '123456789012',
  },
  {
    resource_uid: 'arn:aws:ec2:us-west-2:123456789012:instance/i-0a1b2c3d4e5f6g7h8',
    resource_type: 'EC2 Instance',
    service: 'ec2',
    region: 'us-west-2',
    account_id: '123456789012',
  },
  {
    resource_uid: 'arn:aws:rds:eu-west-1:123456789012:db:prod-database',
    resource_type: 'RDS Database',
    service: 'rds',
    region: 'eu-west-1',
    account_id: '123456789012',
  },
  {
    resource_uid: 'arn:aws:iam::123456789012:role/lambda-execution-role',
    resource_type: 'IAM Role',
    service: 'iam',
    region: 'global',
    account_id: '123456789012',
  },
  {
    resource_uid: 'arn:aws:lambda:ap-southeast-1:123456789012:function:data-processor',
    resource_type: 'Lambda Function',
    service: 'lambda',
    region: 'ap-southeast-1',
    account_id: '123456789012',
  },
];

export const MOCK_FRAMEWORKS = [
  {
    name: 'CIS AWS 2.0',
    score: 78.5,
    total_controls: 143,
    passed_controls: 112,
  },
  {
    name: 'NIST 800-53',
    score: 71.2,
    total_controls: 225,
    passed_controls: 160,
  },
  {
    name: 'ISO 27001',
    score: 75.8,
    total_controls: 114,
    passed_controls: 86,
  },
  {
    name: 'PCI-DSS 4.0',
    score: 68.4,
    total_controls: 93,
    passed_controls: 64,
  },
  {
    name: 'HIPAA',
    score: 82.1,
    total_controls: 76,
    passed_controls: 62,
  },
];

export const MOCK_THREAT_DETAILS = {
  'threat-001': {
    id: 'threat-001',
    title: 'Unencrypted S3 bucket',
    description: 'S3 bucket configured without default encryption. This allows sensitive data to be stored unencrypted, making it vulnerable to unauthorized access and compliance violations.',
    severity: 'critical',
    mitre_tactic: 'Exfiltration',
    mitre_technique: 'T1530 - Data from Cloud Storage',
    mitre_description: 'Adversaries may access data from cloud storage infrastructure. Cloud providers offer various solutions for data storage including S3, Azure Blob Storage, etc.',
    status: 'active',
    risk_score: 95,
    discovered_date: '2026-02-28T14:22:00Z',
    last_seen: '2026-03-05T08:15:00Z',
    affected_assets_count: 3,
  },
  'threat-002': {
    id: 'threat-002',
    title: 'IAM policy allows public access',
    description: 'IAM policy permits principal:* actions that could allow anonymous or unauthorized access. This violates principle of least privilege.',
    severity: 'high',
    mitre_tactic: 'Reconnaissance',
    mitre_technique: 'T1087 - Account Discovery',
    mitre_description: 'Adversaries may attempt to get a listing of accounts within a cloud environment.',
    status: 'active',
    risk_score: 88,
    discovered_date: '2026-03-01T09:45:00Z',
    last_seen: '2026-03-05T07:30:00Z',
    affected_assets_count: 12,
  },
};

export const MOCK_THREAT_ASSETS = {
  'threat-001': [
    {
      resource_uid: 'arn:aws:s3:::production-bucket-001',
      resource_type: 'S3 Bucket',
      service: 's3',
      region: 'us-east-1',
      account_id: '123456789012',
      account_name: 'Production Account',
    },
    {
      resource_uid: 'arn:aws:s3:::backups-prod-data',
      resource_type: 'S3 Bucket',
      service: 's3',
      region: 'us-west-2',
      account_id: '123456789012',
      account_name: 'Production Account',
    },
    {
      resource_uid: 'arn:aws:s3:::archives-historical',
      resource_type: 'S3 Bucket',
      service: 's3',
      region: 'eu-west-1',
      account_id: '210987654321',
      account_name: 'Archive Account',
    },
  ],
  'threat-002': [
    {
      resource_uid: 'arn:aws:iam::123456789012:role/application-role',
      resource_type: 'IAM Role',
      service: 'iam',
      region: 'global',
      account_id: '123456789012',
      account_name: 'Production Account',
    },
    {
      resource_uid: 'arn:aws:iam::123456789012:policy/wildcard-policy',
      resource_type: 'IAM Policy',
      service: 'iam',
      region: 'global',
      account_id: '123456789012',
      account_name: 'Production Account',
    },
  ],
};

export const MOCK_THREAT_FINDINGS = {
  'threat-001': [
    {
      finding_id: 'finding-001-a',
      rule_id: 's3-001',
      rule_name: 'S3 bucket server-side encryption',
      severity: 'critical',
      description: 'S3 bucket does not have default server-side encryption enabled',
      service: 's3',
      resource_uid: 'arn:aws:s3:::production-bucket-001',
    },
    {
      finding_id: 'finding-001-b',
      rule_id: 's3-002',
      rule_name: 'S3 bucket versioning',
      severity: 'high',
      description: 'S3 bucket does not have versioning enabled for data protection',
      service: 's3',
      resource_uid: 'arn:aws:s3:::production-bucket-001',
    },
    {
      finding_id: 'finding-001-c',
      rule_id: 's3-003',
      rule_name: 'S3 bucket public access blocked',
      severity: 'critical',
      description: 'S3 bucket public access block is not enabled',
      service: 's3',
      resource_uid: 'arn:aws:s3:::production-bucket-001',
    },
  ],
  'threat-002': [
    {
      finding_id: 'finding-002-a',
      rule_id: 'iam-001',
      rule_name: 'IAM policy principal restriction',
      severity: 'high',
      description: 'IAM policy allows principal:* which permits public access',
      service: 'iam',
      resource_uid: 'arn:aws:iam::123456789012:policy/wildcard-policy',
    },
  ],
};

export const MOCK_THREAT_REMEDIATION = {
  'threat-001': [
    'Enable default server-side encryption (SSE-S3 or SSE-KMS) on the S3 bucket',
    'Enable S3 bucket versioning to protect against accidental deletions',
    'Enable S3 Object Lock for immutable backups (if applicable)',
    'Block all public access using S3 block public access settings',
    'Enable CloudTrail logging for all S3 API calls',
    'Configure bucket policy to restrict access to specific AWS principals only',
    'Enable MFA Delete protection for critical buckets',
    'Set up bucket lifecycle policies to automatically delete old versions',
  ],
  'threat-002': [
    'Remove principal:* from all IAM policies',
    'Add condition restrictions based on AWS account IDs, principals, or IP ranges',
    'Use resource-based policies to restrict cross-account access',
    'Enable IAM Access Analyzer to review all policies',
    'Implement least privilege by replacing wildcard actions with specific permissions',
    'Use permission boundaries to limit maximum permissions for roles',
    'Enable CloudTrail for all IAM API calls',
    'Audit and remove unused IAM principals and roles',
  ],
};

// ── Toxic Combinations (Wiz-style) ───────────────────────────────────────────
export const MOCK_TOXIC_COMBOS = [
  {
    id: 'tc-001',
    title: 'Public S3 + Unencrypted + Contains PII',
    description: 'Storage accessible publicly, not encrypted, and contains sensitive customer data',
    riskScore: 97,
    affectedResources: 2,
    affectedAccounts: ['prod-account'],
    mitre: 'T1537',
    provider: 'AWS',
    fixLink: '/threats/toxic-combinations',
    severity: 'critical',
  },
  {
    id: 'tc-002',
    title: 'Admin Role + No MFA + Access Key >90 Days',
    description: 'High-privilege identity with stale credentials and no multi-factor auth',
    riskScore: 94,
    affectedResources: 1,
    affectedAccounts: ['prod-account'],
    mitre: 'T1078',
    provider: 'AWS',
    fixLink: '/iam',
    severity: 'critical',
  },
  {
    id: 'tc-003',
    title: 'Internet-Exposed EC2 + Unpatched Critical CVE + SSH Open',
    description: 'Publicly reachable compute with known exploit in the wild and SSH port exposed',
    riskScore: 89,
    affectedResources: 4,
    affectedAccounts: ['prod-account', 'staging-account'],
    mitre: 'T1190',
    provider: 'AWS',
    fixLink: '/threats/toxic-combinations',
    severity: 'critical',
  },
];

// ── Critical Actions ──────────────────────────────────────────────────────────
export const MOCK_CRITICAL_ACTIONS = {
  immediate: [
    { id:'ca-1', title:'4 S3 buckets publicly exposed with PII', link:'/datasec', severity:'critical', affectedCount:4, estimatedFix:'20 min', provider:'AWS', account:'prod-account'  },
    { id:'ca-2', title:'Root account has active access keys',     link:'/iam',     severity:'critical', affectedCount:1, estimatedFix:'5 min',  provider:'AWS', account:'prod-account'  },
    { id:'ca-3', title:'GCP credentials expired — 0 scans in 15d',link:'/onboarding',severity:'critical',affectedCount:1, estimatedFix:'30 min', provider:'GCP', account:'gcp-prod'     },
  ],
  thisWeek: [
    { id:'ca-4', title:'18 IAM users with admin + no MFA',        link:'/iam',            severity:'high', affectedCount:18, estimatedFix:'2h',    provider:'AWS',   account:'prod-account' },
    { id:'ca-5', title:'Critical CVE CVE-2024-21762 in 34 assets',link:'/vulnerabilities', severity:'high', affectedCount:34, estimatedFix:'4h',    provider:'AWS',   account:'prod-account' },
    { id:'ca-6', title:'CloudTrail disabled in ap-south-1',        link:'/misconfig',       severity:'high', affectedCount:1,  estimatedFix:'5 min', provider:'AWS',   account:'prod-account' },
  ],
  thisMonth: [
    { id:'ca-7', title:'312 auto-remediable misconfigurations',   link:'/misconfig', severity:'medium', affectedCount:312, estimatedFix:'1d',  provider:'AWS',   account:'prod-account' },
    { id:'ca-8', title:'28 exceptions expiring this month',        link:'/compliance',severity:'medium', affectedCount:28,  estimatedFix:'3h',  provider:'AWS',   account:'prod-account' },
    { id:'ca-9', title:'SOC2 audit in 45 days — 8 controls failing',link:'/compliance',severity:'medium',affectedCount:8,   estimatedFix:'1w',  provider:'Azure', account:'azure-prod'   },
  ],
};

// ── Vulnerability Mock Data ───────────────────────────────────────────────────
export const MOCK_VULNERABILITIES = [
  { id:'vuln-001', cve_id:'CVE-2024-21762', title:'Fortinet FortiOS RCE via Session Hijacking',          severity:'critical', cvss_score:9.8, epss_score:0.87, affected_assets:34, exploit_available:true,  patch_available:true,  status:'open',        sla_status:'breached', discovered_at:'2026-02-28T10:30:00Z', age_days:7,  provider:'AWS',   account:'prod-account',   region:'us-east-1',  service:'ec2',    environment:'prod',    assignee:'security-team', cisa_kev:true  },
  { id:'vuln-002', cve_id:'CVE-2024-3094',  title:'XZ Utils Backdoor in liblzma Library',                severity:'critical', cvss_score:9.8, epss_score:0.92, affected_assets:127,exploit_available:true,  patch_available:true,  status:'in_progress', sla_status:'breached', discovered_at:'2026-02-15T14:15:00Z', age_days:20, provider:'AWS',   account:'prod-account',   region:'ap-south-1', service:'ec2',    environment:'prod',    assignee:'devops-team',   cisa_kev:true  },
  { id:'vuln-003', cve_id:'CVE-2024-1709',  title:'ConnectWise ScreenConnect Auth Bypass',              severity:'critical', cvss_score:9.6, epss_score:0.89, affected_assets:8,   exploit_available:true,  patch_available:true,  status:'open',        sla_status:'breached', discovered_at:'2026-02-25T09:45:00Z', age_days:10, provider:'Azure', account:'azure-prod',     region:'eastus',     service:'compute', environment:'prod',    assignee:'netops-team',   cisa_kev:true  },
  { id:'vuln-004', cve_id:'CVE-2023-44487', title:'HTTP/2 Rapid Reset Attack (DoS)',                     severity:'high',     cvss_score:7.5, epss_score:0.65, affected_assets:45,  exploit_available:true,  patch_available:true,  status:'open',        sla_status:'breached', discovered_at:'2026-02-18T12:00:00Z', age_days:17, provider:'AWS',   account:'prod-account',   region:'us-east-1',  service:'alb',    environment:'prod',    assignee:'platform-team', cisa_kev:false },
  { id:'vuln-005', cve_id:'CVE-2024-0204',  title:'GoAnywhere MFT Authentication Bypass',               severity:'critical', cvss_score:9.8, epss_score:0.91, affected_assets:3,   exploit_available:true,  patch_available:true,  status:'open',        sla_status:'breached', discovered_at:'2026-03-01T08:00:00Z', age_days:6,  provider:'AWS',   account:'staging-account', region:'us-east-1', service:'ec2',    environment:'staging', assignee:null,            cisa_kev:true  },
  { id:'vuln-006', cve_id:'CVE-2021-44228', title:'Apache Log4j2 RCE (Log4Shell)',                       severity:'critical', cvss_score:10.0,epss_score:0.97, affected_assets:89,  exploit_available:true,  patch_available:true,  status:'in_progress', sla_status:'breached', discovered_at:'2026-01-10T00:00:00Z', age_days:55, provider:'AWS',   account:'prod-account',   region:'us-east-1',  service:'lambda', environment:'prod',    assignee:'devops-team',   cisa_kev:true  },
  { id:'vuln-007', cve_id:'CVE-2022-22965', title:'Spring Framework RCE (Spring4Shell)',                 severity:'critical', cvss_score:9.8, epss_score:0.83, affected_assets:22,  exploit_available:true,  patch_available:true,  status:'open',        sla_status:'at_risk',  discovered_at:'2026-02-20T16:00:00Z', age_days:15, provider:'GCP',   account:'gcp-prod',       region:'us-central1',service:'compute', environment:'prod',    assignee:null,            cisa_kev:true  },
  { id:'vuln-008', cve_id:'CVE-2023-23397', title:'Microsoft Outlook Privilege Escalation',              severity:'high',     cvss_score:9.8, epss_score:0.58, affected_assets:12,  exploit_available:true,  patch_available:true,  status:'open',        sla_status:'at_risk',  discovered_at:'2026-02-22T11:30:00Z', age_days:13, provider:'Azure', account:'azure-prod',     region:'westeurope', service:'compute', environment:'prod',    assignee:'security-team', cisa_kev:false },
  { id:'vuln-009', cve_id:'CVE-2024-6387',  title:'OpenSSH regreSSHion RCE',                            severity:'critical', cvss_score:8.1, epss_score:0.61, affected_assets:67,  exploit_available:false, patch_available:true,  status:'open',        sla_status:'ok',       discovered_at:'2026-03-04T09:00:00Z', age_days:3,  provider:'AWS',   account:'prod-account',   region:'eu-west-1',  service:'ec2',    environment:'prod',    assignee:'platform-team', cisa_kev:false },
  { id:'vuln-010', cve_id:'CVE-2024-4577',  title:'PHP CGI Argument Injection RCE',                     severity:'critical', cvss_score:9.8, epss_score:0.79, affected_assets:14,  exploit_available:true,  patch_available:true,  status:'open',        sla_status:'breached', discovered_at:'2026-02-23T14:00:00Z', age_days:12, provider:'OCI',   account:'oci-primary',   region:'ap-mumbai-1', service:'compute',environment:'prod',    assignee:null,            cisa_kev:false },
  { id:'vuln-011', cve_id:'CVE-2023-22518', title:'Confluence Data Center Improper Auth',               severity:'critical', cvss_score:9.1, epss_score:0.76, affected_assets:6,   exploit_available:true,  patch_available:true,  status:'in_progress', sla_status:'breached', discovered_at:'2026-02-19T10:00:00Z', age_days:16, provider:'AWS',   account:'prod-account',   region:'us-east-1',  service:'ec2',    environment:'prod',    assignee:'devops-team',   cisa_kev:true  },
  { id:'vuln-012', cve_id:'CVE-2024-21893', title:'Ivanti Connect Secure SSRF',                         severity:'high',     cvss_score:8.2, epss_score:0.43, affected_assets:4,   exploit_available:false, patch_available:true,  status:'open',        sla_status:'ok',       discovered_at:'2026-03-03T12:00:00Z', age_days:4,  provider:'AWS',   account:'staging-account', region:'us-east-1', service:'ec2',    environment:'staging', assignee:null,            cisa_kev:false },
  { id:'vuln-013', cve_id:'CVE-2023-20198', title:'Cisco IOS XE Web UI Privilege Escalation',           severity:'critical', cvss_score:10.0,epss_score:0.95, affected_assets:8,   exploit_available:true,  patch_available:true,  status:'open',        sla_status:'breached', discovered_at:'2026-02-10T08:00:00Z', age_days:25, provider:'AWS',   account:'prod-account',   region:'ap-south-1', service:'ec2',    environment:'prod',    assignee:'security-team', cisa_kev:true  },
  { id:'vuln-014', cve_id:'CVE-2024-27198', title:'JetBrains TeamCity Auth Bypass',                     severity:'critical', cvss_score:9.8, epss_score:0.68, affected_assets:3,   exploit_available:true,  patch_available:true,  status:'open',        sla_status:'at_risk',  discovered_at:'2026-02-24T15:00:00Z', age_days:11, provider:'AWS',   account:'dev-account',    region:'us-east-1',  service:'ec2',    environment:'dev',     assignee:'devops-team',   cisa_kev:false },
  { id:'vuln-015', cve_id:'CVE-2023-36884', title:'Microsoft Office and Windows HTML RCE',              severity:'high',     cvss_score:8.3, epss_score:0.38, affected_assets:29,  exploit_available:false, patch_available:true,  status:'open',        sla_status:'ok',       discovered_at:'2026-03-01T16:00:00Z', age_days:6,  provider:'Azure', account:'azure-prod',     region:'eastus',     service:'compute', environment:'prod',    assignee:null,            cisa_kev:false },
];

export const MOCK_REMEDIATION_QUEUE = [
  {
    threat_id: 'threat-001',
    threat_title: 'Unencrypted S3 bucket',
    severity: 'critical',
    affected_count: 3,
    priority_score: 95,
    estimated_effort: 'High',
    status: 'pending',
  },
  {
    threat_id: 'threat-006',
    threat_title: 'Overly permissive security group',
    severity: 'critical',
    affected_count: 8,
    priority_score: 92,
    estimated_effort: 'High',
    status: 'in_progress',
  },
  {
    threat_id: 'threat-010',
    threat_title: 'API Gateway without authentication',
    severity: 'critical',
    affected_count: 2,
    priority_score: 89,
    estimated_effort: 'Medium',
    status: 'pending',
  },
  {
    threat_id: 'threat-002',
    threat_title: 'IAM policy allows public access',
    severity: 'high',
    affected_count: 12,
    priority_score: 88,
    estimated_effort: 'High',
    status: 'pending',
  },
  {
    threat_id: 'threat-007',
    threat_title: 'MFA not enforced on privileged users',
    severity: 'high',
    affected_count: 6,
    priority_score: 85,
    estimated_effort: 'Medium',
    status: 'pending',
  },
  {
    threat_id: 'threat-003',
    threat_title: 'Root account usage detected',
    severity: 'high',
    affected_count: 1,
    priority_score: 82,
    estimated_effort: 'Low',
    status: 'pending',
  },
];
