/**
 * Next.js App Router API Route — Compliance BFF interceptor.
 *
 * Strategy:
 *  1. Forward request to the live NLB BFF endpoint.
 *  2. Detect degenerate data (empty/unnamed frameworks, all-zero scores,
 *     empty failingControls) — this happens when the engine DB scan data
 *     is structurally incomplete (compliance_framework column empty, writer
 *     stored status='open' but query filtered for status='FAIL', etc.).
 *  3. If degenerate → return rich mock data so every chart / KPI card is
 *     populated in local development without requiring an EKS redeploy.
 *  4. If real data is present → merge it through (add missing fields if
 *     needed) and return as-is.
 *
 * Called by: src/app/compliance/page.jsx  (fetchComplianceView helper)
 */

import { NextResponse } from 'next/server';

// ── NLB / gateway base URL (same env-var as next.config.js) ──────────────────
const NLB_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL ||
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';

// ── Deterministic mock data ──────────────────────────────────────────────────
// Pre-computed from the Python mock_compliance() with seed=42.
// Values are stable; no Math.random() so SSR and CSR produce identical results.

const ACCOUNTS = [
  { account_id: '588989875114', account_name: 'prod-account',    provider: 'AWS' },
  { account_id: '312456789012', account_name: 'staging-account', provider: 'AWS' },
  { account_id: '198765432109', account_name: 'dev-account',     provider: 'AWS' },
];

const FW_DEFS = [
  { id: 'cis-aws-2.0',  name: 'CIS AWS 2.0',     short: 'CIS',   controls: 180, score: 82 },
  { id: 'nist-800-53',  name: 'NIST 800-53 r5',   short: 'NIST',  controls: 154, score: 76 },
  { id: 'soc2-type2',   name: 'SOC 2 Type II',     short: 'SOC2',  controls:  64, score: 88 },
  { id: 'pci-dss-4.0',  name: 'PCI DSS 4.0',       short: 'PCI',   controls:  78, score: 71 },
  { id: 'hipaa',        name: 'HIPAA',              short: 'HIPAA', controls:  44, score: 85 },
  { id: 'iso-27001',    name: 'ISO 27001:2022',     short: 'ISO',   controls:  93, score: 79 },
  { id: 'gdpr',         name: 'GDPR',               short: 'GDPR',  controls:  32, score: 91 },
];

// Seeded "random" dates (hours before now) — pre-computed from seed=42 sequence
const FW_HOURS_AGO = [14, 41, 7, 38, 22, 5, 47];

const FAILING_CONTROLS = [
  { control_id: 'CIS-2.1.1', title: 'Ensure S3 Bucket Policy does not grant public read access',      framework: 'CIS AWS 2.0',    account: '588989875114', region: 'us-east-1',  severity: 'critical', total_failed: 12, days_open: 34 },
  { control_id: 'CIS-1.4',   title: 'Ensure no root account access key exists',                        framework: 'CIS AWS 2.0',    account: '312456789012', region: 'us-west-2',  severity: 'critical', total_failed:  3, days_open:  8 },
  { control_id: 'CIS-1.10',  title: 'Ensure MFA is enabled for all IAM users with console access',     framework: 'CIS AWS 2.0',    account: '198765432109', region: 'eu-west-1',  severity: 'high',     total_failed: 27, days_open: 62 },
  { control_id: 'CIS-2.3.1', title: 'Ensure RDS instances are not publicly accessible',                framework: 'CIS AWS 2.0',    account: '588989875114', region: 'ap-south-1', severity: 'high',     total_failed:  5, days_open: 19 },
  { control_id: 'CIS-3.1',   title: 'Ensure CloudTrail is enabled in all regions',                     framework: 'CIS AWS 2.0',    account: '312456789012', region: 'us-east-1',  severity: 'high',     total_failed:  9, days_open: 45 },
  { control_id: 'NIST-AC-2', title: 'Account Management — remove unused IAM credentials',              framework: 'NIST 800-53 r5', account: '198765432109', region: 'us-west-2',  severity: 'medium',   total_failed: 18, days_open: 73 },
  { control_id: 'NIST-SC-8', title: 'Transmission Confidentiality — enforce TLS on all endpoints',     framework: 'NIST 800-53 r5', account: '588989875114', region: 'eu-west-1',  severity: 'high',     total_failed: 31, days_open: 28 },
  { control_id: 'NIST-AU-2', title: 'Audit Events — enable logging on all critical services',           framework: 'NIST 800-53 r5', account: '312456789012', region: 'ap-south-1', severity: 'high',     total_failed:  7, days_open: 15 },
  { control_id: 'SOC2-CC6.1',title: 'Logical and Physical Access Controls — restrict admin access',    framework: 'SOC 2 Type II',  account: '198765432109', region: 'us-east-1',  severity: 'critical', total_failed: 22, days_open: 91 },
  { control_id: 'SOC2-CC7.2',title: 'System Operations — monitor for unauthorized changes',            framework: 'SOC 2 Type II',  account: '588989875114', region: 'us-west-2',  severity: 'medium',   total_failed: 14, days_open: 47 },
  { control_id: 'PCI-1.3.1', title: 'Restrict inbound traffic to cardholder data environment',         framework: 'PCI DSS 4.0',    account: '312456789012', region: 'eu-west-1',  severity: 'critical', total_failed:  6, days_open: 11 },
  { control_id: 'PCI-3.4',   title: 'Render PAN unreadable using encryption',                          framework: 'PCI DSS 4.0',    account: '198765432109', region: 'ap-south-1', severity: 'high',     total_failed: 33, days_open: 84 },
  { control_id: 'HIPAA-164.312', title: 'Technical Security — encrypt data at rest and in transit',    framework: 'HIPAA',          account: '588989875114', region: 'us-east-1',  severity: 'high',     total_failed: 10, days_open: 56 },
  { control_id: 'ISO-A.9.1', title: 'Access Control Policy — enforce role-based access management',    framework: 'ISO 27001:2022', account: '312456789012', region: 'us-west-2',  severity: 'medium',   total_failed: 20, days_open: 38 },
  { control_id: 'GDPR-Art32', title: 'Security of Processing — implement appropriate technical measures', framework: 'GDPR',        account: '198765432109', region: 'eu-west-1',  severity: 'high',     total_failed:  4, days_open: 22 },
];

// 12-month trend: scores 62 → 78 over 12 months
const TREND_SCORES = [62.3, 63.8, 65.1, 66.7, 68.4, 69.9, 71.2, 73.0, 74.8, 75.9, 77.1, 78.0];

// Deterministic per-account score variance (mirrors Python hashlib.md5 + variance_pct logic)
// Pre-computed for the 3 accounts × 7 frameworks
const MATRIX_FW_KEYS = ['CIS', 'NIST', 'SOC2', 'PCI', 'HIPAA', 'ISO', 'GDPR'];
const ACCOUNT_MATRIX_SCORES = {
  '588989875114': { CIS: 88.0, NIST: 81.5, SOC2: 94.2, PCI:  76.3, HIPAA: 91.4, ISO: 84.7, GDPR: 97.8 },
  '312456789012': { CIS: 74.6, NIST: 69.2, SOC2: 80.9, PCI:  65.1, HIPAA: 78.2, ISO: 73.4, GDPR: 84.3 },
  '198765432109': { CIS: 83.1, NIST: 77.8, SOC2: 89.5, PCI:  72.4, HIPAA: 86.9, ISO: 80.2, GDPR: 93.1 },
};

function buildMockCompliance() {
  const now = new Date();

  // Frameworks
  const frameworks = FW_DEFS.map((fw, i) => {
    const passed = Math.round(fw.controls * fw.score / 100);
    return {
      id:            fw.id,
      name:          fw.name,
      score:         fw.score,
      controls:      fw.controls,
      passed,
      failed:        fw.controls - passed,
      last_assessed: new Date(now - FW_HOURS_AGO[i] * 3600 * 1000).toISOString(),
    };
  });

  const totalPassed   = frameworks.reduce((s, fw) => s + fw.passed,   0);
  const totalFailed   = frameworks.reduce((s, fw) => s + fw.failed,   0);
  const totalControls = totalPassed + totalFailed;
  const passRate      = totalControls > 0 ? +((totalPassed / totalControls) * 100).toFixed(1) : 0;
  const overallScore  = 78;
  const criticalGaps  = FAILING_CONTROLS.filter(c => c.severity === 'critical').length;
  const atRisk        = frameworks.filter(fw => fw.score < 70).length;

  // 12-month trend
  const trendData = TREND_SCORES.map((score, i) => {
    const d = new Date(now - (11 - i) * 30 * 24 * 3600 * 1000);
    return { date: d.toISOString().slice(0, 10), score };
  });

  // Audit deadlines (days from now)
  const deadline = (days) => new Date(+now + days * 86400000).toISOString();
  const auditDeadlines = [
    { framework: 'PCI DSS 4.0',    type: 'Annual Compliance Audit',  due_date: deadline(45),  days_remaining: 45,  owner: 'Compliance Team', status: 'at-risk'  },
    { framework: 'SOC 2 Type II',  type: 'SOC 2 Audit Period End',   due_date: deadline(72),  days_remaining: 72,  owner: 'Security Team',   status: 'on-track' },
    { framework: 'HIPAA',          type: 'HIPAA Risk Assessment',    due_date: deadline(90),  days_remaining: 90,  owner: 'Compliance Team', status: 'on-track' },
    { framework: 'ISO 27001:2022', type: 'Surveillance Audit',       due_date: deadline(130), days_remaining: 130, owner: 'ISMS Manager',    status: 'on-track' },
    { framework: 'GDPR',           type: 'DPA Review',               due_date: deadline(180), days_remaining: 180, owner: 'DPO',             status: 'on-track' },
  ];

  // Exceptions (field names match UI exceptionColumns accessorKeys)
  const exceptions = [
    {
      id: 'exc-001', control: 'CIS-2.1.1', framework: 'CIS AWS 2.0',
      justification: 'Public website assets bucket — approved by CISO',
      approved_by: 'ciso@example.com',
      expiry_date: new Date(+now + 60 * 86400000).toISOString().slice(0, 10),
      status: 'active',
    },
    {
      id: 'exc-002', control: 'PCI-1.3.1', framework: 'PCI DSS 4.0',
      justification: 'Legacy payment gateway requires direct access — migration scheduled Q3',
      approved_by: 'vp-engineering@example.com',
      expiry_date: new Date(+now + 120 * 86400000).toISOString().slice(0, 10),
      status: 'active',
    },
    {
      id: 'exc-003', control: 'NIST-SC-8', framework: 'NIST 800-53 r5',
      justification: 'Internal service mesh uses mTLS — external TLS pending cert rotation',
      approved_by: 'security-lead@example.com',
      expiry_date: new Date(+now + 30 * 86400000).toISOString().slice(0, 10),
      status: 'active',
    },
  ];

  // Account matrix
  const accountMatrix = ACCOUNTS.map(acct => {
    const scores = ACCOUNT_MATRIX_SCORES[acct.account_id] || {};
    const vals   = MATRIX_FW_KEYS.map(k => scores[k] || 0).filter(v => v > 0);
    return {
      account:     acct.account_name,
      account_id:  acct.account_id,
      provider:    acct.provider,
      environment: acct.account_name.includes('prod') ? 'production' : 'development',
      cred_expired: false,
      status:      'active',
      ...scores,
      avg: vals.length ? +(vals.reduce((s, v) => s + v, 0) / vals.length).toFixed(1) : 0,
    };
  });

  return {
    pageContext: {
      title: 'Compliance',
      brief: `${passRate}% pass rate — ${totalPassed} passed, ${totalFailed} failed across ${frameworks.length} frameworks`,
      details: [
        'Evaluates resources against 7 compliance frameworks (CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2)',
        'Maps check findings to specific framework controls',
        'Track compliance score trends across scan cycles',
        'Export compliance reports for auditors in PDF/CSV format',
        'Review failing controls sorted by severity and affected resource count',
      ],
      tabs: [
        { id: 'overview',    label: 'Overview',          count: totalControls },
        { id: 'frameworks',  label: 'Frameworks',        count: frameworks.length },
        { id: 'controls',    label: 'Failing Controls',  count: FAILING_CONTROLS.length },
        { id: 'matrix',      label: 'Account Matrix',    count: accountMatrix.length },
      ],
    },
    filterSchema: [
      { key: 'severity',      label: 'Severity',      type: 'enum',   operators: ['is','is_not','in','not_in'], values: ['critical','high','medium','low','info'] },
      { key: 'framework_id',  label: 'Framework',     type: 'string', operators: ['is','is_not','contains','not_contains','starts_with'] },
      { key: 'control_id',    label: 'Control ID',    type: 'string', operators: ['is','is_not','contains','not_contains','starts_with'] },
      { key: 'account_id',    label: 'Account',       type: 'string', operators: ['is','is_not','contains','not_contains','starts_with'] },
      { key: 'region',        label: 'Region',        type: 'string', operators: ['is','is_not','contains','not_contains','starts_with'] },
    ],
    kpiGroups: [
      {
        title: 'Compliance Posture',
        items: [
          { label: 'Overall Score',  value: overallScore,          suffix: '%' },
          { label: 'Pass Rate',      value: passRate,              suffix: '%' },
          { label: 'Frameworks',     value: frameworks.length },
          { label: 'At Risk',        value: atRisk },
        ],
      },
      {
        title: 'Control Status',
        items: [
          { label: 'Total Controls', value: totalControls },
          { label: 'Passed',         value: totalPassed },
          { label: 'Failed',         value: totalFailed },
          { label: 'Critical Gaps',  value: criticalGaps },
        ],
      },
    ],
    frameworks,
    failingControls: FAILING_CONTROLS,
    trendData,
    auditDeadlines,
    exceptions,
    accountMatrix,
    _source: 'mock',
  };
}

// ── Degenerate-data detector ──────────────────────────────────────────────────
// Returns true if the live BFF data is structurally incomplete and should be
// replaced with mock data.
function isDegenerate(data) {
  if (!data || typeof data !== 'object') return true;
  const fws = data.frameworks;
  if (!Array.isArray(fws) || fws.length === 0) return true;
  // All framework names/ids empty → writer never set compliance_framework column
  const allEmpty = fws.every(fw => !fw.id && !fw.name);
  if (allEmpty) return true;
  // All scores are 0 AND no failingControls → likely completely empty scan
  const allZeroScores = fws.every(fw => (fw.score ?? 0) === 0);
  const noFailing     = !Array.isArray(data.failingControls) || data.failingControls.length === 0;
  if (allZeroScores && noFailing) return true;
  return false;
}

// ── Framework detail demo data (Wiz-like) ─────────────────────────────────────
function buildFrameworkDemoData(framework) {
  const FW_META = {
    'cis-aws-2.0':    { name: 'CIS AWS 2.0',     score: 82 },
    'nist-800-53':    { name: 'NIST 800-53 r5',  score: 76 },
    'nist-800-53-r5': { name: 'NIST 800-53 r5',  score: 76 },
    'soc2-type-ii':   { name: 'SOC 2 Type II',   score: 88 },
    'soc2-type2':     { name: 'SOC 2 Type II',   score: 88 },
    'soc2':           { name: 'SOC 2 Type II',   score: 88 },
    'pci-dss-4.0':    { name: 'PCI DSS 4.0',     score: 71 },
    'pci-dss':        { name: 'PCI DSS 4.0',     score: 71 },
    'hipaa':          { name: 'HIPAA',            score: 85 },
    'iso-27001-2022': { name: 'ISO 27001:2022',   score: 79 },
    'iso-27001':      { name: 'ISO 27001:2022',   score: 79 },
    'iso27001':       { name: 'ISO 27001:2022',   score: 79 },
    'gdpr':           { name: 'GDPR',             score: 91 },
    'cis':            { name: 'CIS AWS 2.0',      score: 82 },
  };
  const meta = FW_META[framework?.toLowerCase()] || { name: (framework || 'Unknown').toUpperCase(), score: 78 };
  const DOMAIN_CONTROLS = {
    'Identity & Access': [
      { id: 'IAM-1.4',  name: 'Ensure no root account access key exists',                    severity: 'critical', status: 'fail', resources: ['arn:aws:iam::588989875114:root'] },
      { id: 'IAM-1.10', name: 'Ensure MFA is enabled for all IAM users with console access', severity: 'high',     status: 'fail', resources: ['arn:aws:iam::588989875114:user/dev-user', 'arn:aws:iam::588989875114:user/ci-runner'] },
      { id: 'IAM-1.16', name: 'Ensure IAM policies are attached only to groups or roles',    severity: 'medium',   status: 'pass', resources: [] },
      { id: 'IAM-1.22', name: 'Ensure access keys are rotated every 90 days',                severity: 'medium',   status: 'fail', resources: ['arn:aws:iam::588989875114:user/deploy-bot'] },
    ],
    'Storage & Data': [
      { id: 'S3-2.1.1', name: 'Ensure S3 Bucket Policy does not grant public read access',  severity: 'critical', status: 'fail', resources: ['arn:aws:s3:::aiwebsite01', 'arn:aws:s3:::cspm-lgtech'] },
      { id: 'S3-2.1.2', name: 'Ensure S3 Bucket Policy does not grant public write access', severity: 'critical', status: 'pass', resources: [] },
      { id: 'S3-2.1.5', name: 'Ensure S3 buckets are configured with Block Public Access',  severity: 'high',     status: 'fail', resources: ['arn:aws:s3:::anup-backup'] },
      { id: 'S3-2.2.1', name: 'Ensure S3 bucket server-side encryption is enabled',         severity: 'medium',   status: 'pass', resources: [] },
    ],
    'Logging & Monitoring': [
      { id: 'LOG-3.1',  name: 'Ensure CloudTrail is enabled in all regions',                          severity: 'critical', status: 'fail', resources: ['arn:aws:cloudtrail::588989875114:trail/management-events'] },
      { id: 'LOG-3.2',  name: 'Ensure CloudTrail log file validation is enabled',                     severity: 'high',     status: 'pass', resources: [] },
      { id: 'LOG-3.10', name: 'Ensure AWS Config is enabled in all regions',                          severity: 'medium',   status: 'fail', resources: ['arn:aws:config::588989875114:config-recorder/default'] },
    ],
    'Network Security': [
      { id: 'NET-5.1', name: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',   severity: 'critical', status: 'fail', resources: ['arn:aws:ec2:ap-south-1:588989875114:security-group/sg-008801ad727d19fb4'] },
      { id: 'NET-5.2', name: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389', severity: 'critical', status: 'pass', resources: [] },
      { id: 'NET-5.3', name: 'Ensure VPC flow logging is enabled in all VPCs',                       severity: 'medium',   status: 'fail', resources: ['arn:aws:ec2:ap-south-1:588989875114:vpc/vpc-0abc123'] },
    ],
    'Database': [
      { id: 'RDS-2.3.1', name: 'Ensure RDS instances are not publicly accessible',         severity: 'critical', status: 'fail', resources: ['arn:aws:rds:ap-south-1:588989875114:db/prod-postgres'] },
      { id: 'RDS-2.3.2', name: 'Ensure RDS database instances are encrypted at rest',      severity: 'high',     status: 'pass', resources: [] },
      { id: 'RDS-2.3.3', name: 'Ensure RDS database has deletion protection enabled',      severity: 'medium',   status: 'fail', resources: ['arn:aws:rds:ap-south-1:588989875114:db/dev-mysql'] },
    ],
  };
  const controls = [];
  Object.entries(DOMAIN_CONTROLS).forEach(([domain, items]) => {
    items.forEach(item => {
      controls.push({
        control_id: item.id, control_name: item.name, domain,
        severity: item.severity, status: item.status,
        passed: item.status === 'pass' ? 1 : 0,
        failed: item.status === 'fail' ? (item.resources.length || 1) : 0,
        resources: item.resources.map(uid => ({
          resource_uid: uid,
          resource_type: uid.includes('iam') ? 'iam' : uid.includes('s3') ? 's3' : uid.includes('ec2') ? 'ec2' : uid.includes('rds') ? 'rds' : 'aws',
          region: uid.includes('ap-south-1') ? 'ap-south-1' : 'global',
          severity: item.severity,
          last_seen: new Date().toISOString(),
        })),
      });
    });
  });
  const failed = controls.filter(c => c.status === 'fail').length;
  const passed = controls.filter(c => c.status === 'pass').length;
  return {
    framework: meta.name, framework_slug: framework,
    summary: {
      score: meta.score, total_controls: controls.length,
      passed_controls: passed, failed_controls: failed,
      total_resources_affected: controls.reduce((s, c) => s + c.failed, 0),
      critical_controls: controls.filter(c => c.severity === 'critical' && c.status === 'fail').length,
      high_controls: controls.filter(c => c.severity === 'high' && c.status === 'fail').length,
    },
    controls, _source: 'demo',
  };
}

// ── Route handler ─────────────────────────────────────────────────────────────
export async function GET(request) {
  const { searchParams } = new URL(request.url);

  // ── Framework detail view (/api/bff/compliance?view=framework&fw=cis-aws-2.0)
  const view = searchParams.get('view');
  if (view === 'framework') {
    const fw = searchParams.get('fw') || 'cis-aws-2.0';
    const tenantId = searchParams.get('tenant_id') || 'default-tenant';
    const scanRunId = searchParams.get('scan_run_id') || '';
    let liveFramework = null;
    try {
      const qs = new URLSearchParams({ tenant_id: tenantId, ...(scanRunId ? { scan_run_id: scanRunId } : {}) });
      const res = await fetch(`${NLB_URL}/gateway/api/v1/compliance/findings/framework/${encodeURIComponent(fw)}?${qs}`, { next: { revalidate: 60 } });
      if (res.ok) {
        const data = await res.json();
        if (data?.controls?.length > 0) liveFramework = { ...data, _source: 'live' };
      }
    } catch (_) {}
    const result = liveFramework || buildFrameworkDemoData(fw);
    return NextResponse.json(result, { headers: { 'X-Compliance-Framework-Source': result._source || 'demo' } });
  }

  const tenantId  = searchParams.get('tenant_id') || '';
  const provider  = searchParams.get('provider')  || '';
  const account   = searchParams.get('account')   || '';
  const region    = searchParams.get('region')    || '';

  // Build upstream URL
  const upstreamParams = new URLSearchParams({ tenant_id: tenantId, scan_run_id: 'latest' });
  if (provider) upstreamParams.set('provider', provider);
  if (account)  upstreamParams.set('account',  account);
  if (region)   upstreamParams.set('region',   region);
  const upstreamUrl = `${NLB_URL}/gateway/api/v1/views/compliance?${upstreamParams}`;

  let liveData = null;
  try {
    const res = await fetch(upstreamUrl, {
      headers: { 'Accept': 'application/json' },
      next: { revalidate: 30 },   // cache for 30 s in Next.js cache
    });
    if (res.ok) {
      liveData = await res.json();
    } else {
      console.warn(`[bff/compliance] upstream ${res.status} — falling back to mock`);
    }
  } catch (err) {
    console.warn('[bff/compliance] upstream fetch failed:', err.message, '— falling back to mock');
  }

  // Use mock when live data is absent or degenerate
  if (isDegenerate(liveData)) {
    const mock = buildMockCompliance();
    return NextResponse.json(mock, {
      headers: { 'X-Compliance-Source': 'mock' },
    });
  }

  // Live data is structurally complete — pass through
  return NextResponse.json(
    { ...liveData, _source: 'live' },
    { headers: { 'X-Compliance-Source': 'live' } },
  );
}
