import { NextResponse } from 'next/server';

const NLB_URL = process.env.NLB_URL ||
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';
const TENANT_ID = process.env.TENANT_ID || 'default-tenant';

// Wiz-like demo data per framework slug
function buildDemoData(framework) {
  const FW_META = {
    // canonical slugs
    'cis-aws-2.0':    { name: 'CIS AWS 2.0',      score: 82, color: '#3b82f6' },
    'nist-800-53-r5': { name: 'NIST 800-53 r5',   score: 76, color: '#8b5cf6' },
    'soc2-type-ii':   { name: 'SOC 2 Type II',    score: 88, color: '#22c55e' },
    'pci-dss-4.0':    { name: 'PCI DSS 4.0',      score: 71, color: '#f97316' },
    'hipaa':          { name: 'HIPAA',             score: 85, color: '#ef4444' },
    'iso-27001-2022': { name: 'ISO 27001:2022',    score: 79, color: '#14b8a6' },
    'gdpr':           { name: 'GDPR',              score: 91, color: '#f59e0b' },
    // alternate slugs used by the compliance overview page
    'nist-800-53':    { name: 'NIST 800-53 r5',   score: 76, color: '#8b5cf6' },
    'soc2-type2':     { name: 'SOC 2 Type II',    score: 88, color: '#22c55e' },
    'soc2':           { name: 'SOC 2 Type II',    score: 88, color: '#22c55e' },
    'iso-27001':      { name: 'ISO 27001:2022',    score: 79, color: '#14b8a6' },
    'iso27001':       { name: 'ISO 27001:2022',    score: 79, color: '#14b8a6' },
    'pci-dss':        { name: 'PCI DSS 4.0',      score: 71, color: '#f97316' },
    'cis':            { name: 'CIS AWS 2.0',      score: 82, color: '#3b82f6' },
  };
  const meta = FW_META[framework] || { name: framework.toUpperCase(), score: 78, color: '#6366f1' };

  const DOMAIN_CONTROLS = {
    'Identity & Access': [
      { id: 'IAM-1.4', name: 'Ensure no root account access key exists', severity: 'critical', status: 'fail', resources: ['arn:aws:iam::588989875114:root'] },
      { id: 'IAM-1.10', name: 'Ensure MFA is enabled for all IAM users with console access', severity: 'high', status: 'fail', resources: ['arn:aws:iam::588989875114:user/dev-user', 'arn:aws:iam::588989875114:user/ci-runner'] },
      { id: 'IAM-1.16', name: 'Ensure IAM policies are attached only to groups or roles', severity: 'medium', status: 'pass', resources: [] },
      { id: 'IAM-1.22', name: 'Ensure access keys are rotated every 90 days', severity: 'medium', status: 'fail', resources: ['arn:aws:iam::588989875114:user/deploy-bot', 'arn:aws:iam::588989875114:user/api-service'] },
    ],
    'Storage & Data': [
      { id: 'S3-2.1.1', name: 'Ensure S3 Bucket Policy does not grant public read access', severity: 'critical', status: 'fail', resources: ['arn:aws:s3:::aiwebsite01', 'arn:aws:s3:::cspm-lgtech'] },
      { id: 'S3-2.1.2', name: 'Ensure S3 Bucket Policy does not grant public write access', severity: 'critical', status: 'pass', resources: [] },
      { id: 'S3-2.1.5', name: 'Ensure S3 buckets are configured with Block Public Access', severity: 'high', status: 'fail', resources: ['arn:aws:s3:::anup-backup'] },
      { id: 'S3-2.2.1', name: 'Ensure S3 bucket server-side encryption is enabled', severity: 'medium', status: 'pass', resources: [] },
    ],
    'Logging & Monitoring': [
      { id: 'LOG-3.1', name: 'Ensure CloudTrail is enabled in all regions', severity: 'critical', status: 'fail', resources: ['arn:aws:cloudtrail::588989875114:trail/management-events'] },
      { id: 'LOG-3.2', name: 'Ensure CloudTrail log file validation is enabled', severity: 'high', status: 'pass', resources: [] },
      { id: 'LOG-3.6', name: 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket', severity: 'medium', status: 'pass', resources: [] },
      { id: 'LOG-3.10', name: 'Ensure AWS Config is enabled in all regions', severity: 'medium', status: 'fail', resources: ['arn:aws:config::588989875114:config-recorder/default'] },
    ],
    'Network Security': [
      { id: 'NET-5.1', name: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22', severity: 'critical', status: 'fail', resources: ['arn:aws:ec2:ap-south-1:588989875114:security-group/sg-008801ad727d19fb4', 'arn:aws:ec2:ap-south-1:588989875114:security-group/sg-0ece1d6ddf9fa5a3f'] },
      { id: 'NET-5.2', name: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389', severity: 'critical', status: 'pass', resources: [] },
      { id: 'NET-5.3', name: 'Ensure VPC flow logging is enabled in all VPCs', severity: 'medium', status: 'fail', resources: ['arn:aws:ec2:ap-south-1:588989875114:vpc/vpc-0abc123'] },
      { id: 'NET-5.6', name: 'Ensure that EC2 Metadata Service only allows IMDSv2', severity: 'high', status: 'pass', resources: [] },
    ],
    'Database': [
      { id: 'RDS-2.3.1', name: 'Ensure RDS instances are not publicly accessible', severity: 'critical', status: 'fail', resources: ['arn:aws:rds:ap-south-1:588989875114:db/prod-postgres'] },
      { id: 'RDS-2.3.2', name: 'Ensure RDS database instances are encrypted at rest', severity: 'high', status: 'pass', resources: [] },
      { id: 'RDS-2.3.3', name: 'Ensure RDS database has deletion protection enabled', severity: 'medium', status: 'fail', resources: ['arn:aws:rds:ap-south-1:588989875114:db/dev-mysql', 'arn:aws:rds:ap-south-1:588989875114:db/staging-pg'] },
    ],
  };

  const controls = [];
  Object.entries(DOMAIN_CONTROLS).forEach(([domain, items]) => {
    items.forEach(item => {
      controls.push({
        control_id: item.id,
        control_name: item.name,
        domain,
        severity: item.severity,
        status: item.status,
        passed: item.status === 'pass' ? 1 : 0,
        failed: item.status === 'fail' ? item.resources.length || 1 : 0,
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
    framework: meta.name,
    framework_slug: framework,
    summary: {
      score: meta.score,
      total_controls: controls.length,
      passed_controls: passed,
      failed_controls: failed,
      total_resources_affected: controls.reduce((s, c) => s + c.failed, 0),
      critical_controls: controls.filter(c => c.severity === 'critical' && c.status === 'fail').length,
      high_controls: controls.filter(c => c.severity === 'high' && c.status === 'fail').length,
    },
    controls,
    _source: 'demo',
  };
}

export async function GET(request, { params }) {
  const { framework } = await params;
  const { searchParams } = new URL(request.url);
  const tenantId = searchParams.get('tenant_id') || TENANT_ID;
  const scanRunId = searchParams.get('scan_run_id') || '';

  let liveData = null;
  try {
    const qs = new URLSearchParams({ tenant_id: tenantId, ...(scanRunId ? { scan_run_id: scanRunId } : {}) });
    const res = await fetch(
      `${NLB_URL}/gateway/api/v1/compliance/findings/framework/${encodeURIComponent(framework)}?${qs}`,
      { next: { revalidate: 60 } }
    );
    if (res.ok) {
      const data = await res.json();
      if (data?.controls?.length > 0) {
        liveData = { ...data, _source: 'live' };
      }
    }
  } catch (_) {}

  const result = liveData || buildDemoData(framework);
  return NextResponse.json(result, {
    headers: { 'X-Compliance-Framework-Source': result._source || 'demo' },
  });
}
