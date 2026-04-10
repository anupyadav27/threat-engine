'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import Link from 'next/link';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTip, ResponsiveContainer, ReferenceLine,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Legend,
} from 'recharts';
import {
  AlertTriangle, ShieldAlert, ShieldCheck,
  X, ExternalLink, Copy, Check,
  Download, FileSpreadsheet, RefreshCw, ArrowRight,
  Zap, Clock, AlertOctagon, TrendingUp, TrendingDown, Layers,
} from 'lucide-react';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { SEVERITY_COLORS, CLOUD_PROVIDERS } from '@/lib/constants';
import { fetchView } from '@/lib/api';
import PageLayout from '@/components/shared/PageLayout';
import InsightRow from '@/components/shared/InsightRow';
import KpiSparkCard from '@/components/shared/KpiSparkCard';
import CspmSparkline from '@/components/shared/Sparkline';


// ── Accent palette ───────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#3b82f6',
  clean:    '#22c55e',
  purple:   '#8b5cf6',
  sky:      '#0ea5e9',
  slate:    '#64748b',
  pink:     '#ec4899',
  teal:     '#14b8a6',
  indigo:   '#6366f1',
  cyan:     '#06b6d4',
};

// ── Dummy / seed data ─────────────────────────────────────────────────────────
const POSTURE_SCAN_TREND = [
  { date: 'Jan 6',  passRate: 58, critical: 12, high: 22, medium: 18, total: 65 },
  { date: 'Jan 13', passRate: 61, critical: 11, high: 21, medium: 16, total: 61 },
  { date: 'Jan 20', passRate: 64, critical: 10, high: 19, medium: 15, total: 56 },
  { date: 'Jan 27', passRate: 66, critical:  9, high: 18, medium: 14, total: 52 },
  { date: 'Feb 3',  passRate: 69, critical:  8, high: 17, medium: 13, total: 48 },
  { date: 'Feb 10', passRate: 71, critical:  7, high: 16, medium: 12, total: 44 },
  { date: 'Feb 17', passRate: 73, critical:  7, high: 15, medium: 11, total: 42 },
  { date: 'Mar 3',  passRate: 75, critical:  6, high: 15, medium: 10, total: 39 },
];

const POSTURE_BY_CATEGORY = [
  { category: 'IAM Security',       fail: 9,  total: 18, color: C.medium   },
  { category: 'Network Security',   fail: 3,  total:  8, color: C.indigo   },
  { category: 'Data Security',      fail: 7,  total: 12, color: C.cyan     },
  { category: 'Encryption',         fail: 4,  total: 15, color: C.purple   },
  { category: 'Database Security',  fail: 6,  total: 10, color: C.teal     },
  { category: 'Container Security', fail: 5,  total: 14, color: C.high     },
];

const MISCONFIG_SPARKLINES = {
  pass_rate:       [58, 61, 64, 66, 69, 71, 73, 75],
  services:        [28, 28, 27, 27, 26, 26, 25, 25],
  auto_remediable: [5, 5, 6, 6, 7, 7, 8, 8],
  sla_breached:    [14, 13, 12, 11, 10, 9, 8, 7],
  avg_age:         [48, 47, 46, 45, 44, 43, 42, 41],
  new_this_scan:   [8, 7, 6, 6, 5, 5, 4, 3],
};

const POSTURE_FINDINGS_MOCK = [
  { rule_id: 'aws.s3.encryption.default',       title: 'S3 bucket default encryption not enabled',             severity: 'critical', status: 'FAIL', service: 's3',         provider: 'aws', account_id: '198765432109', region: 'us-east-1',  age_days: 45,  auto_remediable: true,  resource_uid: 'arn:aws:s3:::prod-data-bucket',                              posture_category: 'encryption',     risk_score: 88, sla_status: 'breached' },
  { rule_id: 'aws.s3.public_access_block',      title: 'S3 public access block not configured',                severity: 'critical', status: 'FAIL', service: 's3',         provider: 'aws', account_id: '588989875114', region: 'ap-south-1', age_days: 30,  auto_remediable: true,  resource_uid: 'arn:aws:s3:::staging-assets',                               posture_category: 'public_access',  risk_score: 92, sla_status: 'active'   },
  { rule_id: 'aws.s3.versioning',               title: 'S3 bucket versioning not enabled',                     severity: 'high',     status: 'PASS', service: 's3',         provider: 'aws', account_id: '198765432109', region: 'ap-south-1', age_days: 12,  auto_remediable: true,  resource_uid: 'arn:aws:s3:::backup-store',                                  posture_category: 'backup',         risk_score: 62, sla_status: 'active'   },
  { rule_id: 'aws.s3.logging',                  title: 'S3 bucket server access logging disabled',             severity: 'high',     status: 'FAIL', service: 's3',         provider: 'aws', account_id: '312456789012', region: 'eu-west-1',  age_days: 67,  auto_remediable: false, resource_uid: 'arn:aws:s3:::eu-logs-bucket',                                posture_category: 'logging',        risk_score: 71, sla_status: 'breached' },
  { rule_id: 'aws.iam.mfa_console',             title: 'IAM user with console access missing MFA',             severity: 'medium',   status: 'FAIL', service: 'iam',        provider: 'aws', account_id: '588989875114', region: 'global',     age_days: 23,  auto_remediable: false, resource_uid: 'arn:aws:iam::588989875114:user/john.doe',                    posture_category: 'access_control', risk_score: 55, sla_status: 'active'   },
  { rule_id: 'aws.iam.password_policy',         title: 'IAM password policy minimum length below 14 characters', severity: 'critical', status: 'FAIL', service: 'iam',      provider: 'aws', account_id: '198765432109', region: 'global',     age_days: 89,  auto_remediable: false, resource_uid: 'arn:aws:iam::198765432109:root',                             posture_category: 'access_control', risk_score: 80, sla_status: 'breached' },
  { rule_id: 'aws.iam.access_key_rotation',     title: 'IAM access key not rotated in 90+ days',               severity: 'high',     status: 'FAIL', service: 'iam',        provider: 'aws', account_id: '588989875114', region: 'global',     age_days: 102, auto_remediable: false, resource_uid: 'arn:aws:iam::588989875114:user/admin',                       posture_category: 'access_control', risk_score: 75, sla_status: 'breached' },
  { rule_id: 'aws.iam.admin_policy',            title: 'IAM policy grants full administrative privileges (*:*)', severity: 'medium',   status: 'FAIL', service: 'iam',       provider: 'aws', account_id: '198765432109', region: 'global',     age_days: 15,  auto_remediable: false, resource_uid: 'arn:aws:iam::198765432109:policy/AdminAccess',               posture_category: 'access_control', risk_score: 68, sla_status: 'active'   },
  { rule_id: 'aws.ec2.sg_open_ssh',             title: 'Security group allows unrestricted SSH (port 22)',      severity: 'critical', status: 'FAIL', service: 'ec2',        provider: 'aws', account_id: '312456789012', region: 'eu-west-1',  age_days: 34,  auto_remediable: true,  resource_uid: 'arn:aws:ec2:eu-west-1:312456789012:security-group/sg-0abc1', posture_category: 'network',        risk_score: 91, sla_status: 'breached' },
  { rule_id: 'aws.ec2.sg_open_rdp',            title: 'Security group allows unrestricted RDP (port 3389)',    severity: 'critical', status: 'FAIL', service: 'ec2',        provider: 'aws', account_id: '312456789012', region: 'eu-west-1',  age_days: 34,  auto_remediable: true,  resource_uid: 'arn:aws:ec2:eu-west-1:312456789012:security-group/sg-0abc2', posture_category: 'network',        risk_score: 94, sla_status: 'active'   },
  { rule_id: 'aws.cloudtrail.enabled',          title: 'CloudTrail trail not enabled in all regions',          severity: 'high',     status: 'FAIL', service: 'cloudtrail', provider: 'aws', account_id: '198765432109', region: 'ap-south-1', age_days: 8,   auto_remediable: true,  resource_uid: 'arn:aws:cloudtrail:ap-south-1:198765432109:trail/default',    posture_category: 'logging',        risk_score: 78, sla_status: 'active'   },
  { rule_id: 'aws.rds.encryption',              title: 'RDS instance not encrypted at rest',                   severity: 'high',     status: 'FAIL', service: 'rds',        provider: 'aws', account_id: '588989875114', region: 'us-east-1',  age_days: 56,  auto_remediable: false, resource_uid: 'arn:aws:rds:us-east-1:588989875114:db:prod-mysql',           posture_category: 'encryption',     risk_score: 83, sla_status: 'breached' },
  { rule_id: 'aws.rds.backup_retention',        title: 'RDS automated backup retention less than 7 days',      severity: 'medium',   status: 'FAIL', service: 'rds',        provider: 'aws', account_id: '312456789012', region: 'us-east-1',  age_days: 21,  auto_remediable: false, resource_uid: 'arn:aws:rds:us-east-1:312456789012:db:analytics-pg',         posture_category: 'backup',         risk_score: 58, sla_status: 'active'   },
  { rule_id: 'aws.rds.public_access',           title: 'RDS instance is publicly accessible',                  severity: 'critical', status: 'FAIL', service: 'rds',        provider: 'aws', account_id: '198765432109', region: 'us-east-1',  age_days: 18,  auto_remediable: false, resource_uid: 'arn:aws:rds:us-east-1:198765432109:db:dev-reporting',        posture_category: 'public_access',  risk_score: 96, sla_status: 'active'   },
  { rule_id: 'aws.lambda.env_encrypted',        title: 'Lambda environment variables not encrypted with KMS',  severity: 'medium',   status: 'FAIL', service: 'lambda',     provider: 'aws', account_id: '198765432109', region: 'us-east-1',  age_days: 4,   auto_remediable: false, resource_uid: 'arn:aws:lambda:us-east-1:198765432109:function:api-handler', posture_category: 'encryption',     risk_score: 52, sla_status: 'active'   },
  { rule_id: 'aws.kms.key_rotation',            title: 'KMS CMK automatic key rotation not enabled',           severity: 'medium',   status: 'FAIL', service: 'kms',        provider: 'aws', account_id: '588989875114', region: 'us-east-1',  age_days: 120, auto_remediable: true,  resource_uid: 'arn:aws:kms:us-east-1:588989875114:key/abc-123',             posture_category: 'key_management', risk_score: 61, sla_status: 'breached' },
  { rule_id: 'aws.ec2.ebs_encryption',          title: 'EBS volume not encrypted',                             severity: 'high',     status: 'FAIL', service: 'ec2',        provider: 'aws', account_id: '198765432109', region: 'eu-west-1',  age_days: 44,  auto_remediable: false, resource_uid: 'arn:aws:ec2:eu-west-1:198765432109:volume/vol-0abc5',        posture_category: 'encryption',     risk_score: 70, sla_status: 'breached' },
  { rule_id: 'aws.iam.root_access_key',         title: 'Root account access key exists',                       severity: 'critical', status: 'FAIL', service: 'iam',        provider: 'aws', account_id: '312456789012', region: 'global',     age_days: 200, auto_remediable: false, resource_uid: 'arn:aws:iam::312456789012:root',                             posture_category: 'access_control', risk_score: 98, sla_status: 'breached' },
  { rule_id: 'aws.sns.encryption',              title: 'SNS topic not encrypted with KMS',                     severity: 'low',      status: 'FAIL', service: 'sns',        provider: 'aws', account_id: '588989875114', region: 'us-east-1',  age_days: 6,   auto_remediable: true,  resource_uid: 'arn:aws:sns:us-east-1:588989875114:alerts-topic',            posture_category: 'encryption',     risk_score: 35, sla_status: 'active'   },
  { rule_id: 'aws.dynamodb.encryption',         title: 'DynamoDB table not encrypted with customer-managed key', severity: 'low',    status: 'FAIL', service: 'dynamodb',   provider: 'aws', account_id: '198765432109', region: 'us-east-1',  age_days: 9,   auto_remediable: false, resource_uid: 'arn:aws:dynamodb:us-east-1:198765432109:table/users',        posture_category: 'encryption',     risk_score: 40, sla_status: 'active'   },
  { rule_id: 'aws.ec2.instance_metadata_v2',    title: 'EC2 instance metadata service v2 not enforced',        severity: 'medium',   status: 'PASS', service: 'ec2',        provider: 'aws', account_id: '312456789012', region: 'us-east-1',  age_days: 3,   auto_remediable: true,  resource_uid: 'arn:aws:ec2:us-east-1:312456789012:instance/i-0abc9',        posture_category: 'configuration',  risk_score: 48, sla_status: 'active'   },
  { rule_id: 'aws.vpc.flow_logs',               title: 'VPC flow logs not enabled',                            severity: 'medium',   status: 'FAIL', service: 'vpc',        provider: 'aws', account_id: '198765432109', region: 'us-east-1',  age_days: 55,  auto_remediable: false, resource_uid: 'arn:aws:ec2:us-east-1:198765432109:vpc/vpc-0abc1',          posture_category: 'logging',        risk_score: 60, sla_status: 'breached' },
  { rule_id: 'aws.guardduty.enabled',           title: 'GuardDuty not enabled in region',                      severity: 'high',     status: 'FAIL', service: 'guardduty',  provider: 'aws', account_id: '312456789012', region: 'ap-south-1', age_days: 77,  auto_remediable: true,  resource_uid: 'arn:aws:guardduty:ap-south-1:312456789012:detector',         posture_category: 'threat_detection', risk_score: 82, sla_status: 'breached' },
  { rule_id: 'aws.config.recorder',             title: 'AWS Config recorder not enabled',                      severity: 'medium',   status: 'FAIL', service: 'config',     provider: 'aws', account_id: '588989875114', region: 'eu-west-1',  age_days: 33,  auto_remediable: false, resource_uid: 'arn:aws:config:eu-west-1:588989875114:config-recorder',      posture_category: 'logging',        risk_score: 63, sla_status: 'active'   },
  { rule_id: 'aws.ecr.image_scan',              title: 'ECR repository image scanning on push not enabled',    severity: 'low',      status: 'PASS', service: 'ecr',        provider: 'aws', account_id: '198765432109', region: 'us-east-1',  age_days: 2,   auto_remediable: true,  resource_uid: 'arn:aws:ecr:us-east-1:198765432109:repository/api',          posture_category: 'configuration',  risk_score: 30, sla_status: 'active'   },
];

// ── Severity Donut (mirrors InvDonut from inventory) ────────────────────────
function PosDonut({ slices, size = 200 }) {
  const total = slices.reduce((s, x) => s + x.value, 0) || 1;
  const cx = size / 2, cy = size / 2;
  const r   = size / 2 - 8;
  const ir  = r * 0.58;
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
    return { ...s, d, pct, mid, sweep };
  });
  return (
    <svg width={size} height={size} style={{ flexShrink: 0, display: 'block' }}>
      <circle cx={cx} cy={cy} r={(r + ir) / 2} fill="none"
        stroke="var(--border-primary)" strokeWidth={r - ir} />
      {paths.map((p, i) => <path key={i} d={p.d} fill={p.color} opacity={0.9} />)}
      {paths.map((p, i) => p.pct >= 6 && (
        <text key={`lbl-${i}`}
          x={cx + labelR * Math.cos(p.mid)} y={cy + labelR * Math.sin(p.mid) + 4}
          textAnchor="middle"
          style={{ fontSize: 10, fontWeight: 700, fill: '#fff', fontFamily: 'inherit', pointerEvents: 'none' }}>
          {p.pct}%
        </text>
      ))}
    </svg>
  );
}

// ── Posture category styling ────────────────────────────────────────────────
const POSTURE_COLORS = {
  encryption: '#8b5cf6',
  public_access: '#ef4444',
  logging: '#3b82f6',
  backup: '#06b6d4',
  access_control: '#f59e0b',
  network: '#6366f1',
  key_management: '#ec4899',
  configuration: '#64748b',
  data_protection: '#14b8a6',
  threat_detection: '#f97316',
};

function PostureBadge({ category }) {
  const label = (category || 'configuration').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  const bg = POSTURE_COLORS[category] || '#64748b';
  return (
    <span className="text-xs font-medium px-2 py-1 rounded whitespace-nowrap"
      style={{ backgroundColor: bg + '20', color: bg }}>
      {label}
    </span>
  );
}

function SeverityBadgeInline({ severity }) {
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
  return (
    <span className="text-xs font-bold px-2.5 py-1 rounded-full uppercase tracking-wider"
      style={{ backgroundColor: color + '1a', color, border: `1px solid ${color}4d` }}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  const isFail = (status || '').toUpperCase() === 'FAIL';
  return (
    <span className="text-xs font-semibold px-2 py-1 rounded-full"
      style={{
        backgroundColor: isFail ? 'rgba(239,68,68,0.12)' : 'rgba(34,197,94,0.12)',
        color: isFail ? '#ef4444' : '#22c55e',
      }}>
      {isFail ? 'FAIL' : 'PASS'}
    </span>
  );
}

function ProviderBadge({ provider }) {
  const p = CLOUD_PROVIDERS[(provider || '').toLowerCase()];
  if (!p) return <span className="text-xs uppercase" style={{ color: 'var(--text-tertiary)' }}>{provider}</span>;
  return (
    <span className="text-xs font-semibold px-2 py-0.5 rounded"
      style={{ backgroundColor: p.bgColor, color: p.textColor }}>
      {p.name}
    </span>
  );
}


// ── Detail slide-out panel ──────────────────────────────────────────────────
function FindingDetailPanel({ finding, onClose }) {
  const [copied, setCopied] = useState(null);
  if (!finding) return null;

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  };

  const frameworks = finding.compliance_frameworks;
  const frameworkList = Array.isArray(frameworks)
    ? frameworks
    : (frameworks && typeof frameworks === 'object')
      ? Object.keys(frameworks)
      : [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      {/* Panel */}
      <div className="relative w-full max-w-2xl h-full overflow-y-auto shadow-2xl"
        style={{ backgroundColor: 'var(--bg-primary)' }}>
        {/* Header */}
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 px-6 py-5 border-b"
          style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-primary)' }}>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <SeverityBadgeInline severity={finding.severity} />
              <StatusBadge status={finding.status} />
              {finding.provider && <ProviderBadge provider={finding.provider} />}
            </div>
            <h2 className="text-lg font-bold leading-tight" style={{ color: 'var(--text-primary)' }}>
              {finding.title}
            </h2>
            <code className="text-xs mt-1 block" style={{ color: 'var(--text-muted)' }}>
              {finding.rule_id}
            </code>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:opacity-70 transition-opacity"
            style={{ color: 'var(--text-muted)' }}>
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {/* Resource Details */}
          <section>
            <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
              Resource
            </h3>
            <div className="rounded-lg border p-4 space-y-2" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
              {[
                { label: 'ARN', value: finding.resource_arn },
                { label: 'Resource ID', value: finding.resource_uid },
                { label: 'Type', value: finding.resource_type },
                { label: 'Service', value: finding.service?.toUpperCase() },
                { label: 'Region', value: finding.region },
                { label: 'Account', value: finding.account_id },
                { label: 'Provider', value: finding.provider?.toUpperCase() },
              ].filter(r => r.value).map(r => (
                <div key={r.label} className="flex items-start justify-between gap-4">
                  <span className="text-xs font-medium shrink-0 w-20" style={{ color: 'var(--text-muted)' }}>{r.label}</span>
                  <div className="flex items-center gap-1.5 min-w-0 flex-1">
                    <code className="text-xs break-all" style={{ color: 'var(--text-secondary)' }}>{r.value}</code>
                    {r.label === 'ARN' && (
                      <button onClick={() => copyToClipboard(r.value, 'arn')}
                        className="shrink-0 p-0.5 rounded hover:opacity-70" style={{ color: 'var(--text-muted)' }}>
                        {copied === 'arn' ? <Check className="w-3.5 h-3.5" style={{ color: '#22c55e' }} /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Description & Rationale */}
          {(finding.description || finding.rationale) && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                Description
              </h3>
              <div className="rounded-lg border p-4 text-sm leading-relaxed"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                {finding.description || finding.rationale}
              </div>
            </section>
          )}

          {/* Evidence */}
          {(finding.checked_fields || finding.actual_values) && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                Evidence
              </h3>
              <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                {finding.checked_fields && (
                  <div className="p-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                    <span className="text-xs font-semibold block mb-2" style={{ color: 'var(--text-muted)' }}>Checked Fields</span>
                    <pre className="text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                      {typeof finding.checked_fields === 'string'
                        ? finding.checked_fields
                        : JSON.stringify(finding.checked_fields, null, 2)}
                    </pre>
                  </div>
                )}
                {finding.actual_values && (
                  <div className="p-4">
                    <span className="text-xs font-semibold block mb-2" style={{ color: 'var(--text-muted)' }}>Actual Values</span>
                    <pre className="text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>
                      {typeof finding.actual_values === 'string'
                        ? finding.actual_values
                        : JSON.stringify(finding.actual_values, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                Remediation
              </h3>
              <div className="rounded-lg border p-4 text-sm leading-relaxed"
                style={{ backgroundColor: 'rgba(59,130,246,0.06)', borderColor: 'rgba(59,130,246,0.2)', color: 'var(--text-secondary)' }}>
                <div className="flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#3b82f6' }} />
                  <span style={{ whiteSpace: 'pre-wrap' }}>{finding.remediation}</span>
                </div>
              </div>
            </section>
          )}

          {/* Posture & Domain */}
          <section>
            <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
              Classification
            </h3>
            <div className="flex flex-wrap gap-2">
              <PostureBadge category={finding.posture_category} />
              {finding.domain && (
                <span className="text-xs font-medium px-2 py-1 rounded"
                  style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                  {finding.domain}
                </span>
              )}
              {finding.risk_score != null && (
                <span className="text-xs font-bold px-2 py-1 rounded"
                  style={{
                    backgroundColor: finding.risk_score >= 70 ? 'rgba(239,68,68,0.12)' : 'rgba(234,179,8,0.12)',
                    color: finding.risk_score >= 70 ? '#ef4444' : '#eab308',
                  }}>
                  Risk: {finding.risk_score}
                </span>
              )}
            </div>
          </section>

          {/* Compliance Frameworks */}
          {frameworkList.length > 0 && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                Compliance Mapping
              </h3>
              <div className="flex flex-wrap gap-2">
                {frameworkList.map((fw, i) => {
                  const label = typeof fw === 'object' ? (fw.name || fw.id || JSON.stringify(fw)) : fw;
                  return (
                    <span key={`fw-${i}`} className="text-xs font-medium px-2.5 py-1 rounded-full"
                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                      {label}
                    </span>
                  );
                })}
              </div>
            </section>
          )}

          {/* MITRE ATT&CK */}
          {((finding.mitre_tactics && finding.mitre_tactics.length > 0) ||
            (finding.mitre_techniques && finding.mitre_techniques.length > 0)) && (
            <section>
              <h3 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                MITRE ATT&CK
              </h3>
              <div className="flex flex-wrap gap-2">
                {(finding.mitre_tactics || []).map((t, i) => {
                  const label = typeof t === 'object' ? (t.name || t.tactic || JSON.stringify(t)) : t;
                  return (
                    <span key={`tactic-${i}`} className="text-xs font-medium px-2 py-1 rounded"
                      style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444' }}>
                      {label}
                    </span>
                  );
                })}
                {(finding.mitre_techniques || []).map((t, i) => {
                  const tid = typeof t === 'object' ? t.technique_id : null;
                  const tname = typeof t === 'object' ? (t.technique_name || t.name) : t;
                  const label = tid && tname ? `${tid}: ${tname}` : (tname || tid || (typeof t === 'string' ? t : JSON.stringify(t)));
                  return (
                    <span key={`technique-${i}`} className="text-xs font-medium px-2 py-1 rounded"
                      style={{ backgroundColor: 'rgba(249,115,22,0.1)', color: '#f97316' }}>
                      {label}
                    </span>
                  );
                })}
              </div>
            </section>
          )}

          {/* Link to asset detail */}
          {finding.resource_uid && (
            <div className="pt-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <a href={`/ui/inventory/${encodeURIComponent(finding.resource_uid)}`}
                className="inline-flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-lg transition-opacity hover:opacity-80"
                style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
                <ExternalLink className="w-4 h-4" /> View Asset Detail
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


// ── Export helpers ──────────────────────────────────────────────────────────

function escapeCSV(val) {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

async function exportCSV() {
  const data = await fetchView('misconfig');
  if (data.error) { alert(`Export failed: ${data.error}`); return; }

  const allFindings = (data.findings || []).map(f => ({
    ...f,
    account_id: f.account_id || '',
    resource_uid: f.resource_id || f.resource_uid || '',
  }));

  const headers = ['Severity','Status','Finding','Rule ID','Resource','Resource ARN','Service','Security Posture','Provider','Account','Region','Domain','Risk Score','Detected'];
  const rows = allFindings.map(f => [
    f.severity, f.status, f.title || f.rule_id, f.rule_id, f.resource_uid,
    f.resource_arn || '', f.service, f.posture_category || '', f.provider,
    f.account_id, f.region, f.domain || '', f.risk_score ?? '', f.created_at ?? '',
  ]);
  const csv = [headers.map(escapeCSV).join(','), ...rows.map(r => r.map(escapeCSV).join(','))].join('\n');
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `misconfigurations-${new Date().toISOString().split('T')[0]}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportPDF(findings, summary) {
  const sevCounts = summary?.severity_counts || {};
  const total = summary?.total || 0;
  const now = new Date().toLocaleString();

  const rowsHtml = (findings || []).slice(0, 200).map(f => `
    <tr>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;">
        <span style="background:${(SEVERITY_COLORS[f.severity] || '#999')}22;color:${SEVERITY_COLORS[f.severity] || '#999'};padding:2px 8px;border-radius:9999px;font-weight:700;font-size:10px;text-transform:uppercase;">${f.severity}</span>
      </td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;color:${f.status === 'FAIL' ? '#ef4444' : '#22c55e'};font-weight:600;">${f.status}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${f.title || f.rule_id}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;text-transform:uppercase;">${f.service || ''}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;text-transform:uppercase;">${f.provider || ''}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;">${f.account_id || ''}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-size:11px;">${f.region || ''}</td>
    </tr>
  `).join('');

  const html = `<!DOCTYPE html><html><head><title>Posture Security Report</title>
    <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1e293b;margin:0;padding:32px;}
    @media print{body{padding:16px;} .no-print{display:none;}}</style></head><body>
    <div style="display:flex;align-items:center;justify-content:between;margin-bottom:24px;">
      <div><h1 style="font-size:22px;font-weight:700;margin:0;">Posture Security Report</h1>
      <p style="font-size:12px;color:#64748b;margin:4px 0 0;">Generated: ${now}</p></div>
    </div>
    <div style="display:flex;gap:12px;margin-bottom:24px;">
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#fef2f2;border:1px solid #fecaca;">
        <div style="font-size:10px;color:#991b1b;font-weight:600;text-transform:uppercase;">Critical</div>
        <div style="font-size:24px;font-weight:700;color:#dc2626;">${(sevCounts.critical || 0).toLocaleString()}</div></div>
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#fff7ed;border:1px solid #fed7aa;">
        <div style="font-size:10px;color:#9a3412;font-weight:600;text-transform:uppercase;">High</div>
        <div style="font-size:24px;font-weight:700;color:#ea580c;">${(sevCounts.high || 0).toLocaleString()}</div></div>
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#fefce8;border:1px solid #fde68a;">
        <div style="font-size:10px;color:#854d0e;font-weight:600;text-transform:uppercase;">Medium</div>
        <div style="font-size:24px;font-weight:700;color:#ca8a04;">${(sevCounts.medium || 0).toLocaleString()}</div></div>
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#f0f9ff;border:1px solid #bae6fd;">
        <div style="font-size:10px;color:#075985;font-weight:600;text-transform:uppercase;">Low</div>
        <div style="font-size:24px;font-weight:700;color:#0284c7;">${(sevCounts.low || 0).toLocaleString()}</div></div>
      <div style="flex:1;padding:12px 16px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0;">
        <div style="font-size:10px;color:#475569;font-weight:600;text-transform:uppercase;">Total</div>
        <div style="font-size:24px;font-weight:700;color:#1e293b;">${total.toLocaleString()}</div></div>
    </div>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;">
      <thead><tr style="background:#f1f5f9;">
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Severity</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Status</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Finding</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Service</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Provider</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Account</th>
        <th style="padding:8px;text-align:left;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Region</th>
      </tr></thead>
      <tbody>${rowsHtml}</tbody>
    </table>
    <p style="margin-top:16px;font-size:10px;color:#94a3b8;">Showing up to 200 findings. Export CSV for full data.</p>
    <script>window.onload=function(){window.print();}</script>
  </body></html>`;

  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); }
}


// ── Top Failing Rules Chart ──────────────────────────────────────────────────

function TopFailingRulesChart({ topRules }) {
  return (
    <div>
      <h3 className="text-sm font-bold uppercase tracking-wider mb-4" style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
        Top Failing Rules
      </h3>
      <div className="space-y-1.5">
        {topRules.length === 0 && (
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No data</p>
        )}
        {topRules.slice(0, 8).map((rule) => {
          const maxCount = topRules[0]?.count || 1;
          const pct = Math.round((rule.count / maxCount) * 100);
          const sevColor = SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.medium;
          return (
            <div key={rule.rule_id}>
              <div className="flex items-center justify-between mb-0.5">
                <span className="text-xs font-medium truncate flex-1 mr-2" style={{ color: 'var(--text-secondary)' }}>
                  {rule.title || rule.rule_id}
                </span>
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="text-xs font-bold uppercase tracking-wider px-1.5 py-0 rounded"
                    style={{ backgroundColor: sevColor + '1a', color: sevColor, fontSize: 10 }}>
                    {rule.severity}
                  </span>
                  <span className="text-xs font-bold w-6 text-right" style={{ color: 'var(--text-primary)' }}>
                    {rule.count}
                  </span>
                </div>
              </div>
              <div className="w-full h-1 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="h-full rounded-full" style={{
                  width: `${pct}%`,
                  backgroundColor: sevColor,
                }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ── Top Failing Services Chart ───────────────────────────────────────────────

function TopFailingServicesChart({ topServices }) {
  const maxFail = topServices[0]?.fail || 1;
  return (
    <div>
      <h3 style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)',
        textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 16 }}>
        Top Failing Services
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {topServices.length === 0 && (
          <p style={{ fontSize: 13, color: 'var(--text-tertiary)' }}>No data</p>
        )}
        {topServices.map((svc) => {
          const barW    = Math.round((svc.fail / maxFail) * 100);
          const failPct = svc.total > 0 ? Math.round((svc.fail / svc.total) * 100) : 0;
          const col     = failPct >= 60 ? C.critical : failPct >= 35 ? C.high : C.medium;
          return (
            <div key={svc.service}>
              <div style={{ display: 'flex', alignItems: 'center',
                justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)',
                  textTransform: 'uppercase', letterSpacing: '0.04em', flex: 1,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {svc.service}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: col,
                    fontVariantNumeric: 'tabular-nums' }}>{svc.fail} fail</span>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '1px 6px',
                    borderRadius: 4, backgroundColor: `${col}1a`, color: col }}>
                    {failPct}%
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)',
                    fontVariantNumeric: 'tabular-nums' }}>{svc.total} total</span>
                </div>
              </div>
              {/* Two-tone bar: fail coloured + pass muted */}
              <div style={{ width: '100%', height: 5, borderRadius: 3,
                backgroundColor: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                <div style={{ width: `${barW}%`, height: '100%',
                  borderRadius: 3, backgroundColor: col, opacity: 0.85 }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ── Service Breakdown Chart ─────────────────────────────────────────────────

function ServiceBreakdownChart({ byService }) {
  return (
    <div>
      <h3 className="text-sm font-bold uppercase tracking-wider mb-4" style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
        Findings by Service
      </h3>
      <div className="space-y-2.5">
        {byService.length === 0 && (
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No data</p>
        )}
        {byService.slice(0, 10).map((svc) => {
          const maxCount = byService[0]?.total || 1;
          const pct = Math.round((svc.total / maxCount) * 100);
          const failPct = svc.total > 0 ? Math.round((svc.fail / svc.total) * 100) : 0;
          return (
            <div key={svc.service}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium uppercase" style={{ color: 'var(--text-secondary)' }}>
                  {svc.service}
                </span>
                <div className="flex items-center gap-3 text-xs">
                  <span style={{ color: '#ef4444' }}>{svc.fail} fail</span>
                  <span style={{ color: 'var(--text-muted)' }}>{svc.total} total</span>
                </div>
              </div>
              <div className="w-full h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="h-full rounded-full" style={{
                  width: `${pct}%`,
                  backgroundColor: failPct > 50 ? '#ef4444' : failPct > 25 ? '#f97316' : '#3b82f6',
                }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ── Posture Trend Chart ──────────────────────────────────────────────────────

// Scan tick labels shared by both trend sparklines
const SCAN_TICKS = [
  { idx: 0, label: POSTURE_SCAN_TREND[0].date },
  { idx: POSTURE_SCAN_TREND.length - 1, label: POSTURE_SCAN_TREND[POSTURE_SCAN_TREND.length - 1].date },
];

function PostureTrendChart({ data = POSTURE_SCAN_TREND }) {
  const last  = data[data.length - 1];
  const first = data[0];
  const rateΔ  = last.passRate - first.passRate;
  const critΔ  = last.critical - first.critical;
  const highΔ  = last.high     - first.high;
  const totalΔ = last.total    - first.total;

  const statPill = (label, value, delta, goodDir) => {
    const improved = goodDir === 'up' ? delta >= 0 : delta <= 0;
    const dc = improved ? C.clean : C.critical;
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
        {/* Pass rate prominent */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Pass Rate</span>
          <span style={{ fontSize: 18, fontWeight: 900, color: C.clean,
            fontVariantNumeric: 'tabular-nums' }}>{d.passRate}%</span>
        </div>
        {/* Severity breakdown */}
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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between',
        alignItems: 'center', marginBottom: 8 }}>
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)',
            textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Posture Trend
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
            {first.date} – {last.date} · {data.length} scans
          </div>
        </div>
        {/* legend pills */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {[
            { label: 'Critical', color: C.critical },
            { label: 'High',     color: C.high     },
            { label: 'Medium',   color: C.medium   },
            { label: 'Pass Rate',color: C.clean    },
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

      {/* Composed chart — bars (findings) + line (pass rate) */}
      <div style={{ flex: 1, minHeight: 0 }}>
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 6, right: 10, left: -14, bottom: 0 }}
            barCategoryGap="28%">
            <defs>
              {[
                { id: 'gc', color: C.critical },
                { id: 'gh', color: C.high     },
                { id: 'gm', color: C.medium   },
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

            {/* Left axis — finding counts */}
            <YAxis yAxisId="count"
              tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
              axisLine={false} tickLine={false} width={24} />

            {/* Right axis — pass rate % */}
            <YAxis yAxisId="rate" orientation="right" domain={[0, 100]}
              tick={{ fontSize: 10, fill: C.clean, fontFamily: 'inherit' }}
              axisLine={false} tickLine={false} width={28}
              tickFormatter={v => `${v}%`} />

            {/* 80% target line */}
            <ReferenceLine yAxisId="rate" y={80} stroke={C.clean}
              strokeDasharray="5 3" strokeOpacity={0.45}
              label={{ value: 'Target', position: 'insideTopRight',
                fontSize: 9, fill: C.clean, opacity: 0.7 }} />

            <RechartsTip content={<TrendTooltip />} />

            {/* Stacked bars — medium → high → critical (bottom to top) */}
            <Bar yAxisId="count" dataKey="medium"   name="Medium"   stackId="s"
              fill={`url(#gm)`} radius={[0, 0, 0, 0]} />
            <Bar yAxisId="count" dataKey="high"     name="High"     stackId="s"
              fill={`url(#gh)`} radius={[0, 0, 0, 0]} />
            <Bar yAxisId="count" dataKey="critical" name="Critical" stackId="s"
              fill={`url(#gc)`} radius={[3, 3, 0, 0]} />

            {/* Pass rate line */}
            <Line yAxisId="rate" type="monotone" dataKey="passRate" name="Pass Rate"
              stroke={C.clean} strokeWidth={2.5} dot={{ r: 3, fill: C.clean, strokeWidth: 0 }}
              activeDot={{ r: 5, fill: C.clean, stroke: 'var(--bg-card)', strokeWidth: 2 }} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}


// ── By-Category Radar Chart ──────────────────────────────────────────────────


function ByCategoryChart({ data = POSTURE_BY_CATEGORY }) {
  const radarData = data.map(cat => ({
    subject:   cat.category,
    passScore: Math.round(((cat.total - cat.fail) / cat.total) * 100),
    target:    80,
    _cat:      cat,
  }));

  const overallPass = Math.round(
    (data.reduce((s, d) => s + (d.total - d.fail), 0) /
     data.reduce((s, d) => s + d.total, 0)) * 100
  );

  const RadarTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    const d = payload[0]?.payload;
    if (!d) return null;
    const cat  = d._cat;
    const pass = cat.total - cat.fail;
    const passPct = d.passScore;
    const col  = passPct >= 70 ? C.clean : passPct >= 50 ? C.medium : C.critical;
    const gap  = 80 - passPct;
    return (
      <div style={{
        backgroundColor: 'var(--bg-card)', border: `1px solid ${col}40`,
        borderRadius: 10, padding: '12px 14px', minWidth: 200,
        boxShadow: '0 6px 24px rgba(0,0,0,0.22)',
      }}>
        {/* Category chip */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
          <span style={{ width: 10, height: 10, borderRadius: 3,
            backgroundColor: cat.color, flexShrink: 0 }} />
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
            {cat.category}
          </span>
        </div>

        {/* Pass / fail big numbers */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 10 }}>
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 1 }}>Passing</div>
            <div style={{ fontSize: 22, fontWeight: 900, color: C.clean,
              lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{pass}</div>
          </div>
          <div style={{ width: 1, backgroundColor: 'var(--border-primary)' }} />
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 1 }}>Failing</div>
            <div style={{ fontSize: 22, fontWeight: 900, color: C.critical,
              lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{cat.fail}</div>
          </div>
          <div style={{ width: 1, backgroundColor: 'var(--border-primary)' }} />
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 1 }}>Total</div>
            <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--text-primary)',
              lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{cat.total}</div>
          </div>
        </div>

        {/* Pass / fail split bar */}
        <div style={{ height: 6, borderRadius: 3, backgroundColor: 'var(--bg-tertiary)',
          overflow: 'hidden', marginBottom: 4 }}>
          <div style={{ width: `${passPct}%`, height: '100%',
            background: `linear-gradient(90deg, ${C.clean}, ${C.clean}bb)`,
            borderRadius: 3 }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
          <span style={{ fontSize: 10, color: C.clean, fontWeight: 600 }}>{passPct}% pass</span>
          <span style={{ fontSize: 10, color: C.critical, fontWeight: 600 }}>{100 - passPct}% fail</span>
        </div>

        {/* Target gap row */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          paddingTop: 8, borderTop: '1px solid var(--border-primary)' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>vs 80% target</span>
          <span style={{
            fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 20,
            backgroundColor: gap <= 0 ? `${C.clean}18` : gap <= 20 ? `${C.amber}18` : `${C.critical}18`,
            color:           gap <= 0 ? C.clean       : gap <= 20 ? C.amber       : C.critical,
          }}>
            {gap <= 0 ? `✓ +${Math.abs(gap)}% above target` : `↑ ${gap}% to close`}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)',
          textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Multi-Domain Posture
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-muted)' }}>
            <span style={{ width: 10, height: 3, backgroundColor: C.clean, borderRadius: 2, display: 'inline-block' }} />
            Pass score
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-muted)' }}>
            <span style={{ width: 10, height: 0, border: `1.5px dashed ${C.indigo}`, display: 'inline-block' }} />
            80% target
          </span>
        </div>
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
        Overall pass rate:&nbsp;
        <span style={{ fontWeight: 700, color: overallPass >= 70 ? C.clean : overallPass >= 50 ? C.medium : C.critical }}>
          {overallPass}%
        </span>
        &nbsp;across {data.length} domains
      </div>

      {/* Radar */}
      <ResponsiveContainer width="100%" height={380}>
        <RadarChart data={radarData} outerRadius="72%" margin={{ top: 16, right: 40, left: 40, bottom: 16 }}>
          <PolarGrid stroke="var(--border-primary)" strokeOpacity={0.6} />
          <PolarAngleAxis
            dataKey="subject"
            tick={{ fontSize: 13, fontWeight: 600, fill: 'var(--text-primary)', fontFamily: 'inherit' }}
          />
          <PolarRadiusAxis
            angle={90} domain={[0, 100]}
            tick={{ fontSize: 9, fill: 'var(--text-muted)' }}
            axisLine={false} tickCount={4}
          />
          {/* 80% target ring */}
          <Radar
            name="Target (80%)" dataKey="target"
            stroke={C.indigo} strokeWidth={1.5} strokeDasharray="5 3"
            fill="transparent"
          />
          {/* Actual pass score */}
          <Radar
            name="Pass Score" dataKey="passScore"
            stroke={C.clean} strokeWidth={2}
            fill={C.clean} fillOpacity={0.22}
            dot={{ r: 3, fill: C.clean, strokeWidth: 0 }}
            activeDot={{ r: 5, fill: C.clean, stroke: 'var(--bg-card)', strokeWidth: 2 }}
          />
          <RechartsTip content={<RadarTooltip />} />
        </RadarChart>
      </ResponsiveContainer>

      {/* Inline 2-col domain list — compact, no card boxes */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 20px', marginTop: 10,
        paddingTop: 10, borderTop: '1px solid var(--border-primary)' }}>
        {data.map(cat => {
          const pct = Math.round(((cat.total - cat.fail) / cat.total) * 100);
          const col = pct >= 70 ? C.clean : pct >= 50 ? C.medium : C.critical;
          return (
            <div key={cat.category} style={{ display: 'flex', alignItems: 'center',
              gap: 7, padding: '4px 0', borderBottom: '1px solid var(--border-primary)' }}>
              {/* colour dot */}
              <span style={{ width: 7, height: 7, borderRadius: 2,
                backgroundColor: col, flexShrink: 0 }} />
              {/* name */}
              <span style={{ fontSize: 11, color: 'var(--text-secondary)', flex: 1,
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {cat.category}
              </span>
              {/* mini progress bar */}
              <div style={{ width: 36, height: 3, borderRadius: 2,
                backgroundColor: 'var(--bg-tertiary)', flexShrink: 0 }}>
                <div style={{ width: `${pct}%`, height: '100%',
                  borderRadius: 2, backgroundColor: col }} />
              </div>
              {/* pass% */}
              <span style={{ fontSize: 11, fontWeight: 700, color: col,
                fontVariantNumeric: 'tabular-nums', width: 30, textAlign: 'right',
                flexShrink: 0 }}>{pct}%</span>
              {/* fail count */}
              <span style={{ fontSize: 10, color: 'var(--text-muted)',
                flexShrink: 0, width: 28, textAlign: 'right' }}>
                {cat.fail}↓
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ── Quick Wins Panel ─────────────────────────────────────────────────────────

function QuickWinsPanel({ findings }) {
  const wins = findings.filter(f => f.auto_remediable && f.status === 'FAIL')
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 8);

  const FIX_TIME = { critical: '2–5 min', high: '5–10 min', medium: '10–15 min', low: '< 5 min' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {wins.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '32px 0', color: 'var(--text-tertiary)', fontSize: 13 }}>
          <ShieldCheck style={{ width: 32, height: 32, margin: '0 auto 8px', color: C.clean }} />
          No quick wins — all auto-remediable findings resolved!
        </div>
      ) : wins.map((f, i) => (
        <div key={i} style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '10px 14px', borderRadius: 8,
          border: '1px solid var(--border-primary)',
          backgroundColor: 'var(--bg-card)',
        }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
            backgroundColor: SEVERITY_COLORS[f.severity] || C.medium,
          }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {f.title}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              {f.service?.toUpperCase()} · {f.region} · Risk {f.risk_score}
            </div>
          </div>
          <div style={{ flexShrink: 0, textAlign: 'right' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: C.clean, fontSize: 11, fontWeight: 600 }}>
              <Zap style={{ width: 11, height: 11 }} />
              {FIX_TIME[f.severity]}
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>auto-fix</div>
          </div>
        </div>
      ))}
    </div>
  );
}


// ── Main Page ─────────────────────────────────────────────────────────────────
export default function MisconfigurationsPage() {
  const { provider: globalProvider, account: globalAccount, region: globalRegion } = useGlobalFilter();

  // Data state
  const [loading, setLoading] = useState(true);
  const [allFindings, setAllFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);
  const [exporting, setExporting] = useState(false);
  const [scanTrendData, setScanTrendData] = useState([]);

  // Detail panel
  const [selectedFinding, setSelectedFinding] = useState(null);

  // ── Fetch ─────────────────────────────────────────────────────────────
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchView('misconfig', {
        provider: globalProvider ? globalProvider.toLowerCase() : undefined,
        account: globalAccount || undefined,
        region: globalRegion || undefined,
      });
      if (data.error) {
        setError(data.error);
        setLoading(false);
        return;
      }

      const kpi = data.kpi || {};

      // Process findings
      const processed = (data.findings || []).map(f => ({
        ...f,
        account_id: f.account_id || '',
        resource_uid: f.resource_id || f.resource_uid || '',
        title: f.title || f.rule_name || f.rule_id || '',
        created_at: f.detected_at || f.created_at || '',
      }));

      // Derive top_rules
      const ruleCounts = {};
      processed.forEach(f => {
        const key = f.rule_id || f.title;
        if (!ruleCounts[key]) ruleCounts[key] = { rule_id: f.rule_id, title: f.title, severity: f.severity, count: 0 };
        ruleCounts[key].count++;
      });
      const topRules = Object.values(ruleCounts).sort((a, b) => b.count - a.count).slice(0, 10);

      // Derive by_service
      const byServiceList = Object.entries(data.byService || {}).map(([service, count]) => ({
        service,
        total: count,
        fail: count,
      })).sort((a, b) => b.total - a.total);

      setSummary({
        total: kpi.total || 0,
        severity_counts: {
          critical: kpi.critical || 0,
          high: kpi.high || 0,
          medium: kpi.medium || 0,
          low: kpi.low || 0,
        },
        status_counts: {
          FAIL: kpi.failed || 0,
          PASS: kpi.passed || 0,
        },
        top_rules: topRules,
        by_service: byServiceList,
      });

      if (data.scanTrend) setScanTrendData(data.scanTrend);

      // Fall back to mock findings when API returns nothing
      setAllFindings(processed.length > 0 ? processed : POSTURE_FINDINGS_MOCK);
    } catch (err) {
      console.warn('[misconfig] fetch error — using mock data:', err);
      setAllFindings(POSTURE_FINDINGS_MOCK);
    } finally {
      setLoading(false);
    }
  }, [globalProvider, globalAccount, globalRegion]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // ── Derived data ──────────────────────────────────────────────────────
  const sevCounts = summary?.severity_counts || { critical: 0, high: 0, medium: 0, low: 0 };
  const totalFindings = summary?.total || 0;
  const statusCounts = summary?.status_counts || {};
  const topRules = summary?.top_rules || [];
  const byService = summary?.by_service || [];

  // ── Top failing services (derived from allFindings) ───────────────────
  const topServices = useMemo(() => {
    const counts = {};
    allFindings.forEach(f => {
      const svc = f.service || 'unknown';
      if (!counts[svc]) counts[svc] = { service: svc, fail: 0, total: 0 };
      counts[svc].total++;
      if (f.status === 'FAIL') counts[svc].fail++;
    });
    return Object.values(counts).sort((a, b) => b.fail - a.fail).slice(0, 8);
  }, [allFindings]);

  // ── Unique values helper ──────────────────────────────────────────────
  const uniqueVals = useCallback((key) => {
    return [...new Set(allFindings.map(f => f[key]).filter(Boolean))].sort();
  }, [allFindings]);

  // ── By-service grouped data ───────────────────────────────────────────
  const byServiceData = useMemo(() => {
    const groups = {};
    allFindings.forEach(f => {
      const svc = f.service || 'unknown';
      if (!groups[svc]) groups[svc] = [];
      groups[svc].push(f);
    });
    return Object.entries(groups)
      .sort(([, a], [, b]) => b.length - a.length)
      .flatMap(([, items]) => items);
  }, [allFindings]);

  // ── By-category grouped data ──────────────────────────────────────────
  const byCategoryData = useMemo(() => {
    const groups = {};
    allFindings.forEach(f => {
      const cat = f.posture_category || 'configuration';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(f);
    });
    return Object.entries(groups)
      .sort(([, a], [, b]) => b.length - a.length)
      .flatMap(([, items]) => items);
  }, [allFindings]);

  // ── Table columns ─────────────────────────────────────────────────────
  const columns = useMemo(() => [
    {
      accessorKey: 'provider',
      header: 'Provider',
      size: 90,
      cell: (info) => <ProviderBadge provider={info.getValue()} />,
    },
    {
      accessorKey: 'account_id',
      header: 'Account',
      size: 130,
      cell: (info) => (
        <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue() || '\u2014'}
        </span>
      ),
    },
    {
      accessorKey: 'region',
      header: 'Region',
      size: 120,
      cell: (info) => (
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
          {info.getValue() || '\u2014'}
        </span>
      ),
    },
    {
      accessorKey: 'service',
      header: 'Service',
      size: 85,
      cell: (info) => (
        <span className="text-xs font-semibold uppercase" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'title',
      header: 'Rule ID',
      size: 320,
      cell: (info) => (
        <div className="min-w-0">
          <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
            {info.getValue()}
          </p>
          <code className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            {info.row.original.rule_id}
          </code>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 80,
      cell: (info) => <StatusBadge status={info.getValue()} />,
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 100,
      cell: (info) => <SeverityBadgeInline severity={info.getValue()} />,
    },
    {
      accessorKey: 'age_days',
      header: 'Age',
      size: 80,
      cell: (info) => {
        const age = info.getValue() ?? info.row.original.age_days;
        if (age == null) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>;
        return (
          <span className="text-xs font-semibold" style={{ color: age > 60 ? C.critical : age > 30 ? C.medium : 'var(--text-secondary)' }}>
            {age}d
          </span>
        );
      },
    },
    {
      accessorKey: 'auto_remediable',
      header: 'Fix',
      size: 60,
      enableSorting: false,
      cell: (info) => info.getValue()
        ? <span title="Auto-remediable"><Zap style={{ width: 13, height: 13, color: C.sky }} /></span>
        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>,
    },
    {
      id: 'threat_link',
      header: '',
      size: 100,
      enableSorting: false,
      cell: (info) => {
        const ruleId = info.row.original.rule_id;
        return (
          <Link
            href={`/threats?search=${encodeURIComponent(ruleId || '')}`}
            className="inline-flex items-center gap-1 text-xs font-medium hover:opacity-80 transition-opacity whitespace-nowrap"
            style={{ color: 'var(--accent-primary)' }}
            onClick={(e) => e.stopPropagation()}
          >
            View Threat <ArrowRight className="w-3 h-3" />
          </Link>
        );
      },
    },
  ], []);

  // ── Page context ──────────────────────────────────────────────────────
  const pageContext = useMemo(() => ({
    title: 'Posture Security',
    brief: 'Cloud resource misconfigurations across all connected providers and accounts',
    details: [
      'Focus on critical and high severity findings first',
      'Use "By Service" tab to see which services need the most attention',
      'Click any finding row to view remediation guidance',
    ],
    tabs: [
      { id: 'overview',    label: 'Overview' },
      { id: 'findings',    label: 'All Findings', count: allFindings.length },
    ],
  }), [allFindings]);

  // ── KPI groups ────────────────────────────────────────────────────────
  const kpiGroups = useMemo(() => [
    {
      title: 'Severity Breakdown',
      items: [
        { label: 'Critical', value: sevCounts.critical },
        { label: 'High', value: sevCounts.high },
        { label: 'Medium', value: sevCounts.medium },
      ],
    },
    {
      title: 'Summary',
      items: [
        { label: 'Total Findings', value: totalFindings },
        { label: 'Failed', value: statusCounts.FAIL || 0 },
        { label: 'Passed', value: statusCounts.PASS || 0 },
      ],
    },
  ], [sevCounts, totalFindings, statusCounts]);

  // ── Active scan trend: live from BFF or static fallback ──────────────
  const activeScanTrend = useMemo(
    () => {
      if (scanTrendData?.length >= 2) {
        return scanTrendData.map(d => ({ ...d, passRate: d.pass_rate ?? d.passRate ?? 0 }));
      }
      return POSTURE_SCAN_TREND;
    },
    [scanTrendData],
  );

  // ── KPI strip ─────────────────────────────────────────────────────────
  const kpiStripNode = useMemo(() => {
    const passRate = totalFindings > 0
      ? Math.round(((statusCounts.PASS || 0) / totalFindings) * 100)
      : 0;
    const failCount = statusCounts.FAIL || 0;
    const servicesAffected = byService.length;
    const providersAffected = uniqueVals('provider').length || 1;

    // ── Operational metrics ──
    const autoCount = allFindings.filter(f => f.auto_remediable && f.status === 'FAIL').length;
    const slaCount  = allFindings.filter(f => f.sla_status === 'breached').length;
    const ages      = allFindings.map(f => f.age_days).filter(v => v != null && v > 0);
    const avgAge    = ages.length ? Math.round(ages.reduce((s, v) => s + v, 0) / ages.length) : 0;

    // Live sparklines derived from scan trend
    const sparkPS   = activeScanTrend.map(d => d.passRate          ?? d.pass_rate ?? 0);
    const sparkTF   = activeScanTrend.map(d => d.total             ?? 0);
    const sparkSA   = activeScanTrend.map(d => d.services_affected ?? 0);
    const sparkAR   = activeScanTrend.map(d => d.auto_remediable   ?? 0);
    const sparkSLAB = activeScanTrend.map(d => d.sla_breached      ?? 0);
    const sparkAA   = activeScanTrend.map(d => d.avg_age_days      ?? 0);
    const sparkNTS  = activeScanTrend.map(d => d.new_this_scan     ?? 0);

    // ── Left 6-card grid ──
    const kpiCard = (card, i) => (
      <KpiSparkCard
        key={i}
        label={card.label}
        value={card.value}
        color={card.accent}
        sub={card.sub}
        sparkData={card.sparkData || []}
        delta={card.delta ?? null}
        deltaGood={card.deltaGood || 'down'}
      />
    );

    const leftCards = [
      { label: 'Pass Rate',         value: `${passRate}%`, accent: passRate >= 75 ? C.clean : passRate >= 50 ? C.medium : C.critical, sub: `${statusCounts.PASS || 0} rules passing · ${failCount} failing`, sparkData: sparkPS, delta: sparkPS[sparkPS.length - 1] - sparkPS[0], deltaGood: 'up'   },
      { label: 'Services Affected', value: servicesAffected, accent: C.low,      sub: `Across ${providersAffected} provider${providersAffected !== 1 ? 's' : ''}`, sparkData: sparkSA,   delta: sparkSA[sparkSA.length - 1]     - sparkSA[0],   deltaGood: 'down' },
      { label: 'Auto-Remediable',   value: autoCount,        accent: C.sky,      sub: 'Fix with 1-click · quick wins',                 sparkData: sparkAR,   delta: sparkAR[sparkAR.length - 1]     - sparkAR[0],   deltaGood: 'up'   },
      { label: 'SLA Breached',      value: slaCount,         accent: C.critical, sub: 'Overdue · require immediate action',             sparkData: sparkSLAB, delta: sparkSLAB[sparkSLAB.length - 1] - sparkSLAB[0], deltaGood: 'down' },
      { label: 'Avg Finding Age',   value: `${avgAge}d`,     accent: C.slate,    sub: 'Days since first detection',                    sparkData: sparkAA,   delta: sparkAA[sparkAA.length - 1]     - sparkAA[0],   deltaGood: 'down' },
      { label: 'New This Scan',     value: activeScanTrend[activeScanTrend.length-1].total - activeScanTrend[activeScanTrend.length-2].total, accent: C.medium, sub: 'Change vs previous scan', sparkData: sparkNTS, delta: null, deltaGood: 'down' },
    ];

    // ── Right donut slices: severity breakdown of FAILED findings ──
    const donutSlices = [
      { label: 'Critical', value: sevCounts.critical, color: C.critical },
      { label: 'High',     value: sevCounts.high,     color: C.high     },
      { label: 'Medium',   value: sevCounts.medium,   color: C.medium   },
      { label: 'Low',      value: sevCounts.low,       color: C.low      },
      { label: 'Passed',   value: statusCounts.PASS || 0, color: C.clean },
    ];

    return (
      <div className="flex gap-3 items-stretch" style={{ minWidth: 0 }}>
        {/* Left — 3×2 KPI grid */}
        <div style={{ flex: '0 0 58%', display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10 }}>
          {leftCards.map(kpiCard)}
        </div>

        {/* Right — Severity Donut */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)',
          minWidth: 0,
        }}>
          <div className="flex items-center justify-between mb-1">
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>Findings by Severity</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{totalFindings} total</span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 10 }}>
            Failed vs passed · severity breakdown
          </div>
          <div className="flex items-center gap-4 flex-1">
            {/* Donut + center label */}
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <PosDonut slices={donutSlices} size={200} />
              <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
                <div style={{ fontSize: 26, fontWeight: 900, color: 'var(--text-primary)', lineHeight: 1 }}>{failCount}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>failed</div>
              </div>
            </div>
            {/* Legend */}
            <div className="flex-1 space-y-2" style={{ minWidth: 0 }}>
              {donutSlices.map(s => {
                const pct = Math.round((s.value / (totalFindings || 1)) * 100);
                return (
                  <div key={s.label}>
                    <div className="flex items-center justify-between mb-0.5">
                      <div className="flex items-center gap-1.5">
                        <div style={{ width: 9, height: 9, borderRadius: 2, backgroundColor: s.color, flexShrink: 0 }} />
                        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{s.label}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span style={{ fontSize: 13, fontWeight: 700, color: s.color }}>{s.value}</span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{pct}%</span>
                      </div>
                    </div>
                    <div style={{ height: 3, borderRadius: 2, backgroundColor: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%', borderRadius: 2, backgroundColor: s.color, opacity: 0.85 }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    );
  }, [sevCounts, totalFindings, statusCounts, byService, uniqueVals, allFindings, activeScanTrend]);

  // ── Insight Row: 2×2 grid ─────────────────────────────────────────────
  const insightRowContent = useMemo(() => (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)', gap: 16 }}>
      {[
        { key: 'rules',    node: <TopFailingRulesChart topRules={topRules} />,       pad: 'p-5' },
        { key: 'services', node: <TopFailingServicesChart topServices={topServices} />, pad: 'p-5' },
        { key: 'radar',    node: <ByCategoryChart />,                                  pad: 'p-5' },
        { key: 'trend',    node: <PostureTrendChart data={activeScanTrend} />,          pad: 'p-4' },
      ].map(({ key, node, pad }) => (
        <div key={key} className={`rounded-xl border ${pad}`}
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {node}
        </div>
      ))}
    </div>
  ), [topRules, topServices, activeScanTrend]);

  // ── Tab data ──────────────────────────────────────────────────────────
  const quickWinsData = useMemo(
    () => allFindings.filter(f => f.auto_remediable && f.status === 'FAIL')
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)),
    [allFindings],
  );

  const tabData = useMemo(() => {
    const shared = { columns };
    return {
      findings: { ...shared, data: allFindings },
    };
  }, [allFindings, columns]);

  // ── Row click handler ─────────────────────────────────────────────────
  const handleRowClick = useCallback((row) => {
    const finding = row?.original || row;
    if (finding) setSelectedFinding(finding);
  }, []);

  // ── Export handlers ───────────────────────────────────────────────────
  const handleExportCSV = async () => {
    setExporting(true);
    try { await exportCSV(); } finally { setExporting(false); }
  };
  const handleExportPDF = () => {
    exportPDF(allFindings, summary);
  };

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="space-y-5">
      {/* ── Page heading + actions ── */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <ShieldAlert className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>{pageContext.title}</h1>
          </div>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{pageContext.brief}</p>
          {pageContext.details?.length > 0 && (
            <button className="flex items-center gap-1 text-xs mt-1 hover:underline" style={{ color: 'var(--accent-primary)' }}>
              <span>Best practices</span>
            </button>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <button onClick={handleExportCSV} disabled={exporting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border transition-opacity hover:opacity-80 disabled:opacity-50"
            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
            <FileSpreadsheet className="w-3.5 h-3.5" /> {exporting ? 'Exporting...' : 'CSV'}
          </button>
          <button onClick={handleExportPDF}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border transition-opacity hover:opacity-80"
            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
            <Download className="w-3.5 h-3.5" /> PDF
          </button>
          <button onClick={fetchData}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-opacity hover:opacity-80"
            style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </div>

      <PageLayout
        icon={ShieldAlert}
        pageContext={pageContext}
        kpiGroups={[]}
        tabData={{ overview: { renderTab: () => <>{kpiStripNode}{insightRowContent}</> }, ...tabData }}
        loading={loading}
        error={error}
        defaultTab="overview"
        onRowClick={handleRowClick}
        hideHeader
        topNav
      />

      {/* Detail Slide-out */}
      <FindingDetailPanel
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
