'use client';

// Shared cell renderers for all engine finding tables.
// Implements the Orca-style "merged cell" pattern:
//   - Account = CSP badge + account_id + region stacked
//   - Asset   = icon + name + type stacked, links to /inventory/{uid}
//   - Finding = bold title + muted rule_id below
//   - Module  = colored badge from engine MODULE_MAP
//   - Risk    = mini progress bar + score number

import { useRouter } from 'next/navigation';
import { Globe, GitBranch } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import { resolveModule } from '@/lib/engine-modules';

// ── Cloud provider palette ─────────────────────────────────────────────────────
const CSP = {
  aws:      { label: 'AWS',   bg: 'rgba(255,153,0,0.15)',  color: '#ff9900' },
  gcp:      { label: 'GCP',   bg: 'rgba(66,133,244,0.15)', color: '#4285f4' },
  azure:    { label: 'Azure', bg: 'rgba(0,120,212,0.15)',  color: '#0078d4' },
  oci:      { label: 'OCI',   bg: 'rgba(200,0,0,0.12)',    color: '#c00000' },
  ibm:      { label: 'IBM',   bg: 'rgba(31,112,193,0.15)', color: '#1f70c1' },
  alicloud: { label: 'ALI',   bg: 'rgba(255,106,0,0.15)',  color: '#ff6a00' },
  k8s:      { label: 'K8S',   bg: 'rgba(50,108,229,0.15)', color: '#326ce5' },
};

// ── Resource type → emoji icon ────────────────────────────────────────────────
function resourceIcon(type = '') {
  const t = type.toLowerCase();
  if (/s3|bucket|storage/.test(t))            return '🪣';
  if (/rds|database|aurora|dynamodb/.test(t)) return '🗄️';
  if (/ec2|instance|vm/.test(t))              return '🖥️';
  if (/lambda|function|serverless/.test(t))   return 'λ';
  if (/iam|role|user|identity/.test(t))       return '🔑';
  if (/sg|security.group/.test(t))            return '🛡️';
  if (/eks|ecs|cluster|container/.test(t))    return '📦';
  if (/kms|key/.test(t))                      return '🔒';
  if (/elb|alb|nlb|load.balancer/.test(t))    return '⚖️';
  if (/vpc|subnet|network/.test(t))           return '🌐';
  if (/sagemaker|bedrock/.test(t))            return '🤖';
  return '☁️';
}

// ── AccountCell ───────────────────────────────────────────────────────────────
// CSP badge + account_id + region — 2 rows in one cell
export function AccountCell({ row }) {
  const provider = (row.provider || 'aws').toLowerCase();
  const csp      = CSP[provider] || { label: provider.slice(0, 3).toUpperCase(), bg: 'var(--bg-tertiary)', color: 'var(--text-muted)' };
  const account  = row.account_id || row.account || '';
  const region   = row.region || '';
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <div className="flex items-center gap-1.5">
        <span className="shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded"
          style={{ backgroundColor: csp.bg, color: csp.color }}>{csp.label}</span>
        <code className="text-xs truncate" title={account}
          style={{ color: 'var(--text-primary)', maxWidth: 110 }}>{account || '—'}</code>
      </div>
      {region && (
        <span className="text-[10px] pl-0.5" style={{ color: 'var(--text-muted)' }}>{region}</span>
      )}
    </div>
  );
}

// ── AssetCell ─────────────────────────────────────────────────────────────────
// icon + resource name + type stacked — clicking navigates to /inventory/{uid}
export function AssetCell({ row }) {
  const uid    = row.resource_uid || row.resource_id || '';
  const type   = row.resource_type || row.service || '';
  const name   = row.resource_name
    || (uid ? (uid.split('/').pop() || uid.split(':').pop() || uid) : '');
  const cleanT = type.replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ');
  const icon   = resourceIcon(type || name);

  if (!uid && !name) return <span style={{ color: 'var(--text-muted)' }}>—</span>;

  return (
    <a href={uid ? `/inventory/${encodeURIComponent(uid)}` : undefined}
      onClick={uid ? (e) => e.stopPropagation() : undefined}
      className="flex items-center gap-2 min-w-0 group"
      style={{ textDecoration: 'none' }}>
      <span className="text-sm shrink-0 leading-none">{icon}</span>
      <div className="min-w-0">
        <p className="text-xs font-medium truncate group-hover:underline"
          style={{ color: 'var(--text-primary)', maxWidth: 150 }} title={uid}>
          {name || uid}
        </p>
        {cleanT && (
          <p className="text-[10px] mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>
            {cleanT}
          </p>
        )}
      </div>
    </a>
  );
}

// ── FindingCell ───────────────────────────────────────────────────────────────
// Bold title + muted rule_id below
export function FindingCell({ title, ruleId }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium truncate leading-snug"
        style={{ color: 'var(--text-primary)' }} title={title}>
        {title || ruleId || '—'}
      </p>
      {ruleId && (
        <code className="text-[10px] block truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>
          {ruleId}
        </code>
      )}
    </div>
  );
}

// ── ModuleCell ────────────────────────────────────────────────────────────────
// Colored badge from engine's module map
export function ModuleCell({ row, engine }) {
  const mod = resolveModule(row, engine);
  if (!mod) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  return (
    <span className="text-xs font-medium px-2 py-0.5 rounded whitespace-nowrap"
      style={{ backgroundColor: `${mod.color}18`, color: mod.color }}>
      {mod.label}
    </span>
  );
}

// ── ServiceCell ───────────────────────────────────────────────────────────────
// Cloud service name, cleaned (strips provider prefix)
export function ServiceCell({ value }) {
  if (!value) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const clean = value.replace(/^(aws|gcp|azure|oci|alicloud|ibm)_/i, '').replace(/_/g, ' ');
  return (
    <span className="text-xs px-2 py-0.5 rounded"
      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
      {clean}
    </span>
  );
}

// ── RiskCell ──────────────────────────────────────────────────────────────────
// Mini progress bar + score number
export function RiskCell({ score }) {
  if (score == null || score === '') return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const v = Number(score);
  const c = v >= 75 ? '#ef4444' : v >= 50 ? '#f97316' : v >= 25 ? '#eab308' : '#22c55e';
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-10 h-1.5 rounded-full shrink-0" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        <div className="h-full rounded-full" style={{ width: `${Math.min(v, 100)}%`, backgroundColor: c }} />
      </div>
      <span className="text-xs font-bold tabular-nums" style={{ color: c }}>{v}</span>
    </div>
  );
}

// ── StatusCell ────────────────────────────────────────────────────────────────
export function StatusCell({ value }) {
  const v = value || 'FAIL';
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded ${v === 'FAIL' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
      {v}
    </span>
  );
}

// ── ExposedCell ───────────────────────────────────────────────────────────────
export function ExposedCell({ value }) {
  return value
    ? <div className="flex items-center gap-1"><Globe className="w-3 h-3 text-red-400" /><span className="text-xs font-medium text-red-400">Yes</span></div>
    : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>No</span>;
}

// ── DateCell ──────────────────────────────────────────────────────────────────
export function DateCell({ value }) {
  if (!value) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const d = new Date(value);
  const now = Date.now();
  const diff = now - d.getTime();
  const days = Math.floor(diff / 86400000);
  const ago = days === 0 ? 'today' : days === 1 ? '1d ago' : days < 30 ? `${days}d ago` : d.toLocaleDateString();
  return (
    <span className="text-xs" style={{ color: 'var(--text-muted)' }} title={d.toLocaleString()}>
      {ago}
    </span>
  );
}

// ── AttackPathCell ────────────────────────────────────────────────────────────
export function AttackPathCell({ resourceUid }) {
  if (!resourceUid) return null;
  return (
    <a href={`/attack-paths?asset=${encodeURIComponent(resourceUid)}`}
      onClick={e => e.stopPropagation()}
      className="flex items-center gap-1 hover:opacity-75"
      style={{ textDecoration: 'none' }}>
      <GitBranch className="w-3 h-3" style={{ color: '#ea580c' }} />
      <span className="text-[10px] font-medium" style={{ color: '#ea580c' }}>Paths</span>
    </a>
  );
}

// ── RotationCell ──────────────────────────────────────────────────────────────
// Encryption: key rotation status
export function RotationCell({ row }) {
  const compliant = row.rotation_compliant;
  const enabled   = row.rotation_enabled ?? (row.finding_data?.rotation_enabled);
  const val       = compliant != null ? compliant : enabled;
  if (val == null) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  return val
    ? <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(34,197,94,0.12)', color: '#22c55e' }}>Rotating</span>
    : <span className="text-xs font-medium px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>Static</span>;
}

// ── LastAccessCell ────────────────────────────────────────────────────────────
// IAM: last access date with age-based colour
export function LastAccessCell({ row }) {
  const v = row.last_accessed || row.last_access_date || row.last_used_date || row.last_used || row.access_last_used;
  if (!v) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Never</span>;
  const d = new Date(v);
  const days = Math.floor((Date.now() - d.getTime()) / 86400000);
  const color = days > 90 ? '#ef4444' : days > 30 ? '#f97316' : days > 7 ? '#eab308' : '#22c55e';
  const label = days === 0 ? 'Today' : days === 1 ? '1d ago' : days < 30 ? `${days}d ago` : days < 365 ? `${Math.floor(days/30)}mo ago` : `${Math.floor(days/365)}y ago`;
  return (
    <span className="text-xs font-medium" style={{ color }} title={d.toLocaleDateString()}>
      {label}
    </span>
  );
}

// ── PublicAccessCell ──────────────────────────────────────────────────────────
// Database / AI: publicly accessible flag
export function PublicAccessCell({ row }) {
  const v = row.publicly_accessible ?? row.public_access ?? row.endpoint_public ?? row.is_public;
  if (v == null) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const isPublic = v === true || v === 'true' || v === 'True' || v === 'yes' || v === 'YES';
  return isPublic
    ? <span className="text-xs font-bold" style={{ color: '#ef4444' }}>Public</span>
    : <span className="text-xs" style={{ color: '#22c55e' }}>Private</span>;
}

// ── PortProtocolCell ──────────────────────────────────────────────────────────
// Network: port + protocol in one badge — reads direct fields or parses checked_fields
export function PortProtocolCell({ row }) {
  const port  = row.port     || row.from_port  || (row.finding_data?.port);
  const proto = row.protocol || row.ip_protocol || (row.finding_data?.protocol) || '';
  // fall back: try to extract from rule_id pattern like "sg-22-open" or "port-3306"
  const portGuess = port ?? (() => {
    const m = (row.rule_id || '').match(/[-_](\d{2,5})[-_]/);
    return m ? m[1] : null;
  })();
  if (!portGuess && !proto) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const danger = [22, 3389, 3306, 5432, 6379, 27017, 9200].includes(Number(portGuess));
  return (
    <span className="text-xs font-mono font-medium px-2 py-0.5 rounded"
      style={{ backgroundColor: danger ? 'rgba(239,68,68,0.12)' : 'var(--bg-tertiary)', color: danger ? '#ef4444' : 'var(--text-secondary)' }}>
      {portGuess ? `${portGuess}` : ''}{proto ? `/${proto.toUpperCase()}` : ''}
    </span>
  );
}

// ── CveCountCell ──────────────────────────────────────────────────────────────
// Container: CVE / vulnerability count badge
export function CveCountCell({ row }) {
  const total    = row.cve_count    || row.vulnerability_count    || row.vuln_count    || 0;
  const critical = row.critical_cve || row.critical_vuln_count    || row.cve_critical  || 0;
  if (!total) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>;
  return (
    <div className="flex items-center gap-1">
      <span className="text-xs font-bold px-1.5 py-0.5 rounded"
        style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
        {total}
      </span>
      {critical > 0 && (
        <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
          {critical} crit
        </span>
      )}
    </div>
  );
}

// ── SlaCell ───────────────────────────────────────────────────────────────────
// SLA countdown based on severity and first_seen_at
export function SlaCell({ row }) {
  const SLA_DAYS = { critical: 1, high: 7, medium: 30, low: 90 };
  const sev = (row.severity || '').toLowerCase();
  const slaDays = SLA_DAYS[sev];
  if (!slaDays || !row.first_seen_at) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const ageMs    = Date.now() - new Date(row.first_seen_at).getTime();
  const ageDays  = Math.floor(ageMs / 86400000);
  const remaining = slaDays - ageDays;
  const overdue  = remaining < 0;
  const urgent   = remaining >= 0 && remaining <= 1;
  const color    = overdue ? '#ef4444' : urgent ? '#f97316' : remaining <= 3 ? '#eab308' : 'var(--text-muted)';
  const label    = overdue ? `${Math.abs(remaining)}d over` : remaining === 0 ? 'Due today' : `${remaining}d left`;
  return (
    <span className="text-[10px] font-medium" style={{ color }} title={`SLA: ${slaDays}d for ${sev}`}>
      {label}
    </span>
  );
}

// ── buildUniversalColumns(engine, extraColumns) ───────────────────────────────
// Returns the standard 8 columns + any engine-specific extras.
// extraColumns are merged after Module (before Asset), so they get prominent placement.
export function buildUniversalColumns(engine, extraColumns = []) {
  return [
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 88,
      cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
    },
    {
      accessorKey: 'title',
      header: 'Finding',
      size: 240,
      cell: ({ getValue, row }) => (
        <FindingCell title={getValue()} ruleId={row.original.rule_id} />
      ),
    },
    {
      id: 'module',
      header: 'Module',
      size: 130,
      accessorFn: (row) => resolveModule(row, engine)?.label || '',
      cell: ({ row }) => <ModuleCell row={row.original} engine={engine} />,
    },
    ...extraColumns,
    {
      id: 'asset',
      header: 'Asset',
      size: 180,
      accessorFn: (row) => row.resource_name || row.resource_uid || row.resource_id || '',
      cell: ({ row }) => <AssetCell row={row.original} />,
    },
    {
      id: 'account',
      header: 'Account',
      size: 155,
      accessorFn: (row) => `${row.provider || ''} ${row.account_id || ''} ${row.region || ''}`,
      cell: ({ row }) => <AccountCell row={row.original} />,
    },
    {
      accessorKey: 'risk_score',
      header: 'Risk',
      size: 78,
      cell: ({ getValue }) => <RiskCell score={getValue()} />,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 62,
      cell: ({ getValue }) => <StatusCell value={getValue()} />,
    },
    {
      id: 'sla',
      header: 'SLA',
      size: 72,
      accessorFn: (row) => {
        const SLA_DAYS = { critical: 1, high: 7, medium: 30, low: 90 };
        const sev = (row.severity || '').toLowerCase();
        const slaDays = SLA_DAYS[sev];
        if (!slaDays || !row.first_seen_at) return 9999;
        return slaDays - Math.floor((Date.now() - new Date(row.first_seen_at).getTime()) / 86400000);
      },
      cell: ({ row }) => <SlaCell row={row.original} />,
    },
    {
      accessorKey: 'first_seen_at',
      header: 'First Seen',
      size: 88,
      cell: ({ getValue }) => <DateCell value={getValue()} />,
    },
  ];
}
