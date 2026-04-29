'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  Shield, ChevronRight, CheckCircle, XCircle, AlertTriangle,
  ChevronDown, ChevronUp, Database, Network, Eye, Lock, Server,
  ExternalLink, Filter, Search,
} from 'lucide-react';
import SeverityBadge from '@/components/shared/SeverityBadge';
import KpiCard from '@/components/shared/KpiCard';
import GaugeChart from '@/components/charts/GaugeChart';
import { TENANT_ID } from '@/lib/constants';

/* ─── helpers ─────────────────────────────────────────────── */

function scoreColor(score) {
  if (score >= 80) return { text: 'text-green-400', bg: 'bg-green-500/20', border: '#22c55e' };
  if (score >= 60) return { text: 'text-yellow-400', bg: 'bg-yellow-500/20', border: '#f59e0b' };
  return { text: 'text-red-400', bg: 'bg-red-500/20', border: '#ef4444' };
}

function scoreLabel(score) {
  if (score >= 80) return 'Compliant';
  if (score >= 60) return 'Partially Compliant';
  return 'Non-Compliant';
}

const DOMAIN_ICONS = {
  'Identity & Access': <Lock className="w-4 h-4" />,
  'Storage & Data': <Database className="w-4 h-4" />,
  'Logging & Monitoring': <Eye className="w-4 h-4" />,
  'Network Security': <Network className="w-4 h-4" />,
  'Database': <Server className="w-4 h-4" />,
};

function domainIcon(domain) {
  return DOMAIN_ICONS[domain] || <Shield className="w-4 h-4" />;
}

function resourceService(uid = '') {
  if (uid.includes(':iam:') || uid.includes(':iam::')) return 'IAM';
  if (uid.includes(':s3:::')) return 'S3';
  if (uid.includes(':ec2:')) return 'EC2';
  if (uid.includes(':rds:')) return 'RDS';
  if (uid.includes(':cloudtrail:')) return 'CloudTrail';
  if (uid.includes(':config:')) return 'Config';
  return uid.split(':')[2]?.toUpperCase() || 'AWS';
}

function shortArn(arn = '') {
  // Show last two segments of ARN for brevity
  const parts = arn.split('/');
  if (parts.length > 1) return parts.slice(-2).join('/');
  const colParts = arn.split(':');
  if (colParts.length > 5) return colParts.slice(-2).join(':');
  return arn;
}

/* ─── Resource row (inside expanded control) ──────────────── */

function ResourceRow({ resource }) {
  const svc = resourceService(resource.resource_uid);
  const short = shortArn(resource.resource_uid);

  return (
    <div
      className="flex items-center gap-4 px-4 py-2.5 rounded-lg border text-xs group hover:opacity-90 transition-opacity"
      style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
    >
      {/* Service pill */}
      <span
        className="font-mono font-semibold px-2 py-0.5 rounded text-[10px] shrink-0"
        style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--accent-primary)' }}
      >
        {svc}
      </span>

      {/* ARN */}
      <span
        className="font-mono truncate flex-1 cursor-pointer"
        style={{ color: 'var(--text-secondary)' }}
        title={resource.resource_uid}
      >
        {short}
      </span>

      {/* Region */}
      <span className="shrink-0" style={{ color: 'var(--text-muted)' }}>
        {resource.region || 'global'}
      </span>

      {/* Severity */}
      <span className="shrink-0">
        <SeverityBadge severity={resource.severity} />
      </span>

      {/* Last seen */}
      {resource.last_seen && (
        <span className="shrink-0 text-[10px]" style={{ color: 'var(--text-muted)' }}>
          {new Date(resource.last_seen).toLocaleDateString()}
        </span>
      )}
    </div>
  );
}

/* ─── Control row (expandable) ────────────────────────────── */

function ControlRow({ control }) {
  const [expanded, setExpanded] = useState(false);
  const hasFailed = control.status === 'fail';
  const hasResources = (control.resources || []).length > 0;

  return (
    <>
      <tr
        className="border-b transition-colors"
        style={{ borderColor: 'var(--border-primary)' }}
      >
        {/* Expand toggle */}
        <td className="pl-4 py-3 w-8">
          {hasFailed && hasResources ? (
            <button
              onClick={() => setExpanded((v) => !v)}
              className="p-1 rounded hover:opacity-80 transition-opacity"
              style={{ color: 'var(--text-muted)' }}
            >
              {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          ) : (
            <span className="w-5 inline-block" />
          )}
        </td>

        {/* Control ID */}
        <td className="py-3 pr-4">
          <code
            className="text-xs font-mono px-2 py-1 rounded"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--accent-primary)' }}
          >
            {control.control_id}
          </code>
        </td>

        {/* Name */}
        <td className="py-3 pr-6">
          <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
            {control.control_name}
          </span>
        </td>

        {/* Domain */}
        <td className="py-3 pr-4 hidden md:table-cell">
          <span
            className="flex items-center gap-1.5 text-xs whitespace-nowrap"
            style={{ color: 'var(--text-secondary)' }}
          >
            {domainIcon(control.domain)}
            {control.domain}
          </span>
        </td>

        {/* Severity */}
        <td className="py-3 pr-4">
          <SeverityBadge severity={control.severity} />
        </td>

        {/* Status */}
        <td className="py-3 pr-4">
          {control.status === 'pass' ? (
            <span className="flex items-center gap-1 text-xs font-medium text-green-400">
              <CheckCircle className="w-3.5 h-3.5" /> Pass
            </span>
          ) : (
            <span className="flex items-center gap-1 text-xs font-medium text-red-400">
              <XCircle className="w-3.5 h-3.5" /> Fail
            </span>
          )}
        </td>

        {/* Resources affected */}
        <td className="py-3 pr-6 text-right">
          {control.failed > 0 ? (
            <span
              className="text-sm font-bold tabular-nums"
              style={{ color: 'var(--accent-warning)' }}
            >
              {control.failed} resource{control.failed !== 1 ? 's' : ''}
            </span>
          ) : (
            <span className="text-sm" style={{ color: 'var(--text-muted)' }}>—</span>
          )}
        </td>
      </tr>

      {/* Expanded resources */}
      {expanded && hasResources && (
        <tr style={{ borderColor: 'var(--border-primary)' }} className="border-b">
          <td colSpan={7} className="px-8 py-3">
            <div className="space-y-1.5">
              <p className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
                Affected Resources
              </p>
              {control.resources.map((r, i) => (
                <ResourceRow key={`${r.resource_uid}-${i}`} resource={r} />
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/* ─── Domain summary card ─────────────────────────────────── */

function DomainCard({ domain, controls, onClick, active }) {
  const total = controls.length;
  const passed = controls.filter((c) => c.status === 'pass').length;
  const failed = total - passed;
  const pct = total > 0 ? Math.round((passed / total) * 100) : 0;
  const col = scoreColor(pct);

  return (
    <button
      onClick={onClick}
      className="rounded-xl p-4 border text-left transition-all hover:scale-[1.01]"
      style={{
        backgroundColor: active ? 'var(--bg-secondary)' : 'var(--bg-card)',
        borderColor: active ? col.border : 'var(--border-primary)',
      }}
    >
      <div className="flex items-center gap-2 mb-3">
        <span className={`${col.text}`}>{domainIcon(domain)}</span>
        <span className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
          {domain}
        </span>
      </div>

      <div className="flex items-end justify-between mb-2">
        <span className={`text-2xl font-bold ${col.text}`}>{pct}%</span>
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{passed}/{total}</span>
      </div>

      <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: col.border }} />
      </div>

      {failed > 0 && (
        <p className="mt-2 text-[11px]" style={{ color: 'var(--accent-danger)' }}>
          {failed} failing control{failed !== 1 ? 's' : ''}
        </p>
      )}
    </button>
  );
}

/* ─── Main page ───────────────────────────────────────────── */

export default function FrameworkDetailPage() {
  const router = useRouter();
  const params = useParams();
  const frameworkId = params?.framework;

  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  // Filters
  const [activeDomain, setActiveDomain] = useState('All');
  const [statusFilter, setStatusFilter] = useState('all');   // 'all' | 'fail' | 'pass'
  const [severityFilter, setSeverityFilter] = useState('all');
  const [search, setSearch] = useState('');

  useEffect(() => {
    if (!frameworkId) return;
    setLoading(true);
    setError(null);

    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    fetch(`${origin}/gateway/api/v1/views/compliance/framework/${encodeURIComponent(frameworkId)}?tenant_id=${encodeURIComponent(TENANT_ID || 'default-tenant')}`)
      .then((r) => r.json())
      .then((d) => {
        if (d?.families) {
          // Transform families-based response to flat controls list
          const controls = [];
          let totalResources = 0;
          let criticalCount = 0;
          let highCount = 0;
          for (const fam of d.families || []) {
            for (const c of fam.controls || []) {
              const status = (c.status || 'NOT_ASSESSED').toLowerCase().replace(/_/g, ' ');
              controls.push({ ...c, domain: fam.family || c.control_family || 'General', status });
              totalResources += (c.fail_count || 0);
              if (c.severity === 'critical' && status === 'fail') criticalCount++;
              if (c.severity === 'high' && status === 'fail') highCount++;
            }
          }
          const apiSummary = d.summary || {};
          const passed = apiSummary.PASS || 0;
          const failed = apiSummary.FAIL || 0;
          const partial = apiSummary.PARTIAL || 0;
          const total = d.total_controls || controls.length;
          const score = d.score || (total > 0 ? Math.round(100 * passed / total * 10) / 10 : 0);
          const summary = {
            score,
            total_controls: total,
            passed_controls: passed,
            failed_controls: failed + partial,
            total_resources_affected: totalResources,
            critical_controls: criticalCount,
            high_controls: highCount,
          };
          setData({ ...d, controls, summary, framework: d.framework });
        } else if (d?.controls) {
          setData(d);
        } else {
          setError('Framework data unavailable');
        }
      })
      .catch((e) => setError(e?.message || 'Failed to load framework'))
      .finally(() => setLoading(false));
  }, [frameworkId]);

  /* derived */
  const domains = useMemo(() => {
    if (!data) return [];
    return [...new Set((data.controls || []).map((c) => c.domain))].filter(Boolean);
  }, [data]);

  const filteredControls = useMemo(() => {
    if (!data) return [];
    return (data.controls || []).filter((c) => {
      if (activeDomain !== 'All' && c.domain !== activeDomain) return false;
      if (statusFilter !== 'all' && c.status !== statusFilter) return false;
      if (severityFilter !== 'all' && c.severity !== severityFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!c.control_name?.toLowerCase().includes(q) && !c.control_id?.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [data, activeDomain, statusFilter, severityFilter, search]);

  const domainControls = useMemo(() => {
    if (!data) return {};
    const map = {};
    for (const c of data.controls || []) {
      if (!map[c.domain]) map[c.domain] = [];
      map[c.domain].push(c);
    }
    return map;
  }, [data]);

  /* ── loading ── */
  if (loading) {
    return (
      <div className="space-y-5">
        <div className="h-20 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-28 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          ))}
        </div>
        <div className="h-56 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        <div className="h-96 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl p-8 border text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--accent-danger)' }}>
        <XCircle className="w-10 h-10 mx-auto mb-3 text-red-400" />
        <p className="font-semibold mb-1" style={{ color: 'var(--accent-danger)' }}>Failed to load framework</p>
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>{error}</p>
      </div>
    );
  }

  if (!data) return null;

  const { summary } = data;
  const col = scoreColor(summary.score);

  return (
    <div className="space-y-6">

      {/* ── Breadcrumb ── */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => router.push('/compliance')}
          className="text-sm transition-opacity hover:opacity-70"
          style={{ color: 'var(--text-muted)' }}
        >
          Compliance
        </button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
          {typeof data.framework === 'object' ? data.framework?.framework_name : data.framework}
        </span>
        {data._source === 'demo' && (
          <span className="ml-2 text-[10px] px-2 py-0.5 rounded-full font-medium"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
            DEMO
          </span>
        )}
      </div>

      {/* ── Hero header ── */}
      <div
        className="rounded-xl p-6 border flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-xl ${col.bg}`}>
            <Shield className={`w-7 h-7 ${col.text}`} />
          </div>
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
              {typeof data.framework === 'object' ? data.framework?.framework_name : data.framework}
            </h1>
            <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {summary.total_controls} controls · {summary.total_resources_affected} resources affected
            </p>
          </div>
        </div>

        <div className="flex items-center gap-6">
          {/* Big score */}
          <div className="text-right">
            <p className={`text-5xl font-extrabold tabular-nums ${col.text}`}>
              {summary.score}
            </p>
            <p className="text-xs mt-0.5 font-medium" style={{ color: 'var(--text-muted)' }}>/ 100</p>
          </div>
          <div>
            <span
              className={`px-3 py-1.5 rounded-full text-sm font-semibold ${col.bg} ${col.text}`}
            >
              {scoreLabel(summary.score)}
            </span>
          </div>
        </div>
      </div>

      {/* ── KPI strip ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Total Controls', value: summary.total_controls, color: 'blue' },
          { label: 'Passed', value: summary.passed_controls, color: 'green' },
          { label: 'Failed', value: summary.failed_controls, color: 'red' },
          { label: 'Resources Affected', value: summary.total_resources_affected, color: 'orange' },
          { label: 'Critical', value: summary.critical_controls, color: 'red' },
          { label: 'High', value: summary.high_controls, color: 'orange' },
        ].map(({ label, value, color }) => {
          const colorMap = {
            blue: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: '#3b82f6' },
            green: { bg: 'bg-green-500/10', text: 'text-green-400', border: '#22c55e' },
            red: { bg: 'bg-red-500/10', text: 'text-red-400', border: '#ef4444' },
            orange: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: '#f97316' },
          };
          const c = colorMap[color] || colorMap.blue;
          return (
            <div
              key={label}
              className="rounded-xl p-4 border"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
            >
              <p className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>{label}</p>
              <p className={`text-2xl font-bold tabular-nums ${c.text}`}>{value}</p>
            </div>
          );
        })}
      </div>

      {/* ── Domain breakdown ── */}
      {domains.length > 0 && (
        <div>
          <h2 className="text-base font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
            Coverage by Domain
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {domains.map((d) => (
              <DomainCard
                key={d}
                domain={d}
                controls={domainControls[d] || []}
                active={activeDomain === d}
                onClick={() => setActiveDomain(activeDomain === d ? 'All' : d)}
              />
            ))}
          </div>
        </div>
      )}

      {/* ── Controls table ── */}
      <div
        className="rounded-xl border overflow-hidden"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        {/* Table header / filters */}
        <div
          className="px-6 py-4 border-b flex flex-col md:flex-row items-start md:items-center justify-between gap-3"
          style={{ borderColor: 'var(--border-primary)' }}
        >
          <div>
            <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
              Controls Detail
            </h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {filteredControls.length} control{filteredControls.length !== 1 ? 's' : ''}
              {activeDomain !== 'All' ? ` in ${activeDomain}` : ''}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search */}
            <div
              className="flex items-center gap-2 rounded-lg px-3 py-1.5 border text-sm"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
            >
              <Search className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search controls…"
                className="bg-transparent outline-none w-36 text-xs"
                style={{ color: 'var(--text-primary)' }}
              />
            </div>

            {/* Status filter */}
            {['all', 'fail', 'pass'].map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className="text-xs px-3 py-1.5 rounded-lg border capitalize transition-colors"
                style={{
                  backgroundColor: statusFilter === s ? (s === 'fail' ? 'rgba(239,68,68,0.2)' : s === 'pass' ? 'rgba(34,197,94,0.2)' : 'var(--bg-secondary)') : 'transparent',
                  color: statusFilter === s ? (s === 'fail' ? '#ef4444' : s === 'pass' ? '#22c55e' : 'var(--text-primary)') : 'var(--text-secondary)',
                  borderColor: statusFilter === s ? (s === 'fail' ? '#ef4444' : s === 'pass' ? '#22c55e' : 'var(--accent-primary)') : 'var(--border-primary)',
                }}
              >
                {s === 'all' ? 'All' : s === 'fail' ? 'Failing' : 'Passing'}
              </button>
            ))}

            {/* Severity filter */}
            {['all', 'critical', 'high', 'medium'].map((sv) => (
              <button
                key={sv}
                onClick={() => setSeverityFilter(sv)}
                className="text-xs px-3 py-1.5 rounded-lg border capitalize transition-colors hidden lg:inline-flex"
                style={{
                  backgroundColor: severityFilter === sv ? 'var(--bg-secondary)' : 'transparent',
                  color: severityFilter === sv ? 'var(--text-primary)' : 'var(--text-secondary)',
                  borderColor: severityFilter === sv ? 'var(--accent-primary)' : 'var(--border-primary)',
                }}
              >
                {sv === 'all' ? 'All Severity' : sv.charAt(0).toUpperCase() + sv.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-secondary)' }}>
                <th className="w-8 pl-4 py-2.5" />
                <th className="text-left text-xs font-semibold uppercase tracking-wider py-2.5 pr-4" style={{ color: 'var(--text-muted)' }}>
                  Control ID
                </th>
                <th className="text-left text-xs font-semibold uppercase tracking-wider py-2.5 pr-6" style={{ color: 'var(--text-muted)' }}>
                  Control
                </th>
                <th className="text-left text-xs font-semibold uppercase tracking-wider py-2.5 pr-4 hidden md:table-cell" style={{ color: 'var(--text-muted)' }}>
                  Domain
                </th>
                <th className="text-left text-xs font-semibold uppercase tracking-wider py-2.5 pr-4" style={{ color: 'var(--text-muted)' }}>
                  Severity
                </th>
                <th className="text-left text-xs font-semibold uppercase tracking-wider py-2.5 pr-4" style={{ color: 'var(--text-muted)' }}>
                  Status
                </th>
                <th className="text-right text-xs font-semibold uppercase tracking-wider py-2.5 pr-6" style={{ color: 'var(--text-muted)' }}>
                  Resources
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredControls.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12">
                    <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" style={{ color: 'var(--text-muted)' }} />
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No controls match the current filters</p>
                  </td>
                </tr>
              ) : (
                filteredControls.map((control) => (
                  <ControlRow key={control.control_id} control={control} />
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Table footer */}
        {filteredControls.length > 0 && (
          <div
            className="px-6 py-3 border-t text-xs"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}
          >
            Showing {filteredControls.length} of {(data.controls || []).length} controls
            {summary.failed_controls > 0 && (
              <span className="ml-3 text-red-400">
                · {summary.failed_controls} failing · click a row to expand affected resources
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
