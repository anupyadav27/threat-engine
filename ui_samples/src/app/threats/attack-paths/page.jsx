'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield, ChevronRight, AlertTriangle, Activity,
  ChevronDown, ChevronUp, Clock, Users, Target,
  ExternalLink, Search, Route, Globe, ArrowRight,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import FilterBar from '@/components/shared/FilterBar';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

// ── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const TARGET_TYPE_OPTIONS = [
  { value: 's3', label: 'S3 Bucket' },
  { value: 'rds', label: 'RDS Database' },
  { value: 'dynamodb', label: 'DynamoDB' },
  { value: 'iam', label: 'IAM Role' },
  { value: 'ec2', label: 'EC2 Instance' },
  { value: 'lambda', label: 'Lambda' },
  { value: 'secretsmanager', label: 'Secrets Manager' },
];

const MIN_HOPS_OPTIONS = [
  { value: '2', label: '2+ hops' },
  { value: '3', label: '3+ hops' },
  { value: '4', label: '4+ hops' },
  { value: '5', label: '5+ hops' },
  { value: '6', label: '6+ hops' },
];

const SORT_OPTIONS = [
  { value: 'severity', label: 'Severity' },
  { value: 'hops', label: 'Most Hops' },
  { value: 'recent', label: 'Most Recent' },
  { value: 'blast', label: 'Blast Radius' },
];

// ── Node color helpers ───────────────────────────────────────────────────────

const NODE_COLORS = {
  entry:  { fill: '#3b82f6', border: '#60a5fa', bg: 'rgba(59,130,246,0.15)' },
  hop:    { fill: '#f97316', border: '#fb923c', bg: 'rgba(249,115,22,0.12)' },
  target: { fill: '#ef4444', border: '#f87171', bg: 'rgba(239,68,68,0.15)' },
};

function getNodeRole(step, totalSteps, index) {
  if (step.isEntry || index === 0) return 'entry';
  if (step.isTarget || index === totalSteps - 1) return 'target';
  return 'hop';
}

function getRoleLabel(role) {
  if (role === 'entry') return 'Entry';
  if (role === 'target') return 'Target';
  return 'Hop';
}

// ── Resource type to short label ─────────────────────────────────────────────

function shortResourceType(type) {
  if (!type) return '?';
  // e.g. "s3.bucket" -> "S3", "ec2.instance" -> "EC2", "internet" -> "Internet"
  const parts = type.split('.');
  const base = parts[0];
  const map = {
    internet: 'Internet', s3: 'S3', ec2: 'EC2', iam: 'IAM', rds: 'RDS',
    lambda: 'Lambda', dynamodb: 'DynamoDB', alb: 'ALB', elb: 'ELB',
    ecs: 'ECS', eks: 'EKS', sqs: 'SQS', sns: 'SNS', kms: 'KMS',
    secretsmanager: 'Secrets', cloudfront: 'CF', elasticloadbalancing: 'ALB',
  };
  return map[base.toLowerCase()] || base.toUpperCase().slice(0, 6);
}

// ── Resource type icon character (used inside SVG) ───────────────────────────

function resourceIcon(type) {
  if (!type) return '\u2753';
  const base = type.split('.')[0].toLowerCase();
  const icons = {
    internet: '\uD83C\uDF10', s3: '\uD83E\uDEA3', ec2: '\uD83D\uDDA5',
    iam: '\uD83D\uDD11', rds: '\uD83D\uDDC3', lambda: '\u03BB',
    dynamodb: '\uD83D\uDCCA', alb: '\u2696', elb: '\u2696',
    ecs: '\uD83D\uDCE6', eks: '\u2638', sqs: '\uD83D\uDCEC',
    sns: '\uD83D\uDD14', kms: '\uD83D\uDD10', secretsmanager: '\uD83D\uDD12',
    cloudfront: '\uD83C\uDF10', elasticloadbalancing: '\u2696',
  };
  return icons[base] || '\u26C5';
}

// ── Blast Radius badge ───────────────────────────────────────────────────────

function BlastRadiusBadge({ level }) {
  const normalized = (level || 'medium').toLowerCase();
  const styles = {
    critical: { bg: 'rgba(239,68,68,0.15)', text: '#ef4444', border: 'rgba(239,68,68,0.35)' },
    high:     { bg: 'rgba(249,115,22,0.15)', text: '#f97316', border: 'rgba(249,115,22,0.35)' },
    medium:   { bg: 'rgba(234,179,8,0.15)',  text: '#eab308', border: 'rgba(234,179,8,0.35)' },
    low:      { bg: 'rgba(34,197,94,0.15)',  text: '#22c55e', border: 'rgba(34,197,94,0.35)' },
  };
  const s = styles[normalized] || styles.medium;
  return (
    <span
      className="text-[10px] px-2 py-0.5 rounded border font-semibold uppercase tracking-wide"
      style={{ backgroundColor: s.bg, color: s.text, borderColor: s.border }}
    >
      {normalized} blast
    </span>
  );
}

// ── MITRE Tactic Pill ────────────────────────────────────────────────────────

function MitrePill({ label }) {
  return (
    <span
      className="text-[10px] px-2 py-0.5 rounded font-medium whitespace-nowrap"
      style={{
        backgroundColor: 'rgba(99,102,241,0.12)',
        color: '#818cf8',
        border: '1px solid rgba(99,102,241,0.25)',
      }}
    >
      {label}
    </span>
  );
}

// ── Technique badge (small red pill) ─────────────────────────────────────────

function TechniqueBadge({ code }) {
  if (!code) return null;
  return (
    <span
      className="text-[9px] px-1.5 py-0.5 rounded-full font-bold whitespace-nowrap"
      style={{
        backgroundColor: 'rgba(239,68,68,0.12)',
        color: '#ef4444',
        border: '1px solid rgba(239,68,68,0.25)',
      }}
    >
      {code}
    </span>
  );
}

// ── SVG Attack Path Visualization ────────────────────────────────────────────

function AttackPathSVG({ steps }) {
  if (!steps || steps.length === 0) return null;

  const nodeWidth = 90;
  const nodeHeight = 90;
  const gapWidth = 100;
  const totalWidth = steps.length * nodeWidth + (steps.length - 1) * gapWidth;
  const svgHeight = 160;
  const cy = 60;

  return (
    <div className="w-full overflow-x-auto pb-2">
      <svg
        width={Math.max(totalWidth + 40, 400)}
        height={svgHeight}
        viewBox={`0 0 ${Math.max(totalWidth + 40, 400)} ${svgHeight}`}
        className="min-w-full"
        style={{ minWidth: Math.max(totalWidth + 40, 400) }}
      >
        {steps.map((step, idx) => {
          const x = 20 + idx * (nodeWidth + gapWidth);
          const role = getNodeRole(step, steps.length, idx);
          const colors = NODE_COLORS[role];
          const radius = 28;

          return (
            <g key={idx}>
              {/* Connector arrow to next node */}
              {idx < steps.length - 1 && (() => {
                const nextStep = steps[idx + 1];
                const lineStartX = x + nodeWidth / 2 + radius + 4;
                const lineEndX = x + nodeWidth + gapWidth + nodeWidth / 2 - radius - 4;
                const midX = (lineStartX + lineEndX) / 2;
                const technique = nextStep?.technique || '';

                return (
                  <g>
                    {/* Line */}
                    <line
                      x1={lineStartX} y1={cy}
                      x2={lineEndX - 6} y2={cy}
                      stroke="rgba(255,255,255,0.2)"
                      strokeWidth={2}
                      strokeDasharray="6 3"
                    />
                    {/* Arrowhead */}
                    <polygon
                      points={`${lineEndX},${cy} ${lineEndX - 8},${cy - 4} ${lineEndX - 8},${cy + 4}`}
                      fill="rgba(255,255,255,0.3)"
                    />
                    {/* Technique badge above line */}
                    {technique && (
                      <g>
                        <rect
                          x={midX - 22} y={cy - 26}
                          width={44} height={16}
                          rx={8}
                          fill="rgba(239,68,68,0.15)"
                          stroke="rgba(239,68,68,0.3)"
                          strokeWidth={1}
                        />
                        <text
                          x={midX} y={cy - 15}
                          textAnchor="middle"
                          fill="#ef4444"
                          fontSize={9}
                          fontWeight={700}
                          fontFamily="monospace"
                        >
                          {technique}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })()}

              {/* Node circle */}
              <circle
                cx={x + nodeWidth / 2}
                cy={cy}
                r={radius}
                fill={colors.bg}
                stroke={colors.border}
                strokeWidth={2}
              />

              {/* Icon/emoji inside circle */}
              <text
                x={x + nodeWidth / 2}
                y={cy + 2}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize={18}
              >
                {resourceIcon(step.resourceType)}
              </text>

              {/* Risk score badge (top-right of circle) */}
              {step.riskScore > 0 && (
                <g>
                  <circle
                    cx={x + nodeWidth / 2 + 20}
                    cy={cy - 20}
                    r={11}
                    fill={step.riskScore >= 80 ? '#ef4444' : step.riskScore >= 60 ? '#f97316' : '#22c55e'}
                    stroke="#0a0a0a"
                    strokeWidth={2}
                  />
                  <text
                    x={x + nodeWidth / 2 + 20}
                    y={cy - 19}
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fill="#fff"
                    fontSize={8}
                    fontWeight={700}
                  >
                    {step.riskScore}
                  </text>
                </g>
              )}

              {/* Resource type label */}
              <text
                x={x + nodeWidth / 2}
                y={cy + radius + 16}
                textAnchor="middle"
                fill={colors.fill}
                fontSize={10}
                fontWeight={700}
              >
                {shortResourceType(step.resourceType)}
              </text>

              {/* Resource name */}
              <text
                x={x + nodeWidth / 2}
                y={cy + radius + 28}
                textAnchor="middle"
                fill="#a3a3a3"
                fontSize={9}
              >
                {(step.resourceName || '').length > 14
                  ? step.resourceName.slice(0, 12) + '...'
                  : step.resourceName}
              </text>

              {/* Role label */}
              <text
                x={x + nodeWidth / 2}
                y={cy + radius + 40}
                textAnchor="middle"
                fill="#737373"
                fontSize={8}
                fontStyle="italic"
              >
                {getRoleLabel(role)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ── Step detail row in expanded view ─────────────────────────────────────────

function StepDetailRow({ step, index, total, severityColor }) {
  const riskColor = step.riskScore >= 80 ? '#ef4444' : step.riskScore >= 60 ? '#f97316' : '#22c55e';

  return (
    <div className="flex gap-3">
      {/* Step number + vertical connector */}
      <div className="flex flex-col items-center flex-shrink-0">
        <div
          className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-white"
          style={{ backgroundColor: severityColor }}
        >
          {index + 1}
        </div>
        {index < total - 1 && (
          <div
            className="w-px flex-1 mt-1"
            style={{ backgroundColor: 'var(--border-primary)', minHeight: 20 }}
          />
        )}
      </div>

      {/* Step card */}
      <div
        className="flex-1 rounded-lg p-3 border mb-2"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center gap-2 mb-1.5 flex-wrap">
          <span className="text-base">{resourceIcon(step.resourceType)}</span>
          <span className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
            {step.resourceName}
          </span>
          <span
            className="text-[10px] px-2 py-0.5 rounded font-medium"
            style={{
              backgroundColor: 'rgba(99,102,241,0.12)',
              color: '#818cf8',
            }}
          >
            {step.resourceType}
          </span>
          {step.riskScore > 0 && (
            <span className="ml-auto text-sm font-bold" style={{ color: riskColor }}>
              Risk {step.riskScore}
            </span>
          )}
        </div>
        {step.resourceArn && (
          <p className="text-[11px] font-mono mb-2 truncate" style={{ color: 'var(--text-muted)' }}>
            {step.resourceArn}
          </p>
        )}
        <div className="flex items-center gap-2 flex-wrap">
          {step.technique && <TechniqueBadge code={step.technique} />}
          {step.tacticName && (
            <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
              {step.tacticName}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// ── KPI loading skeleton ─────────────────────────────────────────────────────

function KpiSkeleton() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {[...Array(4)].map((_, i) => (
        <div
          key={i}
          className="rounded-xl p-6 border animate-pulse"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <div className="h-4 w-24 rounded mb-4" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-8 w-16 rounded mb-4" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-3 w-32 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        </div>
      ))}
    </div>
  );
}

// ── Card loading skeleton ────────────────────────────────────────────────────

function CardSkeleton() {
  return (
    <div className="space-y-4">
      {[...Array(3)].map((_, i) => (
        <div
          key={i}
          className="rounded-xl border animate-pulse"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <div className="p-5 space-y-3">
            <div className="flex items-center gap-3">
              <div className="h-5 w-16 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
              <div className="h-5 w-64 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
            </div>
            <div className="flex gap-4">
              <div className="h-4 w-20 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
              <div className="h-4 w-28 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
              <div className="h-4 w-24 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
            </div>
          </div>
          <div className="px-5 pb-5">
            <div className="h-24 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Relative time helper ─────────────────────────────────────────────────────

function relativeTime(dateStr) {
  if (!dateStr) return '';
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function AttackPathsPage() {
  const router = useRouter();

  // Data state
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);

  // UI state
  const [expandedPaths, setExpandedPaths] = useState(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('severity');

  // Filter state
  const [filters, setFilters] = useState({
    severity: '',
    minHops: '',
    targetType: '',
  });

  // ── Data fetch ──────────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);

      try {
        const res = await fetchView('threats/attack-paths', { min_severity: 'medium' });

        if (cancelled) return;

        if (res?.error) {
          setError(res.error);
          return;
        }

        setData(res);
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : 'Failed to load attack paths. Please verify the Threat engine is running.'
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, []);

  // ── Derived data ────────────────────────────────────────────────────────────

  const kpi = data?.kpi || { total: 0, critical: 0, high: 0, active: 0 };
  const attackPaths = data?.attackPaths || [];

  // ── Filter + search + sort ──────────────────────────────────────────────────

  const filteredPaths = useMemo(() => {
    let result = [...attackPaths];

    // Severity filter
    if (filters.severity) {
      result = result.filter((p) => p.severity === filters.severity);
    }

    // Min hops filter
    if (filters.minHops) {
      const min = parseInt(filters.minHops, 10);
      result = result.filter((p) => (p.hops || p.steps?.length || 0) >= min);
    }

    // Target type filter
    if (filters.targetType) {
      result = result.filter((p) => {
        const lastStep = p.steps?.[p.steps.length - 1];
        if (!lastStep) return false;
        return (lastStep.resourceType || '').toLowerCase().includes(filters.targetType.toLowerCase());
      });
    }

    // Search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (p) =>
          (p.title || '').toLowerCase().includes(q) ||
          (p.description || '').toLowerCase().includes(q) ||
          (p.id || '').toLowerCase().includes(q) ||
          (p.steps || []).some(
            (s) =>
              (s.resourceName || '').toLowerCase().includes(q) ||
              (s.technique || '').toLowerCase().includes(q)
          )
      );
    }

    // Sort
    result.sort((a, b) => {
      switch (sortBy) {
        case 'severity':
          return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
        case 'hops':
          return (b.hops || b.steps?.length || 0) - (a.hops || a.steps?.length || 0);
        case 'recent':
          return new Date(b.detectedAt || 0) - new Date(a.detectedAt || 0);
        case 'blast': {
          const blastOrder = { critical: 0, high: 1, medium: 2, low: 3 };
          return (
            (blastOrder[(a.blastRadius || '').toLowerCase()] ?? 99) -
            (blastOrder[(b.blastRadius || '').toLowerCase()] ?? 99)
          );
        }
        default:
          return 0;
      }
    });

    return result;
  }, [attackPaths, filters, searchQuery, sortBy]);

  // ── Expand/collapse toggle ──────────────────────────────────────────────────

  const toggleExpand = useCallback((pathId) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(pathId)) {
        next.delete(pathId);
      } else {
        next.add(pathId);
      }
      return next;
    });
  }, []);

  // ── Filter change handler ───────────────────────────────────────────────────

  const handleFilterChange = useCallback((key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  }, []);

  // ── Severity color helper ──────────────────────────────────────────────────

  function sevColor(severity) {
    const map = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' };
    return map[severity] || '#6b7280';
  }

  // ── Filter definitions for FilterBar ────────────────────────────────────────

  const filterDefs = [
    {
      key: 'severity',
      label: 'Severity',
      options: [
        { value: 'critical', label: 'Critical' },
        { value: 'high', label: 'High' },
        { value: 'medium', label: 'Medium' },
        { value: 'low', label: 'Low' },
      ],
    },
    {
      key: 'minHops',
      label: 'Min Hops',
      options: MIN_HOPS_OPTIONS,
    },
    {
      key: 'targetType',
      label: 'Target Type',
      options: TARGET_TYPE_OPTIONS,
    },
  ];

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* ── Header + Breadcrumb ── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-2">
          <button
            onClick={() => router.push('/threats')}
            className="text-sm hover:opacity-80 transition-opacity"
            style={{ color: 'var(--text-muted)' }}
          >
            Threats
          </button>
          <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Attack Paths
          </h1>
        </div>
      </div>

      {/* Threats Sub-Navigation */}
      <ThreatsSubNav />

      {/* ── Global error ── */}
      {error && (
        <div
          className="rounded-lg p-4 border"
          style={{ backgroundColor: 'rgba(220,38,38,0.1)', borderColor: '#ef4444' }}
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" style={{ color: '#ef4444' }} />
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      )}

      {/* ── KPI Strip ── */}
      {loading ? (
        <KpiSkeleton />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title="Total Paths"
            value={kpi.total}
            subtitle="Attack chains detected"
            icon={<Route className="w-5 h-5" />}
            color="blue"
          />
          <KpiCard
            title="Critical"
            value={kpi.critical}
            subtitle="Immediate remediation"
            icon={<AlertTriangle className="w-5 h-5" />}
            color="red"
          />
          <KpiCard
            title="High"
            value={kpi.high}
            subtitle="High severity paths"
            icon={<AlertTriangle className="w-5 h-5" />}
            color="orange"
          />
          <KpiCard
            title="Active"
            value={kpi.active}
            subtitle="Currently exploitable"
            icon={<Activity className="w-5 h-5" />}
            color="red"
          />
        </div>
      )}

      {/* ── Filter Bar + Search + Sort ── */}
      {!loading && attackPaths.length > 0 && (
        <div className="space-y-3">
          <FilterBar
            filters={filterDefs}
            activeFilters={filters}
            onFilterChange={handleFilterChange}
          />

          {/* Search + Sort row */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* Search input */}
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
                style={{ color: 'var(--text-muted)' }}
              />
              <input
                type="text"
                placeholder="Search paths, resources, techniques..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                style={{
                  backgroundColor: 'var(--bg-secondary)',
                  borderColor: 'var(--border-primary)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>

            {/* Sort dropdown */}
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
              style={{
                backgroundColor: 'var(--bg-secondary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            >
              {SORT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  Sort: {opt.label}
                </option>
              ))}
            </select>

            {/* Result count */}
            <span className="text-xs ml-auto" style={{ color: 'var(--text-muted)' }}>
              {filteredPaths.length} of {attackPaths.length} paths
            </span>
          </div>
        </div>
      )}

      {/* ── Attack Path Cards ── */}
      {loading ? (
        <CardSkeleton />
      ) : !error && filteredPaths.length === 0 && attackPaths.length === 0 ? (
        <EmptyState
          icon={<Shield className="w-12 h-12" />}
          title="No attack paths detected"
          description="No multi-step attack chains have been identified in your environment. Run a threat scan to analyze your infrastructure for potential attack paths."
        />
      ) : filteredPaths.length === 0 ? (
        <EmptyState
          icon={<Search className="w-12 h-12" />}
          title="No matching paths"
          description="No attack paths match the current filters. Try adjusting your search criteria or clearing filters."
          action={{
            label: 'Clear Filters',
            onClick: () => {
              setFilters({ severity: '', minHops: '', targetType: '' });
              setSearchQuery('');
            },
          }}
        />
      ) : (
        <div className="space-y-4">
          {filteredPaths.map((path) => {
            const isExpanded = expandedPaths.has(path.id);
            const pathSevColor = sevColor(path.severity);
            const hopCount = path.hops || path.steps?.length || 0;
            const targetStep = path.steps?.[path.steps.length - 1];

            return (
              <div
                key={path.id}
                className="rounded-xl border overflow-hidden transition-all duration-200"
                style={{
                  backgroundColor: 'var(--bg-card)',
                  borderColor: isExpanded ? pathSevColor : 'var(--border-primary)',
                  boxShadow: isExpanded
                    ? `0 0 0 1px ${pathSevColor}33, 0 4px 24px ${pathSevColor}11`
                    : 'none',
                }}
              >
                {/* ── Collapsed header ── */}
                <button
                  onClick={() => toggleExpand(path.id)}
                  className="w-full text-left p-5 focus:outline-none"
                >
                  <div className="flex items-start justify-between gap-4">
                    {/* Left: severity stripe + title */}
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <div
                        className="w-1 self-stretch rounded-full flex-shrink-0 mt-0.5"
                        style={{ backgroundColor: pathSevColor, minHeight: 48 }}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center flex-wrap gap-2 mb-1">
                          <SeverityBadge severity={path.severity} />
                          <code className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {path.id}
                          </code>
                        </div>
                        <h3
                          className="text-base font-bold leading-snug truncate"
                          style={{ color: 'var(--text-primary)' }}
                          title={path.title}
                        >
                          {path.title}
                        </h3>
                        {path.description && (
                          <p
                            className="text-xs mt-1 line-clamp-2"
                            style={{ color: 'var(--text-secondary)' }}
                          >
                            {path.description}
                          </p>
                        )}
                      </div>
                    </div>

                    {/* Right: status + expand indicator */}
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {path.status && (
                        <span
                          className="text-xs px-2.5 py-1 rounded-full font-semibold capitalize"
                          style={{
                            backgroundColor:
                              path.status === 'active'
                                ? 'rgba(239,68,68,0.12)'
                                : 'rgba(59,130,246,0.12)',
                            color: path.status === 'active' ? '#ef4444' : '#60a5fa',
                          }}
                        >
                          {path.status}
                        </span>
                      )}
                      <div
                        className="p-1.5 rounded-lg"
                        style={{
                          backgroundColor: 'var(--bg-tertiary)',
                          color: 'var(--text-muted)',
                        }}
                      >
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4" />
                        ) : (
                          <ChevronDown className="w-4 h-4" />
                        )}
                      </div>
                    </div>
                  </div>

                  {/* ── Metadata row ── */}
                  <div className="flex items-center flex-wrap gap-4 mt-3 pl-4">
                    <span
                      className="flex items-center gap-1.5 text-xs"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      <Target className="w-3.5 h-3.5" />
                      {hopCount} hops
                    </span>
                    <span
                      className="flex items-center gap-1.5 text-xs"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      <Users className="w-3.5 h-3.5" />
                      {path.affectedResources || 0} resources
                    </span>
                    <BlastRadiusBadge level={path.blastRadius} />
                    <span
                      className="flex items-center gap-1.5 text-xs"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      <Clock className="w-3.5 h-3.5" />
                      {relativeTime(path.detectedAt)}
                    </span>
                  </div>

                  {/* ── MITRE tactic pills ── */}
                  {path.mitreTactics?.length > 0 && (
                    <div className="flex items-center flex-wrap gap-2 mt-3 pl-4">
                      {path.mitreTactics.map((tactic, i) => (
                        <MitrePill key={i} label={tactic} />
                      ))}
                    </div>
                  )}
                </button>

                {/* ── Expanded view ── */}
                {isExpanded && (
                  <div>
                    {/* SVG attack chain visualization */}
                    <div
                      className="px-5 py-4 border-t"
                      style={{
                        borderColor: 'var(--border-primary)',
                        backgroundColor: 'var(--bg-primary)',
                      }}
                    >
                      <p
                        className="text-[10px] font-bold uppercase tracking-wider mb-3"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        Attack Chain Visualization
                      </p>
                      <AttackPathSVG steps={path.steps || []} />
                    </div>

                    {/* Step-by-step details */}
                    <div
                      className="border-t p-5 space-y-1"
                      style={{
                        borderColor: 'var(--border-primary)',
                        backgroundColor: 'var(--bg-secondary)',
                      }}
                    >
                      <p
                        className="text-[10px] font-bold uppercase tracking-wider mb-3"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        Step Details
                      </p>
                      {(path.steps || []).map((step, idx) => (
                        <StepDetailRow
                          key={idx}
                          step={step}
                          index={idx}
                          total={path.steps.length}
                          severityColor={pathSevColor}
                        />
                      ))}
                    </div>

                    {/* Action links */}
                    <div
                      className="border-t px-5 py-4 flex items-center gap-4"
                      style={{
                        borderColor: 'var(--border-primary)',
                        backgroundColor: 'var(--bg-card)',
                      }}
                    >
                      {targetStep?.resourceArn && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            router.push(
                              `/threats/blast-radius?resource_uid=${encodeURIComponent(
                                targetStep.resourceArn
                              )}`
                            );
                          }}
                          className="inline-flex items-center gap-1.5 text-xs font-medium hover:opacity-75 transition-opacity"
                          style={{ color: '#60a5fa' }}
                        >
                          <Globe className="w-3.5 h-3.5" />
                          View Blast Radius
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          router.push('/misconfig');
                        }}
                        className="inline-flex items-center gap-1.5 text-xs font-medium hover:opacity-75 transition-opacity"
                        style={{ color: '#60a5fa' }}
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        View Misconfigurations
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
