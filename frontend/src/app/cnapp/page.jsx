'use client';

import { useEffect, useMemo } from 'react';
import {
  Shield, AlertTriangle, CheckCircle,
  KeyRound, Container, Lock, Network, Activity, Code, Eye,
  TrendingUp, TrendingDown, Minus,
} from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import { subscribeRefresh, emitRefresh } from '@/lib/refreshBus';
import EngineShell from '@/components/shared/EngineShell';
import SeverityBadge from '@/components/shared/SeverityBadge';
import PageLayout from '@/components/shared/PageLayout';

// ── Colour palette ─────────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  sky:      '#38bdf8',
  indigo:   '#6366f1',
  purple:   '#8b5cf6',
  teal:     '#14b8a6',
};

// ── Pillar metadata ────────────────────────────────────────────────────────────
const PILLAR_META = {
  cspm:    { label: 'CSPM',          icon: Shield,         color: '#3b82f6', desc: 'Cloud config compliance' },
  cdr:     { label: 'CDR — Cloud Detection & Response', icon: KeyRound, color: '#8b5cf6', desc: 'Cloud detection & response' },
  cwpp:    { label: 'CWPP',          icon: Container,      color: '#06b6d4', desc: 'Workload protection' },
  dspm:    { label: 'DSPM',          icon: Lock,           color: '#f97316', desc: 'Data security posture' },
  network: { label: 'Network',       icon: Network,        color: '#22c55e', desc: '7-layer network posture' },
  threat:  { label: 'Threat',        icon: AlertTriangle,  color: '#ef4444', desc: 'Attack paths & MITRE' },
  appsec:  { label: 'AppSec',        icon: Code,           color: '#eab308', desc: 'SAST + DAST + SCA' },
};

const RISK_COLORS = {
  low:      '#22c55e',
  medium:   '#eab308',
  high:     '#f97316',
  critical: '#ef4444',
  unknown:  '#6b7280',
};

function ScoreGauge({ score, band, size = 80 }) {
  const color = RISK_COLORS[band] || '#6b7280';
  const r = (size / 2) - 8;
  const circ = 2 * Math.PI * r;
  const dashOffset = circ * (1 - (score || 0) / 100);
  return (
    <svg width={size} height={size} className="rotate-[-90deg]">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        strokeWidth={8} stroke="var(--bg-tertiary)" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        strokeWidth={8} stroke={color}
        strokeDasharray={circ} strokeDashoffset={dashOffset}
        strokeLinecap="round"
        style={{ transition: 'stroke-dashoffset 0.6s ease' }} />
      <text x={size / 2} y={size / 2 + 5}
        textAnchor="middle" className="rotate-90"
        transform={`rotate(90, ${size / 2}, ${size / 2})`}
        fill={color} fontSize={size < 60 ? 12 : 16} fontWeight="bold">
        {score ?? '—'}
      </text>
    </svg>
  );
}

function PillarCard({ pillar }) {
  const meta = PILLAR_META[pillar.id] || { label: pillar.id, icon: Shield, color: '#6b7280', desc: '' };
  const Icon = meta.icon;
  const band = pillar.risk_band || 'unknown';
  const color = RISK_COLORS[band];
  const score = pillar.posture_score;
  const isUnavail = pillar.status === 'unavailable';

  return (
    <div className="rounded-xl p-4 border flex flex-col gap-3"
      style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg" style={{ backgroundColor: `${meta.color}20` }}>
            <Icon className="w-4 h-4" style={{ color: meta.color }} />
          </div>
          <div>
            <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{meta.label}</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{meta.desc}</p>
          </div>
        </div>
        {isUnavail
          ? <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: '#6b728020', color: '#6b7280' }}>Unavailable</span>
          : <span className="text-xs font-medium px-2 py-0.5 rounded-full capitalize"
              style={{ backgroundColor: `${color}20`, color }}>{band}</span>
        }
      </div>

      {/* Score */}
      <div className="flex items-center gap-4">
        <ScoreGauge score={score} band={band} size={64} />
        <div className="flex-1 space-y-1">
          <div className="flex justify-between text-xs">
            <span style={{ color: 'var(--text-muted)' }}>Findings</span>
            <span style={{ color: 'var(--text-primary)' }}>{pillar.total_findings ?? 0}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span style={{ color: 'var(--text-muted)' }}>Critical</span>
            <span style={{ color: C.critical }}>{pillar.critical ?? 0}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span style={{ color: 'var(--text-muted)' }}>High</span>
            <span style={{ color: C.high }}>{pillar.high ?? 0}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Pillar table column def ────────────────────────────────────────────────────
function buildPillarColumns() {
  return [
    {
      accessorKey: 'id',
      header: 'Pillar',
      cell: (info) => {
        const pid = info.getValue();
        const meta = PILLAR_META[pid] || { label: pid, icon: Shield, color: '#6b7280' };
        const Icon = meta.icon;
        return (
          <div className="flex items-center gap-2">
            <Icon className="w-4 h-4" style={{ color: meta.color }} />
            <span className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{meta.label}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'posture_score',
      header: 'Score',
      cell: (info) => {
        const v = info.getValue();
        const band = info.row.original.risk_band || 'unknown';
        const color = RISK_COLORS[band];
        if (v == null) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
        return (
          <div className="flex items-center gap-2">
            <div className="w-20 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full" style={{ width: `${v}%`, backgroundColor: color }} />
            </div>
            <span className="text-xs font-bold" style={{ color }}>{v}/100</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'risk_band',
      header: 'Risk',
      cell: (info) => {
        const v = info.getValue();
        const color = RISK_COLORS[v] || '#6b7280';
        return <span className="text-xs px-2 py-0.5 rounded-full capitalize font-medium"
          style={{ backgroundColor: `${color}20`, color }}>{v}</span>;
      },
    },
    { accessorKey: 'total_findings', header: 'Findings',
      cell: (info) => <span className="text-sm">{info.getValue() ?? 0}</span> },
    { accessorKey: 'critical', header: 'Critical',
      cell: (info) => {
        const v = info.getValue() || 0;
        return <span className="text-sm font-medium" style={{ color: v > 0 ? C.critical : 'var(--text-muted)' }}>{v}</span>;
      }},
    { accessorKey: 'status', header: 'Status',
      cell: (info) => {
        const v = info.getValue();
        const isOk = v === 'ok';
        return <span className="text-xs px-2 py-0.5 rounded-full"
          style={{ backgroundColor: isOk ? '#22c55e20' : '#6b728020', color: isOk ? '#22c55e' : '#6b7280' }}>
          {v}
        </span>;
      }},
  ];
}

// ── Page ───────────────────────────────────────────────────────────────────────
export default function CnappPage() {
  const { data, loading, error, refetch } = useViewFetch('cnapp');

  // Subscribe to refresh bus so the shared Refresh button refetches this page's data
  useEffect(() => subscribeRefresh(() => refetch()), [refetch]);

  const pillars   = data?.data?.pillars || [];
  const cnappScore = data?.data?.cnapp_posture_score ?? null;
  const riskBand   = data?.data?.risk_band || 'unknown';
  const pillarsOk  = data?.data?.pillars_ok || [];
  const pillarsUnavail = data?.data?.pillars_unavailable || [];

  const pageContext  = data?.pageContext || {};
  const kpiGroups    = data?.kpiGroups   || [];

  const pillarColumns = useMemo(() => buildPillarColumns(), []);

  const tabData = useMemo(() => ({
    overview: {
      data: pillars,
      columns: pillarColumns,
      searchPlaceholder: 'Search pillars...',
    },
    ...Object.fromEntries(
      pillars.map(p => [
        p.id,
        {
          data: [p],
          columns: pillarColumns,
          searchPlaceholder: `Search ${p.id}...`,
        },
      ])
    ),
  }), [pillars, pillarColumns]);

  if (loading) {
    return (
      <EngineShell
        icon={Shield}
        title="CNAPP"
        description="Cloud-Native Application Protection Platform — unified posture across all 7 security pillars."
        onRefresh={() => emitRefresh()}
        refreshing
      >
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2"
            style={{ borderColor: 'var(--accent-primary)' }} />
        </div>
      </EngineShell>
    );
  }

  return (
    <EngineShell
      icon={Shield}
      title="CNAPP"
      description="Cloud-Native Application Protection Platform — unified posture across all 7 security pillars."
      rightOfTitle={
        <span className="text-xs px-2 py-0.5 rounded-full font-medium capitalize"
          style={{ backgroundColor: `${RISK_COLORS[riskBand]}20`, color: RISK_COLORS[riskBand] }}>
          {riskBand} risk
        </span>
      }
      onRefresh={() => emitRefresh()}
      refreshing={loading}
    >
      {/* ── CNAPP Score banner ── */}
          <div className="rounded-xl p-5 border flex items-center gap-8"
            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
            <ScoreGauge score={cnappScore} band={riskBand} size={100} />
            <div className="flex-1 grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>CNAPP Score</p>
                <p className="text-2xl font-bold" style={{ color: RISK_COLORS[riskBand] }}>
                  {cnappScore ?? '—'}<span className="text-sm font-normal">/100</span>
                </p>
              </div>
              <div>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Pillars Active</p>
                <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{pillarsOk.length} / {pillars.length}</p>
              </div>
              <div>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Total Findings</p>
                <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
                  {pillars.reduce((s, p) => s + (p.total_findings || 0), 0)}
                </p>
              </div>
              <div>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Critical</p>
                <p className="text-2xl font-bold" style={{ color: C.critical }}>
                  {pillars.reduce((s, p) => s + (p.critical || 0), 0)}
                </p>
              </div>
            </div>
          </div>

          {/* ── Pillar cards grid ── */}
          <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-4 gap-3">
            {pillars.map(p => <PillarCard key={p.id} pillar={p} />)}
          </div>

      {/* ── Pillar table via PageLayout ── */}
      <PageLayout
        icon={Shield}
        pageContext={pageContext}
        kpiGroups={[]}
        tabData={tabData}
        loading={false}
        error={error}
        defaultTab="overview"
        hideHeader
        topNav
      />
    </EngineShell>
  );
}
