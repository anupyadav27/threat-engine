'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Container, Shield, AlertTriangle,
  Server, Box, Cpu, Activity, Lock, AlertOctagon,
} from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import { subscribeRefresh, emitRefresh } from '@/lib/refreshBus';
import EngineShell from '@/components/shared/EngineShell';
import SeverityBadge from '@/components/shared/SeverityBadge';
import PageLayout from '@/components/shared/PageLayout';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';
import KpiCard from '@/components/shared/KpiCard';
import CiemRuntimeCard from '@/components/cwpp/CiemRuntimeCard';
import WorkloadRadarChart from '@/components/cwpp/WorkloadRadarChart';

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

const RISK_COLORS = {
  low:      '#22c55e',
  medium:   '#eab308',
  high:     '#f97316',
  critical: '#ef4444',
  unknown:  '#6b7280',
};

// ── Workload metadata ──────────────────────────────────────────────────────────
const WORKLOAD_META = {
  containers: { label: 'Containers',    icon: Container, color: '#3b82f6', desc: 'K8s / EKS / ECS / AKS / GKE' },
  images:     { label: 'Images',        icon: Box,       color: '#06b6d4', desc: 'Container image security + CVE scan' },
  hosts:      { label: 'Hosts / VMs',   icon: Server,    color: '#8b5cf6', desc: 'OS / middleware CVEs (agent-based)' },
  serverless: { label: 'Serverless',    icon: Activity,  color: '#f97316', desc: 'Lambda / Azure Functions / GCF' },
  runtime:    { label: 'Runtime',       icon: Shield,    color: '#ef4444', desc: 'Privileged containers / CIEM events' },
};

// ── Per-workload stat config: [label, accessor, color] ────────────────────────
const WORKLOAD_STATS = {
  containers: [
    ['Clusters',  s => s.total_clusters ?? 0,            'var(--text-primary)'],
    ['Findings',  s => s.total_findings  ?? 0,            C.high],
    ['Critical',  s => s.critical_findings ?? s.critical ?? 0, C.critical],
    ['High',      s => s.high_findings   ?? s.high ?? 0, C.medium],
  ],
  images: [
    ['Images',   s => s.total_images   ?? 0, 'var(--text-primary)'],
    ['Findings', s => s.total_findings ?? 0,  C.high],
    ['Critical', s => s.critical       ?? 0,  C.critical],
    ['Public',   s => s.public_images  ?? 0,  C.medium],
  ],
  hosts: [
    ['Hosts',       s => s.total_host_scans         ?? 0, 'var(--text-primary)'],
    ['CVEs',        s => s.total_vulnerabilities     ?? 0, C.high],
    ['Critical',    s => s.critical                  ?? 0, C.critical],
    ['Middleware',  s => s.middleware_vulnerabilities ?? 0, C.medium],
  ],
  serverless: [
    ['Functions',  s => s.total_functions  ?? 0, 'var(--text-primary)'],
    ['Findings',   s => s.total_findings   ?? 0, C.high],
    ['Critical',   s => s.critical         ?? 0, C.critical],
    ['Deprecated', s => s.deprecated_runtimes ?? 0, C.medium],
  ],
  runtime: [
    ['Findings',  s => s.total_findings       ?? 0, 'var(--text-primary)'],
    ['Privileged',s => s.privileged_containers ?? 0, C.critical],
    ['Host-Net',  s => s.host_network_findings ?? 0, C.high],
    ['Critical',  s => s.critical              ?? 0, C.medium],
  ],
};

function ScoreBar({ score, band }) {
  const color = RISK_COLORS[band] || '#6b7280';
  if (score == null) return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
      <span className="text-xs font-bold w-10 text-right" style={{ color: '#6b7280' }}>—</span>
    </div>
  );
  const barPct = score === 0 ? 0 : Math.max(score, 4);
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full relative overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        {score === 0
          ? <div className="absolute inset-0 rounded-full" style={{ backgroundColor: '#ef444430', border: '1px solid #ef4444' }} />
          : <div className="h-full rounded-full" style={{ width: `${barPct}%`, backgroundColor: color, transition: 'width 0.5s ease' }} />
        }
      </div>
      <span className="text-xs font-bold w-10 text-right" style={{ color }}>
        {score}
      </span>
    </div>
  );
}

function WorkloadCard({ workload, onClick }) {
  const meta = WORKLOAD_META[workload.id] || { label: workload.id, icon: Shield, color: '#6b7280', desc: '' };
  const Icon = meta.icon;
  const band = workload.risk_band || 'unknown';
  const color = RISK_COLORS[band];
  const isUnavail = workload.status === 'unavailable';
  const isNoData  = workload.status === 'no_data';
  const summary = workload.summary || {};
  const stats = WORKLOAD_STATS[workload.id] || [];

  const { posture_score, prior_score } = workload;
  const hasPrior = prior_score !== null && prior_score !== undefined;
  const arrow = !hasPrior ? null : posture_score > prior_score ? '↑' : posture_score < prior_score ? '↓' : '→';
  const arrowColor = !hasPrior ? '' : posture_score > prior_score ? '#22c55e' : posture_score < prior_score ? '#ef4444' : '#6b7280';

  return (
    <div
      className="rounded-xl p-4 border flex flex-col gap-3 cursor-pointer hover:opacity-90 transition-opacity"
      style={{
        backgroundColor: 'var(--bg-secondary)',
        borderColor: isUnavail ? 'var(--border-primary)' : `${meta.color}40`,
        opacity: isUnavail ? 0.55 : 1,
      }}
      onClick={onClick}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-1">
        <div className="flex items-center gap-2 min-w-0">
          <div className="p-1.5 rounded-lg shrink-0" style={{ backgroundColor: `${meta.color}20` }}>
            <Icon className="w-4 h-4" style={{ color: meta.color }} />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{meta.label}</p>
            <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>{meta.desc}</p>
          </div>
        </div>
        {isUnavail
          ? <span className="text-xs px-2 py-0.5 rounded-full shrink-0" style={{ backgroundColor: '#6b728020', color: '#6b7280' }}>Unavailable</span>
          : isNoData
            ? <span className="text-xs px-2 py-0.5 rounded-full shrink-0" style={{ backgroundColor: '#eab30820', color: '#eab308' }}>No Data</span>
            : <span className="text-xs font-medium px-2 py-0.5 rounded-full capitalize shrink-0"
                style={{ backgroundColor: `${color}20`, color }}>{band}</span>
        }
      </div>

      {/* Score bar */}
      {!isNoData && (
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Score</span>
            {arrow && <span className="text-xs font-bold" style={{ color: arrowColor }}>{arrow}</span>}
          </div>
          <ScoreBar score={isUnavail ? null : posture_score} band={band} />
        </div>
      )}

      {/* 4-stat grid */}
      {!isUnavail && stats.length > 0 && (
        <div className="grid grid-cols-4 gap-1 pt-1 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          {stats.map(([label, accessor, statColor]) => (
            <div key={label} className="text-center">
              <p className="text-[10px] leading-tight mb-0.5" style={{ color: 'var(--text-muted)' }}>{label}</p>
              <p className="text-sm font-bold tabular-nums" style={{ color: statColor }}>
                {accessor(summary)}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Image scan note */}
      {workload.id === 'images' && !isUnavail && (
        <div className="text-[10px] p-1.5 rounded"
          style={{ backgroundColor: '#eab30810', color: '#eab308', border: '1px solid #eab30820' }}>
          CVE scanning (Trivy/Grype) planned — posture checks active today
        </div>
      )}
    </div>
  );
}

// ── Findings table columns ─────────────────────────────────────────────────────
function buildFindingColumns() {
  return [
    {
      accessorKey: 'title',
      header: 'Title',
      cell: (info) => (
        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
          {info.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'resource_uid',
      header: 'Resource',
      cell: (info) => {
        const v = info.getValue() || '';
        const short = v.split('/').pop() || v.split(':').pop() || v;
        return <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }} title={v}>{short}</span>;
      },
    },
    {
      accessorKey: 'security_domain',
      header: 'Domain',
      cell: (info) => {
        const v = info.getValue();
        return v
          ? <span className="text-xs px-2 py-0.5 rounded"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>{v}</span>
          : null;
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const v = info.getValue();
        const isPass = v === 'PASS';
        return <span className="text-xs px-2 py-0.5 rounded-full font-medium"
          style={{ backgroundColor: isPass ? '#22c55e20' : '#ef444420',
                   color: isPass ? '#22c55e' : '#ef4444' }}>{v}</span>;
      },
    },
  ];
}

const CVE_BANNER = (
  <div className="bg-amber-950 border border-amber-700 rounded-lg p-4 flex items-start gap-3 mb-4">
    <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
    <div>
      <p className="text-amber-200 font-medium text-sm">CVE Scanning Not Implemented</p>
      <p className="text-amber-400 text-xs mt-1">
        Image posture scores reflect policy checks only. CVE content scanning via Trivy/Grype is planned.
      </p>
    </div>
  </div>
);

// ── Page ───────────────────────────────────────────────────────────────────────
export default function CwppPage() {
  const { data, loading, error, refetch } = useViewFetch('cwpp');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => subscribeRefresh(() => refetch()), [refetch]);

  const cwppScore  = data?.data?.cwpp_posture_score ?? null;
  const riskBand   = data?.data?.risk_band || 'unknown';
  const workloads  = data?.data?.workloads || [];
  const pageContext = data?.pageContext || {};
  const pageData    = data?.data || {};

  const criticalFindings     = workloads.reduce((sum, w) => sum + (w.critical ?? 0), 0);
  const belowSixty           = workloads.filter(w => w.posture_score != null && w.posture_score < 60).length;
  const unavailableWorkloads = workloads.filter(w => w.status === 'unavailable');

  // Per-tab findings data
  const containerFindings  = pageData.containers?.findings || [];
  const imageFindings      = pageData.images?.findings || [];
  const hostVulns          = [
    ...(pageData.hosts?.os_vulnerabilities || []),
    ...(pageData.hosts?.middleware_vulnerabilities || []),
  ];
  const serverlessFindings = pageData.serverless?.findings || [];
  const runtimeFindings    = pageData.runtime?.findings || [];

  const findingColumns = useMemo(() => buildFindingColumns(), []);

  const commonFindingFilters = [
    { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
    { key: 'status',   label: 'Status',   options: ['FAIL', 'PASS'] },
  ];

  // ── Overview tab content (replaces the DataTable) ────────────────────────────
  const overviewTab = useMemo(() => ({
    renderTab: () => (
      <div className="space-y-6 pt-2">
        {/* KPI strip */}
        <div className="grid grid-cols-4 gap-4">
          <KpiCard
            title="CWPP Score"
            value={cwppScore ?? '—'}
            subtitle={riskBand !== 'unknown' ? `${riskBand} risk` : 'No data yet'}
            color="blue"
          />
          <KpiCard
            title="Total Critical"
            value={criticalFindings}
            subtitle="Critical findings across all workloads"
            color={criticalFindings > 0 ? 'red' : 'green'}
          />
          <KpiCard
            title="Workloads Below 60"
            value={belowSixty}
            subtitle="Posture score below threshold"
            color={belowSixty > 0 ? 'orange' : 'green'}
          />
          <KpiCard
            title="Image CVE Scan"
            value="Not Enabled"
            subtitle="Trivy/Grype scanning not yet implemented"
            color="yellow"
          />
        </div>

        {/* Unavailability banner */}
        {unavailableWorkloads.length > 0 && (
          <div className="bg-amber-950 border border-amber-700 text-amber-200 rounded-lg p-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span className="text-sm">
              {unavailableWorkloads.map(w => WORKLOAD_META[w.id]?.label || w.id).join(', ')} unreachable — scores may be incomplete
            </span>
          </div>
        )}

        {/* Radar chart */}
        <div className="flex justify-center">
          <WorkloadRadarChart
            workloads={workloads}
            onWorkloadClick={(id) => setActiveTab(id)}
            size={320}
          />
        </div>

        {/* Workload cards — 5 columns */}
        <div className="grid grid-cols-5 gap-3">
          {workloads.map(w => (
            <WorkloadCard
              key={w.id}
              workload={w}
              onClick={() => setActiveTab(w.id)}
            />
          ))}
        </div>
      </div>
    ),
  }), [cwppScore, riskBand, criticalFindings, belowSixty, unavailableWorkloads, workloads]);

  const tabData = useMemo(() => ({
    overview: overviewTab,
    containers: {
      data: containerFindings,
      columns: findingColumns,
      filters: commonFindingFilters,
      searchPlaceholder: 'Search container findings...',
      onRowClick: setSelectedFinding,
    },
    images: {
      data: imageFindings,
      columns: findingColumns,
      filters: commonFindingFilters,
      searchPlaceholder: 'Search image findings...',
      headerExtra: CVE_BANNER,
      onRowClick: setSelectedFinding,
    },
    hosts: {
      data: hostVulns,
      columns: [
        { accessorKey: 'cve_id',      header: 'CVE',         cell: (i) => <span className="text-xs font-mono">{i.getValue()}</span> },
        { accessorKey: 'severity',    header: 'Severity',    cell: (i) => <SeverityBadge severity={i.getValue()} /> },
        { accessorKey: 'package_name', header: 'Package',    cell: (i) => <span className="text-xs">{i.getValue()}</span> },
        { accessorKey: 'description', header: 'Description', cell: (i) => <span className="text-xs line-clamp-2">{i.getValue()}</span> },
      ],
      searchPlaceholder: 'Search CVEs...',
      onRowClick: setSelectedFinding,
    },
    serverless: {
      data: serverlessFindings,
      columns: findingColumns,
      filters: commonFindingFilters,
      searchPlaceholder: 'Search serverless findings...',
      onRowClick: setSelectedFinding,
    },
    runtime: {
      data: runtimeFindings,
      columns: findingColumns,
      filters: commonFindingFilters,
      searchPlaceholder: 'Search runtime findings...',
      headerExtra: (
        <CiemRuntimeCard
          ciemRuntimeEvents={pageData.runtime?.ciemRuntimeEvents}
          accountId={null}
        />
      ),
      onRowClick: setSelectedFinding,
    },
  }), [overviewTab, containerFindings, imageFindings, hostVulns, serverlessFindings,
       runtimeFindings, findingColumns, pageData.runtime]);

  if (loading) {
    return (
      <EngineShell
        icon={Container}
        title="CWPP"
        description="Cloud Workload Protection Platform — containers, images, hosts/VMs, serverless, and runtime security."
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
      icon={Container}
      title="CWPP"
      description="Cloud Workload Protection Platform — containers, images, hosts/VMs, serverless, and runtime security."
      rightOfTitle={
        <span className="text-xs px-2 py-0.5 rounded-full font-medium capitalize"
          style={{ backgroundColor: `${RISK_COLORS[riskBand]}20`, color: RISK_COLORS[riskBand] }}>
          {riskBand} risk
        </span>
      }
      onRefresh={() => emitRefresh()}
      refreshing={loading}
    >
      <PageLayout
        key={activeTab}
        icon={Container}
        pageContext={pageContext}
        kpiGroups={data?.kpiGroups || []}
        tabData={tabData}
        loading={false}
        error={error}
        defaultTab={activeTab}
        hideHeader
        topNav
        onRowClick={setSelectedFinding}
      />
      <FindingDetailPanel finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </EngineShell>
  );
}
