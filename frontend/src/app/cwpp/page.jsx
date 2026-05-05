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
  containers: { label: 'Containers',    icon: Container,     color: '#3b82f6', desc: 'K8s / EKS / ECS / AKS / GKE' },
  images:     { label: 'Images',        icon: Box,           color: '#06b6d4', desc: 'Container image security + CVE scan' },
  hosts:      { label: 'Hosts / VMs',   icon: Server,        color: '#8b5cf6', desc: 'OS / middleware CVEs (agent-based)' },
  serverless: { label: 'Serverless',    icon: Activity,      color: '#f97316', desc: 'Lambda / Azure Functions / GCF' },
  runtime:    { label: 'Runtime',       icon: Shield,        color: '#ef4444', desc: 'Privileged containers / CIEM events' },
};

function ScoreBar({ score, band }) {
  const color = RISK_COLORS[band] || '#6b7280';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        <div className="h-full rounded-full" style={{ width: `${score ?? 0}%`, backgroundColor: color,
          transition: 'width 0.5s ease' }} />
      </div>
      <span className="text-xs font-bold w-10 text-right" style={{ color }}>
        {score ?? '—'}
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

  const { posture_score, prior_score } = workload;
  const hasPrior = prior_score !== null && prior_score !== undefined;
  const arrow = !hasPrior ? '—' : posture_score > prior_score ? '↑' : posture_score < prior_score ? '↓' : '→';
  const arrowColor = !hasPrior ? 'text-slate-400' : posture_score > prior_score ? 'text-green-400' : posture_score < prior_score ? 'text-red-400' : 'text-slate-400';

  return (
    <div
      className="rounded-xl p-4 border flex flex-col gap-3 cursor-pointer hover:bg-slate-700 transition-colors"
      style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)',
        opacity: isUnavail ? 0.6 : 1 }}
      onClick={onClick}
    >
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
          : isNoData
            ? <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: '#eab30820', color: '#eab308' }}>No Data</span>
            : <span className="text-xs font-medium px-2 py-0.5 rounded-full capitalize"
                style={{ backgroundColor: `${color}20`, color }}>{band}</span>
        }
      </div>

      {/* Score bar */}
      {!isUnavail && !isNoData && (
        <>
          <ScoreBar score={workload.posture_score} band={band} />
          <span className={`text-xs font-medium ${arrowColor}`}>{arrow}</span>
        </>
      )}

      {/* Stats */}
      {!isUnavail && (
        <div className="grid grid-cols-3 gap-2 text-center">
          {workload.id === 'containers' && <>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Clusters</p>
              <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{summary.total_clusters ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Public</p>
              <p className="text-sm font-bold" style={{ color: C.high }}>{summary.public_clusters ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Critical</p>
              <p className="text-sm font-bold" style={{ color: C.critical }}>{summary.critical_findings ?? 0}</p>
            </div>
          </>}
          {workload.id === 'images' && <>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Images</p>
              <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{summary.total_images ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Findings</p>
              <p className="text-sm font-bold" style={{ color: C.high }}>{summary.total_findings ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>CVE Scan</p>
              <p className="text-xs font-medium px-1 py-0.5 rounded" style={{ backgroundColor: '#eab30820', color: '#eab308' }}>Planned</p>
            </div>
          </>}
          {workload.id === 'hosts' && <>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Scans</p>
              <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{summary.total_host_scans ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>CVEs</p>
              <p className="text-sm font-bold" style={{ color: C.high }}>{summary.total_vulnerabilities ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Critical</p>
              <p className="text-sm font-bold" style={{ color: C.critical }}>{summary.critical ?? 0}</p>
            </div>
          </>}
          {workload.id === 'serverless' && <>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Functions</p>
              <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{summary.total_functions ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Findings</p>
              <p className="text-sm font-bold" style={{ color: C.high }}>{summary.total_findings ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Deprecated</p>
              <p className="text-sm font-bold" style={{ color: C.medium }}>{summary.deprecated_runtimes ?? 0}</p>
            </div>
          </>}
          {workload.id === 'runtime' && <>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Findings</p>
              <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{summary.total_findings ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Privileged</p>
              <p className="text-sm font-bold" style={{ color: C.critical }}>{summary.privileged_containers ?? 0}</p>
            </div>
            <div>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Host-Net</p>
              <p className="text-sm font-bold" style={{ color: C.high }}>{summary.host_network_findings ?? 0}</p>
            </div>
          </>}
        </div>
      )}

      {/* Image scan placeholder note */}
      {workload.id === 'images' && (
        <div className="text-xs p-2 rounded-lg"
          style={{ backgroundColor: '#eab30810', color: '#eab308', border: '1px solid #eab30830' }}>
          CVE scanning (Trivy/Grype) is planned — posture checks active today
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
        return <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}
          title={v}>{short}</span>;
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

// ── Workload table columns ─────────────────────────────────────────────────────
function buildWorkloadColumns() {
  return [
    {
      accessorKey: 'id',
      header: 'Workload Type',
      cell: (info) => {
        const wid = info.getValue();
        const meta = WORKLOAD_META[wid] || { label: wid, icon: Shield, color: '#6b7280' };
        const Icon = meta.icon;
        return (
          <div className="flex items-center gap-2">
            <Icon className="w-4 h-4" style={{ color: meta.color }} />
            <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{meta.label}</span>
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
        return <span className="text-sm font-medium"
          style={{ color: v > 0 ? C.critical : 'var(--text-muted)' }}>{v}</span>;
      }},
    { accessorKey: 'status', header: 'Status',
      cell: (info) => {
        const v = info.getValue();
        const isOk = v === 'ok';
        return <span className="text-xs px-2 py-0.5 rounded-full"
          style={{ backgroundColor: isOk ? '#22c55e20' : '#6b728020',
                   color: isOk ? '#22c55e' : '#6b7280' }}>{v}</span>;
      }},
  ];
}

const CVE_BANNER = (
  <div className="bg-amber-950 border border-amber-700 rounded-lg p-4 flex items-start gap-3 mb-4">
    <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
    <div>
      <p className="text-amber-200 font-medium text-sm">CVE Scanning Not Implemented</p>
      <p className="text-amber-400 text-xs mt-1">
        Image posture scores reflect policy checks only (scan-on-push enabled, image age, encryption).
        CVE content scanning via Trivy/Grype is planned — actual vulnerability exposure may be higher than the score suggests.
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

  const criticalFindings = workloads.reduce((sum, w) => sum + (w.critical ?? 0), 0);
  const belowSixty = workloads.filter(w => w.posture_score < 60).length;
  const unavailableWorkloads = workloads.filter(w => w.status === 'unavailable');

  // Findings from each workload type
  const containerFindings  = pageData.containers?.findings || [];
  const imageFindings      = pageData.images?.findings || [];
  const hostVulns          = [
    ...(pageData.hosts?.os_vulnerabilities || []),
    ...(pageData.hosts?.middleware_vulnerabilities || []),
  ];
  const serverlessFindings = pageData.serverless?.findings || [];
  const runtimeFindings    = pageData.runtime?.findings || [];

  const findingColumns  = useMemo(() => buildFindingColumns(), []);
  const workloadColumns = useMemo(() => buildWorkloadColumns(), []);

  const commonFindingFilters = [
    { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
    { key: 'status',   label: 'Status',   options: ['FAIL', 'PASS'] },
  ];

  const tabData = useMemo(() => ({
    overview: {
      data: workloads,
      columns: workloadColumns,
      searchPlaceholder: 'Search workload types...',
    },
    containers: {
      data: containerFindings,
      columns: findingColumns,
      filters: commonFindingFilters,
      searchPlaceholder: 'Search container findings...',
    },
    images: {
      data: imageFindings,
      columns: findingColumns,
      filters: commonFindingFilters,
      searchPlaceholder: 'Search image findings...',
      headerExtra: CVE_BANNER,
    },
    hosts: {
      data: hostVulns,
      columns: [
        { accessorKey: 'cve_id',     header: 'CVE',      cell: (i) => <span className="text-xs font-mono">{i.getValue()}</span> },
        { accessorKey: 'severity',   header: 'Severity',  cell: (i) => <SeverityBadge severity={i.getValue()} /> },
        { accessorKey: 'package_name', header: 'Package', cell: (i) => <span className="text-xs">{i.getValue()}</span> },
        { accessorKey: 'description', header: 'Description', cell: (i) => <span className="text-xs line-clamp-2">{i.getValue()}</span> },
      ],
      searchPlaceholder: 'Search CVEs...',
    },
    serverless: {
      data: serverlessFindings,
      columns: findingColumns,
      filters: commonFindingFilters,
      searchPlaceholder: 'Search serverless findings...',
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
    },
  }), [workloads, containerFindings, imageFindings, hostVulns, serverlessFindings, runtimeFindings,
       findingColumns, workloadColumns]);

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
      {/* ── KPI strip ── */}
          <div className="grid grid-cols-4 gap-4 mb-6">
            <KpiCard
              title="CWPP Score"
              value={cwppScore ?? '—'}
              subtitle={riskBand !== 'unknown' ? `${riskBand} risk` : undefined}
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

          {/* ── Unavailability banner ── */}
          {unavailableWorkloads.length > 0 && (
            <div className="bg-amber-950 border border-amber-700 text-amber-200 rounded-lg p-3 flex items-center gap-2 mb-4">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span className="text-sm">
                {unavailableWorkloads.map(w => w.name || w.id).join(', ')} engine{unavailableWorkloads.length > 1 ? 's' : ''} unreachable — scores may be incomplete
              </span>
            </div>
          )}

          {/* ── Radar chart + workload cards ── */}
          <div className="flex flex-col items-center gap-6">
            <WorkloadRadarChart
              workloads={workloads}
              onWorkloadClick={(id) => setActiveTab(id)}
              size={360}
            />
            <div className="grid grid-cols-5 gap-3 w-full">
              {workloads.map(w => (
                <WorkloadCard
                  key={w.id}
                  workload={w}
                  onClick={() => setActiveTab(w.id)}
                />
              ))}
            </div>
          </div>

      {/* ── Tabbed findings table ── */}
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
