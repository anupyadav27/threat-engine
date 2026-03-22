'use client';

import { useEffect, useState, useMemo } from 'react';
import {
  Server,
  Shield,
  AlertTriangle,
  CheckCircle,
  ClipboardCheck,
  AlertCircle,
  TrendingUp,
  TrendingDown,
  Clock,
  Activity,
  Zap,
  Bell,
  ArrowRight,
  Flame,
  ExternalLink,
  Filter,
  ChevronRight,
} from 'lucide-react';
import Link from 'next/link';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import TrendLine from '@/components/charts/TrendLine';
import DataTable from '@/components/shared/DataTable';
import PostureScoreHero from '@/components/shared/PostureScoreHero';
import CloudHealthGrid from '@/components/shared/CloudHealthGrid';
import CloudProviderBadge from '@/components/shared/CloudProviderBadge';

// ─── Severity colour helpers ──────────────────────────────────────────────────
const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

/**
 * Enterprise CSPM Dashboard — multi-cloud security posture overview
 * Scope filter is provided globally via GlobalFilterBar in AppShell.
 */
export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [pageError, setPageError] = useState(null);
  const [alertIndex, setAlertIndex] = useState(0);
  const [securityScoreTrendData, setSecurityScoreTrendData] = useState([]);
  const [findingsByCategoryData, setFindingsByCategoryData] = useState([]);
  const [realComplianceFrameworks, setRealComplianceFrameworks] = useState(null);
  const [threatActivityTrend, setThreatActivityTrend] = useState(null);
  const [activeRecentScans, setActiveRecentScans] = useState(null);
  const [activeCloudProviders, setActiveCloudProviders] = useState(null);
  const [toxicCombos, setToxicCombos] = useState([]);
  const [criticalActions, setCriticalActions] = useState({ immediate: [], thisWeek: [], thisMonth: [] });
  const [criticalAlerts, setCriticalAlerts] = useState([]);
  const [attackSurfaceData, setAttackSurfaceData] = useState([]);
  const [mitreTopTechniques, setMitreTopTechniques] = useState([]);
  const [remediationSLA, setRemediationSLA] = useState([]);
  const [riskyResources, setRiskyResources] = useState([]);
  const [cloudHealthData, setCloudHealthData] = useState([]);

  // ── Global scope filter (provider/account/region/timeRange from GlobalFilterBar) ──
  const { provider: filterProvider } = useGlobalFilter();

  // ── Filter cloud health rows by selected provider ────────────────────────
  const filteredCloudHealth = useMemo(() =>
    filterProvider
      ? cloudHealthData.filter((c) => c.provider === filterProvider)
      : cloudHealthData,
    [filterProvider, cloudHealthData]
  );

  const [kpiData, setKpiData] = useState({
    totalAssets: null,
    totalAssetsChange: null,
    openFindings: null,
    openFindingsChange: null,
    criticalHighFindings: null,
    criticalHighFindingsChange: null,
    complianceScore: null,
    complianceScoreChange: null,
    attackSurfaceScore: null,
    attackSurfaceScoreChange: null,
    mttr: null,
    mttrChange: null,
    activeThreats: null,
    activeThreatsChange: null,
    slaCompliance: null,
    slaComplianceChange: null,
  });

  // ── API fetch — single BFF call replaces 16 parallel engine calls ──────
  useEffect(() => {
    const fetchDashboardData = async () => {
      setLoading(true);
      try {
        const data = await fetchView('dashboard', {
          provider: filterProvider || undefined,
        });

        if (data.error) {
          setPageError(data.error);
          return;
        }

        // All data is pre-normalized by the BFF — direct assignment
        if (data.kpi)                  setKpiData(data.kpi);
        if (data.securityScoreTrendData) setSecurityScoreTrendData(data.securityScoreTrendData);
        if (data.findingsByCategoryData) setFindingsByCategoryData(data.findingsByCategoryData);
        if (data.frameworks)           setRealComplianceFrameworks(data.frameworks);
        if (data.threatActivityTrend)  setThreatActivityTrend(data.threatActivityTrend);
        if (data.recentScans)          setActiveRecentScans(data.recentScans);
        if (data.cloudProviders)       setActiveCloudProviders(data.cloudProviders);
        if (data.toxicCombinations)    setToxicCombos(data.toxicCombinations);
        if (data.criticalActions)      setCriticalActions(data.criticalActions);
        if (data.criticalAlerts)       setCriticalAlerts(data.criticalAlerts);
        if (data.attackSurfaceData)    setAttackSurfaceData(data.attackSurfaceData);
        if (data.mitreTopTechniques)   setMitreTopTechniques(data.mitreTopTechniques);
        if (data.remediationSLA)       setRemediationSLA(data.remediationSLA);
        if (data.riskyResources)       setRiskyResources(data.riskyResources);
        if (data.cloudHealthData)      setCloudHealthData(data.cloudHealthData);
      } catch (error) {
        console.warn('Error fetching dashboard data:', error);
        setPageError(error.message || 'Failed to load dashboard data');
      } finally {
        setLoading(false);
      }
    };
    fetchDashboardData();
  }, [filterProvider]);

  // Rotate alert banner every 8 s (only when alerts are loaded)
  useEffect(() => {
    if (criticalAlerts.length === 0) return;
    const interval = setInterval(() => {
      setAlertIndex((prev) => (prev + 1) % criticalAlerts.length);
    }, 8000);
    return () => clearInterval(interval);
  }, [criticalAlerts.length]);

  // ── Table columns ────────────────────────────────────────────────────────
  const riskyResourcesColumns = [
    {
      accessorKey: 'resource',
      header: 'Resource',
      cell: (info) => (
        <div>
          <div className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</div>
          <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.row.original.type}</div>
        </div>
      ),
    },
    {
      accessorKey: 'provider',
      header: 'Provider / Region',
      cell: (info) => (
        <div className="flex flex-col gap-0.5">
          <CloudProviderBadge provider={info.getValue()} size="sm" />
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.row.original.region}</span>
        </div>
      ),
    },
    {
      accessorKey: 'findings',
      header: 'Findings',
      cell: (info) => (
        <span className="text-sm font-semibold" style={{ color: '#ef4444' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'riskScore',
      header: 'Risk Score',
      cell: (info) => {
        const score = info.getValue();
        const color = score > 80 ? '#ef4444' : score > 60 ? '#f97316' : '#eab308';
        return (
          <div className="flex items-center gap-2">
            <div className="w-12 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
            </div>
            <span className="text-sm font-bold" style={{ color }}>{score}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'owner',
      header: 'Owner',
      cell: (info) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'age',
      header: 'Age',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>,
    },
  ];

  const recentScansColumns = [
    {
      accessorKey: 'scanId',
      header: 'Scan ID',
      cell: (info) => (
        <code className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </code>
      ),
    },
    { accessorKey: 'type',     header: 'Type',     cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => <CloudProviderBadge provider={info.getValue()} size="sm" />,
    },
    { accessorKey: 'account',  header: 'Account',  cell: (info) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'duration', header: 'Duration', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
    { accessorKey: 'findings', header: 'Findings', cell: (info) => <span className="text-sm font-semibold" style={{ color: '#ef4444' }}>{info.getValue()}</span> },
    { accessorKey: 'status',   header: 'Status',   cell: (info) => <StatusIndicator status={info.getValue()} /> },
  ];

  // ── Render helpers ────────────────────────────────────────────────────────
  const renderKpiCard = (title, value, subtitle, icon, color, change, isPercent = false, isScore = false) => {
    const trendIcon = change >= 0 ? <TrendingUp className="w-4 h-4" /> : <TrendingDown className="w-4 h-4" />;
    const trendColor = isScore || color === 'blue' || color === 'green'
      ? (change >= 0 ? '#10b981' : '#ef4444')
      : (change <= 0 ? '#10b981' : '#ef4444');
    return (
      <div className="rounded-lg p-4 border transition-all duration-200 hover:border-opacity-80"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-start justify-between mb-3">
          <div className="p-2 rounded-lg" style={{
            backgroundColor: color === 'red' ? 'rgba(239,68,68,0.1)' : color === 'orange' ? 'rgba(249,115,22,0.1)'
              : color === 'yellow' ? 'rgba(234,179,8,0.1)' : color === 'green' ? 'rgba(16,185,129,0.1)'
              : color === 'blue' ? 'rgba(59,130,246,0.1)' : 'rgba(168,85,247,0.1)',
          }}>
            {icon}
          </div>
          <div className="flex items-center gap-1" style={{ color: trendColor }}>
            {trendIcon}
            <span className="text-xs font-semibold">{change > 0 ? '+' : ''}{change}{isPercent ? '%' : ''}</span>
          </div>
        </div>
        <h3 className="text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>{title}</h3>
        <div className="text-2xl font-bold mb-1" style={{ color: 'var(--text-primary)' }}>
          {typeof value === 'string' ? value : value.toLocaleString()}
        </div>
        <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{subtitle}</p>
      </div>
    );
  };

  const renderComplianceGauge = (framework) => {
    const scoreColor = framework.score > 80 ? '#10b981' : framework.score > 60 ? '#eab308' : '#ef4444';
    const trendColor = framework.trend >= 0 ? '#10b981' : '#ef4444';
    return (
      <div key={framework.name} className="rounded-lg p-3 border"
        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between mb-2">
          <h4 className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{framework.name}</h4>
          <div className="flex items-center gap-1" style={{ color: trendColor }}>
            {framework.trend >= 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
            <span className="text-xs font-semibold">{Math.abs(framework.trend)}</span>
          </div>
        </div>
        <div className="w-full rounded-full h-2 mb-2" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
          <div className="h-2 rounded-full transition-all duration-300"
            style={{ width: `${framework.score}%`, backgroundColor: scoreColor }} />
        </div>
        <div className="text-sm font-bold" style={{ color: scoreColor }}>{framework.score}%</div>
      </div>
    );
  };

  const renderAttackSurfaceBar = (item) => {
    const severityColor = item.severity === 'critical' ? '#ef4444' : '#f97316';
    return (
      <div key={item.category} className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{item.category}</span>
          <span className="text-sm font-bold" style={{ color: severityColor }}>{(item.value || 0).toLocaleString()}</span>
        </div>
        <div className="w-full rounded-lg h-6 overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
          <div className="h-full transition-all duration-300 flex items-center justify-end pr-2"
            style={{ width: `${Math.min(100, (item.value / 1500) * 100)}%`, backgroundColor: severityColor }}>
            <span className="text-xs font-bold text-white">{item.value}</span>
          </div>
        </div>
      </div>
    );
  };

  const renderCloudProviderCard = (provider) => {
    const totalFindings  = provider.findings;
    const criticalPct    = (provider.severities.critical / totalFindings) * 100;
    const highPct        = (provider.severities.high    / totalFindings) * 100;
    const mediumPct      = (provider.severities.medium  / totalFindings) * 100;
    return (
      <div key={provider.name} className="rounded-lg p-4 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="mb-4">
          <CloudProviderBadge provider={provider.name} />
        </div>
        <div className="space-y-3 mb-4">
          {[['Accounts', provider.accounts], ['Resources', provider.resources.toLocaleString()],
            ['Findings', provider.findings],
          ].map(([label, val]) => (
            <div key={label} className="flex justify-between text-sm">
              <span style={{ color: 'var(--text-secondary)' }}>{label}:</span>
              <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>{val}</span>
            </div>
          ))}
          <div className="flex justify-between text-sm">
            <span style={{ color: 'var(--text-secondary)' }}>Compliance:</span>
            <span className="font-semibold" style={{ color: provider.compliance > 80 ? '#10b981' : provider.compliance > 60 ? '#eab308' : '#ef4444' }}>
              {provider.compliance}%
            </span>
          </div>
        </div>
        <div className="flex h-8 gap-0.5 rounded-lg overflow-hidden">
          {[['#ef4444', criticalPct, 'C'], ['#f97316', highPct, 'H'], ['#eab308', mediumPct, 'M'],
            ['#3b82f6', 100 - criticalPct - highPct - mediumPct, 'L']].map(([color, pct, label]) => (
            <div key={label} className="flex items-center justify-center text-xs font-bold text-white"
              style={{ width: `${pct}%`, backgroundColor: color }} title={label}>
              {pct > 8 && label}
            </div>
          ))}
        </div>
      </div>
    );
  };

  // ── Toxic combo risk badge ──────────────────────────────────────────────
  const riskScoreBadge = (score) => {
    const color = score >= 90 ? '#ef4444' : score >= 75 ? '#f97316' : '#eab308';
    return (
      <div className="flex items-center justify-center w-12 h-12 rounded-full border-2 flex-shrink-0"
        style={{ borderColor: color, backgroundColor: `${color}18` }}>
        <span className="text-sm font-bold" style={{ color }}>{score}</span>
      </div>
    );
  };

  // ── Critical action severity pill ──────────────────────────────────────
  const sevPill = (severity) => (
    <span className="text-xs font-semibold px-2 py-0.5 rounded-full"
      style={{ backgroundColor: `${SEV_COLOR[severity]}22`, color: SEV_COLOR[severity] }}>
      {severity}
    </span>
  );

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">

      {/* ── Error Banner ─────────────────────────────────────────────────── */}
      {pageError && (
        <div className="rounded-lg p-4 border flex items-center gap-3"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: '#ef4444' }}>
          <AlertCircle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
          <div>
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>Failed to load dashboard data</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{pageError}</p>
          </div>
        </div>
      )}

      {/* ── Page Header ─────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>Enterprise CSPM Dashboard</h1>
          <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Real-time multi-cloud security posture · compliance · threat detection
          </p>
        </div>
      </div>

      {/* ── Security Posture Hero ────────────────────────────────────────── */}
      <PostureScoreHero
        score={kpiData.complianceScore || 0}
        prevScore={(kpiData.complianceScore || 0) - (kpiData.complianceScoreChange || 0)}
        delta={kpiData.complianceScoreChange || 0}
        status={kpiData.complianceScore >= 75 ? 'Good' : kpiData.complianceScore >= 50 ? 'Fair' : 'Critical'}
        criticalActions={kpiData.criticalHighFindings || 0}
        domainScores={{
          compliance: kpiData.complianceScore || 0,
          threats: kpiData.activeThreats ? Math.max(0, 100 - Math.round(kpiData.activeThreats / 10)) : 0,
          iam: kpiData.openFindings ? Math.max(0, 100 - Math.round(kpiData.openFindings / 20)) : 0,
          misconfigs: kpiData.criticalHighFindings ? Math.max(0, 100 - Math.round(kpiData.criticalHighFindings / 5)) : 0,
          dataSec: kpiData.attackSurfaceScore ? Math.max(0, 100 - kpiData.attackSurfaceScore) : 50,
        }}
      />

      {/* ── Posture Snapshot — 6 actionable metrics, 2 grouped categories ── */}
      {(() => {
        const fws      = realComplianceFrameworks && realComplianceFrameworks.length > 0 ? realComplianceFrameworks : [];
        if (fws.length === 0) return null;
        const worstFw  = [...fws].sort((a, b) => a.score - b.score)[0];
        const fwColor  = worstFw.score < 70 ? '#ef4444' : worstFw.score < 80 ? '#eab308' : '#10b981';
        const validAcc = filteredCloudHealth.filter(c => c.credStatus === 'valid').length;
        const totalAcc = filteredCloudHealth.length;
        const allValid = validAcc === totalAcc;

        // Helper for a single metric cell
        const Cell = ({ label, value, valueColor, delta, deltaGoodDown, context, noTrend, borderRight = true }) => {
          const isGood = deltaGoodDown ? delta < 0 : delta > 0;
          const trendColor = isGood ? '#10b981' : '#ef4444';
          return (
            <div className="px-5 py-4 flex flex-col gap-1 min-w-0"
              style={{ borderRight: borderRight ? '1px solid var(--border-primary)' : 'none' }}>
              <p className="text-[10px] font-bold uppercase tracking-wider truncate"
                style={{ color: 'var(--text-muted)' }}>
                {label}
              </p>
              <p className="text-xl font-black leading-none" style={{ color: valueColor || 'var(--text-primary)' }}>
                {value}
              </p>
              {!noTrend && delta !== undefined ? (
                <div className="flex items-center gap-1 mt-0.5">
                  {delta < 0
                    ? <TrendingDown className="w-3 h-3 flex-shrink-0" style={{ color: trendColor }} />
                    : <TrendingUp   className="w-3 h-3 flex-shrink-0" style={{ color: trendColor }} />
                  }
                  <span className="text-[10px] font-semibold" style={{ color: trendColor }}>
                    {delta > 0 ? '+' : ''}{delta}
                  </span>
                  <span className="text-[10px] truncate" style={{ color: 'var(--text-muted)' }}>{context}</span>
                </div>
              ) : (
                <p className="text-[10px] mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>{context}</p>
              )}
            </div>
          );
        };

        return (
          <div className="rounded-xl border overflow-hidden"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

            {/* Group header row */}
            <div className="grid grid-cols-2 border-b text-[9px] font-black uppercase tracking-widest"
              style={{ borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-2 flex items-center gap-2 border-r"
                style={{ borderColor: 'var(--border-primary)', color: '#ef4444' }}>
                <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: '#ef4444' }} />
                Risk Posture
              </div>
              <div className="px-5 py-2 flex items-center gap-2" style={{ color: '#3b82f6' }}>
                <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: '#3b82f6' }} />
                Operations &amp; Coverage
              </div>
            </div>

            {/* 6 metric cells */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
              {/* 1 — Critical + High Findings */}
              <Cell
                label="Critical + High"
                value={kpiData.criticalHighFindings != null ? kpiData.criticalHighFindings.toLocaleString() : '--'}
                valueColor="#ef4444"
                delta={kpiData.criticalHighFindingsChange}
                deltaGoodDown
                context="vs last 7d"
              />
              {/* 2 — Internet-Exposed Assets */}
              <Cell
                label="Internet Exposed"
                value={kpiData.internetExposed != null && kpiData.internetExposed > 0 ? kpiData.internetExposed.toLocaleString() : (attackSurfaceData.length > 0 ? attackSurfaceData.reduce((s, a) => s + (a.value || 0), 0).toLocaleString() : '--')}
                valueColor="#f97316"
                deltaGoodDown
                context="publicly reachable"
                noTrend
              />
              {/* 3 — Lowest compliance framework score (most urgent gap) */}
              <Cell
                label={`${worstFw.name} (worst)`}
                value={`${worstFw.score}%`}
                valueColor={fwColor}
                delta={worstFw.trend}
                deltaGoodDown={false}
                context="compliance score"
                borderRight={false}
              />
              {/* 4 — Mean Time to Remediate */}
              <Cell
                label="Mean Time to Remediate"
                value={kpiData.mttr != null ? `${kpiData.mttr}d` : '--'}
                delta={kpiData.mttrChange}
                deltaGoodDown
                context="avg all severities"
              />
              {/* 5 — Remediation SLA (% fixed within SLA window) */}
              <Cell
                label="Remediation SLA"
                value={kpiData.slaCompliance != null ? `${kpiData.slaCompliance}%` : '--'}
                valueColor={kpiData.slaCompliance != null ? (kpiData.slaCompliance >= 90 ? '#10b981' : kpiData.slaCompliance >= 75 ? '#eab308' : '#ef4444') : undefined}
                delta={kpiData.slaComplianceChange}
                deltaGoodDown={false}
                context="fixed within target"
              />
              {/* 6 — Monitored Accounts (coverage completeness) */}
              <Cell
                label="Monitored Accounts"
                value={`${validAcc} / ${totalAcc}`}
                valueColor={allValid ? '#10b981' : '#ef4444'}
                context={allValid ? 'all credentials valid' : `${totalAcc - validAcc} credential issue`}
                noTrend
                borderRight={false}
              />
            </div>
          </div>
        );
      })()}

      {/* ── Multi-Cloud Coverage ──────────────────────────────────────────── */}
      <CloudHealthGrid clouds={filteredCloudHealth} />

      {/* ── Critical Actions (3-column) ───────────────────────────────────── */}
      <div>
        <div className="mb-3">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Critical Actions</h2>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
            Prioritised remediation tasks requiring security team attention
          </p>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {[
            { key: 'immediate', label: '🔴 Immediate', borderColor: '#ef4444', bgColor: 'rgba(239,68,68,0.06)' },
            { key: 'thisWeek',  label: '🟠 This Week',  borderColor: '#f97316', bgColor: 'rgba(249,115,22,0.06)' },
            { key: 'thisMonth', label: '🟡 This Month', borderColor: '#eab308', bgColor: 'rgba(234,179,8,0.06)'  },
          ].map(({ key, label, borderColor, bgColor }) => (
            <div key={key} className="rounded-xl border overflow-hidden"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-4 py-3 border-b flex items-center justify-between"
                style={{ borderColor, borderBottomWidth: 2, backgroundColor: bgColor }}>
                <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{label}</span>
                <span className="text-xs font-bold px-2 py-0.5 rounded-full"
                  style={{ backgroundColor: borderColor, color: 'white' }}>
                  {(criticalActions[key] || []).length}
                </span>
              </div>
              <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
                {(criticalActions[key] || []).length === 0 ? (
                  <div className="px-4 py-6 text-center text-xs" style={{ color: 'var(--text-tertiary)' }}>
                    No actions available
                  </div>
                ) : (criticalActions[key] || []).map((action) => (
                  <div key={action.id} className="px-4 py-3 hover:opacity-90 transition-opacity">
                    <div className="flex items-start gap-2 mb-2">
                      {sevPill(action.severity)}
                      <CloudProviderBadge provider={action.provider} size="sm" />
                    </div>
                    <p className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>{action.title}</p>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                        <span>{action.affectedCount} affected</span>
                        <span>·</span>
                        <span>{action.estimatedFix} fix</span>
                      </div>
                      <a href={action.link}
                        className="text-xs flex items-center gap-1 font-semibold hover:opacity-80 transition-opacity"
                        style={{ color: 'var(--accent-primary)' }}>
                        Fix <ArrowRight className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Toxic Combinations (Wiz-style) ────────────────────────────────── */}
      <div className="rounded-xl border overflow-hidden"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between"
          style={{ borderColor: 'var(--border-primary)' }}>
          <div>
            <h2 className="text-base font-semibold flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
              <Flame className="w-4 h-4" style={{ color: '#ef4444' }} />
              Toxic Combinations
            </h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Multi-issue compound risk scenarios with critical blast radius
            </p>
          </div>
          <a href="/threats/attack-paths" className="text-xs flex items-center gap-1 font-semibold"
            style={{ color: 'var(--accent-primary)' }}>
            View all <ExternalLink className="w-3 h-3" />
          </a>
        </div>
        <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
          {toxicCombos.length === 0 ? (
            <div className="px-6 py-8 text-center text-sm" style={{ color: 'var(--text-tertiary)' }}>
              No toxic combinations detected
            </div>
          ) : toxicCombos.map((combo) => (
            <div key={combo.id} className="px-6 py-4 flex items-start gap-4 hover:opacity-90 transition-opacity">
              {riskScoreBadge(combo.riskScore)}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{combo.title}</span>
                  <CloudProviderBadge provider={combo.provider} size="sm" />
                  <code className="text-xs px-1.5 py-0.5 rounded font-mono"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: '#f97316' }}>
                    {combo.mitre}
                  </code>
                </div>
                <p className="text-xs mb-2" style={{ color: 'var(--text-secondary)' }}>{combo.description}</p>
                <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--text-muted)' }}>
                  <span>{combo.affectedResources} resource{combo.affectedResources > 1 ? 's' : ''} affected</span>
                  <span>·</span>
                  <span>{(combo.affectedAccounts || []).join(', ')}</span>
                </div>
              </div>
              <a href={combo.fixLink}
                className="flex-shrink-0 text-xs flex items-center gap-1 font-semibold px-3 py-1.5 rounded-lg transition-opacity hover:opacity-80"
                style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}>
                Investigate <ArrowRight className="w-3 h-3" />
              </a>
            </div>
          ))}
        </div>
      </div>

      {/* ── Real-Time Alerts Banner ───────────────────────────────────────── */}
      <div className="rounded-lg p-4 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center gap-2 mb-3">
          <Bell className="w-5 h-5" style={{ color: '#ef4444' }} />
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Real-Time Security Alerts</h2>
          <span className="ml-auto text-xs font-semibold px-2 py-1 rounded"
            style={{ backgroundColor: '#ef4444', color: 'white' }}>
            {criticalAlerts.length} Critical
          </span>
        </div>
        <div>
          {criticalAlerts.length === 0 ? (
            <div className="text-center py-6 text-sm" style={{ color: 'var(--text-tertiary)' }}>
              No critical alerts at this time
            </div>
          ) : (
            <>
              {[criticalAlerts[alertIndex]].filter(Boolean).map((alert) => (
                <div key={alert.id} className="rounded-lg p-3 border transition-all duration-300"
                  style={{ backgroundColor: 'var(--bg-secondary)', borderColor: '#ef4444' }}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <AlertCircle className="w-4 h-4 flex-shrink-0" style={{ color: '#ef4444' }} />
                        <span className="text-sm font-semibold" style={{ color: '#ef4444' }}>
                          Critical: {alert.message}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
                        <span>{alert.resource}</span>
                        <span>•</span>
                        <CloudProviderBadge provider={alert.provider} size="sm" />
                        <span>•</span>
                        <span>{alert.timestamp}</span>
                        <span>•</span>
                        <span>{alert.count} finding{alert.count > 1 ? 's' : ''}</span>
                      </div>
                    </div>
                    <button className="px-3 py-1 rounded text-xs font-semibold transition-colors"
                      style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}>
                      Investigate
                    </button>
                  </div>
                </div>
              ))}
              <div className="flex justify-center gap-1 mt-2">
                {criticalAlerts.map((_, idx) => (
                  <div key={idx} className="w-2 h-2 rounded-full transition-all"
                    style={{ backgroundColor: alertIndex === idx ? '#ef4444' : 'var(--border-primary)' }} />
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Attack Surface + Compliance (2-col) ─────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-lg p-6 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Attack Surface Overview</h2>
          {attackSurfaceData.length === 0 ? (
            <p className="text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>No attack surface data available</p>
          ) : attackSurfaceData.map((item) => renderAttackSurfaceBar(item))}
        </div>

        <div className="rounded-lg p-6 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Compliance Framework Posture</h2>
          <div className="grid grid-cols-2 gap-3">
            {(!realComplianceFrameworks || realComplianceFrameworks.length === 0) ? (
              <p className="col-span-2 text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>No compliance data available</p>
            ) : realComplianceFrameworks.map((fw) => renderComplianceGauge(fw))}
          </div>
        </div>
      </div>

      {/* ── Cloud Provider Breakdown ──────────────────────────────────────── */}
      <div className="rounded-lg p-6 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Cloud Provider Breakdown</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {(!activeCloudProviders || activeCloudProviders.length === 0) ? (
            <p className="col-span-3 text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>No cloud provider data available</p>
          ) : activeCloudProviders.map((p) => renderCloudProviderCard(p))}
        </div>
      </div>

      {/* ── Threats Summary Card ──────────────────────────────────────────── */}
      <div className="rounded-xl border overflow-hidden"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between"
          style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5" style={{ color: '#ef4444' }} />
            <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
              Threats Overview
            </h2>
          </div>
          <Link href="/threats" className="text-xs flex items-center gap-1 font-semibold"
            style={{ color: 'var(--accent-primary)' }}>
            View All Threats <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
        <div className="px-6 py-5">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
            <div className="rounded-lg p-4 border"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
              <p className="text-2xl font-bold" style={{ color: '#ef4444' }}>
                {kpiData.activeThreats ?? 0}
              </p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Active Threats</p>
            </div>
            <div className="rounded-lg p-4 border"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
              <p className="text-2xl font-bold" style={{ color: '#f97316' }}>
                {kpiData.criticalHighFindings ?? 0}
              </p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Critical + High Findings</p>
            </div>
            <div className="rounded-lg p-4 border"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
              <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
                {kpiData.attackSurfaceScore ?? 0}
              </p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Attack Surface Score</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/threats"
              className="text-xs flex items-center gap-1 font-semibold hover:opacity-80 transition-opacity"
              style={{ color: 'var(--accent-primary)' }}>
              View All Threats <ArrowRight className="w-3 h-3" />
            </Link>
            <Link href="/threats/attack-paths"
              className="text-xs flex items-center gap-1 font-semibold hover:opacity-80 transition-opacity"
              style={{ color: 'var(--accent-primary)' }}>
              Attack Paths <ArrowRight className="w-3 h-3" />
            </Link>
            <Link href="/threats/blast-radius"
              className="text-xs flex items-center gap-1 font-semibold hover:opacity-80 transition-opacity"
              style={{ color: 'var(--accent-primary)' }}>
              Blast Radius <ArrowRight className="w-3 h-3" />
            </Link>
            <Link href="/threats/toxic-combinations"
              className="text-xs flex items-center gap-1 font-semibold hover:opacity-80 transition-opacity"
              style={{ color: 'var(--accent-primary)' }}>
              Toxic Combos <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>
      </div>

      {/* ── MITRE + Threat Trend ──────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-lg p-6 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Top 5 MITRE ATT&CK Techniques</h2>
          <div className="space-y-3">
            {mitreTopTechniques.length === 0 ? (
              <p className="text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>No MITRE technique data available</p>
            ) : mitreTopTechniques.map((t) => (
              <div key={t.id} className="flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <code className="text-xs font-semibold" style={{ color: t.color }}>{t.id}</code>
                    <span className="text-sm truncate" style={{ color: 'var(--text-primary)' }}>{t.name}</span>
                  </div>
                  <div className="w-full rounded-full h-2" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <div className="h-2 rounded-full" style={{ width: `${Math.min(100, (t.count / (mitreTopTechniques[0]?.count || t.count)) * 100)}%`, backgroundColor: t.color }} />
                  </div>
                </div>
                <span className="text-sm font-bold w-10 text-right" style={{ color: 'var(--text-primary)' }}>{t.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg p-6 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Threat Activity Trend (30 Days)</h2>
          {threatActivityTrend && threatActivityTrend.length > 0 ? (
            <TrendLine
              data={threatActivityTrend}
              dataKeys={['threats']}
              colors={['#ef4444']}
            />
          ) : (
            <p className="text-sm text-center py-8" style={{ color: 'var(--text-tertiary)' }}>No threat trend data available</p>
          )}
        </div>
      </div>

      {/* ── Findings by Category ─────────────────────────────────────────── */}
      <div className="rounded-lg p-6 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Findings by Category</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-primary)' }}>
                {['Category','Critical','High','Medium','Low'].map((h, i) => (
                  <th key={h} className={`py-2 px-2 font-semibold ${i === 0 ? 'text-left' : 'text-center'}`}
                    style={{ color: i === 0 ? 'var(--text-secondary)' : ['#ef4444','#f97316','#eab308','#3b82f6'][i-1] }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {findingsByCategoryData.map((row) => (
                <tr key={row.category} className="border-b hover:opacity-80"
                  style={{ borderColor: 'var(--border-primary)' }}>
                  <td className="py-3 px-2" style={{ color: 'var(--text-primary)' }}>{row.category}</td>
                  <td className="text-center py-3 px-2 font-semibold" style={{ color: '#ef4444' }}>{row.critical}</td>
                  <td className="text-center py-3 px-2 font-semibold" style={{ color: '#f97316' }}>{row.high}</td>
                  <td className="text-center py-3 px-2 font-semibold" style={{ color: '#eab308' }}>{row.medium}</td>
                  <td className="text-center py-3 px-2 font-semibold" style={{ color: '#3b82f6' }}>{row.low}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Remediation SLA Tracking ─────────────────────────────────────── */}
      <div className="rounded-lg p-6 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Remediation SLA Tracking</h2>
        {remediationSLA.length === 0 ? (
          <p className="text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>No remediation SLA data available</p>
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-primary)' }}>
                {['Severity','SLA Target','Open Count','Within SLA','Breached','Compliance'].map((h) => (
                  <th key={h} className="text-left py-2 px-2 font-semibold" style={{ color: 'var(--text-secondary)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {remediationSLA.map((row) => {
                const complianceColor = row.compliant > 95 ? '#10b981' : row.compliant > 80 ? '#eab308' : '#ef4444';
                return (
                  <tr key={row.severity} className="border-b hover:opacity-80" style={{ borderColor: 'var(--border-primary)' }}>
                    <td className="py-3 px-2 font-semibold" style={{ color: 'var(--text-primary)' }}>{row.severity}</td>
                    <td className="py-3 px-2" style={{ color: 'var(--text-secondary)' }}>{row.slaTarget}</td>
                    <td className="py-3 px-2 font-semibold" style={{ color: 'var(--text-primary)' }}>{row.openCount}</td>
                    <td className="py-3 px-2 font-semibold" style={{ color: '#10b981' }}>{row.withinSLA}</td>
                    <td className="py-3 px-2 font-semibold" style={{ color: '#ef4444' }}>{row.breached}</td>
                    <td className="py-3 px-2 font-bold" style={{ color: complianceColor }}>{(row.compliant || 0).toFixed(1)}%</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        )}
      </div>

      {/* ── Top 10 Riskiest Resources ────────────────────────────────────── */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Top 10 Riskiest Resources</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Cloud resources with highest risk scores requiring immediate attention
          </p>
        </div>
        <DataTable data={riskyResources} columns={riskyResourcesColumns} pageSize={10} loading={loading} emptyMessage="No resources found" />
      </div>

      {/* ── Recent Scan Activity ─────────────────────────────────────────── */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Recent Scan Activity</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--text-tertiary)' }}>Last 10 scans across all cloud environments</p>
        </div>
        <DataTable data={activeRecentScans || []} columns={recentScansColumns} pageSize={10} loading={loading} emptyMessage="No recent scans" />
      </div>

      {/* ── 90-Day Security Score Trend ─────────────────────────────────── */}
      <div className="rounded-lg p-6 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>90-Day Security Score Trend</h2>
        <TrendLine data={securityScoreTrendData} dataKeys={['score']} title="" colors={['#10b981']} />
        <div className="mt-4 flex items-center gap-4 text-xs" style={{ color: 'var(--text-secondary)' }}>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: '#10b981' }} />
            <span>Security Score</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
            <span>Major Events Annotated</span>
          </div>
        </div>
      </div>

    </div>
  );
}
