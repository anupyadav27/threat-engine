'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  Activity,
  Zap,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  TrendingUp,
  Users,
  Target,
  Globe,
  CheckCircle,
  UserX,
  Gauge,
  ExternalLink,
  Clock,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { SEVERITY_COLORS } from '@/lib/constants';
import MetricStrip from '@/components/shared/MetricStrip';
import FilterBar from '@/components/shared/FilterBar';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import DataTable from '@/components/shared/DataTable';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';
import SeverityDonut from '@/components/charts/SeverityDonut';
import TrendLine from '@/components/charts/TrendLine';
import BarChartComponent from '@/components/charts/BarChartComponent';


// ── Helpers ────────────────────────────────────────────────────────────────────

/** Format a timestamp to relative time string */
function relativeTime(dateStr) {
  if (!dateStr) return '—';
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  const days = Math.floor(hours / 24);
  if (hours < 1) return 'Just now';
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

/** Cloud provider badge colors */
const PROVIDER_COLORS = {
  AWS: '#f97316',
  Azure: '#3b82f6',
  GCP: '#eab308',
  OCI: '#8b5cf6',
  AliCloud: '#ff6a00',
  IBM: '#1f70c1',
};

/** Risk score progress bar color */
function riskColor(score) {
  if (score >= 85) return '#ef4444';
  if (score >= 70) return '#f97316';
  if (score >= 50) return '#eab308';
  return '#22c55e';
}

/** MITRE cell heat color based on severity and count */
function mitreCellStyle(severity, count) {
  const intensityFactor = Math.min(count / 20, 1);
  const base = severity === 'critical'
    ? { r: 239, g: 68, b: 68 }
    : severity === 'high'
      ? { r: 249, g: 115, b: 22 }
      : { r: 234, g: 179, b: 8 };
  const alpha = 0.08 + intensityFactor * 0.18;
  return {
    backgroundColor: `rgba(${base.r},${base.g},${base.b},${alpha})`,
    borderColor: `rgba(${base.r},${base.g},${base.b},${0.3 + intensityFactor * 0.4})`,
  };
}

/** Status config for threat statuses */
const THREAT_STATUS = {
  active: { dot: '#ef4444', label: 'Active', animation: 'animate-pulse' },
  investigating: { dot: '#f97316', label: 'Investigating', animation: 'animate-pulse' },
  resolved: { dot: '#22c55e', label: 'Resolved', animation: '' },
  suppressed: { dot: '#6b7280', label: 'Suppressed', animation: '' },
  'false-positive': { dot: '#6b7280', label: 'False Positive', animation: '' },
};


// ── Tab definitions ────────────────────────────────────────────────────────────

const TABLE_TABS = [
  { key: 'all', label: 'All' },
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'attackPath', label: 'Has Attack Path' },
  { key: 'unassigned', label: 'Unassigned' },
];


// ── Section wrapper with error boundary per section ────────────────────────────

function Section({ children, error, title }) {
  if (error) {
    return (
      <div
        className="rounded-xl p-6 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
          <div>
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>
              Failed to load {title || 'section'}
            </p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}


// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ThreatsPage() {
  const router = useRouter();
  const { provider, account, region, filterSummary } = useGlobalFilter();

  // ── Data state ────────────────────────────────────────────────────────────
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [kpi, setKpi] = useState(null);
  const [threats, setThreats] = useState([]);
  const [severityChart, setSeverityChart] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [topServices, setTopServices] = useState([]);
  const [mitreMatrix, setMitreMatrix] = useState({});
  const [attackChains, setAttackChains] = useState([]);
  const [threatIntel, setThreatIntel] = useState([]);

  // ── Local UI state ────────────────────────────────────────────────────────
  const [activeFilters, setActiveFilters] = useState({
    severity: '',
    status: '',
    mitreTactic: '',
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('all');
  const [mitreExpanded, setMitreExpanded] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  // ── Fetch data from BFF ───────────────────────────────────────────────────
  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchView('threats', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) {
          setError(data.error);
          return;
        }
        if (data.kpi) setKpi(data.kpi);
        if (data.threats) setThreats(data.threats);
        if (data.severityChart) setSeverityChart(data.severityChart);
        if (data.trendData) setTrendData(data.trendData);
        if (data.topServices) setTopServices(data.topServices);
        if (data.mitreMatrix) setMitreMatrix(data.mitreMatrix);
        if (data.attackChains) setAttackChains(data.attackChains);
        if (data.threatIntel) setThreatIntel(data.threatIntel);
      } catch (err) {
        console.warn('[threats] fetch error:', err);
        setError('Failed to load threats data');
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [provider, account, region]);

  // ── Filter change handler ─────────────────────────────────────────────────
  const handleFilterChange = useCallback((key, value) => {
    setActiveFilters((prev) => ({ ...prev, [key]: value }));
  }, []);

  // ── Computed KPI values (BFF first, local fallback) ───────────────────────
  const stats = useMemo(() => {
    if (kpi) return kpi;
    return {
      total: threats.length,
      critical: threats.filter((t) => t.severity === 'critical').length,
      high: threats.filter((t) => t.severity === 'high').length,
      active: threats.filter((t) => t.status === 'active').length,
      unassigned: threats.filter((t) => !t.assignee).length,
      avgRiskScore: threats.length
        ? Math.round(threats.reduce((s, t) => s + (t.riskScore || 0), 0) / threats.length)
        : 0,
      deltas: {},
    };
  }, [kpi, threats]);

  // ── Severity donut data ───────────────────────────────────────────────────
  const severityDonutData = useMemo(() => {
    if (severityChart && severityChart.length > 0) {
      const obj = { critical: 0, high: 0, medium: 0, low: 0 };
      severityChart.forEach((d) => {
        const key = (d.name || '').toLowerCase();
        if (obj[key] !== undefined) obj[key] = d.value;
      });
      return obj;
    }
    return {
      critical: stats.critical || 0,
      high: stats.high || 0,
      medium: stats.medium || 0,
      low: stats.low || 0,
    };
  }, [severityChart, stats]);

  // ── Top services bar data ─────────────────────────────────────────────────
  const topServicesBarData = useMemo(() => {
    return (topServices || []).slice(0, 5).map((s) => ({
      name: s.name,
      value: s.total || (s.critical + s.high + s.medium),
    }));
  }, [topServices]);

  // ── Dynamic filter options ────────────────────────────────────────────────
  const uniqueTactics = useMemo(
    () =>
      [...new Set(threats.map((t) => t.mitreTactic).filter(Boolean))].sort().map((t) => ({
        value: t,
        label: t,
      })),
    [threats]
  );

  const filterOptions = useMemo(
    () => [
      {
        key: 'severity',
        label: 'All Severities',
        options: ['critical', 'high', 'medium', 'low'].map((s) => ({
          value: s,
          label: s.charAt(0).toUpperCase() + s.slice(1),
        })),
      },
      {
        key: 'status',
        label: 'All Statuses',
        options: ['active', 'investigating', 'resolved', 'false-positive'].map((s) => ({
          value: s,
          label: s.charAt(0).toUpperCase() + s.slice(1).replace('-', ' '),
        })),
      },
      {
        key: 'mitreTactic',
        label: 'All Tactics',
        options: uniqueTactics,
      },
    ],
    [uniqueTactics]
  );

  // ── Filtered + tabbed threats ─────────────────────────────────────────────
  const filteredThreats = useMemo(() => {
    let result = threats;

    // Filter bar filters
    if (activeFilters.severity) {
      result = result.filter((t) => t.severity === activeFilters.severity);
    }
    if (activeFilters.status) {
      result = result.filter((t) => t.status === activeFilters.status);
    }
    if (activeFilters.mitreTactic) {
      result = result.filter((t) => t.mitreTactic === activeFilters.mitreTactic);
    }

    // MITRE technique click filter
    if (selectedTechnique) {
      result = result.filter((t) => t.mitreTechnique === selectedTechnique);
    }

    // Search
    if (searchTerm) {
      const search = searchTerm.toLowerCase();
      result = result.filter(
        (t) =>
          (t.title || '').toLowerCase().includes(search) ||
          (t.mitreTechnique || '').toLowerCase().includes(search) ||
          (t.resourceType || '').toLowerCase().includes(search) ||
          (t.account || '').toLowerCase().includes(search)
      );
    }

    // Tab filter
    switch (activeTab) {
      case 'critical':
        result = result.filter((t) => t.severity === 'critical');
        break;
      case 'high':
        result = result.filter((t) => t.severity === 'high');
        break;
      case 'attackPath':
        result = result.filter((t) => t.hasAttackPath === true);
        break;
      case 'unassigned':
        result = result.filter((t) => !t.assignee);
        break;
    }

    // Default sort: riskScore desc
    return [...result].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
  }, [threats, activeFilters, searchTerm, activeTab, selectedTechnique]);

  // ── Table columns ─────────────────────────────────────────────────────────
  const columns = useMemo(
    () => [
      {
        accessorKey: 'riskScore',
        header: 'Risk',
        size: 100,
        cell: (info) => {
          const score = info.getValue() || 0;
          const color = riskColor(score);
          return (
            <div className="flex items-center gap-2">
              <div
                className="w-14 h-2 rounded-full flex-shrink-0"
                style={{ backgroundColor: 'var(--bg-tertiary)' }}
              >
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${score}%`, backgroundColor: color }}
                />
              </div>
              <span className="text-xs font-bold tabular-nums w-6" style={{ color }}>
                {score}
              </span>
            </div>
          );
        },
      },
      {
        accessorKey: 'title',
        header: 'Threat',
        cell: (info) => {
          const row = info.row.original;
          return (
            <div>
              <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                {info.getValue()}
              </div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                {row.resourceType || ''}
              </div>
              {/* Indicator chips */}
              <div className="flex flex-wrap gap-1.5 mt-1.5">
                {row.mitreTechnique && (
                  <span
                    className="text-[10px] font-semibold px-1.5 py-0.5 rounded"
                    style={{
                      backgroundColor: 'rgba(59,130,246,0.12)',
                      color: '#60a5fa',
                    }}
                  >
                    {row.mitreTechnique}
                    {row.mitreTactic ? ` · ${row.mitreTactic}` : ''}
                  </span>
                )}
                {row.isInternetExposed && (
                  <span
                    className="inline-flex items-center gap-0.5 text-[10px] font-semibold px-1.5 py-0.5 rounded"
                    style={{
                      backgroundColor: 'rgba(59,130,246,0.12)',
                      color: '#60a5fa',
                    }}
                  >
                    <Globe className="w-2.5 h-2.5" /> Internet Exposed
                  </span>
                )}
                {row.hasAttackPath && (
                  <span
                    className="inline-flex items-center gap-0.5 text-[10px] font-semibold px-1.5 py-0.5 rounded"
                    style={{
                      backgroundColor: 'rgba(249,115,22,0.12)',
                      color: '#f97316',
                    }}
                  >
                    <Zap className="w-2.5 h-2.5" /> Attack Path
                  </span>
                )}
                {row.remediationSteps && row.remediationSteps.length > 0 && (
                  <span
                    className="inline-flex items-center gap-0.5 text-[10px] font-semibold px-1.5 py-0.5 rounded"
                    style={{
                      backgroundColor: 'rgba(34,197,94,0.12)',
                      color: '#22c55e',
                    }}
                  >
                    <CheckCircle className="w-2.5 h-2.5" /> Auto-Fix
                  </span>
                )}
              </div>
            </div>
          );
        },
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        size: 100,
        cell: (info) => <SeverityBadge severity={info.getValue()} />,
      },
      {
        accessorKey: 'affectedResources',
        header: 'Resources',
        size: 90,
        cell: (info) => (
          <span className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
            {info.getValue() || 0}
          </span>
        ),
      },
      {
        accessorKey: 'provider',
        header: 'Provider',
        size: 95,
        cell: (info) => {
          const p = info.getValue();
          const color = PROVIDER_COLORS[p] || '#6b7280';
          return (
            <span
              className="text-xs font-semibold px-2 py-0.5 rounded-full whitespace-nowrap"
              style={{ backgroundColor: `${color}20`, color }}
            >
              {p}
            </span>
          );
        },
      },
      {
        accessorKey: 'account',
        header: 'Account',
        size: 120,
        cell: (info) => (
          <span
            className="text-xs font-mono whitespace-nowrap"
            style={{ color: 'var(--text-tertiary)' }}
          >
            {info.getValue() || '—'}
          </span>
        ),
      },
      {
        accessorKey: 'status',
        header: 'Status',
        size: 120,
        cell: (info) => {
          const val = (info.getValue() || 'active').toLowerCase();
          const cfg = THREAT_STATUS[val] || THREAT_STATUS.active;
          return (
            <div className="flex items-center gap-2">
              <div
                className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.animation}`}
                style={{ backgroundColor: cfg.dot }}
              />
              <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                {cfg.label}
              </span>
            </div>
          );
        },
      },
      {
        accessorKey: 'detected',
        header: 'Detected',
        size: 95,
        cell: (info) => (
          <span className="text-xs whitespace-nowrap" style={{ color: 'var(--text-tertiary)' }}>
            {relativeTime(info.getValue())}
          </span>
        ),
      },
      {
        accessorKey: 'assignee',
        header: 'Assignee',
        size: 110,
        cell: (info) => {
          const val = info.getValue();
          if (val) {
            return (
              <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                {val}
              </span>
            );
          }
          return (
            <span className="text-xs font-medium" style={{ color: '#f97316' }}>
              Unassigned
            </span>
          );
        },
      },
    ],
    []
  );

  // ── Tab counts ────────────────────────────────────────────────────────────
  const tabCounts = useMemo(() => {
    // Apply same filter+search but NOT tab filter
    let base = threats;
    if (activeFilters.severity)
      base = base.filter((t) => t.severity === activeFilters.severity);
    if (activeFilters.status)
      base = base.filter((t) => t.status === activeFilters.status);
    if (activeFilters.mitreTactic)
      base = base.filter((t) => t.mitreTactic === activeFilters.mitreTactic);
    if (selectedTechnique)
      base = base.filter((t) => t.mitreTechnique === selectedTechnique);
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      base = base.filter(
        (t) =>
          (t.title || '').toLowerCase().includes(s) ||
          (t.mitreTechnique || '').toLowerCase().includes(s)
      );
    }
    return {
      all: base.length,
      critical: base.filter((t) => t.severity === 'critical').length,
      high: base.filter((t) => t.severity === 'high').length,
      attackPath: base.filter((t) => t.hasAttackPath === true).length,
      unassigned: base.filter((t) => !t.assignee).length,
    };
  }, [threats, activeFilters, searchTerm, selectedTechnique]);

  // ── Loading state ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="space-y-6">
        {/* Header skeleton */}
        <div className="space-y-2">
          <div className="h-8 w-64 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-4 w-96 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        </div>
        {/* KPI skeleton */}
        <div className="grid grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="h-24 rounded-xl animate-pulse"
              style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}
            />
          ))}
        </div>
        {/* Charts skeleton */}
        <div className="grid grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-80 rounded-xl animate-pulse"
              style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}
            />
          ))}
        </div>
        {/* Table skeleton */}
        <LoadingSkeleton rows={8} cols={6} />
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      {/* ── Error Banner ──────────────────────────────────────────────────── */}
      {error && (
        <div
          className="rounded-lg p-4 border flex items-center gap-3"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: '#ef4444' }}
        >
          <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
          <div>
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>
              Failed to load threats data
            </p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
              {error}
            </p>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* BLOCK 1: HEADER                                                    */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Threats
          </h1>
          <p className="mt-1" style={{ color: 'var(--text-secondary)' }}>
            Contextualized risk scenarios with MITRE ATT&CK mapping and attack path analysis
          </p>
          {filterSummary && (
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
              <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>
                {filterSummary}
              </span>
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => router.push('/threats/attack-paths')}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
            style={{
              backgroundColor: 'var(--bg-secondary)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-primary)',
            }}
          >
            <Zap className="w-4 h-4" /> Attack Paths
          </button>
          <button
            onClick={() => router.push('/threats/internet-exposed')}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
            style={{
              backgroundColor: 'var(--bg-secondary)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-primary)',
            }}
          >
            <Globe className="w-4 h-4" /> Internet Exposed
          </button>
          <button
            onClick={() => router.push('/threats/analytics')}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
            style={{
              backgroundColor: 'var(--bg-secondary)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-primary)',
            }}
          >
            <TrendingUp className="w-4 h-4" /> Analytics
          </button>
        </div>
      </div>

      {/* Threats Sub-Navigation */}
      <ThreatsSubNav />

      {/* Filter Bar */}
      <FilterBar
        filters={filterOptions}
        activeFilters={activeFilters}
        onFilterChange={handleFilterChange}
      />

      {/* Technique filter indicator */}
      {selectedTechnique && (
        <div
          className="flex items-center gap-2 px-4 py-2 rounded-lg border"
          style={{
            backgroundColor: 'rgba(59,130,246,0.08)',
            borderColor: 'rgba(59,130,246,0.3)',
          }}
        >
          <Target className="w-4 h-4" style={{ color: '#60a5fa' }} />
          <span className="text-sm" style={{ color: '#60a5fa' }}>
            Filtered by MITRE technique:{' '}
            <strong>{selectedTechnique}</strong>
          </span>
          <button
            onClick={() => setSelectedTechnique(null)}
            className="ml-auto text-xs font-medium px-2 py-1 rounded hover:opacity-75 transition-opacity"
            style={{ color: '#60a5fa' }}
          >
            Clear
          </button>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* BLOCK 2: KPI STRIP                                                 */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <Section title="KPI metrics">
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            {
              label: 'Total Threats',
              value: stats.total ?? 0,
              icon: <Shield className="w-5 h-5" />,
              color: '#3b82f6',
              delta: stats.deltas?.total,
            },
            {
              label: 'Critical',
              value: stats.critical ?? 0,
              icon: <ShieldAlert className="w-5 h-5" />,
              color: '#ef4444',
              delta: stats.deltas?.critical,
            },
            {
              label: 'High',
              value: stats.high ?? 0,
              icon: <AlertTriangle className="w-5 h-5" />,
              color: '#f97316',
              delta: stats.deltas?.high,
            },
            {
              label: 'Active',
              value: stats.active ?? 0,
              icon: <Activity className="w-5 h-5" />,
              color: '#eab308',
              delta: stats.deltas?.active,
            },
            {
              label: 'Unassigned',
              value: stats.unassigned ?? 0,
              icon: <UserX className="w-5 h-5" />,
              color: '#f97316',
              delta: stats.deltas?.unassigned,
            },
            {
              label: 'Avg Risk Score',
              value: stats.avgRiskScore ?? 0,
              icon: <Gauge className="w-5 h-5" />,
              color: riskColor(stats.avgRiskScore || 0),
              delta: stats.deltas?.avgRiskScore,
            },
          ].map((card) => {
            const delta = card.delta;
            const hasDelta = delta && delta.value != null;
            return (
              <div
                key={card.label}
                className="rounded-xl p-4 border transition-colors duration-200"
                style={{
                  backgroundColor: 'var(--bg-card)',
                  borderColor: 'var(--border-primary)',
                  borderTopWidth: 3,
                  borderTopColor: card.color,
                }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <div
                    className="p-1.5 rounded-lg"
                    style={{ backgroundColor: `${card.color}18` }}
                  >
                    <span style={{ color: card.color }}>{card.icon}</span>
                  </div>
                  <span
                    className="text-xs font-semibold uppercase tracking-wide"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    {card.label}
                  </span>
                </div>
                <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
                  {typeof card.value === 'number' ? card.value.toLocaleString() : card.value}
                </p>
                {hasDelta && (
                  <div className="flex items-center gap-1 mt-1">
                    {delta.direction === 'up' ? (
                      <TrendingUp
                        className="w-3 h-3"
                        style={{
                          color:
                            card.label === 'Avg Risk Score'
                              ? '#ef4444'
                              : card.label === 'Unassigned' || card.label === 'Critical'
                                ? '#ef4444'
                                : '#22c55e',
                        }}
                      />
                    ) : (
                      <ChevronDown
                        className="w-3 h-3"
                        style={{
                          color:
                            card.label === 'Active' || card.label === 'Critical'
                              ? '#22c55e'
                              : '#ef4444',
                        }}
                      />
                    )}
                    <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                      {delta.direction === 'up' ? '+' : ''}
                      {delta.value}
                      {delta.type === 'percent' ? '%' : ''}
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Section>

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* BLOCK 3: CHARTS ROW (3 columns)                                    */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity Donut */}
        <Section title="severity chart">
          {severityDonutData.critical + severityDonutData.high + severityDonutData.medium + severityDonutData.low > 0 ? (
            <SeverityDonut data={severityDonutData} title="Severity Distribution" />
          ) : (
            <div
              className="rounded-xl p-4 border flex items-center justify-center h-80"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-primary)',
              }}
            >
              <EmptyState
                icon={<Shield className="w-12 h-12" />}
                title="No severity data"
                description="Severity distribution will appear once threats are detected."
              />
            </div>
          )}
        </Section>

        {/* 30-Day Trend */}
        <Section title="trend chart">
          {trendData.length > 0 ? (
            <TrendLine
              data={trendData}
              dataKeys={['critical', 'high', 'medium', 'low']}
              colors={['#ef4444', '#f97316', '#eab308', '#3b82f6']}
              title="30-Day Threat Trend"
            />
          ) : (
            <div
              className="rounded-xl p-4 border flex items-center justify-center h-80"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-primary)',
              }}
            >
              <EmptyState
                icon={<Activity className="w-12 h-12" />}
                title="No trend data"
                description="Trend data appears after multiple scans have been completed."
              />
            </div>
          )}
        </Section>

        {/* Top Affected Services */}
        <Section title="top services chart">
          {topServicesBarData.length > 0 ? (
            <BarChartComponent
              data={topServicesBarData}
              color="#f97316"
              title="Top Affected Services"
              horizontal
            />
          ) : (
            <div
              className="rounded-xl p-4 border flex items-center justify-center h-80"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-primary)',
              }}
            >
              <EmptyState
                icon={<Target className="w-12 h-12" />}
                title="No service data"
                description="Service breakdown will appear once threats are mapped to cloud services."
              />
            </div>
          )}
        </Section>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* BLOCK 4: MITRE ATT&CK MATRIX (collapsible)                        */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <Section title="MITRE ATT&CK matrix">
        <div
          className="rounded-xl border transition-colors duration-200"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          {/* Collapsible header */}
          <button
            onClick={() => setMitreExpanded((v) => !v)}
            className="w-full flex items-center justify-between p-5 text-left"
          >
            <div className="flex items-center gap-3">
              <Target className="w-5 h-5" style={{ color: 'var(--accent-primary)' }} />
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                MITRE ATT&CK Coverage
              </h2>
              <span
                className="text-xs px-2 py-0.5 rounded-full font-medium"
                style={{
                  backgroundColor: 'rgba(59,130,246,0.12)',
                  color: '#60a5fa',
                }}
              >
                {Object.keys(mitreMatrix).length} tactics
              </span>
            </div>
            {mitreExpanded ? (
              <ChevronUp className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
            ) : (
              <ChevronDown className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
            )}
          </button>

          {/* Matrix content */}
          {mitreExpanded && (
            <div className="px-5 pb-5">
              {Object.keys(mitreMatrix).length === 0 ? (
                <EmptyState
                  icon={<Target className="w-12 h-12" />}
                  title="No MITRE ATT&CK data"
                  description="MITRE technique mappings will appear once the threat engine detects relevant activity."
                />
              ) : (
                <div className="overflow-x-auto">
                  <div
                    className="grid gap-3"
                    style={{
                      gridTemplateColumns: `repeat(${Object.keys(mitreMatrix).length}, minmax(160px, 1fr))`,
                    }}
                  >
                    {Object.entries(mitreMatrix).map(([tactic, techniques]) => (
                      <div key={tactic}>
                        {/* Tactic header */}
                        <p
                          className="text-[10px] font-bold uppercase tracking-wider mb-2 px-1"
                          style={{ color: 'var(--text-muted)' }}
                        >
                          {tactic}
                        </p>
                        {/* Technique cells */}
                        <div className="space-y-2">
                          {(techniques || []).map((tech) => {
                            const isSelected = selectedTechnique === tech.id;
                            const cellStyles = mitreCellStyle(
                              tech.severity || 'medium',
                              tech.count || 0
                            );
                            return (
                              <div
                                key={tech.id}
                                onClick={() =>
                                  setSelectedTechnique(isSelected ? null : tech.id)
                                }
                                className="p-2.5 rounded-lg border cursor-pointer transition-all hover:scale-[1.02]"
                                style={{
                                  ...cellStyles,
                                  borderWidth: isSelected ? 2 : 1,
                                  ...(isSelected && {
                                    borderColor: 'var(--accent-primary)',
                                    boxShadow: '0 0 0 2px rgba(59,130,246,0.2)',
                                  }),
                                }}
                              >
                                <p
                                  className="font-mono text-xs font-bold"
                                  style={{ color: 'var(--accent-primary)' }}
                                >
                                  {tech.id}
                                </p>
                                <p
                                  className="text-xs mt-0.5 line-clamp-2"
                                  style={{ color: 'var(--text-secondary)' }}
                                >
                                  {tech.name}
                                </p>
                                {/* Heat bar */}
                                <div className="flex items-center gap-2 mt-1.5">
                                  <div
                                    className="flex-1 h-1.5 rounded-full"
                                    style={{ backgroundColor: 'var(--bg-tertiary)' }}
                                  >
                                    <div
                                      className="h-full rounded-full"
                                      style={{
                                        width: `${Math.min((tech.count / 20) * 100, 100)}%`,
                                        backgroundColor:
                                          SEVERITY_COLORS[tech.severity] || '#eab308',
                                      }}
                                    />
                                  </div>
                                  <span
                                    className="text-[10px] font-bold tabular-nums"
                                    style={{
                                      color: SEVERITY_COLORS[tech.severity] || '#eab308',
                                    }}
                                  >
                                    {tech.count}
                                  </span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </Section>

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* BLOCK 5: THREATS TABLE                                             */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <div
        className="rounded-xl border transition-colors duration-200"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        {/* Tab bar */}
        <div
          className="flex items-center gap-1 px-5 pt-4 pb-0 border-b overflow-x-auto"
          style={{ borderColor: 'var(--border-primary)' }}
        >
          {TABLE_TABS.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className="px-4 py-2.5 text-sm font-medium whitespace-nowrap transition-colors relative"
              style={{
                color:
                  activeTab === tab.key
                    ? 'var(--accent-primary)'
                    : 'var(--text-muted)',
              }}
            >
              {tab.label}
              <span
                className="ml-1.5 text-xs tabular-nums"
                style={{ color: 'var(--text-tertiary)' }}
              >
                ({tabCounts[tab.key] ?? 0})
              </span>
              {activeTab === tab.key && (
                <div
                  className="absolute bottom-0 left-0 right-0 h-0.5 rounded-full"
                  style={{ backgroundColor: 'var(--accent-primary)' }}
                />
              )}
            </button>
          ))}
        </div>

        {/* Table content */}
        <div className="p-5">
          <DataTable
            data={filteredThreats}
            columns={columns}
            pageSize={25}
            onRowClick={(threat) => router.push(`/threats/${threat.id}`)}
            loading={false}
            emptyMessage="No threats match the selected filters"
          />
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* BLOCK 6: SECONDARY PANELS (2 columns)                              */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Attack Chains */}
        <Section title="attack chains">
          <div
            className="rounded-xl p-6 border transition-colors duration-200"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                Top Attack Chains
              </h2>
              <button
                onClick={() => router.push('/threats/attack-paths')}
                className="text-xs font-medium flex items-center gap-1 hover:opacity-75 transition-opacity"
                style={{ color: 'var(--accent-primary)' }}
              >
                View All <ExternalLink className="w-3 h-3" />
              </button>
            </div>
            {attackChains.length === 0 ? (
              <EmptyState
                icon={<Zap className="w-12 h-12" />}
                title="No attack chains"
                description="Attack chain analysis will appear once multi-hop threat paths are identified."
              />
            ) : (
              <div className="space-y-3">
                {attackChains.slice(0, 5).map((chain, idx) => (
                  <div
                    key={chain.id || idx}
                    className="rounded-lg p-4 border cursor-pointer transition-all hover:opacity-80"
                    style={{
                      backgroundColor: 'var(--bg-secondary)',
                      borderColor: 'var(--border-primary)',
                    }}
                    onClick={() => router.push(`/threats/attack-paths?chain=${chain.id}`)}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1.5">
                          <SeverityBadge severity={chain.severity} />
                          <span
                            className="text-xs font-medium px-1.5 py-0.5 rounded"
                            style={{
                              backgroundColor: 'var(--bg-tertiary)',
                              color: 'var(--text-tertiary)',
                            }}
                          >
                            {chain.hops} hops
                          </span>
                        </div>
                        <h3
                          className="text-sm font-semibold truncate"
                          style={{ color: 'var(--text-primary)' }}
                        >
                          {chain.name}
                        </h3>
                        <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                          {chain.provider} · {chain.account} ·{' '}
                          {chain.detectionTime
                            ? relativeTime(chain.detectionTime)
                            : '—'}
                        </p>
                        {chain.techniques && chain.techniques.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {chain.techniques.map((tech) => (
                              <code
                                key={tech}
                                className="text-[10px] px-1.5 py-0.5 rounded"
                                style={{
                                  backgroundColor: 'var(--bg-tertiary)',
                                  color: 'var(--accent-primary)',
                                }}
                              >
                                {tech}
                              </code>
                            ))}
                          </div>
                        )}
                      </div>
                      {/* Blast radius indicator */}
                      <div className="flex flex-col items-center flex-shrink-0">
                        <div
                          className="w-10 h-10 flex items-center justify-center rounded-full"
                          style={{
                            border: `2px solid ${
                              chain.severity === 'critical' ? '#ef4444' : '#f97316'
                            }`,
                          }}
                        >
                          <span
                            className="text-sm font-bold"
                            style={{
                              color:
                                chain.severity === 'critical' ? '#ef4444' : '#f97316',
                            }}
                          >
                            {chain.affectedResources}
                          </span>
                        </div>
                        <span
                          className="text-[10px] mt-0.5"
                          style={{ color: 'var(--text-muted)' }}
                        >
                          resources
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Section>

        {/* Threat Intelligence */}
        <Section title="threat intelligence">
          <div
            className="rounded-xl p-6 border transition-colors duration-200"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                Threat Intelligence
              </h2>
              <button
                onClick={() => router.push('/threats/hunting')}
                className="text-xs font-medium flex items-center gap-1 hover:opacity-75 transition-opacity"
                style={{ color: 'var(--accent-primary)' }}
              >
                View All <ExternalLink className="w-3 h-3" />
              </button>
            </div>
            {threatIntel.length === 0 ? (
              <EmptyState
                icon={<Shield className="w-12 h-12" />}
                title="No threat intelligence"
                description="Intelligence feeds will appear once external threat data is correlated with your environment."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr
                      className="border-b"
                      style={{ borderColor: 'var(--border-primary)' }}
                    >
                      {['Source', 'Indicator', 'Type', 'Relevance', 'Matches'].map(
                        (h) => (
                          <th
                            key={h}
                            className="text-left py-2.5 px-3 text-[10px] font-bold uppercase tracking-wider"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            {h}
                          </th>
                        )
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {threatIntel.slice(0, 10).map((intel, idx) => (
                      <tr
                        key={idx}
                        className="border-b last:border-b-0"
                        style={{
                          borderColor: 'var(--border-primary)',
                          backgroundColor:
                            idx % 2 === 0 ? 'var(--bg-secondary)' : 'transparent',
                        }}
                      >
                        <td
                          className="py-2.5 px-3 text-xs"
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          {intel.source}
                        </td>
                        <td className="py-2.5 px-3">
                          <code
                            className="text-xs px-1.5 py-0.5 rounded"
                            style={{
                              backgroundColor: 'var(--bg-tertiary)',
                              color: 'var(--accent-primary)',
                            }}
                          >
                            {intel.indicator}
                          </code>
                        </td>
                        <td
                          className="py-2.5 px-3 text-xs"
                          style={{ color: 'var(--text-tertiary)' }}
                        >
                          {intel.type}
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="flex items-center gap-2">
                            <div
                              className="w-12 h-1.5 rounded-full"
                              style={{ backgroundColor: 'var(--bg-tertiary)' }}
                            >
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${intel.relevance || 0}%`,
                                  backgroundColor:
                                    (intel.relevance || 0) >= 80
                                      ? '#ef4444'
                                      : (intel.relevance || 0) >= 60
                                        ? '#f97316'
                                        : '#22c55e',
                                }}
                              />
                            </div>
                            <span
                              className="text-[10px] font-bold tabular-nums"
                              style={{ color: 'var(--text-secondary)' }}
                            >
                              {intel.relevance}%
                            </span>
                          </div>
                        </td>
                        <td
                          className="py-2.5 px-3 text-xs font-semibold"
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          {intel.matchedAssets}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Section>
      </div>
    </div>
  );
}
