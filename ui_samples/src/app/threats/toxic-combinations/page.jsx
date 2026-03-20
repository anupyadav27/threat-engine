'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useRouter, useSearchParams, usePathname } from 'next/navigation';
import {
  Zap,
  AlertTriangle,
  Target,
  TrendingUp,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  X,
  Shield,
  ExternalLink,
  Layers,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import DataTable from '@/components/shared/DataTable';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TAB_COMBINATIONS = 'combinations';
const TAB_MATRIX = 'matrix';

const SEVERITY_FOR_SCORE = (score) => {
  if (score >= 90) return 'critical';
  if (score >= 75) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Segmented toxicity score bar */
function ToxicityBar({ score }) {
  const segments = 10;
  const filled = Math.round((score / 100) * segments);
  const color =
    score >= 90 ? '#ef4444' : score >= 75 ? '#f97316' : score >= 50 ? '#eab308' : '#3b82f6';

  return (
    <div className="flex items-center gap-2">
      <div className="flex gap-0.5">
        {Array.from({ length: segments }).map((_, i) => (
          <div
            key={i}
            className="h-2.5 w-2 rounded-sm"
            style={{
              backgroundColor: i < filled ? color : 'var(--bg-tertiary)',
            }}
          />
        ))}
      </div>
      <span className="text-sm font-bold tabular-nums" style={{ color }}>
        {score}/100
      </span>
    </div>
  );
}

/** Factor pill badges */
function FactorPills({ factors }) {
  if (!factors || factors.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {factors.map((f, i) => {
        const sev = f.severity || 'high';
        const bgMap = {
          critical: 'rgba(239,68,68,0.15)',
          high: 'rgba(249,115,22,0.15)',
          medium: 'rgba(234,179,8,0.15)',
          low: 'rgba(59,130,246,0.15)',
        };
        const textMap = {
          critical: '#fca5a5',
          high: '#fdba74',
          medium: '#fde047',
          low: '#93c5fd',
        };
        const borderMap = {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
        };
        return (
          <span
            key={i}
            className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg"
            style={{
              backgroundColor: bgMap[sev] || bgMap.high,
              color: textMap[sev] || textMap.high,
              borderLeft: `3px solid ${borderMap[sev] || borderMap.high}`,
            }}
          >
            {f.name || f}
          </span>
        );
      })}
    </div>
  );
}

/** Combination card with expand/collapse */
function CombinationCard({ combo, isExpanded, onToggle }) {
  const severity = SEVERITY_FOR_SCORE(combo.toxicityScore ?? combo.toxicity_score ?? 0);
  const toxScore = combo.toxicityScore ?? combo.toxicity_score ?? 0;
  const multiplier = combo.riskMultiplier ?? combo.risk_multiplier ?? 1;
  const factors = combo.factors ?? [];
  const resourceName = combo.resourceName ?? combo.resource_name ?? 'Unknown';
  const resourceType = combo.resourceType ?? combo.resource_type ?? '';
  const provider = combo.provider ?? combo.csp ?? 'AWS';
  const affectedCount = combo.affectedResources ?? combo.affected_resources ?? 0;
  const techniques = combo.techniquesMapped ?? combo.techniques ?? [];
  const actions = combo.priorityActions ?? combo.remediation_actions ?? [];
  const resources = combo.resources ?? [];
  const exposure = combo.estimatedExposure ?? combo.estimated_exposure ?? 0;

  const resourceColumns = useMemo(
    () => [
      { accessorKey: 'name', header: 'Resource', size: 200 },
      { accessorKey: 'type', header: 'Type', size: 140 },
      { accessorKey: 'region', header: 'Region', size: 120 },
      {
        accessorKey: 'risk_score',
        header: 'Risk',
        size: 80,
        cell: ({ getValue }) => {
          const v = getValue();
          const c = v >= 80 ? '#ef4444' : v >= 60 ? '#f97316' : '#eab308';
          return <span className="font-bold" style={{ color: c }}>{v}</span>;
        },
      },
    ],
    []
  );

  return (
    <div
      className="rounded-xl border transition-all duration-200"
      style={{
        backgroundColor: 'var(--bg-card)',
        borderColor: severity === 'critical' ? 'rgba(239,68,68,0.4)' : 'var(--border-primary)',
        borderLeftWidth: severity === 'critical' ? '4px' : '1px',
        borderLeftColor: severity === 'critical' ? '#ef4444' : undefined,
      }}
    >
      {/* Collapsed header -- always visible */}
      <button
        onClick={onToggle}
        className="w-full text-left p-5 focus:outline-none"
      >
        <div className="flex items-start justify-between gap-4">
          {/* Left: severity + name + factors */}
          <div className="flex-1 min-w-0 space-y-3">
            <div className="flex items-center gap-3 flex-wrap">
              <SeverityBadge severity={severity} />
              <h3
                className="text-base font-semibold truncate"
                style={{ color: 'var(--text-primary)' }}
              >
                {resourceName}
              </h3>
              {resourceType && (
                <span
                  className="text-xs px-2.5 py-0.5 rounded-full"
                  style={{
                    backgroundColor: 'var(--bg-secondary)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {resourceType}
                </span>
              )}
              <span
                className="text-xs px-2.5 py-0.5 rounded-full font-medium"
                style={{
                  backgroundColor:
                    provider.toUpperCase() === 'AWS'
                      ? 'rgba(255,153,0,0.12)'
                      : 'rgba(0,120,212,0.12)',
                  color:
                    provider.toUpperCase() === 'AWS' ? '#FF9900' : '#0078D4',
                }}
              >
                {provider.toUpperCase()}
              </span>
            </div>

            {/* Toxicity bar + multiplier */}
            <div className="flex items-center gap-6">
              <div className="space-y-1">
                <p
                  className="text-[10px] font-semibold uppercase tracking-wider"
                  style={{ color: 'var(--text-muted)' }}
                >
                  Toxicity
                </p>
                <ToxicityBar score={toxScore} />
              </div>
              <div className="space-y-1 text-center">
                <p
                  className="text-[10px] font-semibold uppercase tracking-wider"
                  style={{ color: 'var(--text-muted)' }}
                >
                  Multiplier
                </p>
                <p
                  className="text-lg font-bold"
                  style={{ color: '#f97316' }}
                >
                  x{multiplier}
                </p>
              </div>
            </div>

            {/* Factor pills */}
            <FactorPills factors={factors} />
          </div>

          {/* Right: affected + chevron */}
          <div className="flex items-center gap-3 flex-shrink-0 pt-1">
            {affectedCount > 0 && (
              <div className="text-right">
                <p
                  className="text-xs"
                  style={{ color: 'var(--text-muted)' }}
                >
                  Resources
                </p>
                <p
                  className="text-lg font-bold"
                  style={{ color: 'var(--text-primary)' }}
                >
                  {affectedCount}
                </p>
              </div>
            )}
            {isExpanded ? (
              <ChevronUp
                className="w-5 h-5"
                style={{ color: 'var(--text-muted)' }}
              />
            ) : (
              <ChevronDown
                className="w-5 h-5"
                style={{ color: 'var(--text-muted)' }}
              />
            )}
          </div>
        </div>
      </button>

      {/* Expanded detail */}
      {isExpanded && (
        <div
          className="px-5 pb-5 space-y-4 border-t"
          style={{ borderColor: 'var(--border-primary)' }}
        >
          {/* MITRE techniques */}
          {techniques.length > 0 && (
            <div className="pt-4">
              <p
                className="text-[10px] font-semibold uppercase tracking-wider mb-2"
                style={{ color: 'var(--text-muted)' }}
              >
                MITRE ATT&CK Techniques
              </p>
              <div className="flex flex-wrap gap-2">
                {techniques.map((t) => (
                  <code
                    key={t}
                    className="text-xs px-2 py-1 rounded font-mono"
                    style={{
                      backgroundColor: 'rgba(239,68,68,0.1)',
                      color: '#ef4444',
                      border: '1px solid rgba(239,68,68,0.2)',
                    }}
                  >
                    {t}
                  </code>
                ))}
              </div>
            </div>
          )}

          {/* Remediation actions */}
          {actions.length > 0 && (
            <div>
              <p
                className="text-[10px] font-semibold uppercase tracking-wider mb-2"
                style={{ color: 'var(--text-muted)' }}
              >
                Remediation Priority
              </p>
              <ol className="space-y-1.5">
                {actions.map((action, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-2 text-sm"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <span
                      className="flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold mt-0.5"
                      style={{
                        backgroundColor: 'rgba(59,130,246,0.15)',
                        color: '#3b82f6',
                      }}
                    >
                      {i + 1}
                    </span>
                    {action}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Affected resources table */}
          {resources.length > 0 && (
            <div>
              <p
                className="text-[10px] font-semibold uppercase tracking-wider mb-2"
                style={{ color: 'var(--text-muted)' }}
              >
                Affected Resources
              </p>
              <DataTable
                data={resources}
                columns={resourceColumns}
                pageSize={5}
                emptyMessage="No resource details available"
              />
            </div>
          )}

          {/* Estimated exposure */}
          {exposure > 0 && (
            <div
              className="flex items-center justify-between p-3 rounded-lg"
              style={{ backgroundColor: 'rgba(239,68,68,0.08)' }}
            >
              <span
                className="text-xs font-semibold"
                style={{ color: 'var(--text-secondary)' }}
              >
                Estimated Records at Risk
              </span>
              <span className="text-base font-bold" style={{ color: '#ef4444' }}>
                {exposure.toLocaleString()}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Heatmap co-occurrence matrix */
function CoOccurrenceMatrix({ matrixData, categories, onCellClick }) {
  // Compute max value for intensity normalization
  const maxCount = useMemo(() => {
    if (!matrixData || !categories) return 1;
    let max = 1;
    categories.forEach((row) => {
      categories.forEach((col) => {
        const v = matrixData?.[row]?.[col] ?? 0;
        if (v > max) max = v;
      });
    });
    return max;
  }, [matrixData, categories]);

  if (!categories || categories.length === 0) {
    return (
      <EmptyState
        icon={<Layers className="w-12 h-12" />}
        title="No Matrix Data"
        description="Co-occurrence matrix will appear once toxic combinations are detected."
      />
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs border-collapse">
        <thead>
          <tr>
            <th
              className="text-left py-3 px-3 sticky left-0 z-10"
              style={{
                color: 'var(--text-muted)',
                backgroundColor: 'var(--bg-card)',
              }}
            />
            {categories.map((cat) => (
              <th
                key={cat}
                className="text-center py-3 px-2"
                style={{ color: 'var(--text-muted)' }}
              >
                <div
                  className="h-20 flex items-end justify-center"
                  style={{ writingMode: 'vertical-rl', textOrientation: 'mixed' }}
                >
                  <span className="whitespace-nowrap text-[10px] font-medium transform rotate-180">
                    {cat}
                  </span>
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {categories.map((rowCat, ri) => (
            <tr key={rowCat}>
              <td
                className="py-2.5 px-3 text-xs font-medium whitespace-nowrap sticky left-0 z-10"
                style={{
                  color: 'var(--text-secondary)',
                  backgroundColor: 'var(--bg-card)',
                }}
              >
                {rowCat}
              </td>
              {categories.map((colCat, ci) => {
                const isDiag = ri === ci;
                const value = matrixData?.[rowCat]?.[colCat] ?? 0;
                const intensity = isDiag ? 0 : value / maxCount;

                return (
                  <td
                    key={colCat}
                    className="py-2.5 px-2 text-center transition-transform duration-100"
                    onClick={() => {
                      if (!isDiag && value > 0) {
                        onCellClick?.({ row: rowCat, col: colCat, count: value });
                      }
                    }}
                    title={
                      isDiag
                        ? rowCat
                        : `${value} resources have both "${rowCat}" and "${colCat}"`
                    }
                    style={{
                      backgroundColor: isDiag
                        ? 'var(--bg-tertiary)'
                        : `rgba(239, 68, 68, ${Math.max(intensity * 0.85, 0.03)})`,
                      color:
                        isDiag
                          ? 'var(--text-muted)'
                          : intensity > 0.5
                          ? '#fff'
                          : 'var(--text-secondary)',
                      cursor: isDiag || value === 0 ? 'default' : 'pointer',
                    }}
                  >
                    <span className="font-semibold tabular-nums">
                      {isDiag ? '-' : value}
                    </span>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Modal/drawer for matrix cell detail */
function MatrixCellDetail({ cell, onClose }) {
  if (!cell) return null;
  return (
    <div
      className="mt-4 p-4 rounded-lg border animate-in fade-in duration-200"
      style={{
        backgroundColor: 'var(--bg-secondary)',
        borderColor: 'rgba(239,68,68,0.3)',
      }}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            {cell.row} + {cell.col}
          </p>
          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
            <span className="font-bold">{cell.count}</span> resources have both conditions
          </p>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:opacity-70 transition-opacity"
          style={{ color: 'var(--text-muted)' }}
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Example resources from BFF if available */}
      {cell.examples && cell.examples.length > 0 && (
        <div className="space-y-2">
          {cell.examples.map((ex, i) => (
            <div
              key={i}
              className="flex items-center justify-between p-2 rounded text-xs"
              style={{ backgroundColor: 'var(--bg-tertiary)' }}
            >
              <span style={{ color: 'var(--text-primary)' }}>
                {ex.name || ex.resource_name || ex.uid}
              </span>
              <span style={{ color: 'var(--text-muted)' }}>
                {ex.type || ex.resource_type}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page skeleton
// ---------------------------------------------------------------------------

function PageSkeleton() {
  return (
    <div className="space-y-6">
      {/* KPI strip */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="rounded-xl p-6 border animate-pulse"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <div
              className="h-4 w-24 rounded mb-4"
              style={{ backgroundColor: 'var(--bg-tertiary)' }}
            />
            <div
              className="h-8 w-16 rounded mb-2"
              style={{ backgroundColor: 'var(--bg-tertiary)' }}
            />
            <div
              className="h-3 w-20 rounded"
              style={{ backgroundColor: 'var(--bg-tertiary)' }}
            />
          </div>
        ))}
      </div>
      <LoadingSkeleton rows={4} cols={3} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------

export default function ToxicCombinationsPage() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // Tab state from URL
  const activeTab = searchParams.get('tab') || TAB_COMBINATIONS;

  const setActiveTab = useCallback(
    (tab) => {
      const params = new URLSearchParams(searchParams.toString());
      params.set('tab', tab);
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [router, pathname, searchParams]
  );

  // Data state
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);

  // UI state
  const [expandedCards, setExpandedCards] = useState(new Set());
  const [selectedCell, setSelectedCell] = useState(null);

  // Fetch BFF data
  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);

      const result = await fetchView('threats/toxic-combinations');

      if (cancelled) return;

      if (result?.error) {
        setError(result.error);
      } else {
        setData(result);
      }
      setLoading(false);
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  // Derived data
  const kpi = data?.kpi ?? {};
  const combinations = data?.combinations ?? data?.toxicCombinations ?? [];
  const matrixData = data?.coOccurrenceMatrix?.data ?? data?.coOccurrenceMatrix ?? data?.matrix?.data ?? data?.matrix ?? {};
  const matrixCategories = useMemo(() => {
    if (data?.coOccurrenceMatrix?.categories) return data.coOccurrenceMatrix.categories;
    if (data?.matrix?.categories) return data.matrix.categories;
    // Derive from matrix keys
    if (matrixData && typeof matrixData === 'object') {
      const keys = Object.keys(matrixData);
      return keys.length > 0 ? keys : [];
    }
    return [];
  }, [data, matrixData]);

  // KPI values with fallbacks
  const totalCombos = kpi.total ?? kpi.totalCombinations ?? combinations.length;
  const criticalCount =
    kpi.critical ??
    kpi.criticalCombinations ??
    combinations.filter(
      (c) => (c.toxicityScore ?? c.toxicity_score ?? 0) >= 90
    ).length;
  const resourcesAffected =
    kpi.resourcesAtRisk ??
    kpi.resources_at_risk ??
    combinations.reduce(
      (sum, c) => sum + (c.affectedResources ?? c.affected_resources ?? 1),
      0
    );
  const avgToxicity = useMemo(() => {
    if (kpi.avgMultiplier ?? kpi.avg_multiplier) {
      return kpi.avgMultiplier ?? kpi.avg_multiplier;
    }
    if (combinations.length === 0) return 0;
    const total = combinations.reduce(
      (sum, c) => sum + (c.toxicityScore ?? c.toxicity_score ?? 0),
      0
    );
    return (total / combinations.length).toFixed(1);
  }, [kpi, combinations]);

  // Card expand/collapse
  const toggleCard = useCallback((id) => {
    setExpandedCards((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  // Matrix cell click
  const handleCellClick = useCallback((cell) => {
    setSelectedCell(cell);
  }, []);

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  return (
    <div className="space-y-6">
      {/* Header + Breadcrumb */}
      <div>
        <div className="flex items-center gap-2 text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
          <button
            onClick={() => router.push('/threats')}
            className="hover:underline"
            style={{ color: 'var(--text-secondary)' }}
          >
            Threats
          </button>
          <ChevronRight className="w-3 h-3" />
          <span style={{ color: 'var(--text-primary)' }}>Toxic Combinations</span>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Toxic Combinations
        </h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Compound risk scenarios where multiple findings on a single resource amplify risk
          exponentially.
        </p>
      </div>

      {/* Threats Sub-Navigation */}
      <ThreatsSubNav />

      {/* Loading state */}
      {loading && <PageSkeleton />}

      {/* Error state */}
      {!loading && error && (
        <div
          className="rounded-xl p-5 border"
          style={{
            backgroundColor: 'rgba(239,68,68,0.08)',
            borderColor: 'rgba(239,68,68,0.3)',
          }}
        >
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                Failed to load toxic combinations
              </p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                {error}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && combinations.length === 0 && (
        <EmptyState
          icon={<Shield className="w-12 h-12" />}
          title="No Toxic Combinations Detected"
          description="Run a threat scan to identify compound risk scenarios. Toxic combinations emerge when multiple misconfigurations overlap on a single resource."
        />
      )}

      {/* KPI strip */}
      {!loading && !error && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title="Total Combinations"
            value={totalCombos}
            subtitle="Compound risk scenarios"
            icon={<Zap className="w-5 h-5" />}
            color="red"
          />
          <KpiCard
            title="Critical"
            value={criticalCount}
            subtitle="Toxicity >= 90"
            icon={<AlertTriangle className="w-5 h-5" />}
            color="red"
          />
          <KpiCard
            title="Resources Affected"
            value={resourcesAffected}
            subtitle="Unique resources"
            icon={<Target className="w-5 h-5" />}
            color="orange"
          />
          <KpiCard
            title="Avg Toxicity Score"
            value={avgToxicity}
            subtitle="Mean across combos"
            icon={<TrendingUp className="w-5 h-5" />}
            color="purple"
          />
        </div>
      )}

      {/* Tabs */}
      {!loading && !error && combinations.length > 0 && (
        <>
          <div
            className="flex border-b"
            style={{ borderColor: 'var(--border-primary)' }}
          >
            {[
              { key: TAB_COMBINATIONS, label: 'Combinations List' },
              { key: TAB_MATRIX, label: 'Co-occurrence Matrix' },
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className="px-5 py-3 text-sm font-medium transition-colors duration-150 relative"
                style={{
                  color:
                    activeTab === tab.key
                      ? 'var(--text-primary)'
                      : 'var(--text-muted)',
                }}
              >
                {tab.label}
                {activeTab === tab.key && (
                  <div
                    className="absolute bottom-0 left-0 right-0 h-0.5 rounded-full"
                    style={{ backgroundColor: '#3b82f6' }}
                  />
                )}
              </button>
            ))}
          </div>

          {/* Tab 1: Combinations List */}
          {activeTab === TAB_COMBINATIONS && (
            <div className="space-y-4">
              {combinations.map((combo, idx) => {
                const id = combo.id ?? combo.combination_id ?? `combo-${idx}`;
                return (
                  <CombinationCard
                    key={id}
                    combo={combo}
                    isExpanded={expandedCards.has(id)}
                    onToggle={() => toggleCard(id)}
                  />
                );
              })}
            </div>
          )}

          {/* Tab 2: Co-occurrence Matrix */}
          {activeTab === TAB_MATRIX && (
            <div
              className="rounded-xl p-6 border"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-primary)',
              }}
            >
              <div className="mb-4">
                <h3
                  className="text-lg font-semibold"
                  style={{ color: 'var(--text-primary)' }}
                >
                  Misconfig Co-occurrence Matrix
                </h3>
                <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
                  Cell intensity shows how frequently threat categories appear together on the same
                  resource. Click a cell for details.
                </p>
              </div>

              <CoOccurrenceMatrix
                matrixData={matrixData}
                categories={matrixCategories}
                onCellClick={handleCellClick}
              />

              <MatrixCellDetail
                cell={selectedCell}
                onClose={() => setSelectedCell(null)}
              />
            </div>
          )}
        </>
      )}
    </div>
  );
}
