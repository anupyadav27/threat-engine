'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Clock,
  ChevronRight,
  BarChart3,
  Target,
  Grid3X3,
  Fingerprint,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { fetchView } from '@/lib/api';
import { SEVERITY_COLORS, SEVERITY_ORDER, CLOUD_PROVIDERS } from '@/lib/constants';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import DataTable from '@/components/shared/DataTable';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TIME_RANGES = [
  { label: '7d', value: 7 },
  { label: '14d', value: 14 },
  { label: '30d', value: 30 },
];

const TOOLTIP_STYLE = {
  backgroundColor: 'var(--bg-card)',
  borderColor: 'var(--border-primary)',
  borderRadius: '0.5rem',
  boxShadow: '0 4px 6px rgba(0, 0, 0, 0.3)',
  color: 'var(--text-primary)',
};

const AXIS_TICK = { fill: 'var(--text-tertiary)', fontSize: 12 };

// ---------------------------------------------------------------------------
// Shared UI Primitives
// ---------------------------------------------------------------------------

function CardShell({ children, className = '' }) {
  return (
    <div
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      className={`rounded-xl border p-5 transition-colors duration-200 ${className}`}
    >
      {children}
    </div>
  );
}

function CardTitle({ children, right }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <h3 style={{ color: 'var(--text-primary)' }} className="text-sm font-semibold">
        {children}
      </h3>
      {right}
    </div>
  );
}

function SectionError({ message }) {
  return (
    <div className="flex items-center justify-center py-12">
      <p style={{ color: 'var(--text-muted)' }} className="text-sm">
        {message || 'Failed to load this section.'}
      </p>
    </div>
  );
}

function SkeletonBox({ height = 'h-64' }) {
  return (
    <div
      className={`${height} animate-pulse rounded-lg`}
      style={{ backgroundColor: 'var(--bg-secondary)' }}
    />
  );
}

function TimeRangeToggle({ value, onChange }) {
  return (
    <div
      className="flex rounded-lg overflow-hidden border"
      style={{ borderColor: 'var(--border-primary)' }}
    >
      {TIME_RANGES.map((r) => (
        <button
          key={r.value}
          onClick={() => onChange(r.value)}
          className="px-3 py-1.5 text-xs font-medium transition-colors duration-150"
          style={{
            backgroundColor: value === r.value ? 'var(--accent-primary)' : 'var(--bg-secondary)',
            color: value === r.value ? '#fff' : 'var(--text-muted)',
          }}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Custom Recharts tooltip
// ---------------------------------------------------------------------------

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={TOOLTIP_STYLE}
      className="rounded-lg border p-3 text-xs"
    >
      <p style={{ color: 'var(--text-secondary)' }} className="mb-1 font-medium">
        {label}
      </p>
      {payload.map((entry) => (
        <div key={entry.dataKey} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: entry.color }} />
          <span style={{ color: 'var(--text-tertiary)' }} className="capitalize">
            {entry.dataKey}:
          </span>
          <span style={{ color: 'var(--text-primary)' }} className="font-semibold">
            {entry.value?.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function ThreatAnalyticsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Time range from URL, default 30
  const daysParam = parseInt(searchParams.get('days'), 10);
  const [days, setDays] = useState(TIME_RANGES.some((r) => r.value === daysParam) ? daysParam : 30);

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Persist time range in URL
  const handleDaysChange = useCallback(
    (newDays) => {
      setDays(newDays);
      const params = new URLSearchParams(searchParams.toString());
      params.set('days', String(newDays));
      router.replace(`?${params.toString()}`, { scroll: false });
    },
    [router, searchParams],
  );

  // -----------------------------------------------------------------------
  // Data fetch
  // -----------------------------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetchView('threats/analytics', { days });
        if (!cancelled) {
          if (res?.error) {
            setError(res.error);
          } else {
            setData(res);
          }
        }
      } catch (err) {
        if (!cancelled) setError(err?.message || 'Unknown error');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [days]);

  // -----------------------------------------------------------------------
  // Derived / memoised data
  // -----------------------------------------------------------------------

  const kpi = data?.kpi;

  // Severity donut data (transform BFF array into object for SeverityDonut component)
  const severityObj = useMemo(() => {
    if (!data?.severityDistribution) return null;
    const obj = { critical: 0, high: 0, medium: 0, low: 0 };
    data.severityDistribution.forEach((d) => {
      const key = d.name?.toLowerCase();
      if (key in obj) obj[key] = d.value;
    });
    return obj;
  }, [data?.severityDistribution]);

  // Category bar data
  const categoryData = useMemo(() => data?.byCategory || [], [data?.byCategory]);

  // Provider bar data with CLOUD_PROVIDERS colors
  const providerData = useMemo(() => {
    if (!data?.byProvider) return [];
    return data.byProvider.map((p) => ({
      ...p,
      color: CLOUD_PROVIDERS[p.name?.toLowerCase()]?.color || p.color || '#6b7280',
    }));
  }, [data?.byProvider]);

  // Trend data (slice to selected days window)
  const trendData = useMemo(() => {
    if (!data?.trendData) return [];
    return data.trendData.slice(-days);
  }, [data?.trendData, days]);

  // Top services for stacked bar
  const topServices = useMemo(() => data?.topServices || [], [data?.topServices]);

  // MITRE techniques
  const mitreTechniques = useMemo(() => data?.topMitreTechniques || [], [data?.topMitreTechniques]);

  // Account heatmap
  const accountHeatmap = useMemo(() => data?.accountHeatmap || [], [data?.accountHeatmap]);
  const heatmapMax = useMemo(() => {
    if (!accountHeatmap.length) return 1;
    let max = 0;
    accountHeatmap.forEach((a) => {
      SEVERITY_ORDER.slice(0, 4).forEach((s) => {
        if ((a[s] || 0) > max) max = a[s];
      });
    });
    return max || 1;
  }, [accountHeatmap]);

  // Patterns for DataTable
  const patterns = useMemo(() => data?.patterns || [], [data?.patterns]);
  const patternColumns = useMemo(
    () => [
      {
        accessorKey: 'name',
        header: 'Pattern',
        cell: ({ getValue }) => (
          <span style={{ color: 'var(--text-primary)' }} className="font-medium">
            {getValue()}
          </span>
        ),
      },
      {
        accessorKey: 'occurrences',
        header: 'Occurrences',
        cell: ({ getValue }) => (
          <span style={{ color: 'var(--text-primary)' }} className="font-semibold tabular-nums">
            {getValue()?.toLocaleString()}
          </span>
        ),
      },
      {
        accessorKey: 'severity',
        header: 'Top Severity',
        cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
      },
      {
        accessorKey: 'services',
        header: 'Services Affected',
        cell: ({ getValue }) => {
          const services = getValue();
          if (!services?.length) return '-';
          return (
            <div className="flex flex-wrap gap-1">
              {services.map((s) => (
                <span
                  key={s}
                  className="px-2 py-0.5 rounded text-xs font-medium"
                  style={{
                    backgroundColor: 'var(--bg-secondary)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {s}
                </span>
              ))}
            </div>
          );
        },
      },
    ],
    [],
  );

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------
  return (
    <div className="space-y-6">
      {/* ================================================================== */}
      {/* ROW 1: Header + Time Range                                         */}
      {/* ================================================================== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <button
              onClick={() => router.push('/threats')}
              className="text-sm hover:underline"
              style={{ color: 'var(--text-muted)' }}
            >
              Threats
            </button>
            <ChevronRight className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
            <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              Analytics
            </span>
          </div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Threat Analytics
          </h1>
        </div>
        <TimeRangeToggle value={days} onChange={handleDaysChange} />
      </div>

      {/* Threats Sub-Navigation */}
      <ThreatsSubNav />

      {/* Global error banner */}
      {error && !data && (
        <div
          className="rounded-lg p-4 border"
          style={{ backgroundColor: 'rgba(239,68,68,0.1)', borderColor: '#ef4444' }}
        >
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {error}
          </p>
        </div>
      )}

      {/* ================================================================== */}
      {/* ROW 2: KPI Strip                                                   */}
      {/* ================================================================== */}
      {loading ? (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <SkeletonBox key={i} height="h-32" />
          ))}
        </div>
      ) : kpi ? (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          <KpiCard
            title="Total Threats"
            value={kpi.total?.toLocaleString() ?? '0'}
            icon={<ShieldAlert className="w-5 h-5" />}
            color="red"
            subtitle="Active threats"
          />
          <KpiCard
            title="Critical + High"
            value={kpi.criticalAndHigh?.toLocaleString() ?? '0'}
            icon={<Flame className="w-5 h-5" />}
            color="orange"
            subtitle="Require immediate attention"
          />
          <KpiCard
            title="New This Week"
            value={kpi.newLast7Days?.toLocaleString() ?? '0'}
            icon={<AlertTriangle className="w-5 h-5" />}
            color="yellow"
            subtitle="Last 7 days"
          />
          <KpiCard
            title="Resolved / Week"
            value={kpi.resolvedPerWeek?.toLocaleString() ?? '0'}
            icon={<CheckCircle2 className="w-5 h-5" />}
            color="green"
            subtitle="Average weekly"
          />
          <KpiCard
            title="Mean Time to Detect"
            value={kpi.meanTimeToDetectHours != null ? `${kpi.meanTimeToDetectHours}h` : '-'}
            icon={<Clock className="w-5 h-5" />}
            color="blue"
            subtitle="MTTD"
          />
        </div>
      ) : null}

      {/* ================================================================== */}
      {/* ROW 3: Distribution Charts (3 columns)                             */}
      {/* ================================================================== */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Severity Donut */}
        <CardShell>
          <CardTitle>Severity Distribution</CardTitle>
          {loading ? (
            <SkeletonBox height="h-64" />
          ) : severityObj ? (
            <SeverityDonutInline data={severityObj} />
          ) : (
            <SectionError message="No severity data" />
          )}
        </CardShell>

        {/* By Category */}
        <CardShell>
          <CardTitle>By Category</CardTitle>
          {loading ? (
            <SkeletonBox height="h-64" />
          ) : categoryData.length ? (
            <HorizontalColoredBar data={categoryData} dataKey="count" />
          ) : (
            <SectionError message="No category data" />
          )}
        </CardShell>

        {/* By Provider */}
        <CardShell>
          <CardTitle>By Provider</CardTitle>
          {loading ? (
            <SkeletonBox height="h-64" />
          ) : providerData.length ? (
            <HorizontalColoredBar data={providerData} dataKey="count" />
          ) : (
            <SectionError message="No provider data" />
          )}
        </CardShell>
      </div>

      {/* ================================================================== */}
      {/* ROW 4: Trend Chart (full width, stacked area)                      */}
      {/* ================================================================== */}
      <CardShell>
        <CardTitle
          right={<TimeRangeToggle value={days} onChange={handleDaysChange} />}
        >
          Threat Trend ({days} Days)
        </CardTitle>
        {loading ? (
          <SkeletonBox height="h-72" />
        ) : trendData.length ? (
          <ResponsiveContainer width="100%" height={320}>
            <AreaChart data={trendData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
              <defs>
                {SEVERITY_ORDER.slice(0, 4).map((sev) => (
                  <linearGradient key={sev} id={`grad-${sev}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={SEVERITY_COLORS[sev]} stopOpacity={0.4} />
                    <stop offset="100%" stopColor={SEVERITY_COLORS[sev]} stopOpacity={0.05} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" />
              <XAxis
                dataKey="date"
                tick={AXIS_TICK}
                stroke="var(--border-primary)"
                tickFormatter={(v) => {
                  const d = new Date(v);
                  return `${d.toLocaleString('default', { month: 'short' })} ${d.getDate()}`;
                }}
              />
              <YAxis tick={AXIS_TICK} stroke="var(--border-primary)" />
              <Tooltip content={<ChartTooltip />} />
              <Legend
                wrapperStyle={{ paddingTop: 12 }}
                formatter={(val) => (
                  <span style={{ color: 'var(--text-tertiary)', fontSize: 12, textTransform: 'capitalize' }}>
                    {val}
                  </span>
                )}
              />
              {['low', 'medium', 'high', 'critical'].map((sev) => (
                <Area
                  key={sev}
                  type="monotone"
                  dataKey={sev}
                  stackId="severity"
                  stroke={SEVERITY_COLORS[sev]}
                  fill={`url(#grad-${sev})`}
                  strokeWidth={1.5}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <EmptyState
            icon={<BarChart3 className="w-12 h-12" />}
            title="No trend data"
            description="Threat trend data will appear here once scans have been running for multiple days."
          />
        )}
      </CardShell>

      {/* ================================================================== */}
      {/* ROW 5: Top Lists (2 columns)                                       */}
      {/* ================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Affected Services — stacked horizontal bar */}
        <CardShell>
          <CardTitle>Top Affected Services</CardTitle>
          {loading ? (
            <SkeletonBox height="h-72" />
          ) : topServices.length ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={topServices}
                layout="vertical"
                margin={{ top: 0, right: 20, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" horizontalPoints={[]} />
                <XAxis type="number" tick={AXIS_TICK} stroke="var(--border-primary)" />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={AXIS_TICK}
                  stroke="var(--border-primary)"
                  width={70}
                />
                <Tooltip content={<ChartTooltip />} />
                <Legend
                  wrapperStyle={{ paddingTop: 8 }}
                  formatter={(val) => (
                    <span style={{ color: 'var(--text-tertiary)', fontSize: 12, textTransform: 'capitalize' }}>
                      {val}
                    </span>
                  )}
                />
                {SEVERITY_ORDER.slice(0, 4).map((sev) => (
                  <Bar
                    key={sev}
                    dataKey={sev}
                    stackId="sev"
                    fill={SEVERITY_COLORS[sev]}
                    radius={sev === 'critical' ? [0, 4, 4, 0] : [0, 0, 0, 0]}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <SectionError message="No service data" />
          )}
        </CardShell>

        {/* Top MITRE Techniques */}
        <CardShell>
          <CardTitle>Top MITRE ATT&CK Techniques</CardTitle>
          {loading ? (
            <SkeletonBox height="h-72" />
          ) : mitreTechniques.length ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={mitreTechniques}
                layout="vertical"
                margin={{ top: 0, right: 20, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" horizontalPoints={[]} />
                <XAxis type="number" tick={AXIS_TICK} stroke="var(--border-primary)" />
                <YAxis
                  type="category"
                  dataKey="id"
                  tick={AXIS_TICK}
                  stroke="var(--border-primary)"
                  width={60}
                />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (!active || !payload?.length) return null;
                    const d = payload[0]?.payload;
                    return (
                      <div style={TOOLTIP_STYLE} className="rounded-lg border p-3 text-xs">
                        <p style={{ color: 'var(--text-primary)' }} className="font-semibold mb-1">
                          {d?.id}: {d?.name}
                        </p>
                        <p style={{ color: 'var(--text-tertiary)' }}>
                          Count: {d?.count?.toLocaleString()}
                        </p>
                      </div>
                    );
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {mitreTechniques.map((t, i) => (
                    <Cell
                      key={t.id || i}
                      fill={SEVERITY_COLORS[t.severity] || SEVERITY_COLORS.high}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <SectionError message="No MITRE technique data" />
          )}
        </CardShell>
      </div>

      {/* ================================================================== */}
      {/* ROW 6a: Account Heatmap                                            */}
      {/* ================================================================== */}
      <CardShell>
        <CardTitle>Threat Distribution by Account</CardTitle>
        {loading ? (
          <SkeletonBox height="h-48" />
        ) : accountHeatmap.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottomColor: 'var(--border-primary)' }} className="border-b">
                  <th
                    className="text-left py-3 px-4 font-semibold"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Account
                  </th>
                  {SEVERITY_ORDER.slice(0, 4).map((sev) => (
                    <th
                      key={sev}
                      className="text-center py-3 px-4 font-semibold capitalize"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      {sev}
                    </th>
                  ))}
                  <th
                    className="text-center py-3 px-4 font-semibold"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Total
                  </th>
                </tr>
              </thead>
              <tbody>
                {accountHeatmap.map((acct) => (
                  <tr
                    key={acct.account}
                    style={{ borderBottomColor: 'var(--border-primary)' }}
                    className="border-b last:border-b-0 hover:opacity-80 transition-opacity"
                  >
                    <td className="py-3 px-4">
                      <div>
                        <span
                          className="font-mono text-xs"
                          style={{ color: 'var(--text-primary)' }}
                        >
                          {acct.account}
                        </span>
                        {acct.accountName && (
                          <span
                            className="ml-2 text-xs"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            ({acct.accountName})
                          </span>
                        )}
                      </div>
                    </td>
                    {SEVERITY_ORDER.slice(0, 4).map((sev) => {
                      const count = acct[sev] || 0;
                      const intensity = Math.min(count / heatmapMax, 1);
                      return (
                        <td key={sev} className="text-center py-3 px-4">
                          <span
                            className="inline-flex items-center justify-center w-12 h-8 rounded text-xs font-semibold"
                            style={{
                              backgroundColor: intensity > 0
                                ? `${SEVERITY_COLORS[sev]}${Math.round(intensity * 0.5 * 255)
                                    .toString(16)
                                    .padStart(2, '0')}`
                                : 'transparent',
                              color: intensity > 0.3
                                ? '#fff'
                                : 'var(--text-secondary)',
                            }}
                          >
                            {count}
                          </span>
                        </td>
                      );
                    })}
                    <td className="text-center py-3 px-4">
                      <span
                        className="font-semibold text-xs"
                        style={{ color: 'var(--text-primary)' }}
                      >
                        {acct.total?.toLocaleString()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={<Grid3X3 className="w-12 h-12" />}
            title="No account data"
            description="Account-level threat distribution will appear after scans complete across multiple accounts."
          />
        )}
      </CardShell>

      {/* ================================================================== */}
      {/* ROW 6b: Pattern Analysis                                           */}
      {/* ================================================================== */}
      <CardShell>
        <CardTitle>Common Threat Patterns</CardTitle>
        {loading ? (
          <LoadingSkeleton rows={4} cols={4} />
        ) : patterns.length ? (
          <DataTable
            data={patterns}
            columns={patternColumns}
            pageSize={5}
            emptyMessage="No patterns detected"
          />
        ) : (
          <EmptyState
            icon={<Fingerprint className="w-12 h-12" />}
            title="No patterns detected"
            description="Recurring threat patterns will surface here once enough scan data is available."
          />
        )}
      </CardShell>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inline chart sub-components
// ---------------------------------------------------------------------------

/**
 * Severity donut using Recharts PieChart.
 * Accepts {critical, high, medium, low} object.
 */
function SeverityDonutInline({ data }) {
  const chartData = useMemo(() => {
    return SEVERITY_ORDER.slice(0, 4).map((sev) => ({
      name: sev.charAt(0).toUpperCase() + sev.slice(1),
      value: data[sev] || 0,
      severity: sev,
    }));
  }, [data]);

  const total = useMemo(() => chartData.reduce((s, d) => s + d.value, 0), [chartData]);

  return (
    <div>
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={85}
            paddingAngle={2}
            dataKey="value"
            label={false}
          >
            {chartData.map((entry) => (
              <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity]} />
            ))}
            {/* Center label */}
            <g>
              <text
                x="50%"
                y="47%"
                textAnchor="middle"
                dominantBaseline="middle"
                className="text-xl font-bold"
                fill="var(--text-primary)"
              >
                {total.toLocaleString()}
              </text>
              <text
                x="50%"
                y="57%"
                textAnchor="middle"
                dominantBaseline="middle"
                className="text-xs"
                fill="var(--text-tertiary)"
              >
                Total
              </text>
            </g>
          </Pie>
          <Tooltip
            contentStyle={TOOLTIP_STYLE}
            formatter={(value) => value.toLocaleString()}
          />
        </PieChart>
      </ResponsiveContainer>
      {/* Legend */}
      <div className="flex flex-wrap justify-center gap-4 mt-2">
        {chartData.map((d) => (
          <div key={d.severity} className="flex items-center gap-1.5">
            <span
              className="w-2 h-2 rounded-full inline-block"
              style={{ backgroundColor: SEVERITY_COLORS[d.severity] }}
            />
            <span style={{ color: 'var(--text-tertiary)' }} className="text-xs">
              {d.name}: {d.value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Horizontal bar chart where each bar can have its own color.
 * Expects data = [{name, [dataKey], color}]
 */
function HorizontalColoredBar({ data, dataKey = 'value' }) {
  return (
    <ResponsiveContainer width="100%" height={data.length * 48 + 20}>
      <BarChart
        data={data}
        layout="vertical"
        margin={{ top: 0, right: 20, left: 0, bottom: 0 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" horizontalPoints={[]} />
        <XAxis type="number" tick={AXIS_TICK} stroke="var(--border-primary)" />
        <YAxis
          type="category"
          dataKey="name"
          tick={AXIS_TICK}
          stroke="var(--border-primary)"
          width={120}
        />
        <Tooltip content={<ChartTooltip />} />
        <Bar dataKey={dataKey} radius={[0, 4, 4, 0]} barSize={20}>
          {data.map((entry, index) => (
            <Cell key={index} fill={entry.color || '#3b82f6'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
