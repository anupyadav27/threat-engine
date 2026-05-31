'use client';

import { useState, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ChevronLeft, ChevronDown, ChevronRight, Share2, Wrench } from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import IdentityProfileHeader from '@/components/cdr/IdentityProfileHeader';
import BehavioralTimeline from '@/components/cdr/BehavioralTimeline';
import ActivityHeatmap from '@/components/cdr/ActivityHeatmap';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import EmptyState from '@/components/shared/EmptyState';

const RULE_SOURCE_BADGE = {
  log_event:        { label: 'L1', cls: 'bg-slate-800 text-slate-400 border-slate-700' },
  log_correlation:  { label: 'L2', cls: 'bg-orange-950 text-orange-400 border-orange-800' },
  baseline:         { label: 'L3', cls: 'bg-purple-950 text-purple-400 border-purple-800' },
};

function RuleSourceBadge({ source }) {
  const cfg = RULE_SOURCE_BADGE[source] || RULE_SOURCE_BADGE.log_event;
  return (
    <span className={`inline-flex items-center text-[10px] font-bold px-1.5 py-0.5 rounded border ${cfg.cls}`}>
      {cfg.label}
    </span>
  );
}

function fmtTs(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const METRIC_LABELS = {
  api_call_count:     'API Call Count',
  unique_services:    'Unique Services',
  unique_resources:   'Unique Resources',
  unique_source_ips:  'Source IPs',
  after_hours_ratio:  'After-Hours Ratio',
  cross_region_ratio: 'Cross-Region Ratio',
};

function Sparkline({ points, mean, threshold, anomalous }) {
  if (!points?.length) return null;
  const W = 160, H = 36, PAD = 4;
  const vals   = points.map(p => p.value);
  const maxVal = Math.max(...vals, threshold ?? 0, mean ?? 0, 0.01);
  const minVal = Math.min(...vals, 0);
  const range  = maxVal - minVal || 1;
  const toY    = v => H - PAD - ((v - minVal) / range) * (H - PAD * 2);
  const toX    = i => PAD + (i / Math.max(points.length - 1, 1)) * (W - PAD * 2);

  const pathD = points.map((p, i) =>
    `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(p.value).toFixed(1)}`
  ).join(' ');

  const lineColor = anomalous ? '#ef4444' : '#6366f1';

  return (
    <svg width={W} height={H} style={{ flexShrink: 0 }}>
      {mean != null && (
        <line x1={PAD} x2={W - PAD} y1={toY(mean)} y2={toY(mean)}
          stroke="#6b7280" strokeWidth={1} strokeDasharray="3 2" opacity={0.5} />
      )}
      {threshold != null && (
        <line x1={PAD} x2={W - PAD} y1={toY(threshold)} y2={toY(threshold)}
          stroke={anomalous ? '#ef4444' : '#f97316'} strokeWidth={1}
          strokeDasharray="4 2" opacity={0.7} />
      )}
      <path d={pathD} fill="none" stroke={lineColor} strokeWidth={1.5}
        strokeLinejoin="round" strokeLinecap="round" />
      {points.length > 0 && (
        <circle cx={toX(points.length - 1)} cy={toY(points[points.length - 1].value)}
          r={2.5} fill={lineColor} />
      )}
    </svg>
  );
}

function BaselineSparklines({ metrics }) {
  if (!metrics?.length) {
    return (
      <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
          14-Day Behavioral Baseline
        </div>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Insufficient history for baseline — actor needs at least 14 days of data.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="px-5 py-4 border-b" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>14-Day Behavioral Baseline</div>
        <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Per-metric trend vs baseline threshold — red = anomalous
        </div>
      </div>
      <div className="divide-y" style={{ divideColor: 'var(--border-primary)' }}>
        {metrics.map(m => {
          const latest    = m.points?.length ? m.points[m.points.length - 1].value : null;
          const anomalous = latest != null && m.threshold != null && latest > m.threshold;
          const sigmas    = (m.mean != null && m.stddev && m.stddev > 0 && latest != null)
            ? ((latest - m.mean) / m.stddev).toFixed(1)
            : null;
          const label = METRIC_LABELS[m.metric] || m.metric.replace(/_/g, ' ');

          return (
            <div key={m.metric} className="flex items-center gap-4 px-5 py-3"
              style={{ borderColor: 'var(--border-primary)' }}>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-xs font-medium capitalize" style={{ color: 'var(--text-secondary)' }}>
                    {label}
                  </span>
                  {anomalous && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                      style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
                      {sigmas ? `↑ ${sigmas}σ` : 'ANOMALY'}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-muted)' }}>
                  {m.mean != null && <span>baseline {m.mean.toFixed(1)}</span>}
                  {m.threshold != null && <span>· threshold {m.threshold.toFixed(1)}</span>}
                  {latest != null && (
                    <span className="font-bold" style={{ color: anomalous ? '#ef4444' : 'var(--text-secondary)' }}>
                      · now {latest.toFixed(1)}
                    </span>
                  )}
                </div>
              </div>
              <Sparkline points={m.points} mean={m.mean} threshold={m.threshold} anomalous={anomalous} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function IdentityProfilePage() {
  const params  = useParams();
  const router  = useRouter();
  const principal = decodeURIComponent(params.principal || '');

  const [remediationOpen, setRemediationOpen] = useState(false);
  const [expandedRows, setExpandedRows] = useState(new Set());

  const { data, loading, error } = useViewFetch('cdr_identity', { principal });

  const identity    = data?.identity || {};
  const findings    = data?.findings || [];
  const hourlyData  = data?.hourlyData || data?.hourly_data || [];
  const dowData     = data?.dowData    || data?.dow_data    || [];
  const baselineTrend = data?.baselineTrend || { metrics: [], has_data: false };

  const timelineFindings = useMemo(() =>
    findings.filter(f => f.event_time),
    [findings]
  );

  const findingColumns = useMemo(() => [
    {
      accessorKey: 'rule_source',
      header: 'Level',
      size: 70,
      cell: ({ getValue }) => <RuleSourceBadge source={getValue()} />,
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 90,
      cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
    },
    {
      accessorKey: 'title',
      header: 'Detection',
      cell: ({ getValue, row }) => {
        const isL2 = row.original?.rule_source === 'log_correlation';
        const isExpanded = expandedRows.has(row.original?.finding_id);
        return (
          <div>
            <div className="flex items-center gap-1.5">
              {isL2 && (
                <button
                  onClick={e => {
                    e.stopPropagation();
                    setExpandedRows(prev => {
                      const next = new Set(prev);
                      const id = row.original?.finding_id;
                      if (next.has(id)) next.delete(id); else next.add(id);
                      return next;
                    });
                  }}
                  className="hover:opacity-75 transition-opacity flex-shrink-0"
                  style={{ color: 'var(--text-muted)' }}>
                  {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                </button>
              )}
              <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{getValue() || row.original?.rule_id}</span>
            </div>
            {isL2 && isExpanded && (
              <div className="mt-2 ml-5 space-y-1">
                {(row.original?.finding_data?.contributing_steps || []).map((step, si) => (
                  <div key={si} className="text-xs flex items-start gap-1.5 pl-2 border-l-2 border-orange-700">
                    <span className="text-orange-400 font-semibold">{si + 1}.</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{typeof step === 'string' ? step : step.title || step.description || JSON.stringify(step)}</span>
                  </div>
                ))}
                {!(row.original?.finding_data?.contributing_steps?.length) && (
                  <div className="text-xs pl-2" style={{ color: 'var(--text-muted)' }}>No contributing steps recorded</div>
                )}
              </div>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'rule_id',
      header: 'Rule',
      size: 130,
      cell: ({ getValue }) => (
        <span className="font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>{getValue()}</span>
      ),
    },
    {
      accessorKey: 'service',
      header: 'Service',
      size: 100,
    },
    {
      accessorKey: 'operation',
      header: 'Operation',
      size: 120,
    },
    {
      accessorKey: 'event_time',
      header: 'Time',
      size: 140,
      cell: ({ getValue }) => (
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{fmtTs(getValue())}</span>
      ),
    },
  ], [expandedRows]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          Loading identity profile...
        </div>
      </div>
    );
  }

  if (error || (!loading && !identity?.actor_principal && !identity?.principal)) {
    return (
      <div className="space-y-4 p-6">
        <button
          onClick={() => router.push('/cdr')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          CDR
        </button>
        <EmptyState
          title="No data for this identity"
          description={error || `No findings found for ${principal}`}
        />
      </div>
    );
  }

  const resolvedPrincipal = identity.actor_principal || identity.principal || principal;
  const resolvedType      = identity.actor_principal_type || identity.type || 'unknown';
  const riskScore         = identity.risk_score ?? 0;
  const l2Count           = identity.l2Findings ?? identity.l2_findings ?? 0;
  const l3Count           = identity.l3Findings ?? identity.l3_findings ?? 0;
  const accountCount      = identity.account_count ?? 1;
  const lastSeen          = identity.last_seen ?? identity.lastSeen;
  const sourceIps         = identity.source_ips ?? identity.sourceIps ?? [];

  return (
    <div className="space-y-5">

      {/* Breadcrumb + actions */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => router.push('/cdr')}
          className="flex items-center gap-1.5 text-sm hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          CDR
        </button>

        <div className="flex gap-2">
          <button
            onClick={() => router.push(`/cdr/identity/${encodeURIComponent(resolvedPrincipal)}/blast-radius`)}
            className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-3 py-1.5 rounded-lg transition-colors">
            <Share2 className="w-3.5 h-3.5" />
            Blast Radius
          </button>
          <button
            onClick={() => setRemediationOpen(true)}
            className="flex items-center gap-1.5 text-slate-200 text-sm px-3 py-1.5 rounded-lg transition-colors"
            style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
            <Wrench className="w-3.5 h-3.5" />
            Remediate
          </button>
        </div>
      </div>

      {/* Identity profile header */}
      <IdentityProfileHeader
        principal={resolvedPrincipal}
        type={resolvedType}
        riskScore={riskScore}
        l2Count={l2Count}
        l3Count={l3Count}
        accountCount={accountCount}
        lastSeen={lastSeen}
        sourceIps={sourceIps}
      />

      {/* Behavioral timeline */}
      {timelineFindings.length > 0 && (
        <BehavioralTimeline findings={timelineFindings} />
      )}

      {/* Activity heatmap */}
      {(hourlyData.length > 0 || dowData.length > 0) && (
        <ActivityHeatmap hourlyData={hourlyData} dowData={dowData} />
      )}

      {/* 14-day behavioral baseline sparklines */}
      <BaselineSparklines metrics={baselineTrend.metrics} />

      {/* Findings table */}
      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="px-5 py-4 border-b flex items-center justify-between"
          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
          <div>
            <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Findings</div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {findings.length} total — L1 individual events, L2 correlated chains, L3 anomalies
            </div>
          </div>
          <div className="flex gap-2">
            {[
              { label: 'L1', cls: 'bg-slate-800 text-slate-400 border-slate-700' },
              { label: 'L2', cls: 'bg-orange-950 text-orange-400 border-orange-800' },
              { label: 'L3', cls: 'bg-purple-950 text-purple-400 border-purple-800' },
            ].map(b => (
              <span key={b.label} className={`text-[10px] font-bold px-2 py-0.5 rounded border ${b.cls}`}>
                {b.label}
              </span>
            ))}
          </div>
        </div>
        <div className="p-4">
          {findings.length === 0 ? (
            <EmptyState title="No findings" description="No CDR findings for this identity" />
          ) : (
            <DataTable
              data={findings}
              columns={findingColumns}
              pageSize={15}
              emptyMessage="No findings"
            />
          )}
        </div>
      </div>

      {/* Remediation slide-over placeholder */}
      {remediationOpen && (
        <div
          className="fixed inset-0 z-50 flex justify-end"
          onClick={() => setRemediationOpen(false)}>
          <div
            className="w-96 h-full flex flex-col shadow-2xl"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}
            onClick={e => e.stopPropagation()}>
            <div className="px-5 py-4 border-b flex items-center justify-between"
              style={{ borderColor: 'var(--border-primary)' }}>
              <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Remediate Identity</span>
              <button onClick={() => setRemediationOpen(false)}
                className="text-xs hover:opacity-75"
                style={{ color: 'var(--text-muted)' }}>Close</button>
            </div>
            <div className="flex-1 flex items-center justify-center p-6 text-center">
              <div>
                <div className="text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                  Remediation Advisor
                </div>
                <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  AI-assisted remediation playbooks coming in a future sprint.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
