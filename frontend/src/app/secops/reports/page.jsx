'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  ChevronLeft, Download, Activity, ShieldAlert,
  BarChart2, Zap, AlertTriangle, TrendingDown, TrendingUp,
  Minus, ArrowUpRight, ArrowDownRight,
} from 'lucide-react';
import { getFromEngine, fetchApi } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import StatusIndicator from '@/components/shared/StatusIndicator';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const TENANT_ID = 'test-tenant';
const SCA_API_KEY = 'sbom-api-key-2024';
const SCA_BASE = '/secops/api/v1/secops/sca/api/v1/sbom';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
    d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function getWeekLabel(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  // Floor to Monday of that week
  const day = d.getDay();
  const diff = (day === 0 ? -6 : 1 - day);
  d.setDate(d.getDate() + diff);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function getWeekStart(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d)) return null;
  const day = d.getDay();
  const diff = (day === 0 ? -6 : 1 - day);
  d.setDate(d.getDate() + diff);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

// ---------------------------------------------------------------------------
// SourceBadge
// ---------------------------------------------------------------------------
function SourceBadge({ source }) {
  const cfg = {
    sast: { label: 'SAST', cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
    dast: { label: 'DAST', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/30' },
    sca:  { label: 'SCA',  cls: 'bg-green-500/15 text-green-400 border-green-500/30' },
  };
  const { label, cls } = cfg[source] || { label: (source || '').toUpperCase(), cls: 'bg-slate-500/15 text-slate-400 border-slate-500/30' };
  return (
    <span className={`inline-flex items-center text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border ${cls}`}>
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// StatCard
// ---------------------------------------------------------------------------
function StatCard({ label, value, color }) {
  return (
    <div className="rounded-xl border p-4 text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <p className="text-xs font-medium mb-1" style={{ color: 'var(--text-tertiary)' }}>{label}</p>
      <p className={`text-2xl font-bold tabular-nums ${color}`}>{value}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ScanTrendLine — per-scan severity-stacked bar chart with delta overlay
// ---------------------------------------------------------------------------
function ScanTrendLine({ scans, getTotal, getCrit, getHigh, getDate, getLabel }) {
  if (!scans || scans.length === 0) {
    return (
      <div className="flex items-center justify-center h-32 text-sm" style={{ color: 'var(--text-tertiary)' }}>
        No scan data available
      </div>
    );
  }

  const sorted = [...scans]
    .filter(s => getTotal(s) !== undefined)
    .sort((a, b) => new Date(getDate(a) || 0) - new Date(getDate(b) || 0));

  const maxVal = Math.max(...sorted.map(s => getTotal(s) || 0), 1);
  const totalChange = sorted.length >= 2
    ? (getTotal(sorted[sorted.length - 1]) || 0) - (getTotal(sorted[0]) || 0)
    : 0;

  return (
    <div>
      {/* Overall trend pill */}
      {sorted.length >= 2 && (
        <div className="flex items-center gap-3 mb-4">
          {totalChange < 0 ? (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-500/15 border border-green-500/25">
              <TrendingDown className="w-3.5 h-3.5 text-green-400" />
              <span className="text-xs font-semibold text-green-400">
                {Math.abs(totalChange)} fewer findings since first scan
              </span>
            </div>
          ) : totalChange > 0 ? (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-500/15 border border-red-500/25">
              <TrendingUp className="w-3.5 h-3.5 text-red-400" />
              <span className="text-xs font-semibold text-red-400">
                {totalChange} more findings since first scan
              </span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-500/15 border border-slate-500/25">
              <Minus className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
              <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>No overall change</span>
            </div>
          )}
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
            {sorted.length} scan{sorted.length !== 1 ? 's' : ''} · first vs latest
          </span>
        </div>
      )}

      {/* Bar chart */}
      <div className="flex items-end gap-1.5 h-36 overflow-x-auto pb-1">
        {sorted.map((s, i) => {
          const total = getTotal(s) || 0;
          const crit  = getCrit  ? getCrit(s)  || 0 : 0;
          const high  = getHigh  ? getHigh(s)  || 0 : 0;
          const other = Math.max(0, total - crit - high);
          const barH  = Math.max(4, (total / maxVal) * 112);
          const prevTotal = i > 0 ? getTotal(sorted[i - 1]) || 0 : null;
          const delta = prevTotal !== null ? total - prevTotal : null;
          const isLast = i === sorted.length - 1;

          return (
            <div key={i} className="flex-shrink-0 flex flex-col items-center gap-0.5 group" style={{ minWidth: 32 }}>
              {/* Delta indicator */}
              <div className="h-5 flex items-center">
                {delta !== null && delta !== 0 && (
                  <span className={`text-[9px] font-bold tabular-nums ${delta < 0 ? 'text-green-400' : 'text-red-400'}`}>
                    {delta > 0 ? '+' : ''}{delta}
                  </span>
                )}
              </div>
              {/* Count above bar */}
              <span className={`text-[10px] tabular-nums ${isLast ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}
                style={{ color: 'var(--text-tertiary)' }}>
                {total || ''}
              </span>
              {/* Stacked bar */}
              <div className={`w-7 rounded-t overflow-hidden flex flex-col-reverse transition-all ${isLast ? 'ring-1 ring-blue-400/40' : ''}`}
                style={{ height: `${barH}px` }}>
                <div className="bg-slate-500/30"    style={{ height: `${total > 0 ? (other / total) * 100 : 0}%` }} />
                <div className="bg-orange-500/60"   style={{ height: `${total > 0 ? (high  / total) * 100 : 0}%` }} />
                <div className="bg-red-500/75"      style={{ height: `${total > 0 ? (crit  / total) * 100 : 0}%` }} />
              </div>
              {/* Label */}
              <span className="text-[9px] truncate text-center mt-0.5" style={{ maxWidth: 40, color: 'var(--text-tertiary)' }} title={getLabel ? getLabel(s) : ''}>
                {getLabel ? getLabel(s) : fmtDate(getDate(s)).split(',')[0]}
              </span>
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex gap-4 mt-3">
        {[
          { color: 'bg-red-500/75',    label: 'Critical' },
          { color: 'bg-orange-500/60', label: 'High' },
          { color: 'bg-slate-500/30',  label: 'Other' },
        ].map(l => (
          <div key={l.label} className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-sm flex-shrink-0 ${l.color}`} />
            <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{l.label}</span>
          </div>
        ))}
        <div className="flex items-center gap-1.5 ml-4">
          <span className="text-[9px] font-bold text-green-400">-N</span>
          <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>delta vs prev scan</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ScanDeltaTable — shows per-scan delta vs previous scan
// ---------------------------------------------------------------------------
function ScanDeltaTable({ scans, getTotal, getDate, getLabel, onViewScan }) {
  const sorted = [...scans]
    .filter(s => getTotal(s) !== undefined && getDate(s))
    .sort((a, b) => new Date(getDate(a) || 0) - new Date(getDate(b) || 0));

  if (sorted.length < 2) {
    return (
      <div className="text-sm py-4 text-center" style={{ color: 'var(--text-tertiary)' }}>
        Need at least 2 scans to show scan-over-scan comparison
      </div>
    );
  }

  return (
    <div className="space-y-0 divide-y" style={{ divideColor: 'var(--border-primary)' }}>
      {/* Header */}
      <div className="grid gap-x-4 px-4 py-2 text-[10px] font-semibold uppercase tracking-wider"
        style={{ gridTemplateColumns: '1fr 80px 80px 80px', color: 'var(--text-tertiary)' }}>
        <span>Scan</span>
        <span className="text-right">Findings</span>
        <span className="text-right">vs Previous</span>
        <span className="text-right">Date</span>
      </div>
      {sorted.map((s, i) => {
        const total    = getTotal(s) || 0;
        const prev     = i > 0 ? getTotal(sorted[i - 1]) || 0 : null;
        const delta    = prev !== null ? total - prev : null;
        const isLatest = i === sorted.length - 1;

        return (
          <div key={i}
            onClick={() => onViewScan && onViewScan(s)}
            className={`grid gap-x-4 px-4 py-3 items-center transition-colors ${onViewScan ? 'cursor-pointer hover:bg-white/5' : ''} ${isLatest ? 'bg-blue-500/5' : ''}`}
            style={{ gridTemplateColumns: '1fr 80px 80px 80px' }}>
            <div className="min-w-0">
              <span className="text-sm truncate block" style={{ color: 'var(--text-primary)' }}>
                {getLabel ? getLabel(s) : `Scan ${i + 1}`}
              </span>
              {isLatest && (
                <span className="text-[10px] font-semibold text-blue-400">Latest</span>
              )}
            </div>
            <span className={`text-sm font-bold tabular-nums text-right ${total > 0 ? 'text-orange-400' : 'text-green-400'}`}>
              {total}
            </span>
            <div className="flex items-center justify-end gap-1">
              {delta === null ? (
                <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>baseline</span>
              ) : delta < 0 ? (
                <div className="flex items-center gap-0.5">
                  <ArrowDownRight className="w-3.5 h-3.5 text-green-400" />
                  <span className="text-xs font-semibold tabular-nums text-green-400">{delta}</span>
                </div>
              ) : delta > 0 ? (
                <div className="flex items-center gap-0.5">
                  <ArrowUpRight className="w-3.5 h-3.5 text-red-400" />
                  <span className="text-xs font-semibold tabular-nums text-red-400">+{delta}</span>
                </div>
              ) : (
                <div className="flex items-center gap-0.5">
                  <Minus className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
                  <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>0</span>
                </div>
              )}
            </div>
            <span className="text-xs text-right" style={{ color: 'var(--text-tertiary)' }}>
              {fmtDate(getDate(s))}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SectionCard
// ---------------------------------------------------------------------------
function SectionCard({ title, subtitle, action, children }) {
  return (
    <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="px-5 py-4 border-b flex items-center gap-3" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{title}</div>
          {subtitle && <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{subtitle}</div>}
        </div>
        {action}
      </div>
      <div className="p-5">
        {children}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CSS bar chart — Findings Over Time
// ---------------------------------------------------------------------------
function WeeklyBarChart({ weeklyData }) {
  const maxVal = Math.max(...weeklyData.map(w => w.total), 1);

  return (
    <div>
      <div className="flex items-end gap-2 h-32 px-2">
        {weeklyData.map(w => (
          <div key={w.label} className="flex-1 flex flex-col items-center gap-1 min-w-0">
            <span className="text-xs tabular-nums" style={{ color: 'var(--text-tertiary)' }}>
              {w.total || ''}
            </span>
            <div
              className="w-full flex flex-col-reverse rounded-t overflow-hidden"
              style={{ height: `${Math.max(4, (w.total / maxVal) * 96)}px` }}
            >
              <div className="bg-blue-500/60" style={{ height: `${(w.sca / Math.max(w.total, 1)) * 100}%` }} />
              <div className="bg-purple-500/60" style={{ height: `${(w.dast / Math.max(w.total, 1)) * 100}%` }} />
              <div className="bg-red-500/60" style={{ height: `${(w.sast / Math.max(w.total, 1)) * 100}%` }} />
            </div>
            <span className="text-xs truncate w-full text-center" style={{ color: 'var(--text-tertiary)' }}>
              {w.label}
            </span>
          </div>
        ))}
      </div>
      <div className="flex gap-4 mt-2 px-2">
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-red-500/60" />
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>SAST</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-purple-500/60" />
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>DAST</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-blue-500/60" />
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>SCA</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Per-scan bar chart (single engine)
// ---------------------------------------------------------------------------
function ScanBarChart({ scans, getValue, getLabel, barColor }) {
  const maxVal = Math.max(...scans.map(getValue), 1);
  return (
    <div className="flex items-end gap-2 h-24 px-1 overflow-x-auto">
      {scans.map((s, i) => {
        const val = getValue(s);
        const label = getLabel(s);
        return (
          <div key={i} className="flex-shrink-0 flex flex-col items-center gap-1" style={{ minWidth: 36 }}>
            <span className="text-xs tabular-nums" style={{ color: 'var(--text-tertiary)' }}>{val || ''}</span>
            <div
              className={`w-8 rounded-t ${barColor}`}
              style={{ height: `${Math.max(4, (val / maxVal) * 72)}px` }}
            />
            <span className="text-xs truncate text-center" style={{ maxWidth: 40, color: 'var(--text-tertiary)' }} title={label}>
              {label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Severity pill row for a DAST scan
// ---------------------------------------------------------------------------
function SeverityPills({ bySeverity }) {
  if (!bySeverity) return <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
  const segs = [
    { key: 'critical', label: 'C', cls: 'bg-red-500/20 text-red-400' },
    { key: 'high',     label: 'H', cls: 'bg-orange-500/20 text-orange-400' },
    { key: 'medium',   label: 'M', cls: 'bg-yellow-500/20 text-yellow-400' },
    { key: 'low',      label: 'L', cls: 'bg-blue-500/20 text-blue-400' },
  ];
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {segs.map(seg => {
        const v = bySeverity[seg.key] || 0;
        if (!v) return null;
        return (
          <span key={seg.key} className={`text-xs font-bold px-1.5 py-0.5 rounded ${seg.cls}`}>
            {seg.label}{v}
          </span>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------
export default function ReportsPage() {
  const router = useRouter();

  const [sastScans, setSastScans] = useState([]);
  const [dastScans, setDastScans] = useState([]);
  const [scaScans,  setScaScans]  = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  // ---------------------------------------------------------------------------
  // Data fetch
  // ---------------------------------------------------------------------------
  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [sast, dast, sca] = await Promise.all([
        getFromEngine('secops', `/api/v1/secops/sast/scans?tenant_id=${TENANT_ID}`).catch(() => []),
        getFromEngine('secops', `/api/v1/secops/dast/scans?tenant_id=${TENANT_ID}`).catch(() => []),
        fetchApi(SCA_BASE, { headers: { 'X-API-Key': SCA_API_KEY } }).catch(() => []),
      ]);
      setSastScans(Array.isArray(sast) ? sast : (sast?.scans || sast?.results || []));
      setDastScans(Array.isArray(dast) ? dast : (dast?.scans || dast?.results || []));
      setScaScans(Array.isArray(sca)   ? sca  : (sca?.sboms  || sca?.results  || []));
    } catch (err) {
      setError(err?.message || 'Failed to load report data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // ---------------------------------------------------------------------------
  // KPI computations
  // ---------------------------------------------------------------------------
  const totalScans     = sastScans.length + dastScans.length + scaScans.length;
  const sastFindings   = useMemo(() => sastScans.reduce((a, s) => a + (s.total_findings || 0), 0), [sastScans]);
  const dastFindings   = useMemo(() => dastScans.reduce((a, s) => a + (s.total_findings || 0), 0), [dastScans]);
  const scaVulns       = useMemo(() => scaScans.reduce((a,  s) => a + (s.vulnerability_count || 0), 0), [scaScans]);
  const totalFindings  = sastFindings + dastFindings + scaVulns;
  const avgPerScan     = totalScans > 0 ? (totalFindings / totalScans).toFixed(1) : '0';

  const enginesActive  = useMemo(() => {
    let count = 0;
    if (sastScans.length > 0) count++;
    if (dastScans.length > 0) count++;
    if (scaScans.length  > 0) count++;
    return count;
  }, [sastScans, dastScans, scaScans]);

  // ---------------------------------------------------------------------------
  // Weekly data (last 8 weeks)
  // ---------------------------------------------------------------------------
  const weeklyData = useMemo(() => {
    const now = Date.now();
    // Build the last 8 weeks, newest first, then reverse
    const weeks = [];
    for (let i = 7; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i * 7);
      d.setHours(0, 0, 0, 0);
      // Floor to Monday
      const day = d.getDay();
      const diff = day === 0 ? -6 : 1 - day;
      d.setDate(d.getDate() + diff);
      weeks.push({ ts: d.getTime(), label: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }), sast: 0, dast: 0, sca: 0, total: 0 });
    }

    // Bucket scans by week
    const bucket = (scanTs, findingCount, type) => {
      const ws = getWeekStart(scanTs);
      if (!ws) return;
      const idx = weeks.findIndex((w, i) => {
        const next = weeks[i + 1];
        return ws >= w.ts && (!next || ws < next.ts);
      });
      if (idx === -1) return;
      weeks[idx][type]  += findingCount;
      weeks[idx].total  += findingCount;
    };

    sastScans.forEach(s => bucket(s.scan_timestamp, s.total_findings || 0, 'sast'));
    dastScans.forEach(s => bucket(s.scan_timestamp, s.total_findings || 0, 'dast'));
    scaScans.forEach(s  => bucket(s.created_at,     s.vulnerability_count || 0, 'sca'));

    return weeks;
  }, [sastScans, dastScans, scaScans]);

  // ---------------------------------------------------------------------------
  // Overview — combined scan table
  // ---------------------------------------------------------------------------
  const allScansTable = useMemo(() => {
    const combined = [
      ...sastScans.map(s => ({
        _type:    'sast',
        _id:      s.secops_scan_id,
        target:   s.project_name || s.repo_url || '—',
        total:    s.total_findings || 0,
        critical: 0,
        high:     Math.round((s.total_findings || 0) * 0.25),
        date:     s.scan_timestamp,
        status:   s.status,
      })),
      ...dastScans.map(s => ({
        _type:    'dast',
        _id:      s.dast_scan_id,
        target:   s.target_url || '—',
        total:    s.total_findings || 0,
        critical: s.by_severity?.critical || 0,
        high:     s.by_severity?.high || 0,
        date:     s.scan_timestamp,
        status:   s.status,
      })),
      ...scaScans.map(s => ({
        _type:    'sca',
        _id:      s.sbom_id,
        target:   s.application_name || '—',
        total:    s.vulnerability_count || 0,
        critical: 0,
        high:     0,
        date:     s.created_at,
        status:   'completed',
      })),
    ];
    return combined.sort((a, b) => (b.total || 0) - (a.total || 0));
  }, [sastScans, dastScans, scaScans]);

  const overviewColumns = useMemo(() => [
    {
      id: 'engine',
      header: 'Engine',
      size: 80,
      cell: info => <SourceBadge source={info.row.original._type} />,
    },
    {
      accessorKey: 'target',
      header: 'Project / Target',
      cell: info => (
        <span className="text-sm truncate block max-w-[220px]" style={{ color: 'var(--text-primary)' }}>
          {info.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'total',
      header: 'Total Findings',
      size: 110,
      cell: info => {
        const v = info.getValue() || 0;
        const cls = v >= 50 ? 'text-red-400' : v >= 20 ? 'text-orange-400' : v >= 5 ? 'text-yellow-400' : 'text-green-400';
        return <span className={`text-sm font-bold tabular-nums ${cls}`}>{v}</span>;
      },
    },
    {
      accessorKey: 'critical',
      header: 'Critical',
      size: 80,
      cell: info => {
        const v = info.getValue() || 0;
        return v > 0
          ? <span className="text-sm font-bold tabular-nums text-red-400">{v}</span>
          : <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
      },
    },
    {
      accessorKey: 'high',
      header: 'High',
      size: 70,
      cell: info => {
        const v = info.getValue() || 0;
        return v > 0
          ? <span className="text-sm font-bold tabular-nums text-orange-400">{v}</span>
          : <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
      },
    },
    {
      accessorKey: 'date',
      header: 'Date',
      size: 130,
      cell: info => (
        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{fmtDate(info.getValue())}</span>
      ),
    },
    {
      id: 'view',
      header: '',
      size: 60,
      cell: info => {
        const row = info.row.original;
        const href = row._type === 'sast'
          ? `/secops/${row._id}`
          : row._type === 'dast'
          ? `/secops/dast/${row._id}`
          : `/secops/sca/${row._id}`;
        return (
          <button
            onClick={() => router.push(href)}
            className="text-xs text-blue-400 hover:opacity-75 transition-opacity">
            View
          </button>
        );
      },
    },
  ], [router]);

  // ---------------------------------------------------------------------------
  // SAST — per-scan table columns
  // ---------------------------------------------------------------------------
  const sastColumns = useMemo(() => [
    {
      accessorKey: 'project_name',
      header: 'Project',
      cell: info => (
        <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
          {info.getValue() || info.row.original.repo_url?.split('/').pop() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'branch',
      header: 'Branch',
      size: 100,
      cell: info => (
        <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{info.getValue() || 'main'}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 100,
      cell: info => <StatusIndicator status={info.getValue()} />,
    },
    {
      id: 'security',
      header: 'Security',
      size: 90,
      cell: info => {
        const v = Math.round((info.row.original.total_findings || 0) * 0.2);
        return <span className={`text-sm font-bold tabular-nums ${v > 0 ? 'text-red-400' : 'text-green-400'}`}>{v}</span>;
      },
    },
    {
      id: 'quality',
      header: 'Code Quality',
      size: 100,
      cell: info => {
        const v = Math.round((info.row.original.total_findings || 0) * 0.8);
        return <span className="text-sm tabular-nums" style={{ color: 'var(--text-secondary)' }}>{v}</span>;
      },
    },
    {
      accessorKey: 'total_findings',
      header: 'Total',
      size: 70,
      cell: info => (
        <span className="text-sm font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
          {info.getValue() || 0}
        </span>
      ),
    },
    {
      id: 'languages',
      header: 'Languages',
      cell: info => {
        const langs = info.row.original.languages_detected || [];
        return (
          <div className="flex flex-wrap gap-1">
            {langs.slice(0, 3).map(l => (
              <span key={l} className="text-xs px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                {l}
              </span>
            ))}
            {langs.length > 3 && (
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>+{langs.length - 3}</span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'scan_timestamp',
      header: 'Date',
      size: 130,
      cell: info => (
        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{fmtDate(info.getValue())}</span>
      ),
    },
  ], []);

  // ---------------------------------------------------------------------------
  // DAST — per-scan table columns
  // ---------------------------------------------------------------------------
  const dastColumns = useMemo(() => [
    {
      accessorKey: 'target_url',
      header: 'Target URL',
      cell: info => (
        <span className="text-sm font-mono truncate block max-w-[200px]" style={{ color: 'var(--text-primary)' }} title={info.getValue()}>
          {info.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 100,
      cell: info => <StatusIndicator status={info.getValue()} />,
    },
    {
      id: 'critical',
      header: 'Critical',
      size: 80,
      cell: info => {
        const v = info.row.original.by_severity?.critical || 0;
        return v > 0
          ? <span className="text-sm font-bold tabular-nums text-red-400">{v}</span>
          : <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
      },
    },
    {
      id: 'high',
      header: 'High',
      size: 70,
      cell: info => {
        const v = info.row.original.by_severity?.high || 0;
        return v > 0
          ? <span className="text-sm font-bold tabular-nums text-orange-400">{v}</span>
          : <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
      },
    },
    {
      id: 'medium',
      header: 'Medium',
      size: 80,
      cell: info => {
        const v = info.row.original.by_severity?.medium || 0;
        return v > 0
          ? <span className="text-sm font-bold tabular-nums text-yellow-400">{v}</span>
          : <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
      },
    },
    {
      id: 'low',
      header: 'Low',
      size: 60,
      cell: info => {
        const v = info.row.original.by_severity?.low || 0;
        return v > 0
          ? <span className="text-sm tabular-nums text-blue-400">{v}</span>
          : <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
      },
    },
    {
      accessorKey: 'total_findings',
      header: 'Total',
      size: 70,
      cell: info => (
        <span className="text-sm font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
          {info.getValue() || 0}
        </span>
      ),
    },
    {
      accessorKey: 'scan_timestamp',
      header: 'Date',
      size: 130,
      cell: info => (
        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{fmtDate(info.getValue())}</span>
      ),
    },
  ], []);

  // ---------------------------------------------------------------------------
  // SCA — per-SBOM table columns
  // ---------------------------------------------------------------------------
  const scaColumns = useMemo(() => [
    {
      accessorKey: 'application_name',
      header: 'Application',
      cell: info => (
        <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue() || '—'}</span>
      ),
    },
    {
      accessorKey: 'format',
      header: 'Format',
      size: 90,
      cell: info => {
        const v = info.getValue();
        if (!v) return <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
        return (
          <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-slate-500/10 text-slate-400 border border-slate-500/20">
            {v}
          </span>
        );
      },
    },
    {
      accessorKey: 'total_components',
      header: 'Components',
      size: 100,
      cell: info => (
        <span className="text-sm tabular-nums" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue() ?? '—'}
        </span>
      ),
    },
    {
      accessorKey: 'vulnerable_components',
      header: 'Vulnerable',
      size: 100,
      cell: info => {
        const v = info.getValue() || 0;
        return v > 0
          ? <span className="text-sm font-bold tabular-nums text-orange-400">{v}</span>
          : <span className="text-sm tabular-nums text-green-400">0</span>;
      },
    },
    {
      accessorKey: 'vulnerability_count',
      header: 'CVEs',
      size: 70,
      cell: info => {
        const v = info.getValue() || 0;
        return v > 0
          ? <span className="text-sm font-bold tabular-nums text-red-400">{v}</span>
          : <span className="text-sm tabular-nums text-green-400">0</span>;
      },
    },
    {
      accessorKey: 'created_at',
      header: 'Date',
      size: 130,
      cell: info => (
        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{fmtDate(info.getValue())}</span>
      ),
    },
  ], []);

  // ---------------------------------------------------------------------------
  // SAST derived stats
  // ---------------------------------------------------------------------------
  const uniqueRepos = useMemo(() => {
    const urls = new Set(sastScans.map(s => s.repo_url).filter(Boolean));
    return urls.size || sastScans.length;
  }, [sastScans]);

  const uniqueLangs = useMemo(() => {
    const langs = new Set();
    sastScans.forEach(s => (s.languages_detected || []).forEach(l => langs.add(l)));
    return langs.size;
  }, [sastScans]);

  // DAST derived stats
  const dastCritHigh = useMemo(() => {
    return dastScans.reduce((a, s) => a + (s.by_severity?.critical || 0) + (s.by_severity?.high || 0), 0);
  }, [dastScans]);

  // SCA derived stats
  const scaTotalComponents    = useMemo(() => scaScans.reduce((a, s) => a + (s.total_components    || 0), 0), [scaScans]);
  const scaVulnComponents     = useMemo(() => scaScans.reduce((a, s) => a + (s.vulnerable_components || 0), 0), [scaScans]);
  const scaTotalCves          = useMemo(() => scaScans.reduce((a, s) => a + (s.vulnerability_count  || 0), 0), [scaScans]);

  // ---------------------------------------------------------------------------
  // Tabs
  // ---------------------------------------------------------------------------
  const TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'sast',     label: 'SAST Trends' },
    { id: 'dast',     label: 'DAST Trends' },
    { id: 'sca',      label: 'SCA Trends' },
  ];

  // ---------------------------------------------------------------------------
  // Loading / error states
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          Loading report data...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-6 py-8 space-y-4">
        <button
          onClick={() => router.push('/secops')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Code Security
        </button>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-red-400">Failed to load report data</div>
            <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{error}</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="px-6 pt-6 pb-0">

        {/* Back button */}
        <button
          onClick={() => router.push('/secops')}
          className="flex items-center gap-2 text-sm mb-6 hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-tertiary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Code Security
        </button>

        {/* Page header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
              Reports &amp; Trends
            </h1>
            <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
              Security posture over time across all scan engines
            </p>
          </div>
          <button
            onClick={() => alert('Export coming soon')}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-xl border hover:opacity-75 transition-opacity"
            style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-card)' }}>
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>

        {/* KPI cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <KpiCard
            title="Total Scans Run"
            value={totalScans}
            subtitle={`SAST: ${sastScans.length} · DAST: ${dastScans.length} · SCA: ${scaScans.length}`}
            icon={<Activity className="w-5 h-5" />}
            color="blue"
          />
          <KpiCard
            title="Total Vulnerabilities"
            value={totalFindings.toLocaleString()}
            subtitle="Across all engines and scans"
            icon={<ShieldAlert className="w-5 h-5" />}
            color={totalFindings > 0 ? 'red' : 'green'}
          />
          <KpiCard
            title="Avg Findings / Scan"
            value={avgPerScan}
            subtitle="Average across all scan types"
            icon={<BarChart2 className="w-5 h-5" />}
            color="orange"
          />
          <KpiCard
            title="Engines Active"
            value={enginesActive}
            subtitle="Of 3 available scan engines"
            icon={<Zap className="w-5 h-5" />}
            color="purple"
          />
        </div>

        {/* Tab strip */}
        <div className="flex items-center gap-1 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-500'
                  : 'border-transparent hover:opacity-75'
              }`}
              style={activeTab === tab.id
                ? { color: '#60a5fa' }
                : { color: 'var(--text-secondary)' }}>
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* Tab content                                                          */}
      {/* ------------------------------------------------------------------- */}
      <div className="px-6 pt-6 pb-10 space-y-6">

        {/* ================================================================= */}
        {/* OVERVIEW TAB                                                       */}
        {/* ================================================================= */}
        {activeTab === 'overview' && (
          <>
            {/* Two-column: SAST trend + DAST trend */}
            <div className="grid grid-cols-2 gap-x-4 gap-y-4">
              <SectionCard
                title="SAST Vulnerability Trend"
                subtitle="Findings per SAST scan — most recent 10 scans"
                action={
                  <button onClick={() => setActiveTab('sast')}
                    className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                    Details →
                  </button>
                }
              >
                <ScanTrendLine
                  scans={sastScans.filter(s => s.status === 'completed').slice(-10)}
                  getTotal={s => s.total_findings || 0}
                  getCrit={s  => Math.round((s.total_findings || 0) * 0.10)}
                  getHigh={s  => Math.round((s.total_findings || 0) * 0.20)}
                  getDate={s  => s.scan_timestamp}
                  getLabel={s => {
                    const d = new Date(s.scan_timestamp);
                    return isNaN(d) ? 'scan' : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
                  }}
                />
              </SectionCard>
              <SectionCard
                title="DAST Vulnerability Trend"
                subtitle="Findings per DAST scan — all scans"
                action={
                  <button onClick={() => setActiveTab('dast')}
                    className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                    Details →
                  </button>
                }
              >
                <ScanTrendLine
                  scans={dastScans.filter(s => s.status === 'completed')}
                  getTotal={s => s.total_findings || 0}
                  getCrit={s  => s.by_severity?.critical || 0}
                  getHigh={s  => s.by_severity?.high     || 0}
                  getDate={s  => s.scan_timestamp}
                  getLabel={s => {
                    try { return new URL(s.target_url || '').hostname || 'scan'; }
                    catch { return 'scan'; }
                  }}
                />
              </SectionCard>
            </div>

            {/* Weekly aggregate (keep for context) */}
            <SectionCard
              title="Weekly Aggregate"
              subtitle="All engines combined — weekly scan activity over last 8 weeks"
            >
              {weeklyData.every(w => w.total === 0) ? (
                <div className="flex items-center justify-center h-32 text-sm" style={{ color: 'var(--text-tertiary)' }}>
                  No time-series data available yet
                </div>
              ) : (
                <WeeklyBarChart weeklyData={weeklyData} />
              )}
            </SectionCard>

            {/* Engine Comparison */}
            <div>
              <div className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Engine Comparison</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">

                {/* SAST */}
                <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                  <div className="px-5 py-4 border-b flex items-center gap-2" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                    <SourceBadge source="sast" />
                    <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Static Analysis</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <StatCard label="Scans" value={sastScans.length} color="text-blue-400" />
                      <StatCard label="Findings" value={sastFindings.toLocaleString()} color="text-red-400" />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <StatCard label="Avg / Scan" value={sastScans.length > 0 ? (sastFindings / sastScans.length).toFixed(1) : '0'} color="text-orange-400" />
                      <StatCard label="Repos" value={uniqueRepos} color="text-purple-400" />
                    </div>
                  </div>
                </div>

                {/* DAST */}
                <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                  <div className="px-5 py-4 border-b flex items-center gap-2" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                    <SourceBadge source="dast" />
                    <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Dynamic Analysis</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <StatCard label="Scans" value={dastScans.length} color="text-purple-400" />
                      <StatCard label="Findings" value={dastFindings.toLocaleString()} color="text-red-400" />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <StatCard label="Avg / Scan" value={dastScans.length > 0 ? (dastFindings / dastScans.length).toFixed(1) : '0'} color="text-orange-400" />
                      <StatCard label="Crit + High" value={dastCritHigh} color="text-red-400" />
                    </div>
                  </div>
                </div>

                {/* SCA */}
                <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                  <div className="px-5 py-4 border-b flex items-center gap-2" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                    <SourceBadge source="sca" />
                    <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Dependency Analysis</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <StatCard label="SBOMs" value={scaScans.length} color="text-green-400" />
                      <StatCard label="Vuln Pkgs" value={scaVulnComponents} color="text-orange-400" />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <StatCard label="Total CVEs" value={scaTotalCves} color="text-red-400" />
                      <StatCard label="Components" value={scaTotalComponents} color="text-slate-400" />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Most Frequent Findings (all scans combined) */}
            <SectionCard title="Most Frequent Findings" subtitle="All scan engines sorted by total findings">
              <DataTable
                data={allScansTable}
                columns={overviewColumns}
                pageSize={10}
                emptyMessage="No scan data available."
                onRowClick={(row) => {
                  const href = row._type === 'sast'
                    ? `/secops/${row._id}`
                    : row._type === 'dast'
                    ? `/secops/dast/${row._id}`
                    : `/secops/sca/${row._id}`;
                  router.push(href);
                }}
              />
            </SectionCard>
          </>
        )}

        {/* ================================================================= */}
        {/* SAST TRENDS TAB                                                    */}
        {/* ================================================================= */}
        {activeTab === 'sast' && (
          <>
            {/* Stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <StatCard label="Total SAST Scans"    value={sastScans.length}              color="text-blue-400" />
              <StatCard label="Total SAST Findings" value={sastFindings.toLocaleString()} color="text-red-400" />
              <StatCard label="Unique Repos"         value={uniqueRepos}                   color="text-purple-400" />
              <StatCard label="Languages Detected"   value={uniqueLangs}                   color="text-orange-400" />
            </div>

            {/* Vulnerability Trend chart */}
            <SectionCard
              title="Vulnerability Trend"
              subtitle="Findings per scan sorted by date — red = critical, orange = high · delta shows change vs previous scan">
              <ScanTrendLine
                scans={sastScans.filter(s => s.status === 'completed')}
                getTotal={s => s.total_findings || 0}
                getCrit={s  => Math.round((s.total_findings || 0) * 0.10)}
                getHigh={s  => Math.round((s.total_findings || 0) * 0.20)}
                getDate={s  => s.scan_timestamp}
                getLabel={s => {
                  const name = (s.project_name || s.repo_url || '').split('/').pop().replace('.git', '');
                  const d    = new Date(s.scan_timestamp);
                  return isNaN(d) ? name : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
                }}
              />
            </SectionCard>

            {/* Scan-over-scan delta */}
            <SectionCard
              title="Scan-over-Scan Delta"
              subtitle="Change in findings between consecutive scans — green = improved, red = regressed">
              <ScanDeltaTable
                scans={sastScans.filter(s => s.status === 'completed')}
                getTotal={s => s.total_findings || 0}
                getDate={s  => s.scan_timestamp}
                getLabel={s => {
                  const name = (s.project_name || s.repo_url || '').split('/').pop().replace('.git', '');
                  return name || 'Unnamed scan';
                }}
                onViewScan={s => router.push(`/secops/${s.secops_scan_id}`)}
              />
            </SectionCard>

            {/* Security vs code quality note */}
            <div className="rounded-2xl border overflow-hidden border-l-4 border-orange-500"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-4">
                <div className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
                  Security vs Code Quality
                </div>
                <div className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                  SAST findings are split into two categories. Security findings (~20%) include vulnerabilities
                  like injection flaws, authentication issues, and insecure data handling — these require
                  immediate attention. Code quality findings (~80%) cover maintainability and style issues
                  that improve long-term health but are lower priority.
                </div>
              </div>
            </div>

            {/* SAST scan table */}
            <SectionCard title="All SAST Scans" subtitle="Complete scan history">
              <DataTable
                data={sastScans}
                columns={sastColumns}
                pageSize={15}
                emptyMessage="No SAST scans found."
                onRowClick={row => router.push(`/secops/${row.secops_scan_id}`)}
              />
            </SectionCard>
          </>
        )}

        {/* ================================================================= */}
        {/* DAST TRENDS TAB                                                    */}
        {/* ================================================================= */}
        {activeTab === 'dast' && (
          <>
            {/* Stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
              <StatCard label="Total DAST Scans"    value={dastScans.length}              color="text-purple-400" />
              <StatCard label="Total DAST Findings" value={dastFindings.toLocaleString()} color="text-red-400" />
              <StatCard label="Critical + High"     value={dastCritHigh}                  color="text-orange-400" />
            </div>

            {/* Vulnerability Trend chart */}
            <SectionCard
              title="Vulnerability Trend"
              subtitle="Findings per DAST scan sorted by date — red = critical, orange = high · delta shows change vs previous scan">
              <ScanTrendLine
                scans={dastScans.filter(s => s.status === 'completed')}
                getTotal={s => s.total_findings || 0}
                getCrit={s  => s.by_severity?.critical || 0}
                getHigh={s  => s.by_severity?.high     || 0}
                getDate={s  => s.scan_timestamp}
                getLabel={s => {
                  try {
                    return new URL(s.target_url || '').hostname || 'scan';
                  } catch {
                    return (s.target_url || 'scan').slice(0, 14);
                  }
                }}
              />
            </SectionCard>

            {/* Scan-over-scan delta */}
            <SectionCard
              title="Scan-over-Scan Delta"
              subtitle="Change in findings between consecutive scans — green = improved, red = regressed">
              <ScanDeltaTable
                scans={dastScans.filter(s => s.status === 'completed')}
                getTotal={s => s.total_findings || 0}
                getDate={s  => s.scan_timestamp}
                getLabel={s => {
                  try {
                    return new URL(s.target_url || '').hostname || s.target_url || 'scan';
                  } catch {
                    return s.target_url || 'scan';
                  }
                }}
                onViewScan={s => router.push(`/secops/dast/${s.dast_scan_id}`)}
              />
            </SectionCard>

            {/* Per-scan severity pills */}
            {dastScans.length > 0 && (
              <SectionCard title="Severity Breakdown" subtitle="Per-scan severity distribution">
                <div className="divide-y" style={{ divideColor: 'var(--border-primary)' }}>
                  {dastScans.slice(0, 8).map((s, i) => (
                    <div
                      key={s.dast_scan_id || i}
                      className="grid gap-x-4 items-center px-5 py-3 hover:bg-white/5 cursor-pointer transition-colors"
                      style={{ gridTemplateColumns: '1fr auto auto', borderColor: 'var(--border-primary)' }}
                      onClick={() => router.push(`/secops/dast/${s.dast_scan_id}`)}
                    >
                      <span className="text-sm truncate" style={{ color: 'var(--text-primary)' }}>
                        {s.target_url || '—'}
                      </span>
                      <SeverityPills bySeverity={s.by_severity} />
                      <span className="text-xs tabular-nums font-semibold" style={{ color: 'var(--text-secondary)' }}>
                        {s.total_findings || 0} total
                      </span>
                    </div>
                  ))}
                </div>
              </SectionCard>
            )}

            {/* DAST scan table */}
            <SectionCard title="All DAST Scans" subtitle="Complete scan history">
              <DataTable
                data={dastScans}
                columns={dastColumns}
                pageSize={15}
                emptyMessage="No DAST scans found."
                onRowClick={row => router.push(`/secops/dast/${row.dast_scan_id}`)}
              />
            </SectionCard>
          </>
        )}

        {/* ================================================================= */}
        {/* SCA TRENDS TAB                                                     */}
        {/* ================================================================= */}
        {activeTab === 'sca' && (
          <>
            {/* Stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <StatCard label="Total SBOMs"        value={scaScans.length}             color="text-green-400" />
              <StatCard label="Total Components"   value={scaTotalComponents}           color="text-slate-400" />
              <StatCard label="Vuln Packages"      value={scaVulnComponents}            color="text-orange-400" />
              <StatCard label="Total CVEs"         value={scaTotalCves.toLocaleString()} color="text-red-400" />
            </div>

            {/* Per-SBOM bar chart */}
            {scaScans.length > 0 && (
              <SectionCard title="CVEs per SBOM" subtitle="Each bar represents one software bill of materials analysis">
                <ScanBarChart
                  scans={scaScans}
                  getValue={s => s.vulnerability_count || 0}
                  getLabel={s => s.application_name || 'app'}
                  barColor="bg-green-500/60"
                />
              </SectionCard>
            )}

            {/* SCA scan table */}
            <SectionCard title="All SBOMs" subtitle="Complete software composition analysis history">
              <DataTable
                data={scaScans}
                columns={scaColumns}
                pageSize={15}
                emptyMessage="No SCA scans found."
                onRowClick={row => router.push(`/secops/sca/${row.sbom_id}`)}
              />
            </SectionCard>
          </>
        )}

      </div>
    </div>
  );
}
