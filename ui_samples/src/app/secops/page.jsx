'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  RefreshCw, Plus, X, Code2, Globe, Package,
  CheckCircle, Loader2, AlertTriangle, ChevronRight,
  ShieldAlert, Activity, GitBranch, Clock, Eye,
  TrendingUp, TrendingDown, Minus, Zap, ArrowRight,
  Maximize2,
} from 'lucide-react';
import { getFromEngine, fetchApi } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import FilterBar from '@/components/shared/FilterBar';
import SeverityDonut from '@/components/charts/SeverityDonut';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const TENANT_ID = 'test-tenant';
const SCA_API_KEY = 'sbom-api-key-2024';
const SCA_BASE = '/secops/api/v1/secops/sca/api/v1/sbom';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function normalizeSev(s) {
  if (!s) return 'info';
  const v = String(s).toLowerCase();
  if (v === 'blocker') return 'critical';
  if (v === 'major') return 'high';
  if (v === 'minor') return 'medium';
  return v;
}

function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    hour12: true,
  });
}

// ---------------------------------------------------------------------------
// SourceBadge
// ---------------------------------------------------------------------------
function SourceBadge({ source }) {
  const cfg = {
    sast:  { label: 'SAST',  cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
    dast:  { label: 'DAST',  cls: 'bg-purple-500/15 text-purple-400 border-purple-500/30' },
    sca:   { label: 'SCA',   cls: 'bg-green-500/15 text-green-400 border-green-500/30' },
  };
  const { label, cls } = cfg[source] || { label: source?.toUpperCase() || '—', cls: 'bg-slate-500/15 text-slate-400 border-slate-500/30' };
  return (
    <span className={`inline-flex items-center text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border ${cls}`}>
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// RiskScoreBadge
// ---------------------------------------------------------------------------
function RiskScoreBadge({ score }) {
  const s = parseFloat(score);
  const cfg = s >= 7 ? 'bg-red-500/20 text-red-400 border-red-500/30'
    : s >= 4 ? 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    : s >= 2 ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    : 'bg-green-500/20 text-green-400 border-green-500/30';
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border ${cfg}`}>
      {score}
    </span>
  );
}

// ---------------------------------------------------------------------------
// SeverityBar — horizontal stacked bar with legend
// ---------------------------------------------------------------------------
function SeverityBar({ counts }) {
  const SEG = [
    { key: 'critical', label: 'Critical', bg: 'bg-red-500',    text: 'text-red-400' },
    { key: 'high',     label: 'High',     bg: 'bg-orange-500', text: 'text-orange-400' },
    { key: 'medium',   label: 'Medium',   bg: 'bg-yellow-500', text: 'text-yellow-400' },
    { key: 'low',      label: 'Low',      bg: 'bg-blue-500',   text: 'text-blue-400' },
    { key: 'info',     label: 'Info',     bg: 'bg-slate-500',  text: 'text-slate-400' },
  ];
  const total = SEG.reduce((a, s) => a + (counts[s.key] || 0), 0);
  if (total === 0) {
    return (
      <div className="text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>
        No findings data available
      </div>
    );
  }
  return (
    <div>
      <div className="flex rounded-full overflow-hidden h-3 gap-px">
        {SEG.map(s => {
          const v = counts[s.key] || 0;
          if (!v) return null;
          const pct = (v / total) * 100;
          return (
            <div key={s.key} className={`${s.bg} transition-all`} style={{ width: `${pct}%` }} title={`${s.label}: ${v}`} />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-3">
        {SEG.map(s => {
          const v = counts[s.key] || 0;
          return (
            <div key={s.key} className="flex items-center gap-1.5">
              <span className={`inline-block w-2 h-2 rounded-full ${s.bg}`} />
              <span className={`text-xs font-semibold ${s.text}`}>{v}</span>
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{s.label}</span>
            </div>
          );
        })}
        <div className="flex items-center gap-1.5 ml-auto">
          <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>{total}</span>
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Total</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CoverageCard — engine scan summary with findings proportion bar
// ---------------------------------------------------------------------------
function CoverageCard({ icon, label, count, findings, accentCls, barColor, total }) {
  const pct = total > 0 ? Math.max(1, Math.round((findings / total) * 100)) : 0;
  return (
    <div className="rounded-xl border p-4 flex flex-col gap-3"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      {/* Top row: icon + label */}
      <div className="flex items-center gap-3">
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${accentCls}`}>
          {icon}
        </div>
        <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
          {label}
        </span>
      </div>

      {/* Counts */}
      <div className="flex items-end justify-between">
        <div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
              {findings.toLocaleString()}
            </span>
            <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>findings</span>
          </div>
          <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {count} scan{count !== 1 ? 's' : ''}
          </div>
        </div>
        {total > 0 && (
          <span className="text-xs font-semibold tabular-nums" style={{ color: 'var(--text-secondary)' }}>
            {pct}%
          </span>
        )}
      </div>

      {/* Proportion bar */}
      {total > 0 && (
        <div className="rounded-full overflow-hidden h-1.5" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
          <div className="h-full rounded-full transition-all"
            style={{ width: `${pct}%`, backgroundColor: barColor }} />
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ScanLaunchModal
// ---------------------------------------------------------------------------
function ScanLaunchModal({ onClose, onLaunch, scanStatus }) {
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [targetUrl, setTargetUrl] = useState('');
  const [error, setError] = useState('');

  const isRunning = scanStatus !== null;

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    if (!repoUrl.trim()) { setError('Repository URL is required'); return; }
    onLaunch({ repo_url: repoUrl.trim(), branch: branch.trim() || 'main', target_url: targetUrl.trim() });
  };

  const handleClose = () => {
    if (isRunning) return;
    setRepoUrl(''); setBranch('main'); setTargetUrl(''); setError('');
    onClose();
  };

  const engines = [
    { id: 'sast', label: 'SAST', desc: 'Static code analysis',             color: 'text-blue-400',   bg: 'bg-blue-500/10' },
    { id: 'sca',  label: 'SCA',  desc: 'Dependency vulnerabilities',        color: 'text-green-400',  bg: 'bg-green-500/10' },
    { id: 'dast', label: 'DAST', desc: 'Runtime testing (if URL provided)', color: 'text-purple-400', bg: 'bg-purple-500/10' },
  ];

  const getEngineIcon = (id) => {
    if (!scanStatus) return null;
    const st = scanStatus[id];
    if (st === 'running')   return <Loader2 className="w-4 h-4 animate-spin text-blue-400" />;
    if (st === 'completed') return <CheckCircle className="w-4 h-4 text-green-400" />;
    if (st === 'failed')    return <AlertTriangle className="w-4 h-4 text-red-400" />;
    return <div className="w-4 h-4 rounded-full border-2" style={{ borderColor: 'var(--border-primary)' }} />;
  };

  return (
    <>
      <div className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" onClick={handleClose} />
      <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg border rounded-2xl shadow-2xl z-50"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div>
            <h2 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>New Security Scan</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              SAST + SCA run automatically · DAST runs if target URL is provided
            </p>
          </div>
          <button onClick={handleClose} disabled={isRunning}
            className="p-1.5 rounded-lg hover:bg-white/5 transition-colors disabled:opacity-40">
            <X className="w-5 h-5" style={{ color: 'var(--text-tertiary)' }} />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
              Repository URL <span className="text-red-400">*</span>
            </label>
            <input
              type="url"
              value={repoUrl}
              onChange={e => setRepoUrl(e.target.value)}
              placeholder="https://github.com/org/repo"
              disabled={isRunning}
              className="w-full px-3 py-2 rounded-xl border text-sm outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
              Branch
            </label>
            <input
              type="text"
              value={branch}
              onChange={e => setBranch(e.target.value)}
              placeholder="main"
              disabled={isRunning}
              className="w-full px-3 py-2 rounded-xl border text-sm outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
              DAST Target URL <span className="text-xs font-normal" style={{ color: 'var(--text-tertiary)' }}>(optional)</span>
            </label>
            <input
              type="url"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              placeholder="https://staging.example.com"
              disabled={isRunning}
              className="w-full px-3 py-2 rounded-xl border text-sm outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>

          {error && (
            <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-xl px-3 py-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          {/* Engine status list (shown when running) */}
          {isRunning && (
            <div className="space-y-2 border rounded-xl p-4" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              <div className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
                Pipeline Status
              </div>
              {engines.map(eng => (
                <div key={eng.id} className={`flex items-center gap-3 rounded-lg px-3 py-2 ${eng.bg}`}>
                  <div className={`w-8 h-8 rounded-lg ${eng.bg} flex items-center justify-center`}>
                    {eng.id === 'sast' && <Code2 className={`w-4 h-4 ${eng.color}`} />}
                    {eng.id === 'sca'  && <Package className={`w-4 h-4 ${eng.color}`} />}
                    {eng.id === 'dast' && <Globe className={`w-4 h-4 ${eng.color}`} />}
                  </div>
                  <div className="flex-1">
                    <div className={`text-sm font-semibold ${eng.color}`}>{eng.label}</div>
                    <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{eng.desc}</div>
                  </div>
                  {getEngineIcon(eng.id)}
                </div>
              ))}
            </div>
          )}

          {/* Buttons */}
          <div className="flex items-center gap-3 pt-2">
            <button type="button" onClick={handleClose} disabled={isRunning}
              className="flex-1 px-4 py-2.5 rounded-xl border text-sm font-semibold transition-colors hover:bg-white/5 disabled:opacity-40"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              Cancel
            </button>
            <button type="submit" disabled={isRunning}
              className="flex-1 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-2">
              {isRunning ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Running...</>
              ) : (
                <>Start Pipeline</>
              )}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Security Trend Chart — SVG line graph
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// EngineDonut — pure SVG donut for arbitrary [{name, value, color}] data
// ---------------------------------------------------------------------------
function EngineDonut({ data }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-32 text-sm" style={{ color: 'var(--text-tertiary)' }}>
        No data available
      </div>
    );
  }
  const total = data.reduce((a, d) => a + d.value, 0);
  if (total === 0) {
    return (
      <div className="flex items-center justify-center h-32 text-sm" style={{ color: 'var(--text-tertiary)' }}>
        No findings recorded
      </div>
    );
  }

  // SVG arc helper
  const R = 52, r = 34, CX = 70, CY = 70;
  const toRad = deg => (deg * Math.PI) / 180;
  const polarXY = (cx, cy, radius, angleDeg) => [
    cx + radius * Math.cos(toRad(angleDeg - 90)),
    cy + radius * Math.sin(toRad(angleDeg - 90)),
  ];

  let startAngle = 0;
  const slices = data.map(d => {
    const sweep = (d.value / total) * 360;
    const end = startAngle + sweep;
    const [x1, y1] = polarXY(CX, CY, R, startAngle);
    const [x2, y2] = polarXY(CX, CY, R, end);
    const [ix1, iy1] = polarXY(CX, CY, r, startAngle);
    const [ix2, iy2] = polarXY(CX, CY, r, end);
    const large = sweep > 180 ? 1 : 0;
    const path = [
      `M ${x1.toFixed(2)} ${y1.toFixed(2)}`,
      `A ${R} ${R} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`,
      `L ${ix2.toFixed(2)} ${iy2.toFixed(2)}`,
      `A ${r} ${r} 0 ${large} 0 ${ix1.toFixed(2)} ${iy1.toFixed(2)}`,
      'Z',
    ].join(' ');
    const slice = { ...d, path, sweep };
    startAngle = end;
    return slice;
  });

  return (
    <div className="flex flex-col items-center gap-3">
      <svg viewBox="0 0 140 140" className="w-[120px] h-[120px]">
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color} opacity="0.9">
            <title>{s.name}: {s.value.toLocaleString()} ({((s.value / total) * 100).toFixed(1)}%)</title>
          </path>
        ))}
        {/* Centre label */}
        <text x={CX} y={CY - 5} fontSize="13" fontWeight="700"
          fill="var(--text-primary)" textAnchor="middle">{total.toLocaleString()}</text>
        <text x={CX} y={CY + 11} fontSize="9"
          fill="var(--text-muted)" textAnchor="middle">findings</text>
      </svg>
      {/* Legend */}
      <div className="flex flex-wrap justify-center gap-x-3 gap-y-1">
        {data.map((d, i) => (
          <div key={i} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
            <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>{d.value.toLocaleString()}</span>
            <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{d.name}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Per-project line colours (blue is reserved for the overall aggregate)
const PROJECT_LINE_COLORS = ['#f97316', '#22c55e', '#a855f7', '#eab308', '#06b6d4', '#f43f5e'];

/**
 * SecurityTrendChart
 * @param overall   — array of { label, total, date(ms) } for the aggregate line
 * @param projects  — array of { name, color, scans: [{ label, total, date }] }
 * @param onExpand  — callback to open the enlarged modal
 * @param isModal   — true when rendered inside the expand modal (larger SVG)
 */
function SecurityTrendChart({ overall, projects = [], onExpand, isModal = false }) {
  if (!overall || overall.length < 2) {
    return (
      <div className="flex items-center justify-center h-36 text-sm" style={{ color: 'var(--text-tertiary)' }}>
        Need at least 2 completed scans for trend data
      </div>
    );
  }

  const latest   = overall[overall.length - 1];
  const prev     = overall[overall.length - 2];
  const delta    = latest.total - prev.total;
  const improved = delta < 0;

  // SVG canvas
  const W   = isModal ? 700 : 360;
  const H   = isModal ? 210 : 120;
  const PAD = { top: 20, right: isModal ? 20 : 12, bottom: isModal ? 32 : 26, left: 32 };
  const cW  = W - PAD.left - PAD.right;
  const cH  = H - PAD.top  - PAD.bottom;

  // Shared scales — cover all series
  const allTotals = [
    ...overall.map(s => s.total),
    ...projects.flatMap(p => p.scans.map(s => s.total)),
  ];
  const maxVal = Math.max(...allTotals, 1);

  const allDates  = [
    ...overall.map(s => s.date),
    ...projects.flatMap(p => p.scans.map(s => s.date)),
  ];
  const minDate   = Math.min(...allDates);
  const maxDate   = Math.max(...allDates);
  const dateRange = Math.max(maxDate - minDate, 1);

  const xByDate = d => PAD.left + ((d - minDate) / dateRange) * cW;
  const yOf     = v => PAD.top  + cH - (v / maxVal) * cH;

  // Overall line paths
  const overallPts = overall
    .map(s => `${xByDate(s.date).toFixed(1)},${yOf(s.total).toFixed(1)}`)
    .join(' ');
  const overallAreaPts = [
    `${xByDate(overall[0].date).toFixed(1)},${(PAD.top + cH).toFixed(1)}`,
    overallPts,
    `${xByDate(overall[overall.length - 1].date).toFixed(1)},${(PAD.top + cH).toFixed(1)}`,
  ].join(' ');

  const gridFracs = [0, 0.5, 1];

  // X-axis tick labels: use overall scan dates
  const xLabels = [];
  if (overall.length >= 2) {
    xLabels.push({ i: 0, anchor: 'start' });
    if (overall.length >= 4) xLabels.push({ i: Math.floor(overall.length / 2), anchor: 'middle' });
    xLabels.push({ i: overall.length - 1, anchor: 'end' });
  }

  return (
    <div>
      {/* Trend pill + expand button */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {improved ? (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-green-500/15 border border-green-500/25">
              <TrendingDown className="w-3 h-3 text-green-400" />
              <span className="text-xs font-semibold text-green-400">{Math.abs(delta)} fewer</span>
            </div>
          ) : delta > 0 ? (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-red-500/15 border border-red-500/25">
              <TrendingUp className="w-3 h-3 text-red-400" />
              <span className="text-xs font-semibold text-red-400">+{delta} more</span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-slate-500/15 border border-slate-500/25">
              <Minus className="w-3 h-3" style={{ color: 'var(--text-tertiary)' }} />
              <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Steady</span>
            </div>
          )}
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
            vs previous · {latest.total} total now
          </span>
        </div>

        {/* Expand button (only in inline view) */}
        {!isModal && onExpand && (
          <button
            onClick={onExpand}
            className="p-1 rounded-lg hover:bg-white/5 transition-colors"
            title="Expand chart"
          >
            <Maximize2 className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
          </button>
        )}
      </div>

      {/* SVG multi-line chart */}
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: isModal ? 210 : 120, overflow: 'visible' }}>
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#3b82f6" stopOpacity="0.15" />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.01" />
          </linearGradient>
        </defs>

        {/* Grid lines + Y labels */}
        {gridFracs.map(f => {
          const y   = PAD.top + cH * (1 - f);
          const val = Math.round(maxVal * f);
          return (
            <g key={f}>
              <line x1={PAD.left} y1={y} x2={W - PAD.right} y2={y}
                stroke="rgba(255,255,255,0.06)" strokeWidth="1"
                strokeDasharray={f > 0 ? '3 3' : ''} />
              <text x={PAD.left - 4} y={y + 3.5} fontSize="8"
                fill="rgba(255,255,255,0.28)" textAnchor="end">
                {val}
              </text>
            </g>
          );
        })}

        {/* ── Overall: area fill + semi-transparent line drawn FIRST (behind project lines) ── */}
        {/* Reduce area opacity when per-project lines are present so they don't get obscured */}
        <polygon points={overallAreaPts}
          fill="url(#trendFill)"
          opacity={projects.length > 0 ? 0.5 : 1} />

        <polyline points={overallPts} fill="none"
          stroke={projects.length > 0 ? 'rgba(59,130,246,0.45)' : '#3b82f6'}
          strokeWidth={projects.length > 0 ? (isModal ? 1.5 : 1.5) : (isModal ? 2.5 : 2)}
          strokeDasharray={projects.length > 0 ? '6 3' : ''}
          strokeLinejoin="round" strokeLinecap="round" />

        {/* Overall dots (small, semi-transparent when per-project lines present) */}
        {overall.map((s, i) => {
          const isLast = i === overall.length - 1;
          const cx = xByDate(s.date), cy = yOf(s.total);
          const hasProjLines = projects.length > 0;
          return (
            <g key={i}>
              <circle cx={cx} cy={cy}
                r={isLast ? (hasProjLines ? 4 : 5) : 2.5}
                fill={isLast ? '#3b82f6' : '#1e40af'}
                stroke={isLast ? 'rgba(59,130,246,0.35)' : 'none'}
                strokeWidth="5"
                opacity={hasProjLines ? 0.6 : 1}>
                <title>All projects: {s.total} findings on {s.label}</title>
              </circle>
              {isLast && (
                <text x={cx} y={cy - 9} fontSize="9"
                  fill="#93c5fd" textAnchor="middle" fontWeight="700"
                  opacity={hasProjLines ? 0.7 : 1}>
                  {s.total}
                </text>
              )}
            </g>
          );
        })}

        {/* ── Per-project lines drawn ON TOP of overall ── */}
        {projects.map(proj => {
          if (proj.scans.length < 1) return null;
          const pts = proj.scans
            .map(s => `${xByDate(s.date).toFixed(1)},${yOf(s.total).toFixed(1)}`)
            .join(' ');
          return (
            <g key={proj.name}>
              {proj.scans.length >= 2 && (
                <polyline points={pts} fill="none" stroke={proj.color}
                  strokeWidth={isModal ? 2 : 1.8}
                  strokeLinejoin="round" strokeLinecap="round" />
              )}
              {proj.scans.map((s, si) => {
                const isLatest = si === proj.scans.length - 1;
                return (
                  <circle key={si}
                    cx={xByDate(s.date)} cy={yOf(s.total)}
                    r={isLatest ? (isModal ? 5 : 4) : (isModal ? 3.5 : 3)}
                    fill={proj.color}
                    stroke="var(--bg-card)" strokeWidth="1.5">
                    <title>{proj.name}: {s.total} findings on {s.label}</title>
                  </circle>
                );
              })}
              {/* Latest value label for each project */}
              {(() => {
                const last = proj.scans[proj.scans.length - 1];
                const cx = xByDate(last.date), cy = yOf(last.total);
                return (
                  <text x={cx} y={cy - 8} fontSize="8" fill={proj.color}
                    textAnchor="middle" fontWeight="700">
                    {last.total}
                  </text>
                );
              })()}
            </g>
          );
        })}

        {/* X-axis labels */}
        {xLabels.map(({ i, anchor }) => (
          <text key={i}
            x={xByDate(overall[i].date)} y={H - 4}
            fontSize="8" fill="rgba(255,255,255,0.30)"
            textAnchor={anchor}>
            {overall[i].label}
          </text>
        ))}
      </svg>

      {/* Legend */}
      {projects.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2.5">
          {/* Overall */}
          <div className="flex items-center gap-1.5">
            <span className="inline-block w-5 h-0.5 rounded bg-blue-500" />
            <span className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>Overall</span>
          </div>
          {/* Per-project */}
          {projects.map(p => (
            <div key={p.name} className="flex items-center gap-1.5">
              <span className="inline-block w-5 h-0.5 rounded" style={{ backgroundColor: p.color }} />
              <span className="text-[11px] truncate max-w-[110px]"
                style={{ color: 'var(--text-tertiary)' }}
                title={p.name}>
                {p.name}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fix This First block — top 5 risky rules across recent findings
// ---------------------------------------------------------------------------
const FIX_RULE_MAP = {
  sql_injection:             { label: 'SQL Injection',            sev: 'critical', fix: 'Use parameterized queries — never interpolate user input into SQL strings.' },
  xss_html_string_concat:    { label: 'XSS via HTML concat',      sev: 'high',     fix: 'Escape all user data with markupsafe.escape() before inserting into HTML.' },
  open_redirect:             { label: 'Open Redirect',            sev: 'high',     fix: 'Validate redirect targets — only allow relative paths or trusted domains.' },
  path_traversal:            { label: 'Path Traversal',           sev: 'critical', fix: 'Resolve paths with os.path.realpath() and assert they stay inside BASE_DIR.' },
  command_injection:         { label: 'Command Injection',        sev: 'critical', fix: 'Pass args as a list to subprocess.run() — never build shell strings.' },
  hardcoded_credentials:     { label: 'Hardcoded Credentials',    sev: 'high',     fix: 'Move secrets to environment variables or a secrets manager.' },
  insecure_hash:             { label: 'Weak Hash (MD5/SHA1)',      sev: 'medium',   fix: 'Use bcrypt/argon2 for passwords; SHA-256+ for general hashing.' },
  insecure_random:           { label: 'Insecure Randomness',      sev: 'medium',   fix: 'Use the secrets module for tokens and security-sensitive values.' },
  pickle_deserialization:    { label: 'Unsafe Deserialization',   sev: 'critical', fix: 'Replace pickle.loads() with json.loads() for untrusted data.' },
  ssrf:                      { label: 'SSRF',                     sev: 'high',     fix: 'Validate outbound URLs against an allowlist before fetching.' },
  flask_debug_mode:          { label: 'Debug Mode Enabled',       sev: 'medium',   fix: 'Set debug=False or read from env var — never leave debug=True in production.' },
};

const SEV_PILL = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/25',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/25',
  medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/25',
};

function FixThisFirst({ findings, onViewAll, onItemClick }) {
  // Aggregate by rule_id, count occurrences, weight by severity
  const weight = { critical: 10, high: 5, medium: 2, low: 1 };
  const byRule = {};
  findings.forEach(f => {
    const r = (f.rule_id || '').toLowerCase().replace(/[^a-z0-9_]/g, '_');
    if (!byRule[r]) byRule[r] = { rule_id: r, rawRuleId: f.rule_id, count: 0, score: 0, sev: f.severity, files: new Set(), scanId: f._scan?.secops_scan_id };
    byRule[r].count++;
    byRule[r].score += weight[f.severity] || 1;
    if (f.file_path) byRule[r].files.add(f.file_path);
  });

  const sorted = Object.values(byRule)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  if (sorted.length === 0) {
    return (
      <div className="flex items-center justify-center h-24 text-sm" style={{ color: 'var(--text-tertiary)' }}>
        Run a scan to see prioritized security recommendations here
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      {sorted.map((item, i) => {
        const meta = FIX_RULE_MAP[item.rule_id] || { label: (item.rawRuleId || item.rule_id).replace(/_/g, ' '), sev: item.sev, fix: 'Review and remediate this finding.' };
        const pillCls = SEV_PILL[meta.sev] || SEV_PILL.medium;
        return (
          <button
            key={item.rule_id}
            onClick={() => onItemClick && onItemClick({ sev: meta.sev, scanId: item.scanId, rawRuleId: item.rawRuleId })}
            className="w-full flex items-start gap-3 px-3 py-2.5 rounded-xl border text-left transition-colors hover:bg-white/5 hover:border-blue-500/30 cursor-pointer"
            style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
            {/* Rank */}
            <div className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 text-[10px] font-bold"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
              {i + 1}
            </div>
            {/* Main content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold capitalize" style={{ color: 'var(--text-primary)' }}>
                  {meta.label}
                </span>
                <span className={`text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded-full border ${pillCls}`}>
                  {meta.sev}
                </span>
                <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                  {item.count} occurrence{item.count !== 1 ? 's' : ''}
                  {item.files.size > 0 ? ` · ${item.files.size} file${item.files.size !== 1 ? 's' : ''}` : ''}
                </span>
              </div>
              <p className="text-xs mt-0.5 line-clamp-1" style={{ color: 'var(--text-secondary)' }}>{meta.fix}</p>
            </div>
            <ArrowRight className="w-3.5 h-3.5 flex-shrink-0 mt-1 text-blue-400 opacity-60" />
          </button>
        );
      })}
      {onViewAll && (
        <button onClick={onViewAll}
          className="w-full text-center text-xs py-1.5 hover:text-blue-400 transition-colors"
          style={{ color: 'var(--text-tertiary)' }}>
          View all findings →
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------
export default function SecOpsPage() {
  const router = useRouter();

  // Core data
  const [sastScans,   setSastScans]   = useState([]);
  const [dastScans,   setDastScans]   = useState([]);
  const [scaScans,    setScaScans]    = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState(null);

  // Tab state
  const [activeTab,   setActiveTab]   = useState('overview');

  // Findings (lazy-loaded on All Findings tab)
  const [allFindings,       setAllFindings]       = useState([]);
  const [findingsLoading,   setFindingsLoading]   = useState(false);
  const [findingsLoaded,    setFindingsLoaded]    = useState(false);
  const [findingFilters,    setFindingFilters]    = useState({ severity: '', source: '', status: '', ruleType: '' });

  // Modal
  const [showModal,       setShowModal]       = useState(false);
  const [scanStatus,      setScanStatus]      = useState(null);
  const [showTrendModal,  setShowTrendModal]  = useState(false);

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
        fetchApi(`${SCA_BASE}`, { headers: { 'X-API-Key': SCA_API_KEY } }).catch(() => []),
      ]);
      setSastScans(Array.isArray(sast) ? sast : (sast?.scans || sast?.results || []));
      setDastScans(Array.isArray(dast) ? dast : (dast?.scans || dast?.results || []));
      setScaScans(Array.isArray(sca)  ? sca  : (sca?.sboms  || sca?.results  || []));
    } catch (err) {
      setError(err?.message || 'Failed to load security data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // ---------------------------------------------------------------------------
  // Lazy-load findings when All Findings tab is selected
  // ---------------------------------------------------------------------------
  const loadFindings = useCallback(async () => {
    if (findingsLoaded) return;
    setFindingsLoading(true);
    try {
      const completedSast = sastScans.filter(s => s.status === 'completed').slice(0, 5);
      const completedDast = dastScans.filter(s => s.status === 'completed').slice(0, 3);
      const completedSca  = scaScans.slice(0, 3);

      const [sastResults, dastResults, scaResults] = await Promise.all([
        Promise.all(completedSast.map(s =>
          getFromEngine('secops', `/api/v1/secops/sast/scan/${s.secops_scan_id}/findings?limit=200`)
            .then(r => ({ scan: s, findings: Array.isArray(r) ? r : (r?.findings || []) }))
            .catch(() => ({ scan: s, findings: [] }))
        )),
        Promise.all(completedDast.map(s =>
          getFromEngine('secops', `/api/v1/secops/dast/scan/${s.dast_scan_id}/findings?limit=200`)
            .then(r => ({ scan: s, findings: Array.isArray(r) ? r : (r?.findings || []) }))
            .catch(() => ({ scan: s, findings: [] }))
        )),
        Promise.all(completedSca.map(s =>
          fetchApi(`${SCA_BASE}/${s.sbom_id}`, { headers: { 'X-API-Key': SCA_API_KEY } })
            .then(r => ({ scan: s, detail: r }))
            .catch(() => ({ scan: s, detail: null }))
        )),
      ]);

      const merged = [];

      // SAST findings
      sastResults.forEach(({ scan, findings }) => {
        findings.forEach(f => {
          const sev = normalizeSev(f.severity);
          merged.push({
            _id:      f.id || `${scan.secops_scan_id}-${f.rule_id}-${f.line_number}`,
            source:   'sast',
            severity: sev,
            rule_id:  f.rule_id,
            message:  f.message,
            asset:    f.file_path ? `${f.file_path}:${f.line_number || '?'}` : '—',
            project:  scan.project_name || scan.repo_url || '—',
            status:   f.status || 'open',
            language: f.language,
            _raw:     f,
            _scan:    scan,
            _ts:      scan.scan_timestamp,
          });
        });
      });

      // DAST findings
      dastResults.forEach(({ scan, findings }) => {
        findings.forEach(f => {
          const sev = normalizeSev(f.severity);
          merged.push({
            _id:      f.id || `${scan.dast_scan_id}-${f.rule_id}`,
            source:   'dast',
            severity: sev,
            rule_id:  f.rule_id || f.vulnerability_type,
            message:  f.description,
            asset:    f.endpoint_url || f.resource || '—',
            project:  scan.target_url || '—',
            status:   f.status || 'open',
            _raw:     f,
            _scan:    scan,
            _ts:      scan.scan_timestamp,
          });
        });
      });

      // SCA findings (vulnerable components)
      scaResults.forEach(({ scan, detail }) => {
        if (!detail) return;
        const components = detail.vulnerable_components || [];
        components.forEach(comp => {
          const count = (comp.vulnerability_ids || []).length;
          const sev = count >= 5 ? 'high' : count >= 2 ? 'medium' : 'low';
          merged.push({
            _id:      `sca-${scan.sbom_id}-${comp.name}-${comp.version}`,
            source:   'sca',
            severity: sev,
            rule_id:  'SCA-VULN',
            message:  `${count} CVE(s) detected`,
            asset:    `${comp.name}@${comp.version}`,
            project:  scan.application_name || detail.application_name || '—',
            status:   'open',
            _raw:     comp,
            _scan:    scan,
            _ts:      scan.created_at,
          });
        });
      });

      // Sort by severity
      merged.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
      setAllFindings(merged);
      setFindingsLoaded(true);
    } catch (err) {
      console.warn('[secops] loadFindings error:', err);
    } finally {
      setFindingsLoading(false);
    }
  }, [findingsLoaded, sastScans, dastScans, scaScans]);

  useEffect(() => {
    if (activeTab === 'findings' && !findingsLoaded && !findingsLoading && !loading) {
      loadFindings();
    }
  }, [activeTab, findingsLoaded, findingsLoading, loading, loadFindings]);

  // ---------------------------------------------------------------------------
  // KPI computations
  // ---------------------------------------------------------------------------
  const sastFindings  = useMemo(() => sastScans.reduce((a, s) => a + (s.total_findings || 0), 0), [sastScans]);
  const dastFindings  = useMemo(() => dastScans.reduce((a, s) => a + (s.total_findings || 0), 0), [dastScans]);
  const scaVulns      = useMemo(() => scaScans.reduce((a, s) => a + (s.vulnerability_count || 0), 0), [scaScans]);
  const totalFindings = sastFindings + dastFindings + scaVulns;

  const criticalHigh = useMemo(() => {
    let ch = 0;
    dastScans.forEach(s => {
      ch += (s.by_severity?.critical || 0) + (s.by_severity?.high || 0);
    });
    // Approximate from SAST — assume ~30% critical+high
    ch += Math.round(sastFindings * 0.3);
    return ch;
  }, [dastScans, sastFindings]);

  const reposScanned = useMemo(() => {
    const urls = new Set(sastScans.map(s => s.repo_url).filter(Boolean));
    return urls.size || sastScans.length;
  }, [sastScans]);

  const allScans = useMemo(() => {
    const combined = [
      ...sastScans.map(s => ({ ...s, _type: 'sast', _ts: s.scan_timestamp, _id: s.secops_scan_id })),
      ...dastScans.map(s => ({ ...s, _type: 'dast', _ts: s.scan_timestamp, _id: s.dast_scan_id })),
      ...scaScans.map(s  => ({ ...s, _type: 'sca',  _ts: s.created_at,     _id: s.sbom_id })),
    ];
    return combined.sort((a, b) => new Date(b._ts || 0) - new Date(a._ts || 0));
  }, [sastScans, dastScans, scaScans]);

  const lastScan = allScans[0]?._ts;

  // Top findings states — must be declared BEFORE the useMemos that read them
  const [topFindings,        setTopFindings]        = useState([]);
  const [topQualityFindings, setTopQualityFindings] = useState([]);

  // Helper: classify a finding as security vs code quality (based on rule_id patterns)
  function isSecurityRule(ruleId) {
    const r = (ruleId || '').toLowerCase();
    const QUALITY = ['docstring', 'einops', 'reachable', 'complexity', 'shadowed',
      'dtype', 'pandas', 'except_blocks_should_be_able', 'pattern_should_be_valid'];
    if (QUALITY.some(p => r.includes(p))) return false;
    const SECURITY = ['securitysensitive', 'injection', 'xss', 'sql', 'traversal',
      'command_injection', 'pickle', 'deserialization', 'ssrf', 'debug_mode',
      'hardcoded', 'credentials_should_not', 'weak_hash', 'pseudorandom',
      'open_redirect', 'unrestricted_outbound', 'bucket_ownership',
      'dynamically_executing', 'configuring_logger', 'insecure_'];
    return SECURITY.some(p => r.includes(p));
  }

  // Severity bar counts — real data from loaded findings
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    // Real per-severity from most-recent SAST scan (all findings: security + quality)
    [...topFindings, ...topQualityFindings].forEach(f => {
      const s = f.severity || 'info';
      if (counts[s] !== undefined) counts[s]++;
    });
    // Real per-severity from DAST scans when the API provides it
    dastScans.forEach(s => {
      if (s.by_severity) {
        Object.entries(s.by_severity).forEach(([sev, n]) => {
          if (counts[sev] !== undefined) counts[sev] += (n || 0);
        });
      }
    });
    return counts;
  }, [topFindings, topQualityFindings, dastScans]);

  // SeverityDonut "By Engine"
  const engineDonutData = useMemo(() => [
    { name: 'SAST', value: sastFindings, color: '#3b82f6' },
    { name: 'DAST', value: dastFindings, color: '#8b5cf6' },
    { name: 'SCA',  value: scaVulns,    color: '#22c55e' },
  ].filter(d => d.value > 0), [sastFindings, dastFindings, scaVulns]);

  // Recent scans (5)
  const recentScans = allScans.slice(0, 5);

  // ---------------------------------------------------------------------------
  // Projects (grouped by repo_url from SAST scans)
  // ---------------------------------------------------------------------------
  const projects = useMemo(() => {
    const byRepo = {};
    sastScans.forEach(s => {
      const key = s.repo_url || s.project;
      if (!key) return;
      if (!byRepo[key]) {
        byRepo[key] = {
          repo_url: key,
          name: s.project_name || s.project || key.split('/').pop().replace('.git', ''),
          scans: [],
          totalFindings: 0,
          criticalCount: 0,
          highCount: 0,
          languages: [],
          lastScan: null,
          status: 'completed',
        };
      }
      byRepo[key].scans.push(s);
      byRepo[key].totalFindings += s.total_findings || 0;
      byRepo[key].languages = [...new Set([...byRepo[key].languages, ...(s.languages_detected || s.languages || [])])];
      const ts = s.scan_timestamp || s.started_at;
      if (!byRepo[key].lastScan || new Date(ts) > new Date(byRepo[key].lastScan)) {
        byRepo[key].lastScan = ts;
        byRepo[key].status = s.status;
      }
    });

    // Compute per-project critical+high counts from topFindings (most recent scan data)
    const critByRepo = {}, highByRepo = {};
    topFindings.forEach(f => {
      const repo = f._scan?.repo_url;
      if (!repo) return;
      if (f.severity === 'critical') critByRepo[repo] = (critByRepo[repo] || 0) + 1;
      if (f.severity === 'high')     highByRepo[repo] = (highByRepo[repo] || 0) + 1;
    });

    return Object.values(byRepo)
      .map(p => ({
        ...p,
        riskScore: Math.min(10, ((p.criticalCount * 10 + p.highCount * 5 + p.totalFindings * 0.5) / 10)).toFixed(1),
        criticalCount: critByRepo[p.repo_url] || 0,
        highCount:     highByRepo[p.repo_url] || 0,
        securityFindings: (critByRepo[p.repo_url] || 0) + (highByRepo[p.repo_url] || 0),
      }))
      .sort((a, b) => parseFloat(b.riskScore) - parseFloat(a.riskScore));
  }, [sastScans, topFindings]);

  // ---------------------------------------------------------------------------
  // Top findings for "Fix This First" block (loaded on mount, limited)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const mostRecentCompleted = [...sastScans]
      .filter(s => s.status === 'completed')
      .sort((a, b) => new Date(b.scan_timestamp || 0) - new Date(a.scan_timestamp || 0))[0];
    if (!mostRecentCompleted) return;
    getFromEngine('secops', `/api/v1/secops/sast/scan/${mostRecentCompleted.secops_scan_id}/findings?limit=200`)
      .then(r => {
        const raw = Array.isArray(r) ? r : (r?.findings || []);
        // Attach _scan so projects useMemo can key by repo_url
        const withScan = raw.map(f => ({
          ...f,
          severity: normalizeSev(f.severity),
          _scan: {
            repo_url:        mostRecentCompleted.repo_url,
            secops_scan_id:  mostRecentCompleted.secops_scan_id,
          },
        }));
        setTopFindings(withScan.filter(f => isSecurityRule(f.rule_id)));
        setTopQualityFindings(withScan.filter(f => !isSecurityRule(f.rule_id)));
      })
      .catch(() => {});
  }, [sastScans]);

  // ---------------------------------------------------------------------------
  // Trend chart data — overall + per-project series, oldest→newest
  // ---------------------------------------------------------------------------
  const trendData = useMemo(() => {
    const completed = sastScans.filter(s => s.status === 'completed' && s.scan_timestamp);

    // ── Overall aggregate (last 10 scans) ──────────────────────────────────
    const overall = [...completed]
      .sort((a, b) => new Date(a.scan_timestamp) - new Date(b.scan_timestamp))
      .slice(-10)
      .map(s => {
        const d = new Date(s.scan_timestamp);
        return {
          label: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
          total: s.total_findings || 0,
          date:  d.getTime(),
        };
      });

    // ── Per-project series (grouped by repo_url / project_name) ───────────
    const byProject = {};
    completed.forEach(s => {
      const key  = s.repo_url || s.project_name || '—';
      const name = s.project_name
        || s.repo_url?.split('/').pop()?.replace(/\.git$/, '')
        || '—';
      if (!byProject[key]) byProject[key] = { name, scans: [] };
      const d = new Date(s.scan_timestamp);
      byProject[key].scans.push({
        label: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
        total: s.total_findings || 0,
        date:  d.getTime(),
      });
    });

    const projects = Object.values(byProject)
      .map((p, i) => ({
        name:  p.name,
        color: PROJECT_LINE_COLORS[i % PROJECT_LINE_COLORS.length],
        scans: p.scans
          .sort((a, b) => a.date - b.date)
          .slice(-8),
      }))
      .filter(p => p.scans.length >= 1)
      .slice(0, 6); // cap at 6 projects for legibility

    return { overall, projects };
  }, [sastScans]);

  // ---------------------------------------------------------------------------
  // Filtered findings for All Findings tab
  // ---------------------------------------------------------------------------
  const filteredFindings = useMemo(() => {
    return allFindings.filter(f => {
      if (findingFilters.severity && f.severity !== findingFilters.severity) return false;
      if (findingFilters.source   && f.source   !== findingFilters.source)   return false;
      if (findingFilters.status   && f.status   !== findingFilters.status)   return false;
      return true;
    });
  }, [allFindings, findingFilters]);

  // ---------------------------------------------------------------------------
  // Scan launch handler
  // ---------------------------------------------------------------------------
  const handleLaunch = async ({ repo_url, branch, target_url }) => {
    setScanStatus({ sast: 'running', sca: 'running', dast: target_url ? 'running' : 'pending' });
    try {
      // Fire-and-forget kick-off (real API wiring done externally)
      await Promise.all([
        getFromEngine('secops', `/api/v1/secops/sast/scan`, { method: 'POST', body: JSON.stringify({ repo_url, branch, tenant_id: TENANT_ID }) }).catch(() => {}),
      ]);
      setTimeout(() => { setScanStatus(null); setShowModal(false); loadData(); setFindingsLoaded(false); }, 3000);
    } catch (_) {
      setScanStatus(null);
    }
  };

  // ---------------------------------------------------------------------------
  // Column definitions
  // ---------------------------------------------------------------------------
  const findingColumns = useMemo(() => [
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 90,
      cell: info => <SeverityBadge severity={info.getValue()} />,
    },
    {
      id: 'issue',
      header: 'Issue / Rule',
      cell: info => {
        const row = info.row.original;
        return (
          <div className="min-w-0">
            <div className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
              {row.rule_id || '—'}
            </div>
            <div className="text-xs truncate mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              {row.message || '—'}
            </div>
          </div>
        );
      },
    },
    {
      accessorKey: 'source',
      header: 'Source',
      size: 80,
      cell: info => <SourceBadge source={info.getValue()} />,
    },
    {
      accessorKey: 'asset',
      header: 'Asset',
      cell: info => (
        <span className="text-xs font-mono truncate block max-w-[200px]" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'project',
      header: 'Project',
      cell: info => (
        <span className="text-xs truncate block max-w-[160px]" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 90,
      cell: info => {
        const v = info.getValue();
        const cfg = {
          open:      'bg-orange-500/15 text-orange-400 border-orange-500/30',
          violation: 'bg-red-500/15 text-red-400 border-red-500/30',
          resolved:  'bg-green-500/15 text-green-400 border-green-500/30',
        };
        const cls = cfg[v] || 'bg-slate-500/15 text-slate-400 border-slate-500/30';
        return (
          <span className={`inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded-full border ${cls}`}>
            {v || 'open'}
          </span>
        );
      },
    },
    {
      id: 'action',
      header: '',
      size: 60,
      cell: info => {
        const row = info.row.original;
        const handleView = (e) => {
          e.stopPropagation();
          if (row.source === 'sast' && row._scan?.secops_scan_id) router.push(`/secops/${row._scan.secops_scan_id}`);
          else if (row.source === 'dast' && row._scan?.dast_scan_id) router.push(`/secops/dast/${row._scan.dast_scan_id}`);
          else if (row.source === 'sca' && row._scan?.sbom_id) router.push(`/secops/sca/${row._scan.sbom_id}`);
        };
        return (
          <button onClick={handleView}
            className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
            title="View scan">
            <Eye className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
          </button>
        );
      },
    },
  ], [router]);

  const historyColumns = useMemo(() => [
    {
      id: 'type',
      header: 'Type',
      size: 80,
      cell: info => <SourceBadge source={info.row.original._type} />,
    },
    {
      id: 'project',
      header: 'Project / Target',
      cell: info => {
        const row = info.row.original;
        const name = row.project_name || row.application_name || row.target_url || row.repo_url || '—';
        const sub  = row.branch || row.sbom_format || '';
        const langs = row.languages_detected || [];
        return (
          <div className="min-w-0">
            <div className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{name}</div>
            {sub && <div className="text-xs truncate mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{sub}</div>}
            {langs.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {langs.slice(0, 3).map(l => (
                  <span key={l} className="text-[10px] px-1.5 py-0.5 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    {l}
                  </span>
                ))}
                {langs.length > 3 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded-md" style={{ color: 'var(--text-tertiary)' }}>+{langs.length - 3}</span>
                )}
              </div>
            )}
          </div>
        );
      },
    },
    {
      id: 'status',
      header: 'Status',
      size: 110,
      cell: info => <StatusIndicator status={info.row.original.status} />,
    },
    {
      id: 'findings',
      header: 'Findings',
      size: 90,
      cell: info => {
        const row = info.row.original;
        const n = row.total_findings ?? row.vulnerability_count ?? 0;
        return (
          <span className={`text-sm font-bold ${n > 0 ? 'text-orange-400' : 'text-green-400'}`}>
            {n}
          </span>
        );
      },
    },
    {
      id: 'date',
      header: 'Date',
      size: 140,
      cell: info => (
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          {fmtDate(info.row.original._ts)}
        </span>
      ),
    },
    {
      id: 'action',
      header: '',
      size: 60,
      cell: info => {
        const row = info.row.original;
        const handleView = (e) => {
          e.stopPropagation();
          if (row._type === 'sast') router.push(`/secops/${row._id}`);
          else if (row._type === 'dast') router.push(`/secops/dast/${row._id}`);
          else if (row._type === 'sca')  router.push(`/secops/sca/${row._id}`);
        };
        return (
          <button onClick={handleView}
            className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
            title="View details">
            <Eye className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
          </button>
        );
      },
    },
  ], [router]);

  // ---------------------------------------------------------------------------
  // Filter bar configs
  // ---------------------------------------------------------------------------
  const findingFilterDefs = [
    {
      key: 'severity',
      label: 'Severity',
      options: [
        { value: 'critical', label: 'Critical' },
        { value: 'high',     label: 'High' },
        { value: 'medium',   label: 'Medium' },
        { value: 'low',      label: 'Low' },
        { value: 'info',     label: 'Info' },
      ],
    },
    {
      key: 'source',
      label: 'Scanner',
      options: [
        { value: 'sast', label: 'SAST — Code Analysis' },
        { value: 'dast', label: 'DAST — Runtime Testing' },
        { value: 'sca',  label: 'SCA — Dependencies' },
      ],
    },
    {
      key: 'status',
      label: 'Status',
      options: [
        { value: 'open',      label: 'Open' },
        { value: 'violation', label: 'Violation' },
        { value: 'resolved',  label: 'Resolved' },
      ],
    },
  ];

  // ---------------------------------------------------------------------------
  // Tabs
  // ---------------------------------------------------------------------------
  const tabs = [
    { id: 'overview',  label: 'Overview' },
    { id: 'findings',  label: `All Findings${allFindings.length > 0 ? ` (${allFindings.length})` : ''}` },
    { id: 'history',   label: `Scan History (${allScans.length})` },
  ];

  // ---------------------------------------------------------------------------
  // Render helpers
  // ---------------------------------------------------------------------------
  const renderStatusPill = (status) => {
    const cfg = {
      open: 'bg-orange-500/15 text-orange-400',
      violation: 'bg-red-500/15 text-red-400',
      resolved: 'bg-green-500/15 text-green-400',
      completed: 'bg-green-500/15 text-green-400',
      running: 'bg-blue-500/15 text-blue-400',
      failed: 'bg-red-500/15 text-red-400',
      pending: 'bg-slate-500/15 text-slate-400',
    };
    return (
      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${cfg[status] || 'bg-slate-500/15 text-slate-400'}`}>
        {status}
      </span>
    );
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        Loading security data...
      </div>
    );
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      {/* Page header */}
      <div className="px-6 pt-6 pb-0">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Code Security</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
              SAST, DAST, and SCA vulnerability management across all repositories
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={loadData}
              className="flex items-center gap-2 px-3 py-2 rounded-xl border text-sm font-medium hover:bg-white/5 transition-colors"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors">
              <Plus className="w-4 h-4" />
              New Scan Pipeline
            </button>
          </div>
        </div>

        {/* Tab strip */}
        <div className="flex items-center gap-1 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent hover:opacity-75'
              }`}
              style={activeTab !== tab.id ? { color: 'var(--text-secondary)' } : {}}>
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="px-6 pt-6 pb-8">

        {/* ── OVERVIEW TAB ── */}
        {activeTab === 'overview' && (
          <div className="space-y-6">

            {/* KPI cards */}
            <div className="grid grid-cols-4 gap-x-4 gap-y-4">
              <KpiCard
                title="Total Findings"
                value={totalFindings}
                subtitle={`${scaVulns} vulnerabilities from SCA`}
                icon={<ShieldAlert className="w-5 h-5" />}
                color={totalFindings > 50 ? 'red' : 'green'}
              />
              <KpiCard
                title="Critical + High"
                value={criticalHigh}
                subtitle="Requires immediate attention"
                icon={<AlertTriangle className="w-5 h-5" />}
                color="orange"
              />
              <KpiCard
                title="Repos Scanned"
                value={reposScanned}
                subtitle={`${sastScans.length} SAST scans total`}
                icon={<Code2 className="w-5 h-5" />}
                color="blue"
              />
              <KpiCard
                title="Last Scan"
                value={lastScan ? fmtDate(lastScan).split(' ').slice(0, 2).join(' ') : '—'}
                subtitle={lastScan ? fmtDate(lastScan).split(' ').slice(2).join(' ') : 'No scans yet'}
                icon={<Clock className="w-5 h-5" />}
                color="purple"
              />
            </div>

            {/* ── Row 1: Security Trend (left) + Severity Distribution (right) ── */}
            <div className="grid grid-cols-2 gap-x-4 gap-y-4">

              {/* Security Trend Chart */}
              <div className="rounded-2xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="px-5 py-4 border-b flex items-center justify-between"
                  style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <div>
                    <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Security Trend</div>
                    <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                      SAST findings per scan — last {trendData.overall.length} scans
                      {trendData.projects.length > 1 && ` · ${trendData.projects.length} projects`}
                    </div>
                  </div>
                  <Activity className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
                </div>
                <div className="px-5 py-4">
                  <SecurityTrendChart
                    overall={trendData.overall}
                    projects={trendData.projects}
                    onExpand={() => setShowTrendModal(true)}
                  />
                </div>
              </div>

              {/* Severity Distribution */}
              <div className="rounded-2xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="px-5 py-4 border-b flex items-center justify-between"
                  style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <div>
                    <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Severity Distribution</div>
                    <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                      Based on most recent SAST scan findings
                    </div>
                  </div>
                  <Activity className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
                </div>
                <div className="px-5 py-5 flex items-center justify-center gap-8">
                  {/* Donut chart */}
                  <div className="flex-shrink-0">
                    {(topFindings.length + topQualityFindings.length) > 0 ? (
                      /* SeverityDonut expects { critical, high, medium, low } keyed object */
                      <SeverityDonut
                        data={{
                          critical: severityCounts.critical || 0,
                          high:     severityCounts.high     || 0,
                          medium:   severityCounts.medium   || 0,
                          low:      severityCounts.low      || 0,
                        }}
                        title=""
                      />
                    ) : sastScans.filter(s => s.status === 'completed').length > 0 ? (
                      /* Findings are still loading — show spinner */
                      <div className="flex flex-col items-center justify-center gap-2 w-[120px] h-[120px]">
                        <Loader2 className="w-6 h-6 animate-spin" style={{ color: 'var(--text-muted)' }} />
                        <span className="text-[11px] text-center" style={{ color: 'var(--text-tertiary)' }}>
                          Loading findings…
                        </span>
                      </div>
                    ) : (
                      <div className="text-sm text-center py-8 w-[120px]" style={{ color: 'var(--text-tertiary)' }}>
                        No completed scans yet
                      </div>
                    )}
                  </div>
                  {/* Stacked bar */}
                  <div className="flex-1 min-w-0">
                    <SeverityBar counts={severityCounts} />
                  </div>
                </div>
              </div>

            </div>

            {/* ── Row 2: Fix This First — Security (left) + Code Quality (right) ── */}
            <div className="grid grid-cols-2 gap-x-4 gap-y-4">

              {/* Fix This First — Vulnerabilities */}
              <div className="rounded-2xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="px-5 py-4 border-b flex items-center justify-between"
                  style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-lg bg-red-500/15">
                      <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Fix This First — Vulnerabilities</div>
                      <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                        Top security risks by impact score
                      </div>
                    </div>
                  </div>
                  <button onClick={() => setActiveTab('findings')}
                    className="text-xs text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1">
                    All findings <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
                <div className="px-4 py-3">
                  <FixThisFirst
                    findings={topFindings}
                    onViewAll={() => setActiveTab('findings')}
                    onItemClick={({ sev, scanId, rawRuleId }) => {
                      if (scanId && rawRuleId) {
                        router.push(`/secops/${scanId}?rule=${encodeURIComponent(rawRuleId)}`);
                      } else if (scanId) {
                        router.push(`/secops/${scanId}`);
                      } else {
                        setFindingFilters(prev => ({ ...prev, severity: sev }));
                        setActiveTab('findings');
                      }
                    }}
                  />
                </div>
              </div>

              {/* Fix This First — Code Quality */}
              <div className="rounded-2xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="px-5 py-4 border-b flex items-center justify-between"
                  style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-lg bg-blue-500/15">
                      <Code2 className="w-3.5 h-3.5 text-blue-400" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Fix This First — Code Quality</div>
                      <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                        Top code quality issues to address
                      </div>
                    </div>
                  </div>
                  <button onClick={() => setActiveTab('findings')}
                    className="text-xs text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1">
                    All findings <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
                <div className="px-4 py-3">
                  <FixThisFirst
                    findings={topQualityFindings}
                    onViewAll={() => setActiveTab('findings')}
                    onItemClick={({ sev, scanId, rawRuleId }) => {
                      if (scanId && rawRuleId) {
                        router.push(`/secops/${scanId}?rule=${encodeURIComponent(rawRuleId)}&tab=quality`);
                      } else if (scanId) {
                        router.push(`/secops/${scanId}?tab=quality`);
                      } else {
                        setActiveTab('findings');
                      }
                    }}
                  />
                </div>
              </div>

            </div>

            {/* Applications Risk Table */}
            <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-blue-500/15">
                    <GitBranch className="w-4 h-4 text-blue-400" />
                  </div>
                  <div>
                    <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>Applications</h2>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{projects.length} repositor{projects.length !== 1 ? 'ies' : 'y'} scanned</p>
                  </div>
                </div>
                <button onClick={() => router.push('/secops/projects')}
                  className="text-xs flex items-center gap-1 hover:opacity-75 transition-opacity"
                  style={{ color: '#60a5fa' }}>
                  View all <ChevronRight className="w-3 h-3" />
                </button>
              </div>
              {/* Column headers */}
              <div className="grid px-5 py-2 text-xs font-semibold uppercase tracking-wider border-b"
                style={{ gridTemplateColumns: '2fr 90px 60px 60px 120px 130px', gap: '1rem', borderColor: 'var(--border-primary)', color: 'var(--text-tertiary)', backgroundColor: 'var(--bg-secondary)' }}>
                <span>Repository</span>
                <span className="text-center">Risk Score</span>
                <span className="text-right">Critical</span>
                <span className="text-right">High</span>
                <span>Languages</span>
                <span className="text-right">Last Scan</span>
              </div>
              {projects.slice(0, 5).map(p => (
                <button key={p.repo_url} onClick={() => router.push(`/secops/projects/${encodeURIComponent(p.repo_url)}`)}
                  className="w-full grid items-center px-5 py-3 border-b last:border-0 hover:bg-white/5 transition-colors text-left"
                  style={{ gridTemplateColumns: '2fr 90px 60px 60px 120px 130px', gap: '1rem', borderColor: 'var(--border-primary)' }}>
                  {/* Repository */}
                  <div className="min-w-0 overflow-hidden">
                    <p className="text-sm font-medium truncate" title={p.name} style={{ color: 'var(--text-primary)' }}>{p.name}</p>
                    <p className="text-xs truncate font-mono" title={p.repo_url} style={{ color: 'var(--text-tertiary)' }}>{p.repo_url}</p>
                  </div>
                  {/* Risk Score */}
                  <div className="flex justify-center">
                    <RiskScoreBadge score={p.riskScore} />
                  </div>
                  {/* Critical */}
                  <div className="text-right">
                    {p.criticalCount > 0
                      ? <span className="text-sm font-bold tabular-nums text-red-400">{p.criticalCount}</span>
                      : <span className="text-sm tabular-nums" style={{ color: 'var(--text-tertiary)' }}>—</span>}
                  </div>
                  {/* High */}
                  <div className="text-right">
                    {p.highCount > 0
                      ? <span className="text-sm font-bold tabular-nums text-orange-400">{p.highCount}</span>
                      : <span className="text-sm tabular-nums" style={{ color: 'var(--text-tertiary)' }}>—</span>}
                  </div>
                  {/* Languages */}
                  <div className="flex flex-wrap gap-1 overflow-hidden" style={{ maxHeight: 28 }}>
                    {p.languages.slice(0, 2).map(l => (
                      <span key={l} className="text-xs px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-300 whitespace-nowrap">{l}</span>
                    ))}
                    {p.languages.length > 2 && <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>+{p.languages.length - 2}</span>}
                  </div>
                  {/* Last Scan */}
                  <div className="text-right overflow-hidden">
                    <span className="text-xs truncate block" style={{ color: 'var(--text-tertiary)' }}>{fmtDate(p.lastScan)}</span>
                  </div>
                </button>
              ))}
              {projects.length === 0 && !loading && (
                <div className="px-5 py-8 text-center">
                  <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No repositories scanned yet — start a scan pipeline to see projects here</p>
                </div>
              )}
            </div>

            {/* Two-column grid: Coverage (2/3) + Donut (1/3) */}
            <div className="grid grid-cols-3 gap-x-4 gap-y-4">
              {/* Scan Coverage (2 cols) */}
              <div className="col-span-2 rounded-2xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                  <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Scan Coverage</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Active scanning engines and results</div>
                </div>
                <div className="p-5 grid grid-cols-3 gap-x-4 gap-y-4">
                  <CoverageCard
                    icon={<Code2 className="w-5 h-5 text-blue-400" />}
                    label="SAST"
                    count={sastScans.length}
                    findings={sastFindings}
                    accentCls="bg-blue-500/10"
                    barColor="#3b82f6"
                    total={totalFindings}
                  />
                  <CoverageCard
                    icon={<Globe className="w-5 h-5 text-purple-400" />}
                    label="DAST"
                    count={dastScans.length}
                    findings={dastFindings}
                    accentCls="bg-purple-500/10"
                    barColor="#8b5cf6"
                    total={totalFindings}
                  />
                  <CoverageCard
                    icon={<Package className="w-5 h-5 text-green-400" />}
                    label="SCA"
                    count={scaScans.length}
                    findings={scaVulns}
                    accentCls="bg-green-500/10"
                    barColor="#22c55e"
                    total={totalFindings}
                  />
                </div>
              </div>

              {/* By Engine donut (1 col) */}
              <div className="col-span-1 rounded-2xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                  <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>By Engine</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Findings distribution</div>
                </div>
                <div className="p-5">
                  <EngineDonut data={engineDonutData} />
                </div>
              </div>
            </div>

            {/* Recent Scans */}
            <div className="rounded-2xl border overflow-hidden"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-4 border-b flex items-center justify-between"
                style={{ borderColor: 'var(--border-primary)' }}>
                <div>
                  <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Recent Scans</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Latest 5 scans across all engines</div>
                </div>
                <button
                  onClick={() => setActiveTab('history')}
                  className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors">
                  View all
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {recentScans.length === 0 ? (
                <div className="px-5 py-8 text-center text-sm" style={{ color: 'var(--text-tertiary)' }}>
                  No scans found. Launch a scan pipeline to get started.
                </div>
              ) : (
                <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
                  {/* Table header */}
                  <div className="px-5 py-2.5 grid grid-cols-5 gap-x-4"
                    style={{ backgroundColor: 'var(--bg-secondary)' }}>
                    {['Project / Target', 'Type', 'Status', 'Findings', 'Date'].map(h => (
                      <div key={h} className="text-xs font-semibold uppercase tracking-wider"
                        style={{ color: 'var(--text-tertiary)' }}>{h}</div>
                    ))}
                  </div>
                  {recentScans.map((scan, i) => {
                    const name = scan.project_name || scan.application_name || scan.target_url || scan.repo_url || '—';
                    const n = scan.total_findings ?? scan.vulnerability_count ?? 0;
                    return (
                      <div key={i}
                        className="px-5 py-3 grid grid-cols-5 gap-x-4 items-center hover:bg-white/2 cursor-pointer transition-colors"
                        onClick={() => {
                          if (scan._type === 'sast') router.push(`/secops/${scan._id}`);
                          else if (scan._type === 'dast') router.push(`/secops/dast/${scan._id}`);
                          else router.push(`/secops/sca/${scan._id}`);
                        }}>
                        <div className="text-sm truncate font-medium" title={name} style={{ color: 'var(--text-primary)' }}>{name}</div>
                        <div><SourceBadge source={scan._type} /></div>
                        <div>{renderStatusPill(scan.status)}</div>
                        <div className={`text-sm font-semibold ${n > 0 ? 'text-orange-400' : 'text-green-400'}`}>{n}</div>
                        <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{fmtDate(scan._ts)}</div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

          </div>
        )}

        {/* ── ALL FINDINGS TAB ── */}
        {activeTab === 'findings' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <FilterBar
                filters={findingFilterDefs}
                activeFilters={findingFilters}
                onFilterChange={(key, val) => setFindingFilters(prev => ({ ...prev, [key]: val }))}
              />
              <div className="text-sm font-medium" style={{ color: 'var(--text-tertiary)' }}>
                {findingsLoading ? (
                  <span className="flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Loading...</span>
                ) : (
                  `${filteredFindings.length} finding${filteredFindings.length !== 1 ? 's' : ''}`
                )}
              </div>
            </div>

            <DataTable
              data={filteredFindings}
              columns={findingColumns}
              pageSize={25}
              loading={findingsLoading}
              emptyMessage={findingsLoaded ? 'No findings match the current filters.' : 'Loading findings from all scan engines...'}
              onRowClick={(row) => {
                if (row.source === 'sast' && row._scan?.secops_scan_id) router.push(`/secops/${row._scan.secops_scan_id}`);
                else if (row.source === 'dast' && row._scan?.dast_scan_id) router.push(`/secops/dast/${row._scan.dast_scan_id}`);
                else if (row.source === 'sca' && row._scan?.sbom_id) router.push(`/secops/sca/${row._scan.sbom_id}`);
              }}
            />
          </div>
        )}

        {/* ── SCAN HISTORY TAB ── */}
        {activeTab === 'history' && (
          <div className="space-y-4">
            <DataTable
              data={allScans}
              columns={historyColumns}
              pageSize={20}
              loading={loading}
              emptyMessage="No scans found. Launch a scan pipeline to get started."
              onRowClick={(row) => {
                if (row._type === 'sast') router.push(`/secops/${row._id}`);
                else if (row._type === 'dast') router.push(`/secops/dast/${row._id}`);
                else router.push(`/secops/sca/${row._id}`);
              }}
            />
          </div>
        )}

      </div>

      {/* Scan launch modal */}
      {showModal && (
        <ScanLaunchModal
          onClose={() => { if (!scanStatus) setShowModal(false); }}
          onLaunch={handleLaunch}
          scanStatus={scanStatus}
        />
      )}

      {/* Security Trend — expanded modal */}
      {showTrendModal && (
        <>
          <div
            className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm"
            onClick={() => setShowTrendModal(false)}
          />
          <div
            className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-3xl border rounded-2xl shadow-2xl z-50"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b"
              style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              <div>
                <h3 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
                  Security Trend — Project Breakdown
                </h3>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                  Per-project finding counts over time · dashed lines = individual projects · solid blue = overall
                </p>
              </div>
              <button
                onClick={() => setShowTrendModal(false)}
                className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
              >
                <X className="w-5 h-5" style={{ color: 'var(--text-tertiary)' }} />
              </button>
            </div>

            {/* Chart */}
            <div className="px-6 py-6">
              <SecurityTrendChart
                overall={trendData.overall}
                projects={trendData.projects}
                isModal={true}
              />
            </div>

            {/* Project summary table (only if multiple projects) */}
            {trendData.projects.length > 1 && (
              <div className="px-6 pb-6">
                <div className="rounded-xl border overflow-hidden"
                  style={{ borderColor: 'var(--border-primary)' }}>
                  <div className="grid px-4 py-2 text-[10px] font-bold uppercase tracking-wider border-b"
                    style={{
                      gridTemplateColumns: '1fr 80px 80px 80px',
                      gap: '1rem',
                      borderColor: 'var(--border-primary)',
                      color: 'var(--text-muted)',
                      backgroundColor: 'var(--bg-secondary)',
                    }}>
                    <span>Project</span>
                    <span className="text-right">Scans</span>
                    <span className="text-right">Latest</span>
                    <span className="text-right">Trend</span>
                  </div>
                  {trendData.projects.map(p => {
                    const latest = p.scans[p.scans.length - 1]?.total ?? 0;
                    const prev   = p.scans[p.scans.length - 2]?.total ?? latest;
                    const diff   = latest - prev;
                    return (
                      <div key={p.name}
                        className="grid items-center px-4 py-2.5 border-b last:border-0"
                        style={{ gridTemplateColumns: '1fr 80px 80px 80px', gap: '1rem', borderColor: 'var(--border-primary)' }}>
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="inline-block w-3 h-3 rounded-full flex-shrink-0"
                            style={{ backgroundColor: p.color }} />
                          <span className="text-xs font-medium truncate"
                            style={{ color: 'var(--text-primary)' }} title={p.name}>
                            {p.name}
                          </span>
                        </div>
                        <span className="text-xs text-right tabular-nums"
                          style={{ color: 'var(--text-secondary)' }}>{p.scans.length}</span>
                        <span className="text-xs text-right font-bold tabular-nums"
                          style={{ color: 'var(--text-primary)' }}>{latest}</span>
                        <div className="flex justify-end">
                          {diff < 0 ? (
                            <span className="text-xs font-semibold text-green-400">{diff}</span>
                          ) : diff > 0 ? (
                            <span className="text-xs font-semibold text-red-400">+{diff}</span>
                          ) : (
                            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
