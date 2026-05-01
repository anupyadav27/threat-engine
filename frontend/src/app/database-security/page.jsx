'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Database, Shield, AlertTriangle, AlertCircle, CheckCircle, Lock, KeyRound, FileText, RefreshCw,
} from 'lucide-react';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { useViewFetch } from '@/lib/use-view-fetch';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
import KpiSparkCard from '@/components/shared/KpiSparkCard';
import FindingDetailPanel from '@/components/shared/FindingDetailPanel';

// ── Colour palette ────────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  sky:      '#38bdf8',
  amber:    '#f59e0b',
  emerald:  '#10b981',
  indigo:   '#6366f1',
  purple:   '#8b5cf6',
  teal:     '#14b8a6',
};

const DOMAIN_META = {
  access_control:   { label: 'Access Control',   icon: KeyRound,      color: '#8b5cf6' },
  encryption:       { label: 'Encryption',        icon: Lock,          color: '#3b82f6' },
  audit_logging:    { label: 'Audit Logging',     icon: FileText,      color: '#06b6d4' },
  backup_recovery:  { label: 'Backup & Recovery', icon: Shield,        color: '#22c55e' },
  network_security: { label: 'Network Security',  icon: Shield,        color: '#f97316' },
  configuration:    { label: 'Configuration',      icon: AlertTriangle, color: '#eab308' },
};

// ── Enriched scan trend ───────────────────────────────────────────────────────
const DB_DOMAIN_MAP = {
  access_control:   { label: 'Access Control',    color: '#8b5cf6' },
  encryption:       { label: 'Encryption',        color: '#3b82f6' },
  audit_logging:    { label: 'Audit Logging',     color: '#06b6d4' },
  backup_recovery:  { label: 'Backup & Recovery', color: '#22c55e' },
  network_security: { label: 'Network Security',  color: '#f97316' },
  configuration:    { label: 'Configuration',     color: '#eab308' },
};

// ── Pure-SVG severity donut ───────────────────────────────────────────────────
function DbDonut({ slices, size = 160 }) {
  const total = slices.reduce((s, x) => s + x.value, 0) || 1;
  const cx = size / 2, cy = size / 2;
  const r  = size / 2 - 8;
  const ir = r * 0.58;
  const gapA   = (2.5 / 360) * 2 * Math.PI;
  const labelR = (r + ir) / 2;
  let angle = -Math.PI / 2;

  const paths = slices.filter(s => s.value > 0).map(s => {
    const pct   = Math.round((s.value / total) * 100);
    const sweep = Math.max((s.value / total) * 2 * Math.PI - gapA, 0.001);
    const a0 = angle + gapA / 2, a1 = a0 + sweep;
    const mid = (a0 + a1) / 2;
    const large = sweep > Math.PI ? 1 : 0;
    const d = [
      `M ${cx + r  * Math.cos(a0)} ${cy + r  * Math.sin(a0)}`,
      `A ${r}  ${r}  0 ${large} 1 ${cx + r  * Math.cos(a1)} ${cy + r  * Math.sin(a1)}`,
      `L ${cx + ir * Math.cos(a1)} ${cy + ir * Math.sin(a1)}`,
      `A ${ir} ${ir} 0 ${large} 0 ${cx + ir * Math.cos(a0)} ${cy + ir * Math.sin(a0)}`,
      'Z',
    ].join(' ');
    angle += sweep + gapA;
    return { ...s, d, pct, mid };
  });

  return (
    <svg width={size} height={size} style={{ flexShrink: 0, display: 'block' }}>
      <circle cx={cx} cy={cy} r={(r + ir) / 2}
        fill="none" stroke="var(--border-primary)" strokeWidth={r - ir} />
      {paths.map((p, i) => <path key={i} d={p.d} fill={p.color} opacity={0.9} />)}
      {paths.map((p, i) => p.pct >= 8 && (
        <text key={`l${i}`}
          x={cx + labelR * Math.cos(p.mid)} y={cy + labelR * Math.sin(p.mid) + 4}
          textAnchor="middle"
          style={{ fontSize: 10, fontWeight: 700, fill: '#fff', fontFamily: 'inherit', pointerEvents: 'none' }}>
          {p.pct}%
        </text>
      ))}
    </svg>
  );
}



export default function DatabaseSecurityPage() {
  const { data, loading, error } = useViewFetch('database-security');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const handleRowClick = (row) => { const f = row?.original || row; if (f) setSelectedFinding(f); };

  const pageContext = data.pageContext || {};
  const rawDatabases = data.databases     || [];
  const rawFindings  = data.findings      || [];
  const databases = rawDatabases;
  const findings  = rawFindings;
  const domainScores = data.domain_scores || {};

  // ── Helper: unique values from an array ──
  const uniqueVals = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Column definitions ──

  const inventoryColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    {
      accessorKey: 'db_service', header: 'DB Service',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'db_engine', header: 'DB Engine' },
    {
      accessorKey: 'posture_score', header: 'Posture Score',
      cell: (info) => {
        const score = info.getValue();
        const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
        return <span className="text-xs font-bold" style={{ color }}>{score ?? '-'}</span>;
      },
    },
    {
      accessorKey: 'publicly_accessible', header: 'Public',
      cell: (info) => {
        const v = info.getValue();
        const isPublic = v === true || v === 'true' || v === 'True' || v === 'yes';
        return isPublic
          ? <AlertTriangle className="w-4 h-4 text-red-400" />
          : <CheckCircle className="w-4 h-4 text-green-400" />;
      },
    },
    {
      accessorKey: 'encryption', header: 'Encryption',
      cell: (info) => {
        const v = info.getValue();
        const encrypted = v === 'encrypted' || v === 'enabled' || v === true;
        return encrypted
          ? <CheckCircle className="w-4 h-4 text-green-400" />
          : <AlertTriangle className="w-4 h-4 text-red-400" />;
      },
    },
    {
      accessorKey: 'iam_auth', header: 'IAM Auth',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    },
    {
      accessorKey: 'backup', header: 'Backup',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    },
    {
      accessorKey: 'multi_az', header: 'Multi-AZ',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>-</span>,
    },
  ];

  const findingsColumns = useMemo(() => [
    { accessorKey: 'provider',         header: 'Provider', size: 70,
      cell: (info) => info.getValue()?.toUpperCase() || '—' },
    { accessorKey: 'account_id',       header: 'Account', size: 130,
      cell: (info) => info.getValue() || info.row.original.account || '—' },
    { accessorKey: 'region',           header: 'Region', size: 110 },
    { accessorKey: 'service',          header: 'Service', size: 110,
      cell: (info) => info.getValue() || info.row.original.network_layer || info.row.original.encryption_domain || info.row.original.container_service || info.row.original.db_service || '—' },
    { accessorKey: 'rule_id',          header: 'Rule ID', size: 130,
      cell: (info) => <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{info.getValue() || '—'}</span> },
    { accessorKey: 'title',            header: 'Finding',
      cell: (info) => <span className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue() || info.row.original.rule_id || '—'}</span> },
    { accessorKey: 'severity',         header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    { accessorKey: 'status',           header: 'Status',
      cell: (info) => { const v = info.getValue(), f = v === 'FAIL'; return <span className={`text-xs px-2 py-0.5 rounded ${f ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{v}</span>; } },
    { accessorKey: 'resource_uid',     header: 'Resource',
      cell: (info) => { const v = info.getValue() || info.row.original.resource_id || ''; return <span className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>{v.split('/').pop() || v.split(':').pop() || v}</span>; } },
    { accessorKey: 'resource_type',    header: 'Type' },
    { accessorKey: 'db_service',       header: 'DB Service',
      cell: (info) => { const v = info.getValue(); return v ? <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(20,184,166,0.12)', color: '#2dd4bf' }}>{v}</span> : null; } },
    { accessorKey: 'db_engine',        header: 'Engine' },
    { accessorKey: 'security_domain',  header: 'Domain',
      cell: (info) => { const v = info.getValue(); return v ? <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>{v}</span> : null; } },
    { accessorKey: 'risk_score',       header: 'Risk',
      cell: (info) => { const v = info.getValue(); if (!v) return null; const c = v >= 75 ? '#ef4444' : v >= 50 ? '#f97316' : v >= 25 ? '#eab308' : '#22c55e'; return <div className="flex items-center gap-1.5"><div className="w-10 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}><div className="h-full rounded-full" style={{ width: `${v}%`, backgroundColor: c }} /></div><span className="text-xs font-bold" style={{ color: c }}>{v}</span></div>; } },
  ], []);

  // ── Derive KPI numbers ────────────────────────────────────────────────────
  const kpiNums = useMemo(() => {
    const g0 = data.kpiGroups?.[0]?.items || [];
    const get = (arr, lbl) => arr.find(x => x.label?.toLowerCase() === lbl.toLowerCase())?.value ?? null;
    return {
      posture_score:   get(g0, 'Posture Score')    ?? 0,
      total_findings:  get(g0, 'Total Findings')   ?? findings.length,
      critical:        get(g0, 'Critical')         ?? 0,
      high:            get(g0, 'High')             ?? 0,
      medium:          get(g0, 'Medium')           ?? 0,
      low:             get(g0, 'Low')              ?? 0,
      db_instances:    get(g0, 'Total Databases')  ?? 0,
      public_dbs:      get(g0, 'Public Databases') ?? 0,
      unencrypted_dbs: 0,
      no_backup:       0,
    };
  }, [data.kpiGroups, findings]);

  // ── Active scan trend: live from BFF or static fallback ──────────────
  const activeScanTrend = useMemo(
    () => {
      if (data.scanTrend?.length >= 1) {
        return data.scanTrend.map(d => ({ ...d, passRate: d.pass_rate ?? d.passRate ?? 0 }));
      }
      return [];
    },
    [data.scanTrend],
  );

  const activeModuleScores = useMemo(() => {
    const db = data.domainBreakdown;
    if (db?.length >= 1) {
      return db.map(d => {
        const meta = DB_DOMAIN_MAP[d.security_domain] ?? { label: d.security_domain, color: '#64748b' };
        return { module: meta.label, pass: d.pass_count ?? 0, total: d.total ?? 0, color: meta.color };
      });
    }
    return [];
  }, [data.domainBreakdown]);

  // ── Insight strip ─────────────────────────────────────────────────────────
  const insightStrip = useMemo(() => {
    const {
      posture_score, total_findings, critical, high, medium, low,
      db_instances, public_dbs, unencrypted_dbs, no_backup,
    } = kpiNums;

    // Live sparklines derived from scan trend
    const sparkPS  = activeScanTrend.map(d => d.passRate ?? d.pass_rate ?? 0);
    const sparkTF  = activeScanTrend.map(d => d.total            ?? 0);
    const sparkPD  = activeScanTrend.map(d => d.public_databases ?? 0);
    const sparkUDB = activeScanTrend.map(d => d.unencrypted_dbs  ?? 0);

    const scoreColor = posture_score >= 70 ? C.emerald
                     : posture_score >= 50 ? C.amber
                     : C.critical;

    // ── KPI tile ──
    const tile = (label, value, color, suffix = '', sub = '', sparkData = [], delta = null, deltaGood = 'down') => (
      <KpiSparkCard
        key={label}
        label={label}
        value={value}
        color={color}
        suffix={suffix}
        sub={sub}
        sparkData={sparkData}
        delta={delta}
        deltaGood={deltaGood}
      />
    );

    // ── Donut slices ──
    const donutSlices = [
      { label: 'Critical', value: critical, color: C.critical },
      { label: 'High',     value: high,     color: C.high     },
      { label: 'Medium',   value: medium,   color: C.medium   },
      { label: 'Low',      value: low,      color: C.low      },
    ];

    // ── Trend deltas ──
    const first = activeScanTrend[0] || {};
    const last  = activeScanTrend[activeScanTrend.length - 1] || {};
    const rateΔ  = (last.passRate  ?? 0) - (first.passRate  ?? 0);
    const critΔ  = (last.critical  ?? 0) - (first.critical  ?? 0);
    const highΔ  = (last.high      ?? 0) - (first.high      ?? 0);
    const totalΔ = (last.total     ?? 0) - (first.total     ?? 0);

    const statPill = (label, value, delta, goodDir) => {
      const improved = goodDir === 'up' ? delta >= 0 : delta <= 0;
      const dc   = improved ? C.emerald : C.critical;
      const sign = delta > 0 ? '+' : '';
      return (
        <div key={label} style={{
          flex: 1, backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-primary)', borderRadius: 8,
          padding: '8px 10px',
        }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>
            {label}
          </div>
          <div style={{ fontSize: 20, fontWeight: 900, color: 'var(--text-primary)',
            lineHeight: 1, fontVariantNumeric: 'tabular-nums', marginBottom: 3 }}>
            {value}
          </div>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 20,
            backgroundColor: `${dc}18`, color: dc,
          }}>{sign}{delta}{label === 'Pass Rate' ? '%' : ''}</span>
        </div>
      );
    };

    const TrendTooltip = ({ active, payload, label }) => {
      if (!active || !payload?.length) return null;
      const d = payload[0]?.payload;
      if (!d) return null;
      return (
        <div style={{
          backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)',
          borderRadius: 10, padding: '12px 14px', minWidth: 190,
          boxShadow: '0 6px 24px rgba(0,0,0,0.20)',
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
            marginBottom: 8, borderBottom: '1px solid var(--border-primary)', paddingBottom: 6 }}>
            {label}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Pass Rate</span>
            <span style={{ fontSize: 18, fontWeight: 900, color: C.emerald,
              fontVariantNumeric: 'tabular-nums' }}>{d.passRate}%</span>
          </div>
          {[
            { label: 'Critical', value: d.critical, color: C.critical },
            { label: 'High',     value: d.high,     color: C.high     },
            { label: 'Medium',   value: d.medium,   color: C.medium   },
          ].map(s => (
            <div key={s.label} style={{ marginBottom: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 5,
                  fontSize: 11, color: 'var(--text-secondary)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2,
                    backgroundColor: s.color, display: 'inline-block' }} />
                  {s.label}
                </span>
                <span style={{ fontSize: 12, fontWeight: 700, color: s.color,
                  fontVariantNumeric: 'tabular-nums' }}>{s.value}</span>
              </div>
              <div style={{ height: 3, borderRadius: 2, backgroundColor: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                <div style={{ width: `${Math.round((s.value / d.total) * 100)}%`,
                  height: '100%', borderRadius: 2, backgroundColor: s.color, opacity: 0.85 }} />
              </div>
            </div>
          ))}
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8,
            paddingTop: 6, borderTop: '1px solid var(--border-primary)' }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Total findings</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
              fontVariantNumeric: 'tabular-nums' }}>{d.total}</span>
          </div>
        </div>
      );
    };

    return (
      <div className="flex gap-3 items-stretch" style={{ minHeight: 260 }}>

        {/* ── Row 1: 4 KPI tiles ── */}
        <div style={{
          flex: 1, display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: 8, minWidth: 0,
        }}>
          {tile('Posture Score',    posture_score,     scoreColor, '/100', `${medium} medium · ${low} low risk`, sparkPS, sparkPS[sparkPS.length - 1] - sparkPS[0], 'up')}
          {tile('Total Findings',   total_findings,    C.high,     '',     `${critical} critical · ${high} high`, sparkTF, sparkTF[sparkTF.length - 1] - sparkTF[0], 'down')}
          {tile('Public Databases', public_dbs,      C.critical, '',     `${db_instances} total DB instances`,  sparkPD,  sparkPD[sparkPD.length   - 1] - sparkPD[0],  'down')}
          {tile('Unencrypted DBs',  unencrypted_dbs, C.amber,    '',     `${no_backup} without backup enabled`, sparkUDB, sparkUDB[sparkUDB.length - 1] - sparkUDB[0], 'down')}
        </div>

          {/* ── Col 1: Findings by Severity donut + Module Scores ── */}
          <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
          }}>
            {/* Header */}
            <div className="flex items-center justify-between mb-0.5">
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                Findings by Severity
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                {total_findings.toLocaleString()} total
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 10 }}>
              Database posture · severity breakdown
            </div>

            {/* Donut + progress-bar legend */}
            <div className="flex items-center gap-4" style={{ flex: 1 }}>
              <div style={{ position: 'relative', flexShrink: 0 }}>
                <DbDonut slices={donutSlices} size={160} />
                <div style={{
                  position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
                  alignItems: 'center', justifyContent: 'center', pointerEvents: 'none',
                }}>
                  <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--text-primary)', lineHeight: 1 }}>
                    {total_findings.toLocaleString()}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>findings</div>
                </div>
              </div>
              <div className="flex-1 space-y-2" style={{ minWidth: 0 }}>
                {donutSlices.map(s => {
                  const pct = Math.round((s.value / (total_findings || 1)) * 100);
                  return (
                    <div key={s.label}>
                      <div className="flex items-center justify-between mb-0.5">
                        <div className="flex items-center gap-1.5">
                          <div style={{ width: 9, height: 9, borderRadius: 2,
                            backgroundColor: s.color, flexShrink: 0 }} />
                          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{s.label}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span style={{ fontSize: 13, fontWeight: 700, color: s.color }}>
                            {s.value.toLocaleString()}
                          </span>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{pct}%</span>
                        </div>
                      </div>
                      <div style={{ height: 3, borderRadius: 2, backgroundColor: 'var(--bg-tertiary)', overflow: 'hidden' }}>
                        <div style={{ width: `${pct}%`, height: '100%', borderRadius: 2,
                          backgroundColor: s.color, opacity: 0.85 }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Module Scores — compact 2-col list */}
            <div style={{
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 16px',
              marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border-primary)',
            }}>
              {activeModuleScores.map(m => {
                const pct = Math.round((m.pass / m.total) * 100);
                const col = pct >= 70 ? C.emerald : pct >= 50 ? C.amber : C.critical;
                return (
                  <div key={m.module} style={{ display: 'flex', alignItems: 'center',
                    gap: 6, padding: '3px 0', borderBottom: '1px solid var(--border-primary)' }}>
                    <span style={{ width: 7, height: 7, borderRadius: 2,
                      backgroundColor: col, flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: 'var(--text-secondary)', flex: 1,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {m.module}
                    </span>
                    <div style={{ width: 32, height: 3, borderRadius: 2,
                      backgroundColor: 'var(--bg-tertiary)', flexShrink: 0, overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%',
                        borderRadius: 2, backgroundColor: col }} />
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 700, color: col,
                      flexShrink: 0, fontVariantNumeric: 'tabular-nums', width: 28, textAlign: 'right' }}>
                      {pct}%
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ── Col 2: Database Posture Trend (ComposedChart) ── */}
          <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
          }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between',
              alignItems: 'center', marginBottom: 8 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                  Database Posture Trend
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                  {first.date && last.date ? `${first.date} – ${last.date} · ` : ''}{activeScanTrend.length} scans
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {[
                  { label: 'Critical', color: C.critical },
                  { label: 'High',     color: C.high     },
                  { label: 'Medium',   color: C.medium   },
                  { label: 'Pass Rate',color: C.emerald  },
                ].map(s => (
                  <span key={s.label} style={{ display: 'flex', alignItems: 'center',
                    gap: 4, fontSize: 10, color: 'var(--text-muted)' }}>
                    <span style={{ width: 8, height: s.label === 'Pass Rate' ? 2 : 8,
                      borderRadius: s.label === 'Pass Rate' ? 1 : 2,
                      backgroundColor: s.color, display: 'inline-block' }} />
                    {s.label}
                  </span>
                ))}
              </div>
            </div>

            {/* 4-stat summary strip */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
              {statPill('Pass Rate', `${last.passRate ?? 0}%`, rateΔ,  'up'  )}
              {statPill('Critical',  last.critical ?? 0,    critΔ,  'down')}
              {statPill('High',      last.high ?? 0,        highΔ,  'down')}
              {statPill('Total',     last.total ?? 0,       totalΔ, 'down')}
            </div>

            {/* Composed chart — fills remaining height */}
            <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
              <div style={{ position: 'absolute', inset: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={activeScanTrend}
                    margin={{ top: 6, right: 10, left: -14, bottom: 0 }} barCategoryGap="28%">
                    <defs>
                      {[
                        { id: 'dc', color: C.critical },
                        { id: 'dh', color: C.high     },
                        { id: 'dm', color: C.medium   },
                      ].map(g => (
                        <linearGradient key={g.id} id={g.id} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%"   stopColor={g.color} stopOpacity={0.95} />
                          <stop offset="100%" stopColor={g.color} stopOpacity={0.55} />
                        </linearGradient>
                      ))}
                    </defs>
                    <CartesianGrid vertical={false} strokeDasharray="3 3"
                      stroke="var(--border-primary)" opacity={0.5} />
                    <XAxis dataKey="date"
                      tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
                      axisLine={false} tickLine={false} />
                    <YAxis yAxisId="count"
                      tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
                      axisLine={false} tickLine={false} width={24} />
                    <YAxis yAxisId="rate" orientation="right" domain={[0, 100]}
                      tick={{ fontSize: 10, fill: C.emerald, fontFamily: 'inherit' }}
                      axisLine={false} tickLine={false} width={28}
                      tickFormatter={v => `${v}%`} />
                    <ReferenceLine yAxisId="rate" y={80} stroke={C.emerald}
                      strokeDasharray="5 3" strokeOpacity={0.45}
                      label={{ value: 'Target', position: 'insideTopRight',
                        fontSize: 9, fill: C.emerald, opacity: 0.7 }} />
                    <RechartsTip content={<TrendTooltip />} />
                    <Bar yAxisId="count" dataKey="medium"   name="Medium"   stackId="s" fill={`url(#dm)`} radius={[0,0,0,0]} />
                    <Bar yAxisId="count" dataKey="high"     name="High"     stackId="s" fill={`url(#dh)`} radius={[0,0,0,0]} />
                    <Bar yAxisId="count" dataKey="critical" name="Critical" stackId="s" fill={`url(#dc)`} radius={[3,3,0,0]} />
                    <Line yAxisId="rate" type="monotone" dataKey="passRate" name="Pass Rate"
                      stroke={C.emerald} strokeWidth={2.5}
                      dot={{ r: 3, fill: C.emerald, strokeWidth: 0 }}
                      activeDot={{ r: 5, fill: C.emerald, stroke: 'var(--bg-card)', strokeWidth: 2 }} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

      </div>
    );
  }, [kpiNums, activeScanTrend]);

  const serviceOptions = useMemo(() =>
    [...new Set((findings || []).map(f => f.service || '').filter(Boolean))].sort(),
  [findings]);

  const resourceTypeOptions = useMemo(() =>
    [...new Set((findings || []).map(f => f.resource_type || '').filter(Boolean))].sort(),
  [findings]);

  // ── Common filter config ──
  const commonFilters = [
    { key: 'provider',  label: 'Cloud Platform', options: ['aws', 'azure', 'gcp'] },
    { key: 'severity',  label: 'Severity',        options: ['critical', 'high', 'medium', 'low'] },
    { key: 'status',    label: 'Status',           options: ['FAIL', 'PASS'] },
    { key: 'service',   label: 'Service',          options: serviceOptions },
  ];
  const extraFilters = [
    { key: 'region',        label: 'Region',        options: [] },
    { key: 'account_id',    label: 'Account',       options: [] },
    { key: 'resource_type', label: 'Resource Type', options: resourceTypeOptions },
  ];

  // ── Build tabData ──
  const tabData = useMemo(() => {
    // Domain classification: check both security_domain and posture_category
    const matchDomain = (f, ...domains) =>
      domains.some(d =>
        (f.security_domain || '').toLowerCase().includes(d) ||
        (f.posture_category || '').toLowerCase().includes(d) ||
        (f.rule_id || '').toLowerCase().includes(d)
      );

    const accessFindings    = findings.filter(f => matchDomain(f, 'access', 'iam', 'auth', 'privilege'));
    const encFindings       = findings.filter(f => matchDomain(f, 'encrypt', 'kms', 'tls', 'ssl'));
    const auditFindings     = findings.filter(f => matchDomain(f, 'audit', 'log', 'monitor', 'cloudtrail'));

    const findingTab = (data) => ({
      data,
      columns: findingsColumns,
      filters: commonFilters,
      extraFilters,
      searchPlaceholder: 'Search by rule, resource, title...',
    });

    return {
      overview: {
        data: findings.length ? findings : databases,
        columns: findings.length ? findingsColumns : inventoryColumns,
        filters: findings.length ? commonFilters : [],
        extraFilters: findings.length ? extraFilters : [],
        searchPlaceholder: 'Search by rule, resource, title...',
      },
      inventory: {
        data: databases,
        columns: inventoryColumns,
        searchPlaceholder: 'Search databases...',
      },
      findings: findingTab(findings),
      access_control: findingTab(accessFindings),
      encryption:     findingTab(encFindings),
      audit_logging:  findingTab(auditFindings),
    };
  }, [databases, findings, findingsColumns, serviceOptions, resourceTypeOptions]);

  return (
    <div className="space-y-5">
      {/* ── Heading ── */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Database className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
              {pageContext.title || 'Database Security'}
            </h1>
          </div>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {pageContext.brief || 'Database posture, encryption coverage, access controls, and backup compliance across all connected accounts.'}
          </p>
        </div>
        <button onClick={() => window.location.reload()}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-opacity hover:opacity-80"
          style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* ── Tabs + table ── */}
      <PageLayout icon={Database} pageContext={pageContext} kpiGroups={[]} insightRow={insightStrip}
        tabData={tabData} loading={loading} error={error} defaultTab="overview" hideHeader topNav
        onRowClick={handleRowClick} />

      <FindingDetailPanel finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
}
