'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Database,
  Lock,
  AlertTriangle,
  RefreshCw,
  Info,
  ChevronDown,
  ShieldCheck,
  FileSearch,
} from 'lucide-react';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
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

// ── Enriched scan trend (static fallback) ─────────────────────────────────────
const DS_SCAN_TREND = [
  { date: 'Jan 13', passRate: 44, critical: 9,  high: 28, medium: 35, total: 72 },
  { date: 'Jan 20', passRate: 47, critical: 8,  high: 26, medium: 32, total: 66 },
  { date: 'Jan 27', passRate: 46, critical: 9,  high: 27, medium: 33, total: 69 },
  { date: 'Feb 3',  passRate: 51, critical: 7,  high: 24, medium: 30, total: 61 },
  { date: 'Feb 10', passRate: 54, critical: 6,  high: 22, medium: 28, total: 56 },
  { date: 'Feb 17', passRate: 57, critical: 6,  high: 21, medium: 26, total: 53 },
  { date: 'Feb 24', passRate: 59, critical: 5,  high: 19, medium: 24, total: 48 },
  { date: 'Mar 3',  passRate: 61, critical: 5,  high: 18, medium: 23, total: 46 },
];

// ── Module scores (domain-based, derived when possible) ──────────────────────
const DS_MODULE_FALLBACK = [
  { module: 'Data Classification', pass: 7,  total: 12, color: '#8b5cf6' },
  { module: 'Encryption Coverage', pass: 9,  total: 16, color: '#3b82f6' },
  { module: 'Public Access',       pass: 3,  total: 8,  color: '#ef4444' },
  { module: 'DLP Rules',           pass: 11, total: 14, color: '#06b6d4' },
  { module: 'Data Residency',      pass: 8,  total: 11, color: '#10b981' },
  { module: 'Access Monitoring',   pass: 6,  total: 10, color: '#f59e0b' },
];

// ── Category badge ────────────────────────────────────────────────────────────
function CategoryBadge({ value }) {
  const v = (value || '').toLowerCase();
  const style =
    v === 'encryption'       ? { backgroundColor: 'rgba(59,130,246,0.15)', color: '#60a5fa' }
    : v === 'data_protection' ? { backgroundColor: 'rgba(245,158,11,0.15)', color: '#fbbf24' }
    : v === 'dlp'             ? { backgroundColor: 'rgba(239,68,68,0.15)',  color: '#f87171' }
    : { backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' };
  const label = v === 'encryption'       ? 'Encryption'
    : v === 'data_protection' ? 'Data Protection'
    : v === 'dlp'             ? 'DLP'
    : value || '—';
  return <span className="text-xs px-2 py-0.5 rounded font-medium" style={style}>{label}</span>;
}

// ── Pure-SVG severity donut ───────────────────────────────────────────────────
function DsDonut({ slices, size = 160 }) {
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

export default function DataSecurityPage() {
  const [loading, setLoading]               = useState(true);
  const [error, setError]                   = useState(null);
  const [realCatalog, setRealCatalog]       = useState([]);
  const [dlpViolations, setDlpViolations]   = useState([]);
  const [dataResidency, setDataResidency]   = useState([]);
  const [accessMonitoring, setAccessMonitoring] = useState([]);
  const [realFindings, setRealFindings]     = useState([]);
  const [scanTrendData, setScanTrendData]   = useState([]);
  const [detailsOpen, setDetailsOpen]       = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const handleRowClick = (row) => { const f = row?.original || row; if (f) setSelectedFinding(f); };

  const { provider, account, region } = useGlobalFilter();

  // ── Data fetch ──────────────────────────────────────────────────────────────
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchView('datasec', {
          provider: provider || undefined,
          account:  account  || undefined,
          region:   region   || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.catalog)          setRealCatalog(data.catalog);
        if (data.dlp)              setDlpViolations(data.dlp);
        if (data.residency)        setDataResidency(data.residency);
        if (data.accessMonitoring) setAccessMonitoring(data.accessMonitoring);
        if (data.scanTrend)        setScanTrendData(data.scanTrend);
        if (data.findings)         setRealFindings(data.findings);
      } catch (err) {
        console.warn('Error fetching data security data:', err);
        setError(err?.message || 'Failed to load data security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  // ── Severity counts from real findings ──────────────────────────────────────
  const severityCount = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of realFindings) {
      const s = (f.severity || 'medium').toLowerCase();
      if (s in counts) counts[s]++;
    }
    return counts;
  }, [realFindings]);

  // ── Category split (encryption vs data_protection) ──────────────────────────
  const categorySplit = useMemo(() => {
    let enc = 0, dp = 0, other = 0;
    for (const f of realFindings) {
      const cat = (f.posture_category || '').toLowerCase();
      if (cat === 'encryption')        enc++;
      else if (cat === 'data_protection') dp++;
      else other++;
    }
    return { encryption: enc, data_protection: dp, other };
  }, [realFindings]);

  // ── KPI numbers — derived from real data ────────────────────────────────────
  const kpiNums = useMemo(() => {
    const total = realFindings.length;
    const { critical, high, medium, low } = severityCount;
    // posture score from severity weights (same formula as BFF)
    const sevW = { critical: 4, high: 3, medium: 2, low: 1 };
    const totalW = realFindings.reduce((s, f) => s + (sevW[(f.severity || 'medium').toLowerCase()] || 2), 0);
    const posture = total ? Math.min(100, Math.round((totalW / (total * 4)) * 100)) : 0;

    return {
      posture_score:   total ? posture : 0,
      total_findings:  total,
      critical, high, medium, low,
      dlp_violations:  dlpViolations.length,
      encryption_count: categorySplit.encryption,
      data_protection_count: categorySplit.data_protection,
    };
  }, [realFindings, severityCount, dlpViolations.length, categorySplit]);

  // ── Catalog data — use realFindings (full check fields) when catalog lacks them ──
  const catalogData = useMemo(() => {
    // normalize_datastore strips rule_id/severity/status; use realFindings directly
    // when catalog is derived from check engine (both have same length)
    if (realFindings.length && Math.abs(realCatalog.length - realFindings.length) < 5) {
      return realFindings;
    }
    return realCatalog.length ? realCatalog : realFindings;
  }, [realCatalog, realFindings]);

  // ── Scan trend ───────────────────────────────────────────────────────────────
  const activeScanTrend = useMemo(() => {
    if (scanTrendData?.length >= 2) {
      return scanTrendData.map(d => ({ ...d, passRate: d.pass_rate ?? d.passRate ?? 0 }));
    }
    return DS_SCAN_TREND;
  }, [scanTrendData]);

  // ── Module scores — derive from category split when available ────────────────
  const activeModuleScores = useMemo(() => {
    const total = realFindings.length;
    if (!total) return DS_MODULE_FALLBACK;
    const { encryption, data_protection } = categorySplit;
    return [
      { module: 'Encryption Coverage', pass: encryption,      total: Math.max(encryption, 1),      color: '#3b82f6' },
      { module: 'Data Protection',     pass: data_protection, total: Math.max(data_protection, 1), color: '#f59e0b' },
      { module: 'DLP Rules',           pass: dlpViolations.length, total: Math.max(dlpViolations.length, 1), color: '#06b6d4' },
      { module: 'Data Residency',      pass: dataResidency.length, total: Math.max(dataResidency.length, 1), color: '#10b981' },
      { module: 'Access Monitoring',   pass: accessMonitoring.length, total: Math.max(accessMonitoring.length, 1), color: '#f59e0b' },
    ];
  }, [realFindings.length, categorySplit, dlpViolations.length, dataResidency.length, accessMonitoring.length]);

  // ── Insight strip ────────────────────────────────────────────────────────────
  const insightStrip = useMemo(() => {
    const {
      posture_score, total_findings, critical, high, medium, low,
      dlp_violations, encryption_count, data_protection_count,
    } = kpiNums;

    const sparkPS = activeScanTrend.map(d => d.passRate ?? 0);
    const sparkTF = activeScanTrend.map(d => d.total ?? 0);

    const scoreColor = posture_score >= 70 ? C.emerald
                     : posture_score >= 50 ? C.amber
                     : C.critical;

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

    const donutSlices = [
      { label: 'Critical', value: critical, color: C.critical },
      { label: 'High',     value: high,     color: C.high     },
      { label: 'Medium',   value: medium,   color: C.medium   },
      { label: 'Low',      value: low,      color: C.low      },
    ];

    const first  = activeScanTrend[0];
    const last   = activeScanTrend[activeScanTrend.length - 1];
    const rateΔ  = last.passRate  - first.passRate;
    const critΔ  = (last.critical ?? 0) - (first.critical ?? 0);
    const highΔ  = (last.high ?? 0)     - (first.high ?? 0);
    const totalΔ = (last.total ?? 0)    - (first.total ?? 0);

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
                <div style={{ width: `${Math.round((s.value / (d.total || 1)) * 100)}%`,
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

        {/* ── 4 KPI tiles ── */}
        <div style={{
          flex: 1, display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: 8, minWidth: 0,
        }}>
          {tile('Posture Score',   posture_score,   scoreColor,  '/100',
            `${medium} medium · ${low} low risk`, sparkPS,
            sparkPS.length ? sparkPS[sparkPS.length-1] - sparkPS[0] : null, 'up')}
          {tile('Total Findings', total_findings,  C.high,      '',
            `${critical} critical · ${high} high`, sparkTF,
            sparkTF.length ? sparkTF[sparkTF.length-1] - sparkTF[0] : null, 'down')}
          {tile('Encryption',     encryption_count, C.indigo,   '',
            `${encryption_count} encryption findings`, [], null, 'down')}
          {tile('DLP Violations', dlp_violations,  C.amber,     '',
            `${data_protection_count} data-protection findings`, [], null, 'down')}
        </div>

        {/* ── Findings by Severity donut + Module list ── */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
        }}>
          <div className="flex items-center justify-between mb-0.5">
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
              Findings by Severity
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
              {total_findings.toLocaleString()} total
            </span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 10 }}>
            Data security · severity breakdown
          </div>

          <div className="flex items-center gap-4" style={{ flex: 1 }}>
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <DsDonut slices={donutSlices} size={160} />
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

          {/* Module/domain breakdown */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 16px',
            marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border-primary)',
          }}>
            {activeModuleScores.map(m => {
              const pct = m.total ? Math.round((m.pass / m.total) * 100) : 0;
              const col = pct >= 70 ? C.emerald : pct >= 50 ? C.amber : C.critical;
              return (
                <div key={m.module} style={{ display: 'flex', alignItems: 'center',
                  gap: 6, padding: '3px 0', borderBottom: '1px solid var(--border-primary)' }}>
                  <span style={{ width: 7, height: 7, borderRadius: 2,
                    backgroundColor: m.color, flexShrink: 0 }} />
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)', flex: 1,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {m.module}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: m.color,
                    flexShrink: 0, fontVariantNumeric: 'tabular-nums' }}>
                    {m.pass.toLocaleString()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Scan trend chart ── */}
        <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
          background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', marginBottom: 8 }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                Data Security Trend
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                {first.date} – {last.date} · {activeScanTrend.length} scans
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {[
                { label: 'Critical',  color: C.critical },
                { label: 'High',      color: C.high     },
                { label: 'Medium',    color: C.medium   },
                { label: 'Pass Rate', color: C.emerald  },
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

          <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
            {statPill('Pass Rate', `${last.passRate}%`, rateΔ, 'up'  )}
            {statPill('Critical',  last.critical,       critΔ, 'down')}
            {statPill('High',      last.high,           highΔ, 'down')}
            {statPill('Total',     last.total,          totalΔ,'down')}
          </div>

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
                  <Bar yAxisId="count" dataKey="medium"   name="Medium"   stackId="s" fill="url(#dm)" radius={[0,0,0,0]} />
                  <Bar yAxisId="count" dataKey="high"     name="High"     stackId="s" fill="url(#dh)" radius={[0,0,0,0]} />
                  <Bar yAxisId="count" dataKey="critical" name="Critical" stackId="s" fill="url(#dc)" radius={[3,3,0,0]} />
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
  }, [kpiNums, activeScanTrend, activeModuleScores]);

  // ── Column definitions ──────────────────────────────────────────────────────

  const commonCols = {
    provider: {
      accessorKey: 'provider', header: 'Provider', size: 75,
      cell: (info) => <span className="text-xs font-semibold uppercase"
        style={{ color: 'var(--text-secondary)' }}>{info.getValue() || '—'}</span>,
    },
    account: {
      accessorKey: 'account_id', header: 'Account', size: 130,
      cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
        {info.getValue() || info.row.original.account || '—'}</span>,
    },
    region: {
      accessorKey: 'region', header: 'Region', size: 110,
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue() || '—'}</span>,
    },
    service: {
      accessorKey: 'service', header: 'Service', size: 110,
      cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
        {info.getValue() || info.row.original.resource_type || '—'}</span>,
    },
    ruleId: {
      accessorKey: 'rule_id', header: 'Rule ID', size: 135,
      cell: (info) => <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{info.getValue() || '—'}</span>,
    },
    resource: {
      accessorKey: 'resource_uid', header: 'Resource',
      cell: (info) => { const v = info.getValue() || info.row.original.resource_id || info.row.original.name || ''; return <span className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>{v.split('/').pop() || v.split(':').pop() || v || '—'}</span>; },
    },
    severity: {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    status: {
      accessorKey: 'status', header: 'Status',
      cell: (info) => { const v = info.getValue(), f = v === 'FAIL'; return <span className={`text-xs px-2 py-0.5 rounded ${f ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{v || '—'}</span>; },
    },
    category: {
      accessorKey: 'posture_category', header: 'Category', size: 140,
      cell: (info) => <CategoryBadge value={info.getValue()} />,
    },
    riskScore: {
      accessorKey: 'risk_score', header: 'Risk',
      cell: (info) => { const v = info.getValue(); if (!v) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>; const c = v >= 75 ? '#ef4444' : v >= 50 ? '#f97316' : v >= 25 ? '#eab308' : '#22c55e'; return <div className="flex items-center gap-1.5"><div className="w-10 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}><div className="h-full rounded-full" style={{ width: `${v}%`, backgroundColor: c }} /></div><span className="text-xs font-bold" style={{ color: c }}>{v}</span></div>; },
    },
  };

  // Catalog: resource-focused view of check findings
  const catalogColumns = [
    commonCols.provider,
    commonCols.account,
    commonCols.region,
    commonCols.service,
    commonCols.ruleId,
    commonCols.resource,
    commonCols.category,
    {
      accessorKey: 'title', header: 'Finding',
      cell: (info) => <span className="text-xs" style={{ color: 'var(--text-primary)' }}>{info.getValue() || '—'}</span>,
    },
    commonCols.severity,
    commonCols.status,
    commonCols.riskScore,
  ];

  // Findings: full detail view
  const findingsColumns = useMemo(() => [
    commonCols.provider,
    commonCols.account,
    commonCols.region,
    commonCols.service,
    commonCols.ruleId,
    {
      accessorKey: 'title', header: 'Finding',
      cell: (info) => <span className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue() || info.row.original.rule_id || '—'}</span>,
    },
    commonCols.severity,
    commonCols.status,
    commonCols.resource,
    { accessorKey: 'resource_type', header: 'Type', size: 130 },
    commonCols.category,
    commonCols.riskScore,
  ], []);

  // DLP: data-protection findings with full context columns
  const dlpColumns = useMemo(() => [
    commonCols.provider,
    commonCols.account,
    commonCols.region,
    commonCols.service,
    commonCols.ruleId,
    commonCols.resource,
    {
      accessorKey: 'title', header: 'Policy Violation',
      cell: (info) => <span className="text-xs" style={{ color: 'var(--text-primary)' }}>{info.getValue() || info.row.original.description || '—'}</span>,
    },
    commonCols.severity,
    commonCols.status,
    commonCols.riskScore,
  ], []);

  const residencyColumns = [
    { accessorKey: 'region', header: 'Region', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'assets', header: 'Data Stores', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'compliance', header: 'Compliance Frameworks', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
    { accessorKey: 'status', header: 'Status', cell: (info) => {
      const s = info.getValue();
      return s === 'compliant'
        ? <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-green-500" /><span className="text-sm text-green-400">Compliant</span></div>
        : <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-red-500" /><span className="text-sm text-red-400">Non-compliant</span></div>;
    }},
  ];

  const accessColumns = [
    { accessorKey: 'timestamp', header: 'Timestamp', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{new Date(info.getValue()).toLocaleString()}</span> },
    { accessorKey: 'resource', header: 'Resource', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'user', header: 'User / Service', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'action', header: 'Action', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'location', header: 'Location', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'anomaly', header: 'Anomaly', cell: (info) => (
      info.getValue()
        ? <span className="text-xs px-2 py-1 rounded bg-orange-500/20 text-orange-400">Detected</span>
        : <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>Normal</span>
    )},
  ];

  // ── Filter options derived from real data ───────────────────────────────────
  const serviceOptions = useMemo(() =>
    [...new Set((realFindings).map(f => f.service || '').filter(Boolean))].sort(),
  [realFindings]);

  const dlpServiceOptions = useMemo(() =>
    [...new Set((dlpViolations).map(f => f.service || '').filter(Boolean))].sort(),
  [dlpViolations]);

  const categoryOptions = ['encryption', 'data_protection'];

  // ── Empty state ─────────────────────────────────────────────────────────────
  const EmptyTabState = ({ icon: Icon = FileSearch, message }) => (
    <div className="flex flex-col items-center justify-center py-16 gap-3" style={{ color: 'var(--text-muted)' }}>
      <Icon className="w-8 h-8 opacity-40" />
      <p className="text-sm text-center max-w-md" style={{ color: 'var(--text-secondary)' }}>{message}</p>
    </div>
  );

  // ── Page context ────────────────────────────────────────────────────────────
  const pageContext = {
    title: 'Data Security',
    brief: realFindings.length
      ? `${realFindings.length.toLocaleString()} findings — ${kpiNums.encryption_count} encryption · ${kpiNums.dlp_violations} DLP violations`
      : 'Data catalog, classification, encryption coverage, residency compliance, and DLP violation tracking.',
    tabs: [
      { id: 'overview',  label: 'Overview' },
      { id: 'catalog',   label: 'Data Catalog',     count: catalogData.length       },
      { id: 'findings',  label: 'Findings',          count: realFindings.length      },
      { id: 'dlp',       label: 'DLP',               count: dlpViolations.length     },
      { id: 'residency', label: 'Data Residency',    count: dataResidency.length     },
      { id: 'access',    label: 'Access Monitoring', count: accessMonitoring.length  },
    ],
  };

  const tabData = {
    catalog: {
      data: catalogData,
      columns: catalogColumns,
      filters: [
        { key: 'provider',         label: 'Cloud Platform', options: ['aws', 'azure', 'gcp'] },
        { key: 'severity',         label: 'Severity',       options: ['critical', 'high', 'medium', 'low'] },
        { key: 'status',           label: 'Status',         options: ['FAIL', 'PASS'] },
        { key: 'posture_category', label: 'Category',       options: categoryOptions },
      ],
      extraFilters: [
        { key: 'service',       label: 'Service',       options: serviceOptions },
        { key: 'region',        label: 'Region',        options: [] },
        { key: 'account_id',    label: 'Account',       options: [] },
        { key: 'resource_type', label: 'Resource Type', options: [] },
      ],
      searchPlaceholder: 'Search by rule, resource, account...',
    },
    findings: {
      data: realFindings,
      columns: findingsColumns,
      filters: [
        { key: 'provider',         label: 'Cloud Platform', options: ['aws', 'azure', 'gcp'] },
        { key: 'severity',         label: 'Severity',       options: ['critical', 'high', 'medium', 'low'] },
        { key: 'status',           label: 'Status',         options: ['FAIL', 'PASS'] },
        { key: 'posture_category', label: 'Category',       options: categoryOptions },
        { key: 'service',          label: 'Service',        options: serviceOptions },
      ],
      extraFilters: [
        { key: 'region',        label: 'Region',        options: [] },
        { key: 'account_id',    label: 'Account',       options: [] },
        { key: 'resource_type', label: 'Resource Type', options: [] },
      ],
      searchPlaceholder: 'Search by rule, resource, title...',
    },
    dlp: dlpViolations.length
      ? {
          data: dlpViolations,
          columns: dlpColumns,
          filters: [
            { key: 'provider', label: 'Cloud Platform', options: ['aws', 'azure', 'gcp'] },
            { key: 'severity', label: 'Severity',       options: ['critical', 'high', 'medium', 'low'] },
            { key: 'status',   label: 'Status',         options: ['FAIL', 'PASS'] },
            { key: 'service',  label: 'Service',        options: dlpServiceOptions },
          ],
          extraFilters: [
            { key: 'region',     label: 'Region',  options: [] },
            { key: 'account_id', label: 'Account', options: [] },
          ],
          searchPlaceholder: 'Search by rule, resource...',
        }
      : { renderTab: () => <EmptyTabState icon={ShieldCheck} message="No DLP policy violations detected. Data Loss Prevention findings appear here after scan analysis completes." /> },
    residency: dataResidency.length
      ? { data: dataResidency, columns: residencyColumns }
      : { renderTab: () => <EmptyTabState message="Data residency findings appear after scan — no residency rules matched for this account." /> },
    access: accessMonitoring.length
      ? { data: accessMonitoring, columns: accessColumns }
      : { renderTab: () => <EmptyTabState message="Access monitoring findings appear here after activity analysis. Enable CloudTrail or equivalent logging to populate this tab." /> },
  };

  return (
    <div className="space-y-5">

      {/* ── Heading ── */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Database className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />
            <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Data Security</h1>
          </div>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {pageContext.brief}
          </p>
        </div>
        <button onClick={() => window.location.reload()}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-opacity hover:opacity-80"
          style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* ── Tabs + table ── */}
      <PageLayout
        icon={Database}
        pageContext={pageContext}
        kpiGroups={[]}
        tabData={{ overview: { renderTab: () => insightStrip }, ...tabData }}
        loading={loading}
        error={error}
        defaultTab="overview"
        hideHeader
        topNav
        onRowClick={handleRowClick}
      />
      <FindingDetailPanel finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
}
