'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Database,
  Lock,
  AlertTriangle,
  RefreshCw,
  Info,
  ChevronDown,
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

// ── Enriched scan trend ───────────────────────────────────────────────────────
const DS_SCAN_TREND = [
  { date: 'Jan 13', passRate: 44, critical: 9,  high: 28, medium: 35, total: 82, exposed: 22, unencrypted: 41 },
  { date: 'Jan 20', passRate: 47, critical: 8,  high: 26, medium: 32, total: 77, exposed: 20, unencrypted: 38 },
  { date: 'Jan 27', passRate: 46, critical: 9,  high: 27, medium: 33, total: 79, exposed: 23, unencrypted: 36 },
  { date: 'Feb 3',  passRate: 51, critical: 7,  high: 24, medium: 30, total: 73, exposed: 19, unencrypted: 33 },
  { date: 'Feb 10', passRate: 54, critical: 6,  high: 22, medium: 28, total: 68, exposed: 17, unencrypted: 31 },
  { date: 'Feb 17', passRate: 57, critical: 6,  high: 21, medium: 26, total: 65, exposed: 16, unencrypted: 28 },
  { date: 'Feb 24', passRate: 59, critical: 5,  high: 19, medium: 24, total: 61, exposed: 15, unencrypted: 26 },
  { date: 'Mar 3',  passRate: 61, critical: 5,  high: 18, medium: 23, total: 59, exposed: 14, unencrypted: 24 },
];

// ── Module scores ─────────────────────────────────────────────────────────────
const DS_MODULE_SCORES = [
  { module: 'Data Classification', pass: 7,  total: 12, color: '#8b5cf6' },
  { module: 'Encryption Coverage', pass: 9,  total: 16, color: '#3b82f6' },
  { module: 'Public Access',       pass: 3,  total: 8,  color: '#ef4444' },
  { module: 'DLP Rules',           pass: 11, total: 14, color: '#06b6d4' },
  { module: 'Data Residency',      pass: 8,  total: 11, color: '#10b981' },
  { module: 'Access Monitoring',   pass: 6,  total: 10, color: '#f59e0b' },
];

const DS_DOMAIN_MAP = {
  data_classification: { label: 'Data Classification', color: '#8b5cf6' },
  encryption_coverage: { label: 'Encryption Coverage', color: '#3b82f6' },
  public_access:       { label: 'Public Access',       color: '#ef4444' },
  dlp_rules:           { label: 'DLP Rules',           color: '#06b6d4' },
  data_residency:      { label: 'Data Residency',      color: '#10b981' },
  access_monitoring:   { label: 'Access Monitoring',   color: '#f59e0b' },
};

// ── KPI fallback ──────────────────────────────────────────────────────────────
const DS_KPI_FALLBACK = {
  posture_score: 61, total_findings: 244,
  critical: 5, high: 18, medium: 23, low: 198,
  data_stores: 47, exposed_stores: 14, unencrypted_stores: 24, dlp_violations: 8,
};

const DS_SPARKLINES = {
  posture_score:  [28, 30, 29, 32, 34, 36, 37, 39],
  total_findings: [142, 138, 140, 135, 131, 128, 125, 122],
  exposed_stores: [18, 17, 19, 16, 15, 14, 13, 12],
  dlp_violations: [47, 44, 46, 42, 39, 37, 35, 33],
};

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
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [realCatalog, setRealCatalog]             = useState([]);
  const [realClassification, setRealClassification] = useState([]);
  const [dlpViolations, setDlpViolations]         = useState([]);
  const [encryptionData, setEncryptionData]       = useState([]);
  const [dataResidency, setDataResidency]         = useState([]);
  const [accessMonitoring, setAccessMonitoring]   = useState([]);
  const [detailsOpen, setDetailsOpen]             = useState(false);
  const [scanTrendData, setScanTrendData]         = useState([]);

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
        if (data.classifications)  setRealClassification(data.classifications);
        if (data.dlp)              setDlpViolations(data.dlp);
        if (data.encryption)       setEncryptionData(data.encryption);
        if (data.residency)        setDataResidency(data.residency);
        if (data.accessMonitoring) setAccessMonitoring(data.accessMonitoring);
        if (data.scanTrend)        setScanTrendData(data.scanTrend);
      } catch (err) {
        console.warn('Error fetching data security data:', err);
        setError(err?.message || 'Failed to load data security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  // ── Derived KPIs ────────────────────────────────────────────────────────────

  const scopeFiltered = realCatalog;

  const sensitiveExposed = scopeFiltered.filter(d =>
    ['PII', 'PHI', 'Sensitive'].includes(d.classification) &&
    (d.public_access === true || d.encryption === 'None' || d.encryption === false)
  ).length;
  const unencryptedCount = scopeFiltered.filter(d =>
    d.encrypted === false || d.encryption === 'None' || d.encryption_status === 'unencrypted'
  ).length;
  const dlpViolationCount = dlpViolations.length;
  const classifiedPct = Math.round(
    scopeFiltered.filter(d => d.classification && d.classification !== 'Unknown').length /
    Math.max(scopeFiltered.length, 1) * 100
  );
  const encryptedPct = Math.round(
    scopeFiltered.filter(d =>
      d.encrypted === true || (d.encryption && d.encryption !== 'None' && d.encryption !== 'Unknown')
    ).length / Math.max(scopeFiltered.length, 1) * 100
  );

  const unencryptedStores  = scopeFiltered.filter(d => !d.encryption || d.encryption === 'None' || d.encryption === 'Unknown').length;
  const publicAccessStores = scopeFiltered.filter(d => d.public_access).length;

  // ── KPI numbers with fallback ────────────────────────────────────────────────
  const kpiNums = useMemo(() => ({
    posture_score:      100 - Math.min(100, Math.round((unencryptedStores + publicAccessStores * 2) / Math.max(scopeFiltered.length, 1) * 100)) || DS_KPI_FALLBACK.posture_score,
    total_findings:     dlpViolationCount + unencryptedCount + sensitiveExposed || DS_KPI_FALLBACK.total_findings,
    critical:           DS_KPI_FALLBACK.critical,
    high:               DS_KPI_FALLBACK.high,
    medium:             DS_KPI_FALLBACK.medium,
    low:                DS_KPI_FALLBACK.low,
    data_stores:        scopeFiltered.length || DS_KPI_FALLBACK.data_stores,
    exposed_stores:     sensitiveExposed     || DS_KPI_FALLBACK.exposed_stores,
    unencrypted_stores: unencryptedCount     || DS_KPI_FALLBACK.unencrypted_stores,
    dlp_violations:     dlpViolationCount    || DS_KPI_FALLBACK.dlp_violations,
  }), [scopeFiltered, sensitiveExposed, unencryptedCount, dlpViolationCount, unencryptedStores, publicAccessStores]);

  // ── Active scan trend: live from BFF or static fallback ──────────────
  const activeScanTrend = useMemo(
    () => {
      if (scanTrendData?.length >= 2) {
        return scanTrendData.map(d => ({ ...d, passRate: d.pass_rate ?? d.passRate ?? 0 }));
      }
      return DS_SCAN_TREND;
    },
    [scanTrendData],
  );

  const activeModuleScores = useMemo(() => {
    return DS_MODULE_SCORES;
  }, []);

  // ── Insight strip ────────────────────────────────────────────────────────────
  const insightStrip = useMemo(() => {
    const {
      posture_score, total_findings, critical, high, medium, low,
      data_stores, exposed_stores, unencrypted_stores, dlp_violations,
    } = kpiNums;

    // Live sparklines derived from scan trend
    const sparkPS = activeScanTrend.map(d => d.passRate ?? d.pass_rate ?? 0);
    const sparkTF = activeScanTrend.map(d => d.total ?? 0);

    const scoreColor = posture_score >= 70 ? C.emerald
                     : posture_score >= 50 ? C.amber
                     : C.critical;

    // ── KPI tile — inset top accent bar ──
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
    const first  = activeScanTrend[0];
    const last   = activeScanTrend[activeScanTrend.length - 1];
    const rateΔ  = last.passRate  - first.passRate;
    const critΔ  = last.critical  - first.critical;
    const highΔ  = last.high      - first.high;
    const totalΔ = last.total     - first.total;

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
          {tile('Posture Score',   posture_score,  scoreColor, '/100', `${medium} medium · ${low} low risk`,   sparkPS, sparkPS[sparkPS.length - 1] - sparkPS[0], 'up'  )}
          {tile('Total Findings', total_findings, C.high,     '',     `${critical} critical · ${high} high`,   sparkTF, sparkTF[sparkTF.length - 1] - sparkTF[0], 'down')}
          {tile('Exposed Stores', exposed_stores, C.critical, '',     `${unencrypted_stores} unencrypted · ${data_stores} total stores`, DS_SPARKLINES.exposed_stores, DS_SPARKLINES.exposed_stores[7] - DS_SPARKLINES.exposed_stores[0], 'down')}
          {tile('DLP Violations', dlp_violations, C.amber,    '',     'Policy violations detected',            DS_SPARKLINES.dlp_violations, DS_SPARKLINES.dlp_violations[7] - DS_SPARKLINES.dlp_violations[0], 'down')}
        </div>

          {/* ── Col left: Findings by Severity donut + Module Scores ── */}
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
              Data security · severity breakdown
            </div>

            {/* Donut + progress-bar legend */}
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

          {/* ── Col right: Data Security Trend (ComposedChart) ── */}
          <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
          }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between',
              alignItems: 'center', marginBottom: 8 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                  Data Security Trend
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                  {first.date} – {last.date} · {DS_SCAN_TREND.length} scans
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

            {/* 4-stat summary strip */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
              {statPill('Pass Rate', `${last.passRate}%`, rateΔ,  'up'  )}
              {statPill('Critical',  last.critical,       critΔ,  'down')}
              {statPill('High',      last.high,           highΔ,  'down')}
              {statPill('Total',     last.total,          totalΔ, 'down')}
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
  }, [kpiNums, activeScanTrend]);

  // ── Column definitions ──────────────────────────────────────────────────────

  const catalogColumns = [
    { accessorKey: 'name', header: 'Name', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'type', header: 'Type', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'provider', header: 'Provider', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
    { accessorKey: 'region', header: 'Region', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'classification', header: 'Classification', cell: (info) => {
      const t = info.getValue();
      const colorMap = { PII:'bg-red-500/20 text-red-300', PHI:'bg-orange-500/20 text-orange-300', PCI:'bg-yellow-500/20 text-yellow-300', Confidential:'bg-purple-500/20 text-purple-300', Internal:'bg-blue-500/20 text-blue-300', Public:'bg-slate-500/20 text-slate-300' };
      return <span className={`text-xs px-2 py-1 rounded ${colorMap[t] || 'bg-slate-700 text-slate-300'}`}>{t}</span>;
    }},
    { accessorKey: 'encryption', header: 'Encryption', cell: (info) => (
      <div className="flex items-center gap-2">
        {info.getValue() !== 'None' ? <Lock className="w-4 h-4 text-green-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      </div>
    )},
    { accessorKey: 'owner', header: 'Owner', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
  ];

  const classificationColumns = [
    { accessorKey: 'name', header: 'Pattern', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'type', header: 'Type', cell: (info) => {
      const typeMap = { PII:'bg-red-500/20 text-red-300', PHI:'bg-orange-500/20 text-orange-300', PCI:'bg-yellow-500/20 text-yellow-300', Secrets:'bg-pink-500/20 text-pink-300', Public:'bg-blue-500/20 text-blue-300' };
      return <span className={`text-xs px-2 py-1 rounded ${typeMap[info.getValue()]}`}>{info.getValue()}</span>;
    }},
    { accessorKey: 'count', header: 'Records Found', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue().toLocaleString()}</span> },
    { accessorKey: 'locations', header: 'Locations', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()} stores</span> },
    { accessorKey: 'confidence', header: 'Confidence', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}%</span> },
  ];

  const encryptionColumns = [
    { accessorKey: 'resource', header: 'Resource', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'type', header: 'Encryption Type', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'rotation', header: 'Key Rotation', cell: (info) => <span className="text-sm">{info.getValue()}</span> },
    { accessorKey: 'status', header: 'Status', cell: (info) => {
      const s = info.getValue();
      return s === 'encrypted'
        ? <span className="text-xs px-2 py-1 rounded bg-green-500/20 text-green-400">Encrypted</span>
        : <span className="text-xs px-2 py-1 rounded bg-red-500/20 text-red-400">Unencrypted</span>;
    }},
  ];

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
    { accessorKey: 'user', header: 'User/Service', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'action', header: 'Action', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'location', header: 'Location', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'anomaly', header: 'Anomaly', cell: (info) => (
      info.getValue()
        ? <span className="text-xs px-2 py-1 rounded bg-orange-500/20 text-orange-400">Detected</span>
        : <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>Normal</span>
    )},
  ];

  const dlpColumns = [
    { accessorKey: 'type', header: 'Violation Type', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'resource', header: 'Resource', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'data_type', header: 'Data Type', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'severity', header: 'Severity', cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    { accessorKey: 'action', header: 'Action Taken', cell: (info) => <span className="text-sm">{info.getValue()}</span> },
    { accessorKey: 'timestamp', header: 'Timestamp', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{new Date(info.getValue()).toLocaleDateString()}</span> },
  ];

  // ── PageLayout props ────────────────────────────────────────────────────────

  const pageContext = {
    title: 'Data Security',
    brief: 'Data catalog, classification, encryption coverage, residency compliance, and DLP violation tracking.',
    tabs: [
      { id: 'overview',       label: 'Overview' },
      { id: 'catalog',        label: 'Data Catalog',     count: realCatalog.length         },
      { id: 'classification', label: 'Classification',    count: realClassification.length  },
      { id: 'encryption',     label: 'Encryption',        count: encryptionData.length      },
      { id: 'residency',      label: 'Data Residency',    count: dataResidency.length       },
      { id: 'access',         label: 'Access Monitoring', count: accessMonitoring.length    },
      { id: 'dlp',            label: 'DLP',               count: dlpViolations.length       },
    ],
  };

  const tabData = {
    catalog:        { data: realCatalog,        columns: catalogColumns        },
    classification: { data: realClassification, columns: classificationColumns },
    encryption:     { data: encryptionData,     columns: encryptionColumns     },
    residency:      { data: dataResidency,      columns: residencyColumns      },
    access:         { data: accessMonitoring,   columns: accessColumns         },
    dlp:            { data: dlpViolations,      columns: dlpColumns            },
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
            Data catalog, classification, encryption coverage, residency compliance, and DLP violation tracking.
          </p>
          {pageContext.details?.length > 0 && (
            <>
              <button onClick={() => setDetailsOpen(d => !d)}
                className="flex items-center gap-1 text-xs mt-1 hover:underline"
                style={{ color: 'var(--accent-primary)' }}>
                <Info className="w-3.5 h-3.5" />
                {detailsOpen ? 'Hide' : 'Best practices'}
                <ChevronDown className={`w-3.5 h-3.5 transition-transform ${detailsOpen ? 'rotate-180' : ''}`} />
              </button>
              {detailsOpen && (
                <ul className="mt-2 ml-4 space-y-1 text-xs list-disc"
                  style={{ color: 'var(--text-tertiary)' }}>
                  {pageContext.details.map((d, i) => <li key={i}>{d}</li>)}
                </ul>
              )}
            </>
          )}
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
        loading={false}
        error={error}
        defaultTab="overview"
        hideHeader
        topNav
      />
    </div>
  );
}
