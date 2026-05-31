'use client';

import { useState, useEffect, useMemo } from 'react';
import { Activity, AlertTriangle, AlertOctagon, Info, TrendingUp, Shield, DollarSign, Target, BarChart2, Crown } from 'lucide-react';
import {
  AreaChart, Area,
  PieChart, Pie, Sector, Cell, Legend,
  XAxis, YAxis, CartesianGrid, Tooltip as RechartsTip,
  ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { useViewFetch } from '@/lib/use-view-fetch';
import { subscribeRefresh, emitRefresh } from '@/lib/refreshBus';
import EngineShell from '@/components/shared/EngineShell';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';
import KpiSparkCard from '@/components/shared/KpiSparkCard';

// ── Colour palette ─────────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  emerald:  '#10b981',
  blue:     '#3b82f6',
  purple:   '#8b5cf6',
  amber:    '#f59e0b',
  teal:     '#14b8a6',
  crown:    '#f59e0b',
};

// ── Static fallback scan trend ─────────────────────────────────────────────────
const RISK_SCAN_TREND = [
  { date: 'Jan 13', risk_score: 72 },
  { date: 'Jan 20', risk_score: 69 },
  { date: 'Jan 27', risk_score: 71 },
  { date: 'Feb 3',  risk_score: 68 },
  { date: 'Feb 10', risk_score: 65 },
  { date: 'Feb 17', risk_score: 63 },
  { date: 'Feb 24', risk_score: 60 },
  { date: 'Mar 3',  risk_score: 58 },
];

// ── Helpers ────────────────────────────────────────────────────────────────────
const fmtMoney = (v) => {
  if (!v) return '$0';
  if (v >= 1e9) return `$${(v / 1e9).toFixed(1)}B`;
  if (v >= 1e6) return `$${(v / 1e6).toFixed(1)}M`;
  if (v >= 1e3) return `$${(v / 1e3).toFixed(0)}K`;
  return `$${v}`;
};

const getRiskSeverity = (r) =>
  ({ critical: 'critical', high: 'high', medium: 'medium', low: 'low' }[r] || 'low');

// ── Investigation Step Header ──────────────────────────────────────────────────
function StepHeader({ num, label, sub, icon: Icon, color = 'var(--accent-primary)' }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
      <div style={{
        width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
        backgroundColor: `${color}18`, border: `1.5px solid ${color}40`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ fontSize: 12, fontWeight: 900, color }}>{String(num).padStart(2, '0')}</span>
      </div>
      {Icon && <Icon size={14} style={{ color, flexShrink: 0 }} />}
      <div>
        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.2 }}>
          {label}
        </div>
        {sub && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>{sub}</div>
        )}
      </div>
      <div style={{ flex: 1, height: 1, backgroundColor: 'var(--border-primary)', marginLeft: 4 }} />
    </div>
  );
}

// ── Risk Score Arc Gauge ───────────────────────────────────────────────────────
function RiskGauge({ score = 0, size = 180 }) {
  const cx = size / 2;
  const cy = size * 0.60;
  const r  = size * 0.38;
  const ir = r * 0.60;

  const START = -Math.PI;
  const END   = 0;
  const range = END - START;

  const polar = (a, radius) => ({
    x: cx + radius * Math.cos(a),
    y: cy + radius * Math.sin(a),
  });

  const arcPath = (a0, a1, ro, ri) => {
    const p0 = polar(a0, ro), p1 = polar(a1, ro);
    const p2 = polar(a1, ri), p3 = polar(a0, ri);
    const lg = a1 - a0 > Math.PI ? 1 : 0;
    return `M${p0.x},${p0.y} A${ro},${ro} 0 ${lg} 1 ${p1.x},${p1.y} L${p2.x},${p2.y} A${ri},${ri} 0 ${lg} 0 ${p3.x},${p3.y} Z`;
  };

  const needleAngle = START + (Math.min(score, 100) / 100) * range;
  const needleTip   = polar(needleAngle, r * 0.80);
  const col = score >= 80 ? C.critical : score >= 60 ? C.high : score >= 40 ? C.amber : C.emerald;

  const zones = [
    { a0: START,               a1: START + range * 0.40, fill: `${C.emerald}35` },
    { a0: START + range * 0.40, a1: START + range * 0.60, fill: `${C.amber}35`   },
    { a0: START + range * 0.60, a1: START + range * 0.80, fill: `${C.high}35`    },
    { a0: START + range * 0.80, a1: END,                  fill: `${C.critical}35` },
  ];

  return (
    <svg width={size} height={size * 0.68}
      viewBox={`0 0 ${size} ${size * 0.68}`} style={{ display: 'block' }}>
      {zones.map((z, i) => <path key={i} d={arcPath(z.a0, z.a1, r, ir)} fill={z.fill} />)}
      <path d={arcPath(START, needleAngle, r, ir)} fill={col} opacity={0.92} />
      <line x1={cx} y1={cy} x2={needleTip.x} y2={needleTip.y}
        stroke="var(--text-primary)" strokeWidth={2.5} strokeLinecap="round" />
      <circle cx={cx} cy={cy} r={5} fill={col} />
      <text x={cx} y={cy - r * 0.08}
        textAnchor="middle"
        style={{ fontSize: size * 0.19, fontWeight: 900, fill: col, fontFamily: 'inherit' }}>
        {score}
      </text>
      <text x={cx} y={cy + r * 0.18}
        textAnchor="middle"
        style={{ fontSize: size * 0.072, fill: 'var(--text-muted)', fontFamily: 'inherit' }}>
        / 100
      </text>
      <text x={polar(START, r + 8).x} y={cy + 14} textAnchor="middle"
        style={{ fontSize: 9, fill: C.emerald, fontWeight: 700, fontFamily: 'inherit' }}>LOW</text>
      <text x={polar(END, r + 8).x} y={cy + 14} textAnchor="middle"
        style={{ fontSize: 9, fill: C.critical, fontWeight: 700, fontFamily: 'inherit' }}>HIGH</text>
    </svg>
  );
}

const DOMAIN_COLORS = [C.purple, C.critical, C.blue, C.high, C.amber, C.teal, C.emerald];

const POSTURE_DOMAINS = [
  { key: 'iam_security',       label: 'IAM Security',       color: C.purple,   mult: 1.15 },
  { key: 'misconfig',          label: 'Misconfig / Posture', color: C.critical, mult: 1.10 },
  { key: 'network_security',   label: 'Network Security',    color: C.blue,     mult: 1.05 },
  { key: 'data_security',      label: 'Data Security',       color: C.high,     mult: 0.95 },
  { key: 'encryption',         label: 'Encryption',          color: C.amber,    mult: 0.85 },
  { key: 'database_security',  label: 'Database Security',   color: C.teal,     mult: 0.90 },
  { key: 'container_security', label: 'Container Security',  color: C.emerald,  mult: 0.80 },
];

const normaliseDomains = (raw = [], riskScore = 0) => {
  const liveScores = {};
  raw.forEach(d => {
    const k = (d.category || d.domain || '')
      .toLowerCase()
      .replace(/[\s\-/]+/g, '_')
      .replace(/[^a-z0-9_]/g, '');
    liveScores[k] = d.score ?? 0;
  });

  return POSTURE_DOMAINS.map(p => {
    const liveScore = liveScores[p.key]
      ?? Object.entries(liveScores).find(([k]) => k === p.key)?.[1]
      ?? null;
    return {
      name:  p.label,
      score: liveScore !== null
        ? Math.min(100, liveScore)
        : Math.min(100, Math.round(riskScore * p.mult)),
      color: p.color,
    };
  });
};

// ── Domain Pie Chart ───────────────────────────────────────────────────────────
function DomainPieChart({ domainBreakdown = [], riskScore = 0 }) {
  const [activeIdx, setActiveIdx] = useState(0);

  const pieData = normaliseDomains(domainBreakdown, riskScore);
  const total = pieData.reduce((s, d) => s + (d.score || 0), 0) || 1;
  const active = pieData[activeIdx] ?? pieData[0];
  const activePct = Math.round(((active?.score ?? 0) / total) * 100);

  const renderActiveShape = ({ cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill }) => (
    <g>
      <Sector cx={cx} cy={cy} innerRadius={innerRadius - 2} outerRadius={outerRadius + 12}
        startAngle={startAngle} endAngle={endAngle} fill={fill} />
      <Sector cx={cx} cy={cy} innerRadius={outerRadius + 16} outerRadius={outerRadius + 20}
        startAngle={startAngle} endAngle={endAngle} fill={fill} opacity={0.45} />
      <text x={cx} y={cy - 20} textAnchor="middle" dominantBaseline="middle"
        fontSize={9} fontWeight={700} letterSpacing={1.2}
        fill="var(--text-muted)" style={{ textTransform: 'uppercase' }}>
        {active.name.length > 13 ? active.name.slice(0, 12) + '…' : active.name}
      </text>
      <text x={cx} y={cy + 4} textAnchor="middle" dominantBaseline="middle"
        fontSize={30} fontWeight={900} fill={fill}>
        {activePct}%
      </text>
      <text x={cx} y={cy + 26} textAnchor="middle" dominantBaseline="middle"
        fontSize={10} fill="var(--text-muted)">
        score&nbsp;
        <tspan fontWeight={700} fill="var(--text-secondary)">{active.score}</tspan>
        /100
      </text>
    </g>
  );

  return (
    <div style={{ flex: 1, minHeight: 240 }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            activeIndex={activeIdx}
            activeShape={renderActiveShape}
            data={pieData}
            dataKey="score"
            nameKey="name"
            cx="50%" cy="47%"
            innerRadius="30%"
            outerRadius="46%"
            paddingAngle={2}
            strokeWidth={0}
            onMouseEnter={(_, i) => setActiveIdx(i)}
          >
            {pieData.map((d, i) => (
              <Cell key={i} fill={d.color ?? DOMAIN_COLORS[i % DOMAIN_COLORS.length]}
                opacity={i === activeIdx ? 1 : 0.72}
                style={{ cursor: 'pointer', transition: 'opacity 0.2s' }} />
            ))}
          </Pie>
          <Legend iconType="circle" iconSize={8}
            wrapperStyle={{ fontSize: 10, paddingTop: 6 }}
            formatter={(value, entry) => {
              const pct = Math.round((entry.payload.score / total) * 100);
              const isActive = entry.payload.name === active.name;
              return (
                <span style={{
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  fontWeight: isActive ? 700 : 400,
                }}>
                  {value}&nbsp;<strong style={{ color: entry.color }}>{pct}%</strong>
                </span>
              );
            }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────

export default function RiskPage() {
  const { data: riskData, loading, error, refetch } = useViewFetch('risk');

  useEffect(() => subscribeRefresh(() => refetch()), [refetch]);

  // ── BFF data extraction ─────────────────────────────────────────────────────
  const scenariosData     = riskData?.scenarios       || [];
  const riskRegister      = riskData?.riskRegister    ?? riskData?.risk_register      ?? [];
  const mitigationRoadmap = riskData?.mitigationRoadmap ?? riskData?.mitigation_roadmap ?? [];

  const riskScore = useMemo(() => {
    const items = riskData?.kpiGroups?.[0]?.items ?? [];
    return (
      items.find(x => /risk.*(score|exposure)/i.test(x.label))?.value
      ?? riskData?.riskScore
      ?? riskData?.risk_score
      ?? 0
    );
  }, [riskData]);

  const criticalRisks = useMemo(
    () => scenariosData.filter(s => s.risk_rating === 'critical').length,
    [scenariosData],
  );

  const openMitigations = mitigationRoadmap.filter(
    m => !m.status || m.status === 'planned' || m.status === 'in_progress',
  ).length;

  const totalALE = useMemo(
    () => scenariosData.reduce((s, sc) => s + (sc.expected_loss || 0), 0),
    [scenariosData],
  );

  const riskLevel      = riskScore >= 80 ? 'Critical' : riskScore >= 60 ? 'High' : riskScore >= 40 ? 'Medium' : 'Low';
  const riskLevelColor = riskScore >= 80 ? C.critical : riskScore >= 60 ? C.high : riskScore >= 40 ? C.amber  : C.emerald;

  const domainBreakdown = useMemo(() => riskData?.riskCategories ?? [], [riskData]);

  // Crown jewel assets — scenarios tagged with is_crown_jewel=true
  const crownJewelScenarios = useMemo(
    () => scenariosData
      .filter(s => s.is_crown_jewel)
      .sort((a, b) => (b.expected_loss || 0) - (a.expected_loss || 0))
      .slice(0, 10),
    [scenariosData],
  );

  // ── Live scan trend ─────────────────────────────────────────────────────────
  const activeScanTrend = useMemo(() => {
    const td = riskData?.trendData ?? [];
    if (td.length >= 2) {
      const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      return td.map(d => ({
        date: typeof d.date === 'string' && d.date.includes('-')
          ? (() => {
              const parts = d.date.split('-');
              return `${MONTHS[parseInt(parts[1], 10) - 1] ?? ''} ${parseInt(parts[2], 10)}`;
            })()
          : (d.date ?? ''),
        risk_score: d.score ?? d.risk_score ?? 0,
      }));
    }
    return RISK_SCAN_TREND;
  }, [riskData?.trendData]);

  const sparkRS = activeScanTrend.map(d => d.risk_score ?? 0);
  const trendΔ  = Math.round((sparkRS[sparkRS.length - 1] - sparkRS[0]) * 10) / 10;
  const first   = activeScanTrend[0];
  const last    = activeScanTrend[activeScanTrend.length - 1];

  // ── Trend tooltip ──────────────────────────────────────────────────────────
  const TrendTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    const sc = payload[0]?.payload?.risk_score ?? 0;
    const tc = sc >= 80 ? C.critical : sc >= 60 ? C.high : sc >= 40 ? C.amber : C.emerald;
    return (
      <div style={{
        backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)',
        borderRadius: 10, padding: '10px 14px', boxShadow: '0 6px 24px rgba(0,0,0,.20)',
      }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>{label}</div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
          <span style={{ fontSize: 22, fontWeight: 900, color: tc, fontVariantNumeric: 'tabular-nums' }}>{sc}</span>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/100</span>
        </div>
      </div>
    );
  };

  // ── Overview tab — 5-step investigation workflow ───────────────────────────
  const overviewTab = useMemo(() => {
    const top5 = [...scenariosData]
      .sort((a, b) => (b.expected_loss || 0) - (a.expected_loss || 0))
      .slice(0, 5);

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 28 }}>

        {/* ── Step 1: Financial Exposure ─────────────────────────────────────── */}
        <div>
          <StepHeader num={1} icon={DollarSign} label="Financial Exposure"
            sub="FAIR model — annual loss expectancy across all risk scenarios" color={C.blue} />

          <div style={{ display: 'flex', gap: 12, minHeight: 320 }}>
            {/* 2×2 KPI grid */}
            <div style={{
              flex: 1, display: 'grid',
              gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
              gap: 8, minWidth: 0,
            }}>
              <KpiSparkCard label="Risk Score" value={riskScore} suffix="/100"
                color={riskLevelColor} sub={`${riskLevel} exposure · FAIR model`}
                sparkData={sparkRS} delta={trendΔ} deltaGood="down" />
              <KpiSparkCard label="Total ALE" value={fmtMoney(totalALE)} color={C.amber}
                sub="Annual Loss Expectancy"
                sparkData={sparkRS.map(v => Math.round(v * 18))} delta={null} deltaGood="down" />
              <KpiSparkCard label="Critical Scenarios" value={criticalRisks} color={C.critical}
                sub={`of ${scenariosData.length} total scenarios`}
                sparkData={sparkRS.map(v => Math.round(v / 15))} delta={null} deltaGood="down" />
              <KpiSparkCard label="Open Mitigations" value={openMitigations} color={C.blue}
                sub="Planned / in progress"
                sparkData={sparkRS.map((_, i, a) => Math.max(0, openMitigations - i * Math.floor(openMitigations / a.length)))}
                delta={null} deltaGood="down" />
            </div>

            {/* Gauge + Domain bars */}
            <div className="flex flex-col flex-1 p-4 rounded-xl" style={{
              background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
              border: '1px solid var(--border-primary)', minWidth: 0, overflow: 'hidden',
            }}>
              <div className="flex items-center justify-between mb-1">
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                    Risk Exposure
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                    FAIR model · score 0–100
                  </div>
                </div>
                <span style={{
                  fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20,
                  backgroundColor: `${riskLevelColor}20`, color: riskLevelColor,
                }}>{riskLevel}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'center' }}>
                <RiskGauge score={riskScore} size={180} />
              </div>
              <div style={{ marginTop: 'auto', paddingTop: 8, borderTop: '1px solid var(--border-primary)' }}>
                {normaliseDomains(domainBreakdown, riskScore).map((d) => {
                  const scoreColor = d.score >= 80 ? C.critical : d.score >= 60 ? C.high : d.score >= 40 ? C.amber : C.emerald;
                  return (
                    <div key={d.name} style={{ marginBottom: 5 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                        <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{d.name}</span>
                        <span style={{ fontSize: 11, fontWeight: 700, color: scoreColor }}>{d.score}</span>
                      </div>
                      <div style={{ height: 4, borderRadius: 3, backgroundColor: 'var(--bg-tertiary)' }}>
                        <div style={{ width: `${d.score}%`, height: '100%', borderRadius: 3,
                          backgroundColor: d.color, opacity: 0.9 }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* ── Step 2: Domain Risk Analysis ──────────────────────────────────── */}
        <div>
          <StepHeader num={2} icon={BarChart2} label="Domain Risk Analysis"
            sub="Which security domains contribute most to financial exposure" color={C.purple} />

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            {/* Pie chart */}
            <div className="p-4 rounded-xl" style={{
              background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
              border: '1px solid var(--border-primary)', display: 'flex', flexDirection: 'column', minHeight: 280,
            }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>
                Risk Domain Distribution
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
                FAIR exposure share by domain
              </div>
              <DomainPieChart domainBreakdown={domainBreakdown} riskScore={riskScore} />
            </div>

            {/* FAIR Heat Map */}
            <div className="p-4 rounded-xl" style={{
              background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
              border: '1px solid var(--border-primary)',
            }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>
                FAIR Risk Heat Map
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
                Likelihood (X) vs Impact (Y) · 5×5 matrix
              </div>
              <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
                <div style={{ display: 'flex', flexDirection: 'column',
                  justifyContent: 'space-between', paddingBottom: 22, height: 152 }}>
                  {['5','4','3','2','1'].map(v => (
                    <span key={v} style={{ fontSize: 9, color: 'var(--text-muted)', textAlign: 'right', width: 10 }}>{v}</span>
                  ))}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 3 }}>
                    {Array.from({ length: 25 }).map((_, idx) => {
                      const row = Math.floor(idx / 5);
                      const col = idx % 5;
                      const impact     = 5 - row;
                      const likelihood = col + 1;
                      const raw = impact + likelihood;
                      const bg  = raw >= 8 ? C.critical : raw >= 6 ? C.high : raw >= 4 ? C.amber : C.emerald;
                      return (
                        <div key={idx} style={{
                          aspectRatio: '1', borderRadius: 4,
                          backgroundColor: `${bg}cc`,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: '#fff' }}>
                            {Math.round((impact * likelihood) / 5)}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 3, marginTop: 4 }}>
                    {['1','2','3','4','5'].map(v => (
                      <span key={v} style={{ fontSize: 9, color: 'var(--text-muted)', textAlign: 'center' }}>{v}</span>
                    ))}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 10, flexWrap: 'wrap' }}>
                {[
                  { label: 'Critical', color: C.critical },
                  { label: 'High',     color: C.high     },
                  { label: 'Medium',   color: C.amber    },
                  { label: 'Low',      color: C.emerald  },
                ].map(l => (
                  <span key={l.label} style={{ display: 'flex', alignItems: 'center',
                    gap: 4, fontSize: 10, color: 'var(--text-muted)' }}>
                    <span style={{ width: 8, height: 8, borderRadius: 2,
                      backgroundColor: l.color, display: 'inline-block' }} />
                    {l.label}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Step 3: Top Risk Scenarios ────────────────────────────────────── */}
        <div>
          <StepHeader num={3} icon={AlertTriangle} label="Top Risk Scenarios"
            sub="Ranked by expected financial loss — focus remediation here first" color={C.high} />

          <div className="p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)',
          }}>
            {top5.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {top5.map((s, i) => {
                  const isLast = i === top5.length - 1;
                  const rating = s.risk_rating ?? 'medium';
                  const col  = rating === 'critical' ? C.critical : rating === 'high' ? C.high : rating === 'medium' ? C.amber : C.emerald;
                  const Icon = rating === 'critical' ? AlertOctagon : rating === 'high' ? AlertTriangle : rating === 'medium' ? Activity : Info;
                  const cat = (s.threat_category || s.scenario_category || '')
                    .replace(/_/g, ' ')
                    .replace(/\b\w/g, c => c.toUpperCase());
                  return (
                    <div key={i} style={{ display: 'flex', gap: 10, position: 'relative', paddingBottom: isLast ? 0 : 14 }}>
                      {!isLast && (
                        <div style={{ position: 'absolute', left: 11, top: 24, bottom: 0,
                          width: 1, backgroundColor: 'var(--border-primary)' }} />
                      )}
                      <div style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        width: 24, height: 24, borderRadius: '50%', flexShrink: 0,
                        backgroundColor: `${col}20`, border: `1.5px solid ${col}50`, marginTop: 1, zIndex: 1,
                      }}>
                        <Icon size={11} style={{ color: col }} />
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', flex: 1 }}>
                            {s.scenario_name || `Scenario ${i + 1}`}
                          </span>
                          <div style={{ textAlign: 'right', flexShrink: 0 }}>
                            <div style={{ fontSize: 13, fontWeight: 800, color: col, fontVariantNumeric: 'tabular-nums' }}>
                              {fmtMoney(s.expected_loss || 0)}
                            </div>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                              worst {fmtMoney(s.worst_case_loss || 0)}
                            </div>
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                          <SeverityBadge severity={getRiskSeverity(rating)} />
                          {cat && (
                            <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 10,
                              backgroundColor: `${col}18`, color: col, fontWeight: 600 }}>
                              {cat}
                            </span>
                          )}
                          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                            {s.probability ?? 0}% probability
                          </span>
                          {s.is_crown_jewel && (
                            <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 10,
                              backgroundColor: `${C.crown}25`, color: C.crown, fontWeight: 700 }}>
                              Crown Jewel
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                padding: '32px 0', color: 'var(--text-muted)', fontSize: 12 }}>
                No active scenarios
              </div>
            )}
          </div>
        </div>

        {/* ── Step 4: Risk Score Trend ──────────────────────────────────────── */}
        <div>
          <StepHeader num={4} icon={TrendingUp} label="Risk Score Trend"
            sub={`${first?.date} – ${last?.date} · ${activeScanTrend.length} scans · lower is better`} color={C.teal} />

          <div className="p-4 rounded-xl" style={{
            background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
            border: '1px solid var(--border-primary)',
          }}>
            {/* Stat pills */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              {[
                { label: 'Current Score', value: last?.risk_score ?? 0,                   color: riskLevelColor },
                { label: 'Trend',         value: `${trendΔ > 0 ? '+' : ''}${trendΔ}`,    color: trendΔ <= 0 ? C.emerald : C.critical },
                { label: 'Total Scenarios', value: scenariosData.length,                  color: 'var(--text-primary)' },
                { label: 'Critical',        value: criticalRisks,                         color: C.critical },
              ].map(({ label, value, color }) => (
                <div key={label} style={{
                  flex: 1, backgroundColor: 'var(--bg-secondary)',
                  border: '1px solid var(--border-primary)', borderRadius: 8, padding: '8px 10px',
                }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600,
                    textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>
                    {label}
                  </div>
                  <div style={{ fontSize: 20, fontWeight: 900, color, lineHeight: 1,
                    fontVariantNumeric: 'tabular-nums' }}>
                    {value}
                  </div>
                </div>
              ))}
            </div>

            <div style={{ height: 200 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activeScanTrend} margin={{ top: 6, right: 10, left: -14, bottom: 0 }}>
                  <defs>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%"   stopColor={C.critical} stopOpacity={0.35} />
                      <stop offset="100%" stopColor={C.critical} stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} strokeDasharray="3 3"
                    stroke="var(--border-primary)" opacity={0.5} />
                  <XAxis dataKey="date"
                    tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
                    axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]}
                    tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'inherit' }}
                    axisLine={false} tickLine={false} width={24} />
                  <ReferenceLine y={75} stroke={C.critical} strokeDasharray="5 3" strokeOpacity={0.4}
                    label={{ value: 'High ≥75', position: 'insideTopRight', fontSize: 9, fill: C.critical, opacity: 0.7 }} />
                  <ReferenceLine y={40} stroke={C.amber} strokeDasharray="5 3" strokeOpacity={0.4}
                    label={{ value: 'Medium ≥40', position: 'insideTopRight', fontSize: 9, fill: C.amber, opacity: 0.7 }} />
                  <RechartsTip content={<TrendTooltip />} />
                  <Area type="monotone" dataKey="risk_score"
                    stroke={C.critical} strokeWidth={2.5}
                    fill="url(#riskGrad)"
                    dot={{ r: 3, fill: C.critical, strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: C.critical, stroke: 'var(--bg-card)', strokeWidth: 2 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* ── Step 5: Crown Jewel Assets at Risk ────────────────────────────── */}
        <div>
          <StepHeader num={5} icon={Crown} label="Crown Jewel Assets at Risk"
            sub="High-value assets with amplified FAIR exposure scores" color={C.crown} />

          {crownJewelScenarios.length > 0 ? (
            <div className="p-4 rounded-xl" style={{
              background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
              border: `1px solid ${C.crown}40`,
            }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {crownJewelScenarios.map((s, i) => {
                  const rating = s.risk_rating ?? 'high';
                  const col  = rating === 'critical' ? C.critical : rating === 'high' ? C.high : C.amber;
                  const typeLabel = (s.crown_jewel_type || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                  return (
                    <div key={i} style={{
                      display: 'flex', alignItems: 'center', gap: 12,
                      padding: '10px 12px', borderRadius: 8,
                      backgroundColor: `${C.crown}08`, border: `1px solid ${C.crown}25`,
                    }}>
                      <Crown size={14} style={{ color: C.crown, flexShrink: 0 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)',
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {s.scenario_name || s.resource_uid || `Asset ${i + 1}`}
                        </div>
                        <div style={{ display: 'flex', gap: 6, marginTop: 3, alignItems: 'center', flexWrap: 'wrap' }}>
                          {typeLabel && (
                            <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 10,
                              backgroundColor: `${C.crown}20`, color: C.crown, fontWeight: 700 }}>
                              {typeLabel}
                            </span>
                          )}
                          <SeverityBadge severity={getRiskSeverity(rating)} />
                          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                            {s.csp || s.provider || ''} {s.region ? `· ${s.region}` : ''}
                          </span>
                        </div>
                      </div>
                      <div style={{ textAlign: 'right', flexShrink: 0 }}>
                        <div style={{ fontSize: 14, fontWeight: 800, color: col, fontVariantNumeric: 'tabular-nums' }}>
                          {fmtMoney(s.expected_loss || 0)}
                        </div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>ALE</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="p-6 rounded-xl" style={{
              background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
              border: '1px solid var(--border-primary)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--text-muted)', fontSize: 12,
            }}>
              No crown jewel assets identified in current scenarios
            </div>
          )}
        </div>

      </div>
    );
  }, [
    riskScore, riskLevel, riskLevelColor, criticalRisks, totalALE, openMitigations,
    scenariosData, domainBreakdown, activeScanTrend, sparkRS, trendΔ, first, last,
    crownJewelScenarios, TrendTooltip,
  ]);

  // ── Column defs ────────────────────────────────────────────────────────────
  const scenarioColumns = [
    { accessorKey: 'scenario_name',   header: 'Risk Scenario',
      cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'threat_category', header: 'Threat Category',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
    { accessorKey: 'probability',     header: 'Probability',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}%</span> },
    { accessorKey: 'expected_loss',   header: 'Expected Loss',
      cell: (info) => <span className="text-sm font-semibold" style={{ color: C.amber }}>{fmtMoney(info.getValue())}</span> },
    { accessorKey: 'worst_case_loss', header: 'Worst Case',
      cell: (info) => <span className="text-sm font-semibold" style={{ color: C.high }}>{fmtMoney(info.getValue())}</span> },
    { accessorKey: 'risk_rating',     header: 'Risk Rating',
      cell: (info) => <SeverityBadge severity={getRiskSeverity(info.getValue())} /> },
  ];

  const registerColumns = [
    { accessorKey: 'id',       header: 'ID', size: 80,
      cell: (info) => <span className="text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'title',    header: 'Risk Title',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'category', header: 'Category',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
    { accessorKey: 'inherent', header: 'Inherent', size: 80,
      cell: (info) => { const v = info.getValue();
        return <span className="text-sm font-bold" style={{ color: v > 75 ? C.critical : 'var(--text-secondary)' }}>{v}</span>; } },
    { accessorKey: 'residual', header: 'Residual', size: 80,
      cell: (info) => { const v = info.getValue();
        return <span className="text-sm font-bold" style={{ color: v > 40 ? C.critical : C.emerald }}>{v}</span>; } },
    { accessorKey: 'owner',    header: 'Owner',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'status',   header: 'Status', size: 100,
      cell: (info) => {
        const s = info.getValue();
        const bg  = s === 'Open' ? '#ef44442a' : s === 'Mitigated' ? '#10b9812a' : '#8b5cf62a';
        const col = s === 'Open' ? C.critical : s === 'Mitigated' ? C.emerald : '#8b5cf6';
        return <span className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: bg, color: col }}>{s}</span>;
      } },
  ];

  const roadmapColumns = [
    { accessorKey: 'action',       header: 'Action',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'current_risk', header: 'Current', size: 80,
      cell: (info) => <span className="text-sm font-bold" style={{ color: C.amber }}>{info.getValue()}</span> },
    { accessorKey: 'target_risk',  header: 'Target', size: 80,
      cell: (info) => <span className="text-sm font-bold" style={{ color: C.emerald }}>{info.getValue()}</span> },
    { id: 'reduction',             header: 'Reduction', size: 85,
      cell: ({ row }) => {
        const { current_risk, target_risk } = row.original;
        const r = current_risk ? ((current_risk - target_risk) / current_risk * 100).toFixed(0) : 0;
        return <span className="text-sm font-bold" style={{ color: C.emerald }}>↓ {r}%</span>;
      } },
    { accessorKey: 'cost',     header: 'Cost', size: 90,
      cell: (info) => <span className="text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'priority', header: 'Priority', size: 85,
      cell: (info) => {
        const p = info.getValue();
        const bg  = p === 'Critical' ? '#ef44442a' : '#f59e0b2a';
        const col = p === 'Critical' ? C.critical : C.amber;
        return <span className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: bg, color: col }}>{p}</span>;
      } },
    { accessorKey: 'owner',    header: 'Owner', size: 100,
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'due_date', header: 'Due Date', size: 100,
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
  ];

  // ── Page context ────────────────────────────────────────────────────────────
  const pageContext = {
    title: 'Enterprise Risk Management',
    brief: 'Financial risk quantification, scenario modeling, and mitigation roadmap using FAIR methodology',
    tabs: [
      { id: 'overview',  label: 'Overview'                                                    },
      { id: 'scenarios', label: 'Risk Scenarios',     count: scenariosData.length             },
      { id: 'register',  label: 'Risk Register',      count: riskRegister.length              },
      { id: 'roadmap',   label: 'Mitigation Roadmap', count: mitigationRoadmap.length         },
    ],
  };

  const tabData = {
    overview: { renderTab: () => overviewTab },
    scenarios: {
      data: scenariosData,
      columns: scenarioColumns,
      filters: [
        { key: 'risk_rating',     label: 'Risk Rating',     options: ['critical', 'high', 'medium', 'low'] },
        { key: 'threat_category', label: 'Threat Category', options: [...new Set(scenariosData.map(s => s.threat_category).filter(Boolean))].sort() },
      ],
      groupByOptions: [
        { key: 'risk_rating',     label: 'Risk Rating'     },
        { key: 'threat_category', label: 'Threat Category' },
      ],
    },
    register: {
      data: riskRegister,
      columns: registerColumns,
      filters: [
        { key: 'status',   label: 'Status',   options: ['Open', 'Mitigated', 'Accepted'] },
        { key: 'category', label: 'Category', options: [...new Set(riskRegister.map(r => r.category).filter(Boolean))].sort() },
      ],
    },
    roadmap: {
      data: mitigationRoadmap,
      columns: roadmapColumns,
      filters: [
        { key: 'priority', label: 'Priority', options: ['Critical', 'High', 'Medium', 'Low'] },
      ],
    },
  };

  return (
    <EngineShell
      icon={Activity}
      title="Enterprise Risk Management"
      description="Financial risk quantification · scenario modeling · FAIR methodology"
      onRefresh={() => emitRefresh()}
      refreshing={loading}
    >
      <PageLayout
        icon={Activity}
        pageContext={pageContext}
        kpiGroups={[]}
        tabData={tabData}
        persistenceKey="risk"
        loading={loading}
        error={error}
        defaultTab="overview"
        hideHeader
        topNav
      />
    </EngineShell>
  );
}
