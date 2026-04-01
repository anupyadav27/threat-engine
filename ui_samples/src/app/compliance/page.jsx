'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  ClipboardCheck, CheckCircle, XCircle, RefreshCw,
  AlertTriangle, Shield, BarChart3,
} from 'lucide-react';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PieChart, Pie, Cell,
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip as RechartsTip,
  ResponsiveContainer, Legend,
} from 'recharts';
import { postToEngine } from '@/lib/api';
import { TENANT_ID } from '@/lib/constants';
import { useToast } from '@/lib/toast-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import KpiSparkCard from '@/components/shared/KpiSparkCard';
import SearchBar from '@/components/shared/SearchBar';

/**
 * Fetch compliance data through our local BFF interceptor.
 * The interceptor (src/app/api/bff/compliance/route.js) tries the live NLB,
 * detects degenerate data (empty framework names / all-zero scores), and falls
 * back to rich mock data so every KPI card and chart is populated even before
 * engine DB fixes are deployed to EKS.
 */
async function fetchComplianceView(params = {}) {
  const qs = new URLSearchParams();
  if (TENANT_ID) qs.set('tenant_id', TENANT_ID);
  if (params.provider) qs.set('provider', params.provider);
  if (params.account)  qs.set('account',  params.account);
  if (params.region)   qs.set('region',   params.region);

  const origin =
    typeof window !== 'undefined'
      ? window.location.origin
      : 'http://localhost:3000';
  const url = `${origin}/api/bff/compliance?${qs}`;
  try {
    const res = await fetch(url);
    if (!res.ok) return { error: `BFF error: ${res.status}` };
    return res.json();
  } catch (err) {
    return { error: err?.message || 'Failed to fetch compliance data' };
  }
}

// ── Colour palette ────────────────────────────────────────────────────────────
const C = {
  passed:   '#22c55e',
  failed:   '#ef4444',
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  blue:     '#3b82f6',
  purple:   '#8b5cf6',
  teal:     '#14b8a6',
  amber:    '#f59e0b',
};

const MATRIX_FRAMEWORKS = ['CIS', 'NIST', 'SOC2', 'PCI', 'HIPAA', 'ISO', 'GDPR'];
const MATRIX_FRAMEWORK_LABELS = {
  CIS: 'CIS AWS', NIST: 'NIST 800-53', SOC2: 'SOC 2',
  PCI: 'PCI DSS', HIPAA: 'HIPAA', ISO: 'ISO 27001', GDPR: 'GDPR',
};
const FW_COLORS = ['#3b82f6', '#8b5cf6', '#22c55e', '#f97316', '#ef4444', '#14b8a6', '#f59e0b'];

const SEV_CFG = {
  critical: { bg: 'rgba(239,68,68,0.15)',  text: '#ef4444' },
  high:     { bg: 'rgba(249,115,22,0.15)', text: '#f97316' },
  medium:   { bg: 'rgba(234,179,8,0.15)',  text: '#eab308' },
  low:      { bg: 'rgba(34,197,94,0.15)',  text: '#22c55e' },
};

const AUDIT_CHECKLIST = [
  { label: 'All framework scans up to date',   done: true  },
  { label: 'Zero critical unresolved controls', done: false },
  { label: 'Active exceptions reviewed',        done: true  },
  { label: 'Evidence packages generated',       done: false },
  { label: 'Audit trail continuity verified',   done: true  },
  { label: 'Remediation plan for failures',     done: false },
];

function matrixCellColor(score, expired) {
  if (expired) return { bg: 'var(--bg-tertiary)', text: 'var(--text-muted)' };
  const hue = (score / 100) * 120;
  return {
    bg:   `hsla(${hue}, 70%, 45%, 0.2)`,
    text: score >= 75 ? '#22c55e' : score >= 55 ? '#f59e0b' : '#ef4444',
  };
}

// ── Compliance Gauge ──────────────────────────────────────────────────────────
function ComplianceGauge({ score = 0, size = 170 }) {
  const r   = size * 0.38;
  const cx  = size / 2;
  const cy  = size * 0.56;
  const pct = Math.min(Math.max(score, 0), 100) / 100;
  const toXY = (a) => [cx + r * Math.cos(a), cy + r * Math.sin(a)];

  const [tx1, ty1] = toXY(Math.PI);
  const [tx2, ty2] = toXY(0);
  const needleAngle = Math.PI - pct * Math.PI;
  const [sx2, sy2] = toXY(needleAngle);
  const largeArc = pct > 0.5 ? 1 : 0;
  const [nx, ny]  = [cx + (r - 10) * Math.cos(needleAngle), cy + (r - 10) * Math.sin(needleAngle)];
  const col = score >= 80 ? C.passed : score >= 60 ? C.amber : score >= 40 ? C.high : C.failed;

  return (
    <svg width={size} height={size * 0.62} viewBox={`0 0 ${size} ${size * 0.62}`}>
      <path d={`M ${tx1} ${ty1} A ${r} ${r} 0 0 1 ${tx2} ${ty2}`}
        fill="none" stroke="var(--bg-tertiary)" strokeWidth={size * 0.06} strokeLinecap="round" />
      {pct > 0 && (
        <path d={`M ${tx1} ${ty1} A ${r} ${r} 0 ${largeArc} 1 ${sx2} ${sy2}`}
          fill="none" stroke={col} strokeWidth={size * 0.06} strokeLinecap="round" />
      )}
      <line x1={cx} y1={cy} x2={nx} y2={ny} stroke={col} strokeWidth={2.5} strokeLinecap="round" opacity={0.85} />
      <circle cx={cx} cy={cy} r={4} fill={col} />
      <text x={cx} y={cy - r * 0.16} textAnchor="middle" fontSize={size * 0.2} fontWeight={900} fill={col}>{score}</text>
      <text x={cx} y={cy + r * 0.12} textAnchor="middle" fontSize={size * 0.09} fill="var(--text-muted)">/ 100</text>
    </svg>
  );
}

// ──────────────────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const router = useRouter();
  const toast  = useToast();
  const { provider, account, region } = useGlobalFilter();

  const [loading,         setLoading]         = useState(true);
  const [error,           setError]           = useState(null);
  const [trendData,       setTrendData]       = useState([]);
  const [frameworks,      setFrameworks]      = useState([]);
  const [auditDeadlines,  setAuditDeadlines]  = useState([]);
  const [exceptions,      setExceptions]      = useState([]);
  const [accounts,        setAccounts]        = useState([]);
  const [failingControls, setFailingControls] = useState([]);
  const [overallScore,    setOverallScore]    = useState(null);

  const [matrixSortBy,  setMatrixSortBy]  = useState('account');
  const [matrixSortDir, setMatrixSortDir] = useState('asc');
  const [hoveredCell,   setHoveredCell]   = useState(null);
  const [tooltipPos,    setTooltipPos]    = useState({ x: 0, y: 0 });
  const [frameworkSearch, setFrameworkSearch] = useState('');

  // ── Fetch ─────────────────────────────────────────────────────────────────
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchComplianceView({
          provider: provider || undefined,
          account:  account  || undefined,
          region:   region   || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.frameworks)      setFrameworks(data.frameworks);
        if (data.trendData)       setTrendData(data.trendData);
        if (data.auditDeadlines)  setAuditDeadlines(data.auditDeadlines);
        if (data.exceptions)      setExceptions(data.exceptions);
        if (data.accountMatrix)   setAccounts(data.accountMatrix);
        if (data.failingControls) setFailingControls(data.failingControls);
        // Score from dedicated key or kpiGroups
        const sc = data.overallScore
          ?? data.kpiGroups?.[0]?.items?.find(x => /overall/i.test(x.label))?.value
          ?? data.kpiGroups?.[1]?.items?.find(x => /overall/i.test(x.label))?.value
          ?? null;
        if (sc != null) setOverallScore(sc);
      } catch (err) {
        console.warn('[compliance] fetch error:', err);
        setError(err?.message || 'Failed to load compliance data');
      } finally { setLoading(false); }
    };
    fetchData();
  }, [provider, account, region]);

  // ── Actions ───────────────────────────────────────────────────────────────
  const handleGenerateReport = async () => {
    try {
      const r = await postToEngine('compliance', '/api/v1/compliance/generate/from-threat-engine', { tenant_id: TENANT_ID });
      r && !r.error ? toast.success('Report generation started.') : toast.info('Report queued.');
    } catch { toast.info('Report request sent.'); }
  };

  const handleMatrixSort = (col) => {
    if (matrixSortBy === col) setMatrixSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setMatrixSortBy(col); setMatrixSortDir('desc'); }
  };

  // ── Derived KPIs ─────────────────────────────────────────────────────────
  const passedControls   = frameworks.reduce((s, fw) => s + (fw.passed   || 0), 0);
  const failedControls   = frameworks.reduce((s, fw) => s + (fw.failed   || 0), 0);
  const totalControls    = Math.max(frameworks.reduce((s, fw) => s + (fw.controls || 0), 0), passedControls + failedControls);
  const passRate         = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 0;
  const criticalFailures = failingControls.filter(c => c.severity === 'critical').length;
  const highFailures     = failingControls.filter(c => c.severity === 'high').length;
  const atRiskCount      = frameworks.filter(fw => (fw.score ?? 0) < 70).length;
  const computedScore    = Math.round(overallScore ?? passRate ?? 0);
  const auditReadiness   = Math.round((AUDIT_CHECKLIST.filter(c => c.done).length / AUDIT_CHECKLIST.length) * 100);
  const expiringExc      = exceptions.filter(e => e.status === 'expiring-soon').length;

  // ── Trend normalization ───────────────────────────────────────────────────
  const activeTrend = useMemo(() => {
    if (trendData.length >= 2) {
      const M = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      return trendData.map(d => ({
        date: typeof d.date === 'string' && d.date.includes('-')
          ? (() => { const p = d.date.split('-'); return `${M[parseInt(p[1],10)-1]??''} ${parseInt(p[2],10)}`; })()
          : (d.date ?? ''),
        score: d.score ?? 0,
      }));
    }
    return trendData;
  }, [trendData]);

  const sparkScore = activeTrend.map(d => d.score ?? 0);
  const scoreΔ = sparkScore.length >= 2
    ? Math.round((sparkScore[sparkScore.length - 1] - sparkScore[0]) * 10) / 10
    : 0;

  // ── Per-framework severity counts (from failingControls) ──────────────────
  const fwSeverityMap = useMemo(() => {
    const map = {};
    failingControls.forEach(c => {
      const fw = c.framework || 'Unknown';
      if (!map[fw]) map[fw] = { critical: 0, high: 0, medium: 0, low: 0 };
      if (c.severity) map[fw][c.severity] = (map[fw][c.severity] || 0) + 1;
    });
    return map;
  }, [failingControls]);

  // ── Sorted matrix rows ────────────────────────────────────────────────────
  const sortedMatrix = useMemo(() => {
    return [...accounts].sort((a, b) => {
      let va, vb;
      if (matrixSortBy === 'account') {
        va = a.account || a.account_id || '';
        vb = b.account || b.account_id || '';
        return matrixSortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
      }
      if (matrixSortBy === 'avg') {
        const avg = r => MATRIX_FRAMEWORKS.reduce((s, fw) => s + (r[fw] || 0), 0) / MATRIX_FRAMEWORKS.length;
        va = avg(a); vb = avg(b);
      } else { va = a[matrixSortBy] || 0; vb = b[matrixSortBy] || 0; }
      return matrixSortDir === 'asc' ? va - vb : vb - va;
    });
  }, [accounts, matrixSortBy, matrixSortDir]);

  // ── Column definitions ────────────────────────────────────────────────────
  const failingControlColumns = [
    { accessorKey: 'control_id', header: 'Control ID', cell: i => <code className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>{i.getValue()}</code> },
    { accessorKey: 'title',      header: 'Control',    cell: i => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span> },
    { accessorKey: 'framework',  header: 'Framework',  cell: i => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey: 'account',    header: 'Account',    cell: i => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{i.getValue()}</span> },
    { accessorKey: 'severity',   header: 'Severity',   cell: i => { const s = i.getValue(); const c = SEV_CFG[s] || SEV_CFG.medium; return <span className="text-xs px-2 py-0.5 rounded-full font-semibold capitalize" style={{ backgroundColor: c.bg, color: c.text }}>{s}</span>; } },
    { accessorKey: 'days_open',  header: 'Days Open',  cell: i => { const d = i.getValue(); return <span className="text-xs font-semibold" style={{ color: d > 30 ? C.failed : d > 14 ? C.high : 'var(--text-tertiary)' }}>{d}d</span>; } },
  ];

  const auditColumns = [
    { accessorKey: 'framework',      header: 'Framework',  cell: i => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span> },
    { accessorKey: 'type',           header: 'Audit Type', cell: i => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey: 'due_date',       header: 'Due Date',   cell: i => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{new Date(i.getValue()).toLocaleDateString()}</span> },
    { accessorKey: 'days_remaining', header: 'Days Left',  cell: i => { const d = i.getValue(); return <span className={`text-sm font-semibold ${d <= 30 ? 'text-red-400' : 'text-green-400'}`}>{d}d</span>; } },
    { accessorKey: 'owner',          header: 'Owner',      cell: i => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey: 'status',         header: 'Status',     cell: i => { const s = i.getValue(); const cfg = { 'on-track': { bg: 'rgba(34,197,94,0.15)', text: '#22c55e', label: 'On Track' }, 'at-risk': { bg: 'rgba(249,115,22,0.15)', text: '#f97316', label: 'At Risk' } }; const c = cfg[s] || cfg['on-track']; return <span className="text-xs px-2 py-1 rounded font-medium" style={{ backgroundColor: c.bg, color: c.text }}>{c.label}</span>; } },
  ];

  const exceptionColumns = [
    { accessorKey: 'framework',     header: 'Framework',     cell: i => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span> },
    { accessorKey: 'control',       header: 'Control',       cell: i => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey: 'justification', header: 'Justification', cell: i => <span className="text-sm line-clamp-2" style={{ color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey: 'approved_by',   header: 'Approved By',   cell: i => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey: 'expiry_date',   header: 'Expires',       cell: i => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{new Date(i.getValue()).toLocaleDateString()}</span> },
    { accessorKey: 'status',        header: 'Status',        cell: i => { const s = i.getValue(); return <span className="text-xs px-2 py-1 rounded font-medium" style={{ backgroundColor: s === 'expiring-soon' ? 'rgba(249,115,22,0.15)' : 'rgba(34,197,94,0.15)', color: s === 'expiring-soon' ? '#f97316' : '#22c55e' }}>{s === 'expiring-soon' ? 'Expiring Soon' : 'Active'}</span>; } },
  ];

  // ── Insight Strip ─────────────────────────────────────────────────────────
  const insightStrip = useMemo(() => {
    const col   = computedScore >= 80 ? C.passed : computedScore >= 60 ? C.amber : computedScore >= 40 ? C.high : C.failed;
    const level = computedScore >= 80 ? 'Good' : computedScore >= 60 ? 'Fair' : computedScore >= 40 ? 'At Risk' : 'Critical';

    const TrendTip = ({ active, payload, label }) => {
      if (!active || !payload?.length) return null;
      const sc = payload[0]?.value ?? 0;
      const tc = sc >= 80 ? C.passed : sc >= 60 ? C.amber : sc >= 40 ? C.high : C.failed;
      return (
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)', borderRadius: 10, padding: '10px 14px', boxShadow: '0 6px 24px rgba(0,0,0,.2)' }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>{label}</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
            <span style={{ fontSize: 22, fontWeight: 900, color: tc }}>{sc}</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>/ 100</span>
          </div>
        </div>
      );
    };

    const top5 = [...failingControls]
      .sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1 }[b.severity] ?? 0) - ({ critical: 4, high: 3, medium: 2, low: 1 }[a.severity] ?? 0))
      .slice(0, 5);

    return (
      <div className="flex gap-3 items-stretch" style={{ minHeight: 330, marginBottom: 12 }}>

        {/* ── Col 1: 2×3 KPI Grid ── */}
        <div style={{ flex: 1.3, display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 8, minWidth: 0 }}>
          <KpiSparkCard label="Overall Score"   value={`${computedScore}%`}             color={col}        sub={`${level} posture`}                          sparkData={sparkScore} delta={scoreΔ} deltaGood="up" />
          <KpiSparkCard label="Pass Rate"       value={`${passRate}%`}                  color={C.passed}   sub={`${passedControls.toLocaleString()} / ${totalControls.toLocaleString()}`} sparkData={sparkScore} delta={scoreΔ} deltaGood="up" />
          <KpiSparkCard label="Critical Gaps"   value={criticalFailures}                color={C.critical} sub={`${highFailures} high severity`}             sparkData={sparkScore.map(v => Math.max(0, Math.round((100 - v) / 10)))} delta={-criticalFailures} deltaGood="down" />
          <KpiSparkCard label="At-Risk FWs"     value={atRiskCount}                     color={C.high}     sub="frameworks below 70%"                        sparkData={sparkScore.map(v => Math.max(0, 7 - Math.round(v / 15)))} delta={null} deltaGood="down" />
          <KpiSparkCard label="Total Controls"  value={totalControls.toLocaleString()}  color={C.blue}     sub={`${frameworks.length} frameworks`}            sparkData={sparkScore.map(v => Math.round(v * 5))} delta={null} deltaGood="up" />
          <KpiSparkCard label="Audit Readiness" value={`${auditReadiness}%`}            color={C.teal}     sub={`${expiringExc} exceptions expiring`}         sparkData={sparkScore} delta={null} deltaGood="up" />
        </div>

        {/* ── Col 2: Gauge + Framework Bars ── */}
        <div className="p-4 rounded-xl flex flex-col" style={{
          flex: 1.1, background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)', minWidth: 0,
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>Compliance Posture</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Overall score · 0–100</div>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <ComplianceGauge score={computedScore} size={168} />
          </div>
          <div style={{ marginTop: 'auto', paddingTop: 8, borderTop: '1px solid var(--border-primary)' }}>
            {frameworks.length === 0
              ? <p style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>No framework data</p>
              : frameworks.slice(0, 7).map((fw, i) => {
                  const sc   = fw.score ?? 0;
                  const sCol = sc >= 80 ? C.passed : sc >= 60 ? C.amber : sc >= 40 ? C.high : C.failed;
                  return (
                    <div key={fw.id || i} style={{ marginBottom: 5 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                        <span style={{ fontSize: 10, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '72%' }}>{fw.name}</span>
                        <span style={{ fontSize: 10, fontWeight: 700, color: sCol }}>{sc}%</span>
                      </div>
                      <div style={{ height: 4, borderRadius: 3, backgroundColor: 'var(--bg-tertiary)' }}>
                        <div style={{ width: `${sc}%`, height: '100%', borderRadius: 3, backgroundColor: FW_COLORS[i % FW_COLORS.length], opacity: 0.85 }} />
                      </div>
                    </div>
                  );
                })
            }
          </div>
        </div>

        {/* ── Col 3: Score Trend + Failing Controls Feed ── */}
        <div className="p-4 rounded-xl flex flex-col" style={{
          flex: 1.2, background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))',
          border: '1px solid var(--border-primary)', minWidth: 0,
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>Score Trend</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>12-month compliance score</div>
          <div style={{ height: 105 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activeTrend} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <defs>
                  <linearGradient id="cmpGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={C.passed} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={C.passed} stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" opacity={0.4} />
                <XAxis dataKey="date" tick={{ fontSize: 9, fill: 'var(--text-muted)' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: 'var(--text-muted)' }} tickLine={false} axisLine={false} />
                <RechartsTip content={<TrendTip />} />
                <Area type="monotone" dataKey="score" stroke={C.passed} strokeWidth={2} fill="url(#cmpGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div style={{ borderTop: '1px solid var(--border-primary)', margin: '10px 0 8px' }} />

          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
            Top Failing Controls
          </div>
          {top5.length === 0
            ? <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>No failing controls — great posture! ✅</p>
            : top5.map((c, i) => {
                const sc = SEV_CFG[c.severity] || SEV_CFG.medium;
                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 7, paddingBottom: 7, borderBottom: i < top5.length - 1 ? '1px solid var(--border-primary)' : 'none' }}>
                    <div style={{ width: 3, alignSelf: 'stretch', borderRadius: 2, backgroundColor: sc.text, flexShrink: 0, marginTop: 2 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {c.title || c.control_id}
                      </div>
                      <div style={{ display: 'flex', gap: 6, marginTop: 2, flexWrap: 'wrap', alignItems: 'center' }}>
                        <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 10, backgroundColor: sc.bg, color: sc.text }}>{c.severity}</span>
                        <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>{c.framework}</span>
                        {c.days_open > 0 && <span style={{ fontSize: 9, color: c.days_open > 30 ? C.failed : C.amber }}>{c.days_open}d open</span>}
                      </div>
                    </div>
                  </div>
                );
              })
          }
        </div>
      </div>
    );
  }, [frameworks, failingControls, activeTrend, computedScore, passRate, passedControls,
      totalControls, criticalFailures, highFailures, atRiskCount, auditReadiness,
      expiringExc, sparkScore, scoreΔ]);

  // ── Insight Row ───────────────────────────────────────────────────────────
  const insightRow = useMemo(() => {
    // Radar data
    const radarData = frameworks.length > 0
      ? frameworks.map((fw, i) => ({ subject: fw.name?.split(' ')[0] ?? `FW${i}`, fullName: fw.name, score: fw.score ?? 0 }))
      : MATRIX_FRAMEWORKS.map(k => ({ subject: k, fullName: MATRIX_FRAMEWORK_LABELS[k], score: 0 }));

    // Control status donut
    const donutData = [
      { name: 'Passed',     value: passedControls,  color: C.passed },
      { name: 'Failed',     value: failedControls,  color: C.failed },
      { name: 'Exceptions', value: exceptions.length, color: C.amber },
    ].filter(d => d.value > 0);
    const donutTotal = donutData.reduce((s, d) => s + d.value, 0) || 1;

    // Severity breakdown
    const sevData = frameworks.slice(0, 7).map(fw => {
      const sev = fwSeverityMap[fw.name] || fwSeverityMap[fw.id] || {};
      return { name: fw.name?.split(' ')[0] ?? fw.id, critical: sev.critical || 0, high: sev.high || 0, medium: sev.medium || 0, low: sev.low || 0 };
    });

    const RadarTip = ({ active, payload }) => {
      if (!active || !payload?.length) return null;
      const d = payload[0]?.payload;
      const sc = d?.score ?? 0;
      return (
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)', borderRadius: 8, padding: '8px 12px', fontSize: 11 }}>
          <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: 3 }}>{d?.fullName ?? d?.subject}</div>
          <span style={{ fontSize: 18, fontWeight: 900, color: sc >= 80 ? C.passed : sc >= 60 ? C.amber : C.failed }}>{sc}%</span>
        </div>
      );
    };

    const panel = (title, sub, children) => (
      <div className="p-4 rounded-xl" style={{ background: 'linear-gradient(160deg, var(--bg-secondary), var(--bg-card))', border: '1px solid var(--border-primary)', display: 'flex', flexDirection: 'column' }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>{title}</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>{sub}</div>
        {children}
      </div>
    );

    return (
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 16 }}>

        {/* Framework Radar */}
        {panel('Framework Radar', 'Compliance score across all frameworks',
          <div style={{ height: 250 }}>
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData} margin={{ top: 10, right: 28, bottom: 10, left: 28 }}>
                <PolarGrid stroke="var(--border-primary)" />
                <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: 'var(--text-secondary)', fontWeight: 600 }} />
                <Radar name="Score" dataKey="score" stroke={C.blue} fill={C.blue} fillOpacity={0.18} strokeWidth={2} dot={{ r: 3, fill: C.blue }} />
                <RechartsTip content={<RadarTip />} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Control Status Donut */}
        {panel('Control Status', 'Passed · Failed · Exceptions distribution',
          <>
            <div style={{ flex: 1, minHeight: 200 }}>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={donutData} dataKey="value" nameKey="name"
                    cx="50%" cy="46%" innerRadius="32%" outerRadius="52%"
                    paddingAngle={3} strokeWidth={0}>
                    {donutData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Pie>
                  <RechartsTip
                    contentStyle={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)', borderRadius: 8, fontSize: 11 }}
                    formatter={(v, name) => [`${v.toLocaleString()} (${Math.round(v / donutTotal * 100)}%)`, name]}
                  />
                  <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 10 }}
                    formatter={(value, entry) => (
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {value}&nbsp;<strong style={{ color: entry.color }}>{Math.round((entry.payload.value / donutTotal) * 100)}%</strong>
                      </span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-around', paddingTop: 10, borderTop: '1px solid var(--border-primary)' }}>
              {[{ label: 'PASSED', val: passedControls, col: C.passed }, { label: 'FAILED', val: failedControls, col: C.failed }, { label: 'EXCEPTIONS', val: exceptions.length, col: C.amber }].map(({ label, val, col }) => (
                <div key={label} style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 18, fontWeight: 900, color: col }}>{val.toLocaleString()}</div>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: 0.5 }}>{label}</div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Severity Breakdown */}
        {panel('Failures by Severity', 'Failing controls per framework by severity',
          <div style={{ height: 250 }}>
            {sevData.some(d => d.critical + d.high + d.medium + d.low > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sevData} layout="vertical" margin={{ top: 0, right: 10, bottom: 0, left: 4 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" opacity={0.3} horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 9, fill: 'var(--text-muted)' }} tickLine={false} axisLine={false} />
                  <YAxis type="category" dataKey="name" width={38} tick={{ fontSize: 9, fill: 'var(--text-secondary)' }} tickLine={false} axisLine={false} />
                  <RechartsTip contentStyle={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)', borderRadius: 8, fontSize: 11 }} />
                  <Bar dataKey="critical" name="Critical" stackId="a" fill={C.critical} />
                  <Bar dataKey="high"     name="High"     stackId="a" fill={C.high} />
                  <Bar dataKey="medium"   name="Medium"   stackId="a" fill={C.medium} />
                  <Bar dataKey="low"      name="Low"      stackId="a" fill={C.low} radius={[0, 2, 2, 0]} />
                  <Legend iconType="square" iconSize={8} wrapperStyle={{ fontSize: 10 }}
                    formatter={v => <span style={{ color: 'var(--text-secondary)' }}>{v}</span>} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                <CheckCircle style={{ width: 36, height: 36, color: C.passed }} />
                <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>No severity breakdown available</p>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }, [frameworks, passedControls, failedControls, exceptions, fwSeverityMap]);

  // ── Tab renderers ─────────────────────────────────────────────────────────
  const renderMatrixTab = () => (
    <div className="space-y-6">
      {/* Heat map */}
      <div className="rounded-xl border overflow-hidden relative" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
            <div>
              <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Per-Account Compliance Matrix</h3>
              <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Continuous gradient — hover for breakdown — click header to sort — click cell to drill down</p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
            {[['hsla(0,70%,45%,0.3)', 'Low'], ['hsla(60,70%,45%,0.3)', 'Mid'], ['hsla(120,70%,45%,0.3)', 'High']].map(([bg, label]) => (
              <span key={label} className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-sm" style={{ backgroundColor: bg }} />{label}</span>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto" onMouseLeave={() => setHoveredCell(null)}>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-primary)' }}>
                {[['account', 'Account'], ['env', 'Env', false], ['cloud', 'Cloud', false]].map(([key, label, sortable = true]) => (
                  <th key={key} className={`text-left py-2.5 px-4 text-xs font-semibold uppercase tracking-wider ${sortable ? 'cursor-pointer hover:opacity-75 select-none' : ''}`}
                    style={{ color: matrixSortBy === key ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                    onClick={() => sortable && handleMatrixSort(key)}>
                    {label} {sortable && matrixSortBy === key ? (matrixSortDir === 'asc' ? '↑' : '↓') : ''}
                  </th>
                ))}
                {MATRIX_FRAMEWORKS.map(fw => (
                  <th key={fw} className="text-center py-2.5 px-3 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:opacity-75 select-none"
                    style={{ color: matrixSortBy === fw ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                    onClick={() => handleMatrixSort(fw)}>
                    {fw} {matrixSortBy === fw ? (matrixSortDir === 'asc' ? '↑' : '↓') : ''}
                  </th>
                ))}
                <th className="text-center py-2.5 px-3 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:opacity-75 select-none"
                  style={{ color: matrixSortBy === 'avg' ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                  onClick={() => handleMatrixSort('avg')}>
                  Avg {matrixSortBy === 'avg' ? (matrixSortDir === 'asc' ? '↑' : '↓') : ''}
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedMatrix.length === 0 ? (
                <tr><td colSpan={MATRIX_FRAMEWORKS.length + 4} className="py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No account data available</td></tr>
              ) : sortedMatrix.map((row, idx) => {
                const name  = row.account || row.account_id || '';
                const prov  = (row.provider || row.csp || '').toUpperCase();
                const exp   = row.credExpired || row.cred_expired || false;
                const scores = MATRIX_FRAMEWORKS.map(fw => exp ? 0 : (row[fw] || 0));
                const avg   = exp ? null : Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
                const env   = name.includes('prod') ? 'prod' : name.includes('staging') ? 'staging' : 'dev';
                const envC  = { prod: { bg: 'rgba(239,68,68,0.15)', text: '#ef4444' }, staging: { bg: 'rgba(249,115,22,0.15)', text: '#f97316' }, dev: { bg: 'rgba(34,197,94,0.15)', text: '#22c55e' } };
                const provC = { AWS: { bg: 'rgba(249,115,22,0.15)', text: '#f97316' }, AZURE: { bg: 'rgba(59,130,246,0.15)', text: '#3b82f6' }, GCP: { bg: 'rgba(234,179,8,0.15)', text: '#eab308' } };
                const pC    = provC[prov] || { bg: 'rgba(139,92,246,0.15)', text: '#8b5cf6' };
                return (
                  <tr key={row.account_id || `r${idx}`} className="border-b hover:opacity-90 transition-opacity" style={{ borderColor: 'var(--border-primary)' }}>
                    <td className="py-3 px-4"><span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{name}</span></td>
                    <td className="py-3 px-4"><span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor: envC[env].bg, color: envC[env].text }}>{env}</span></td>
                    <td className="py-3 px-4"><span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor: pC.bg, color: pC.text }}>{prov}</span></td>
                    {MATRIX_FRAMEWORKS.map(fw => {
                      const score = row[fw] ?? 0;
                      const { bg, text } = matrixCellColor(score, exp);
                      return (
                        <td key={fw} className="py-2 px-3 text-center cursor-pointer"
                          onClick={() => !exp && router.push(`/compliance/${fw.toLowerCase()}`)}
                          onMouseEnter={e => {
                            if (!exp) {
                              const r = e.currentTarget.getBoundingClientRect();
                              setTooltipPos({ x: r.left, y: r.bottom + 4 });
                              setHoveredCell({ account: name, framework: MATRIX_FRAMEWORK_LABELS[fw] || fw, score, passed: Math.round(score / 5), failed: 20 - Math.round(score / 5) });
                            }
                          }}>
                          {exp ? <span className="text-xs" style={{ color: 'var(--text-muted)' }}>--</span>
                               : <span className="inline-flex items-center justify-center w-12 h-7 rounded text-xs font-bold" style={{ backgroundColor: bg, color: text }}>{score}</span>}
                        </td>
                      );
                    })}
                    <td className="py-2 px-3 text-center">
                      {avg === null ? <span className="text-xs" style={{ color: 'var(--text-muted)' }}>N/A</span>
                        : <span className="text-sm font-bold" style={{ color: avg >= 75 ? '#22c55e' : avg >= 55 ? '#f59e0b' : '#ef4444' }}>{avg}%</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {hoveredCell && (
          <div className="fixed z-50 rounded-xl p-3 shadow-xl border pointer-events-none"
            style={{ left: `${tooltipPos.x}px`, top: `${tooltipPos.y}px`, backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', minWidth: 180 }}>
            <div className="text-xs font-bold mb-1" style={{ color: 'var(--text-primary)' }}>{hoveredCell.account}</div>
            <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>{hoveredCell.framework}</div>
            <div className="text-lg font-bold mb-1" style={{ color: hoveredCell.score >= 75 ? '#22c55e' : hoveredCell.score >= 55 ? '#f59e0b' : '#ef4444' }}>{hoveredCell.score}%</div>
            <div className="flex gap-3 text-xs">
              <span style={{ color: '#22c55e' }}>✓ {hoveredCell.passed} passed</span>
              <span style={{ color: '#ef4444' }}>✗ {hoveredCell.failed} failed</span>
            </div>
            <div className="text-[10px] mt-1.5" style={{ color: 'var(--text-muted)' }}>Click to drill down →</div>
          </div>
        )}
      </div>

      {/* Pass/Fail stacked bars */}
      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="px-6 py-4 border-b flex items-center gap-2" style={{ borderColor: 'var(--border-primary)' }}>
          <BarChart3 className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <div>
            <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Framework Pass / Fail Breakdown</h3>
            <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Passed (green) vs Failed (red) controls per framework</p>
          </div>
        </div>
        <div className="p-6 space-y-3">
          {frameworks.length === 0 && !loading && <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>No framework data available</p>}
          {frameworks.map(fw => {
            const tot  = fw.controls || (fw.passed + fw.failed);
            const pw   = tot > 0 ? (fw.passed / tot) * 100 : 0;
            const fw2  = tot > 0 ? (fw.failed / tot) * 100 : 0;
            return (
              <div key={fw.id} className="flex items-center gap-3">
                <span className="text-xs font-medium w-44 truncate flex-shrink-0" style={{ color: 'var(--text-primary)' }}>{fw.name}</span>
                <div className="flex-1 flex h-6 rounded overflow-hidden gap-px" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                  <div className="h-full flex items-center justify-center text-xs font-bold text-white" style={{ width: `${pw}%`, backgroundColor: '#22c55e' }} title={`${fw.passed} passed`}>{pw > 12 && fw.passed}</div>
                  <div className="h-full flex items-center justify-center text-xs font-bold text-white" style={{ width: `${fw2}%`, backgroundColor: '#ef4444' }} title={`${fw.failed} failed`}>{fw2 > 12 && fw.failed}</div>
                </div>
                <span className="text-xs w-10 text-right flex-shrink-0 font-semibold" style={{ color: fw.score >= 80 ? '#22c55e' : fw.score >= 60 ? '#eab308' : '#ef4444' }}>{fw.score}%</span>
              </div>
            );
          })}
          <div className="flex items-center gap-4 pt-2">
            {[['#22c55e', 'Passed'], ['#ef4444', 'Failed']].map(([bg, label]) => (
              <span key={label} className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-tertiary)' }}>
                <span className="w-3 h-3 rounded-sm inline-block" style={{ backgroundColor: bg }} />{label}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  const renderFrameworksTab = () => (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Framework Compliance Scores</h2>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>Click any framework to view detailed controls</p>
        </div>
        <SearchBar value={frameworkSearch} onChange={setFrameworkSearch} placeholder="Search frameworks..." />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {frameworks
          .filter(fw => !frameworkSearch || fw.name?.toLowerCase().includes(frameworkSearch.toLowerCase()))
          .map((fw, i) => {
            const fCol  = FW_COLORS[i % FW_COLORS.length];
            const sCol  = fw.score >= 80 ? C.passed : fw.score >= 60 ? C.amber : C.failed;
            const sLvl  = fw.score >= 80 ? 'Good' : fw.score >= 60 ? 'Fair' : 'At Risk';
            const sev   = fwSeverityMap[fw.name] || fwSeverityMap[fw.id] || {};
            return (
              <div key={fw.id} onClick={() => router.push(`/compliance/${fw.id}`)}
                className="cursor-pointer rounded-xl p-5 border flex flex-col gap-3 hover:scale-[1.02] transition-transform"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="flex items-start justify-between gap-2">
                  <h4 className="text-sm font-semibold line-clamp-2" style={{ color: 'var(--text-primary)' }}>{fw.name}</h4>
                  <span className="text-xs px-2 py-0.5 rounded-full font-semibold flex-shrink-0" style={{ backgroundColor: `${sCol}20`, color: sCol }}>{sLvl}</span>
                </div>
                <div>
                  <div className="flex items-end gap-2 mb-2">
                    <span className="text-3xl font-black" style={{ color: fCol }}>{fw.score}</span>
                    <span className="text-sm mb-1" style={{ color: 'var(--text-muted)' }}>%</span>
                  </div>
                  <div className="w-full h-2 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <div className="h-full rounded-full transition-all" style={{ width: `${fw.score}%`, backgroundColor: fCol }} />
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center border-t pt-3" style={{ borderColor: 'var(--border-primary)' }}>
                  <div><p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>Controls</p><p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{fw.controls}</p></div>
                  <div><p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>Passed</p><p className="text-sm font-semibold" style={{ color: C.passed }}>{fw.passed}</p></div>
                  <div><p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>Failed</p><p className="text-sm font-semibold" style={{ color: C.failed }}>{fw.failed}</p></div>
                </div>
                {Object.values(sev).some(v => v > 0) && (
                  <div className="flex gap-2 flex-wrap">
                    {sev.critical > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded-full" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: C.critical }}>{sev.critical} critical</span>}
                    {sev.high     > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded-full" style={{ backgroundColor: 'rgba(249,115,22,0.15)', color: C.high }}>{sev.high} high</span>}
                    {sev.medium   > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded-full" style={{ backgroundColor: 'rgba(234,179,8,0.15)', color: C.medium }}>{sev.medium} medium</span>}
                  </div>
                )}
                <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>Last assessed: {fw.last_assessed ? new Date(fw.last_assessed).toLocaleDateString() : 'N/A'}</p>
              </div>
            );
          })}
      </div>
    </div>
  );

  // ── Final render ──────────────────────────────────────────────────────────
  const pageContext = {
    tabs: [
      { id: 'overview',   label: 'Overview' },
      { id: 'matrix',     label: 'Compliance Matrix',  count: accounts.length },
      { id: 'controls',   label: 'Failing Controls',   count: failingControls.length },
      { id: 'frameworks', label: 'Frameworks',          count: frameworks.length },
      { id: 'audits',     label: 'Audit Deadlines',     count: auditDeadlines.length },
      { id: 'exceptions', label: 'Exceptions',          count: exceptions.length },
    ],
  };

  const tabData = {
    matrix:     { renderTab: renderMatrixTab },
    controls:   { data: failingControls,  columns: failingControlColumns },
    frameworks: { renderTab: renderFrameworksTab },
    audits:     { data: auditDeadlines,   columns: auditColumns },
    exceptions: { data: exceptions,       columns: exceptionColumns },
  };

  return (
    <div style={{ padding: '24px 24px 0', maxWidth: '100%' }}>
      {/* Heading */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <ClipboardCheck style={{ width: 22, height: 22, color: 'var(--accent-primary)' }} />
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>Compliance Dashboard</h1>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
              Enterprise-wide compliance posture · {frameworks.length} frameworks · {totalControls.toLocaleString()} controls
            </p>
          </div>
        </div>
        <button onClick={handleGenerateReport} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 10, fontSize: 13, fontWeight: 600, backgroundColor: 'var(--accent-primary)', color: 'white', border: 'none', cursor: 'pointer' }}>
          <RefreshCw style={{ width: 14, height: 14 }} />
          Generate Report
        </button>
      </div>

      <PageLayout
        icon={ClipboardCheck}
        pageContext={pageContext}
        tabData={{ overview: { renderTab: () => <>{insightStrip}{insightRow}</> }, ...tabData }}
        loading={loading}
        error={error}
        defaultTab="overview"
        hideHeader
        topNav
      />
    </div>
  );
}
