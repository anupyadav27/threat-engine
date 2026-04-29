'use client';

import { useEffect, useState, useMemo } from 'react';
import {
  Bug, Shield, AlertTriangle, Activity, Package, Search,
  Server, RefreshCw, ExternalLink, ChevronUp, ChevronDown,
  Clock, CheckCircle, XCircle, Zap, FileText, Globe, Code2,
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  XAxis, YAxis, CartesianGrid, Tooltip as RechartsTip,
  ResponsiveContainer, Legend,
} from 'recharts';
import { TENANT_ID } from '@/lib/constants';
import { useToast } from '@/lib/toast-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import SearchBar from '@/components/shared/SearchBar';

// ── Colour palette ────────────────────────────────────────────────────────────
const C = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6',
  passed:   '#22c55e', blue: '#3b82f6', purple: '#8b5cf6',
  teal:     '#14b8a6', amber: '#f59e0b', pink: '#ec4899',
};
const SEV_CFG = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)',    text: '#ef4444' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)',   text: '#f97316' },
  MEDIUM:   { bg: 'rgba(234,179,8,0.15)',    text: '#eab308' },
  LOW:      { bg: 'rgba(59,130,246,0.15)',   text: '#3b82f6' },
};
const PLATFORM_ICON = { linux:'🐧', windows:'🪟', macos:'🍎' };
const ECOSYSTEM_COLOR = {
  system:'#64748b', pypi:'#3b82f6', npm:'#f59e0b',
  maven:'#ef4444', golang:'#14b8a6', cargo:'#f97316', gem:'#ec4899',
};
const ATTACK_COLORS = {
  'SQL Injection':'#ef4444','Reflected XSS':'#f97316','Stored XSS':'#f59e0b',
  'SSRF':'#8b5cf6','XXE':'#14b8a6','SSTI':'#ec4899','Command Injection':'#ef4444',
  'Path Traversal':'#f97316','Broken Object Auth':'#eab308',
  'Broken Access Control':'#ef4444','Insecure Deserialization':'#f97316',
  'Broken Auth':'#eab308','Info Disclosure':'#3b82f6','NoSQL Injection':'#8b5cf6',
};

async function fetchVulnData(params = {}) {
  const qs = new URLSearchParams();
  if (TENANT_ID) qs.set('tenant_id', TENANT_ID);
  if (params.provider) qs.set('provider', params.provider);
  if (params.account)  qs.set('account',  params.account);
  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  try {
    const res = await fetch(`${origin}/api/bff/vulnerabilities?${qs}`);
    if (!res.ok) return { error: `BFF ${res.status}` };
    return res.json();
  } catch (e) { return { error: e.message }; }
}

// ── Mini KPI Card ─────────────────────────────────────────────────────────────
function KpiCard({ label, value, sub, color, icon: Icon, delta }) {
  const dir = delta > 0 ? 'up' : delta < 0 ? 'down' : null;
  const deltaColor = dir === 'down' ? C.passed : dir === 'up' ? C.critical : 'var(--text-muted)';
  return (
    <div style={{
      background:'var(--bg-card)', border:`1px solid ${color}28`,
      borderRadius:10, padding:'12px 14px',
      boxShadow:`0 4px 18px ${color}10`,
      display:'flex', flexDirection:'column', gap:4,
    }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <span style={{ fontSize:11, fontWeight:700, color:'var(--text-secondary)', letterSpacing:'0.02em' }}>{label}</span>
        {Icon && <Icon size={13} color={color} opacity={0.7} />}
      </div>
      <div style={{ display:'flex', alignItems:'baseline', gap:6 }}>
        <span style={{ fontSize:26, fontWeight:900, color, lineHeight:1, fontVariantNumeric:'tabular-nums' }}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>
        {delta !== undefined && delta !== null && (
          <span style={{ fontSize:10, fontWeight:700, padding:'1px 5px', borderRadius:4,
            background:`${deltaColor}1a`, color:deltaColor }}>
            {dir === 'up' ? '▲' : '▼'} {Math.abs(delta)}
          </span>
        )}
      </div>
      {sub && <div style={{ fontSize:10, color:'var(--text-tertiary)' }}>{sub}</div>}
    </div>
  );
}

// ── Severity pill ─────────────────────────────────────────────────────────────
function SevPill({ sev }) {
  const c = SEV_CFG[sev] || SEV_CFG.LOW;
  return (
    <span style={{ fontSize:10, fontWeight:700, padding:'2px 7px', borderRadius:20,
      background:c.bg, color:c.text, textTransform:'uppercase', letterSpacing:'0.05em' }}>
      {sev}
    </span>
  );
}

// ── CVSS badge ────────────────────────────────────────────────────────────────
function CvssBadge({ score }) {
  const color = score >= 9 ? C.critical : score >= 7 ? C.high : score >= 4 ? C.medium : C.low;
  return (
    <span style={{ fontSize:11, fontWeight:800, color, minWidth:30, display:'inline-block' }}>
      {score?.toFixed(1)}
    </span>
  );
}

// ── Risk gauge (half-arc) ─────────────────────────────────────────────────────
function RiskGauge({ score = 0, size = 130 }) {
  const r   = size * 0.38;
  const cx  = size / 2, cy = size * 0.56;
  const pct = Math.min(Math.max(score, 0), 100) / 100;
  const toXY = a => [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  const [tx1, ty1] = toXY(Math.PI);
  const [tx2, ty2] = toXY(0);
  const needleAngle = Math.PI - pct * Math.PI;
  const [sx2, sy2] = toXY(needleAngle);
  const [nx, ny]   = [cx + (r-10)*Math.cos(needleAngle), cy + (r-10)*Math.sin(needleAngle)];
  const largeArc   = pct > 0.5 ? 1 : 0;
  const col = score >= 80 ? C.critical : score >= 60 ? C.high : score >= 40 ? C.medium : C.passed;
  const lvl = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
  return (
    <div style={{ textAlign:'center' }}>
      <svg width={size} height={size*0.62} viewBox={`0 0 ${size} ${size*0.62}`}>
        <path d={`M ${tx1} ${ty1} A ${r} ${r} 0 0 1 ${tx2} ${ty2}`}
          fill="none" stroke="var(--bg-tertiary)" strokeWidth={size*0.06} strokeLinecap="round" />
        {pct > 0 && <path d={`M ${tx1} ${ty1} A ${r} ${r} 0 ${largeArc} 1 ${sx2} ${sy2}`}
          fill="none" stroke={col} strokeWidth={size*0.06} strokeLinecap="round" />}
        <line x1={cx} y1={cy} x2={nx} y2={ny} stroke={col} strokeWidth={2} strokeLinecap="round" opacity={0.9}/>
        <circle cx={cx} cy={cy} r={3.5} fill={col}/>
        <text x={cx} y={cy - r*0.14} textAnchor="middle" fontSize={size*0.18} fontWeight={900} fill={col}>{score}</text>
        <text x={cx} y={cy + r*0.12} textAnchor="middle" fontSize={size*0.09} fill="var(--text-muted)">RISK SCORE</text>
      </svg>
      <div style={{ fontSize:11, fontWeight:700, color:col, marginTop:-4 }}>{lvl} EXPOSURE</div>
    </div>
  );
}

// ── Custom Tooltip ────────────────────────────────────────────────────────────
function ChartTip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)',
      borderRadius:8, padding:'8px 12px', boxShadow:'0 4px 20px rgba(0,0,0,.3)', fontSize:12 }}>
      <div style={{ fontWeight:700, color:'var(--text-primary)', marginBottom:4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || p.fill, fontVariantNumeric:'tabular-nums' }}>
          {p.name}: <strong>{p.value?.toLocaleString()}</strong>
        </div>
      ))}
    </div>
  );
}

// ── Sortable table header ─────────────────────────────────────────────────────
function SortTh({ col, label, sortBy, sortDir, onSort, style={} }) {
  const active = sortBy === col;
  return (
    <th onClick={() => onSort(col)} style={{
      padding:'8px 10px', fontSize:11, fontWeight:700, textAlign:'left',
      color: active ? C.blue : 'var(--text-secondary)', cursor:'pointer',
      userSelect:'none', whiteSpace:'nowrap',
      borderBottom:'1px solid var(--border-primary)', ...style,
    }}>
      {label}{active && (sortDir === 'asc' ? ' ↑' : ' ↓')}
    </th>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function VulnerabilitiesPage() {
  const toast = useToast();
  const { provider, account } = useGlobalFilter();

  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [data,     setData]     = useState(null);
  const [activeTab, setTab]     = useState('overview');
  const [search,   setSearch]   = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [sortBy,   setSortBy]   = useState('cvss');
  const [sortDir,  setSortDir]  = useState('desc');
  const [selectedCve, setSelectedCve] = useState(null);

  useEffect(() => {
    (async () => {
      setLoading(true); setError(null);
      const d = await fetchVulnData({ provider, account });
      if (d.error) { setError(d.error); setLoading(false); return; }
      setData(d);
      setLoading(false);
    })();
  }, [provider, account]);

  const handleSort = col => {
    if (sortBy === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortBy(col); setSortDir('desc'); }
  };

  // ── Derived data ────────────────────────────────────────────────────────────
  const s   = data?.summary || {};
  const vulns = useMemo(() => data?.vulnerabilities || [], [data]);
  const assets = useMemo(() => data?.assets || [], [data]);
  const sbom   = useMemo(() => data?.sbom || [], [data]);
  const dast   = useMemo(() => data?.dast || [], [data]);
  const queue  = useMemo(() => data?.remediation_queue || [], [data]);

  // Risk score (composite)
  const riskScore = useMemo(() => {
    if (!s.total_vulnerabilities) return 0;
    return Math.min(100, Math.round(
      (s.critical_count * 10 + s.high_count * 4 + (s.medium_count||0) * 1.5) /
      Math.max(s.total_vulnerabilities, 1) * 10
    ));
  }, [s]);

  // CVSS distribution for bar chart
  const cvssDistChart = useMemo(() => {
    const b = data?.cvss_distribution || {};
    return [
      { label:'9–10 (Critical)', count: b['9-10']||0, fill: C.critical },
      { label:'7–9 (High)',      count: b['7-9'] ||0, fill: C.high },
      { label:'4–7 (Medium)',    count: b['4-7'] ||0, fill: C.medium },
      { label:'0–4 (Low)',       count: b['0-4'] ||0, fill: C.low },
    ];
  }, [data]);

  // Age distribution
  const ageDistChart = useMemo(() => {
    const b = data?.age_distribution || {};
    return [
      { label:'< 7 days',   count: b['<7d']   ||0, fill: C.high },
      { label:'7–30 days',  count: b['7-30d'] ||0, fill: C.medium },
      { label:'30–90 days', count: b['30-90d']||0, fill: C.amber },
      { label:'> 90 days',  count: b['>90d']  ||0, fill: C.critical },
    ];
  }, [data]);

  // Severity donut
  const sevDonut = useMemo(() => {
    const b = data?.severity_breakdown || {};
    return [
      { name:'Critical', value: b.CRITICAL||0, fill: C.critical },
      { name:'High',     value: b.HIGH||0,     fill: C.high },
      { name:'Medium',   value: b.MEDIUM||0,   fill: C.medium },
      { name:'Low',      value: b.LOW||0,       fill: C.low },
    ].filter(x => x.value > 0);
  }, [data]);

  // DAST by attack type
  const dastByAttack = useMemo(() => {
    const m = {};
    dast.forEach(d => { m[d.attack] = (m[d.attack]||0) + 1; });
    return Object.entries(m)
      .sort((a,b) => b[1]-a[1])
      .slice(0, 8)
      .map(([name, count]) => ({ name, count, fill: ATTACK_COLORS[name] || C.purple }));
  }, [dast]);

  // Filtered + sorted findings
  const filteredVulns = useMemo(() => {
    let list = [...vulns];
    if (sevFilter !== 'ALL') list = list.filter(v => v.sev === sevFilter);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(v =>
        v.cve_id?.toLowerCase().includes(q) ||
        v.pkg?.toLowerCase().includes(q) ||
        v.desc?.toLowerCase().includes(q)
      );
    }
    return list.sort((a, b) => {
      let va = a[sortBy] ?? 0, vb = b[sortBy] ?? 0;
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }, [vulns, sevFilter, search, sortBy, sortDir]);

  // Remediation actions — group CVEs by package into one actionable row
  const remediationActions = useMemo(() => {
    const byPkg = {};
    vulns.forEach(v => {
      if (!byPkg[v.pkg]) {
        byPkg[v.pkg] = {
          pkg: v.pkg, cves: [], cve_ids: [],
          max_sev: 'LOW', max_cvss: 0,
          any_exploit: false, any_patch: false, any_sla: false,
          assets: new Set(),
        };
      }
      const g = byPkg[v.pkg];
      g.cves.push(v);
      g.cve_ids.push(v.cve_id);
      (v.affected_agents || v.agents || []).forEach(a => g.assets.add(a));
      if (v.exploit) g.any_exploit = true;
      if (v.patch)   g.any_patch   = true;
      if (v.sla_breached)      g.any_sla     = true;
      const rank = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 };
      if ((rank[v.sev]||0) > (rank[g.max_sev]||0)) { g.max_sev = v.sev; g.max_cvss = v.cvss; }
      else if (v.cvss > g.max_cvss) g.max_cvss = v.cvss;
    });
    return Object.values(byPkg).map(g => ({
      pkg:        g.pkg,
      cve_count:  g.cves.length,
      cve_ids:    g.cve_ids.slice(0, 3),  // show first 3 CVE IDs
      action:     g.any_patch
                    ? (g.fixed_version ? `Upgrade to ${g.fixed_version}` : 'Apply available patch')
                    : 'Investigate & mitigate',
      severity:   g.max_sev,
      cvss:       g.max_cvss,
      assets:     g.assets.size,
      exploit:    g.any_exploit,
      patch:      g.any_patch,
      sla:        g.any_sla,
      effort:     g.cves.length >= 5 || g.any_exploit ? 'High'
                : g.cves.length >= 2 || !g.any_patch   ? 'Medium' : 'Low',
      status:     g.any_sla ? 'Overdue' : g.any_exploit ? 'Urgent' : 'Open',
    })).sort((a, b) => {
      const rank = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 };
      return (rank[b.severity]||0) - (rank[a.severity]||0) || b.cvss - a.cvss;
    });
  }, [vulns]);

  if (loading) return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:400, gap:12, color:'var(--text-muted)' }}>
      <RefreshCw size={18} className="animate-spin" /><span>Loading vulnerability data…</span>
    </div>
  );

  if (error) return (
    <div style={{ padding:24, color:C.critical }}>{error}</div>
  );

  const tabs = [
    { id:'overview',    label:'Overview',    count:null,                        icon:<Activity size={13}/> },
    { id:'findings',    label:'Findings',    count:s.total_vulnerabilities,     icon:<Bug size={13}/> },
    { id:'assets',      label:'Assets',      count:s.total_agents,              icon:<Server size={13}/> },
    { id:'remediation', label:'Remediation', count:remediationActions.length,   icon:<CheckCircle size={13}/> },
  ];

  return (
    <div className="space-y-5">
      {/* ── Page Header ─────────────────────────────────────────────────────── */}
      <div>
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:4 }}>
          <div style={{ display:'flex', alignItems:'center', gap:10 }}>
            <Bug size={20} color={C.critical} />
            <h1 style={{ fontSize:20, fontWeight:700, color:'var(--text-primary)', margin:0 }}>Vulnerability Management</h1>
          </div>
          <button onClick={() => toast.info('Scan triggered')} style={{
            display:'flex', alignItems:'center', gap:6, padding:'7px 14px',
            background:C.critical, color:'#fff', border:'none', borderRadius:8,
            fontSize:12, fontWeight:700, cursor:'pointer',
          }}>
            <RefreshCw size={13}/> Trigger Scan
          </button>
        </div>
        <p style={{ fontSize:13, color:'var(--text-secondary)', margin:0 }}>
          {`${s.total_vulnerabilities || 0} vulnerabilities · ${s.critical_count || 0} critical · ${s.affected_assets || 0} affected assets`}
        </p>
      </div>

      {/* ── Tab Bar ─────────────────────────────────────────────────────────── */}
      <div style={{ display:'flex', gap:4, borderBottom:'1px solid var(--border-primary)' }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            display:'flex', alignItems:'center', gap:5,
            padding:'8px 14px', border:'none', background:'transparent', cursor:'pointer',
            fontSize:12, fontWeight:600,
            color: activeTab === t.id ? C.blue : 'var(--text-secondary)',
            borderBottom: activeTab === t.id ? `2px solid ${C.blue}` : '2px solid transparent',
            marginBottom:-1, whiteSpace:'nowrap',
          }}>
            {t.icon}{t.label}
            {t.count != null && (
              <span style={{ fontSize:10, padding:'1px 5px', borderRadius:10,
                background: activeTab === t.id ? `${C.blue}22` : 'var(--bg-tertiary)',
                color: activeTab === t.id ? C.blue : 'var(--text-muted)' }}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Tab: Overview ───────────────────────────────────────────────────── */}
      {activeTab === 'overview' && (
        <div style={{ paddingTop:10, display:'flex', flexDirection:'column', gap:18 }}>

          {/* ── Vulnerability Summary ──────────────────────────────────────── */}
          <div>
            <div style={{ fontSize:11, fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10, paddingBottom:6, borderBottom:'1px solid var(--border-primary)' }}>Vulnerability Summary</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(6,1fr)', gap:8 }}>
              <KpiCard label="Total Vulns"     value={s.total_vulnerabilities||0} color={C.critical} icon={Bug}          delta={12}  sub={`${s.exploitable_count||0} exploitable`}/>
              <KpiCard label="Critical"        value={s.critical_count||0}        color={C.critical} icon={AlertTriangle} delta={3}   sub="Needs immediate action"/>
              <KpiCard label="High"            value={s.high_count||0}            color={C.high}     icon={Shield}        delta={-2}  sub="Within 14-day SLA"/>
              <KpiCard label="Affected Assets" value={s.affected_assets||0}       color={C.purple}   icon={Server}        delta={1}   sub={`${s.total_agents||0} total agents`}/>
              <KpiCard label="SLA Breached"    value={s.sla_breached||0}          color={C.amber}    icon={Clock}         delta={5}   sub="Past remediation deadline"/>
              <KpiCard label="Patch Coverage"  value={`${s.patch_coverage_pct||0}%`} color={C.passed} icon={CheckCircle}  delta={-2}  sub={`MTTR ${s.mean_time_to_remediate||0}d avg`}/>
            </div>
          </div>

          {/* ── Trends & Distribution ──────────────────────────────────────── */}
          <div>
            <div style={{ fontSize:11, fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10, paddingBottom:6, borderBottom:'1px solid var(--border-primary)' }}>Trends & Distribution</div>
            <div style={{ display:'grid', gridTemplateColumns:'200px 1fr 1fr 1fr', gap:10 }}>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:'14px 10px', display:'flex', flexDirection:'column', alignItems:'center', gap:8 }}>
                <RiskGauge score={riskScore} size={130} />
                <div style={{ width:'100%' }}>
                  {sevDonut.map((d, i) => (
                    <div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:3 }}>
                      <div style={{ display:'flex', alignItems:'center', gap:5 }}>
                        <div style={{ width:8, height:8, borderRadius:2, background:d.fill }}/>
                        <span style={{ fontSize:10, color:'var(--text-secondary)' }}>{d.name}</span>
                      </div>
                      <span style={{ fontSize:10, fontWeight:700, color:d.fill }}>{d.value}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:'14px 12px' }}>
                <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:2 }}>30-Day Vulnerability Trend</div>
                <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:8 }}>New vs. Resolved per day</div>
                <ResponsiveContainer width="100%" height={130}>
                  <AreaChart data={data?.trend_30d || []} margin={{ top:0, right:0, left:-30, bottom:0 }}>
                    <defs>
                      <linearGradient id="gnew" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={C.critical} stopOpacity={0.3}/>
                        <stop offset="95%" stopColor={C.critical} stopOpacity={0.03}/>
                      </linearGradient>
                      <linearGradient id="gres" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={C.passed}   stopOpacity={0.3}/>
                        <stop offset="95%" stopColor={C.passed}   stopOpacity={0.03}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" opacity={0.4}/>
                    <XAxis dataKey="date" tick={{ fontSize:8, fill:'var(--text-muted)' }} tickFormatter={v => v.slice(5)} interval={6}/>
                    <YAxis tick={{ fontSize:8, fill:'var(--text-muted)' }}/>
                    <RechartsTip content={<ChartTip/>}/>
                    <Area type="monotone" dataKey="new_vulns"      name="New"      stroke={C.critical} fill="url(#gnew)" strokeWidth={1.5}/>
                    <Area type="monotone" dataKey="resolved_vulns" name="Resolved" stroke={C.passed}   fill="url(#gres)" strokeWidth={1.5}/>
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:'14px 12px' }}>
                <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:2 }}>CVSS Score Distribution</div>
                <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:8 }}>Vulnerabilities by score band</div>
                <ResponsiveContainer width="100%" height={130}>
                  <BarChart data={cvssDistChart} margin={{ top:0, right:0, left:-30, bottom:0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" opacity={0.4}/>
                    <XAxis dataKey="label" tick={{ fontSize:8, fill:'var(--text-muted)' }} tickFormatter={v => v.split(' ')[0]}/>
                    <YAxis tick={{ fontSize:8, fill:'var(--text-muted)' }}/>
                    <RechartsTip content={<ChartTip/>}/>
                    <Bar dataKey="count" name="Count" radius={[3,3,0,0]}>
                      {cvssDistChart.map((e, i) => <Cell key={i} fill={e.fill}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:'14px 12px' }}>
                <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:2 }}>Vulnerability Age</div>
                <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:8 }}>Time-in-environment distribution</div>
                <ResponsiveContainer width="100%" height={130}>
                  <BarChart data={ageDistChart} margin={{ top:0, right:0, left:-30, bottom:0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" opacity={0.4}/>
                    <XAxis dataKey="label" tick={{ fontSize:8, fill:'var(--text-muted)' }} tickFormatter={v => v.split(' ')[0]}/>
                    <YAxis tick={{ fontSize:8, fill:'var(--text-muted)' }}/>
                    <RechartsTip content={<ChartTip/>}/>
                    <Bar dataKey="count" name="Count" radius={[3,3,0,0]}>
                      {ageDistChart.map((e, i) => <Cell key={i} fill={e.fill}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* ── Exposure by Asset ──────────────────────────────────────────── */}
          <div>
            <div style={{ fontSize:11, fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10, paddingBottom:6, borderBottom:'1px solid var(--border-primary)' }}>Exposure by Asset</div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:14 }}>
                <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:8 }}>Vulnerabilities per Asset</div>
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={assets.slice().sort((a,b)=>b.vuln_total-a.vuln_total)} margin={{ top:0, right:0, left:-20, bottom:20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" opacity={0.4}/>
                    <XAxis dataKey="hostname" tick={{ fontSize:8, fill:'var(--text-muted)' }} angle={-30} textAnchor="end" interval={0}/>
                    <YAxis tick={{ fontSize:8, fill:'var(--text-muted)' }}/>
                    <RechartsTip content={<ChartTip/>}/>
                    <Bar dataKey="vuln_critical" name="Critical" stackId="a" fill={C.critical}/>
                    <Bar dataKey="vuln_high"     name="High"     stackId="a" fill={C.high}/>
                    <Bar dataKey="vuln_medium"   name="Medium"   stackId="a" fill={C.medium}/>
                    <Bar dataKey="vuln_low"      name="Low"      stackId="a" fill={C.low} radius={[2,2,0,0]}/>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:14 }}>
                <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:8 }}>Asset Coverage</div>
                <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginBottom:8 }}>
                  {['active','inactive'].map(st => (
                    <div key={st} style={{ flex:1, padding:'10px 12px', borderRadius:8, background:'var(--bg-secondary)', border:'1px solid var(--border-primary)', textAlign:'center' }}>
                      <div style={{ fontSize:20, fontWeight:900, color: st === 'active' ? C.passed : C.critical }}>{assets.filter(a => a.status === st).length}</div>
                      <div style={{ fontSize:10, color:'var(--text-muted)', textTransform:'capitalize' }}>{st}</div>
                    </div>
                  ))}
                  {['linux','windows','macos'].map(pl => (
                    <div key={pl} style={{ flex:1, padding:'10px 12px', borderRadius:8, background:'var(--bg-secondary)', border:'1px solid var(--border-primary)', textAlign:'center' }}>
                      <div style={{ fontSize:20 }}>{PLATFORM_ICON[pl]}</div>
                      <div style={{ fontSize:11, fontWeight:700, color:'var(--text-primary)' }}>{assets.filter(a => a.platform === pl).length}</div>
                      <div style={{ fontSize:9, color:'var(--text-muted)', textTransform:'capitalize' }}>{pl}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* ── Remediation Readiness ──────────────────────────────────────── */}
          <div>
            <div style={{ fontSize:11, fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10, paddingBottom:6, borderBottom:'1px solid var(--border-primary)' }}>Remediation Readiness</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8, marginBottom:10 }}>
              <KpiCard label="Actions Required" value={remediationActions.length}                               color={C.critical} icon={Bug}/>
              <KpiCard label="SLA Overdue"       value={remediationActions.filter(r=>r.sla).length}             color={C.amber}    icon={Clock}/>
              <KpiCard label="Exploit Risk"      value={remediationActions.filter(r=>r.exploit).length}         color={C.high}     icon={Zap}/>
              <KpiCard label="Patch Available"   value={remediationActions.filter(r=>r.patch).length}           color={C.passed}   icon={CheckCircle}/>
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:10 }}>
              {/* By Effort */}
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:14 }}>
                <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:10 }}>By Effort</div>
                {[
                  { label:'High',   color:C.critical, count: remediationActions.filter(r=>r.effort==='High').length },
                  { label:'Medium', color:C.amber,    count: remediationActions.filter(r=>r.effort==='Medium').length },
                  { label:'Low',    color:C.passed,   count: remediationActions.filter(r=>r.effort==='Low').length },
                ].map(({ label, color, count }) => (
                  <div key={label} style={{ marginBottom:8 }}>
                    <div style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}>
                      <span style={{ fontSize:11, color:'var(--text-secondary)' }}>{label}</span>
                      <span style={{ fontSize:11, fontWeight:700, color }}>{count}</span>
                    </div>
                    <div style={{ height:5, borderRadius:3, background:'var(--bg-tertiary)' }}>
                      <div style={{ width:`${remediationActions.length ? count/remediationActions.length*100 : 0}%`, height:'100%', borderRadius:3, background:color }}/>
                    </div>
                  </div>
                ))}
              </div>
              {/* By Status */}
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:14 }}>
                <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)', marginBottom:10 }}>By Status</div>
                {[
                  { label:'Overdue', color:C.critical, count: remediationActions.filter(r=>r.status==='Overdue').length },
                  { label:'Urgent',  color:C.high,     count: remediationActions.filter(r=>r.status==='Urgent').length },
                  { label:'Open',    color:C.blue,     count: remediationActions.filter(r=>r.status==='Open').length },
                ].map(({ label, color, count }) => (
                  <div key={label} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:10 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <div style={{ width:8, height:8, borderRadius:2, background:color }}/>
                      <span style={{ fontSize:11, color:'var(--text-secondary)' }}>{label}</span>
                    </div>
                    <span style={{ fontSize:18, fontWeight:900, color }}>{count}</span>
                  </div>
                ))}
              </div>
              {/* Patchable */}
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:14, display:'flex', flexDirection:'column', justifyContent:'center', alignItems:'center', gap:4 }}>
                <div style={{ fontSize:12, fontWeight:700, color:'var(--text-primary)' }}>Patchable Actions</div>
                <div style={{ fontSize:40, fontWeight:900, color:C.passed, lineHeight:1 }}>
                  {remediationActions.length ? Math.round(remediationActions.filter(r=>r.patch).length / remediationActions.length * 100) : 0}%
                </div>
                <div style={{ fontSize:10, color:'var(--text-muted)' }}>{remediationActions.filter(r=>r.patch).length} of {remediationActions.length} have a patch</div>
              </div>
            </div>
          </div>

          {/* ── Package & Agent Intelligence ───────────────────────────────── */}
          <div>
            <div style={{ fontSize:11, fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10, paddingBottom:6, borderBottom:'1px solid var(--border-primary)' }}>Package & Agent Intelligence</div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:14 }}>
                <div style={{ fontSize:13, fontWeight:700, color:'var(--text-primary)', marginBottom:10 }}>Top Vulnerable Packages</div>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={data?.top_packages || []} layout="vertical" margin={{ top:0, right:30, left:0, bottom:0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" opacity={0.4} horizontal={false}/>
                    <XAxis type="number" tick={{ fontSize:9, fill:'var(--text-muted)' }}/>
                    <YAxis type="category" dataKey="name" tick={{ fontSize:10, fill:'var(--text-secondary)' }} width={90}/>
                    <RechartsTip content={<ChartTip/>}/>
                    <Bar dataKey="count" name="CVEs" fill={C.critical} radius={[0,3,3,0]}>
                      {(data?.top_packages||[]).map((_, i) => (
                        <Cell key={i} fill={i < 3 ? C.critical : i < 6 ? C.high : C.medium}/>
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, padding:14 }}>
                <div style={{ fontSize:13, fontWeight:700, color:'var(--text-primary)', marginBottom:10 }}>Agent Health</div>
                <div style={{ display:'flex', flexDirection:'column', gap:6, maxHeight:220, overflowY:'auto' }}>
                  {assets.map((a, i) => (
                    <div key={i} style={{
                      display:'flex', alignItems:'center', justifyContent:'space-between',
                      padding:'7px 10px', borderRadius:8,
                      background: a.status === 'active' ? 'var(--bg-secondary)' : 'rgba(239,68,68,0.05)',
                      border:'1px solid var(--border-primary)',
                    }}>
                      <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                        <span style={{ fontSize:14 }}>{PLATFORM_ICON[a.platform]||'💻'}</span>
                        <div>
                          <div style={{ fontSize:11, fontWeight:600, color:'var(--text-primary)' }}>{a.hostname}</div>
                          <div style={{ fontSize:9, color:'var(--text-muted)' }}>{a.platform} · {a.architecture}</div>
                        </div>
                      </div>
                      <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                        {a.vuln_critical > 0 && <span style={{ fontSize:10, fontWeight:700, color:C.critical }}>C:{a.vuln_critical}</span>}
                        {a.vuln_high     > 0 && <span style={{ fontSize:10, fontWeight:700, color:C.high     }}>H:{a.vuln_high}</span>}
                        <span style={{ width:6, height:6, borderRadius:'50%', background: a.status === 'active' ? C.passed : C.critical }}/>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

        </div>
      )}

      {/* ── Tab: Findings ───────────────────────────────────────────────────── */}
      {activeTab === 'findings' && (
        <div style={{ paddingTop:10 }}>
          {/* Filter bar */}
          <div style={{ display:'flex', gap:8, marginBottom:10, flexWrap:'wrap' }}>
            <SearchBar value={search} onChange={setSearch} placeholder="Search CVE, package, description…" style={{ flex:1, minWidth:240 }}/>
            {['ALL','CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
              <button key={s} onClick={() => setSevFilter(s)} style={{
                padding:'5px 12px', fontSize:11, fontWeight:700, borderRadius:6, cursor:'pointer',
                border:`1px solid ${sevFilter===s ? (SEV_CFG[s]?.text||C.blue) : 'var(--border-primary)'}`,
                background: sevFilter===s ? `${SEV_CFG[s]?.bg||C.blue+'22'}` : 'var(--bg-secondary)',
                color: sevFilter===s ? (SEV_CFG[s]?.text||C.blue) : 'var(--text-secondary)',
              }}>{s}</button>
            ))}
            <span style={{ fontSize:11, color:'var(--text-muted)', padding:'5px 0', alignSelf:'center' }}>
              {filteredVulns.length} results
            </span>
          </div>
          {/* CVE Table */}
          <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, overflow:'hidden' }}>
            <table style={{ width:'100%', borderCollapse:'collapse' }}>
              <thead>
                <tr style={{ background:'var(--bg-secondary)' }}>
                  <SortTh col="cve_id"  label="CVE ID"        sortBy={sortBy} sortDir={sortDir} onSort={handleSort}/>
                  <SortTh col="pkg"     label="Package"       sortBy={sortBy} sortDir={sortDir} onSort={handleSort}/>
                  <SortTh col="sev"     label="Severity"      sortBy={sortBy} sortDir={sortDir} onSort={handleSort}/>
                  <SortTh col="cvss"    label="CVSS"          sortBy={sortBy} sortDir={sortDir} onSort={handleSort}/>
                  <SortTh col="epss"    label="EPSS"          sortBy={sortBy} sortDir={sortDir} onSort={handleSort}/>
                  <th style={{ padding:'8px 10px', fontSize:11, fontWeight:700, color:'var(--text-secondary)', borderBottom:'1px solid var(--border-primary)' }}>Exploit</th>
                  <SortTh col="affected_assets" label="Assets" sortBy={sortBy} sortDir={sortDir} onSort={handleSort}/>
                  <SortTh col="days"    label="Days Open"     sortBy={sortBy} sortDir={sortDir} onSort={handleSort}/>
                  <th style={{ padding:'8px 10px', fontSize:11, fontWeight:700, color:'var(--text-secondary)', borderBottom:'1px solid var(--border-primary)' }}>SLA</th>
                </tr>
              </thead>
              <tbody>
                {filteredVulns.slice(0, 50).map((v, i) => (
                  <tr key={i}
                    onClick={() => setSelectedCve(v)}
                    style={{
                      borderBottom:'1px solid var(--border-primary)',
                      cursor:'pointer',
                      background: selectedCve?.cve_id === v.cve_id ? `${C.blue}08` : 'transparent',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = `${C.blue}06`}
                    onMouseLeave={e => e.currentTarget.style.background = selectedCve?.cve_id === v.cve_id ? `${C.blue}08` : 'transparent'}
                  >
                    <td style={{ padding:'8px 10px' }}>
                      <div style={{ fontSize:11, fontWeight:700, color:C.blue, fontFamily:'monospace' }}>{v.cve_id}</div>
                      <div style={{ fontSize:9, color:'var(--text-muted)', maxWidth:200, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{v.desc}</div>
                    </td>
                    <td style={{ padding:'8px 10px' }}>
                      <span style={{ fontSize:11, fontWeight:600, color:'var(--text-primary)', fontFamily:'monospace' }}>{v.pkg}</span>
                      <div style={{ fontSize:9, color:'var(--text-muted)' }}>{v.ver}</div>
                    </td>
                    <td style={{ padding:'8px 10px' }}><SevPill sev={v.sev}/></td>
                    <td style={{ padding:'8px 10px' }}><CvssBadge score={v.cvss}/></td>
                    <td style={{ padding:'8px 10px' }}>
                      <span style={{ fontSize:11, fontWeight:600, color: v.epss > 0.8 ? C.critical : v.epss > 0.5 ? C.high : 'var(--text-secondary)' }}>
                        {(v.epss * 100).toFixed(0)}%
                      </span>
                    </td>
                    <td style={{ padding:'8px 10px' }}>
                      {v.exploit
                        ? <span style={{ fontSize:9, fontWeight:700, padding:'2px 6px', borderRadius:4, background:'rgba(239,68,68,0.12)', color:C.critical }}>🔴 POC</span>
                        : <span style={{ fontSize:9, color:'var(--text-muted)' }}>—</span>}
                    </td>
                    <td style={{ padding:'8px 10px', fontSize:11, fontWeight:600, color:'var(--text-primary)' }}>{v.affected_assets}</td>
                    <td style={{ padding:'8px 10px' }}>
                      <span style={{ fontSize:11, fontWeight:600, color: v.days > 90 ? C.critical : v.days > 30 ? C.high : 'var(--text-secondary)' }}>
                        {v.days}d
                      </span>
                    </td>
                    <td style={{ padding:'8px 10px' }}>
                      {v.sla_breached
                        ? <span style={{ fontSize:9, fontWeight:700, padding:'2px 6px', borderRadius:4, background:'rgba(239,68,68,0.12)', color:C.critical }}>BREACHED</span>
                        : <span style={{ fontSize:9, fontWeight:700, padding:'2px 6px', borderRadius:4, background:'rgba(34,197,94,0.12)', color:C.passed }}>OK</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* CVE Detail Panel */}
          {selectedCve && (
            <div style={{
              marginTop:10, background:'var(--bg-card)', border:`1px solid ${C.blue}40`,
              borderRadius:10, padding:16,
            }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:12 }}>
                <div>
                  <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:4 }}>
                    <span style={{ fontSize:15, fontWeight:900, color:C.blue, fontFamily:'monospace' }}>{selectedCve.cve_id}</span>
                    <SevPill sev={selectedCve.sev}/>
                    <CvssBadge score={selectedCve.cvss}/>
                    {selectedCve.exploit && <span style={{ fontSize:10, fontWeight:700, padding:'2px 7px', borderRadius:4, background:'rgba(239,68,68,0.15)', color:C.critical }}>⚡ Exploit Available</span>}
                  </div>
                  <div style={{ fontSize:12, color:'var(--text-secondary)', maxWidth:600 }}>{selectedCve.desc}</div>
                </div>
                <button onClick={() => setSelectedCve(null)} style={{ background:'none', border:'none', cursor:'pointer', color:'var(--text-muted)', fontSize:18 }}>✕</button>
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>
                <div>
                  <div style={{ fontSize:10, fontWeight:700, color:'var(--text-muted)', marginBottom:6, textTransform:'uppercase' }}>Package Details</div>
                  <div style={{ fontSize:12 }}><span style={{ color:'var(--text-muted)' }}>Package:</span> <strong style={{ color:'var(--text-primary)', fontFamily:'monospace' }}>{selectedCve.pkg}</strong></div>
                  <div style={{ fontSize:12 }}><span style={{ color:'var(--text-muted)' }}>Version:</span> <strong style={{ color:'var(--text-primary)', fontFamily:'monospace' }}>{selectedCve.ver}</strong></div>
                  <div style={{ fontSize:12 }}><span style={{ color:'var(--text-muted)' }}>CWE:</span> <span style={{ color:C.amber }}>{selectedCve.cwe}</span></div>
                </div>
                <div>
                  <div style={{ fontSize:10, fontWeight:700, color:'var(--text-muted)', marginBottom:6, textTransform:'uppercase' }}>Scoring</div>
                  <div style={{ fontSize:12 }}><span style={{ color:'var(--text-muted)' }}>CVSS v3:</span> <CvssBadge score={selectedCve.cvss}/></div>
                  <div style={{ fontSize:12 }}><span style={{ color:'var(--text-muted)' }}>EPSS:</span> <strong style={{ color: selectedCve.epss > 0.8 ? C.critical : C.amber }}>{(selectedCve.epss*100).toFixed(1)}%</strong></div>
                  <div style={{ fontSize:12 }}><span style={{ color:'var(--text-muted)' }}>Days Open:</span> <strong style={{ color: selectedCve.days > 30 ? C.critical : 'var(--text-primary)' }}>{selectedCve.days} days</strong></div>
                </div>
                <div>
                  <div style={{ fontSize:10, fontWeight:700, color:'var(--text-muted)', marginBottom:6, textTransform:'uppercase' }}>Affected Hosts ({selectedCve.affected_agents?.length})</div>
                  <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
                    {selectedCve.affected_agents?.map((aid, i) => {
                      const ag = assets.find(a => a.agent_id === aid);
                      return (
                        <span key={i} style={{ fontSize:9, padding:'2px 6px', borderRadius:4, background:'var(--bg-tertiary)', color:'var(--text-secondary)', fontFamily:'monospace' }}>
                          {ag?.hostname || aid}
                        </span>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Assets ─────────────────────────────────────────────────────── */}
      {activeTab === 'assets' && (
        <div style={{ paddingTop:10 }}>
          {/* Asset Table */}
          <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, overflow:'hidden' }}>
            <table style={{ width:'100%', borderCollapse:'collapse' }}>
              <thead>
                <tr style={{ background:'var(--bg-secondary)' }}>
                  {['Host','Platform','Status','Risk','Critical','High','Medium','Low','Total','Last Scan','Packages'].map(h => (
                    <th key={h} style={{ padding:'8px 10px', fontSize:11, fontWeight:700, textAlign:'left', color:'var(--text-secondary)', borderBottom:'1px solid var(--border-primary)', whiteSpace:'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {assets.map((a, i) => (
                  <tr key={i} style={{ borderBottom:'1px solid var(--border-primary)' }}>
                    <td style={{ padding:'8px 10px' }}>
                      <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                        <span style={{ fontSize:13 }}>{PLATFORM_ICON[a.platform]||'💻'}</span>
                        <div>
                          <div style={{ fontSize:11, fontWeight:600, color:'var(--text-primary)' }}>{a.hostname}</div>
                          <div style={{ fontSize:9, color:'var(--text-muted)', fontFamily:'monospace' }}>{a.agent_id}</div>
                        </div>
                      </div>
                    </td>
                    <td style={{ padding:'8px 10px', fontSize:11, color:'var(--text-secondary)', textTransform:'capitalize' }}>{a.platform}</td>
                    <td style={{ padding:'8px 10px' }}>
                      <span style={{ fontSize:9, fontWeight:700, padding:'2px 6px', borderRadius:20,
                        background: a.status==='active' ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)',
                        color: a.status==='active' ? C.passed : C.critical }}>
                        {a.status}
                      </span>
                    </td>
                    <td style={{ padding:'8px 10px' }}>
                      <span style={{ fontSize:11, fontWeight:700,
                        color: a.risk_level==='CRITICAL'?C.critical:a.risk_level==='HIGH'?C.high:a.risk_level==='MEDIUM'?C.medium:C.low }}>
                        {a.risk_score}
                      </span>
                    </td>
                    <td style={{ padding:'8px 10px', fontSize:11, fontWeight:700, color: a.vuln_critical>0?C.critical:'var(--text-muted)' }}>{a.vuln_critical||'—'}</td>
                    <td style={{ padding:'8px 10px', fontSize:11, fontWeight:700, color: a.vuln_high>0?C.high:'var(--text-muted)' }}>{a.vuln_high||'—'}</td>
                    <td style={{ padding:'8px 10px', fontSize:11, color: a.vuln_medium>0?C.medium:'var(--text-muted)' }}>{a.vuln_medium||'—'}</td>
                    <td style={{ padding:'8px 10px', fontSize:11, color: a.vuln_low>0?C.low:'var(--text-muted)' }}>{a.vuln_low||'—'}</td>
                    <td style={{ padding:'8px 10px', fontSize:11, fontWeight:600, color:'var(--text-primary)' }}>{a.vuln_total}</td>
                    <td style={{ padding:'8px 10px', fontSize:10, color:'var(--text-tertiary)' }}>
                      {new Date(a.last_seen_ts).toLocaleDateString()}
                    </td>
                    <td style={{ padding:'8px 10px', fontSize:11, color:'var(--text-secondary)' }}>{a.packages_scanned}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Tab: Remediation ────────────────────────────────────────────────── */}
      {activeTab === 'remediation' && (
        <div style={{ paddingTop:10 }}>
          <div>

            {/* Remediation Actions table */}
            <div style={{ background:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:10, overflow:'hidden' }}>
              <div style={{ padding:'11px 14px', borderBottom:'1px solid var(--border-primary)' }}>
                <div style={{ fontSize:13, fontWeight:700, color:'var(--text-primary)' }}>Remediation Actions</div>
                <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:2 }}>
                  One action per affected package · sorted by worst severity
                </div>
              </div>
              <table style={{ width:'100%', borderCollapse:'collapse' }}>
                <thead>
                  <tr style={{ background:'var(--bg-secondary)' }}>
                    {['#','Package','Recommended Action','CVEs','Severity','Assets','Exploit','Effort','Status'].map(h => (
                      <th key={h} style={{ padding:'8px 10px', fontSize:11, fontWeight:700, textAlign:'left',
                        color:'var(--text-secondary)', borderBottom:'1px solid var(--border-primary)', whiteSpace:'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {remediationActions.map((r, i) => (
                    <tr key={i} style={{
                      borderBottom:'1px solid var(--border-primary)',
                      background: i < 3 ? `${C.critical}05` : 'transparent',
                    }}>
                      <td style={{ padding:'8px 10px' }}>
                        <span style={{ fontSize:11, fontWeight:900, color: i<3?C.critical:i<6?C.high:'var(--text-muted)' }}>#{i+1}</span>
                      </td>
                      <td style={{ padding:'8px 10px' }}>
                        <div style={{ fontSize:11, fontWeight:700, fontFamily:'monospace', color:'var(--text-primary)' }}>{r.pkg}</div>
                        <div style={{ fontSize:9, color:'var(--text-muted)', marginTop:2 }}>
                          {r.cve_ids.join(', ')}{r.cve_count > 3 ? ` +${r.cve_count - 3} more` : ''}
                        </div>
                      </td>
                      <td style={{ padding:'8px 10px', fontSize:11, color: r.patch ? C.passed : C.amber, fontWeight:600 }}>
                        {r.action}
                      </td>
                      <td style={{ padding:'8px 10px', fontSize:12, fontWeight:900,
                        color: r.cve_count >= 5 ? C.critical : r.cve_count >= 2 ? C.high : 'var(--text-primary)' }}>
                        {r.cve_count}
                      </td>
                      <td style={{ padding:'8px 10px' }}><SevPill sev={r.severity}/></td>
                      <td style={{ padding:'8px 10px', fontSize:11, color:'var(--text-primary)' }}>{r.assets}</td>
                      <td style={{ padding:'8px 10px', textAlign:'center' }}>
                        {r.exploit
                          ? <span style={{ fontSize:10, fontWeight:700, color:C.critical }}>⚡ Yes</span>
                          : <span style={{ fontSize:10, color:'var(--text-muted)' }}>—</span>}
                      </td>
                      <td style={{ padding:'8px 10px' }}>
                        <span style={{ fontSize:9, fontWeight:700, padding:'2px 8px', borderRadius:20,
                          background: r.effort==='High'?`${C.critical}18`:r.effort==='Medium'?`${C.amber}18`:`${C.passed}18`,
                          color: r.effort==='High'?C.critical:r.effort==='Medium'?C.amber:C.passed }}>
                          {r.effort}
                        </span>
                      </td>
                      <td style={{ padding:'8px 10px' }}>
                        <span style={{ fontSize:9, fontWeight:700, padding:'2px 8px', borderRadius:20,
                          background: r.status==='Overdue'?`${C.critical}18`:r.status==='Urgent'?`${C.high}18`:`${C.blue}18`,
                          color: r.status==='Overdue'?C.critical:r.status==='Urgent'?C.high:C.blue }}>
                          {r.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
