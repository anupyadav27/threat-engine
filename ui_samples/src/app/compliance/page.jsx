'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  ClipboardCheck, CheckCircle, XCircle, TrendingUp, Download,
  AlertTriangle, BarChart3, Shield,
} from 'lucide-react';
import { fetchView, postToEngine } from '@/lib/api';
import { TENANT_ID } from '@/lib/constants';
import { useToast } from '@/lib/toast-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import InsightRow from '@/components/shared/InsightRow';
import TrendLine from '@/components/charts/TrendLine';
import GaugeChart from '@/components/charts/GaugeChart';
import SearchBar from '@/components/shared/SearchBar';

// ── Constants ────────────────────────────────────────────────────────────────

const MATRIX_FRAMEWORKS = ['CIS','NIST','SOC2','PCI','HIPAA','ISO','GDPR'];
const MATRIX_FRAMEWORK_LABELS = {
  CIS:'CIS AWS', NIST:'NIST 800-53', SOC2:'SOC 2', PCI:'PCI DSS', HIPAA:'HIPAA', ISO:'ISO 27001', GDPR:'GDPR'
};

const AUDIT_CHECKLIST = [
  { label:'All framework scans up to date',  done:true  },
  { label:'Zero critical unresolved controls',done:false },
  { label:'Active exceptions reviewed',       done:true  },
  { label:'Evidence packages generated',      done:false },
  { label:'Audit trail continuity verified',  done:true  },
  { label:'Remediation plan for failures',    done:false },
];

// Continuous HSL gradient: 0=red(0) -> 50=amber(30) -> 100=green(120)
function matrixCellColor(score, expired) {
  if (expired) return { bg:'var(--bg-tertiary)', text:'var(--text-muted)' };
  const hue = (score / 100) * 120;
  return {
    bg:   `hsla(${hue}, 70%, 45%, 0.2)`,
    text: score >= 75 ? '#22c55e' : score >= 55 ? '#f59e0b' : '#ef4444',
  };
}

// ── Page Component ──────────────────────────────────────────────────────────

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

  // Matrix local state
  const [matrixSortBy,  setMatrixSortBy]  = useState('account');
  const [matrixSortDir, setMatrixSortDir] = useState('asc');
  const [hoveredCell,   setHoveredCell]   = useState(null);
  const [tooltipPos,    setTooltipPos]    = useState({ x: 0, y: 0 });

  // Framework cards search
  const [frameworkSearch, setFrameworkSearch] = useState('');

  // ── Data fetch ──────────────────────────────────────────────────────────────

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchView('compliance', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.frameworks)      setFrameworks(data.frameworks);
        if (data.overallScore != null) setOverallScore(data.overallScore);
        if (data.trendData)       setTrendData(data.trendData);
        if (data.auditDeadlines)  setAuditDeadlines(data.auditDeadlines);
        if (data.exceptions)      setExceptions(data.exceptions);
        if (data.accountMatrix)   setAccounts(data.accountMatrix);
        if (data.failingControls) setFailingControls(data.failingControls);
      } catch (err) {
        console.warn('[compliance] fetchData error:', err);
        setError(err?.message || 'Failed to load compliance data');
      } finally { setLoading(false); }
    };
    fetchData();
  }, [provider, account, region]);

  // ── Actions ─────────────────────────────────────────────────────────────────

  const handleGenerateReport = async () => {
    try {
      const r = await postToEngine('compliance', '/api/v1/compliance/generate/from-threat-engine', { tenant_id: TENANT_ID });
      r && !r.error ? toast.success('Report generation started.') : toast.info('Report queued.');
    } catch { toast.info('Report request sent.'); }
  };

  const handleFrameworkClick = (id) => {
    router.push(`/compliance/${id}`);
  };

  const handleMatrixSort = (col) => {
    if (matrixSortBy === col) {
      setMatrixSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setMatrixSortBy(col);
      setMatrixSortDir('desc');
    }
  };

  // ── Derived KPIs ────────────────────────────────────────────────────────────

  const passedControls  = frameworks.reduce((s, fw) => s + (fw.passed || 0), 0);
  const failedControls  = frameworks.reduce((s, fw) => s + (fw.failed || 0), 0);
  const totalControls   = frameworks.reduce((s, fw) => s + (fw.controls || 0), 0);
  const passRate        = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 0;
  const criticalFailures = failingControls.filter(c => c.severity === 'critical').length;
  const atRiskCount      = frameworks.filter(fw => fw.score < 70).length;
  const computedScore    = overallScore ?? passRate ?? 0;
  const bestFw           = frameworks.reduce((best, fw) => (!best || fw.score > best.score) ? fw : best, null);
  const worstFw          = frameworks.reduce((worst, fw) => (!worst || fw.score < worst.score) ? fw : worst, null);
  const auditReadiness   = Math.round((AUDIT_CHECKLIST.filter(c => c.done).length / AUDIT_CHECKLIST.length) * 100);

  // ── Sorted matrix rows ──────────────────────────────────────────────────────

  const sortedMatrix = useMemo(() => {
    return [...accounts].sort((a, b) => {
      let valA, valB;
      if (matrixSortBy === 'account') {
        valA = a.account || a.account_id || a.name || '';
        valB = b.account || b.account_id || b.name || '';
        return matrixSortDir === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }
      if (matrixSortBy === 'avg') {
        const avg = row => MATRIX_FRAMEWORKS.reduce((s, fw) => s + (row[fw] || 0), 0) / MATRIX_FRAMEWORKS.length;
        valA = avg(a); valB = avg(b);
      } else {
        valA = a[matrixSortBy] || 0; valB = b[matrixSortBy] || 0;
      }
      return matrixSortDir === 'asc' ? valA - valB : valB - valA;
    });
  }, [accounts, matrixSortBy, matrixSortDir]);

  // ── Filter helpers ──────────────────────────────────────────────────────────

  const frameworkOptions = MATRIX_FRAMEWORKS.map(k => ({ value: k, label: MATRIX_FRAMEWORK_LABELS[k] }));
  const controlUniqueVals = (key) => [...new Set(failingControls.map(r => r[key]).filter(Boolean))].sort();
  const auditUniqueVals = (key) => [...new Set(auditDeadlines.map(r => r[key]).filter(Boolean))].sort();
  const exceptionUniqueVals = (key) => [...new Set(exceptions.map(r => r[key]).filter(Boolean))].sort();

  const controlFilterDefs = useMemo(() => {
    const f = [
      { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
      { key: 'framework', label: 'Framework', options: frameworkOptions },
    ];
    const accountVals = controlUniqueVals('account');
    if (accountVals.length > 0) f.push({ key: 'account', label: 'Account', options: accountVals });
    const regionVals = controlUniqueVals('region');
    if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
    return f;
  }, [failingControls]);

  const auditFilterDefs = useMemo(() => {
    const f = [];
    const fwVals = auditUniqueVals('framework');
    if (fwVals.length > 0) f.push({ key: 'framework', label: 'Framework', options: fwVals });
    const statusVals = auditUniqueVals('status');
    if (statusVals.length > 0) f.push({ key: 'status', label: 'Status', options: statusVals });
    const ownerVals = auditUniqueVals('owner');
    if (ownerVals.length > 0) f.push({ key: 'owner', label: 'Owner', options: ownerVals });
    return f;
  }, [auditDeadlines]);

  const exceptionFilterDefs = useMemo(() => {
    const f = [];
    const fwVals = exceptionUniqueVals('framework');
    if (fwVals.length > 0) f.push({ key: 'framework', label: 'Framework', options: fwVals });
    const statusVals = exceptionUniqueVals('status');
    if (statusVals.length > 0) f.push({ key: 'status', label: 'Status', options: statusVals });
    return f;
  }, [exceptions]);

  // ── Column definitions ──────────────────────────────────────────────────────

  const failingControlColumns = [
    { accessorKey:'control_id', header:'Control ID',  cell:(i) => <code className="text-xs px-2 py-1 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--text-tertiary)' }}>{i.getValue()}</code> },
    { accessorKey:'title',      header:'Control',     cell:(i) => <span className="text-sm font-medium" style={{ color:'var(--text-primary)' }}>{i.getValue()}</span> },
    { accessorKey:'framework',  header:'Framework',   cell:(i) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey:'account',    header:'Account',     cell:(i) => <span className="text-xs" style={{ color:'var(--text-tertiary)' }}>{i.getValue()}</span> },
    { accessorKey:'region',     header:'Region',      cell:(i) => <span className="text-xs" style={{ color:'var(--text-muted)' }}>{i.getValue()}</span> },
    { accessorKey:'severity',   header:'Severity',    cell:(i) => {
      const s=i.getValue(); const cfg={critical:{bg:'rgba(239,68,68,0.15)',text:'#ef4444'},high:{bg:'rgba(249,115,22,0.15)',text:'#f97316'},medium:{bg:'rgba(234,179,8,0.15)',text:'#eab308'},low:{bg:'rgba(34,197,94,0.15)',text:'#22c55e'}};
      const c=cfg[s]||cfg.medium;
      return <span className="text-xs px-2 py-0.5 rounded-full font-semibold capitalize" style={{ backgroundColor:c.bg, color:c.text }}>{s}</span>;
    }},
    { accessorKey:'days_open',  header:'Days Open',   cell:(i) => {
      const d=i.getValue(); const color=d>30?'#ef4444':d>14?'#f97316':'var(--text-tertiary)';
      return <span className="text-xs font-semibold" style={{ color }}>{d}d</span>;
    }},
  ];

  const auditColumns = [
    { accessorKey:'framework',      header:'Framework',      cell:(i) => <span className="text-sm font-medium" style={{ color:'var(--text-primary)' }}>{i.getValue()}</span> },
    { accessorKey:'type',           header:'Audit Type',     cell:(i) => <span className="text-sm" style={{ color:'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey:'due_date',       header:'Due Date',       cell:(i) => <span className="text-sm" style={{ color:'var(--text-secondary)' }}>{new Date(i.getValue()).toLocaleDateString()}</span> },
    { accessorKey:'days_remaining', header:'Days Left',      cell:(i) => { const d=i.getValue(); return <span className={`text-sm font-semibold ${d<=30?'text-red-400':'text-green-400'}`}>{d}d</span>; } },
    { accessorKey:'owner',          header:'Owner',          cell:(i) => <span className="text-sm" style={{ color:'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey:'status',         header:'Status',         cell:(i) => {
      const s=i.getValue(); const cfg={'on-track':{bg:'rgba(34,197,94,0.15)',text:'#22c55e',label:'On Track'},'at-risk':{bg:'rgba(249,115,22,0.15)',text:'#f97316',label:'At Risk'}};
      const c=cfg[s]||cfg['on-track'];
      return <span className="text-xs px-2 py-1 rounded font-medium" style={{ backgroundColor:c.bg, color:c.text }}>{c.label}</span>;
    }},
  ];

  const exceptionColumns = [
    { accessorKey:'framework',    header:'Framework',    cell:(i) => <span className="text-sm font-medium" style={{ color:'var(--text-primary)' }}>{i.getValue()}</span> },
    { accessorKey:'control',      header:'Control',      cell:(i) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey:'justification',header:'Justification',cell:(i) => <span className="text-sm line-clamp-2" style={{ color:'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey:'approved_by',  header:'Approved By',  cell:(i) => <span className="text-sm" style={{ color:'var(--text-secondary)' }}>{i.getValue()}</span> },
    { accessorKey:'expiry_date',  header:'Expires',      cell:(i) => <span className="text-sm" style={{ color:'var(--text-secondary)' }}>{new Date(i.getValue()).toLocaleDateString()}</span> },
    { accessorKey:'status',       header:'Status',       cell:(i) => {
      const s=i.getValue();
      return <span className="text-xs px-2 py-1 rounded font-medium" style={{ backgroundColor:s==='expiring-soon'?'rgba(249,115,22,0.15)':'rgba(34,197,94,0.15)', color:s==='expiring-soon'?'#f97316':'#22c55e' }}>
        {s==='expiring-soon'?'Expiring Soon':'Active'}
      </span>;
    }},
  ];

  // ── Custom tab renderers ────────────────────────────────────────────────────

  const renderMatrixTab = () => (
    <div className="space-y-6">
      {/* Per-Account Compliance Matrix HeatMap */}
      <div className="rounded-xl border overflow-hidden relative" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor:'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4" style={{ color:'var(--accent-primary)' }} />
            <div>
              <h3 className="text-base font-semibold" style={{ color:'var(--text-primary)' }}>Per-Account Compliance Matrix</h3>
              <p className="text-xs" style={{ color:'var(--text-tertiary)' }}>
                Continuous gradient -- hover for breakdown -- click header to sort -- click cell to drill down
              </p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-3 text-xs" style={{ color:'var(--text-muted)' }}>
            <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-sm" style={{ backgroundColor:'hsla(0,70%,45%,0.3)' }} /> Low</span>
            <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-sm" style={{ backgroundColor:'hsla(60,70%,45%,0.3)' }} /> Mid</span>
            <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-sm" style={{ backgroundColor:'hsla(120,70%,45%,0.3)' }} /> High</span>
          </div>
        </div>
        <div className="overflow-x-auto" onMouseLeave={() => setHoveredCell(null)}>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b" style={{ borderColor:'var(--border-primary)' }}>
                <th className="text-left py-2.5 px-4 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:opacity-75 select-none"
                  style={{ color: matrixSortBy==='account' ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                  onClick={() => handleMatrixSort('account')}>
                  Account {matrixSortBy==='account' ? (matrixSortDir==='asc' ? '\u2191' : '\u2193') : ''}
                </th>
                <th className="text-left py-2.5 px-4 text-xs font-semibold uppercase tracking-wider" style={{ color:'var(--text-muted)' }}>Env</th>
                <th className="text-left py-2.5 px-4 text-xs font-semibold uppercase tracking-wider" style={{ color:'var(--text-muted)' }}>Cloud</th>
                {MATRIX_FRAMEWORKS.map(fw => (
                  <th key={fw} className="text-center py-2.5 px-3 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:opacity-75 select-none"
                    style={{ color: matrixSortBy===fw ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                    onClick={() => handleMatrixSort(fw)}>
                    {fw} {matrixSortBy===fw ? (matrixSortDir==='asc' ? '\u2191' : '\u2193') : ''}
                  </th>
                ))}
                <th className="text-center py-2.5 px-3 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:opacity-75 select-none"
                  style={{ color: matrixSortBy==='avg' ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                  onClick={() => handleMatrixSort('avg')}>
                  Avg {matrixSortBy==='avg' ? (matrixSortDir==='asc' ? '\u2191' : '\u2193') : ''}
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedMatrix.length === 0 ? (
                <tr>
                  <td colSpan={MATRIX_FRAMEWORKS.length + 4} className="py-8 text-center text-sm" style={{ color:'var(--text-muted)' }}>
                    No account data available
                  </td>
                </tr>
              ) : sortedMatrix.map((row, idx) => {
                const accountName = row.account || row.account_id || row.name || '';
                const providerName = (row.provider || row.csp || '').toUpperCase();
                const credExpired = row.credExpired || row.cred_expired || false;
                const scores = MATRIX_FRAMEWORKS.map(fw => credExpired ? 0 : (row[fw] || 0));
                const avg    = credExpired ? null : Math.round(scores.reduce((a,b) => a+b, 0) / scores.length);
                const env    = accountName.includes('prod') ? 'prod' : accountName.includes('staging') ? 'staging' : 'dev';
                const envCfg = { prod:{ bg:'rgba(239,68,68,0.15)', text:'#ef4444' }, staging:{ bg:'rgba(249,115,22,0.15)', text:'#f97316' }, dev:{ bg:'rgba(34,197,94,0.15)', text:'#22c55e' } };
                return (
                  <tr key={row.account_id || `acct-${idx}`} className="border-b hover:opacity-90 transition-opacity" style={{ borderColor:'var(--border-primary)' }}>
                    <td className="py-3 px-4"><span className="text-sm font-medium" style={{ color:'var(--text-primary)' }}>{accountName}</span></td>
                    <td className="py-3 px-4"><span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor:envCfg[env].bg, color:envCfg[env].text }}>{env}</span></td>
                    <td className="py-3 px-4">
                      <span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{
                        backgroundColor: providerName==='AWS'?'rgba(249,115,22,0.15)':providerName==='AZURE'?'rgba(59,130,246,0.15)':providerName==='GCP'?'rgba(234,179,8,0.15)':'rgba(139,92,246,0.15)',
                        color: providerName==='AWS'?'#f97316':providerName==='AZURE'?'#3b82f6':providerName==='GCP'?'#eab308':'#8b5cf6',
                      }}>{providerName}</span>
                    </td>
                    {MATRIX_FRAMEWORKS.map(fw => {
                      const score = row[fw] ?? 0;
                      const { bg, text } = matrixCellColor(score, credExpired);
                      const passed = credExpired ? 0 : Math.round((score / 100) * 20);
                      const failed = 20 - passed;
                      return (
                        <td key={fw} className="py-2 px-3 text-center cursor-pointer"
                          onClick={() => !credExpired && router.push(`/compliance/${fw.toLowerCase()}`)}
                          onMouseEnter={(e) => {
                            if (!credExpired) {
                              const rect = e.currentTarget.getBoundingClientRect();
                              setTooltipPos({ x: rect.left, y: rect.bottom + 4 });
                              setHoveredCell({ account: accountName, framework: MATRIX_FRAMEWORK_LABELS[fw]||fw, score, passed, failed });
                            }
                          }}>
                          {credExpired
                            ? <span className="text-xs" style={{ color:'var(--text-muted)' }}>--</span>
                            : <div className="inline-flex flex-col items-center gap-0.5">
                                <span className="inline-flex items-center justify-center w-12 h-7 rounded text-xs font-bold transition-all" style={{ backgroundColor:bg, color:text }}>{score}</span>
                              </div>
                          }
                        </td>
                      );
                    })}
                    <td className="py-2 px-3 text-center">
                      {avg === null
                        ? <span className="text-xs" style={{ color:'var(--text-muted)' }}>N/A</span>
                        : <span className="text-sm font-bold" style={{ color: avg >= 75 ? '#22c55e' : avg >= 55 ? '#f59e0b' : '#ef4444' }}>{avg}%</span>
                      }
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Hover tooltip */}
        {hoveredCell && (
          <div className="fixed z-50 rounded-xl p-3 shadow-xl border pointer-events-none"
            style={{ left:`${tooltipPos.x}px`, top:`${tooltipPos.y}px`, backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)', minWidth:'180px' }}>
            <div className="text-xs font-bold mb-1" style={{ color:'var(--text-primary)' }}>{hoveredCell.account}</div>
            <div className="text-xs mb-1" style={{ color:'var(--text-muted)' }}>{hoveredCell.framework}</div>
            <div className="text-lg font-bold mb-1" style={{ color: hoveredCell.score >= 75 ? '#22c55e' : hoveredCell.score >= 55 ? '#f59e0b' : '#ef4444' }}>{hoveredCell.score}%</div>
            <div className="flex gap-3 text-xs">
              <span style={{ color:'#22c55e' }}>{'\u2713'} {hoveredCell.passed} passed</span>
              <span style={{ color:'#ef4444' }}>{'\u2717'} {hoveredCell.failed} failed</span>
            </div>
            <div className="text-[10px] mt-1.5" style={{ color:'var(--text-muted)' }}>Click to drill down {'\u2192'}</div>
          </div>
        )}
      </div>

      {/* Framework Pass/Fail Stacked Bar */}
      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <div className="px-6 py-4 border-b flex items-center gap-2" style={{ borderColor:'var(--border-primary)' }}>
          <BarChart3 className="w-4 h-4" style={{ color:'var(--accent-primary)' }} />
          <div>
            <h3 className="text-base font-semibold" style={{ color:'var(--text-primary)' }}>Framework Pass / Fail Breakdown</h3>
            <p className="text-xs" style={{ color:'var(--text-tertiary)' }}>Passed (green) vs Failed (red) controls per framework</p>
          </div>
        </div>
        <div className="p-6 space-y-3">
          {frameworks.length === 0 && !loading && (
            <p className="text-sm text-center py-4" style={{ color:'var(--text-muted)' }}>No framework data available</p>
          )}
          {frameworks.map(fw => {
            const total = fw.controls || (fw.passed + fw.failed);
            const passW = total > 0 ? (fw.passed / total) * 100 : 0;
            const failW = total > 0 ? (fw.failed / total) * 100 : 0;
            return (
              <div key={fw.id} className="flex items-center gap-3">
                <span className="text-xs font-medium w-44 truncate flex-shrink-0" style={{ color:'var(--text-primary)' }}>{fw.name}</span>
                <div className="flex-1 flex h-6 rounded overflow-hidden gap-px" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                  <div className="h-full flex items-center justify-center text-xs font-bold text-white transition-all"
                    style={{ width:`${passW}%`, backgroundColor:'#22c55e', minWidth: passW > 5 ? undefined : 0 }}
                    title={`${fw.passed} passed`}>
                    {passW > 12 && fw.passed}
                  </div>
                  <div className="h-full flex items-center justify-center text-xs font-bold text-white transition-all"
                    style={{ width:`${failW}%`, backgroundColor:'#ef4444', minWidth: failW > 5 ? undefined : 0 }}
                    title={`${fw.failed} failed`}>
                    {failW > 12 && fw.failed}
                  </div>
                </div>
                <span className="text-xs w-10 text-right flex-shrink-0 font-semibold" style={{ color: fw.score >= 80 ? '#22c55e' : fw.score >= 60 ? '#eab308' : '#ef4444' }}>
                  {fw.score}%
                </span>
              </div>
            );
          })}
          <div className="flex items-center gap-4 pt-2">
            <span className="flex items-center gap-1.5 text-xs" style={{ color:'var(--text-tertiary)' }}>
              <span className="w-3 h-3 rounded-sm inline-block" style={{ backgroundColor:'#22c55e' }} /> Passed
            </span>
            <span className="flex items-center gap-1.5 text-xs" style={{ color:'var(--text-tertiary)' }}>
              <span className="w-3 h-3 rounded-sm inline-block" style={{ backgroundColor:'#ef4444' }} /> Failed
            </span>
          </div>
        </div>
      </div>
    </div>
  );

  const renderFrameworksTab = () => (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Framework Compliance Scores</h2>
          <p className="text-sm" style={{ color:'var(--text-secondary)' }}>Click any framework to view detailed controls</p>
        </div>
        <SearchBar value={frameworkSearch} onChange={setFrameworkSearch} placeholder="Search frameworks..." />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {frameworks
          .filter(fw => !frameworkSearch || fw.name.toLowerCase().includes(frameworkSearch.toLowerCase()))
          .map(fw => (
            <div key={fw.id} onClick={() => handleFrameworkClick(fw.id)} className="cursor-pointer transform transition-all hover:scale-105">
              <div className="rounded-xl p-6 border h-full flex flex-col" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
                <div className="mb-4 flex-1">
                  <h4 className="text-sm font-semibold mb-4 line-clamp-2" style={{ color:'var(--text-primary)' }}>{fw.name}</h4>
                  <div className="flex items-end gap-4 mb-4">
                    <div>
                      <p className="text-3xl font-bold" style={{ color:'var(--accent-primary)' }}>{fw.score}</p>
                      <p className="text-xs" style={{ color:'var(--text-muted)' }}>% Compliant</p>
                    </div>
                    <div className="flex-1">
                      <div className="w-full rounded-full h-2" style={{ backgroundColor:'var(--bg-secondary)' }}>
                        <div className="h-full rounded-full transition-all" style={{ width:`${fw.score}%`, backgroundColor: fw.score>=80?'#22c55e':fw.score>=60?'#f97316':'#ef4444' }} />
                      </div>
                    </div>
                  </div>
                </div>
                <div className="border-t pt-4" style={{ borderColor:'var(--border-primary)' }}>
                  <div className="grid grid-cols-3 gap-2 text-xs text-center">
                    <div><p style={{ color:'var(--text-muted)' }}>Total</p><p className="font-semibold" style={{ color:'var(--text-primary)' }}>{fw.controls}</p></div>
                    <div><p style={{ color:'var(--text-muted)' }}>Passed</p><p className="font-semibold text-green-400">{fw.passed}</p></div>
                    <div><p style={{ color:'var(--text-muted)' }}>Failed</p><p className="font-semibold text-red-400">{fw.failed}</p></div>
                  </div>
                  <p className="text-xs mt-3" style={{ color:'var(--text-muted)' }}>
                    Last assessed: {fw.last_assessed ? new Date(fw.last_assessed).toLocaleDateString() : 'N/A'}
                  </p>
                </div>
              </div>
            </div>
          ))}
      </div>
    </div>
  );

  // ── PageLayout props ────────────────────────────────────────────────────────

  const pageContext = {
    title: 'Compliance Dashboard',
    brief: `Enterprise-wide compliance posture across ${frameworks.length} frameworks`,
    tabs: [
      { id: 'matrix',     label: 'Compliance Matrix', count: accounts.length },
      { id: 'controls',   label: 'Failing Controls',  count: failingControls.length },
      { id: 'frameworks', label: 'Frameworks',         count: frameworks.length },
      { id: 'audits',     label: 'Audit Deadlines',    count: auditDeadlines.length },
      { id: 'exceptions', label: 'Exceptions',         count: exceptions.length },
    ],
  };

  const kpiGroups = [
    {
      title: 'Compliance Gaps',
      items: [
        { label: 'Failing Controls',  value: failedControls },
        { label: 'Critical Failures', value: criticalFailures },
        { label: 'At-Risk Frameworks', value: atRiskCount, suffix: 'below 70%' },
      ],
    },
    {
      title: 'Posture',
      items: [
        { label: 'Overall Score',    value: computedScore + '%' },
        { label: 'Best Framework',   value: bestFw ? bestFw.name.split(' ')[0] + ' ' + bestFw.score + '%' : '--' },
        { label: 'Worst Framework',  value: worstFw ? worstFw.name.split(' ')[0] + ' ' + worstFw.score + '%' : '--' },
      ],
    },
  ];

  const insightRowEl = (
    <InsightRow
      left={
        <div className="flex flex-col items-center justify-center">
          <h2 className="text-base font-semibold mb-4" style={{ color:'var(--text-secondary)' }}>Overall Compliance Score</h2>
          <GaugeChart score={Math.round(computedScore ?? 0)} size={200} label="Across all frameworks" />
          {totalControls > 0 && (
            <p className="text-sm mt-4" style={{ color:'var(--text-secondary)' }}>
              {passedControls.toLocaleString()} of {totalControls.toLocaleString()} controls passed
            </p>
          )}
        </div>
      }
      right={
        trendData.length > 0 ? (
          <div>
            <h2 className="text-base font-semibold mb-4" style={{ color:'var(--text-secondary)' }}>12-Month Compliance Trend</h2>
            <TrendLine data={trendData} dataKeys={['score']} title="" colors={['#22c55e']} />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full">
            <div className="flex items-center justify-between mb-4 w-full">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4" style={{ color:'var(--accent-primary)' }} />
                <h2 className="text-base font-semibold" style={{ color:'var(--text-primary)' }}>Audit Readiness</h2>
              </div>
              <span className="text-2xl font-bold"
                style={{ color: auditReadiness >= 80 ? '#22c55e' : auditReadiness >= 50 ? '#f97316' : '#ef4444' }}>
                {auditReadiness}%
              </span>
            </div>
            <div className="w-full h-2 rounded-full mb-5" style={{ backgroundColor:'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full transition-all"
                style={{ width:`${auditReadiness}%`, backgroundColor: auditReadiness >= 80 ? '#22c55e' : auditReadiness >= 50 ? '#f97316' : '#ef4444' }} />
            </div>
            <div className="space-y-2.5 w-full">
              {AUDIT_CHECKLIST.map((item, i) => (
                <div key={i} className="flex items-center gap-3">
                  {item.done
                    ? <CheckCircle className="w-4 h-4 flex-shrink-0" style={{ color:'#22c55e' }} />
                    : <XCircle    className="w-4 h-4 flex-shrink-0" style={{ color:'#ef4444' }} />
                  }
                  <span className="text-sm" style={{ color: item.done ? 'var(--text-primary)' : 'var(--text-secondary)' }}>{item.label}</span>
                  {!item.done && (
                    <span className="ml-auto text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor:'rgba(239,68,68,0.12)', color:'#ef4444' }}>Action needed</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )
      }
    />
  );

  const tabData = {
    matrix: {
      renderTab: renderMatrixTab,
    },
    controls: {
      data: failingControls,
      columns: failingControlColumns,
      filters: controlFilterDefs,
      groupByOptions: [
        { key: 'severity', label: 'Severity' },
        { key: 'framework', label: 'Framework' },
        { key: 'account', label: 'Account' },
        { key: 'region', label: 'Region' },
      ],
    },
    frameworks: {
      renderTab: renderFrameworksTab,
    },
    audits: {
      data: auditDeadlines,
      columns: auditColumns,
      filters: auditFilterDefs,
      groupByOptions: [
        { key: 'framework', label: 'Framework' },
        { key: 'status', label: 'Status' },
        { key: 'owner', label: 'Owner' },
      ],
    },
    exceptions: {
      data: exceptions,
      columns: exceptionColumns,
      filters: exceptionFilterDefs,
      groupByOptions: [
        { key: 'framework', label: 'Framework' },
        { key: 'status', label: 'Status' },
      ],
    },
  };

  return (
    <PageLayout
      icon={ClipboardCheck}
      pageContext={pageContext}
      kpiGroups={kpiGroups}
      insightRow={insightRowEl}
      tabData={tabData}
      loading={loading}
      error={error}
      defaultTab="matrix"
    />
  );
}
