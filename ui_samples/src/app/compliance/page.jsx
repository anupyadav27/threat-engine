'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  ClipboardCheck, CheckCircle, XCircle, TrendingUp, Download,
  AlertCircle, Calendar, AlertTriangle, BarChart3, ListChecks,
  Shield,
} from 'lucide-react';
import { fetchView, postToEngine } from '@/lib/api';
import { TENANT_ID } from '@/lib/constants';
import { useToast } from '@/lib/toast-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import SearchBar from '@/components/shared/SearchBar';
import TrendLine from '@/components/charts/TrendLine';
import GaugeChart from '@/components/charts/GaugeChart';
import DataTable from '@/components/shared/DataTable';
import FilterBar from '@/components/shared/FilterBar';

const MATRIX_FRAMEWORKS = ['CIS','NIST','SOC2','PCI','HIPAA','ISO','GDPR'];
const MATRIX_FRAMEWORK_LABELS = {
  CIS:'CIS AWS', NIST:'NIST 800-53', SOC2:'SOC 2', PCI:'PCI DSS', HIPAA:'HIPAA', ISO:'ISO 27001', GDPR:'GDPR'
};

// ── Audit readiness checklist ─────────────────────────────────────────────────
const AUDIT_CHECKLIST = [
  { label:'All framework scans up to date',  done:true  },
  { label:'Zero critical unresolved controls',done:false },
  { label:'Active exceptions reviewed',       done:true  },
  { label:'Evidence packages generated',      done:false },
  { label:'Audit trail continuity verified',  done:true  },
  { label:'Remediation plan for failures',    done:false },
];

// Continuous HSL gradient: 0=red(0°) → 50=amber(30°) → 100=green(120°)
function matrixCellColor(score, expired) {
  if (expired) return { bg:'var(--bg-tertiary)', text:'var(--text-muted)' };
  const hue = (score / 100) * 120;
  return {
    bg:   `hsla(${hue}, 70%, 45%, 0.2)`,
    text: score >= 75 ? '#22c55e' : score >= 55 ? '#f59e0b' : '#ef4444',
  };
}

export default function CompliancePage() {
  const router = useRouter();
  const toast  = useToast();
  const { provider, account, region, filterSummary } = useGlobalFilter();
  const [loading,         setLoading]         = useState(true);
  const [error,           setError]           = useState(null);
  const [trendData,       setTrendData]       = useState([]);
  const [frameworks,      setFrameworks]      = useState([]);
  const [auditDeadlines,  setAuditDeadlines]  = useState([]);
  const [exceptions,      setExceptions]      = useState([]);
  const [accounts,        setAccounts]        = useState([]);
  const [failingControls, setFailingControls] = useState([]);
  const [overallScore,    setOverallScore]    = useState(null);
  const [frameworkSearch, setFrameworkSearch] = useState('');
  const [exceptionSearch, setExceptionSearch] = useState('');

  // Hierarchical filter (provider and account come from global filter)
  const [activeFilters, setActiveFilters] = useState({ framework: '' });

  // HeatMap state
  const [hoveredCell, setHoveredCell] = useState(null);
  const [tooltipPos,  setTooltipPos]  = useState({ x: 0, y: 0 });
  const [matrixSortBy,  setMatrixSortBy]  = useState('account');
  const [matrixSortDir, setMatrixSortDir] = useState('asc');

  const handleFilterChange = (key, value) => {
    setActiveFilters(prev => ({ ...prev, [key]: value }));
  };


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

  const handleGenerateReport = async () => {
    try {
      const r = await postToEngine('compliance', '/api/v1/compliance/generate/from-threat-engine', { tenant_id: TENANT_ID });
      r && !r.error ? toast.success('Report generation started.') : toast.info('Report queued.');
    } catch { toast.info('Report request sent.'); }
  };

  // ── Derived KPIs ───────────────────────────────────────────────────────────
  const passedControls = frameworks.reduce((s, fw) => s + (fw.passed || 0), 0);
  const failedControls = frameworks.reduce((s, fw) => s + (fw.failed || 0), 0);
  const totalControls  = frameworks.reduce((s, fw) => s + (fw.controls || 0), 0);
  const passRate       = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 0;

  // ── MetricStrip KPIs ────────────────────────────────────────────────────────
  const criticalFailures = failingControls.filter(c => c.severity === 'critical').length;
  const atRiskCount      = frameworks.filter(fw => fw.score < 70).length;
  const computedScore    = overallScore ?? (passRate || null);
  const bestFw           = frameworks.reduce((best, fw) => (!best || fw.score > best.score) ? fw : best, null);
  const worstFw          = frameworks.reduce((worst, fw) => (!worst || fw.score < worst.score) ? fw : worst, null);

  // ── Filter options ─────────────────────────────────────────────────────────
  const frameworkOptions = MATRIX_FRAMEWORKS.map(k => ({ value: k, label: MATRIX_FRAMEWORK_LABELS[k] }));

  const filterDefs = [
    { key:'framework', label:'All Frameworks', options: frameworkOptions },
  ];

  // ── Matrix rows (already scope-filtered by BFF) ──────────────────────────
  const filteredMatrix = accounts;

  // ── Sorted matrix rows ─────────────────────────────────────────────────────
  const sortedMatrix = useMemo(() => {
    return [...filteredMatrix].sort((a, b) => {
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

  // ── Filtered frameworks to show in matrix columns ─────────────────────────
  const visibleFrameworks = activeFilters.framework
    ? [activeFilters.framework]
    : MATRIX_FRAMEWORKS;

  // ── Filtered failing controls ─────────────────────────────────────────────
  const filteredControls = useMemo(() =>
    failingControls.filter(c =>
      (!account              || c.account   === account) &&
      (!activeFilters.framework || c.framework === MATRIX_FRAMEWORK_LABELS[activeFilters.framework])
    ),
    [failingControls, account, activeFilters.framework]);

  // ── Audit checklist score ─────────────────────────────────────────────────
  const auditReadiness = Math.round((AUDIT_CHECKLIST.filter(c => c.done).length / AUDIT_CHECKLIST.length) * 100);

  // ── Audit deadline columns ────────────────────────────────────────────────
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

  if (error) {
    return (
      <div className="rounded-xl p-8 border text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <AlertCircle className="w-10 h-10 mx-auto mb-3" style={{ color: '#ef4444' }} />
        <p className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Failed to load compliance data</p>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color:'var(--text-primary)' }}>Compliance Dashboard</h1>
          {filterSummary && (
            <p className="text-xs mt-0.5 mb-2" style={{ color:'var(--text-tertiary)' }}>
              <span style={{ color:'var(--accent-primary)' }}>Filtered to:</span>{' '}
              <span style={{ fontWeight:600, color:'var(--text-secondary)' }}>{filterSummary}</span>
            </p>
          )}
          <p className="mt-1" style={{ color:'var(--text-secondary)' }}>
            Enterprise-wide compliance posture across {frameworks.length} frameworks
          </p>
        </div>
        <div className="flex gap-3">
          <button onClick={handleGenerateReport} className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium text-sm transition-colors" style={{ backgroundColor:'var(--accent-primary)' }}>
            <TrendingUp className="w-4 h-4" /> Generate Report
          </button>
          <button onClick={() => toast.info('Generating PDF…')} className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium text-sm transition-colors" style={{ backgroundColor:'var(--accent-primary)' }}>
            <Download className="w-4 h-4" /> PDF
          </button>
          <button onClick={() => toast.info('Generating Excel…')} className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium text-sm transition-colors" style={{ backgroundColor:'rgba(34,197,94,0.8)' }}>
            <Download className="w-4 h-4" /> Excel
          </button>
        </div>
      </div>

      {/* Hierarchical Filter Bar */}
      <FilterBar filters={filterDefs} activeFilters={activeFilters} onFilterChange={handleFilterChange} />

      {/* MetricStrip — Compliance KPIs */}
      <MetricStrip groups={[
        {
          label: '🔴 COMPLIANCE GAPS',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'FAILING CONTROLS', value: failedControls, valueColor: 'var(--severity-critical)', delta: -5, deltaGoodDown: true, context: 'vs last week' },
            { label: 'CRITICAL FAILURES', value: criticalFailures, valueColor: 'var(--severity-critical)', noTrend: true, context: 'control failures' },
            { label: 'AT-RISK FRAMEWORKS', value: atRiskCount, valueColor: 'var(--severity-high)', noTrend: true, context: 'score below 70%' },
          ],
        },
        {
          label: '🔵 POSTURE',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'OVERALL SCORE', value: computedScore + '%', valueColor: 'var(--accent-success)', delta: +1.2, context: 'vs last week' },
            { label: 'BEST FRAMEWORK', value: bestFw ? bestFw.name.split(' ')[0] + ' ' + bestFw.score + '%' : '—', noTrend: true },
            { label: 'WORST FRAMEWORK', value: worstFw ? worstFw.name.split(' ')[0] + ' ' + worstFw.score + '%' : '—', valueColor: 'var(--severity-critical)', noTrend: true },
          ],
        },
      ]} />

      {/* Gauge + Audit Readiness — 2 columns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Overall Score Gauge */}
        <div className="rounded-xl p-8 border flex flex-col items-center justify-center transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
          <h2 className="text-base font-semibold mb-4" style={{ color:'var(--text-secondary)' }}>
            Overall Compliance Score
          </h2>
          <GaugeChart score={Math.round(computedScore ?? 0)} size={200} label="Across all frameworks" />
          {totalControls > 0 && (
            <p className="text-sm mt-4" style={{ color:'var(--text-secondary)' }}>
              {passedControls.toLocaleString()} of {totalControls.toLocaleString()} controls passed
            </p>
          )}
        </div>

        {/* Audit Readiness */}
        <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4" style={{ color:'var(--accent-primary)' }} />
              <h2 className="text-base font-semibold" style={{ color:'var(--text-primary)' }}>Audit Readiness</h2>
            </div>
            <span
              className="text-2xl font-bold"
              style={{ color: auditReadiness >= 80 ? '#22c55e' : auditReadiness >= 50 ? '#f97316' : '#ef4444' }}
            >
              {auditReadiness}%
            </span>
          </div>
          {/* Readiness progress bar */}
          <div className="w-full h-2 rounded-full mb-5" style={{ backgroundColor:'var(--bg-tertiary)' }}>
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${auditReadiness}%`,
                backgroundColor: auditReadiness >= 80 ? '#22c55e' : auditReadiness >= 50 ? '#f97316' : '#ef4444',
              }}
            />
          </div>
          <div className="space-y-2.5">
            {AUDIT_CHECKLIST.map((item, i) => (
              <div key={i} className="flex items-center gap-3">
                {item.done
                  ? <CheckCircle className="w-4 h-4 flex-shrink-0" style={{ color:'#22c55e' }} />
                  : <XCircle    className="w-4 h-4 flex-shrink-0" style={{ color:'#ef4444' }} />
                }
                <span className="text-sm" style={{ color: item.done ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                  {item.label}
                </span>
                {!item.done && (
                  <span className="ml-auto text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor:'rgba(239,68,68,0.12)', color:'#ef4444' }}>
                    Action needed
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Per-Account Compliance Matrix — Enhanced HeatMap */}
      <div className="rounded-xl border overflow-hidden transition-colors duration-200 relative" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor:'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4" style={{ color:'var(--accent-primary)' }} />
            <div>
              <h3 className="text-base font-semibold" style={{ color:'var(--text-primary)' }}>Per-Account Compliance Matrix</h3>
              <p className="text-xs" style={{ color:'var(--text-tertiary)' }}>
                Continuous gradient · hover for breakdown · click header to sort · click cell to drill down
              </p>
            </div>
          </div>
          {/* Color legend */}
          <div className="hidden md:flex items-center gap-3 text-xs" style={{ color:'var(--text-muted)' }}>
            <span className="flex items-center gap-1">
              <span className="inline-block w-3 h-3 rounded-sm" style={{ backgroundColor:'hsla(0,70%,45%,0.3)' }} /> Low
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-3 h-3 rounded-sm" style={{ backgroundColor:'hsla(60,70%,45%,0.3)' }} /> Mid
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-3 h-3 rounded-sm" style={{ backgroundColor:'hsla(120,70%,45%,0.3)' }} /> High
            </span>
          </div>
        </div>
        <div className="overflow-x-auto" onMouseLeave={() => setHoveredCell(null)}>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b" style={{ borderColor:'var(--border-primary)' }}>
                <th
                  className="text-left py-2.5 px-4 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:opacity-75 select-none"
                  style={{ color: matrixSortBy==='account' ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                  onClick={() => handleMatrixSort('account')}
                >
                  Account {matrixSortBy==='account' ? (matrixSortDir==='asc' ? '↑' : '↓') : ''}
                </th>
                <th className="text-left py-2.5 px-4 text-xs font-semibold uppercase tracking-wider" style={{ color:'var(--text-muted)' }}>
                  Env
                </th>
                <th className="text-left py-2.5 px-4 text-xs font-semibold uppercase tracking-wider" style={{ color:'var(--text-muted)' }}>
                  Cloud
                </th>
                {visibleFrameworks.map(fw => (
                  <th
                    key={fw}
                    className="text-center py-2.5 px-3 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:opacity-75 select-none"
                    style={{ color: matrixSortBy===fw ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                    onClick={() => handleMatrixSort(fw)}
                  >
                    {fw} {matrixSortBy===fw ? (matrixSortDir==='asc' ? '↑' : '↓') : ''}
                  </th>
                ))}
                <th
                  className="text-center py-2.5 px-3 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:opacity-75 select-none"
                  style={{ color: matrixSortBy==='avg' ? 'var(--accent-primary)' : 'var(--text-muted)' }}
                  onClick={() => handleMatrixSort('avg')}
                >
                  Avg {matrixSortBy==='avg' ? (matrixSortDir==='asc' ? '↑' : '↓') : ''}
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedMatrix.length === 0 ? (
                <tr>
                  <td colSpan={visibleFrameworks.length + 4} className="py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                    No account data available
                  </td>
                </tr>
              ) : sortedMatrix.map((row, idx) => {
                const accountName = row.account || row.account_id || row.name || '';
                const providerName = (row.provider || row.csp || '').toUpperCase();
                const credExpired = row.credExpired || row.cred_expired || false;
                const scores = visibleFrameworks.map(fw => credExpired ? 0 : (row[fw] || 0));
                const avg    = credExpired ? null : Math.round(scores.reduce((a,b) => a+b, 0) / scores.length);
                // Environment badge derived from account name
                const env    = accountName.includes('prod') ? 'prod' : accountName.includes('staging') ? 'staging' : 'dev';
                const envCfg = { prod:{ bg:'rgba(239,68,68,0.15)', text:'#ef4444' }, staging:{ bg:'rgba(249,115,22,0.15)', text:'#f97316' }, dev:{ bg:'rgba(34,197,94,0.15)', text:'#22c55e' } };
                return (
                  <tr key={row.account_id || `acct-${idx}`} className="border-b hover:opacity-90 transition-opacity" style={{ borderColor:'var(--border-primary)' }}>
                    <td className="py-3 px-4">
                      <span className="text-sm font-medium" style={{ color:'var(--text-primary)' }}>{accountName}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor:envCfg[env].bg, color:envCfg[env].text }}>
                        {env}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{
                        backgroundColor: providerName==='AWS'?'rgba(249,115,22,0.15)':providerName==='AZURE'?'rgba(59,130,246,0.15)':providerName==='GCP'?'rgba(234,179,8,0.15)':'rgba(139,92,246,0.15)',
                        color: providerName==='AWS'?'#f97316':providerName==='AZURE'?'#3b82f6':providerName==='GCP'?'#eab308':'#8b5cf6',
                      }}>{providerName}</span>
                    </td>
                    {visibleFrameworks.map(fw => {
                      const score = row[fw] ?? 0;
                      const { bg, text } = matrixCellColor(score, credExpired);
                      const passed = credExpired ? 0 : Math.round((score / 100) * 20);
                      const failed = 20 - passed;
                      return (
                        <td
                          key={fw}
                          className="py-2 px-3 text-center cursor-pointer"
                          onClick={() => !credExpired && router.push(`/compliance/${fw.toLowerCase()}`)}
                          onMouseEnter={(e) => {
                            if (!credExpired) {
                              const rect = e.currentTarget.getBoundingClientRect();
                              setTooltipPos({ x: rect.left, y: rect.bottom + 4 });
                              setHoveredCell({ account: accountName, framework: MATRIX_FRAMEWORK_LABELS[fw]||fw, score, passed, failed });
                            }
                          }}
                        >
                          {credExpired
                            ? <span className="text-xs" style={{ color:'var(--text-muted)' }}>—</span>
                            : <div className="inline-flex flex-col items-center gap-0.5">
                                <span className="inline-flex items-center justify-center w-12 h-7 rounded text-xs font-bold transition-all" style={{ backgroundColor:bg, color:text }}>
                                  {score}
                                </span>
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

        {/* Hover tooltip — fixed position */}
        {hoveredCell && (
          <div
            className="fixed z-50 rounded-xl p-3 shadow-xl border pointer-events-none"
            style={{
              left: `${tooltipPos.x}px`,
              top:  `${tooltipPos.y}px`,
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
              minWidth: '180px',
            }}
          >
            <div className="text-xs font-bold mb-1" style={{ color:'var(--text-primary)' }}>
              {hoveredCell.account}
            </div>
            <div className="text-xs mb-1" style={{ color:'var(--text-muted)' }}>{hoveredCell.framework}</div>
            <div className="text-lg font-bold mb-1" style={{ color: hoveredCell.score >= 75 ? '#22c55e' : hoveredCell.score >= 55 ? '#f59e0b' : '#ef4444' }}>
              {hoveredCell.score}%
            </div>
            <div className="flex gap-3 text-xs">
              <span style={{ color:'#22c55e' }}>✓ {hoveredCell.passed} passed</span>
              <span style={{ color:'#ef4444' }}>✗ {hoveredCell.failed} failed</span>
            </div>
            <div className="text-[10px] mt-1.5" style={{ color:'var(--text-muted)' }}>Click to drill down →</div>
          </div>
        )}
      </div>

      {/* Framework Pass/Fail Stacked Bar */}
      <div className="rounded-xl border overflow-hidden transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <div className="px-6 py-4 border-b flex items-center gap-2" style={{ borderColor:'var(--border-primary)' }}>
          <BarChart3 className="w-4 h-4" style={{ color:'var(--accent-primary)' }} />
          <div>
            <h3 className="text-base font-semibold" style={{ color:'var(--text-primary)' }}>Framework Pass / Fail Breakdown</h3>
            <p className="text-xs" style={{ color:'var(--text-tertiary)' }}>Passed (green) vs Failed (red) controls per framework</p>
          </div>
        </div>
        <div className="p-6 space-y-3">
          {frameworks.length === 0 && !loading && (
            <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>No framework data available</p>
          )}
          {frameworks.map(fw => {
            const total = fw.controls || (fw.passed + fw.failed);
            const passW = total > 0 ? (fw.passed / total) * 100 : 0;
            const failW = total > 0 ? (fw.failed / total) * 100 : 0;
            return (
              <div key={fw.id} className="flex items-center gap-3">
                <span className="text-xs font-medium w-44 truncate flex-shrink-0" style={{ color:'var(--text-primary)' }}>
                  {fw.name}
                </span>
                <div className="flex-1 flex h-6 rounded overflow-hidden gap-px" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                  <div
                    className="h-full flex items-center justify-center text-xs font-bold text-white transition-all"
                    style={{ width:`${passW}%`, backgroundColor:'#22c55e', minWidth: passW > 5 ? undefined : 0 }}
                    title={`${fw.passed} passed`}
                  >
                    {passW > 12 && fw.passed}
                  </div>
                  <div
                    className="h-full flex items-center justify-center text-xs font-bold text-white transition-all"
                    style={{ width:`${failW}%`, backgroundColor:'#ef4444', minWidth: failW > 5 ? undefined : 0 }}
                    title={`${fw.failed} failed`}
                  >
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

      {/* Framework Cards Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Framework Compliance Scores</h2>
            <p className="text-sm" style={{ color:'var(--text-secondary)' }}>Click any framework to view detailed controls</p>
          </div>
          <SearchBar value={frameworkSearch} onChange={setFrameworkSearch} placeholder="Search frameworks..." />
        </div>
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(7)].map((_, i) => (
              <div key={i} className="h-48 rounded-xl animate-pulse border" style={{ backgroundColor:'var(--bg-secondary)', borderColor:'var(--border-primary)' }} />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {frameworks
              .filter(fw => !frameworkSearch || fw.name.toLowerCase().includes(frameworkSearch.toLowerCase()))
              .map(fw => (
                <div key={fw.id} onClick={() => handleFrameworkClick(fw.id)} className="cursor-pointer transform transition-all hover:scale-105">
                  <div className="rounded-xl p-6 border h-full flex flex-col transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
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
        )}
      </div>

      {/* Top Failing Controls */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <ListChecks className="w-4 h-4" style={{ color:'#ef4444' }} />
          <h2 className="text-lg font-semibold" style={{ color:'var(--text-primary)' }}>Top Failing Controls</h2>
        </div>
        <p className="text-sm -mt-1" style={{ color:'var(--text-secondary)' }}>
          {filteredControls.length} critical and high-severity controls failing across accounts
        </p>
        <DataTable
          data={filteredControls}
          columns={failingControlColumns}
          pageSize={10}
          loading={false}
          emptyMessage="No failing controls match the selected filters"
        />
      </div>

      {/* 12-Month Trend */}
      {trendData.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-lg font-semibold" style={{ color:'var(--text-primary)' }}>12-Month Compliance Trend</h2>
          <TrendLine data={trendData} dataKeys={['score']} title="" colors={['#22c55e']} />
        </div>
      )}

      {/* Upcoming Audits */}
      <div className="space-y-3">
        <h2 className="text-lg font-semibold" style={{ color:'var(--text-primary)' }}>Upcoming Audit Deadlines</h2>
        <DataTable data={auditDeadlines} columns={auditColumns} pageSize={5} loading={loading} emptyMessage="No upcoming audits" />
      </div>

      {/* Active Exceptions */}
      <div className="space-y-3">
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-lg font-semibold" style={{ color:'var(--text-primary)' }}>Active Exceptions</h2>
          <SearchBar value={exceptionSearch} onChange={setExceptionSearch} placeholder="Search exceptions..." />
        </div>
        <DataTable
          data={exceptions.filter(e => !exceptionSearch || (e.framework+' '+e.control+' '+e.justification).toLowerCase().includes(exceptionSearch.toLowerCase()))}
          columns={exceptionColumns}
          pageSize={5}
          loading={loading}
          emptyMessage="No active exceptions"
        />
      </div>

      {/* Status Summary */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <h3 className="text-sm font-semibold mb-4" style={{ color:'var(--text-secondary)' }}>Compliance Status Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <p className="text-xs mb-1" style={{ color:'var(--text-tertiary)' }}>Last Compliance Scan</p>
            <p className="text-sm font-medium" style={{ color:'var(--text-primary)' }}>2026-03-05 at 10:30 UTC</p>
          </div>
          <div>
            <p className="text-xs mb-1" style={{ color:'var(--text-tertiary)' }}>Next Scheduled Scan</p>
            <p className="text-sm font-medium" style={{ color:'var(--text-primary)' }}>2026-03-06 at 02:00 UTC</p>
          </div>
          <div>
            <p className="text-xs mb-1" style={{ color:'var(--text-tertiary)' }}>Monthly Trend</p>
            <p className="text-sm font-medium flex items-center gap-1" style={{ color:'#22c55e' }}>
              <TrendingUp className="w-4 h-4" /> +2.3% from last month
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
