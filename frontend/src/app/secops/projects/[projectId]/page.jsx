'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ChevronLeft, ExternalLink, Code2, Globe, Package,
  AlertTriangle, Loader2, ShieldAlert, FileCode, GitBranch,
} from 'lucide-react';
import { getFromEngine, fetchApi } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import FilterBar from '@/components/shared/FilterBar';

// ---------------------------------------------------------------------------
// Constants & helpers
// ---------------------------------------------------------------------------
const TENANT_ID = 'test-tenant';
const SCA_API_KEY = 'sbom-api-key-2024';
const SCA_BASE = '/secops/api/v1/secops/sca/api/v1/sbom';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function normalizeSev(s) {
  if (!s) return 'info';
  const v = String(s).toLowerCase();
  if (v === 'blocker') return 'critical';
  if (v === 'major')   return 'high';
  if (v === 'minor')   return 'medium';
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

function calcRiskScore(findings) {
  const c = findings.filter(f => f._sev === 'critical').length;
  const h = findings.filter(f => f._sev === 'high').length;
  const m = findings.filter(f => f._sev === 'medium').length;
  const raw = c * 10 + h * 5 + m * 2;
  return Math.min(10, raw / 10).toFixed(1);
}

const SECURITY_RULE_PATTERNS = [
  'injection', 'xss', 'sqli', 'sql', 'path', 'cmd',
  'pickle', 'ssrf', 'debug', 'hash', 'random', 'secret',
  'crypto', 'auth', 'exec', 'eval', 'deserializ',
];

function isSecurityFinding(f) {
  const sev = normalizeSev(f.severity);
  if (['critical', 'high', 'medium'].includes(sev)) return true;
  const ruleId = (f.rule_id || '').toLowerCase();
  const cat = (f.metadata?.category || '').toLowerCase();
  if (cat.includes('security')) return true;
  return SECURITY_RULE_PATTERNS.some(p => ruleId.includes(p));
}

function getVulnCategory(text) {
  const t = (text || '').toLowerCase();
  if (/sql|inject|query/.test(t))                           return 'SQL Injection';
  if (/xss|cross.site|html|template/.test(t))               return 'XSS';
  if (/command|os\.system|subprocess|shell/.test(t))         return 'Command Injection';
  if (/path|traversal|directory/.test(t))                   return 'Path Traversal';
  if (/pickle|deserializ/.test(t))                          return 'Insecure Deserialization';
  if (/ssrf|request|fetch/.test(t))                         return 'SSRF';
  if (/secret|password|credential|hardcode|api.key/.test(t)) return 'Hardcoded Credentials';
  if (/hash|md5|sha1|weak.crypt/.test(t))                   return 'Weak Cryptography';
  if (/redirect/.test(t))                                   return 'Open Redirect';
  if (/debug/.test(t))                                      return 'Debug Mode';
  return null;
}

// ---------------------------------------------------------------------------
// Inline components
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

function SourceBadge({ source }) {
  const cfg = {
    sast: { label: 'SAST', cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
    dast: { label: 'DAST', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/30' },
    sca:  { label: 'SCA',  cls: 'bg-green-500/15 text-green-400 border-green-500/30' },
  };
  const { label, cls } = cfg[source] || { label: source?.toUpperCase() || '—', cls: 'bg-slate-500/15 text-slate-400 border-slate-500/30' };
  return (
    <span className={`inline-flex items-center text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border ${cls}`}>
      {label}
    </span>
  );
}

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
            <div key={s.key} className={`${s.bg} transition-all`}
              style={{ width: `${pct}%` }} title={`${s.label}: ${v}`} />
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
// Expanded row for SAST finding
// ---------------------------------------------------------------------------
function ExpandedFindingRow({ row }) {
  const meta = row.metadata || {};
  return (
    <div className="px-5 py-4 space-y-3 border-t"
      style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
      <div>
        <div className="text-xs font-semibold uppercase tracking-wider mb-1"
          style={{ color: 'var(--text-tertiary)' }}>Full Message</div>
        <div className="text-sm" style={{ color: 'var(--text-primary)' }}>
          {row.message || '—'}
        </div>
      </div>
      {(meta.cwe || meta.category || meta.owasp) && (
        <div className="flex flex-wrap gap-x-6 gap-y-2">
          {meta.cwe && (
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider mb-0.5"
                style={{ color: 'var(--text-tertiary)' }}>CWE</div>
              <span className="text-xs font-mono px-2 py-0.5 rounded-md bg-orange-500/10 text-orange-400 border border-orange-500/20">
                {meta.cwe}
              </span>
            </div>
          )}
          {meta.category && (
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider mb-0.5"
                style={{ color: 'var(--text-tertiary)' }}>Category</div>
              <span className="text-xs px-2 py-0.5 rounded-md"
                style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-tertiary)' }}>
                {meta.category}
              </span>
            </div>
          )}
          {meta.owasp && (
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider mb-0.5"
                style={{ color: 'var(--text-tertiary)' }}>OWASP</div>
              <span className="text-xs px-2 py-0.5 rounded-md bg-red-500/10 text-red-400 border border-red-500/20">
                {meta.owasp}
              </span>
            </div>
          )}
        </div>
      )}
      {meta.code_context && (
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider mb-1"
            style={{ color: 'var(--text-tertiary)' }}>Code Context</div>
          <pre className="text-xs font-mono p-3 rounded-xl overflow-x-auto"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
            {meta.code_context}
          </pre>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Expanded row for SCA component
// ---------------------------------------------------------------------------
function ExpandedScaRow({ row }) {
  return (
    <div className="px-5 py-4 border-t"
      style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
      <div className="text-xs font-semibold uppercase tracking-wider mb-2"
        style={{ color: 'var(--text-tertiary)' }}>All CVEs</div>
      <div className="flex flex-wrap gap-1.5">
        {(row._vuln_ids || []).map(id => (
          <span key={id} className="text-xs font-mono px-2 py-0.5 rounded-md bg-red-500/10 text-red-400 border border-red-500/20">
            {id}
          </span>
        ))}
        {(!row._vuln_ids || row._vuln_ids.length === 0) && (
          <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No CVE details available</span>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function ProjectDetailPage() {
  const params = useParams();
  const router = useRouter();
  const repo_url = decodeURIComponent(params.projectId);
  const projectName = repo_url.split('/').pop().replace('.git', '');

  // Data state
  const [allSastScans, setAllSastScans] = useState([]);
  const [allDastScans, setAllDastScans] = useState([]);
  const [allScaScans,  setAllScaScans]  = useState([]);
  const [sastFindings, setSastFindings] = useState([]);
  const [dastFindings, setDastFindings] = useState([]);
  const [scaDetail,    setScaDetail]    = useState(null);

  const [loading,         setLoading]         = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [error,           setError]           = useState(null);
  const [activeTab,       setActiveTab]       = useState('overview');

  const [secFilters, setSecFilters] = useState({ severity: '', language: '' });
  const [depFilters, setDepFilters] = useState({ severity: '' });

  // ---------------------------------------------------------------------------
  // Fetch list data on mount
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
      setAllSastScans(Array.isArray(sast) ? sast : (sast?.scans || sast?.results || []));
      setAllDastScans(Array.isArray(dast) ? dast : (dast?.scans || dast?.results || []));
      setAllScaScans(Array.isArray(sca)  ? sca  : (sca?.sboms  || sca?.results  || []));
    } catch (err) {
      setError(err?.message || 'Failed to load project data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // ---------------------------------------------------------------------------
  // Derived: scans for this repo
  // ---------------------------------------------------------------------------
  const repoSastScans = useMemo(() =>
    allSastScans.filter(s => s.repo_url === repo_url || s.project_name === projectName),
    [allSastScans, repo_url, projectName]
  );

  const repoScaScans = useMemo(() =>
    allScaScans.filter(s =>
      s.host_id === repo_url ||
      (s.application_name && s.application_name.toLowerCase().includes(projectName.toLowerCase()))
    ),
    [allScaScans, repo_url, projectName]
  );

  const latestSastScan = useMemo(() =>
    [...repoSastScans]
      .filter(s => s.status === 'completed')
      .sort((a, b) => new Date(b.scan_timestamp || 0) - new Date(a.scan_timestamp || 0))[0] || repoSastScans[0],
    [repoSastScans]
  );

  const latestDastScan = useMemo(() =>
    [...allDastScans]
      .filter(s => s.status === 'completed')
      .sort((a, b) => new Date(b.scan_timestamp || 0) - new Date(a.scan_timestamp || 0))[0],
    [allDastScans]
  );

  const latestScaScan = useMemo(() =>
    [...repoScaScans].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))[0],
    [repoScaScans]
  );

  // ---------------------------------------------------------------------------
  // Load findings once scan list is available
  // ---------------------------------------------------------------------------
  const loadFindings = useCallback(async () => {
    if (!latestSastScan && !latestDastScan && !latestScaScan) return;
    setFindingsLoading(true);
    try {
      const [sastRes, dastRes, scaRes] = await Promise.all([
        latestSastScan
          ? getFromEngine('secops', `/api/v1/secops/sast/scan/${latestSastScan.secops_scan_id}/findings?limit=500`)
              .then(r => Array.isArray(r) ? r : (r?.findings || []))
              .catch(() => [])
          : Promise.resolve([]),
        latestDastScan
          ? getFromEngine('secops', `/api/v1/secops/dast/scan/${latestDastScan.dast_scan_id}/findings?limit=500`)
              .then(r => Array.isArray(r) ? r : (r?.findings || []))
              .catch(() => [])
          : Promise.resolve([]),
        latestScaScan
          ? fetchApi(`${SCA_BASE}/${latestScaScan.sbom_id}`, { headers: { 'X-API-Key': SCA_API_KEY } })
              .catch(() => null)
          : Promise.resolve(null),
      ]);
      setSastFindings(sastRes);
      setDastFindings(dastRes);
      setScaDetail(scaRes);
    } catch (err) {
      console.warn('[project-detail] loadFindings error:', err);
    } finally {
      setFindingsLoading(false);
    }
  }, [latestSastScan, latestDastScan, latestScaScan]);

  useEffect(() => {
    if (!loading && (latestSastScan || latestDastScan || latestScaScan)) {
      loadFindings();
    }
  }, [loading, loadFindings]);

  // ---------------------------------------------------------------------------
  // Normalized SAST findings
  // ---------------------------------------------------------------------------
  const normalizedSast = useMemo(() =>
    sastFindings
      .map(f => ({ ...f, _sev: normalizeSev(f.severity), _isSecurity: isSecurityFinding(f) }))
      .sort((a, b) => (SEV_ORDER[a._sev] ?? 9) - (SEV_ORDER[b._sev] ?? 9)),
    [sastFindings]
  );

  const normalizedDast = useMemo(() =>
    dastFindings.map(f => ({ ...f, _sev: normalizeSev(f.severity) })),
    [dastFindings]
  );

  const securityFindings = useMemo(() => normalizedSast.filter(f => f._isSecurity), [normalizedSast]);

  // ---------------------------------------------------------------------------
  // KPI data
  // ---------------------------------------------------------------------------
  const sevCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    normalizedSast.forEach(f => { if (counts[f._sev] !== undefined) counts[f._sev]++; });
    return counts;
  }, [normalizedSast]);

  const riskScore = useMemo(() => calcRiskScore(normalizedSast.map(f => ({ _sev: f._sev }))), [normalizedSast]);
  const filesScanned = latestSastScan?.files_scanned ?? 0;
  const scaVulnCount = repoScaScans.reduce((a, s) => a + (s.vulnerability_count || 0), 0);

  // ---------------------------------------------------------------------------
  // Correlated risks
  // ---------------------------------------------------------------------------
  const correlatedRisks = useMemo(() => {
    const sastCats = {};
    const dastCats = {};

    normalizedSast.forEach(f => {
      const cat = getVulnCategory(f.rule_id) || getVulnCategory(f.message);
      if (!cat) return;
      if (!sastCats[cat]) sastCats[cat] = { sev: f._sev, finding: f };
      else if ((SEV_ORDER[f._sev] ?? 9) < (SEV_ORDER[sastCats[cat].sev] ?? 9)) {
        sastCats[cat] = { sev: f._sev, finding: f };
      }
    });

    normalizedDast.forEach(f => {
      const cat = getVulnCategory(f.vulnerability_type) || getVulnCategory(f.description);
      if (!cat) return;
      if (!dastCats[cat]) dastCats[cat] = { sev: f._sev, finding: f };
      else if ((SEV_ORDER[f._sev] ?? 9) < (SEV_ORDER[dastCats[cat].sev] ?? 9)) {
        dastCats[cat] = { sev: f._sev, finding: f };
      }
    });

    const allCats = new Set([...Object.keys(sastCats), ...Object.keys(dastCats)]);
    const rows = [];

    allCats.forEach(cat => {
      const inSast = !!sastCats[cat];
      const inDast = !!dastCats[cat];
      const sources = [];
      if (inSast) sources.push('sast');
      if (inDast) sources.push('dast');
      const sev = inSast ? sastCats[cat].sev : dastCats[cat].sev;
      const sastEvidence = inSast
        ? `${sastCats[cat].finding.file_path || ''}${sastCats[cat].finding.line_number ? `:${sastCats[cat].finding.line_number}` : ''}`
        : '—';
      const dastF = inDast ? dastCats[cat].finding : null;
      const dastEvidence = dastF
        ? (dastF.endpoint_url ? `${dastF.endpoint_url}` : dastF.resource || '—')
        : '—';
      rows.push({ cat, sev, sources, inSast, inDast, sastEvidence, dastEvidence });
    });

    return rows
      .sort((a, b) => {
        // Correlated first, then by severity
        const corrA = a.inSast && a.inDast ? 0 : 1;
        const corrB = b.inSast && b.inDast ? 0 : 1;
        if (corrA !== corrB) return corrA - corrB;
        return (SEV_ORDER[a.sev] ?? 9) - (SEV_ORDER[b.sev] ?? 9);
      })
      .slice(0, 8);
  }, [normalizedSast, normalizedDast]);

  // ---------------------------------------------------------------------------
  // SCA vulnerable components
  // ---------------------------------------------------------------------------
  const vulnComponents = useMemo(() => {
    if (!scaDetail?.vulnerable_components) return [];
    return scaDetail.vulnerable_components.map(c => ({
      name:       c.name,
      version:    c.version,
      purl:       c.purl,
      _vuln_ids:  c.vulnerability_ids || [],
      cveCount:   (c.vulnerability_ids || []).length,
      _risk:      (c.vulnerability_ids || []).length >= 5 ? 'high'
               : (c.vulnerability_ids || []).length >= 2 ? 'medium' : 'low',
    })).sort((a, b) => b.cveCount - a.cveCount);
  }, [scaDetail]);

  // ---------------------------------------------------------------------------
  // All languages
  // ---------------------------------------------------------------------------
  const allLanguages = useMemo(() => {
    const langs = new Set(normalizedSast.map(f => f.language).filter(Boolean));
    return [...langs].sort();
  }, [normalizedSast]);

  // ---------------------------------------------------------------------------
  // Filtered security findings
  // ---------------------------------------------------------------------------
  const filteredSecurity = useMemo(() =>
    securityFindings.filter(f => {
      if (secFilters.severity && f._sev !== secFilters.severity) return false;
      if (secFilters.language && f.language !== secFilters.language) return false;
      return true;
    }),
    [securityFindings, secFilters]
  );

  // ---------------------------------------------------------------------------
  // Filtered dependencies
  // ---------------------------------------------------------------------------
  const filteredDeps = useMemo(() =>
    vulnComponents.filter(c => {
      if (depFilters.severity && c._risk !== depFilters.severity) return false;
      return true;
    }),
    [vulnComponents, depFilters]
  );

  // ---------------------------------------------------------------------------
  // Combined scan history
  // ---------------------------------------------------------------------------
  const scanHistory = useMemo(() => {
    const combined = [
      ...repoSastScans.map(s => ({ ...s, _type: 'sast', _ts: s.scan_timestamp, _id: s.secops_scan_id })),
      ...repoScaScans.map(s  => ({ ...s, _type: 'sca',  _ts: s.created_at,     _id: s.sbom_id })),
    ];
    return combined.sort((a, b) => new Date(b._ts || 0) - new Date(a._ts || 0));
  }, [repoSastScans, repoScaScans]);

  // ---------------------------------------------------------------------------
  // Column definitions
  // ---------------------------------------------------------------------------
  const securityColumns = useMemo(() => [
    {
      accessorKey: '_sev',
      header: 'Severity',
      size: 100,
      cell: info => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'rule_id',
      header: 'Rule',
      size: 180,
      cell: info => {
        const v = info.getValue() || '—';
        return (
          <span className="text-sm font-semibold truncate block max-w-[160px]" title={v} style={{ color: 'var(--text-primary)' }}>
            {v}
          </span>
        );
      },
    },
    {
      id: 'file',
      header: 'File:Line',
      cell: info => {
        const row = info.row.original;
        const txt = `${row.file_path || '—'}${row.line_number ? `:${row.line_number}` : ''}`;
        return (
          <span className="text-xs font-mono truncate block max-w-[180px]" title={txt} style={{ color: 'var(--text-secondary)' }}>
            {txt}
          </span>
        );
      },
    },
    {
      accessorKey: 'message',
      header: 'Message',
      cell: info => {
        const v = info.getValue() || '—';
        return (
          <span className="text-xs truncate block max-w-[220px]" title={v} style={{ color: 'var(--text-secondary)' }}>
            {v}
          </span>
        );
      },
    },
    {
      accessorKey: 'language',
      header: 'Language',
      size: 100,
      cell: info => {
        const v = info.getValue();
        if (!v) return <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
        return (
          <span className="text-xs px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20">
            {v}
          </span>
        );
      },
    },
  ], []);

  const depColumns = useMemo(() => [
    {
      id: 'package',
      header: 'Package',
      cell: info => {
        const row = info.row.original;
        return (
          <div className="min-w-0">
            <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{row.name}</span>
            <span className="ml-2 text-xs px-1.5 py-0.5 rounded bg-slate-500/20 text-slate-400 font-mono">{row.version}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'cveCount',
      header: 'CVE Count',
      size: 100,
      cell: info => {
        const v = info.getValue();
        const cls = v >= 5 ? 'text-red-400' : v >= 2 ? 'text-orange-400' : 'text-yellow-400';
        return <span className={`text-sm font-bold tabular-nums ${cls}`}>{v}</span>;
      },
    },
    {
      accessorKey: '_risk',
      header: 'Risk',
      size: 90,
      cell: info => {
        const v = info.getValue();
        const cfg = {
          high:   'bg-red-500/15 text-red-400 border-red-500/30',
          medium: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
          low:    'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
        };
        return (
          <span className={`inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded-full border ${cfg[v] || 'bg-slate-500/15 text-slate-400 border-slate-500/30'}`}>
            {v}
          </span>
        );
      },
    },
    {
      id: 'cves',
      header: 'CVEs',
      cell: info => {
        const row = info.row.original;
        const ids = row._vuln_ids || [];
        return (
          <div className="flex flex-wrap gap-1">
            {ids.slice(0, 2).map(id => (
              <span key={id} className="text-xs font-mono px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                {id}
              </span>
            ))}
            {ids.length > 2 && (
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>+{ids.length - 2} more</span>
            )}
          </div>
        );
      },
    },
    {
      id: 'recommendation',
      header: 'Recommendation',
      cell: () => (
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          Upgrade to latest stable version
        </span>
      ),
    },
  ], []);

  const historyColumns = useMemo(() => [
    {
      id: 'type',
      header: 'Type',
      size: 80,
      cell: info => <SourceBadge source={info.row.original._type} />,
    },
    {
      id: 'branch',
      header: 'Branch',
      size: 120,
      cell: info => {
        const row = info.row.original;
        const b = row.branch || row.sbom_format || '—';
        return (
          <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{b}</span>
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
          <span className={`text-sm font-bold ${n > 0 ? 'text-orange-400' : 'text-green-400'}`}>{n}</span>
        );
      },
    },
    {
      id: 'files',
      header: 'Files',
      size: 80,
      cell: info => {
        const v = info.row.original.files_scanned;
        return (
          <span className="text-sm tabular-nums" style={{ color: 'var(--text-secondary)' }}>
            {v ?? '—'}
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
        return (
          <button
            onClick={e => {
              e.stopPropagation();
              if (row._type === 'sast') router.push(`/secops/${row._id}`);
              else if (row._type === 'sca') router.push(`/secops/sca/${row._id}`);
            }}
            className="text-xs px-2.5 py-1 rounded-lg border hover:bg-white/5 transition-colors"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
            View
          </button>
        );
      },
    },
  ], [router]);

  // ---------------------------------------------------------------------------
  // Tab definitions
  // ---------------------------------------------------------------------------
  const tabs = [
    { id: 'overview',     label: 'Overview' },
    { id: 'security',     label: `Security Issues (${securityFindings.length})` },
    { id: 'dependencies', label: `Dependencies (${vulnComponents.length})` },
    { id: 'history',      label: `Scan History (${scanHistory.length})` },
  ];

  // ---------------------------------------------------------------------------
  // Loading state
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        Loading project data...
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-6 py-8 space-y-4">
        <button onClick={() => router.push('/secops/projects')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Projects
        </button>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-red-400">Failed to load project</div>
            <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{error}</div>
          </div>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="px-6 pt-6 pb-0">

        {/* Back button */}
        <button onClick={() => router.push('/secops/projects')}
          className="flex items-center gap-2 text-sm mb-6 hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Projects
        </button>

        {/* Page header */}
        <div className="flex items-start justify-between mb-6">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{projectName}</h1>
              <RiskScoreBadge score={riskScore} />
              {latestSastScan?.status && <StatusIndicator status={latestSastScan.status} />}
            </div>
            <div className="flex items-center gap-2 mt-2">
              <a
                href={repo_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono flex items-center gap-1 hover:opacity-75 transition-opacity"
                style={{ color: 'var(--text-tertiary)' }}>
                {repo_url}
                <ExternalLink className="w-3 h-3 flex-shrink-0" />
              </a>
            </div>
          </div>
          {latestSastScan?.languages_detected?.length > 0 && (
            <div className="flex flex-wrap gap-1.5 ml-4">
              {latestSastScan.languages_detected.map(l => (
                <span key={l} className="text-xs px-2.5 py-1 rounded-full border bg-slate-500/10 text-slate-400 border-slate-500/20">
                  {l}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* KPI cards */}
        <div className="grid grid-cols-4 gap-x-4 gap-y-4 mb-6">
          <KpiCard
            title="Risk Score"
            value={riskScore}
            subtitle={parseFloat(riskScore) >= 7 ? 'High risk — action required' : parseFloat(riskScore) >= 4 ? 'Medium risk' : 'Low risk'}
            icon={<ShieldAlert className="w-5 h-5" />}
            color={parseFloat(riskScore) >= 7 ? 'red' : parseFloat(riskScore) >= 4 ? 'orange' : 'green'}
          />
          <KpiCard
            title="Security Issues"
            value={securityFindings.length}
            subtitle={`${sevCounts.critical} critical, ${sevCounts.high} high`}
            icon={<AlertTriangle className="w-5 h-5" />}
            color={securityFindings.length > 0 ? 'orange' : 'green'}
          />
          <KpiCard
            title="SCA Vulnerabilities"
            value={scaVulnCount}
            subtitle={`${vulnComponents.length} vulnerable packages`}
            icon={<Package className="w-5 h-5" />}
            color={scaVulnCount > 0 ? 'orange' : 'green'}
          />
          <KpiCard
            title="Files Scanned"
            value={filesScanned}
            subtitle={`${repoSastScans.length} SAST scan${repoSastScans.length !== 1 ? 's' : ''} run`}
            icon={<FileCode className="w-5 h-5" />}
            color="blue"
          />
        </div>

        {/* Tab strip */}
        <div className="flex items-center gap-1 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === tab.id ? 'border-blue-500' : 'border-transparent hover:opacity-75'
              }`}
              style={activeTab === tab.id ? { color: '#60a5fa' } : { color: 'var(--text-secondary)' }}>
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="px-6 pt-6 pb-8 space-y-6">

        {/* ── OVERVIEW TAB ── */}
        {activeTab === 'overview' && (
          <>
            {/* Severity distribution bar */}
            <div className="rounded-2xl border overflow-hidden"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-4 border-b flex items-center justify-between"
                style={{ borderColor: 'var(--border-primary)' }}>
                <div>
                  <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Severity Distribution</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                    SAST findings breakdown by severity
                  </div>
                </div>
              </div>
              <div className="px-5 py-4">
                {findingsLoading ? (
                  <div className="flex items-center gap-2 text-sm py-2" style={{ color: 'var(--text-tertiary)' }}>
                    <Loader2 className="w-4 h-4 animate-spin" /> Loading findings...
                  </div>
                ) : (
                  <SeverityBar counts={sevCounts} />
                )}
              </div>
            </div>

            {/* Correlated risks card */}
            <div className="rounded-2xl border overflow-hidden border-l-4 border-l-orange-500"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-4 border-b"
                style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-orange-500/15">
                    <AlertTriangle className="w-4 h-4 text-orange-400" />
                  </div>
                  <div>
                    <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
                      Correlated Risks — Found across multiple engines
                    </h2>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                      Vulnerability categories detected by SAST and/or DAST analysis
                    </p>
                  </div>
                </div>
              </div>

              {findingsLoading ? (
                <div className="px-5 py-6 flex items-center gap-2 text-sm" style={{ color: 'var(--text-tertiary)' }}>
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading correlation data...
                </div>
              ) : correlatedRisks.length === 0 ? (
                <div className="px-5 py-8 text-center">
                  <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>No security findings to correlate</p>
                </div>
              ) : (
                <>
                  {normalizedDast.length === 0 && (
                    <div className="px-5 py-3 border-b"
                      style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                      <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                        Run a DAST scan against this application's URL to see runtime correlation
                      </p>
                    </div>
                  )}
                  {/* Column headers */}
                  <div className="grid grid-cols-12 gap-x-4 px-5 py-2 text-xs font-semibold uppercase tracking-wider border-b"
                    style={{ borderColor: 'var(--border-primary)', color: 'var(--text-tertiary)', backgroundColor: 'var(--bg-secondary)' }}>
                    <span className="col-span-1">Severity</span>
                    <span className="col-span-3">Category</span>
                    <span className="col-span-2">Sources</span>
                    <span className="col-span-3">SAST Evidence</span>
                    <span className="col-span-3">DAST Evidence</span>
                  </div>
                  {correlatedRisks.map((row, i) => (
                    <div key={i}
                      className="grid grid-cols-12 gap-x-4 items-center px-5 py-3 border-b last:border-0 hover:bg-white/5 transition-colors"
                      style={{ borderColor: 'var(--border-primary)' }}>
                      <div className="col-span-1">
                        <SeverityBadge severity={row.sev} />
                      </div>
                      <div className="col-span-3 text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                        {row.cat}
                      </div>
                      <div className="col-span-2 flex flex-wrap gap-1">
                        {row.sources.map(s => <SourceBadge key={s} source={s} />)}
                        {row.inSast && row.inDast && (
                          <span className="inline-flex items-center text-[10px] font-semibold px-2 py-0.5 rounded-full border bg-orange-500/15 text-orange-400 border-orange-500/30">
                            CORRELATED
                          </span>
                        )}
                      </div>
                      <div className="col-span-3">
                        <span className="text-xs font-mono truncate block" style={{ color: 'var(--text-secondary)' }}>
                          {row.sastEvidence}
                        </span>
                      </div>
                      <div className="col-span-3">
                        <span className="text-xs font-mono truncate block" style={{ color: 'var(--text-secondary)' }}>
                          {row.dastEvidence}
                        </span>
                      </div>
                    </div>
                  ))}
                </>
              )}
            </div>

            {/* Two-column: top security issues + vulnerable deps */}
            <div className="grid grid-cols-2 gap-x-4 gap-y-4">
              {/* Top Security Issues */}
              <div className="rounded-2xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Top Security Issues</h3>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Highest severity SAST findings</p>
                </div>
                <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
                  {securityFindings.slice(0, 5).length === 0 ? (
                    <div className="px-5 py-6 text-sm text-center" style={{ color: 'var(--text-tertiary)' }}>
                      {findingsLoading ? 'Loading...' : 'No security issues found'}
                    </div>
                  ) : securityFindings.slice(0, 5).map((f, i) => (
                    <div key={i} className="px-5 py-3 flex items-start gap-3">
                      <div className="flex-shrink-0 mt-0.5">
                        <SeverityBadge severity={f._sev} />
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
                          {f.rule_id || '—'}
                        </div>
                        <div className="text-xs font-mono mt-0.5 truncate" style={{ color: 'var(--text-tertiary)' }}>
                          {f.file_path || '—'}{f.line_number ? `:${f.line_number}` : ''}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Vulnerable Dependencies */}
              <div className="rounded-2xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Vulnerable Dependencies</h3>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Packages with known CVEs</p>
                </div>
                <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
                  {vulnComponents.slice(0, 5).length === 0 ? (
                    <div className="px-5 py-6 text-sm text-center" style={{ color: 'var(--text-tertiary)' }}>
                      {findingsLoading ? 'Loading...' : 'No vulnerable packages found'}
                    </div>
                  ) : vulnComponents.slice(0, 5).map((c, i) => (
                    <div key={i} className="px-5 py-3 flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{c.name}</div>
                        <div className="text-xs font-mono mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{c.version}</div>
                      </div>
                      <span className={`text-xs font-bold px-2 py-0.5 rounded-full flex-shrink-0 ${
                        c.cveCount >= 5 ? 'bg-red-500/20 text-red-400'
                        : c.cveCount >= 2 ? 'bg-orange-500/20 text-orange-400'
                        : 'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {c.cveCount} CVE{c.cveCount !== 1 ? 's' : ''}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {/* ── SECURITY ISSUES TAB ── */}
        {activeTab === 'security' && (
          <>
            <FilterBar
              filters={[
                { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low', 'info'] },
                { key: 'language', label: 'Language', options: allLanguages },
              ]}
              activeFilters={secFilters}
              onFilterChange={(key, val) => setSecFilters(prev => ({ ...prev, [key]: val }))}
            />
            <DataTable
              data={filteredSecurity}
              columns={securityColumns}
              pageSize={25}
              loading={findingsLoading}
              emptyMessage="No security findings match the current filters."
              renderExpandedRow={row => <ExpandedFindingRow row={row} />}
            />
          </>
        )}

        {/* ── DEPENDENCIES TAB ── */}
        {activeTab === 'dependencies' && (
          <>
            <FilterBar
              filters={[
                { key: 'severity', label: 'Risk',     options: ['high', 'medium', 'low'] },
              ]}
              activeFilters={depFilters}
              onFilterChange={(key, val) => setDepFilters(prev => ({ ...prev, [key]: val }))}
            />
            <DataTable
              data={filteredDeps}
              columns={depColumns}
              pageSize={25}
              loading={findingsLoading}
              emptyMessage="No vulnerable dependencies found."
              renderExpandedRow={row => <ExpandedScaRow row={row} />}
            />
          </>
        )}

        {/* ── SCAN HISTORY TAB ── */}
        {activeTab === 'history' && (
          <DataTable
            data={scanHistory}
            columns={historyColumns}
            pageSize={20}
            loading={loading}
            emptyMessage="No scans found for this repository."
            onRowClick={row => {
              if (row._type === 'sast') router.push(`/secops/${row._id}`);
              else if (row._type === 'sca') router.push(`/secops/sca/${row._id}`);
            }}
          />
        )}

      </div>
    </div>
  );
}
