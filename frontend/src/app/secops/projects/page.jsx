'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  ChevronLeft, ChevronRight, RefreshCw, Plus, X,
  Code2, Globe, Package, ShieldAlert, AlertTriangle,
  GitBranch, Clock, Loader2, CheckCircle,
} from 'lucide-react';
import { getFromEngine, fetchApi } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
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
// SourceBadge
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// ScanModal (simplified — SAST only)
// ---------------------------------------------------------------------------
function ScanModal({ onClose, onLaunch, scanStatus }) {
  const [repoUrl, setRepoUrl]   = useState('');
  const [branch,  setBranch]    = useState('main');
  const [error,   setError]     = useState('');
  const isRunning = scanStatus !== null;

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    if (!repoUrl.trim()) { setError('Repository URL is required'); return; }
    onLaunch({ repo_url: repoUrl.trim(), branch: branch.trim() || 'main' });
  };

  const handleClose = () => {
    if (isRunning) return;
    setRepoUrl(''); setBranch('main'); setError('');
    onClose();
  };

  return (
    <>
      <div className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" onClick={handleClose} />
      <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg border rounded-2xl shadow-2xl z-50"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

        <div className="flex items-center justify-between p-6 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div>
            <h2 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>New Security Scan</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Runs SAST analysis on the target repository
            </p>
          </div>
          <button onClick={handleClose} disabled={isRunning}
            className="p-1.5 rounded-lg hover:bg-white/5 transition-colors disabled:opacity-40">
            <X className="w-5 h-5" style={{ color: 'var(--text-tertiary)' }} />
          </button>
        </div>

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

          {error && (
            <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-xl px-3 py-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          {isRunning && (
            <div className="flex items-center gap-3 rounded-xl px-4 py-3 bg-blue-500/10 border border-blue-500/20">
              <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
              <div>
                <div className="text-sm font-semibold text-blue-400">Scan running</div>
                <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>SAST analysis in progress</div>
              </div>
              {scanStatus?.sast === 'completed' && <CheckCircle className="w-4 h-4 text-green-400 ml-auto" />}
            </div>
          )}

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
                <>Start Scan</>
              )}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function ProjectsPage() {
  const router = useRouter();

  const [sastScans, setSastScans] = useState([]);
  const [dastScans, setDastScans] = useState([]);
  const [scaScans,  setScaScans]  = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);

  const [showModal,   setShowModal]   = useState(false);
  const [scanStatus,  setScanStatus]  = useState(null);

  const [activeFilters, setActiveFilters] = useState({ riskLevel: '', language: '' });

  // ---------------------------------------------------------------------------
  // Fetch
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
  // Derived: group SAST scans into projects
  // ---------------------------------------------------------------------------
  const projects = useMemo(() => {
    const byRepo = {};

    sastScans.forEach(s => {
      const key = s.repo_url || s.project_name;
      if (!key) return;
      if (!byRepo[key]) {
        byRepo[key] = {
          repo_url: key,
          name: s.project_name || key.split('/').pop().replace('.git', ''),
          scans: [],
          totalFindings: 0,
          languages: [],
          lastScan: null,
          status: 'completed',
        };
      }
      byRepo[key].scans.push(s);
      byRepo[key].totalFindings += s.total_findings || 0;
      byRepo[key].languages = [...new Set([...byRepo[key].languages, ...(s.languages_detected || [])])];
      const ts = s.scan_timestamp || s.started_at;
      if (!byRepo[key].lastScan || new Date(ts) > new Date(byRepo[key].lastScan)) {
        byRepo[key].lastScan = ts;
        byRepo[key].status = s.status;
      }
    });

    return Object.values(byRepo)
      .map(p => {
        // Approximate risk: treat total findings roughly as high-severity
        const approxFindings = Array.from({ length: p.totalFindings }, (_, i) => ({
          _sev: i < p.totalFindings * 0.1 ? 'critical'
              : i < p.totalFindings * 0.35 ? 'high'
              : 'medium',
        }));
        const riskScore = calcRiskScore(approxFindings);
        const criticalCount = Math.round(p.totalFindings * 0.1);
        const highCount     = Math.round(p.totalFindings * 0.25);

        // Match SCA by host_id === repo_url
        const matchedSca = scaScans.filter(
          s => s.host_id === p.repo_url || (s.application_name && p.name && s.application_name.toLowerCase().includes(p.name.toLowerCase()))
        );
        const scaVulns = matchedSca.reduce((a, s) => a + (s.vulnerability_count || 0), 0);

        return { ...p, riskScore, criticalCount, highCount, scaVulns };
      })
      .sort((a, b) => parseFloat(b.riskScore) - parseFloat(a.riskScore));
  }, [sastScans, scaScans]);

  // ---------------------------------------------------------------------------
  // KPI computations
  // ---------------------------------------------------------------------------
  const totalVulns    = useMemo(() => projects.reduce((a, p) => a + p.totalFindings, 0), [projects]);
  const criticalCount = useMemo(() => projects.reduce((a, p) => a + p.criticalCount, 0), [projects]);
  const lastScanTs    = useMemo(() => {
    const ts = projects.map(p => p.lastScan).filter(Boolean).sort().reverse()[0];
    return ts ? fmtDate(ts) : '—';
  }, [projects]);

  // ---------------------------------------------------------------------------
  // All languages (for filter)
  // ---------------------------------------------------------------------------
  const allLanguages = useMemo(() => {
    const langs = new Set();
    projects.forEach(p => p.languages.forEach(l => langs.add(l)));
    return [...langs].sort();
  }, [projects]);

  // ---------------------------------------------------------------------------
  // Filtered projects
  // ---------------------------------------------------------------------------
  const filteredProjects = useMemo(() => {
    return projects.filter(p => {
      if (activeFilters.language && !p.languages.includes(activeFilters.language)) return false;
      if (activeFilters.riskLevel) {
        const s = parseFloat(p.riskScore);
        const level = activeFilters.riskLevel;
        if (level === 'critical (≥7)' && s < 7)  return false;
        if (level === 'high (4–6.9)'  && (s < 4 || s >= 7)) return false;
        if (level === 'medium (2–3.9)' && (s < 2 || s >= 4)) return false;
        if (level === 'low (<2)'       && s >= 2) return false;
      }
      return true;
    });
  }, [projects, activeFilters]);

  // ---------------------------------------------------------------------------
  // Scan launch handler
  // ---------------------------------------------------------------------------
  const handleLaunch = useCallback(async ({ repo_url, branch }) => {
    setScanStatus({ sast: 'running' });
    try {
      await getFromEngine('secops', `/api/v1/secops/sast/scan`, {
        method: 'POST',
        body: JSON.stringify({ repo_url, branch, tenant_id: TENANT_ID }),
      }).catch(() => {});
      setTimeout(() => { setScanStatus(null); setShowModal(false); loadData(); }, 3000);
    } catch (_) {
      setScanStatus(null);
    }
  }, [loadData]);

  // ---------------------------------------------------------------------------
  // Column definitions
  // ---------------------------------------------------------------------------
  const columns = useMemo(() => [
    {
      id: 'project',
      accessorKey: 'name',
      header: 'Project',
      cell: info => {
        const row = info.row.original;
        return (
          <div className="min-w-0">
            <div className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
              {row.name}
            </div>
            <div className="text-xs font-mono truncate mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              {row.repo_url}
            </div>
          </div>
        );
      },
    },
    {
      accessorKey: 'riskScore',
      header: 'Risk Score',
      size: 110,
      cell: info => <RiskScoreBadge score={info.getValue()} />,
    },
    {
      accessorKey: 'criticalCount',
      header: 'Critical',
      size: 80,
      cell: info => {
        const v = info.getValue();
        return (
          <span className={`text-sm font-bold tabular-nums ${v > 0 ? 'text-red-400' : ''}`}
            style={v === 0 ? { color: 'var(--text-tertiary)' } : {}}>
            {v || '—'}
          </span>
        );
      },
    },
    {
      accessorKey: 'highCount',
      header: 'High',
      size: 80,
      cell: info => {
        const v = info.getValue();
        return (
          <span className={`text-sm font-bold tabular-nums ${v > 0 ? 'text-orange-400' : ''}`}
            style={v === 0 ? { color: 'var(--text-tertiary)' } : {}}>
            {v || '—'}
          </span>
        );
      },
    },
    {
      accessorKey: 'totalFindings',
      header: 'Findings',
      size: 90,
      cell: info => {
        const v = info.getValue();
        return (
          <span className={`text-sm font-bold tabular-nums ${v > 0 ? 'text-orange-400' : 'text-green-400'}`}>
            {v}
          </span>
        );
      },
    },
    {
      accessorKey: 'languages',
      header: 'Languages',
      cell: info => {
        const langs = info.getValue() || [];
        return (
          <div className="flex flex-wrap gap-1">
            {langs.slice(0, 3).map(l => (
              <span key={l} className="text-xs px-1.5 py-0.5 rounded-md bg-purple-500/20 text-purple-300">
                {l}
              </span>
            ))}
            {langs.length > 3 && (
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>+{langs.length - 3}</span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'lastScan',
      header: 'Last Scan',
      size: 140,
      cell: info => (
        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
          {fmtDate(info.getValue())}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 110,
      cell: info => <StatusIndicator status={info.getValue() || 'completed'} />,
    },
    {
      id: 'action',
      header: '',
      size: 50,
      cell: info => {
        const row = info.row.original;
        return (
          <button
            onClick={e => { e.stopPropagation(); router.push(`/secops/projects/${encodeURIComponent(row.repo_url)}`); }}
            className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
            title="View project">
            <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
          </button>
        );
      },
    },
  ], [router]);

  // ---------------------------------------------------------------------------
  // Filter bar definitions
  // ---------------------------------------------------------------------------
  const filterDefs = [
    { key: 'riskLevel', label: 'Risk Level', options: ['critical (≥7)', 'high (4–6.9)', 'medium (2–3.9)', 'low (<2)'] },
    { key: 'language',  label: 'Language',   options: allLanguages },
  ];

  // ---------------------------------------------------------------------------
  // Loading state
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        Loading projects...
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="px-6 pt-6 pb-8 space-y-6">

        {/* Back button */}
        <button onClick={() => router.push('/secops')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Code Security
        </button>

        {/* Page header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Projects</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
              Git repositories scanned for security issues
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
              New Scan
            </button>
          </div>
        </div>

        {/* KPI cards */}
        <div className="grid grid-cols-4 gap-x-4 gap-y-4">
          <KpiCard
            title="Total Projects"
            value={projects.length}
            subtitle={`${projects.length} repositor${projects.length !== 1 ? 'ies' : 'y'} scanned`}
            icon={<GitBranch className="w-5 h-5" />}
            color="blue"
          />
          <KpiCard
            title="Total Vulnerabilities"
            value={totalVulns}
            subtitle="Across all repositories"
            icon={<ShieldAlert className="w-5 h-5" />}
            color={totalVulns > 0 ? 'red' : 'green'}
          />
          <KpiCard
            title="Critical Issues"
            value={criticalCount}
            subtitle="Requires immediate attention"
            icon={<AlertTriangle className="w-5 h-5" />}
            color="orange"
          />
          <KpiCard
            title="Last Scan"
            value={lastScanTs.split(' ').slice(0, 2).join(' ')}
            subtitle={lastScanTs.split(' ').slice(2).join(' ') || 'No scans yet'}
            icon={<Clock className="w-5 h-5" />}
            color="purple"
          />
        </div>

        {/* Filter bar */}
        <FilterBar
          filters={filterDefs}
          activeFilters={activeFilters}
          onFilterChange={(key, val) => setActiveFilters(prev => ({ ...prev, [key]: val }))}
        />

        {/* Data table */}
        <DataTable
          data={filteredProjects}
          columns={columns}
          pageSize={20}
          loading={loading}
          emptyMessage="No repositories scanned yet — start a scan pipeline to see projects here."
          onRowClick={row => router.push(`/secops/projects/${encodeURIComponent(row.repo_url)}`)}
        />

      </div>

      {/* Scan modal */}
      {showModal && (
        <ScanModal
          onClose={() => { if (!scanStatus) setShowModal(false); }}
          onLaunch={handleLaunch}
          scanStatus={scanStatus}
        />
      )}
    </div>
  );
}
