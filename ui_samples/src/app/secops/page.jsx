'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  Code2,
  Plus,
  X,
  Shield,
  Package,
  Zap,
  FileCode2,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
} from 'lucide-react';
import { getFromEngine, postToEngine } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';

/* ─────────────────────────────────────────────────────────────────────────────
   STATIC FALLBACK DATA  (shown when engines are offline / no real scans yet)
───────────────────────────────────────────────────────────────────────────── */
const DEMO_SAST_SCANS = [
  {
    scan_id: 'sast-001', repo_name: 'threat-engine', repo_url: 'https://github.com/org/threat-engine',
    branch: 'main', status: 'completed', findings_count: 47, critical: 8, high: 19, medium: 14, low: 6,
    started_at: new Date(Date.now() - 3600000).toISOString(), completed_at: new Date(Date.now() - 3000000).toISOString(),
    duration: '10m 12s', languages: 'Python, Dockerfile, YAML', files_scanned: 312, iac_findings: 11,
    secrets_found: 3, container_vulns: 7,
  },
  {
    scan_id: 'sast-002', repo_name: 'cloud-infra', repo_url: 'https://github.com/org/cloud-infra',
    branch: 'develop', status: 'completed', findings_count: 31, critical: 4, high: 12, medium: 9, low: 6,
    started_at: new Date(Date.now() - 86400000).toISOString(), completed_at: new Date(Date.now() - 83000000).toISOString(),
    duration: '7m 45s', languages: 'Terraform, Python', files_scanned: 198, iac_findings: 22,
    secrets_found: 1, container_vulns: 0,
  },
  {
    scan_id: 'sast-003', repo_name: 'frontend-app', repo_url: 'https://github.com/org/frontend-app',
    branch: 'main', status: 'running', findings_count: 0, critical: 0, high: 0, medium: 0, low: 0,
    started_at: new Date(Date.now() - 300000).toISOString(), completed_at: null,
    duration: 'Running…', languages: 'TypeScript, JavaScript', files_scanned: 0, iac_findings: 0,
    secrets_found: 0, container_vulns: 0,
  },
];

const DEMO_DAST_SCANS = [
  {
    scan_id: 'dast-001', target_url: 'https://api.threat-engine.internal', scan_type: 'Active',
    status: 'completed', vulnerabilities: 14, critical: 2, high: 5, medium: 5, low: 2,
    started_at: new Date(Date.now() - 7200000).toISOString(), duration: '22m 30s',
    auth_type: 'Bearer Token', pages_crawled: 148,
  },
  {
    scan_id: 'dast-002', target_url: 'https://dashboard.threat-engine.internal', scan_type: 'Passive',
    status: 'completed', vulnerabilities: 7, critical: 0, high: 2, medium: 3, low: 2,
    started_at: new Date(Date.now() - 172800000).toISOString(), duration: '8m 10s',
    auth_type: 'OAuth2', pages_crawled: 64,
  },
  {
    scan_id: 'dast-003', target_url: 'https://onboarding.threat-engine.internal', scan_type: 'Active',
    status: 'pending', vulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0,
    started_at: new Date(Date.now() - 60000).toISOString(), duration: '—',
    auth_type: 'API Key', pages_crawled: 0,
  },
];

const DEMO_SCA_SCANS = [
  {
    scan_id: 'sca-001', repo_name: 'threat-engine', package_manager: 'pip', total_packages: 87,
    vulnerable: 12, critical: 3, high: 5, medium: 4, low: 0, outdated: 23,
    license_issues: 2, status: 'completed',
    scanned_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    scan_id: 'sca-002', repo_name: 'frontend-app', package_manager: 'npm', total_packages: 342,
    vulnerable: 19, critical: 1, high: 7, medium: 8, low: 3, outdated: 67,
    license_issues: 5, status: 'completed',
    scanned_at: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    scan_id: 'sca-003', repo_name: 'cloud-infra', package_manager: 'go mod', total_packages: 56,
    vulnerable: 4, critical: 0, high: 2, medium: 2, low: 0, outdated: 9,
    license_issues: 0, status: 'completed',
    scanned_at: new Date(Date.now() - 172800000).toISOString(),
  },
];

/* ─────────────────────────────────────────────────────────────────────────────
   SCAN REPOSITORY MODAL
───────────────────────────────────────────────────────────────────────────── */
function ScanRepositoryModal({ isOpen, onClose, onSubmit, isLoading }) {
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    if (!repoUrl.trim()) { setError('Repository URL is required'); return; }
    if (!branch.trim())  { setError('Branch name is required'); return; }
    onSubmit({ repo_url: repoUrl, branch });
    setRepoUrl('');
    setBranch('main');
  };

  if (!isOpen) return null;
  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />
      <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md border rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between p-6 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <h2 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Scan Repository</h2>
          <button onClick={onClose} className="p-1 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            <X className="w-5 h-5" style={{ color: 'var(--text-tertiary)' }} />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>Repository URL</label>
            <input type="text" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/org/repo"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              disabled={isLoading} />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>Branch</label>
            <input type="text" value={branch} onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              disabled={isLoading} />
          </div>
          {error && (
            <div className="p-3 border rounded-lg bg-red-500/20 border-red-800">
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}
          <div className="flex gap-3 pt-4">
            <button type="button" onClick={onClose} disabled={isLoading}
              className="flex-1 px-4 py-2 rounded-lg font-medium transition-colors"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
              Cancel
            </button>
            <button type="submit" disabled={isLoading}
              className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors">
              {isLoading ? 'Starting…' : 'Start Scan'}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   DAST SCAN MODAL
───────────────────────────────────────────────────────────────────────────── */
function DastScanModal({ isOpen, onClose, onSubmit, isLoading }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('passive');
  const [authType, setAuthType] = useState('none');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    if (!targetUrl.trim()) { setError('Target URL is required'); return; }
    onSubmit({ target_url: targetUrl, scan_type: scanType, auth_type: authType });
    setTargetUrl('');
    setScanType('passive');
    setAuthType('none');
  };

  if (!isOpen) return null;
  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />
      <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md border rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between p-6 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <h2 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>New DAST Scan</h2>
          <button onClick={onClose} className="p-1 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            <X className="w-5 h-5" style={{ color: 'var(--text-tertiary)' }} />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>Target URL</label>
            <input type="text" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://api.yourdomain.com"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              disabled={isLoading} />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>Scan Type</label>
            <select value={scanType} onChange={(e) => setScanType(e.target.value)}
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              disabled={isLoading}>
              <option value="passive">Passive (safe, read-only)</option>
              <option value="active">Active (full exploit testing)</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>Authentication</label>
            <select value={authType} onChange={(e) => setAuthType(e.target.value)}
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              disabled={isLoading}>
              <option value="none">None</option>
              <option value="bearer">Bearer Token</option>
              <option value="oauth2">OAuth2</option>
              <option value="api_key">API Key</option>
              <option value="basic">Basic Auth</option>
            </select>
          </div>
          {error && (
            <div className="p-3 border rounded-lg bg-red-500/20 border-red-800">
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}
          <div className="flex gap-3 pt-4">
            <button type="button" onClick={onClose} disabled={isLoading}
              className="flex-1 px-4 py-2 rounded-lg font-medium transition-colors"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
              Cancel
            </button>
            <button type="submit" disabled={isLoading}
              className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors">
              {isLoading ? 'Starting…' : 'Start DAST Scan'}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   MINI STAT ROW  (used inside Overview cards)
───────────────────────────────────────────────────────────────────────────── */
function StatRow({ label, value, valueColor }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b last:border-0" style={{ borderColor: 'var(--border-primary)' }}>
      <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <span className="text-sm font-semibold" style={{ color: valueColor || 'var(--text-primary)' }}>{value}</span>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   LANGUAGE BAR CHART  (horizontal bar rows)
───────────────────────────────────────────────────────────────────────────── */
function LangBar({ lang, count, max }) {
  const pct = max ? Math.round((count / max) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-secondary)' }}>
        <span>{lang}</span>
        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{count} scan{count !== 1 ? 's' : ''}</span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: 'var(--accent-primary)' }} />
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   FINDING CATEGORY BADGE
───────────────────────────────────────────────────────────────────────────── */
const CATEGORY_COLORS = {
  secrets:    { bg: 'rgba(239,68,68,0.15)',   text: '#f87171' },
  iac:        { bg: 'rgba(249,115,22,0.15)',  text: '#fb923c' },
  container:  { bg: 'rgba(168,85,247,0.15)', text: '#c084fc' },
  sast:       { bg: 'rgba(59,130,246,0.15)', text: '#60a5fa' },
  dast:       { bg: 'rgba(20,184,166,0.15)', text: '#2dd4bf' },
  sca:        { bg: 'rgba(234,179,8,0.15)',  text: '#facc15' },
};
function CategoryBadge({ type }) {
  const c = CATEGORY_COLORS[type?.toLowerCase()] || { bg: 'var(--bg-tertiary)', text: 'var(--text-secondary)' };
  return (
    <span className="text-xs px-2 py-0.5 rounded-full font-medium uppercase" style={{ backgroundColor: c.bg, color: c.text }}>
      {type}
    </span>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   MAIN PAGE COMPONENT
───────────────────────────────────────────────────────────────────────────── */
export default function SecopsPage() {
  const router = useRouter();
  const { provider, account, filterSummary } = useGlobalFilter();

  /* ── Data state ─────────────────────────────────────────────────────────── */
  const [loadingSast, setLoadingSast]   = useState(true);
  const [loadingDast, setLoadingDast]   = useState(true);
  const [loadingSca,  setLoadingSca]    = useState(true);
  const [sastScans,   setSastScans]     = useState([]);
  const [dastScans,   setDastScans]     = useState([]);
  const [scaScans,    setScaScans]      = useState([]);
  const [errorMsg,    setErrorMsg]      = useState(null);

  /* ── Modal state ────────────────────────────────────────────────────────── */
  const [showSastModal, setShowSastModal] = useState(false);
  const [showDastModal, setShowDastModal] = useState(false);
  const [isSubmitting,  setIsSubmitting]  = useState(false);

  /* ── Fetch all scan types ───────────────────────────────────────────────── */
  useEffect(() => {
    const fetchSast = async () => {
      try {
        const d = await getFromEngine('secops', '/api/v1/secops/scans');
        const list = Array.isArray(d) ? d : (d?.scans ?? []);
        setSastScans(list.length ? list : DEMO_SAST_SCANS);
      } catch { setSastScans(DEMO_SAST_SCANS); }
      finally { setLoadingSast(false); }
    };

    const fetchDast = async () => {
      try {
        const d = await getFromEngine('secops', '/api/v1/secops/dast/scans');
        const list = Array.isArray(d) ? d : (d?.scans ?? []);
        setDastScans(list.length ? list : DEMO_DAST_SCANS);
      } catch { setDastScans(DEMO_DAST_SCANS); }
      finally { setLoadingDast(false); }
    };

    const fetchSca = async () => {
      try {
        const d = await getFromEngine('secops', '/api/v1/secops/sca/scans');
        const list = Array.isArray(d) ? d : (d?.scans ?? []);
        setScaScans(list.length ? list : DEMO_SCA_SCANS);
      } catch { setScaScans(DEMO_SCA_SCANS); }
      finally { setLoadingSca(false); }
    };

    fetchSast();
    fetchDast();
    fetchSca();
  }, []);

  /* ── SAST: submit new scan ──────────────────────────────────────────────── */
  const handleSastSubmit = async (formData) => {
    setIsSubmitting(true);
    try {
      const result = await postToEngine('secops', '/api/v1/secops/scan', formData);
      const newScan = result?.scan_id ? result : {
        scan_id: `secops-${Date.now()}`,
        repo_name: formData.repo_url.split('/').pop().replace('.git', ''),
        repo_url: formData.repo_url,
        branch: formData.branch,
        status: 'running',
        findings_count: 0, critical: 0, high: 0, medium: 0, low: 0,
        started_at: new Date().toISOString(), completed_at: null,
        duration: 'Running…', languages: 'Detecting…', files_scanned: 0,
        iac_findings: 0, secrets_found: 0, container_vulns: 0,
      };
      setSastScans(prev => [newScan, ...prev]);
      setShowSastModal(false);
    } catch { /* silently keep existing list */ }
    finally { setIsSubmitting(false); }
  };

  /* ── DAST: submit new scan ──────────────────────────────────────────────── */
  const handleDastSubmit = async (formData) => {
    setIsSubmitting(true);
    try {
      const result = await postToEngine('secops', '/api/v1/secops/dast/scan', formData);
      const newScan = result?.scan_id ? result : {
        scan_id: `dast-${Date.now()}`,
        target_url: formData.target_url,
        scan_type: formData.scan_type === 'active' ? 'Active' : 'Passive',
        auth_type: formData.auth_type,
        status: 'pending',
        vulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0,
        started_at: new Date().toISOString(), duration: '—', pages_crawled: 0,
      };
      setDastScans(prev => [newScan, ...prev]);
      setShowDastModal(false);
    } catch { /* silently keep existing list */ }
    finally { setIsSubmitting(false); }
  };

  /* ── Scope filtering ────────────────────────────────────────────────────── */
  const filteredSast = useMemo(() => {
    let d = sastScans;
    if (provider) d = d.filter(r => !r.provider || r.provider?.toLowerCase() === provider.toLowerCase());
    if (account)  d = d.filter(r => !r.account || r.account === account);
    return d;
  }, [sastScans, provider, account]);

  const filteredDast = useMemo(() => {
    let d = dastScans;
    if (provider) d = d.filter(r => !r.provider || r.provider?.toLowerCase() === provider.toLowerCase());
    if (account)  d = d.filter(r => !r.account || r.account === account);
    return d;
  }, [dastScans, provider, account]);

  const filteredSca = useMemo(() => {
    let d = scaScans;
    if (provider) d = d.filter(r => !r.provider || r.provider?.toLowerCase() === provider.toLowerCase());
    if (account)  d = d.filter(r => !r.account || r.account === account);
    return d;
  }, [scaScans, provider, account]);

  /* ── Derived aggregate metrics ──────────────────────────────────────────── */
  const totalCritical      = filteredSast.reduce((s, r) => s + (r.critical || 0), 0);
  const totalSecrets       = filteredSast.reduce((s, r) => s + (r.secrets_found || 0), 0);
  const totalIacFindings   = filteredSast.reduce((s, r) => s + (r.iac_findings || 0), 0);
  const totalContainerVuln = filteredSast.reduce((s, r) => s + (r.container_vulns || 0), 0);
  const totalFindings      = filteredSast.reduce((s, r) => s + (r.findings_count || 0), 0);
  const completedSast      = filteredSast.filter(r => r.status === 'completed').length;
  const dastVulns          = filteredDast.reduce((s, r) => s + (r.vulnerabilities || 0), 0);
  const scaVulnPkgs        = filteredSca.reduce((s, r) => s + (r.vulnerable || 0), 0);

  const allLanguages = useMemo(() => {
    const set = new Set();
    filteredSast.forEach(s => (s.languages || '').split(',').forEach(l => { if (l.trim()) set.add(l.trim()); }));
    return set;
  }, [filteredSast]);

  const langStats = useMemo(() => {
    const map = {};
    filteredSast.forEach(s => (s.languages || '').split(',').forEach(l => {
      const t = l.trim(); if (t) map[t] = (map[t] || 0) + 1;
    }));
    return Object.entries(map).sort((a, b) => b[1] - a[1]);
  }, [filteredSast]);

  const lastScanDate = filteredSast.length > 0
    ? new Date(filteredSast[0].started_at).toLocaleDateString()
    : '—';

  /* ── MetricStrip (pinned in Overview) ───────────────────────────────────── */
  const metricStrip = (
    <MetricStrip groups={[
      {
        label: '🔴 CODE RISK',
        color: 'var(--accent-danger)',
        cells: [
          { label: 'CRITICAL SECRETS',    value: totalSecrets,       valueColor: 'var(--severity-critical)', noTrend: true,  context: 'credentials exposed' },
          { label: 'CRITICAL IaC',        value: totalIacFindings,   valueColor: 'var(--severity-high)',     delta: -2,      deltaGoodDown: true, context: 'vs last scan' },
          { label: 'CRITICAL CONTAINERS', value: totalContainerVuln, valueColor: 'var(--severity-critical)', noTrend: true,  context: 'image CVEs' },
        ],
      },
      {
        label: '🔵 SCAN COVERAGE',
        color: 'var(--accent-primary)',
        cells: [
          { label: 'REPOS SCANNED',       value: filteredSast.length,  context: 'repositories' },
          { label: 'LANGUAGES',           value: allLanguages.size,   noTrend: true, context: 'scan technologies' },
          { label: 'LAST SCAN',           value: lastScanDate,        noTrend: true, context: 'most recent' },
        ],
      },
      {
        label: '🟡 DAST & SCA',
        color: 'var(--accent-warning)',
        cells: [
          { label: 'DAST VULNS',          value: dastVulns,    valueColor: dastVulns > 0 ? 'var(--severity-high)' : undefined, noTrend: true, context: 'web app issues' },
          { label: 'VULNERABLE PKGS',     value: scaVulnPkgs,  valueColor: scaVulnPkgs > 0 ? 'var(--severity-high)' : undefined, noTrend: true, context: 'supply chain' },
          { label: 'TOTAL FINDINGS',      value: totalFindings, noTrend: true, context: 'across SAST' },
        ],
      },
    ]} />
  );

  /* ── Overview insight cards ─────────────────────────────────────────────── */
  const maxLang = langStats[0]?.[1] || 1;

  const overviewCards = (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

      {/* Language breakdown */}
      <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center gap-2 mb-4">
          <FileCode2 className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <h3 className="text-sm font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>IaC &amp; Code Languages</h3>
        </div>
        <div className="space-y-3">
          {langStats.length === 0 ? (
            <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>No scan data yet</p>
          ) : (
            langStats.slice(0, 8).map(([lang, cnt]) => (
              <LangBar key={lang} lang={lang} count={cnt} max={maxLang} />
            ))
          )}
        </div>
      </div>

      {/* SAST statistics */}
      <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <h3 className="text-sm font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>SAST Statistics</h3>
        </div>
        <div className="space-y-0.5">
          <StatRow label="Completed Scans"   value={`${completedSast} / ${filteredSast.length}`} />
          <StatRow label="Critical Findings" value={totalCritical}      valueColor="var(--severity-critical)" />
          <StatRow label="Total Findings"    value={totalFindings}      valueColor="var(--severity-high)" />
          <StatRow label="Secrets Exposed"   value={totalSecrets}       valueColor={totalSecrets > 0 ? 'var(--severity-critical)' : undefined} />
          <StatRow label="IaC Issues"        value={totalIacFindings} />
          <StatRow label="Container CVEs"    value={totalContainerVuln} />
          <StatRow label="Avg Files Scanned" value={
            filteredSast.length > 0
              ? Math.round(filteredSast.reduce((s, r) => s + (r.files_scanned || 0), 0) / filteredSast.length)
              : 0
          } />
        </div>
      </div>

      {/* DAST + SCA summary */}
      <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <h3 className="text-sm font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>DAST &amp; Supply Chain</h3>
        </div>
        <p className="text-xs font-medium mb-2 uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>Dynamic Testing</p>
        <div className="space-y-0.5 mb-4">
          <StatRow label="Targets Scanned" value={filteredDast.length} />
          <StatRow label="Vulnerabilities"  value={dastVulns}  valueColor={dastVulns > 0 ? 'var(--severity-high)' : undefined} />
          <StatRow label="Critical"         value={filteredDast.reduce((s, r) => s + (r.critical || 0), 0)} valueColor="var(--severity-critical)" />
        </div>
        <p className="text-xs font-medium mb-2 uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>Software Composition</p>
        <div className="space-y-0.5">
          <StatRow label="Repos Analysed"   value={filteredSca.length} />
          <StatRow label="Vulnerable Pkgs"  value={scaVulnPkgs}   valueColor={scaVulnPkgs > 0 ? 'var(--severity-high)' : undefined} />
          <StatRow label="Outdated Pkgs"    value={filteredSca.reduce((s, r) => s + (r.outdated || 0), 0)} />
          <StatRow label="License Issues"   value={filteredSca.reduce((s, r) => s + (r.license_issues || 0), 0)} />
        </div>
      </div>

    </div>
  );

  /* ── SAST Scans table columns ────────────────────────────────────────────── */
  const sastColumns = [
    {
      accessorKey: 'repo_name',
      header: 'Repository',
      cell: (info) => (
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</p>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{info.row.original.repo_url}</p>
        </div>
      ),
    },
    {
      accessorKey: 'branch',
      header: 'Branch',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'status', header: 'Status', cell: (info) => <StatusIndicator status={info.getValue()} /> },
    {
      accessorKey: 'findings_count', header: 'Total',
      cell: (info) => (
        <span className={`text-sm font-medium ${info.getValue() > 0 ? 'text-orange-400' : 'text-green-400'}`}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'critical', header: 'Critical',
      cell: (info) => info.getValue() > 0
        ? <span className="text-sm font-medium text-red-400">{info.getValue()}</span>
        : <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>—</span>,
    },
    {
      accessorKey: 'high', header: 'High',
      cell: (info) => info.getValue() > 0
        ? <span className="text-sm font-medium text-orange-400">{info.getValue()}</span>
        : <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>—</span>,
    },
    { accessorKey: 'iac_findings', header: 'IaC', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    {
      accessorKey: 'secrets_found', header: 'Secrets',
      cell: (info) => info.getValue() > 0
        ? <span className="text-sm font-medium text-red-400">{info.getValue()}</span>
        : <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>—</span>,
    },
    { accessorKey: 'container_vulns', header: 'Container', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    {
      accessorKey: 'started_at', header: 'Started',
      cell: (info) => {
        const d = new Date(info.getValue());
        return <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{d.toLocaleDateString()} {d.toLocaleTimeString()}</span>;
      },
    },
  ];

  /* ── DAST table columns ──────────────────────────────────────────────────── */
  const dastColumns = [
    {
      accessorKey: 'target_url', header: 'Target',
      cell: (info) => <span className="text-sm font-mono" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'scan_type', header: 'Type',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded font-medium" style={{
          backgroundColor: info.getValue() === 'Active' ? 'rgba(239,68,68,0.15)' : 'rgba(59,130,246,0.15)',
          color: info.getValue() === 'Active' ? '#f87171' : '#60a5fa',
        }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'status', header: 'Status', cell: (info) => <StatusIndicator status={info.getValue()} /> },
    {
      accessorKey: 'vulnerabilities', header: 'Vulns',
      cell: (info) => (
        <span className={`text-sm font-medium ${info.getValue() > 0 ? 'text-orange-400' : 'text-green-400'}`}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'critical', header: 'Critical',
      cell: (info) => info.getValue() > 0
        ? <span className="text-sm font-medium text-red-400">{info.getValue()}</span>
        : <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>—</span>,
    },
    { accessorKey: 'auth_type', header: 'Auth', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'pages_crawled', header: 'Pages', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'duration', header: 'Duration', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
    {
      accessorKey: 'started_at', header: 'Started',
      cell: (info) => {
        const d = new Date(info.getValue());
        return <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{d.toLocaleDateString()} {d.toLocaleTimeString()}</span>;
      },
    },
  ];

  /* ── SCA / SBOM table columns ────────────────────────────────────────────── */
  const scaColumns = [
    { accessorKey: 'repo_name', header: 'Repository', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    {
      accessorKey: 'package_manager', header: 'Package Manager',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'status', header: 'Status', cell: (info) => <StatusIndicator status={info.getValue()} /> },
    { accessorKey: 'total_packages', header: 'Total Pkgs', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    {
      accessorKey: 'vulnerable', header: 'Vulnerable',
      cell: (info) => (
        <span className={`text-sm font-medium ${info.getValue() > 0 ? 'text-orange-400' : 'text-green-400'}`}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'critical', header: 'Critical',
      cell: (info) => info.getValue() > 0
        ? <span className="text-sm font-medium text-red-400">{info.getValue()}</span>
        : <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>—</span>,
    },
    {
      accessorKey: 'outdated', header: 'Outdated',
      cell: (info) => (
        <span className={`text-sm ${info.getValue() > 0 ? 'text-yellow-400' : ''}`} style={{ color: info.getValue() > 0 ? undefined : 'var(--text-tertiary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'license_issues', header: 'License Issues',
      cell: (info) => info.getValue() > 0
        ? <span className="text-sm font-medium text-yellow-400">{info.getValue()}</span>
        : <span className="text-sm text-green-400">Clean</span>,
    },
    {
      accessorKey: 'scanned_at', header: 'Scanned',
      cell: (info) => {
        const d = new Date(info.getValue());
        return <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{d.toLocaleDateString()}</span>;
      },
    },
  ];

  /* ── Page context ────────────────────────────────────────────────────────── */
  const pageContext = useMemo(() => ({
    title: 'Code Security',
    brief: 'IaC · SAST · DAST · SCA · Container · Secrets scanning',
    tabs: [
      { id: 'overview',   label: 'Overview'  },
      { id: 'sast',       label: 'SAST Scans' },
      { id: 'dast',       label: 'DAST'       },
      { id: 'sca',        label: 'SBOM / SCA' },
    ],
  }), []);

  /* ── Tab action buttons ──────────────────────────────────────────────────── */
  const sastAction = (
    <button onClick={() => setShowSastModal(true)}
      className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium text-sm transition-colors">
      <Plus className="w-4 h-4" /> Scan Repository
    </button>
  );

  const dastAction = (
    <button onClick={() => setShowDastModal(true)}
      className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded-lg font-medium text-sm transition-colors">
      <Plus className="w-4 h-4" /> New DAST Scan
    </button>
  );

  /* ── tabData ─────────────────────────────────────────────────────────────── */
  const tabData = {
    overview: {
      renderTab: () => (
        <>
          {metricStrip}
          <div className="mt-6">{overviewCards}</div>
        </>
      ),
    },

    sast: {
      renderTab: () => (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>SAST Scan History</h2>
              <p className="text-sm mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                Click a scan to view detailed findings and remediation guidance
              </p>
            </div>
            {sastAction}
          </div>
          <DataTable
            data={filteredSast}
            columns={sastColumns}
            pageSize={10}
            onRowClick={(scan) => router.push(`/secops/${scan.scan_id}`)}
            loading={loadingSast}
            emptyMessage="No SAST scans found. Click 'Scan Repository' to start."
          />
        </div>
      ),
    },

    dast: {
      renderTab: () => (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>DAST Scan History</h2>
              <p className="text-sm mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                Dynamic application security testing against live endpoints
              </p>
            </div>
            {dastAction}
          </div>
          <DataTable
            data={filteredDast}
            columns={dastColumns}
            pageSize={10}
            loading={loadingDast}
            emptyMessage="No DAST scans found. Click 'New DAST Scan' to start."
          />
        </div>
      ),
    },

    sca: {
      renderTab: () => (
        <div className="space-y-4">
          <div>
            <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Software Bill of Materials &amp; SCA</h2>
            <p className="text-sm mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Dependency vulnerability analysis and open-source license compliance
            </p>
          </div>
          <DataTable
            data={filteredSca}
            columns={scaColumns}
            pageSize={10}
            loading={loadingSca}
            emptyMessage="No SCA scans found."
          />
        </div>
      ),
    },
  };

  /* ── Render ──────────────────────────────────────────────────────────────── */
  return (
    <>
      <PageLayout
        icon={Code2}
        pageContext={pageContext}
        tabData={tabData}
        defaultTab="overview"
        topNav
        loading={false}
        error={null}
      />

      <ScanRepositoryModal
        isOpen={showSastModal}
        onClose={() => setShowSastModal(false)}
        onSubmit={handleSastSubmit}
        isLoading={isSubmitting}
      />

      <DastScanModal
        isOpen={showDastModal}
        onClose={() => setShowDastModal(false)}
        onSubmit={handleDastSubmit}
        isLoading={isSubmitting}
      />
    </>
  );
}
