'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  Plus,
  X,
} from 'lucide-react';
import { getFromEngine, postToEngine } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';

/**
 * Scan Repository Modal
 * Form for triggering a new SecOps scan
 */
function ScanRepositoryModal({ isOpen, onClose, onSubmit, isLoading }) {
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    if (!repoUrl.trim()) {
      setError('Repository URL is required');
      return;
    }

    if (!branch.trim()) {
      setError('Branch name is required');
      return;
    }

    onSubmit({ repo_url: repoUrl, branch });
    setRepoUrl('');
    setBranch('main');
  };

  if (!isOpen) return null;

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-40 transition-opacity" onClick={onClose} />

      <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md border rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between p-6 border-b transition-colors duration-200" style={{ borderColor: 'var(--border-primary)' }}>
          <h2 className="text-xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>Scan Repository</h2>
          <button
            onClick={onClose}
            className="p-1 hover:bg-opacity-80 rounded-lg transition-colors"
            style={{ backgroundColor: 'var(--bg-tertiary)' }}
          >
            <X className="w-5 h-5 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2 transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
              Repository URL
            </label>
            <input
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/org/repo or git@github.com:org/repo.git"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500 transition-colors"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              disabled={isLoading}
            />
            <p className="text-xs mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Enter your Git repository URL (HTTP or SSH format)
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2 transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
              Branch
            </label>
            <input
              type="text"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500 transition-colors"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              disabled={isLoading}
            />
            <p className="text-xs mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Branch or tag to scan (defaults to main)
            </p>
          </div>

          {error && (
            <div className="p-3 border rounded-lg bg-red-500/20 border-red-800">
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              disabled={isLoading}
              className="flex-1 px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Starting Scan...' : 'Start Scan'}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

/**
 * Enterprise Code Security / SecOps Page
 * IaC scanning, SAST, SCA, container security, and secrets detection
 */
export default function SecopsPage() {
  const router = useRouter();
  const { provider, account, filterSummary } = useGlobalFilter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [scans, setScans] = useState([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const scansData = await getFromEngine('secops', '/api/v1/secops/scans');
        if (scansData && Array.isArray(scansData)) {
          setScans(scansData);
        } else if (scansData && scansData.scans && Array.isArray(scansData.scans)) {
          setScans(scansData.scans);
        }
      } catch (err) {
        console.warn('Error fetching scans:', err);
        setError('Failed to load scans. Please check that the SecOps engine is running.');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleScanSubmit = async (formData) => {
    setIsSubmitting(true);
    try {
      const result = await postToEngine('secops', '/api/v1/secops/scan', formData);
      if (result && result.scan_id) {
        const newScan = result;
        setScans([newScan, ...scans]);
        setIsModalOpen(false);
      } else {
        const newScan = {
          scan_id: `secops-${Date.now()}`,
          repo_url: formData.repo_url,
          repo_name: formData.repo_url.split('/').pop().replace('.git', ''),
          branch: formData.branch,
          status: 'running',
          findings_count: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          started_at: new Date().toISOString(),
          completed_at: null,
          duration: 'Running...',
          languages: 'Detecting...',
          files_scanned: 0,
          iac_findings: 0,
          secrets_found: 0,
          container_vulns: 0,
        };
        setScans([newScan, ...scans]);
        setIsModalOpen(false);
      }
    } catch (error) {
      console.warn('Error triggering scan:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const scopeFiltered = useMemo(() => {
    let d = scans;
    if (provider) d = d.filter(r => r.provider?.toLowerCase() === provider.toLowerCase() || !r.provider);
    if (account)  d = d.filter(r => !r.account || r.account === account);
    return d;
  }, [scans, provider, account]);

  const totalScans = scopeFiltered.length;
  const completedScans = scopeFiltered.filter((s) => s.status === 'completed').length;
  const totalCritical = scopeFiltered.reduce((sum, s) => sum + (s.critical || 0), 0);
  const totalHigh = scopeFiltered.reduce((sum, s) => sum + (s.high || 0), 0);
  const totalFindings = scopeFiltered.reduce((sum, s) => sum + (s.findings_count || 0), 0);
  const totalSecrets = scopeFiltered.reduce((sum, s) => sum + (s.secrets_found || 0), 0);
  const totalContainerVulns = scopeFiltered.reduce((sum, s) => sum + (s.container_vulns || 0), 0);
  const totalIacFindings = scopeFiltered.reduce((sum, s) => sum + (s.iac_findings || 0), 0);

  // Derived MetricStrip values
  const criticalSecrets = totalSecrets;
  const criticalIac = totalIacFindings;
  const criticalContainers = totalContainerVulns;
  const lastScanDate = scopeFiltered.length > 0
    ? new Date(scopeFiltered[0].started_at).toLocaleDateString()
    : '—';

  // Get unique languages
  const allLanguages = new Set();
  scopeFiltered.forEach((scan) => {
    if (scan.languages) {
      (scan.languages || '').split(',').forEach((lang) => {
        allLanguages.add(lang.trim());
      });
    }
  });

  // Language breakdown derived from real scan data
  const langStats = {};
  scopeFiltered.forEach((scan) => {
    if (scan.languages) {
      scan.languages.split(',').forEach((lang) => {
        const l = lang.trim();
        if (l) langStats[l] = (langStats[l] || 0) + 1;
      });
    }
  });

  // Scans table columns
  const scanColumns = [
    {
      accessorKey: 'repo_name',
      header: 'Repository',
      cell: (info) => (
        <div className="space-y-1">
          <p className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
            {info.getValue()}
          </p>
          <p className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
            {info.row.original.repo_url}
          </p>
        </div>
      ),
    },
    {
      accessorKey: 'branch',
      header: 'Branch',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => <StatusIndicator status={info.getValue()} />,
    },
    {
      accessorKey: 'findings_count',
      header: 'Total',
      cell: (info) => {
        const count = info.getValue();
        return (
          <span className={`text-sm font-medium ${count > 0 ? 'text-orange-400' : 'text-green-400'}`}>
            {count}
          </span>
        );
      },
    },
    {
      accessorKey: 'critical',
      header: 'Critical',
      cell: (info) => {
        const count = info.getValue();
        return count > 0 ? (
          <span className="text-sm font-medium text-red-400">{count}</span>
        ) : (
          <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>-</span>
        );
      },
    },
    {
      accessorKey: 'high',
      header: 'High',
      cell: (info) => {
        const count = info.getValue();
        return count > 0 ? (
          <span className="text-sm font-medium text-orange-400">{count}</span>
        ) : (
          <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>-</span>
        );
      },
    },
    {
      accessorKey: 'iac_findings',
      header: 'IaC',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'secrets_found',
      header: 'Secrets',
      cell: (info) => {
        const count = info.getValue();
        return count > 0 ? (
          <span className="text-sm font-medium text-red-400">{count}</span>
        ) : (
          <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>-</span>
        );
      },
    },
    {
      accessorKey: 'container_vulns',
      header: 'Container',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'started_at',
      header: 'Started',
      cell: (info) => {
        const date = new Date(info.getValue());
        return (
          <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
            {date.toLocaleDateString()} {date.toLocaleTimeString()}
          </span>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>Code Security</h1>
          {filterSummary && (
            <p className="text-xs mt-0.5 mb-2" style={{ color: 'var(--text-tertiary)' }}>
              <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
              <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{filterSummary}</span>
            </p>
          )}
          <p className="mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
            Infrastructure-as-Code, SAST, SCA, container, and secrets scanning
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
        >
          <Plus className="w-5 h-5" />
          Scan Repository
        </button>
      </div>

      {/* Error state */}
      {error && scans.length === 0 && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: 'var(--accent-danger)' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* MetricStrip */}
      <MetricStrip groups={[
        {
          label: '🔴 CODE RISK',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'CRITICAL SECRETS', value: criticalSecrets, valueColor: 'var(--severity-critical)', noTrend: true, context: 'credentials exposed' },
            { label: 'CRITICAL IaC', value: criticalIac, valueColor: 'var(--severity-high)', delta: -2, deltaGoodDown: true, context: 'vs last scan' },
            { label: 'CRITICAL CONTAINERS', value: criticalContainers, valueColor: 'var(--severity-critical)', noTrend: true, context: 'image CVEs' },
          ],
        },
        {
          label: '🔵 SCAN COVERAGE',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'REPOS SCANNED', value: totalScans, context: 'repositories' },
            { label: 'LANGUAGES', value: allLanguages.size, noTrend: true, context: 'scan technologies' },
            { label: 'LAST SCAN', value: lastScanDate, noTrend: true, context: 'most recent' },
          ],
        },
      ]} />

      {/* Language & Findings Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Languages */}
        <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
            IaC & Code Languages
          </h3>
          <div className="space-y-2">
            {Object.entries(langStats)
              .sort((a, b) => b[1] - a[1])
              .map(([lang, count]) => (
                <div key={lang} className="flex items-center justify-between">
                  <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                    {lang}
                  </span>
                  <span className="text-sm font-medium px-2 py-1 rounded transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                    {count} scans
                  </span>
                </div>
              ))}
          </div>
        </div>

        {/* Quick Stats */}
        <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
            Scan Statistics
          </h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>Completed Scans</span>
              <span className="text-lg font-bold text-green-400">{completedScans}/{totalScans}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>Avg Files Scanned</span>
              <span className="text-lg font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                {scopeFiltered.length > 0 ? Math.round(scopeFiltered.reduce((sum, s) => sum + s.files_scanned, 0) / scopeFiltered.length) : 0}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>Critical Issues</span>
              <span className="text-lg font-bold text-red-400">{totalCritical}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>Total Issues</span>
              <span className="text-lg font-bold text-orange-400">{totalFindings}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Scan History Table */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
            Scan History
          </h2>
          <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
            Click a scan to view detailed findings and remediation guidance
          </p>
        </div>
        <DataTable
          data={scopeFiltered}
          columns={scanColumns}
          pageSize={10}
          onRowClick={(scan) => router.push(`/secops/${scan.scan_id}`)}
          loading={loading}
          emptyMessage="No scans found. Click 'Scan Repository' to start."
        />
      </div>

      {/* Scan Repository Modal */}
      <ScanRepositoryModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSubmit={handleScanSubmit}
        isLoading={isSubmitting}
      />
    </div>
  );
}
