'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Code,
  AlertTriangle,
  FileText,
  CheckCircle,
  Copy,
  Terminal,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import SeverityDonut from '@/components/charts/SeverityDonut';
import StatusIndicator from '@/components/shared/StatusIndicator';

/**
 * SecOps Scan Detail Page
 * Displays comprehensive findings for a specific code security scan
 */
export default function SecopsScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.scanId;

  const [loading, setLoading] = useState(true);
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState(null);
  const [activeLanguageTab, setActiveLanguageTab] = useState('all');
  const [expandedFinding, setExpandedFinding] = useState(null);

  useEffect(() => {
    const fetchScanData = async () => {
      setError(null);
      try {
        // Fetch scan status/details
        const scanData = await getFromEngine('secops', `/api/v1/secops/scan/${scanId}/status`);
        if (scanData && !scanData.error) {
          setScan(scanData);
        } else {
          setError(scanData?.error || 'Failed to load scan details');
        }

        // Fetch findings
        const findingsData = await getFromEngine('secops', `/api/v1/secops/scan/${scanId}/findings`);
        if (findingsData && Array.isArray(findingsData)) {
          setFindings(findingsData);
        } else if (findingsData && Array.isArray(findingsData.findings)) {
          setFindings(findingsData.findings);
        }
        // If no findings returned, keep empty array
      } catch (err) {
        setError(err?.message || 'Failed to load scan data');
      } finally {
        setLoading(false);
      }
    };

    if (scanId) {
      fetchScanData();
    }
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <p className="transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>Loading scan details...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--accent-danger)' }}>
        <p className="text-sm font-medium" style={{ color: 'var(--accent-danger)' }}>Error: {error}</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No data available</p>
      </div>
    );
  }

  // Get unique languages
  const languages = ['all', ...new Set(findings.map((f) => f.language).filter(Boolean))];

  // Filter findings by language
  const filteredFindings =
    activeLanguageTab === 'all'
      ? findings
      : findings.filter((f) => f.language === activeLanguageTab);

  // Calculate severity distribution
  const severityDistribution = [
    { name: 'Critical', value: scan.critical, color: '#ef4444' },
    { name: 'High', value: scan.high, color: '#f97316' },
    { name: 'Medium', value: scan.medium, color: '#eab308' },
    { name: 'Low', value: scan.low, color: '#3b82f6' },
  ];

  // Category statistics
  const categoryStats = {};
  findings.forEach((finding) => {
    if (!categoryStats[finding.category]) {
      categoryStats[finding.category] = { count: 0, critical: 0, high: 0 };
    }
    categoryStats[finding.category].count++;
    if (finding.severity === 'critical') categoryStats[finding.category].critical++;
    if (finding.severity === 'high') categoryStats[finding.category].high++;
  });

  // Findings table columns
  const findingsColumns = [
    {
      accessorKey: 'file_path',
      header: 'File',
      cell: (info) => {
        const path = info.getValue();
        const fileName = path.split('/').pop();
        return (
          <div className="space-y-1">
            <p className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              {fileName}
            </p>
            <p className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              {path}
            </p>
          </div>
        );
      },
    },
    {
      accessorKey: 'line_number',
      header: 'Line',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
          :{info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'category',
      header: 'Category',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'title',
      header: 'Issue',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'language',
      header: 'Language',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded bg-purple-500/20 text-purple-300">
          {info.getValue()}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Back Button & Header */}
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <button
            onClick={() => router.back()}
            className="flex items-center gap-2 text-blue-400 hover:text-blue-300 transition-colors mb-3"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Scans
          </button>
          <div>
            <h1 className="text-3xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              {scan.repo_name}
            </h1>
            <p className="mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              {scan.repo_url} · Branch: <code>{scan.branch}</code>
            </p>
          </div>
        </div>
        <div className="text-right">
          <StatusIndicator status={scan.status} />
          <p className="text-xs mt-2 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
            {scan.started_at ? new Date(scan.started_at).toLocaleDateString() : 'N/A'}{' '}
            {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : 'N/A'}
          </p>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Findings"
          value={scan.total_findings}
          subtitle="Issues discovered"
          icon={<AlertTriangle className="w-5 h-5" />}
          color="orange"
        />
        <KpiCard
          title="Critical"
          value={scan.critical}
          subtitle="Require immediate action"
          icon={<AlertTriangle className="w-5 h-5" />}
          color="red"
        />
        <KpiCard
          title="High"
          value={scan.high}
          subtitle="Important findings"
          icon={<AlertTriangle className="w-5 h-5" />}
          color="orange"
        />
        <KpiCard
          title="Files Scanned"
          value={scan.files_scanned}
          subtitle="Source and config files"
          icon={<FileText className="w-5 h-5" />}
          color="blue"
        />
      </div>

      {/* Severity Distribution & Category Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
            Severity Distribution
          </h3>
          <div className="flex justify-center">
            <SeverityDonut data={severityDistribution} title="Findings" />
          </div>
        </div>

        {/* Category Breakdown */}
        <div className="lg:col-span-2 rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
            By Category
          </h3>
          <div className="space-y-3">
            {Object.entries(categoryStats)
              .sort((a, b) => b[1].count - a[1].count)
              .map(([category, stats]) => (
                <div key={category} className="flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1">
                    <Code className="w-4 h-4 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }} />
                    <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                      {category}
                    </span>
                  </div>
                  <div className="flex items-center gap-4">
                    {stats.critical > 0 && <span className="text-sm text-red-400">{stats.critical} critical</span>}
                    {stats.high > 0 && <span className="text-sm text-orange-400">{stats.high} high</span>}
                    <span className="text-sm font-medium w-12 text-right transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                      {stats.count} total
                    </span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      </div>

      {/* Language Tabs */}
      <div className="border-b transition-colors duration-200" style={{ borderColor: 'var(--border-primary)' }}>
        <div className="flex gap-1 overflow-x-auto">
          {languages.map((language) => {
            const count =
              language === 'all'
                ? findings.length
                : findings.filter((f) => f.language === language).length;
            return (
              <button
                key={language}
                onClick={() => setActiveLanguageTab(language)}
                className={`px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors border-b-2 ${
                  activeLanguageTab === language
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent transition-colors duration-200 hover:opacity-80'
                }`}
                style={activeLanguageTab !== language ? { color: 'var(--text-tertiary)' } : {}}
              >
                {language === 'all' ? `All Languages (${count})` : `${language} (${count})`}
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings Table */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
            Findings {activeLanguageTab !== 'all' && `· ${activeLanguageTab}`}
          </h2>
          <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
            Click a finding to view details and remediation guidance
          </p>
        </div>
        <DataTable
          data={filteredFindings}
          columns={findingsColumns}
          pageSize={10}
          onRowClick={(finding) => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)}
          loading={loading}
          emptyMessage={
            activeLanguageTab === 'all'
              ? 'No findings in this scan'
              : `No findings for ${activeLanguageTab}`
          }
        />
      </div>

      {/* Expanded Finding Details */}
      {expandedFinding && (
        <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {(() => {
            const finding = findings.find(f => f.id === expandedFinding);
            if (!finding) return null;

            return (
              <div className="space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                      {finding.title}
                    </h3>
                    <p className="text-sm mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                      Rule: {finding.rule_id}
                    </p>
                  </div>
                  <SeverityBadge severity={finding.severity} />
                </div>

                <div>
                  <h4 className="text-sm font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                    Description
                  </h4>
                  <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                    {finding.description}
                  </p>
                </div>

                <div>
                  <h4 className="text-sm font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                    Remediation
                  </h4>
                  <div className="p-3 rounded-lg border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                    <div className="flex items-start gap-2">
                      <Terminal className="w-4 h-4 flex-shrink-0 mt-1" style={{ color: 'var(--accent-success)' }} />
                      <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                        {finding.remediation}
                      </p>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                    Location
                  </h4>
                  <div className="p-3 rounded-lg border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                    <code className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                      {finding.file_path}:{finding.line_number}
                    </code>
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Rule Library Summary */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
          Scan Summary
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-lg border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}>
            <p className="text-sm mb-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>Unique Rules Triggered</p>
            <p className="text-2xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              {new Set(findings.map((f) => f.rule_id).filter(Boolean)).size}
            </p>
          </div>
          <div className="p-4 rounded-lg border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}>
            <p className="text-sm mb-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>Languages Detected</p>
            <p className="text-2xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              {languages.length - 1}
            </p>
          </div>
          <div className="p-4 rounded-lg border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}>
            <p className="text-sm mb-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>Categories Found</p>
            <p className="text-2xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              {Object.keys(categoryStats).length}
            </p>
          </div>
          <div className="p-4 rounded-lg border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}>
            <p className="text-sm mb-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>Scan Duration</p>
            <p className="text-2xl font-bold text-blue-400">{scan.duration}</p>
          </div>
        </div>
      </div>

      {/* Next Steps */}
      <div className="border rounded-xl p-6 bg-blue-950/30 border-blue-800">
        <div className="flex gap-4">
          <CheckCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-1" />
          <div>
            <h3 className="text-sm font-semibold text-blue-300 mb-2">Remediation Next Steps</h3>
            <ul className="text-sm text-blue-200 space-y-1">
              <li>1. Review critical and high-severity findings first (highest risk)</li>
              <li>2. Click on findings to view detailed remediation guidance and code examples</li>
              <li>3. Update your Infrastructure-as-Code, Dockerfiles, and source code to fix issues</li>
              <li>4. Commit fixes and push to your repository</li>
              <li>5. Re-scan the repository after applying fixes to verify resolution</li>
              <li>6. Integrate this scan into your CI/CD pipeline for continuous security</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
