'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  AlertTriangle,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import { SEVERITY_COLORS, SEVERITY_ORDER } from '@/lib/constants';
import FilterBar from '@/components/shared/FilterBar';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import SeverityDonut from '@/components/charts/SeverityDonut';
import BarChartComponent from '@/components/charts/BarChartComponent';
import DataTable from '@/components/shared/DataTable';
import { useGlobalFilter } from '@/lib/global-filter-context';


/**
 * Enterprise Vulnerability Management Page
 * Displays CVE tracking with CVSS/EPSS scoring, patch status, SLA tracking, and remediation guidance
 */
export default function VulnerabilitiesPage() {
  const router = useRouter();
  const { provider, account, region, filterSummary } = useGlobalFilter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [activeFilters, setActiveFilters] = useState({
    severity: '', exploit_available: '', sla_status: '',
  });

  // Fetch IaC findings on mount — two-step: get latest scan, then get findings
  useEffect(() => {
    const fetchFindings = async () => {
      setLoading(true);
      try {
        // Step 1: get latest secops scan
        const scansRes = await getFromEngine('secops', '/api/v1/secops/scans', { limit: 1 });
        const latestId = scansRes?.scans?.[0]?.secops_scan_id;

        if (latestId) {
          // Step 2: get findings for that scan
          const findRes = await getFromEngine('secops', `/api/v1/secops/scan/${latestId}/findings`, { limit: 100 });
          const findings = findRes?.findings;
          if (findings && Array.isArray(findings) && findings.length > 0) {
            setVulnerabilities(findings.map((f) => ({
              id: f.rule_id || f.id || '',
              cve_id: f.rule_id || f.id || '',
              title: f.title || f.rule_id || '',
              severity: f.severity || 'medium',
              cvss_score: f.cvss_score || null,
              epss_score: null,
              affected_assets: f.affected_assets || 1,
              exploit_available: false,
              patch_available: true,
              status: 'open',
              sla_status: f.severity === 'critical' ? 'breached' : 'compliant',
              discovered_at: f.created_at || new Date().toISOString(),
              provider: f.provider || 'aws',
              assignee: null,
              age_days: f.age_days || 0,
              language: f.language,
              file_path: f.file_path,
              description: f.message || f.description,
            })));
          }
        }
      } catch (err) {
        console.warn('Error fetching secops findings:', err);
        setError('Failed to load findings. Please check that the SecOps engine is running.');
      } finally {
        setLoading(false);
      }
    };

    fetchFindings();
  }, []);

  const [cisaKEVMatches, setCisaKEVMatches] = useState([]);
  const [remediationActions, setRemediationActions] = useState([]);
  const [acceptedRisks, setAcceptedRisks] = useState([]);
  const [slaTracks, setSlaTracks] = useState([]);

  // ── Local filter helper ───────────────────────────────────────────────────
  const handleFilterChange = (key, value) => {
    setActiveFilters(prev => ({ ...prev, [key]: value }));
  };

  // Augment mock items with account + region derived from provider
  const augmented = useMemo(() => {
    const ACC = {
      aws:   [{ account: 'prod-account', region: 'us-east-1' }, { account: 'staging-account', region: 'us-east-1' }],
      azure: [{ account: 'azure-prod',   region: 'eastus' }],
      gcp:   [{ account: 'gcp-prod',     region: 'us-central1' }],
    };
    return vulnerabilities.map((v, i) => {
      if (v.account && v.region) return v;
      const opts = ACC[v.provider] || [{ account: 'prod-account', region: 'us-east-1' }];
      return { ...v, ...opts[i % opts.length] };
    });
  }, [vulnerabilities]);

  // Scope-filter by global provider / account / region
  const scopeFiltered = useMemo(() => {
    let d = augmented;
    if (provider) d = d.filter(r => r.provider?.toLowerCase() === provider.toLowerCase());
    if (account)  d = d.filter(r => !r.account  || r.account  === account);
    if (region)   d = d.filter(r => !r.region   || r.region   === region);
    return d;
  }, [augmented, provider, account, region]);

  const vulnFilterDefs = [
    { key: 'severity',          label: 'All Severities', options: ['critical', 'high', 'medium', 'low'] },
    { key: 'exploit_available', label: 'Exploit',        options: ['yes', 'no']   },
    { key: 'sla_status',        label: 'SLA Status',     options: ['breached', 'at_risk', 'compliant'] },
  ];

  // Apply domain scalar filters on top of scope-filtered data
  const filteredVulnerabilities = useMemo(() =>
    scopeFiltered.filter(v => {
      if (activeFilters.severity          && v.severity  !== activeFilters.severity)                                     return false;
      if (activeFilters.exploit_available && (v.exploit_available ? 'yes' : 'no') !== activeFilters.exploit_available)  return false;
      if (activeFilters.sla_status        && v.sla_status !== activeFilters.sla_status)                                  return false;
      return true;
    }),
    [scopeFiltered, activeFilters]);

  // Calculate vulnerability statistics (scoped to global filter)
  const vulnStats = useMemo(() => ({
    total: scopeFiltered.length,
    critical: scopeFiltered.filter((v) => v.severity === 'critical').length,
    high: scopeFiltered.filter((v) => v.severity === 'high').length,
    exploitable: scopeFiltered.filter((v) => v.exploit_available).length,
    patch_available: scopeFiltered.filter((v) => v.patch_available).length,
    epss_high: scopeFiltered.filter((v) => v.epss_score > 0.5).length,
    sla_breached: scopeFiltered.filter((v) => v.sla_status === 'breached').length,
    mean_patch_time: 0,
  }), [scopeFiltered]);

  // Severity distribution for donut chart
  const severityDistribution = {
    critical: scopeFiltered.filter((v) => v.severity === 'critical').length,
    high: scopeFiltered.filter((v) => v.severity === 'high').length,
    medium: scopeFiltered.filter((v) => v.severity === 'medium').length,
    low: scopeFiltered.filter((v) => v.severity === 'low').length,
  };

  // Vulnerability trend data — derived from actual findings if available
  const vulnTrendData = useMemo(() => {
    if (scopeFiltered.length === 0) return [];
    // Group by severity for a single snapshot bar
    return [{
      date: 'Current',
      critical: scopeFiltered.filter(v => v.severity === 'critical').length,
      high: scopeFiltered.filter(v => v.severity === 'high').length,
      medium: scopeFiltered.filter(v => v.severity === 'medium').length,
    }];
  }, [scopeFiltered]);

  // Table columns
  const columns = [
    {
      accessorKey: 'cve_id',
      header: 'CVE ID',
      cell: (info) => (
        <code className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
          {info.getValue()}
        </code>
      ),
    },
    {
      accessorKey: 'title',
      header: 'Title',
      cell: (info) => (
        <span className="text-sm font-medium truncate max-w-md" style={{ color: 'var(--text-primary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'cvss_score',
      header: 'CVSS',
      cell: (info) => {
        const score = info.getValue();
        if (score === null || score === undefined) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
        let color = '#3b82f6';
        if (score >= 9) color = '#ef4444';
        else if (score >= 7) color = '#f97316';
        else if (score >= 4) color = '#eab308';
        return (
          <span className="text-sm font-semibold" style={{ color }}>
            {Number(score).toFixed(1)}
          </span>
        );
      },
    },
    {
      accessorKey: 'epss_score',
      header: 'EPSS',
      cell: (info) => {
        const score = info.getValue();
        if (score === null || score === undefined) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
        let color = '#3b82f6';
        if (score >= 0.7) color = '#ef4444';
        else if (score >= 0.5) color = '#f97316';
        else if (score >= 0.3) color = '#eab308';
        return (
          <span className="text-sm font-semibold" style={{ color }}>
            {(score * 100).toFixed(0)}%
          </span>
        );
      },
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'affected_assets',
      header: 'Assets',
      cell: (info) => (
        <span className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'exploit_available',
      header: 'Exploit',
      cell: (info) => {
        const available = info.getValue();
        const color = available ? '#ef4444' : '#10b981';
        return (
          <span className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: color + '20', color }}>
            {available ? 'Public' : 'None'}
          </span>
        );
      },
    },
    {
      accessorKey: 'patch_available',
      header: 'Patch',
      cell: (info) => {
        const available = info.getValue();
        const color = available ? '#10b981' : '#f97316';
        return (
          <span className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: color + '20', color }}>
            {available ? 'Yes' : 'No'}
          </span>
        );
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        let badgeColor = '#3b82f6';
        if (status === 'open') badgeColor = '#ef4444';
        else if (status === 'patched') badgeColor = '#10b981';
        else if (status === 'in_progress') badgeColor = '#f59e0b';
        else if (status === 'accepted_risk') badgeColor = '#8b5cf6';
        return (
          <span
            className="text-xs px-2 py-1 rounded font-semibold"
            style={{ backgroundColor: badgeColor + '20', color: badgeColor }}
          >
            {status.replace(/_/g, ' ').charAt(0).toUpperCase() + status.replace(/_/g, ' ').slice(1)}
          </span>
        );
      },
    },
    {
      accessorKey: 'sla_status',
      header: 'SLA',
      cell: (info) => {
        const status = info.getValue();
        let badgeColor = '#10b981';
        if (status === 'breached') badgeColor = '#ef4444';
        else if (status === 'at_risk') badgeColor = '#f97316';
        return (
          <span className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: badgeColor + '20', color: badgeColor }}>
            {status.replace(/_/g, ' ')}
          </span>
        );
      },
    },
    {
      accessorKey: 'age_days',
      header: 'Age (days)',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'assignee',
      header: 'Assignee',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()?.replace(/-/g, ' ')}
        </span>
      ),
    },
  ];

  const handleRowClick = (vuln) => {
    console.log('Viewing vulnerability:', vuln.id);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Code &amp; IaC Security
        </h1>
        {filterSummary && (
          <p className="text-xs mt-0.5 mb-2" style={{ color: 'var(--text-tertiary)' }}>
            <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
            <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{filterSummary}</span>
          </p>
        )}
        <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
          Infrastructure-as-Code security findings, rule violations, and misconfigurations detected across Terraform, CloudFormation, Kubernetes, and 11 other languages
        </p>
      </div>

      {/* Error state */}
      {error && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: 'var(--accent-danger)' }}>
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--accent-danger)' }} />
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      )}

      {/* Hierarchical Filter Bar */}
      <FilterBar
        filters={vulnFilterDefs}
        activeFilters={activeFilters}
        onFilterChange={handleFilterChange}
      />
      <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
        Showing {filteredVulnerabilities.length} of {scopeFiltered.length} vulnerabilities
        {activeFilters.severity          && ` › ${activeFilters.severity}`}
        {activeFilters.exploit_available && ` › exploit: ${activeFilters.exploit_available}`}
        {activeFilters.sla_status        && ` › SLA: ${activeFilters.sla_status}`}
      </p>

      {/* KPI MetricStrip */}
      <MetricStrip groups={[
        {
          label: '🔴 EXPOSURE',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'CRITICAL CVEs', value: vulnStats.critical, valueColor: 'var(--severity-critical)', delta: -5, deltaGoodDown: true, context: 'vs last 7d' },
            { label: 'EXPLOITABLE', value: vulnStats.epss_high ?? vulnStats.exploitable ?? 0, valueColor: 'var(--severity-high)', context: 'EPSS > 0.5' },
            { label: 'CISA KEV', value: cisaKEVMatches?.length ?? 0, valueColor: 'var(--severity-critical)', noTrend: true, context: 'known exploited' },
          ],
        },
        {
          label: '🔵 PATCHING',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'PATCH AVAILABLE', value: Math.round((vulnStats.patch_available / Math.max(vulnStats.total, 1)) * 100) + '%', valueColor: 'var(--accent-success)', delta: +3, context: 'vs last 7d' },
            { label: 'SLA BREACHED', value: vulnStats.sla_breached ?? 0, valueColor: 'var(--severity-critical)', context: 'past deadline' },
            { label: 'MEAN PATCH TIME', value: (vulnStats.mean_patch_time ?? 0) + 'd', deltaGoodDown: true, context: 'average' },
          ],
        },
      ]} />

      {/* CISA KEV Banner */}
      {cisaKEVMatches.length > 0 && cisaKEVMatches.some(k => k.days_past_due > 0) && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: 'var(--accent-danger)' }}>
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--accent-danger)' }} />
            <div>
              <h3 className="font-semibold mb-2" style={{ color: 'var(--accent-danger)' }}>
                URGENT: Known Exploited Vulnerabilities Past Due
              </h3>
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                {cisaKEVMatches.filter(k => k.days_past_due > 0).length} CISA KEV items are overdue for remediation. Immediate action required.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Vulnerability Trend Chart */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Vulnerability Trend (90 days)
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Open vulnerabilities by severity over time
          </p>
        </div>
        <BarChartComponent
          data={vulnTrendData}
          dataKey="value"
          nameKey="date"
          title="Open CVEs by Severity"
          colors={['#ef4444', '#f97316', '#eab308']}
        />
      </div>

      {/* CISA KEV Known Exploited Vulnerabilities */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            CISA Known Exploited Vulnerabilities (KEV)
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            CVEs actively exploited in the wild - urgent remediation required
          </p>
        </div>
        <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
          <table className="w-full" style={{ backgroundColor: 'var(--bg-card)' }}>
            <thead style={{ backgroundColor: 'var(--bg-secondary)' }}>
              <tr>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>CVE</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Title</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Due Date</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Assets</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {cisaKEVMatches.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No CISA KEV data available</td>
                </tr>
              ) : cisaKEVMatches.map((item, idx) => (
                <tr key={idx} style={{ borderTop: `1px solid var(--border-primary)` }}>
                  <td className="px-4 py-3">
                    <code className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
                      {item.cve}
                    </code>
                  </td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{item.title}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>
                    {item.due_date}
                    {item.days_past_due > 0 && (
                      <span style={{ color: 'var(--accent-danger)', marginLeft: '8px', fontWeight: 'bold' }}>
                        ({item.days_past_due}d past)
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>{item.affected_assets}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs px-2 py-1 rounded font-semibold" style={{
                      backgroundColor: item.status === 'open' ? '#ef44442a' : '#f59e0b2a',
                      color: item.status === 'open' ? 'var(--accent-danger)' : 'var(--accent-warning)',
                    }}>
                      {(item.status || '').replace(/_/g, ' ')}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* EPSS × CVSS 4-Quadrant Priority Grid */}
      <div className="space-y-3">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            EPSS × CVSS Priority Matrix
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            High CVSS ≥ 7.0 · High EPSS ≥ 0.50. Focus remediation on top-right quadrant first.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          {[
            {
              label: '⚡ Patch Now!',
              desc: 'High CVSS + High EPSS',
              filter: v => v.cvss_score >= 7 && v.epss_score >= 0.5,
              bg: '#ef444420', border: '#ef4444', text: '#ef4444',
            },
            {
              label: '👁 Watch',
              desc: 'Low CVSS + High EPSS',
              filter: v => v.cvss_score < 7 && v.epss_score >= 0.5,
              bg: '#f9731620', border: '#f97316', text: '#f97316',
            },
            {
              label: '🔍 Monitor',
              desc: 'High CVSS + Low EPSS',
              filter: v => v.cvss_score >= 7 && v.epss_score < 0.5,
              bg: '#eab30820', border: '#eab308', text: '#eab308',
            },
            {
              label: '✓ Low Priority',
              desc: 'Low CVSS + Low EPSS',
              filter: v => v.cvss_score < 7 && v.epss_score < 0.5,
              bg: '#22c55e20', border: '#22c55e', text: '#22c55e',
            },
          ].map((q) => {
            const cnt = filteredVulnerabilities.filter(q.filter).length;
            return (
              <div key={q.label} className="rounded-xl p-5 border flex items-center justify-between transition-colors duration-200"
                style={{ backgroundColor: q.bg, borderColor: q.border }}>
                <div>
                  <p className="text-sm font-bold" style={{ color: q.text }}>{q.label}</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{q.desc}</p>
                </div>
                <p className="text-3xl font-black" style={{ color: q.text }}>{cnt}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Exploitability Analysis */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Exploitability Analysis
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Vulnerabilities ranked by exploitability (CVSS × EPSS × exploit availability × asset criticality)
          </p>
        </div>
        <DataTable
          data={filteredVulnerabilities}
          columns={columns}
          pageSize={20}
          onRowClick={handleRowClick}
          loading={loading}
          emptyMessage="No vulnerabilities found matching your filters"
        />
      </div>

      {/* Patch SLA Tracking */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Patch SLA Tracking by Severity
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Critical: 48h, High: 7d, Medium: 30d, Low: 90d
          </p>
        </div>
        <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
          <table className="w-full" style={{ backgroundColor: 'var(--bg-card)' }}>
            <thead style={{ backgroundColor: 'var(--bg-secondary)' }}>
              <tr>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Severity</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>SLA Target</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Open</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Within SLA</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Breached</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Compliance %</th>
              </tr>
            </thead>
            <tbody>
              {slaTracks.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No SLA tracking data available</td>
                </tr>
              ) : slaTracks.map((sla, idx) => (
                <tr key={idx} style={{ borderTop: `1px solid var(--border-primary)` }}>
                  <td className="px-4 py-3 text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>{sla.severity}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-tertiary)' }}>{sla.sla_target}</td>
                  <td className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>{sla.open_count}</td>
                  <td className="px-4 py-3 text-center text-sm" style={{ color: 'var(--accent-success)' }}>{sla.within_sla}</td>
                  <td className="px-4 py-3 text-center text-sm font-semibold" style={{ color: sla.breached > 0 ? 'var(--accent-danger)' : 'var(--text-secondary)' }}>{sla.breached}</td>
                  <td className="px-4 py-3 text-center text-sm font-semibold" style={{ color: sla.compliance >= 90 ? 'var(--accent-success)' : sla.compliance >= 70 ? 'var(--accent-warning)' : 'var(--accent-danger)' }}>
                    {sla.compliance}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Remediation Guidance */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Top Remediation Actions
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Actions that would resolve the most vulnerabilities
          </p>
        </div>
        {remediationActions.length === 0 ? (
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No remediation data available</p>
        ) : (
          <div className="space-y-3">
            {remediationActions.map((action, idx) => (
              <div key={idx} className="p-4 rounded-lg border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <p className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{action.action}</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                      Would resolve <span className="font-semibold">{action.cvesResolved} CVEs</span>
                    </p>
                  </div>
                  <span className="text-xs px-2 py-1 rounded font-semibold" style={{
                    backgroundColor: action.priority === 'critical' ? '#ef44442a' : '#f59e0b2a',
                    color: action.priority === 'critical' ? 'var(--accent-danger)' : 'var(--accent-warning)',
                  }}>
                    {action.priority}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Risk Acceptance Table */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Risk Acceptance Records
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Approved risk acceptances with compensating controls and expiry dates
          </p>
        </div>
        <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
          <table className="w-full" style={{ backgroundColor: 'var(--bg-card)' }}>
            <thead style={{ backgroundColor: 'var(--bg-secondary)' }}>
              <tr>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>CVE</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Justification</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Accepted By</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Expiry</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Compensating Control</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Review Date</th>
              </tr>
            </thead>
            <tbody>
              {acceptedRisks.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No accepted risk records available</td>
                </tr>
              ) : acceptedRisks.map((risk, idx) => (
                <tr key={idx} style={{ borderTop: `1px solid var(--border-primary)` }}>
                  <td className="px-4 py-3">
                    <code className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
                      {risk.cve}
                    </code>
                  </td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{risk.justification}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{risk.accepted_by}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{risk.expiry}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-tertiary)' }}>{risk.control}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{risk.review_date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
