'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { Play, Plus } from 'lucide-react';
import { fetchView, postToEngine } from '@/lib/api';
import { useToast } from '@/lib/toast-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';
import FilterBar from '@/components/shared/FilterBar';
import StatusIndicator from '@/components/shared/StatusIndicator';


export default function ScansPage() {
  const router = useRouter();
  const toast = useToast();
  const [scans, setScans] = useState([]);
  const [scheduledScans, setScheduledScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showRunModal, setShowRunModal] = useState(false);
  const [selectedAccount, setSelectedAccount] = useState('');
  const [selectedType, setSelectedType] = useState('full');
  const [filters, setFilters] = useState({
    type: '',
    status: '',
  });

  const { provider, account, filterSummary } = useGlobalFilter();

  // BFF handles scope filtering — scopeFiltered is now just scans
  const scopeFiltered = scans;

  // Fetch scan history via BFF
  useEffect(() => {
    const loadScans = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchView('scans', {
          provider: provider || undefined,
          account: account || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.scans)     setScans(data.scans);
        if (data.scheduled) setScheduledScans(data.scheduled);
      } catch (err) {
        setError(err?.message || 'Failed to load scan history');
      } finally {
        setLoading(false);
      }
    };

    loadScans();
  }, [provider, account]);

  const handleRunScan = async () => {
    if (!selectedAccount || !selectedType) return;

    try {
      const result = await postToEngine('gateway', '/api/v1/gateway/orchestrate', {
        account_id: selectedAccount,
        scan_type: selectedType,
      });

      if (result.error) {
        toast.error(`Error: ${result.error}`);
      } else {
        const newScan = {
          scan_id: result.scan_id || `scan-new-${Date.now()}`,
          scan_name: `${selectedType.charAt(0).toUpperCase() + selectedType.slice(1)} Scan`,
          scan_type: selectedType,
          account_id: selectedAccount,
          account_name: selectedAccount,
          status: 'pending',
          started_at: new Date().toISOString(),
          completed_at: null,
          duration: '0m 0s',
          resources_scanned: 0,
          total_findings: 0,
          critical_findings: 0,
          high_findings: 0,
          triggered_by: 'manual',
        };
        setScans([newScan, ...scans]);
        setShowRunModal(false);
        setSelectedAccount('');
        setSelectedType('full');
      }
    } catch (err) {
      toast.error(`Error triggering scan: ${err.message}`);
    }
  };

  // Filter scans (local type/status filters applied on top of scopeFiltered)
  const filteredScans = useMemo(() => {
    return scopeFiltered.filter((scan) => {
      if (filters.type && scan.scan_type !== filters.type) return false;
      if (filters.status && scan.status !== filters.status) return false;
      return true;
    });
  }, [scopeFiltered, filters]);

  // Calculate KPI metrics from scopeFiltered
  const activeScans = scopeFiltered.filter((s) => s.status === 'running').length;
  const activeScanCount = scopeFiltered.filter((s) => s.status === 'running' || s.status === 'pending').length;
  const totalScansCompleted = scopeFiltered.filter((s) => s.status === 'completed').length;
  const failedScans = scopeFiltered.filter((s) => s.status === 'failed').length;
  const coverage = scopeFiltered.length > 0
    ? ((totalScansCompleted / scopeFiltered.length) * 100).toFixed(1)
    : '0.0';
  const totalFindings = scopeFiltered.reduce((sum, s) => sum + (s.total_findings || 0), 0);
  const criticalAssets = scopeFiltered.reduce((sum, s) => sum + (s.critical_findings || 0), 0);
  const avgDuration = totalScansCompleted > 0
    ? (
        scopeFiltered
          .filter((s) => s.status === 'completed')
          .reduce((sum, s) => {
            const match = s.duration.match(/(\d+)m (\d+)s/);
            if (match) {
              return sum + parseInt(match[1]) * 60 + parseInt(match[2]);
            }
            return sum;
          }, 0) / totalScansCompleted / 60
      ).toFixed(0)
    : 0;

  const types = [
    { value: 'full', label: 'Full Scan' },
    { value: 'incremental', label: 'Incremental' },
    { value: 'compliance', label: 'Compliance' },
    { value: 'vulnerability', label: 'Vulnerability' },
    { value: 'iac', label: 'IaC Scan' },
  ];

  const statuses = [
    { value: 'completed', label: 'Completed' },
    { value: 'running', label: 'Running' },
    { value: 'pending', label: 'Pending' },
    { value: 'failed', label: 'Failed' },
  ];

  // Table columns
  const columns = [
    {
      accessorKey: 'scan_name',
      header: 'Scan Name',
      cell: (info) => (
        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'scan_type',
      header: 'Type',
      cell: (info) => (
        <span
          className="inline-block px-2 py-1 rounded text-xs font-medium"
          style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-tertiary)' }}
        >
          {(info.getValue() || '').toUpperCase()}
        </span>
      ),
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => {
        const providers = { aws: '🟠', azure: '🔵', gcp: '🔴', multi: '🌐' };
        return (
          <span className="font-medium text-sm" style={{ color: 'var(--text-secondary)' }}>
            {providers[info.getValue()] || ''} {info.getValue().toUpperCase()}
          </span>
        );
      },
    },
    {
      accessorKey: 'account_name',
      header: 'Account',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
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
      accessorKey: 'started_at',
      header: 'Started',
      cell: (info) => {
        const date = new Date(info.getValue());
        return (
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {date.toLocaleDateString()} {date.toLocaleTimeString()}
          </span>
        );
      },
    },
    {
      accessorKey: 'duration',
      header: 'Duration',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'resources_scanned',
      header: 'Resources',
      cell: (info) => (
        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'total_findings',
      header: 'Findings',
      cell: (info) => {
        const total = info.getValue();
        return (
          <div className="flex items-center gap-1">
            <span style={{ color: 'var(--text-primary)' }} className="font-semibold">
              {total}
            </span>
            {total > 0 && (
              <span style={{ color: 'var(--text-tertiary)' }} className="text-xs">
                (
                {info.row.original.critical_findings > 0 && `${info.row.original.critical_findings}C `}
                {info.row.original.high_findings > 0 && `${info.row.original.high_findings}H`})
              </span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'triggered_by',
      header: 'Triggered By',
      cell: (info) => (
        <span
          className="text-xs px-2 py-1 rounded"
          style={{
            backgroundColor: (info.getValue() || '') === 'scheduler' ? 'var(--bg-tertiary)' : 'var(--accent-primary)',
            color: (info.getValue() || '') === 'scheduler' ? 'var(--text-secondary)' : 'white',
          }}
        >
          {((info.getValue() || '').charAt(0).toUpperCase() + (info.getValue() || '').slice(1))}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--accent-danger)' }}>
          <p className="text-sm font-medium" style={{ color: 'var(--accent-danger)' }}>Error: {error}</p>
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Scan Management
          </h1>
          {filterSummary && (
            <p className="text-xs mt-0.5 mb-2" style={{ color: 'var(--text-tertiary)' }}>
              <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
              <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{filterSummary}</span>
            </p>
          )}
          <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Monitor and manage cloud discovery and compliance scans
          </p>
        </div>
        <button
          onClick={() => setShowRunModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors text-white"
          style={{ backgroundColor: 'var(--accent-primary)' }}
        >
          <Play className="w-4 h-4" />
          Run New Scan
        </button>
      </div>

      {/* Metric Strip */}
      <MetricStrip groups={[
        {
          label: '🔵 SCAN HEALTH',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'ACTIVE SCANS', value: activeScans, context: 'currently running' },
            { label: 'COVERAGE', value: coverage + '%', valueColor: 'var(--accent-success)', context: 'assets covered' },
            { label: 'FAILED SCANS', value: failedScans, valueColor: 'var(--accent-danger)', deltaGoodDown: true, context: 'last 30 days' },
          ],
        },
        {
          label: '🔴 FINDINGS',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'TOTAL FOUND', value: totalFindings, delta: +34, deltaGoodDown: true, context: 'vs prev scan' },
            { label: 'CRITICAL ASSETS', value: criticalAssets, valueColor: 'var(--severity-critical)', noTrend: true, context: 'from last scan' },
            { label: 'AVG DURATION', value: avgDuration + 'm', noTrend: true, context: 'last 30 scans' },
          ],
        },
      ]} />

      {/* Scan Pipeline Stepper */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-5" style={{ color: 'var(--text-primary)' }}>Scan Pipeline</h2>
        {(() => {
          const pipelineSteps = [
            { name: 'Discovery', desc: 'Enumerate cloud resources' },
            { name: 'Check',     desc: 'Evaluate compliance rules' },
            { name: 'Inventory', desc: 'Normalize & relate assets' },
            { name: 'Threat',    desc: 'Detect threats & map MITRE' },
            { name: 'Compliance',desc: 'Build framework reports' },
          ];
          // Derive pipeline status from latest running/pending scan
          const activeScan = scans.find(s => s.status === 'running' || s.status === 'pending');
          const latestCompleted = scans.find(s => s.status === 'completed');
          return (
            <div className="flex items-start gap-0 overflow-x-auto">
              {pipelineSteps.map((step, idx, arr) => {
                let status = 'queued';
                let color = '#6b7280';
                let time = '—';
                if (activeScan) {
                  // If there's an active scan, show pipeline in progress
                  if (idx < 3) { status = 'done'; color = '#22c55e'; }
                  else if (idx === 3) { status = 'running'; color = '#f97316'; }
                } else if (latestCompleted) {
                  status = 'done'; color = '#22c55e';
                  time = latestCompleted.duration || '—';
                }
                return (
                  <div key={step.name} className="flex items-start flex-shrink-0" style={{ minWidth: 160 }}>
                    <div className="flex flex-col items-center" style={{ width: 160 }}>
                      <div className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm border-2 flex-shrink-0"
                        style={{ backgroundColor: color + '20', borderColor: color, color: color }}>
                        {status === 'done' ? '✓' : status === 'running' ? '⟳' : idx + 1}
                      </div>
                      <p className="text-xs font-bold mt-2 text-center" style={{ color: 'var(--text-primary)' }}>{step.name}</p>
                      <p className="text-xs mt-0.5 text-center" style={{ color: 'var(--text-tertiary)' }}>{step.desc}</p>
                      {status !== 'queued' && (
                        <span className="text-xs mt-1 px-2 py-0.5 rounded-full"
                          style={{ backgroundColor: color + '20', color: color }}>{status === 'running' ? 'In Progress' : 'Done'}</span>
                      )}
                    </div>
                    {idx < arr.length - 1 && (
                      <div className="flex-1 h-0.5 mt-5 mx-1 flex-shrink-0" style={{ backgroundColor: arr[idx + 1] && status === 'done' && (idx + 1 < 3 || !activeScan) ? '#22c55e' : 'var(--bg-tertiary)', minWidth: 20 }} />
                    )}
                  </div>
                );
              })}
            </div>
          );
        })()}
      </div>

      {/* Coverage Summary by Provider */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Scan Coverage by Provider</h2>
        <p className="text-sm mb-5" style={{ color: 'var(--text-tertiary)' }}>Scan success rates by cloud provider</p>
        {(() => {
          // Derive coverage from actual scan data grouped by provider
          const providerStats = {};
          scans.forEach(s => {
            const p = (s.provider || 'unknown').toUpperCase();
            if (!providerStats[p]) providerStats[p] = { total: 0, completed: 0, failed: 0, findings: 0, resources: 0 };
            providerStats[p].total += 1;
            if (s.status === 'completed') providerStats[p].completed += 1;
            if (s.status === 'failed') providerStats[p].failed += 1;
            providerStats[p].findings += s.total_findings || 0;
            providerStats[p].resources += s.resources_scanned || 0;
          });
          const providers = Object.entries(providerStats);
          if (providers.length === 0) {
            return <p className="text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>No scan data available to compute coverage</p>;
          }
          const cellBg = (pct) => pct >= 80 ? '#22c55e20' : pct >= 50 ? '#eab30820' : '#ef444420';
          const cellText = (pct) => pct >= 80 ? '#22c55e' : pct >= 50 ? '#eab308' : '#ef4444';
          return (
            <div className="overflow-x-auto">
              <table className="w-full text-sm border-collapse">
                <thead>
                  <tr>
                    <th className="text-left py-2 px-3 text-xs font-semibold" style={{ color: 'var(--text-tertiary)' }}>Provider</th>
                    <th className="py-2 px-3 text-center text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Total Scans</th>
                    <th className="py-2 px-3 text-center text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Completed</th>
                    <th className="py-2 px-3 text-center text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Failed</th>
                    <th className="py-2 px-3 text-center text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Success Rate</th>
                    <th className="py-2 px-3 text-center text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Resources</th>
                    <th className="py-2 px-3 text-center text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {providers.map(([name, stats]) => {
                    const successRate = stats.total > 0 ? Math.round((stats.completed / stats.total) * 100) : 0;
                    return (
                      <tr key={name}>
                        <td className="py-2 px-3 font-semibold text-xs" style={{ color: 'var(--text-primary)' }}>{name}</td>
                        <td className="py-2 px-3 text-center text-xs" style={{ color: 'var(--text-secondary)' }}>{stats.total}</td>
                        <td className="py-2 px-3 text-center text-xs" style={{ color: '#22c55e' }}>{stats.completed}</td>
                        <td className="py-2 px-3 text-center text-xs" style={{ color: stats.failed > 0 ? '#ef4444' : 'var(--text-secondary)' }}>{stats.failed}</td>
                        <td className="py-2 px-3 text-center">
                          <span className="text-xs font-bold px-2 py-1 rounded" style={{ backgroundColor: cellBg(successRate), color: cellText(successRate) }}>
                            {successRate}%
                          </span>
                        </td>
                        <td className="py-2 px-3 text-center text-xs" style={{ color: 'var(--text-secondary)' }}>{stats.resources}</td>
                        <td className="py-2 px-3 text-center text-xs" style={{ color: 'var(--text-secondary)' }}>{stats.findings}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          );
        })()}
      </div>

      {/* Scheduled Scans */}
      <div
        className="rounded-lg p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
          Scheduled Scans
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottomColor: 'var(--border-primary)' }} className="border-b">
                <th
                  className="text-left py-3 px-4 font-semibold"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Scan Name
                </th>
                <th
                  className="text-left py-3 px-4 font-semibold"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Type
                </th>
                <th
                  className="text-left py-3 px-4 font-semibold"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Frequency
                </th>
                <th
                  className="text-left py-3 px-4 font-semibold"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Next Run
                </th>
                <th
                  className="text-left py-3 px-4 font-semibold"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Providers
                </th>
                <th
                  className="text-left py-3 px-4 font-semibold"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {scheduledScans.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-sm" style={{ color: 'var(--text-tertiary)' }}>
                    No scheduled scans found
                  </td>
                </tr>
              )}
              {scheduledScans.map((schedule) => (
                <tr
                  key={schedule.id}
                  style={{ borderBottomColor: 'var(--border-primary)' }}
                  className="border-b"
                >
                  <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>
                    {schedule.name}
                  </td>
                  <td
                    className="py-3 px-4 text-xs px-2 py-1 rounded font-medium inline-block"
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {(schedule.type || '').toUpperCase()}
                  </td>
                  <td className="py-3 px-4" style={{ color: 'var(--text-tertiary)' }}>
                    {schedule.frequency}
                  </td>
                  <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>
                    {schedule.next_run ? new Date(schedule.next_run).toLocaleString() : 'N/A'}
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex gap-1">
                      {(schedule.providers || []).map((p) => (
                        <span
                          key={p}
                          className="px-2 py-1 rounded text-xs font-medium"
                          style={{
                            backgroundColor: 'var(--bg-tertiary)',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          {p.toUpperCase()}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <input
                      type="checkbox"
                      checked={schedule.enabled}
                      readOnly
                      className="rounded"
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Active Scans */}
      {activeScanCount > 0 && (
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            Active Scans
          </h2>
          <div className="space-y-4">
            {scans
              .filter((s) => s.status === 'running' || s.status === 'pending')
              .map((scan) => (
                <div
                  key={scan.scan_id}
                  className="rounded-lg p-4 border"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    borderColor: 'var(--border-primary)',
                  }}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h3 className="font-semibold" style={{ color: 'var(--text-primary)' }}>
                        {scan.scan_name}
                      </h3>
                      <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
                        Started {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}
                      </p>
                    </div>
                    <StatusIndicator status={scan.status} />
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {scan.resources_scanned} / ~{Math.floor(scan.resources_scanned * 1.3)} resources
                      </span>
                      <span style={{ color: 'var(--text-tertiary)' }}>{scan.duration}</span>
                    </div>
                    <div
                      className="w-full h-2 rounded-full overflow-hidden"
                      style={{ backgroundColor: 'var(--bg-secondary)' }}
                    >
                      <div
                        className="h-full bg-blue-500"
                        style={{
                          width: `${(scan.resources_scanned / (scan.resources_scanned * 1.3)) * 100}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <FilterBar
        filters={[
          { key: 'type', label: 'Scan Type', options: types },
          { key: 'status', label: 'Status', options: statuses },
        ]}
        onFilterChange={(key, value) => {
          setFilters({ ...filters, [key]: value });
        }}
        activeFilters={filters}
      />

      {/* Scan History Table */}
      <div
        className="rounded-lg p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Scan History
          </h2>
          <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
            {filteredScans.length} of {scans.length} scans
          </span>
        </div>
        <DataTable
          data={filteredScans}
          columns={columns}
          pageSize={15}
          onRowClick={(scan) => router.push(`/scans/${scan.scan_id}`)}
          loading={loading}
          emptyMessage="No scans found matching your filters"
        />
      </div>

      {/* Run Scan Modal */}
      {showRunModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div
            className="rounded-lg border p-6 max-w-md w-full mx-4"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
            }}
          >
            <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Run New Scan
            </h3>

            <div className="space-y-4">
              <div>
                <label
                  className="block text-sm font-medium mb-2"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Scan Type
                </label>
                <select
                  value={selectedType}
                  onChange={(e) => setSelectedType(e.target.value)}
                  className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    borderColor: 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                >
                  <option value="full">Full Scan</option>
                  <option value="incremental">Incremental Scan</option>
                  <option value="compliance">Compliance Scan</option>
                  <option value="vulnerability">Vulnerability Scan</option>
                  <option value="iac">IaC Scan</option>
                </select>
              </div>

              <div>
                <label
                  className="block text-sm font-medium mb-2"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Select Account
                </label>
                <select
                  value={selectedAccount}
                  onChange={(e) => setSelectedAccount(e.target.value)}
                  className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    borderColor: 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                >
                  <option value="">Choose an account...</option>
                  {Array.from(new Set(scans.map((s) => s.account_id).filter(Boolean)))
                    .filter((a) => a && a !== 'all')
                    .map((account) => (
                      <option key={account} value={account}>
                        {account}
                      </option>
                    ))}
                </select>
              </div>

              <div>
                <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                  This will trigger discovery, checks, inventory, threat detection, and compliance evaluation across all selected accounts and resources.
                </p>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowRunModal(false)}
                className="flex-1 px-4 py-2 rounded-lg font-medium transition-colors"
                style={{
                  backgroundColor: 'var(--bg-tertiary)',
                  color: 'var(--text-primary)',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleRunScan}
                disabled={!selectedAccount}
                className="flex-1 px-4 py-2 text-white rounded-lg font-medium transition-colors"
                style={{
                  backgroundColor: !selectedAccount ? 'var(--text-tertiary)' : 'var(--accent-primary)',
                  opacity: !selectedAccount ? 0.5 : 1,
                  cursor: !selectedAccount ? 'not-allowed' : 'pointer',
                }}
              >
                Start Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
