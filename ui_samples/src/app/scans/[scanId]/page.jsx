'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Shield,
  Zap,
  Activity,
  CheckCircle,
  AlertTriangle,
  Play,
  Download,
  RefreshCw,
  Clock,
  TrendingUp,
  TrendingDown,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import KpiCard from '@/components/shared/KpiCard';


export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.scanId;

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showLogsExpanded, setShowLogsExpanded] = useState(false);

  // Fetch scan details on mount
  useEffect(() => {
    const loadScan = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await getFromEngine('gateway', `/api/v1/gateway/scans/${scanId}`);
        if (result && !result.error && result.scan) {
          setScan(result.scan);
        } else {
          setError(result?.error || 'Failed to load scan details');
        }
      } catch (err) {
        setError(err?.message || 'Failed to load scan details');
      } finally {
        setLoading(false);
      }
    };

    loadScan();
  }, [scanId]);

  // Findings table columns
  const findingsColumns = [
    {
      accessorKey: 'finding_id',
      header: 'Finding ID',
      cell: (info) => (
        <code
          className="text-xs px-2 py-1 rounded"
          style={{
            color: 'var(--text-tertiary)',
            backgroundColor: 'var(--bg-tertiary)',
          }}
        >
          {info.getValue().substring(0, 12)}...
        </code>
      ),
    },
    {
      accessorKey: 'rule',
      header: 'Rule',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'resource',
      header: 'Resource',
      cell: (info) => (
        <code
          className="text-xs"
          style={{ color: 'var(--text-tertiary)' }}
        >
          {info.getValue().substring(0, 35)}...
        </code>
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
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        return (
          <span
            className="text-xs font-medium px-2 py-1 rounded"
            style={{
              backgroundColor: status === 'open' ? 'var(--accent-danger)' : 'var(--accent-success)',
              color: 'white',
            }}
          >
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </span>
        );
      },
    },
  ];

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-24 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        <div className="h-48 animate-pulse rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />
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

  const totalDuration = (scan.stages || []).reduce((sum, s) => {
    const match = s.duration.match(/(\d+)m (\d+)s/);
    if (match) {
      return sum + parseInt(match[1]) * 60 + parseInt(match[2]);
    }
    return sum;
  }, 0);

  const durationMinutes = Math.floor(totalDuration / 60);
  const durationSeconds = totalDuration % 60;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4 flex-1">
          <button
            onClick={() => router.push('/scans')}
            className="mt-1 p-1 rounded-lg transition-colors"
            onMouseEnter={(e) => (e.target.style.backgroundColor = 'var(--bg-tertiary)')}
            onMouseLeave={(e) => (e.target.style.backgroundColor = 'transparent')}
          >
            <ArrowLeft className="w-5 h-5" style={{ color: 'var(--text-tertiary)' }} />
          </button>
          <div>
            <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
              {scan.scan_name}
            </h1>
            <div className="mt-2 flex items-center gap-3">
              <code
                className="text-sm px-3 py-1 rounded"
                style={{
                  color: 'var(--text-tertiary)',
                  backgroundColor: 'var(--bg-tertiary)',
                }}
              >
                {scanId}
              </code>
              <StatusIndicator status={scan.status} />
              <span
                className="text-xs font-medium px-2 py-1 rounded"
                style={{
                  backgroundColor: 'var(--bg-tertiary)',
                  color: 'var(--text-secondary)',
                }}
              >
                {(scan.scan_type || '').toUpperCase()}
              </span>
            </div>
          </div>
        </div>

        {/* Scan Info Card */}
        <div
          className="rounded-lg p-4 border text-right"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <p className="text-xs mb-1" style={{ color: 'var(--text-tertiary)' }}>
            Duration
          </p>
          <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            {durationMinutes}m {durationSeconds}s
          </p>
          <p className="text-xs mt-2" style={{ color: 'var(--text-tertiary)' }}>
            Started {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}
          </p>
        </div>
      </div>

      {/* Scan Pipeline Visualization */}
      <div
        className="rounded-lg p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <h2 className="text-lg font-semibold mb-6" style={{ color: 'var(--text-primary)' }}>
          Scan Pipeline
        </h2>
        <div className="flex items-center justify-between">
          {(scan.stages || []).map((stage, idx) => (
            <div key={stage.name} className="flex flex-col items-center flex-1">
              <div className="flex items-center w-full">
                {/* Stage Circle */}
                <div
                  className="rounded-full w-10 h-10 flex items-center justify-center"
                  style={{
                    backgroundColor:
                      stage.status === 'completed'
                        ? 'var(--accent-success)'
                        : stage.status === 'running'
                          ? 'var(--accent-warning)'
                          : 'var(--text-tertiary)',
                    color: 'white',
                  }}
                >
                  {stage.status === 'completed' && <CheckCircle className="w-5 h-5" />}
                  {stage.status === 'running' && <RefreshCw className="w-5 h-5 animate-spin" />}
                  {stage.status === 'pending' && <Clock className="w-5 h-5" />}
                </div>

                {/* Connector */}
                {idx < (scan.stages || []).length - 1 && (
                  <div
                    className="flex-1 h-1 mx-2"
                    style={{
                      backgroundColor:
                        stage.status === 'completed'
                          ? 'var(--accent-success)'
                          : 'var(--border-primary)',
                    }}
                  />
                )}
              </div>

              {/* Stage Label */}
              <p
                className="text-sm font-semibold mt-2"
                style={{ color: 'var(--text-primary)' }}
              >
                {stage.name}
              </p>
              <p
                className="text-xs"
                style={{ color: 'var(--text-tertiary)' }}
              >
                {stage.duration}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Resources Discovered"
          value={scan.discovered_resources}
          subtitle="Unique cloud assets"
          icon={<Shield className="w-6 h-6" />}
          color="blue"
        />
        <KpiCard
          title="Checks Run"
          value={scan.checks_run}
          subtitle="Compliance rules evaluated"
          icon={<CheckCircle className="w-6 h-6" />}
          color="green"
        />
        <KpiCard
          title="Findings"
          value={(scan.findings || []).length}
          subtitle={`${scan.findings_summary?.critical || 0} critical, ${scan.findings_summary?.high || 0} high`}
          icon={<AlertTriangle className="w-6 h-6" />}
          color="orange"
        />
        <KpiCard
          title="Compliance Score"
          value={`${scan.compliance_score}%`}
          subtitle="Overall posture"
          icon={<Activity className="w-6 h-6" />}
          color="purple"
        />
      </div>

      {/* Findings Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Findings by Severity */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            Severity Breakdown
          </h3>
          <div className="space-y-3">
            {[
              {
                label: 'Critical',
                value: scan.findings_summary?.critical || 0,
                color: 'var(--accent-danger)',
              },
              {
                label: 'High',
                value: scan.findings_summary?.high || 0,
                color: 'var(--accent-warning)',
              },
              {
                label: 'Medium',
                value: scan.findings_summary?.medium || 0,
                color: '#f59e0b',
              },
              {
                label: 'Low',
                value: scan.findings_summary?.low || 0,
                color: 'var(--accent-success)',
              },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {item.label}
                  </span>
                </div>
                <span
                  className="font-semibold"
                  style={{ color: item.color }}
                >
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Category Breakdown */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            Top Categories
          </h3>
          <div className="space-y-2">
            {(scan.category_breakdown || []).slice(0, 6).map((item) => (
              <div key={item.category} className="flex items-center justify-between text-sm">
                <span style={{ color: 'var(--text-secondary)' }}>
                  {item.category}
                </span>
                <span
                  className="font-semibold px-2 py-1 rounded"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    color: 'var(--text-primary)',
                  }}
                >
                  {item.count}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Comparison with Previous Scan */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            vs Previous Scan
          </h3>
          <div className="space-y-3">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <TrendingUp className="w-4 h-4" style={{ color: 'var(--accent-danger)' }} />
                <span style={{ color: 'var(--text-secondary)' }}>New Findings</span>
              </div>
              <p
                className="text-2xl font-bold"
                style={{ color: 'var(--accent-danger)' }}
              >
                +{scan.comparison?.new_findings || 0}
              </p>
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <CheckCircle
                  className="w-4 h-4"
                  style={{ color: 'var(--accent-success)' }}
                />
                <span style={{ color: 'var(--text-secondary)' }}>Resolved</span>
              </div>
              <p
                className="text-2xl font-bold"
                style={{ color: 'var(--accent-success)' }}
              >
                -{scan.comparison?.resolved_findings || 0}
              </p>
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span style={{ color: 'var(--text-tertiary)' }}>Unchanged</span>
              </div>
              <p
                className="text-2xl font-bold"
                style={{ color: 'var(--text-secondary)' }}
              >
                {scan.comparison?.unchanged_findings || 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div
        className="rounded-lg p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Findings
          </h2>
          <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
            {(scan.findings || []).length} findings
          </span>
        </div>
        <DataTable
          data={scan.findings}
          columns={findingsColumns}
          pageSize={10}
          loading={loading}
          emptyMessage="No findings for this scan"
        />
      </div>

      {/* Scan Logs */}
      <div
        className="rounded-lg p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Scan Logs
          </h2>
          <button
            onClick={() => setShowLogsExpanded(!showLogsExpanded)}
            className="text-sm px-3 py-1 rounded transition-colors"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
            }}
          >
            {showLogsExpanded ? 'Collapse' : 'Expand'}
          </button>
        </div>

        <div
          className={`rounded-lg border overflow-hidden ${
            showLogsExpanded ? '' : 'max-h-60'
          }`}
          style={{
            backgroundColor: 'var(--bg-secondary)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <div className="font-mono text-xs">
            {(scan.scan_logs || []).map((log, idx) => (
              <div
                key={idx}
                className="px-4 py-2 border-b last:border-b-0 flex gap-4"
                style={{
                  borderBottomColor: 'var(--border-primary)',
                  backgroundColor:
                    log.level === 'warning'
                      ? 'var(--accent-warning)'
                      : log.level === 'error'
                        ? 'var(--accent-danger)'
                        : 'transparent',
                }}
              >
                <span
                  style={{
                    color: 'var(--text-tertiary)',
                    minWidth: '160px',
                  }}
                >
                  {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'N/A'}
                </span>
                <span
                  style={{
                    color:
                      log.level === 'warning'
                        ? '#000'
                        : log.level === 'error'
                          ? '#fff'
                          : 'var(--text-secondary)',
                    minWidth: '60px',
                  }}
                  className={`font-semibold ${
                    log.level === 'warning' || log.level === 'error' ? 'text-white' : ''
                  }`}
                >
                  [{(log.level || '').toUpperCase()}]
                </span>
                <span
                  style={{
                    color:
                      log.level === 'warning'
                        ? '#000'
                        : log.level === 'error'
                          ? '#fff'
                          : 'var(--text-secondary)',
                  }}
                >
                  {log.message}
                </span>
              </div>
            ))}
          </div>
        </div>

        {!showLogsExpanded && (scan.scan_logs || []).length > 6 && (
          <div
            className="text-center py-2 mt-2 text-sm"
            style={{ color: 'var(--text-tertiary)' }}
          >
            Showing 6 of {(scan.scan_logs || []).length} log entries
          </div>
        )}
      </div>

      {/* Action Buttons */}
      <div className="flex gap-3">
        <button
          className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors"
          style={{
            backgroundColor: 'var(--accent-primary)',
            color: 'white',
          }}
        >
          <Play className="w-4 h-4" />
          Re-run Scan
        </button>
        <button
          className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors"
          style={{
            backgroundColor: 'var(--bg-tertiary)',
            color: 'var(--text-secondary)',
          }}
        >
          <Download className="w-4 h-4" />
          Export Results
        </button>
      </div>
    </div>
  );
}
