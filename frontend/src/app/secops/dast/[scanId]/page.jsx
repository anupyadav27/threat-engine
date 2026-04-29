'use client';

import { useState, useEffect, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ChevronLeft, Globe, ExternalLink, AlertTriangle,
  Shield, Crosshair, Activity, Loader2,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import FilterBar from '@/components/shared/FilterBar';

// ---------------------------------------------------------------------------
// Constants & helpers
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// SeverityBar component (inline)
// ---------------------------------------------------------------------------
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
        No findings data
      </div>
    );
  }
  return (
    <div>
      <div className="flex rounded-full overflow-hidden h-3 gap-px">
        {SEG.map(s => {
          const v = counts[s.key] || 0;
          if (!v) return null;
          return (
            <div key={s.key} className={`${s.bg} transition-all`}
              style={{ width: `${(v / total) * 100}%` }}
              title={`${s.label}: ${v}`} />
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
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MethodBadge
// ---------------------------------------------------------------------------
function MethodBadge({ method }) {
  const cfg = {
    GET:    'bg-blue-500/15 text-blue-400 border-blue-500/30',
    POST:   'bg-orange-500/15 text-orange-400 border-orange-500/30',
    PUT:    'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    DELETE: 'bg-red-500/15 text-red-400 border-red-500/30',
    PATCH:  'bg-purple-500/15 text-purple-400 border-purple-500/30',
  };
  const m = (method || '').toUpperCase();
  const cls = cfg[m] || 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  return (
    <span className={`inline-flex items-center text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${cls}`}>
      {m || '?'}
    </span>
  );
}

// ---------------------------------------------------------------------------
// ExpandedFindingRow
// ---------------------------------------------------------------------------
function ExpandedFindingRow({ finding }) {
  const meta = finding.metadata || {};
  return (
    <div className="px-5 py-4 space-y-4 border-t" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>

      {/* Description */}
      {finding.description && (
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-tertiary)' }}>
            Description
          </div>
          <div className="text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
            {finding.description}
          </div>
        </div>
      )}

      {/* Evidence */}
      {(meta.parameter_name || meta.payload || meta.evidence) && (
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-tertiary)' }}>
            Evidence
          </div>
          <div className="space-y-1.5 rounded-xl border p-3"
            style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}>
            {meta.parameter_name && (
              <div className="flex items-start gap-3">
                <span className="text-xs font-semibold w-24 flex-shrink-0" style={{ color: 'var(--text-tertiary)' }}>Parameter</span>
                <span className="text-xs font-mono" style={{ color: 'var(--text-primary)' }}>{meta.parameter_name}</span>
              </div>
            )}
            {meta.payload && (
              <div className="flex items-start gap-3">
                <span className="text-xs font-semibold w-24 flex-shrink-0" style={{ color: 'var(--text-tertiary)' }}>Payload</span>
                <code className="text-xs font-mono px-2 py-0.5 rounded bg-orange-500/10 text-orange-300 break-all">
                  {meta.payload}
                </code>
              </div>
            )}
            {meta.evidence && (
              <div className="flex items-start gap-3">
                <span className="text-xs font-semibold w-24 flex-shrink-0" style={{ color: 'var(--text-tertiary)' }}>Evidence</span>
                <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{meta.evidence}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Remediation */}
      {meta.remediation && (
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-tertiary)' }}>
            Remediation
          </div>
          <div className="text-sm leading-relaxed p-3 rounded-xl border border-green-500/20 bg-green-500/5 text-green-300">
            {meta.remediation}
          </div>
        </div>
      )}

      {/* CVSS */}
      {(meta.cvss_score || meta.cvss_vector) && (
        <div className="flex items-center gap-6">
          {meta.cvss_score && (
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-tertiary)' }}>CVSS Score</div>
              <span className={`text-lg font-bold ${
                meta.cvss_score >= 9 ? 'text-red-400' :
                meta.cvss_score >= 7 ? 'text-orange-400' :
                meta.cvss_score >= 4 ? 'text-yellow-400' : 'text-blue-400'
              }`}>
                {meta.cvss_score}
              </span>
              <span className="text-xs ml-1" style={{ color: 'var(--text-tertiary)' }}>/10</span>
            </div>
          )}
          {meta.cvss_vector && (
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-tertiary)' }}>CVSS Vector</div>
              <code className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{meta.cvss_vector}</code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function DastScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.scanId;

  const [summary,  setSummary]  = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [sevFilter, setSevFilter] = useState({ severity: '' });

  // ---------------------------------------------------------------------------
  // Fetch data
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!scanId) return;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [statusData, findingsData] = await Promise.all([
          getFromEngine('secops', `/api/v1/secops/dast/scan/${scanId}/status?tenant_id=test-tenant`),
          getFromEngine('secops', `/api/v1/secops/dast/scan/${scanId}/findings?limit=500`),
        ]);
        if (statusData && !statusData.error) setSummary(statusData);
        else setError(statusData?.error || statusData?.detail || 'Failed to load scan status');
        const raw = Array.isArray(findingsData) ? findingsData : (findingsData?.findings || []);
        setFindings(raw);
      } catch (err) {
        setError(err?.message || 'Failed to load DAST scan data');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [scanId]);

  // ---------------------------------------------------------------------------
  // Derived data
  // ---------------------------------------------------------------------------
  const normalizedFindings = useMemo(() => {
    return findings.map(f => ({
      ...f,
      _normalSev: normalizeSev(f.severity),
    })).sort((a, b) => (SEV_ORDER[a._normalSev] ?? 9) - (SEV_ORDER[b._normalSev] ?? 9));
  }, [findings]);

  const severityCounts = useMemo(() => {
    const bySev = summary?.by_severity || {};
    if (Object.keys(bySev).length > 0) return bySev;
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    normalizedFindings.forEach(f => { counts[f._normalSev] = (counts[f._normalSev] || 0) + 1; });
    return counts;
  }, [summary, normalizedFindings]);

  const criticalHigh = (severityCounts.critical || 0) + (severityCounts.high || 0);

  const endpointsDiscovered = useMemo(() => {
    const endpoints = new Set(normalizedFindings.map(f => f.endpoint_url).filter(Boolean));
    return endpoints.size || summary?.endpoints_discovered || 0;
  }, [normalizedFindings, summary]);

  const attacksSent = summary?.attacks_sent || summary?.summary?.attacks_sent || 0;

  const filteredFindings = useMemo(() => {
    return normalizedFindings.filter(f => {
      if (sevFilter.severity && f._normalSev !== sevFilter.severity) return false;
      return true;
    });
  }, [normalizedFindings, sevFilter]);

  // ---------------------------------------------------------------------------
  // Column definitions
  // ---------------------------------------------------------------------------
  const columns = useMemo(() => [
    {
      accessorKey: '_normalSev',
      header: 'Severity',
      size: 100,
      cell: info => <SeverityBadge severity={info.getValue()} />,
    },
    {
      id: 'vuln_type',
      header: 'Vulnerability',
      size: 180,
      cell: info => {
        const row = info.row.original;
        const v = row.vulnerability_type || row.rule_id || '—';
        return (
          <span className="text-sm font-semibold truncate block max-w-[180px]" title={v} style={{ color: 'var(--text-primary)' }}>
            {v}
          </span>
        );
      },
    },
    {
      id: 'endpoint',
      header: 'Endpoint',
      cell: info => {
        const row = info.row.original;
        const method = row.metadata?.method || row.method || '';
        const url = row.endpoint_url || row.resource || '—';
        return (
          <div className="flex items-center gap-2 min-w-0">
            {method && <MethodBadge method={method} />}
            <span className="text-xs font-mono truncate max-w-[240px]" title={url} style={{ color: 'var(--text-secondary)' }}>
              {url}
            </span>
          </div>
        );
      },
    },
    {
      id: 'description',
      header: 'Risk / Description',
      cell: info => {
        const row = info.row.original;
        return (
          <span className="text-xs truncate block max-w-[280px]" title={row.description || '—'} style={{ color: 'var(--text-secondary)' }}>
            {row.description || '—'}
          </span>
        );
      },
    },
    {
      id: 'cvss',
      header: 'CVSS',
      size: 70,
      cell: info => {
        const score = info.row.original.metadata?.cvss_score;
        if (!score) return <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
        const cls = score >= 9 ? 'text-red-400' : score >= 7 ? 'text-orange-400' : score >= 4 ? 'text-yellow-400' : 'text-blue-400';
        return <span className={`text-sm font-bold ${cls}`}>{score}</span>;
      },
    },
  ], []);

  // Filter bar config
  const filterDefs = [
    { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low', 'info'] },
  ];

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <div className="flex items-center gap-2">
          <Loader2 className="w-5 h-5 animate-spin" />
          Loading DAST scan data...
        </div>
      </div>
    );
  }

  const targetUrl  = summary?.target_url || scanId;
  const scanStatus = summary?.status;
  const profile    = summary?.scan_profile || summary?.profile || 'standard';

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="px-6 pt-6 pb-0">

        {/* Back button */}
        <button onClick={() => router.push('/secops')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity mb-4"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Code Security
        </button>

        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>DAST Scan</h1>
              {scanStatus && <StatusIndicator status={scanStatus} />}
              <span className="text-xs px-2.5 py-1 rounded-full border bg-purple-500/10 text-purple-400 border-purple-500/30">
                {profile}
              </span>
            </div>
            <div className="flex items-center gap-2 mt-2">
              <Globe className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
              <span className="text-sm font-mono truncate max-w-[480px]" style={{ color: 'var(--text-secondary)' }}>
                {targetUrl}
              </span>
              {targetUrl && targetUrl !== scanId && (
                <a href={targetUrl} target="_blank" rel="noopener noreferrer"
                  className="p-1 rounded hover:bg-white/5 transition-colors">
                  <ExternalLink className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
                </a>
              )}
            </div>
          </div>
        </div>

        {/* Status banners */}
        {scanStatus === 'failed' && (
          <div className="flex items-start gap-3 p-4 rounded-xl border border-red-500/30 bg-red-500/10 mb-6">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="text-sm font-semibold text-red-400">Scan Failed</div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                {summary?.error || 'Target URL was not reachable. Verify the target is accessible and try again.'}
              </div>
            </div>
          </div>
        )}

        {scanStatus === 'running' && (
          <div className="flex items-center gap-3 p-4 rounded-xl border border-blue-500/30 bg-blue-500/10 mb-6">
            <Loader2 className="w-5 h-5 text-blue-400 animate-spin flex-shrink-0" />
            <div>
              <div className="text-sm font-semibold text-blue-400">Scan In Progress</div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                DAST scan is actively testing the target. Results will appear here as they are discovered.
              </div>
            </div>
          </div>
        )}

        {error && !summary && (
          <div className="flex items-start gap-3 p-4 rounded-xl border border-red-500/30 bg-red-500/10 mb-6">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="text-sm font-semibold text-red-400">Error loading scan</div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</div>
            </div>
          </div>
        )}

        {/* KPI cards */}
        <div className="grid grid-cols-4 gap-x-4 gap-y-4 mb-6">
          <KpiCard
            title="Total Findings"
            value={normalizedFindings.length}
            subtitle={fmtDate(summary?.scan_timestamp)}
            icon={<Shield className="w-5 h-5" />}
            color={normalizedFindings.length > 0 ? 'orange' : 'green'}
          />
          <KpiCard
            title="Critical + High"
            value={criticalHigh}
            subtitle="Immediate attention required"
            icon={<AlertTriangle className="w-5 h-5" />}
            color={criticalHigh > 0 ? 'red' : 'green'}
          />
          <KpiCard
            title="Endpoints"
            value={endpointsDiscovered}
            subtitle="Unique endpoints discovered"
            icon={<Crosshair className="w-5 h-5" />}
            color="blue"
          />
          <KpiCard
            title="Attacks Sent"
            value={attacksSent || '—'}
            subtitle="Total attack probes sent"
            icon={<Activity className="w-5 h-5" />}
            color="purple"
          />
        </div>

        {/* Severity distribution bar */}
        <div className="rounded-2xl border overflow-hidden mb-6"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
            <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Severity Distribution</div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>All findings by severity level</div>
          </div>
          <div className="px-5 py-4">
            <SeverityBar counts={severityCounts} />
          </div>
        </div>

      </div>

      {/* Findings table */}
      <div className="px-6 pb-8 space-y-4">
        <FilterBar
          filters={filterDefs}
          activeFilters={sevFilter}
          onFilterChange={(key, val) => setSevFilter(prev => ({ ...prev, [key]: val }))}
        />
        <DataTable
          data={filteredFindings}
          columns={columns}
          pageSize={25}
          emptyMessage={
            normalizedFindings.length === 0
              ? (scanStatus === 'running'
                  ? 'Scan in progress — findings will appear here as they are discovered.'
                  : 'No findings detected for this scan.')
              : 'No findings match the current filters.'
          }
          renderExpandedRow={(row) => <ExpandedFindingRow finding={row} />}
        />
      </div>
    </div>
  );
}
