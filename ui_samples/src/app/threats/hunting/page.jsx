'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ChevronRight,
  Crosshair,
  ShieldAlert,
  Target,
  SearchCode,
  Zap,
  BarChart3,
  Copy,
  Check,
  Play,
  Loader2,
  ChevronDown,
  ChevronUp,
  Globe,
  Hash,
  Link2,
  Fingerprint,
  Search,
} from 'lucide-react';
import { fetchView, postToEngine } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

/* ──────────────────────────── helpers ──────────────────────────── */

/** Format a relative time string from ISO timestamp */
function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

/** IOC type icon mapping */
function IocTypeIcon({ type }) {
  const t = (type || '').toLowerCase();
  if (t === 'ip' || t === 'ipv4' || t === 'ipv6') return <Globe className="w-3.5 h-3.5" />;
  if (t === 'domain' || t === 'url') return <Link2 className="w-3.5 h-3.5" />;
  if (t === 'hash' || t === 'md5' || t === 'sha256' || t === 'sha1') return <Fingerprint className="w-3.5 h-3.5" />;
  if (t === 'tech' || t === 'technique' || t === 'cve') return <ShieldAlert className="w-3.5 h-3.5" />;
  return <Hash className="w-3.5 h-3.5" />;
}

/** Status badge with appropriate styling */
function StatusBadge({ status }) {
  const s = (status || '').toLowerCase();
  const config = {
    active: { bg: 'rgba(34,197,94,0.15)', color: '#22c55e', label: 'Active' },
    inactive: { bg: 'rgba(107,114,128,0.2)', color: '#9ca3af', label: 'Inactive' },
    running: { bg: 'rgba(59,130,246,0.15)', color: '#3b82f6', label: 'Running' },
    completed: { bg: 'rgba(34,197,94,0.15)', color: '#22c55e', label: 'Completed' },
    failed: { bg: 'rgba(239,68,68,0.15)', color: '#ef4444', label: 'Failed' },
    pending: { bg: 'rgba(234,179,8,0.15)', color: '#eab308', label: 'Pending' },
  };
  const c = config[s] || config.active;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium ${s === 'running' ? 'animate-pulse' : ''}`}
      style={{ backgroundColor: c.bg, color: c.color }}
    >
      {s === 'running' && <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: c.color }} />}
      {c.label}
    </span>
  );
}

/** Confidence mini progress bar */
function ConfidenceBar({ value }) {
  const v = Math.max(0, Math.min(100, value ?? 0));
  const color = v >= 80 ? '#ef4444' : v >= 60 ? '#f97316' : v >= 40 ? '#eab308' : '#3b82f6';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)', maxWidth: 64 }}>
        <div className="h-full rounded-full transition-all duration-300" style={{ width: `${v}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{v}%</span>
    </div>
  );
}

/** Copy to clipboard button */
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback((e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center p-1 rounded hover:opacity-75 transition-opacity"
      style={{ color: 'var(--text-muted)' }}
      title="Copy to clipboard"
    >
      {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

/** TTP pill for MITRE technique IDs */
function TtpPill({ technique }) {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium"
      style={{ backgroundColor: 'rgba(139,92,246,0.15)', color: '#a78bfa' }}
    >
      {technique}
    </span>
  );
}

/* ──────────────────────────── constants ──────────────────────────── */

const IOC_TYPE_OPTIONS = ['All', 'IP', 'Domain', 'Hash', 'URL', 'Tech', 'CVE'];
const SEVERITY_OPTIONS = ['All', 'critical', 'high', 'medium', 'low', 'info'];
const HUNT_TYPE_OPTIONS = ['All', 'Scheduled', 'Manual', 'Automated', 'Custom'];
const TAB_IOC = 'ioc';
const TAB_HUNT = 'hunt';

/* ──────────────────────────── main page ──────────────────────────── */

export default function ThreatHuntingPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { filterSummary } = useGlobalFilter();

  // Tab state from URL
  const activeTab = searchParams.get('tab') === TAB_HUNT ? TAB_HUNT : TAB_IOC;
  const setActiveTab = useCallback((tab) => {
    const params = new URLSearchParams(searchParams.toString());
    params.set('tab', tab);
    router.replace(`?${params.toString()}`, { scroll: false });
  }, [router, searchParams]);

  // Data state
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);

  // IOC tab filters
  const [iocTypeFilter, setIocTypeFilter] = useState('All');
  const [iocSeverityFilter, setIocSeverityFilter] = useState('All');
  const [iocSearch, setIocSearch] = useState('');

  // Hunt tab filters
  const [huntTypeFilter, setHuntTypeFilter] = useState('All');
  const [huntSeverityFilter, setHuntSeverityFilter] = useState('All');
  const [huntSearch, setHuntSearch] = useState('');

  // Expanded rows
  const [expandedIoc, setExpandedIoc] = useState(null);
  const [expandedQuery, setExpandedQuery] = useState(null);

  // Running queries tracking
  const [runningQueries, setRunningQueries] = useState({});
  const [queryResults, setQueryResults] = useState({});

  /* ──────────────── fetch data ──────────────── */

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetchView('threats/hunting');
        if (cancelled) return;
        if (res?.error) {
          setError(res.error);
        } else {
          setData(res);
        }
      } catch (err) {
        if (!cancelled) setError(err?.message || 'Failed to load threat hunting data.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, []);

  /* ──────────────── derived data ──────────────── */

  const kpi = data?.kpi || {};
  const iocs = data?.iocs || data?.indicators || [];
  const huntQueries = data?.huntQueries || data?.queries || [];

  // Filter IOCs
  const filteredIocs = useMemo(() => {
    let result = iocs;
    if (iocTypeFilter !== 'All') {
      result = result.filter((i) => (i.type || '').toLowerCase() === iocTypeFilter.toLowerCase());
    }
    if (iocSeverityFilter !== 'All') {
      result = result.filter((i) => (i.severity || '').toLowerCase() === iocSeverityFilter.toLowerCase());
    }
    if (iocSearch) {
      const q = iocSearch.toLowerCase();
      result = result.filter((i) =>
        (i.indicator || '').toLowerCase().includes(q) ||
        (i.source || '').toLowerCase().includes(q) ||
        (i.type || '').toLowerCase().includes(q)
      );
    }
    return result;
  }, [iocs, iocTypeFilter, iocSeverityFilter, iocSearch]);

  // Filter Hunt Queries
  const filteredQueries = useMemo(() => {
    let result = huntQueries;
    if (huntTypeFilter !== 'All') {
      result = result.filter((q) => (q.huntType || q.hunt_type || '').toLowerCase() === huntTypeFilter.toLowerCase());
    }
    if (huntSeverityFilter !== 'All') {
      result = result.filter((q) => (q.severity || '').toLowerCase() === huntSeverityFilter.toLowerCase());
    }
    if (huntSearch) {
      const s = huntSearch.toLowerCase();
      result = result.filter((q) =>
        (q.name || '').toLowerCase().includes(s) ||
        (q.description || '').toLowerCase().includes(s)
      );
    }
    return result;
  }, [huntQueries, huntTypeFilter, huntSeverityFilter, huntSearch]);

  /* ──────────────── actions ──────────────── */

  const handleRunQuery = useCallback(async (queryId, e) => {
    e?.stopPropagation();
    setRunningQueries((prev) => ({ ...prev, [queryId]: true }));
    setQueryResults((prev) => ({ ...prev, [queryId]: null }));
    try {
      const res = await postToEngine('threat', `/api/v1/hunt/queries/${queryId}/execute`);
      setQueryResults((prev) => ({ ...prev, [queryId]: res?.error ? { error: res.error } : res }));
    } catch (err) {
      setQueryResults((prev) => ({ ...prev, [queryId]: { error: err?.message || 'Execution failed' } }));
    } finally {
      setRunningQueries((prev) => ({ ...prev, [queryId]: false }));
    }
  }, []);

  /* ──────────────── IOC columns ──────────────── */

  const iocColumns = useMemo(() => [
    {
      accessorKey: 'source',
      header: 'Source',
      size: 120,
      cell: (info) => (
        <span className="text-xs font-medium px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'indicator',
      header: 'Indicator',
      size: 260,
      cell: (info) => {
        const val = info.getValue() || info.row.original.value || '';
        return (
          <div className="flex items-center gap-2">
            <code
              className="text-xs font-mono truncate"
              style={{ color: 'var(--accent-primary)', maxWidth: 200 }}
              title={val}
            >
              {val}
            </code>
            <CopyButton text={val} />
          </div>
        );
      },
    },
    {
      accessorKey: 'type',
      header: 'Type',
      size: 100,
      cell: (info) => {
        const val = info.getValue() || '';
        return (
          <span
            className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
          >
            <IocTypeIcon type={val} />
            {val}
          </span>
        );
      },
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 100,
      cell: (info) => <SeverityBadge severity={(info.getValue() || 'info').toLowerCase()} />,
    },
    {
      accessorKey: 'confidence',
      header: 'Confidence',
      size: 130,
      cell: (info) => <ConfidenceBar value={info.getValue()} />,
    },
    {
      accessorKey: 'matchedAssets',
      header: 'Matched Assets',
      size: 120,
      cell: (info) => {
        const v = info.getValue() ?? info.row.original.matched_assets ?? 0;
        return (
          <span className="text-sm font-bold" style={{ color: v > 0 ? 'var(--accent-danger)' : 'var(--text-muted)' }}>
            {v}
          </span>
        );
      },
    },
    {
      accessorKey: 'ttps',
      header: 'TTPs',
      size: 180,
      cell: (info) => {
        const techniques = info.getValue() || info.row.original.mitreTechniques || [];
        if (!techniques.length) return <span style={{ color: 'var(--text-muted)' }} className="text-xs">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {techniques.slice(0, 3).map((t) => <TtpPill key={t} technique={t} />)}
            {techniques.length > 3 && (
              <span className="text-[10px] font-medium" style={{ color: 'var(--text-muted)' }}>
                +{techniques.length - 3}
              </span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'lastUpdated',
      header: 'Last Updated',
      size: 110,
      cell: (info) => {
        const val = info.getValue() || info.row.original.last_seen || info.row.original.updated_at;
        return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{timeAgo(val)}</span>;
      },
    },
  ], []);

  /* ──────────────── Hunt Query columns ──────────────── */

  const huntColumns = useMemo(() => [
    {
      accessorKey: 'name',
      header: 'Query Name',
      size: 200,
      cell: (info) => (
        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'description',
      header: 'Description',
      size: 260,
      cell: (info) => (
        <span className="text-xs line-clamp-2" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'huntType',
      header: 'Hunt Type',
      size: 110,
      cell: (info) => {
        const val = info.getValue() || info.row.original.hunt_type || '—';
        return (
          <span
            className="text-xs font-medium px-2 py-1 rounded"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
          >
            {val}
          </span>
        );
      },
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 100,
      cell: (info) => <SeverityBadge severity={(info.getValue() || 'info').toLowerCase()} />,
    },
    {
      accessorKey: 'lastExecuted',
      header: 'Last Executed',
      size: 120,
      cell: (info) => {
        const val = info.getValue() || info.row.original.last_run || info.row.original.last_executed;
        return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{timeAgo(val)}</span>;
      },
    },
    {
      accessorKey: 'hitCount',
      header: 'Hit Count',
      size: 100,
      cell: (info) => {
        const v = info.getValue() ?? info.row.original.findings ?? info.row.original.hit_count ?? 0;
        return (
          <span className="text-sm font-bold" style={{ color: v > 0 ? 'var(--accent-warning)' : 'var(--text-muted)' }}>
            {v}
          </span>
        );
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 100,
      cell: (info) => {
        const qId = info.row.original.id || info.row.original.query_id;
        if (runningQueries[qId]) return <StatusBadge status="running" />;
        return <StatusBadge status={info.getValue() || 'active'} />;
      },
    },
    {
      id: 'actions',
      header: '',
      size: 80,
      enableSorting: false,
      cell: (info) => {
        const qId = info.row.original.id || info.row.original.query_id;
        const isRunning = runningQueries[qId];
        return (
          <button
            onClick={(e) => handleRunQuery(qId, e)}
            disabled={isRunning}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-200 hover:opacity-80 disabled:opacity-50 disabled:cursor-not-allowed"
            style={{
              backgroundColor: isRunning ? 'rgba(59,130,246,0.15)' : 'rgba(34,197,94,0.15)',
              color: isRunning ? '#3b82f6' : '#22c55e',
            }}
          >
            {isRunning ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5" />
            )}
            {isRunning ? 'Running' : 'Run'}
          </button>
        );
      },
    },
  ], [runningQueries, handleRunQuery]);

  /* ──────────────── IOC expanded row ──────────────── */

  const renderIocExpanded = useCallback((ioc) => {
    if (!ioc) return null;
    const indicator = ioc.indicator || ioc.value || '';
    const matchedList = ioc.matchedAssetsList || ioc.matched_assets_list || [];
    const ttps = ioc.ttps || ioc.mitreTechniques || [];
    return (
      <div
        className="rounded-lg border p-4 mt-2 mb-4 space-y-3"
        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>FULL INDICATOR</p>
            <div className="flex items-center gap-2">
              <code className="text-sm font-mono break-all" style={{ color: 'var(--accent-primary)' }}>{indicator}</code>
              <CopyButton text={indicator} />
            </div>
          </div>
          <div>
            <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>SOURCE DETAILS</p>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              {ioc.source || '—'} {ioc.feedName ? `(${ioc.feedName})` : ''}
            </p>
          </div>
        </div>
        {ttps.length > 0 && (
          <div>
            <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>MITRE ATT&CK TECHNIQUES</p>
            <div className="flex flex-wrap gap-1.5">
              {ttps.map((t) => <TtpPill key={t} technique={t} />)}
            </div>
          </div>
        )}
        {matchedList.length > 0 && (
          <div>
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-muted)' }}>
              MATCHED ASSETS ({matchedList.length})
            </p>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {matchedList.map((asset, idx) => (
                <div
                  key={asset.uid || asset.arn || idx}
                  className="flex items-center justify-between p-2 rounded text-xs"
                  style={{ backgroundColor: 'var(--bg-card)' }}
                >
                  <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                    {asset.name || asset.uid || asset.arn || `Asset ${idx + 1}`}
                  </span>
                  <span style={{ color: 'var(--text-muted)' }}>
                    {asset.resourceType || asset.type || ''}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
        {ioc.description && (
          <div>
            <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>DESCRIPTION</p>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{ioc.description}</p>
          </div>
        )}
      </div>
    );
  }, []);

  /* ──────────────── Hunt Query expanded row ──────────────── */

  const renderQueryExpanded = useCallback((query) => {
    if (!query) return null;
    const qId = query.id || query.query_id;
    const result = queryResults[qId];
    const params = query.parameters || query.params || [];
    const recentResults = query.recentResults || query.recent_results || [];
    return (
      <div
        className="rounded-lg border p-4 mt-2 mb-4 space-y-3"
        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>QUERY DETAILS</p>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{query.description || '—'}</p>
            {query.query && (
              <div className="mt-2">
                <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>QUERY</p>
                <code className="text-xs font-mono block p-2 rounded" style={{ backgroundColor: 'var(--bg-card)', color: 'var(--accent-primary)' }}>
                  {query.query}
                </code>
              </div>
            )}
          </div>
          {params.length > 0 && (
            <div>
              <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>PARAMETERS</p>
              <div className="space-y-1">
                {params.map((p, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs">
                    <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>{p.name || p.key}:</span>
                    <span style={{ color: 'var(--text-muted)' }}>{p.value || p.default || '—'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Inline execution result */}
        {result && (
          <div>
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-muted)' }}>EXECUTION RESULT</p>
            {result.error ? (
              <div className="rounded-lg p-3 border" style={{ backgroundColor: 'rgba(239,68,68,0.1)', borderColor: '#ef4444' }}>
                <p className="text-xs" style={{ color: '#ef4444' }}>{result.error}</p>
              </div>
            ) : (
              <div className="rounded-lg p-3 border" style={{ backgroundColor: 'rgba(34,197,94,0.1)', borderColor: '#22c55e' }}>
                <p className="text-xs font-medium mb-1" style={{ color: '#22c55e' }}>
                  Completed - {result.hitCount ?? result.hit_count ?? result.total ?? 0} hits found
                </p>
                {(result.results || result.findings || []).slice(0, 5).map((r, idx) => (
                  <div key={idx} className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                    {r.resource || r.name || r.description || JSON.stringify(r).slice(0, 100)}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Recent results */}
        {recentResults.length > 0 && !result && (
          <div>
            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--text-muted)' }}>RECENT RESULTS</p>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {recentResults.map((r, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2 rounded text-xs"
                  style={{ backgroundColor: 'var(--bg-card)' }}
                >
                  <span style={{ color: 'var(--text-secondary)' }}>{r.name || r.resource || `Result ${idx + 1}`}</span>
                  <span style={{ color: 'var(--text-muted)' }}>{timeAgo(r.timestamp || r.detected_at)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }, [queryResults]);

  /* ──────────────── filter bar component ──────────────── */

  function FilterSelect({ value, onChange, options, label }) {
    return (
      <div className="flex items-center gap-1.5">
        <label className="text-[10px] font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>{label}</label>
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="text-xs px-2 py-1.5 rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
        >
          {options.map((o) => (
            <option key={typeof o === 'string' ? o : o.value} value={typeof o === 'string' ? o : o.value}>
              {typeof o === 'string' ? (o === 'All' ? `All ${label}s` : o.charAt(0).toUpperCase() + o.slice(1)) : o.label}
            </option>
          ))}
        </select>
      </div>
    );
  }

  /* ──────────────── render ──────────────── */

  return (
    <div className="space-y-6">
      {/* Header + Breadcrumb */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <button
            onClick={() => router.push('/threats')}
            className="text-sm hover:underline"
            style={{ color: 'var(--text-muted)' }}
          >
            Threats
          </button>
          <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Hunting</span>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Threat Hunting</h1>
        {filterSummary && (
          <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
            <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
            <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{filterSummary}</span>
          </p>
        )}
      </div>

      {/* Threats Sub-Navigation */}
      <ThreatsSubNav />

      {/* Error state */}
      {error && (
        <div
          className="rounded-lg p-4 border flex items-center gap-3"
          style={{ backgroundColor: 'rgba(239,68,68,0.1)', borderColor: '#ef4444' }}
        >
          <ShieldAlert className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* KPI Metric Strip */}
      {loading ? (
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <LoadingSkeleton rows={1} cols={6} />
        </div>
      ) : (
        <MetricStrip
          groups={[
            {
              label: 'THREAT INTELLIGENCE',
              color: '#ef4444',
              cells: [
                {
                  label: 'ACTIVE IOCs',
                  value: kpi.activeIocs ?? kpi.active_iocs ?? iocs.filter((i) => (i.status || 'active') === 'active').length,
                  valueColor: '#ef4444',
                  noTrend: true,
                  context: 'indicators tracked',
                },
                {
                  label: 'CRITICAL IOCs',
                  value: kpi.criticalIocs ?? kpi.critical_iocs ?? iocs.filter((i) => (i.severity || '').toLowerCase() === 'critical').length,
                  valueColor: '#ef4444',
                  noTrend: true,
                  context: 'immediate action',
                },
                {
                  label: 'MATCHED ASSETS',
                  value: kpi.matchedAssets ?? kpi.matched_assets ?? 0,
                  valueColor: '#f97316',
                  noTrend: true,
                  context: 'assets affected',
                },
              ],
            },
            {
              label: 'HUNT OPERATIONS',
              color: '#3b82f6',
              cells: [
                {
                  label: 'HUNT QUERIES',
                  value: kpi.huntQueries ?? kpi.hunt_queries ?? huntQueries.length,
                  noTrend: true,
                  context: 'active hunts',
                },
                {
                  label: 'TOTAL HITS',
                  value: kpi.totalHits ?? kpi.total_hits ?? 0,
                  valueColor: '#eab308',
                  noTrend: true,
                  context: 'across all queries',
                },
                {
                  label: 'FALSE POSITIVE RATE',
                  value: kpi.falsePositiveRate ?? kpi.false_positive_rate ?? '—',
                  noTrend: true,
                  context: 'of all hits',
                },
              ],
            },
          ]}
        />
      )}

      {/* Tabs */}
      <div
        className="flex border-b"
        style={{ borderColor: 'var(--border-primary)' }}
      >
        <button
          onClick={() => setActiveTab(TAB_IOC)}
          className="px-5 py-3 text-sm font-medium transition-colors duration-200 relative"
          style={{
            color: activeTab === TAB_IOC ? 'var(--accent-primary)' : 'var(--text-muted)',
          }}
        >
          <span className="flex items-center gap-2">
            <Crosshair className="w-4 h-4" />
            IOC Intelligence
          </span>
          {activeTab === TAB_IOC && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5" style={{ backgroundColor: 'var(--accent-primary)' }} />
          )}
        </button>
        <button
          onClick={() => setActiveTab(TAB_HUNT)}
          className="px-5 py-3 text-sm font-medium transition-colors duration-200 relative"
          style={{
            color: activeTab === TAB_HUNT ? 'var(--accent-primary)' : 'var(--text-muted)',
          }}
        >
          <span className="flex items-center gap-2">
            <SearchCode className="w-4 h-4" />
            Hunt Queries
          </span>
          {activeTab === TAB_HUNT && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5" style={{ backgroundColor: 'var(--accent-primary)' }} />
          )}
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === TAB_IOC && (
        <div className="space-y-4">
          {/* Filter bar */}
          <div
            className="flex flex-wrap items-center gap-3 p-3 rounded-lg border"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <FilterSelect value={iocTypeFilter} onChange={setIocTypeFilter} options={IOC_TYPE_OPTIONS} label="Type" />
            <FilterSelect value={iocSeverityFilter} onChange={setIocSeverityFilter} options={SEVERITY_OPTIONS} label="Severity" />
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  placeholder="Search indicators..."
                  value={iocSearch}
                  onChange={(e) => setIocSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                  style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
                />
              </div>
            </div>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {filteredIocs.length} indicator{filteredIocs.length !== 1 ? 's' : ''}
            </span>
          </div>

          {loading ? (
            <LoadingSkeleton rows={8} cols={8} />
          ) : filteredIocs.length === 0 ? (
            <EmptyState
              icon={<Crosshair className="w-12 h-12" />}
              title="No IOC indicators found"
              description="No indicators of compromise match the current filters. Try adjusting your search criteria or check back later."
            />
          ) : (
            <div className="space-y-0">
              <DataTable
                columns={iocColumns}
                data={filteredIocs}
                pageSize={10}
                onRowClick={(row) => {
                  const r = row?.original || row;
                  const id = r.id || r.ioc_id;
                  setExpandedIoc((prev) => (prev === id ? null : id));
                }}
                emptyMessage="No IOC indicators found"
              />
              {/* Expanded IOC detail */}
              {expandedIoc && renderIocExpanded(filteredIocs.find((i) => (i.id || i.ioc_id) === expandedIoc))}
            </div>
          )}
        </div>
      )}

      {activeTab === TAB_HUNT && (
        <div className="space-y-4">
          {/* Filter bar */}
          <div
            className="flex flex-wrap items-center gap-3 p-3 rounded-lg border"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <FilterSelect value={huntTypeFilter} onChange={setHuntTypeFilter} options={HUNT_TYPE_OPTIONS} label="Type" />
            <FilterSelect value={huntSeverityFilter} onChange={setHuntSeverityFilter} options={SEVERITY_OPTIONS} label="Severity" />
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  placeholder="Search queries..."
                  value={huntSearch}
                  onChange={(e) => setHuntSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                  style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
                />
              </div>
            </div>
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {filteredQueries.length} quer{filteredQueries.length !== 1 ? 'ies' : 'y'}
            </span>
          </div>

          {loading ? (
            <LoadingSkeleton rows={8} cols={7} />
          ) : filteredQueries.length === 0 ? (
            <EmptyState
              icon={<SearchCode className="w-12 h-12" />}
              title="No hunt queries found"
              description="No hunt queries match the current filters. Try adjusting your search criteria or check back later."
            />
          ) : (
            <div className="space-y-0">
              <DataTable
                columns={huntColumns}
                data={filteredQueries}
                pageSize={10}
                onRowClick={(row) => {
                  const r = row?.original || row;
                  const id = r.id || r.query_id;
                  setExpandedQuery((prev) => (prev === id ? null : id));
                }}
                emptyMessage="No hunt queries found"
              />
              {/* Expanded query detail */}
              {expandedQuery && renderQueryExpanded(filteredQueries.find((q) => (q.id || q.query_id) === expandedQuery))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
