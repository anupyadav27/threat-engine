'use client';

/**
 * Attack Paths Page — /attack-paths/ (AP-REDESIGN-03)
 *
 * Layout:
 *   KPI bar (6 metrics)
 *   ChokeBar (sticky, always visible)
 *   Filter + GroupBy row
 *   Grouped path list (accordion)
 *   Pagination (20 per page)
 *
 * Data: fetchView('attack-paths', params) → BFF /api/v1/views/attack-paths
 *
 * Security:
 *   - Viewer: KPI bar + ChokeBar + row list visible, no expand, restriction banner
 *   - policy_statement: NEVER rendered (only in PathDetailPanel)
 *   - credential_ref: NEVER rendered anywhere
 *   - No mock / fallback data — 503 shows error state only
 */

import {
  useEffect, useState, useMemo, useCallback, useRef,
} from 'react';
import {
  Network, AlertTriangle, RotateCcw, ChevronDown, ChevronUp, Search,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import ChokeBar from './ChokeBar';
import GroupBySelector from './GroupBySelector';
import AttackPathRow from './AttackPathRow';
import AttackPathExpanded from './AttackPathExpanded';
import styles from './attack-paths.module.css';

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_COLOR  = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#6b7280' };
const SEV_BG     = { critical: 'rgba(239,68,68,0.12)', high: 'rgba(249,115,22,0.12)', medium: 'rgba(234,179,8,0.12)', low: 'rgba(107,114,128,0.12)' };
const SEV_BORDER = { critical: 'rgba(239,68,68,0.35)', high: 'rgba(249,115,22,0.35)', medium: 'rgba(234,179,8,0.35)', low: 'rgba(107,114,128,0.35)' };

const SEVERITIES       = ['all', 'critical', 'high', 'medium', 'low'];
const ENTRY_TYPES      = ['all', 'internet', 'vpn', 'onprem', 'peer_account'];
const PAGE_SIZE        = 20;
const DEBOUNCE_MS      = 400;

// ── Grouping function ─────────────────────────────────────────────────────────

function groupPaths(paths, groupBy) {
  return paths.reduce((acc, path) => {
    let key;
    switch (groupBy) {
      case 'severity':
        key = path.severity || 'unknown';
        break;
      case 'crown_jewel':
        key = `${path.crown_jewel_type || 'resource'}: ${(path.crown_jewel_uid || 'unknown').slice(-20)}`;
        break;
      case 'entry_point':
        key = path.entry_point_type || 'unknown';
        break;
      case 'technique':
        key = path.attack_technique_chain?.[0]?.technique_id
          ?? path.attack_technique_chain?.[0]
          ?? 'Unknown';
        break;
      case 'cdr_status':
        key = path.has_active_cdr_actor ? 'CDR Live' : 'Dormant';
        break;
      default:
        key = path.severity || 'unknown';
    }
    if (!acc[key]) acc[key] = [];
    acc[key].push(path);
    return acc;
  }, {});
}

// Sort group keys by priority (severity ordering, then alphabetical)
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function sortGroupKeys(keys, groupBy) {
  if (groupBy === 'severity') {
    return [...keys].sort((a, b) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9));
  }
  if (groupBy === 'cdr_status') {
    return ['CDR Live', 'Dormant'].filter(k => keys.includes(k));
  }
  return [...keys].sort((a, b) => a.localeCompare(b));
}

// ── KPI Bar ───────────────────────────────────────────────────────────────────

function KpiBar({ kpis, total, onSevFilter }) {
  const cells = [
    { label: 'Total Paths',       value: total,                            color: null,      onClick: null },
    { label: 'Critical',          value: kpis?.critical ?? 0,              color: '#ef4444', onClick: () => onSevFilter('critical') },
    { label: 'High',              value: kpis?.high ?? 0,                  color: '#f97316', onClick: () => onSevFilter('high') },
    { label: 'High Confidence',   value: kpis?.confirmed_paths ?? 0,       color: '#22c55e', onClick: null },
    { label: 'Choke Points',      value: kpis?.choke_points ?? 0,          color: '#a855f7', onClick: null },
    { label: 'CDR Live Paths',    value: kpis?.paths_with_active_cdr ?? 0, color: '#ef4444', onClick: null },
  ];

  return (
    <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
      {cells.map(({ label, value, color, onClick }) => (
        <button
          key={label}
          onClick={onClick || undefined}
          className="rounded-xl border px-3 py-3 text-left transition-all"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: color ? `${color}30` : 'rgba(255,255,255,0.07)',
            cursor: onClick ? 'pointer' : 'default',
          }}
        >
          <div
            className="text-xl font-bold tabular-nums"
            style={{ color: color || 'var(--text-primary)' }}
          >
            {value}
          </div>
          <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-secondary)' }}>
            {label}
          </div>
        </button>
      ))}
    </div>
  );
}

// ── Skeleton KPI ──────────────────────────────────────────────────────────────

function SkeletonKpi() {
  return (
    <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="h-16 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
      ))}
    </div>
  );
}

// ── Severity Badge ────────────────────────────────────────────────────────────

function SevBadge({ severity }) {
  const color  = SEV_COLOR[severity]  || '#6b7280';
  const bg     = SEV_BG[severity]     || 'rgba(107,114,128,0.12)';
  const border = SEV_BORDER[severity] || 'rgba(107,114,128,0.35)';
  return (
    <span
      className="text-[9px] font-bold px-1.5 py-0.5 rounded-full uppercase tracking-wide"
      style={{ backgroundColor: bg, color, border: `1px solid ${border}` }}
    >
      {severity}
    </span>
  );
}

// ── Filter Row ────────────────────────────────────────────────────────────────

function FilterRow({
  search, onSearchChange,
  severity, onSev,
  entryType, onEntry,
  groupBy, onGroupBy,
  activeFilterCount,
  onReset,
}) {
  return (
    <div className="space-y-2">
      {/* Top line: search + group-by + reset */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search
            className="absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
            style={{ width: 13, height: 13, color: 'var(--text-secondary)' }}
          />
          <input
            type="text"
            value={search}
            onChange={e => onSearchChange(e.target.value)}
            placeholder="Search paths…"
            className="w-full pl-8 pr-3 py-1.5 rounded-lg border text-[11px] focus:outline-none"
            style={{
              backgroundColor: 'var(--bg-secondary)',
              borderColor: 'rgba(255,255,255,0.1)',
              color: 'var(--text-primary)',
            }}
          />
        </div>

        <GroupBySelector value={groupBy} onChange={onGroupBy} />

        {activeFilterCount > 0 && (
          <button
            onClick={onReset}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[10px] font-medium hover:opacity-80"
            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
          >
            <RotateCcw style={{ width: 11, height: 11 }} /> Reset
            <span
              className="ml-1 text-[9px] font-bold px-1 py-0.5 rounded-full"
              style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
            >
              {activeFilterCount}
            </span>
          </button>
        )}
      </div>

      {/* Filter chips row */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* Severity */}
        <div className="flex items-center gap-1">
          {SEVERITIES.map(s => (
            <button
              key={s}
              onClick={() => onSev(s)}
              className="text-[10px] px-2 py-0.5 rounded-full border font-medium capitalize transition-all"
              style={{
                backgroundColor: severity === s
                  ? s === 'all' ? 'var(--accent-primary)' : SEV_BG[s]
                  : 'var(--bg-secondary)',
                color: severity === s
                  ? s === 'all' ? '#fff' : SEV_COLOR[s]
                  : 'var(--text-secondary)',
                borderColor: severity === s
                  ? s === 'all' ? 'var(--accent-primary)' : SEV_BORDER[s]
                  : 'var(--border-primary)',
              }}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="w-px h-4 bg-white/10 flex-shrink-0" />

        {/* Entry type */}
        <div className="flex items-center gap-1">
          {ENTRY_TYPES.map(e => (
            <button
              key={e}
              onClick={() => onEntry(e)}
              className="text-[10px] px-2 py-0.5 rounded-full border font-medium capitalize transition-all"
              style={{
                backgroundColor: entryType === e ? 'rgba(14,165,233,0.15)' : 'var(--bg-secondary)',
                color: entryType === e ? '#0ea5e9' : 'var(--text-secondary)',
                borderColor: entryType === e ? '#0ea5e9' : 'var(--border-primary)',
              }}
            >
              {e === 'peer_account' ? 'Peer' : e}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Group Section ─────────────────────────────────────────────────────────────

function GroupSection({
  groupKey,
  paths,
  expandedPathId,
  onTogglePath,
  activeChoke,
  detailCache,
  isViewer,
}) {
  const [collapsed, setCollapsed] = useState(false);
  const count = paths.length;

  return (
    <div className="space-y-1">
      {/* Group header */}
      <button
        onClick={() => setCollapsed(c => !c)}
        className={styles.groupHeader}
      >
        <span
          className="text-[10px] font-bold uppercase tracking-wide flex-1 text-left truncate"
          style={{ color: 'var(--text-primary)' }}
        >
          {groupKey}
        </span>
        <span
          className="text-[9px] font-bold px-1.5 py-0.5 rounded-full flex-shrink-0"
          style={{ backgroundColor: 'rgba(255,255,255,0.07)', color: 'var(--text-secondary)' }}
        >
          {count}
        </span>
        {collapsed
          ? <ChevronDown style={{ width: 11, height: 11, color: 'var(--text-secondary)', flexShrink: 0 }} />
          : <ChevronUp   style={{ width: 11, height: 11, color: 'var(--text-secondary)', flexShrink: 0 }} />
        }
      </button>

      {/* Path rows */}
      {!collapsed && (
        <div className="space-y-1 pl-1">
          {paths.map(path => {
            const isExpanded = expandedPathId === path.path_id;
            const chokeMatch = activeChoke && path.choke_node_uid === activeChoke;

            return (
              <div key={path.path_id}>
                <AttackPathRow
                  path={path}
                  isExpanded={isExpanded}
                  onToggle={onTogglePath}
                  chokeHighlight={!!chokeMatch}
                  isViewer={isViewer}
                />

                {isExpanded && (
                  <AttackPathExpanded
                    pathId={path.path_id}
                    detailCache={detailCache}
                    onClose={() => onTogglePath(path.path_id)}
                  />
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Pagination ────────────────────────────────────────────────────────────────

function Pagination({ page, totalPages, onPage }) {
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-center gap-2 pt-2">
      <button
        disabled={page === 1}
        onClick={() => onPage(page - 1)}
        className="text-[11px] px-3 py-1.5 rounded-lg border font-medium disabled:opacity-40 transition-all"
        style={{
          backgroundColor: 'var(--bg-secondary)',
          borderColor: 'var(--border-primary)',
          color: 'var(--text-secondary)',
        }}
      >
        Previous
      </button>
      <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>
        Page {page} of {totalPages}
      </span>
      <button
        disabled={page === totalPages}
        onClick={() => onPage(page + 1)}
        className="text-[11px] px-3 py-1.5 rounded-lg border font-medium disabled:opacity-40 transition-all"
        style={{
          backgroundColor: 'var(--bg-secondary)',
          borderColor: 'var(--border-primary)',
          color: 'var(--text-secondary)',
        }}
      >
        Next
      </button>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AttackPathsPage() {
  const { account }  = useGlobalFilter();
  const { role }     = useAuth();
  const isViewer     = role === 'viewer';

  // Data state
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [data, setData]       = useState(null);

  // Filter state
  const [severity, setSeverity]     = useState('all');
  const [entryType, setEntryType]   = useState('all');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch]         = useState(''); // debounced value
  const [page, setPage]             = useState(1);
  const [groupBy, setGroupBy]       = useState('severity');

  // Choke filter
  const [activeChoke, setActiveChoke] = useState(null);

  // Accordion state
  const [expandedPathId, setExpandedPathId] = useState(null);

  // Detail fetch cache — persisted across row open/close
  const detailCache = useRef(new Map());

  // ── Debounce search ─────────────────────────────────────────────────────────

  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(searchInput);
      setPage(1);
    }, DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput]);

  // ── Fetch main view ─────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setExpandedPathId(null);

    const params = {};
    if (severity !== 'all')    params.severity         = severity;
    if (entryType !== 'all')   params.entry_point_type = entryType;
    if (search)                params.search           = search;
    if (page > 1)              params.page             = page;
    params.page_size = PAGE_SIZE;

    fetchView('attack-paths', params).then(result => {
      if (cancelled) return;
      if (result?.error) {
        setError(result.error);
        setLoading(false);
        return;
      }
      setData(result);
      setLoading(false);
    }).catch(err => {
      if (cancelled) return;
      setError(err?.message || 'Failed to load attack paths');
      setLoading(false);
    });

    return () => { cancelled = true; };
  }, [account, severity, entryType, search, page]);

  // ── Client-side filtering (additional) ──────────────────────────────────────

  const filteredPaths = useMemo(() => {
    let paths = data?.paths || [];

    // Choke filter
    if (activeChoke) {
      paths = paths.filter(p => p.choke_node_uid === activeChoke);
    }

    return paths;
  }, [data, activeChoke]);

  // ── Grouping ────────────────────────────────────────────────────────────────

  const grouped = useMemo(() => groupPaths(filteredPaths, groupBy), [filteredPaths, groupBy]);
  const sortedGroupKeys = useMemo(() => sortGroupKeys(Object.keys(grouped), groupBy), [grouped, groupBy]);

  // ── Pagination ──────────────────────────────────────────────────────────────

  const total      = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  // ── Active filter count ─────────────────────────────────────────────────────

  const activeFilterCount = [
    severity !== 'all',
    entryType !== 'all',
    search !== '',
  ].filter(Boolean).length;

  // ── Handlers ────────────────────────────────────────────────────────────────

  const handleTogglePath = useCallback((pathId) => {
    setExpandedPathId(prev => prev === pathId ? null : pathId);
  }, []);

  const handleSevFilter = useCallback((s) => {
    setSeverity(prev => prev === s ? 'all' : s);
    setPage(1);
    setExpandedPathId(null);
  }, []);

  const handleReset = useCallback(() => {
    setSeverity('all');
    setEntryType('all');
    setSearchInput('');
    setSearch('');
    setPage(1);
    setExpandedPathId(null);
    setActiveChoke(null);
  }, []);

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4">
      {/* Page header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Attack Paths
          </h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
            Multi-step attack chains from entry points to crown jewels
          </p>
        </div>
      </div>

      {/* Loading skeleton */}
      {loading && (
        <div className="space-y-4">
          <SkeletonKpi />
          <div className="h-10 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="h-14 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
            ))}
          </div>
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div
          className="rounded-xl p-5 border"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.3)' }}
        >
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                Failed to load attack paths
              </p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Main content */}
      {!loading && !error && (
        <>
          {/* KPI bar — always visible */}
          <KpiBar
            kpis={data?.kpis}
            total={total}
            onSevFilter={handleSevFilter}
          />

          {/* ChokeBar — sticky, always visible */}
          <ChokeBar
            chokePoints={data?.choke_points_preview || []}
            activeChoke={activeChoke}
            onChipClick={setActiveChoke}
          />

          {/* Viewer restriction banner */}
          {isViewer && (
            <div
              className="rounded-xl border px-5 py-4 text-center text-sm"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'rgba(255,255,255,0.08)',
                color: 'var(--text-secondary)',
              }}
            >
              Contact your admin for investigation access
            </div>
          )}

          {/* Filter row — viewer still sees it, but expand is disabled */}
          <FilterRow
            search={searchInput}
            onSearchChange={v => { setSearchInput(v); }}
            severity={severity}
            onSev={handleSevFilter}
            entryType={entryType}
            onEntry={v => { setEntryType(v); setPage(1); setExpandedPathId(null); }}
            groupBy={groupBy}
            onGroupBy={v => { setGroupBy(v); setExpandedPathId(null); }}
            activeFilterCount={activeFilterCount}
            onReset={handleReset}
          />

          {/* Path count note */}
          {(activeFilterCount > 0 || activeChoke) && (
            <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              Showing{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{filteredPaths.length}</strong>
              {' '}of {total} paths
              {activeChoke && (
                <span style={{ color: '#f59e0b' }}> (choke filter active)</span>
              )}
            </p>
          )}

          {/* Empty state */}
          {filteredPaths.length === 0 && (
            <div
              className="rounded-xl border py-14 text-center space-y-2"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'rgba(255,255,255,0.07)' }}
            >
              <Network className="w-10 h-10 mx-auto opacity-25" />
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                {activeFilterCount > 0 || activeChoke
                  ? 'No paths match these filters'
                  : 'No Attack Paths Detected'}
              </p>
              <p className="text-xs max-w-sm mx-auto" style={{ color: 'var(--text-secondary)' }}>
                {activeFilterCount > 0 || activeChoke
                  ? 'Try adjusting filters or clearing the choke filter.'
                  : 'No multi-step attack paths were found. Run a full pipeline scan (Discovery → Check → Threat → Attack Path) to discover paths.'}
              </p>
            </div>
          )}

          {/* Grouped path list */}
          {filteredPaths.length > 0 && (
            <div className="space-y-3">
              {sortedGroupKeys.map(groupKey => (
                <GroupSection
                  key={groupKey}
                  groupKey={groupKey}
                  paths={grouped[groupKey]}
                  expandedPathId={expandedPathId}
                  onTogglePath={handleTogglePath}
                  activeChoke={activeChoke}
                  detailCache={detailCache}
                  isViewer={isViewer}
                />
              ))}
            </div>
          )}

          {/* Pagination */}
          <Pagination page={page} totalPages={totalPages} onPage={p => { setPage(p); setExpandedPathId(null); }} />
        </>
      )}
    </div>
  );
}
