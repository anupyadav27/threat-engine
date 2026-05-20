'use client';

/**
 * Attack Paths Page — /attack-paths/ (Orca-style 3-zone layout)
 *
 * Zones:
 *   Left  (280px) — ranked path list with filter + pagination
 *   Center (flex) — React Flow canvas for the selected path
 *   Right  (320px) — node detail slide-in panel on canvas node click
 *
 * Data: fetchView('attack-paths', params) → BFF /api/v1/views/attack-paths
 *       fetchView('attack-paths/{id}')    → BFF /api/v1/views/attack-paths/{id}
 *
 * Security:
 *   - Viewer: KPI bar visible, path list visible (no canvas / detail), restriction banner
 *   - policy_statement: NEVER rendered
 *   - credential_ref: NEVER rendered anywhere
 *   - No mock / fallback data — 503 shows error state only
 */

import {
  useEffect, useState, useMemo, useCallback, useRef,
} from 'react';
import {
  Network, AlertTriangle, RotateCcw, Search, ChevronDown, ChevronUp,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import ChokeBar from './ChokeBar';
import GroupBySelector from './GroupBySelector';
import dynamic from 'next/dynamic';
import AttackPathRow from './AttackPathRow';
import PathDetailPanel from './PathDetailPanel';

// React Flow uses browser-only APIs (window, ResizeObserver) — must not SSR
const AttackPathCanvas = dynamic(() => import('./AttackPathCanvas'), { ssr: false });
import styles from './attack-paths.module.css';

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_COLOR  = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#6b7280' };
const SEV_BG     = { critical: 'rgba(239,68,68,0.12)', high: 'rgba(249,115,22,0.12)', medium: 'rgba(234,179,8,0.12)', low: 'rgba(107,114,128,0.12)' };
const SEV_BORDER = { critical: 'rgba(239,68,68,0.35)', high: 'rgba(249,115,22,0.35)', medium: 'rgba(234,179,8,0.35)', low: 'rgba(107,114,128,0.35)' };

const SEVERITIES  = ['all', 'critical', 'high', 'medium', 'low'];
const ENTRY_TYPES = ['all', 'internet', 'vpn', 'onprem', 'peer_account'];
const PAGE_SIZE   = 25;
const DEBOUNCE_MS = 400;
const SEV_ORDER   = { critical: 0, high: 1, medium: 2, low: 3 };

// ── Grouping helpers ──────────────────────────────────────────────────────────

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
    { label: 'Total Paths',     value: total,                            color: null,      onClick: null },
    { label: 'Critical',        value: kpis?.critical ?? 0,              color: '#ef4444', onClick: () => onSevFilter('critical') },
    { label: 'High',            value: kpis?.high ?? 0,                  color: '#f97316', onClick: () => onSevFilter('high') },
    { label: 'High Confidence', value: kpis?.confirmed_paths ?? 0,       color: '#22c55e', onClick: null },
    { label: 'Choke Points',    value: kpis?.choke_points ?? 0,          color: '#a855f7', onClick: null },
    { label: 'CDR Live',        value: kpis?.paths_with_active_cdr ?? 0, color: '#ef4444', onClick: null },
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
          <div className="text-xl font-bold tabular-nums" style={{ color: color || 'var(--text-primary)' }}>
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

function SkeletonKpi() {
  return (
    <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="h-16 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
      ))}
    </div>
  );
}

// ── Left panel: compact filter ────────────────────────────────────────────────

function LeftFilter({
  search, onSearchChange,
  severity, onSev,
  entryType, onEntry,
  groupBy, onGroupBy,
  activeFilterCount, onReset,
}) {
  return (
    <div style={{ padding: '10px 10px 8px', borderBottom: '1px solid rgba(255,255,255,0.07)', display: 'flex', flexDirection: 'column', gap: 8 }}>
      {/* Search */}
      <div style={{ position: 'relative' }}>
        <Search
          style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', width: 12, height: 12, color: 'rgba(255,255,255,0.3)', pointerEvents: 'none' }}
        />
        <input
          type="text"
          value={search}
          onChange={e => onSearchChange(e.target.value)}
          placeholder="Search paths…"
          style={{
            width: '100%',
            paddingLeft: 28,
            paddingRight: 8,
            paddingTop: 6,
            paddingBottom: 6,
            borderRadius: 8,
            border: '1px solid rgba(255,255,255,0.1)',
            backgroundColor: 'rgba(255,255,255,0.04)',
            color: 'rgba(255,255,255,0.85)',
            fontSize: 11,
            outline: 'none',
            boxSizing: 'border-box',
          }}
        />
      </div>

      {/* Severity chips */}
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        {SEVERITIES.map(s => (
          <button
            key={s}
            onClick={() => onSev(s)}
            style={{
              fontSize: 9,
              padding: '2px 7px',
              borderRadius: 20,
              border: `1px solid ${severity === s ? (s === 'all' ? 'var(--accent-primary, #3b82f6)' : SEV_BORDER[s]) : 'rgba(255,255,255,0.1)'}`,
              backgroundColor: severity === s
                ? s === 'all' ? 'rgba(59,130,246,0.2)' : SEV_BG[s]
                : 'rgba(255,255,255,0.04)',
              color: severity === s
                ? s === 'all' ? '#60a5fa' : SEV_COLOR[s]
                : 'rgba(255,255,255,0.4)',
              fontWeight: 600,
              cursor: 'pointer',
              textTransform: 'capitalize',
              transition: 'all 0.12s',
            }}
          >
            {s}
          </button>
        ))}
      </div>

      {/* Group-by + reset row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <GroupBySelector value={groupBy} onChange={onGroupBy} />
        {activeFilterCount > 0 && (
          <button
            onClick={onReset}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              padding: '3px 8px',
              borderRadius: 6,
              border: '1px solid rgba(255,255,255,0.1)',
              backgroundColor: 'rgba(255,255,255,0.04)',
              color: 'rgba(255,255,255,0.45)',
              fontSize: 9,
              cursor: 'pointer',
            }}
          >
            <RotateCcw style={{ width: 9, height: 9 }} /> Reset
          </button>
        )}
      </div>
    </div>
  );
}

// ── Left panel: group section ─────────────────────────────────────────────────

function GroupSection({ groupKey, paths, selectedPathId, onSelectPath, activeChoke, isViewer }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div>
      <button
        onClick={() => setCollapsed(c => !c)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '5px 8px',
          borderRadius: 6,
          backgroundColor: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.06)',
          cursor: 'pointer',
          marginBottom: 3,
        }}
      >
        <span style={{ flex: 1, textAlign: 'left', fontSize: 9, fontWeight: 700, color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', letterSpacing: '0.05em', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {groupKey}
        </span>
        <span style={{ fontSize: 8, fontWeight: 700, padding: '1px 5px', borderRadius: 10, backgroundColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.35)', flexShrink: 0 }}>
          {paths.length}
        </span>
        {collapsed
          ? <ChevronDown style={{ width: 10, height: 10, color: 'rgba(255,255,255,0.3)', flexShrink: 0 }} />
          : <ChevronUp   style={{ width: 10, height: 10, color: 'rgba(255,255,255,0.3)', flexShrink: 0 }} />
        }
      </button>

      {!collapsed && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, paddingLeft: 2 }}>
          {paths.map(path => (
            <AttackPathRow
              key={path.path_id}
              path={path}
              isSelected={selectedPathId === path.path_id}
              onSelect={onSelectPath}
              chokeHighlight={!!(activeChoke && path.choke_node_uid === activeChoke)}
              isViewer={isViewer}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Left panel: pagination ────────────────────────────────────────────────────

function Pagination({ page, totalPages, onPage }) {
  if (totalPages <= 1) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 10px', borderTop: '1px solid rgba(255,255,255,0.07)' }}>
      <button
        disabled={page === 1}
        onClick={() => onPage(page - 1)}
        style={{ fontSize: 10, padding: '4px 8px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)', backgroundColor: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.5)', cursor: page === 1 ? 'default' : 'pointer', opacity: page === 1 ? 0.4 : 1 }}
      >
        ← Prev
      </button>
      <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)' }}>
        {page}/{totalPages}
      </span>
      <button
        disabled={page === totalPages}
        onClick={() => onPage(page + 1)}
        style={{ fontSize: 10, padding: '4px 8px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)', backgroundColor: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.5)', cursor: page === totalPages ? 'default' : 'pointer', opacity: page === totalPages ? 0.4 : 1 }}
      >
        Next →
      </button>
    </div>
  );
}

// ── Canvas header strip ───────────────────────────────────────────────────────

function CanvasHeader({ path }) {
  if (!path) return null;
  const sevColor = SEV_COLOR[path.severity] || '#6b7280';
  const hops = path.depth ?? (path.node_uids?.length ?? 0);
  return (
    <div
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        zIndex: 10,
        padding: '8px 14px',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        backgroundColor: 'rgba(8,13,23,0.85)',
        backdropFilter: 'blur(8px)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      <span
        style={{ fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 20, backgroundColor: `${sevColor}20`, color: sevColor, textTransform: 'uppercase', border: `1px solid ${sevColor}35`, flexShrink: 0 }}
      >
        {path.severity}
      </span>
      <span style={{ flex: 1, fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,0.88)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {path.attack_name || path.title || 'Attack Path'}
      </span>
      <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', flexShrink: 0 }}>
        {hops} hop{hops !== 1 ? 's' : ''}
      </span>
      {path.confidence_level && (
        <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', flexShrink: 0 }}>
          {path.confidence_level}
        </span>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AttackPathsPage() {
  const { account }  = useGlobalFilter();
  const { role }     = useAuth();
  const isViewer     = role === 'viewer';

  // ── List data state ─────────────────────────────────────────────────────────
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [data, setData]       = useState(null);

  // ── Filter state ────────────────────────────────────────────────────────────
  const [severity, setSeverity]       = useState('all');
  const [entryType, setEntryType]     = useState('all');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch]           = useState('');
  const [page, setPage]               = useState(1);
  const [groupBy, setGroupBy]         = useState('severity');
  const [activeChoke, setActiveChoke] = useState(null);

  // ── Canvas / panel state ────────────────────────────────────────────────────
  const [selectedPathId, setSelectedPathId]   = useState(null);
  const [selectedNodeData, setSelectedNodeData] = useState(null);
  const [detail, setDetail]                   = useState(null);
  const [detailLoading, setDetailLoading]     = useState(false);
  const detailCache = useRef(new Map());

  // ── Debounce search ─────────────────────────────────────────────────────────
  useEffect(() => {
    const t = setTimeout(() => { setSearch(searchInput); setPage(1); }, DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput]);

  // ── Fetch path list ─────────────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    const params = { page, page_size: PAGE_SIZE };
    if (severity !== 'all')  params.severity         = severity;
    if (entryType !== 'all') params.entry_point_type = entryType;
    if (search)              params.search           = search;

    fetchView('attack-paths', params).then(result => {
      if (cancelled) return;
      if (result?.error) { setError(result.error); setLoading(false); return; }
      setData(result);
      setLoading(false);
    }).catch(err => {
      if (cancelled) return;
      setError(err?.message || 'Failed to load attack paths');
      setLoading(false);
    });

    return () => { cancelled = true; };
  }, [account, severity, entryType, search, page]);

  // ── Fetch selected path detail ──────────────────────────────────────────────
  useEffect(() => {
    if (!selectedPathId) { setDetail(null); setSelectedNodeData(null); return; }

    if (detailCache.current.has(selectedPathId)) {
      setDetail(detailCache.current.get(selectedPathId));
      setSelectedNodeData(null);
      return;
    }

    setDetailLoading(true);
    setDetail(null);
    setSelectedNodeData(null);

    fetchView(`attack-paths/${selectedPathId}`).then(result => {
      if (result?.error || result?.detail) {
        setDetailLoading(false);
        return;
      }
      detailCache.current.set(selectedPathId, result);
      setDetail(result);
      setDetailLoading(false);
    }).catch(() => setDetailLoading(false));
  }, [selectedPathId]);

  // ── Filtered + grouped paths ────────────────────────────────────────────────
  const filteredPaths = useMemo(() => {
    let paths = data?.paths || [];
    if (activeChoke) paths = paths.filter(p => p.choke_node_uid === activeChoke);
    return paths;
  }, [data, activeChoke]);

  const grouped       = useMemo(() => groupPaths(filteredPaths, groupBy), [filteredPaths, groupBy]);
  const sortedKeys    = useMemo(() => sortGroupKeys(Object.keys(grouped), groupBy), [grouped, groupBy]);
  const total         = data?.total ?? 0;
  const totalPages    = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const activeFilters = [severity !== 'all', entryType !== 'all', search !== ''].filter(Boolean).length;

  // Selected path metadata (for canvas header)
  const selectedPath = useMemo(
    () => filteredPaths.find(p => p.path_id === selectedPathId) ?? null,
    [filteredPaths, selectedPathId],
  );

  // ── Handlers ────────────────────────────────────────────────────────────────
  const handleSelectPath = useCallback((pathId) => {
    setSelectedPathId(pathId);
    setSelectedNodeData(null);
  }, []);

  const handleSevFilter = useCallback((s) => {
    setSeverity(prev => prev === s ? 'all' : s);
    setPage(1);
  }, []);

  const handleReset = useCallback(() => {
    setSeverity('all');
    setEntryType('all');
    setSearchInput('');
    setSearch('');
    setPage(1);
    setActiveChoke(null);
  }, []);

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Attack Paths
        </h1>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          Multi-step attack chains from entry points to crown jewels
        </p>
      </div>

      {/* Loading skeleton */}
      {loading && <SkeletonKpi />}

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
          {/* KPI bar */}
          <KpiBar kpis={data?.kpis} total={total} onSevFilter={handleSevFilter} />

          {/* ChokeBar */}
          <ChokeBar
            chokePoints={data?.choke_points_preview || []}
            activeChoke={activeChoke}
            onChipClick={setActiveChoke}
          />

          {/* Viewer restriction banner */}
          {isViewer && (
            <div
              className="rounded-xl border px-5 py-4 text-center text-sm"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'rgba(255,255,255,0.08)', color: 'var(--text-secondary)' }}
            >
              Contact your admin for investigation access
            </div>
          )}

          {/* ── 3-zone layout ──────────────────────────────────────────────── */}
          <div
            style={{
              display: 'flex',
              gap: 10,
              height: '70vh',
              minHeight: 500,
            }}
          >
            {/* LEFT: path list */}
            <div
              style={{
                width: 280,
                flexShrink: 0,
                display: 'flex',
                flexDirection: 'column',
                backgroundColor: 'var(--bg-card)',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 12,
                overflow: 'hidden',
              }}
            >
              <LeftFilter
                search={searchInput}
                onSearchChange={v => setSearchInput(v)}
                severity={severity}
                onSev={handleSevFilter}
                entryType={entryType}
                onEntry={v => { setEntryType(v); setPage(1); }}
                groupBy={groupBy}
                onGroupBy={v => setGroupBy(v)}
                activeFilterCount={activeFilters}
                onReset={handleReset}
              />

              {/* Path list (scrollable) */}
              <div style={{ flex: 1, overflowY: 'auto', padding: '8px 6px', display: 'flex', flexDirection: 'column', gap: 6 }}>
                {filteredPaths.length === 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, gap: 8 }}>
                    <Network style={{ width: 32, height: 32, opacity: 0.15 }} />
                    <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', textAlign: 'center' }}>
                      {activeFilters > 0 || activeChoke
                        ? 'No paths match these filters'
                        : 'No attack paths found'}
                    </p>
                  </div>
                )}

                {filteredPaths.length > 0 && sortedKeys.map(groupKey => (
                  <GroupSection
                    key={groupKey}
                    groupKey={groupKey}
                    paths={grouped[groupKey]}
                    selectedPathId={selectedPathId}
                    onSelectPath={handleSelectPath}
                    activeChoke={activeChoke}
                    isViewer={isViewer}
                  />
                ))}
              </div>

              <Pagination page={page} totalPages={totalPages} onPage={p => setPage(p)} />
            </div>

            {/* CENTER: canvas */}
            <div
              style={{
                flex: 1,
                minWidth: 0,
                position: 'relative',
                backgroundColor: '#080d17',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 12,
                overflow: 'hidden',
              }}
            >
              {/* Path context header */}
              <CanvasHeader path={selectedPath} />

              {/* Canvas (top padding when header is visible) */}
              <div
                style={{
                  position: 'absolute',
                  inset: 0,
                  top: selectedPath ? 40 : 0,
                }}
              >
                {isViewer ? (
                  <div
                    style={{
                      width: '100%',
                      height: '100%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexDirection: 'column',
                      gap: 10,
                      color: 'rgba(255,255,255,0.2)',
                    }}
                  >
                    <Network style={{ width: 40, height: 40, opacity: 0.2 }} />
                    <p style={{ fontSize: 12 }}>Canvas restricted for viewer role</p>
                  </div>
                ) : (
                  <AttackPathCanvas
                    detail={detail}
                    loading={detailLoading}
                    selectedNodeUid={selectedNodeData?.node_uid ?? null}
                    onNodeClick={setSelectedNodeData}
                  />
                )}
              </div>
            </div>

            {/* RIGHT: node detail panel */}
            {selectedNodeData && !isViewer && (
              <PathDetailPanel
                node={selectedNodeData}
                onClose={() => setSelectedNodeData(null)}
              />
            )}
          </div>
        </>
      )}
    </div>
  );
}
