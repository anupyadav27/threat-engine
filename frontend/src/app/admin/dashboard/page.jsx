'use client';

import { useState, useCallback, useRef, useEffect } from 'react';
import {
  LayoutGrid, CheckCircle, XCircle, AlertTriangle, Clock,
  RefreshCw, ChevronLeft, ChevronRight, Activity, X,
} from 'lucide-react';
import { useViewFetch } from '@/lib/use-view-fetch';
import { useAuth } from '@/lib/auth-context';

// ── Engine pipeline stage groups ────────────────────────────────────────────────
// Order determines render order. Add/reorder groups here — nowhere else.
const ENGINE_GROUPS = [
  {
    label: 'INGEST',
    engines: ['discoveries', 'inventory', 'onboarding'],
    variant: 'default',
  },
  {
    label: 'CHECK',
    engines: ['check', 'rule'],
    variant: 'default',
  },
  {
    label: 'ANALYSIS',
    engines: ['threat', 'iam', 'cdr', 'network-security', 'datasec', 'secops', 'vulnerability', 'container-sec'],
    variant: 'default',
  },
  {
    label: 'REPORTING',
    engines: ['compliance', 'risk', 'billing', 'platform-admin'],
    variant: 'default',
  },
  {
    label: 'ENTERPRISE',
    engines: ['ai-security', 'encryption', 'dbsec', 'fix-secops'],
    variant: 'enterprise',
  },
];

function partitionEnginesByGroup(engines) {
  const allGroupedNames = new Set(
    ENGINE_GROUPS.flatMap(g => g.engines.map(n => n.toLowerCase()))
  );
  const byName = Object.fromEntries(
    engines.map(e => [(e.name || '').toLowerCase(), e])
  );

  const groups = ENGINE_GROUPS.map(group => ({
    ...group,
    tiles: group.engines
      .map(name => byName[name.toLowerCase()])
      .filter(Boolean), // skip group entries with no matching engine tile in API response
  })).filter(g => g.tiles.length > 0); // skip empty groups entirely

  // Catch-all for engines not in any group
  const ungrouped = engines.filter(
    e => !allGroupedNames.has((e.name || '').toLowerCase())
  );
  if (ungrouped.length > 0) {
    groups.push({ label: 'OTHER', tiles: ungrouped, variant: 'default' });
  }

  return groups;
}

// ── Colour helpers ─────────────────────────────────────────────────────────────
function statusDot(color) {
  const MAP = {
    green:  { ring: 'rgba(16,185,129,0.25)', fill: '#10b981' },
    yellow: { ring: 'rgba(245,158,11,0.25)',  fill: '#f59e0b' },
    red:    { ring: 'rgba(239,68,68,0.25)',   fill: '#ef4444' },
    gray:   { ring: 'rgba(107,114,128,0.2)',  fill: '#6b7280' },
  };
  return MAP[color] || MAP.gray;
}

const SUB_STATUS_STYLES = {
  green:  { bg: 'rgba(16,185,129,0.12)',  color: '#34d399' },
  blue:   { bg: 'rgba(59,130,246,0.12)',  color: '#60a5fa' },
  yellow: { bg: 'rgba(245,158,11,0.12)',  color: '#fbbf24' },
  red:    { bg: 'rgba(239,68,68,0.12)',   color: '#f87171' },
  gray:   { bg: 'rgba(107,114,128,0.12)', color: '#9ca3af' },
};

const TIER_COLORS = {
  free:       '#9ca3af',
  starter:    '#60a5fa',
  pro:        '#a78bfa',
  enterprise: '#fbbf24',
};

// ── Sub-components ─────────────────────────────────────────────────────────────

function EngineTile({ engine: eng }) {
  const dot = statusDot(eng.status_color);
  return (
    <div
      className="p-3 space-y-1.5"
      style={{ backgroundColor: 'var(--bg-card)' }}
      aria-label={`Engine health: ${eng.name || 'unknown'} — ${eng.status_color || 'unknown'} — ${eng.latency_ms != null ? eng.latency_ms + 'ms' : 'latency unknown'} — ${eng.pod_count != null ? eng.pod_count + ' pods' : 'pod count unknown'}`}>
      {/* Status dot */}
      <div className="flex items-center gap-1.5">
        <span className="relative flex h-2.5 w-2.5">
          <span className="absolute inline-flex h-full w-full rounded-full opacity-75"
            style={{
              backgroundColor: dot.ring,
              animation: eng.status_color === 'green' ? 'ping 2s cubic-bezier(0,0,0.2,1) infinite' : 'none',
            }} />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5"
            style={{ backgroundColor: dot.fill }} />
        </span>
        <span className="text-[10px] font-medium uppercase truncate"
          style={{ color: 'var(--text-secondary)' }}>
          {eng.name || '—'}
        </span>
      </div>
      {/* Latency */}
      {eng.latency_ms != null && (
        <div className="text-[10px] tabular-nums" style={{ color: 'var(--text-muted)' }}>
          {eng.latency_ms}ms
        </div>
      )}
      {/* Pod count */}
      {eng.pod_count != null && (
        <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
          {eng.pod_count} pod{eng.pod_count !== 1 ? 's' : ''}
        </div>
      )}
    </div>
  );
}

function EngineGroupPanel({ label, tiles, variant = 'default' }) {
  const isEnterprise = variant === 'enterprise';
  return (
    <div className="space-y-2">
      {/* Group label */}
      <div className="text-[10px] font-semibold uppercase tracking-widest px-1"
        style={{ color: isEnterprise ? 'var(--accent-warning)' : 'var(--text-muted)' }}>
        {label}
      </div>
      {/* Tile grid */}
      <div className="rounded-lg overflow-hidden"
        style={{
          backgroundColor: 'var(--bg-card)',
          border: isEnterprise
            ? '1px solid rgba(251,191,36,0.25)'
            : '1px solid var(--border-primary)',
        }}>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-px"
          style={{ backgroundColor: isEnterprise ? 'rgba(251,191,36,0.08)' : 'var(--border-primary)' }}>
          {tiles.map((eng, i) => (
            <EngineTile key={eng.name || i} engine={eng} />
          ))}
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, sublabel, color, onClick, filterActive, severity, ariaLabel }) {
  const isInteractive = !!onClick;
  const valueColor = severity === 'ok'
    ? 'var(--accent-success)'
    : severity === 'warn'
      ? 'var(--accent-warning)'
      : severity === 'danger'
        ? 'var(--accent-danger)'
        : (color || 'var(--accent-primary)');

  return (
    <div
      role={isInteractive ? 'button' : undefined}
      tabIndex={isInteractive ? 0 : undefined}
      aria-label={isInteractive ? (ariaLabel || `Filter by ${label}`) : undefined}
      aria-pressed={isInteractive ? filterActive : undefined}
      onClick={isInteractive ? onClick : undefined}
      onKeyDown={isInteractive ? (e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } }) : undefined}
      className={`rounded-lg p-4 space-y-1 transition-all ${isInteractive ? 'cursor-pointer hover:border-[--accent-primary]' : ''}`}
      style={{
        backgroundColor: 'var(--bg-card)',
        border: filterActive
          ? '2px solid var(--accent-primary)'
          : '1px solid var(--border-primary)',
        outline: 'none',
      }}>
      <div className="text-[10px] uppercase tracking-wider font-medium" style={{ color: 'var(--text-muted)' }}>
        {label}
      </div>
      <div className="text-2xl font-bold tabular-nums" style={{ color: valueColor }}>
        {typeof value === 'number' ? value.toLocaleString() : value ?? '—'}
      </div>
      {sublabel && (
        <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{sublabel}</div>
      )}
    </div>
  );
}

// ── Trial countdown helper ─────────────────────────────────────────────────────
function trialCountdown(trialEndAt) {
  if (!trialEndAt) return '—';
  const endMs = typeof trialEndAt === 'number'
    ? (trialEndAt > 1e10 ? trialEndAt : trialEndAt * 1000)
    : new Date(trialEndAt).getTime();
  const daysLeft = Math.ceil((endMs - Date.now()) / 86400000);
  if (daysLeft < 0) return 'Expired';
  if (daysLeft === 0) return 'Expires today';
  return `${daysLeft}d left`;
}

// ── ActionPopover ──────────────────────────────────────────────────────────────
function ActionPopover({ title, confirmLabel, body, onConfirm, onCancel }) {
  const [state, setState] = useState('idle'); // idle | loading | success | error
  const [errorMsg, setErrorMsg] = useState('');
  const popoverRef = useRef(null);

  // Focus trap: on mount, focus the confirm button
  useEffect(() => {
    popoverRef.current?.querySelector('[data-autofocus]')?.focus();
  }, []);

  // Escape closes + Tab cycles within popover (AC11)
  useEffect(() => {
    function handler(e) {
      if (e.key === 'Escape') { onCancel(); return; }
      if (e.key === 'Tab' && popoverRef.current) {
        const focusable = Array.from(
          popoverRef.current.querySelectorAll(
            'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          )
        );
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey) {
          if (document.activeElement === first) { e.preventDefault(); last.focus(); }
        } else {
          if (document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
      }
    }
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onCancel]);

  // Auto-dismiss after 3s on success
  useEffect(() => {
    if (state === 'success') {
      const t = setTimeout(onCancel, 3000);
      return () => clearTimeout(t);
    }
  }, [state, onCancel]);

  async function handleConfirm() {
    setState('loading');
    try {
      await onConfirm();
      setState('success');
    } catch (err) {
      setErrorMsg(err?.message || 'Action failed. Please try again.');
      setState('error');
    }
  }

  return (
    <div
      ref={popoverRef}
      role="dialog"
      aria-modal="true"
      aria-label={title}
      className="absolute right-0 z-50 w-64 rounded-lg p-4 space-y-3 shadow-xl"
      style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-secondary)',
        top: '100%',
        marginTop: '4px',
      }}>
      <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{title}</div>
      {body && (
        <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>{body}</div>
      )}

      {state === 'success' ? (
        <div className="flex items-center gap-2 text-xs"
          style={{ color: 'var(--accent-success)' }}>
          <CheckCircle className="w-4 h-4" />
          Action completed successfully
        </div>
      ) : state === 'error' ? (
        <div className="text-xs" style={{ color: 'var(--accent-danger)' }}>
          {errorMsg}
          <button className="block mt-1 underline" onClick={() => setState('idle')}>Retry</button>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <button
            data-autofocus
            onClick={handleConfirm}
            disabled={state === 'loading'}
            className="flex-1 px-3 py-1.5 rounded text-xs font-semibold"
            style={{
              backgroundColor: state === 'loading' ? 'var(--bg-tertiary)' : 'var(--accent-primary)',
              color: state === 'loading' ? 'var(--text-muted)' : '#020617',
              cursor: state === 'loading' ? 'not-allowed' : 'pointer',
            }}>
            {state === 'loading' ? 'Processing…' : confirmLabel}
          </button>
          <button
            onClick={onCancel}
            className="flex-1 px-3 py-1.5 rounded text-xs"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}

function getOrgAction(org) {
  const status = (org.status || '').toLowerCase();
  if (status === 'trialing') return { label: 'Extend', action: 'extend' };
  if (status === 'free')     return { label: 'Grant trial', action: 'grant_trial' };
  if (status === 'active')   return { label: 'View usage', action: 'view_usage' };
  if (status === 'past_due') return { label: 'Contact', action: 'contact' };
  return null;
}

async function performOrgAction(action, orgId) {
  if (action === 'contact') {
    window.open(`mailto:support@cspm.local?subject=Account+inquiry+${orgId}`, '_blank');
    return;
  }
  if (action === 'view_usage') {
    window.open(`/ui/billing?org_id=${orgId}`, '_blank');
    return;
  }
  const endpointMap = {
    extend: `/gateway/api/v1/billing/admin/orgs/${orgId}/extend-trial`,
    grant_trial: `/gateway/api/v1/billing/admin/orgs/${orgId}/grant-trial`,
  };
  const resp = await fetch(endpointMap[action], {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err?.detail || `HTTP ${resp.status}`);
  }
}

function OrgSubscriptionTable({ orgs, pagination, onPageChange, pageSize, onPageSizeChange, activeFilter, onClearFilter }) {
  const [openPopoverOrgId, setOpenPopoverOrgId] = useState(null);
  const [openPopoverAction, setOpenPopoverAction] = useState(null);

  const { total, page, page_size } = pagination || {};
  const totalPages = total && (page_size || pageSize) ? Math.ceil(total / (page_size || pageSize)) : 1;

  const isFilterActive = activeFilter && activeFilter !== 'engine_health';

  return (
    <div className="rounded-lg overflow-hidden"
      style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>

      {/* Table header row with filter chip and row-count selector */}
      <div className="px-5 py-3 border-b flex items-center justify-between"
        style={{ borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            Organisations
            {isFilterActive && (
              <span className="ml-2 inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full"
                style={{ backgroundColor: 'rgba(96,165,250,0.15)', color: 'var(--accent-primary)', border: '1px solid rgba(96,165,250,0.3)' }}>
                {activeFilter === 'trialing' ? 'Trialing' : 'Past Due'}
                <button onClick={onClearFilter} aria-label="Clear filter">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
          </h2>
          {!isFilterActive && total > 0 && (
            <span className="text-xs font-normal" style={{ color: 'var(--text-muted)' }}>
              ({total.toLocaleString()} total)
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Show</span>
          <select
            value={pageSize}
            onChange={e => onPageSizeChange(Number(e.target.value))}
            className="text-xs rounded px-2 py-1"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-secondary)',
            }}>
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
          </select>
        </div>
      </div>

      {!Array.isArray(orgs) || orgs.length === 0 ? (
        <div className="p-5">
          {isFilterActive ? (
            <p className="text-xs text-center" style={{ color: 'var(--text-muted)' }}>
              No organisations match this filter.
              <button onClick={onClearFilter} className="ml-2 hover:underline"
                style={{ color: 'var(--accent-primary)' }}>
                Clear filter
              </button>
            </p>
          ) : (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No organisations found.</p>
          )}
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-secondary)' }}>
                  {['Org', 'Tier', 'Status', 'Accounts', 'Trial', 'Actions'].map(col => (
                    <th key={col} className="text-left px-4 py-2.5 font-medium"
                      style={{ color: 'var(--text-muted)' }}>{col}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {orgs.map((org, i) => {
                  const ss = SUB_STATUS_STYLES[org.status_color] || SUB_STATUS_STYLES.gray;
                  const tierColor = TIER_COLORS[(org.tier || '').toLowerCase()] || '#9ca3af';

                  return (
                    <tr key={org.org_id || i} className="border-t"
                      style={{ borderColor: 'var(--border-primary)' }}>
                      <td className="px-4 py-2.5">
                        <div className="font-medium" style={{ color: 'var(--text-primary)' }}>
                          {org.org_name || org.org_id || '—'}
                        </div>
                        {org.org_name && (
                          <div className="text-[10px] tabular-nums" style={{ color: 'var(--text-muted)' }}>
                            {org.org_id}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="font-semibold uppercase text-[10px] tracking-wide"
                          style={{ color: tierColor }}>
                          {org.tier || '—'}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium capitalize"
                          style={{ backgroundColor: ss.bg, color: ss.color }}>
                          {(org.status || '').replace('_', ' ') || '—'}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 tabular-nums" style={{ color: 'var(--text-secondary)' }}>
                        {org.accounts_connected ?? '—'}
                        {org.max_accounts != null && (
                          <span style={{ color: 'var(--text-muted)' }}> / {org.max_accounts}</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 tabular-nums" style={{ color: 'var(--text-secondary)' }}>
                        {trialCountdown(org.trial_end_at)}
                      </td>
                      <td className="px-4 py-2.5 relative">
                        {(() => {
                          const orgAction = getOrgAction(org);
                          if (!orgAction) return '—';
                          const isOpen = openPopoverOrgId === org.org_id && openPopoverAction === orgAction.action;
                          return (
                            <div className="relative inline-block">
                              <button
                                onClick={() => {
                                  if (orgAction.action === 'view_usage' || orgAction.action === 'contact') {
                                    performOrgAction(orgAction.action, org.org_id);
                                    return;
                                  }
                                  if (isOpen) {
                                    setOpenPopoverOrgId(null);
                                    setOpenPopoverAction(null);
                                  } else {
                                    setOpenPopoverOrgId(org.org_id);
                                    setOpenPopoverAction(orgAction.action);
                                  }
                                }}
                                className="px-2.5 py-1 rounded text-[11px] font-medium"
                                style={{
                                  backgroundColor: 'var(--bg-tertiary)',
                                  color: 'var(--text-secondary)',
                                  border: '1px solid var(--border-secondary)',
                                }}>
                                {orgAction.label}
                              </button>
                              {isOpen && (
                                <ActionPopover
                                  title={`${orgAction.label} — ${org.org_name || org.org_id}`}
                                  confirmLabel={orgAction.label}
                                  body={
                                    orgAction.action === 'extend'
                                      ? `Extend trial for ${org.org_name || org.org_id} by 7 days`
                                      : orgAction.action === 'grant_trial'
                                        ? `Grant a 14-day trial to ${org.org_name || org.org_id}`
                                        : null
                                  }
                                  onConfirm={() => performOrgAction(orgAction.action, org.org_id)}
                                  onCancel={() => { setOpenPopoverOrgId(null); setOpenPopoverAction(null); }}
                                />
                              )}
                            </div>
                          );
                        })()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t"
              style={{ borderColor: 'var(--border-primary)' }}>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Showing {((page - 1) * (page_size || pageSize)) + 1}–{Math.min(page * (page_size || pageSize), total || 0)} of {(total || 0).toLocaleString()}
              </span>
              <div className="flex items-center gap-1">
                <button
                  disabled={page <= 1}
                  onClick={() => onPageChange(page - 1)}
                  className="p-1 rounded disabled:opacity-30"
                  style={{ color: 'var(--text-secondary)' }}>
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  disabled={page >= totalPages}
                  onClick={() => onPageChange(page + 1)}
                  className="p-1 rounded disabled:opacity-30"
                  style={{ color: 'var(--text-secondary)' }}>
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AdminDashboardPage() {
  const { user } = useAuth();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [activeFilter, setActiveFilter] = useState(null); // null | 'trialing' | 'past_due'
  const { data, loading, error, refetch } = useViewFetch('platform-admin', { page: String(page), page_size: String(pageSize) });
  const [countdown, setCountdown] = useState(30);
  const intervalRef = useRef(null);
  const refetchRef = useRef(refetch);
  useEffect(() => { refetchRef.current = refetch; });

  const resetAutoRefresh = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    let counter = 30;
    setCountdown(30);
    intervalRef.current = setInterval(() => {
      counter -= 1;
      setCountdown(counter);
      if (counter <= 0) {
        refetchRef.current();
        counter = 30;
        setCountdown(30);
      }
    }, 1000);
  }, []);

  useEffect(() => {
    resetAutoRefresh();
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRefresh = useCallback(() => {
    refetch();
    resetAutoRefresh();
  }, [refetch, resetAutoRefresh]);

  const handlePageChange = useCallback((newPage) => {
    setPage(newPage);
    refetch();
  }, [refetch]);

  function toggleFilter(filterKey) {
    setActiveFilter(prev => prev === filterKey ? null : filterKey);
  }

  // Permission gate: only platform_admin
  const role = user?.role || user?.roles?.[0] || '';
  if (user && role !== 'platform_admin') {
    return (
      <div className="p-8 text-center space-y-3">
        <LayoutGrid className="w-10 h-10 mx-auto" style={{ color: 'var(--text-muted)' }} />
        <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>Admin Dashboard</h2>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Not authorized. Requires <code className="text-xs px-1 rounded"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>platform:admin</code> role.
        </p>
      </div>
    );
  }

  // data.error from BFF forbidden
  if (!loading && (data?.error === 'forbidden' || error?.includes('403'))) {
    return (
      <div className="p-8 text-center space-y-3">
        <LayoutGrid className="w-10 h-10 mx-auto" style={{ color: 'var(--text-muted)' }} />
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Not authorized. Requires platform:admin role.
        </p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="space-y-4 p-6">
        <div className="h-8 w-48 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
          ))}
        </div>
        <div className="h-64 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
        <div className="h-64 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 p-4 rounded-lg text-sm"
          style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>
          <XCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      </div>
    );
  }

  const metrics = data?.metrics || {};
  const engines = data?.engines || [];
  const orgs = data?.orgs || [];
  const pagination = data?.pagination || { total: 0, page: 1, page_size: 25 };

  const healthyCount = engines.filter(e => e.status_color === 'green').length;
  const unhealthyCount = engines.filter(e => e.status_color === 'red').length;

  // Client-side filter — does not reset pagination
  const filteredOrgs = activeFilter
    ? orgs.filter(org => {
        if (activeFilter === 'trialing') return (org.status || '').toLowerCase() === 'trialing';
        if (activeFilter === 'past_due') return (org.status || '').toLowerCase() === 'past_due';
        return true;
      })
    : orgs;

  return (
    <div className="p-6 space-y-5 max-w-7xl">
      {/* Page heading */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <LayoutGrid className="w-5 h-5" style={{ color: 'var(--accent-primary)' }} />
          <h1 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>Platform Admin Dashboard</h1>
        </div>
        <button
          onClick={handleRefresh}
          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded"
          style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)',
            border: '1px solid var(--border-primary)' }}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
          <span className="tabular-nums" style={{ color: 'var(--text-muted)' }}>{countdown}s</span>
        </button>
      </div>

      {/* Platform metrics summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <MetricCard
          label="Total Orgs"
          value={metrics.total_orgs}
          sublabel="across all tiers"
          color="var(--accent-primary)"
        />
        <MetricCard
          label="Trials Expiring"
          value={metrics.trials_expiring_7d}
          sublabel="within 7 days"
          severity={metrics.trials_expiring_7d > 0 ? 'warn' : 'ok'}
          onClick={() => toggleFilter('trialing')}
          filterActive={activeFilter === 'trialing'}
          ariaLabel="Filter organisations by trialing status"
        />
        <MetricCard
          label="Past Due"
          value={metrics.past_due_orgs}
          sublabel="need attention"
          severity={metrics.past_due_orgs > 0 ? 'danger' : 'ok'}
          onClick={() => toggleFilter('past_due')}
          filterActive={activeFilter === 'past_due'}
          ariaLabel="Filter organisations by past due status"
        />
        <MetricCard
          label="Engines Healthy"
          value={engines.length > 0 ? `${healthyCount} / ${engines.length}` : '—'}
          sublabel={unhealthyCount > 0 ? `${unhealthyCount} degraded` : 'all healthy'}
          severity={unhealthyCount > 0 ? 'danger' : 'ok'}
        />
      </div>

      {/* Engine health — grouped by pipeline stage */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />
          <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Engine Health</h2>
        </div>
        {engines.length === 0 ? (
          <div className="rounded-lg p-5"
            style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No health data available.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-4">
            {partitionEnginesByGroup(engines)
              .filter(g => g.label !== 'ENTERPRISE')
              .map(group => (
                <EngineGroupPanel key={group.label} label={group.label} tiles={group.tiles} variant={group.variant} />
              ))}
          </div>
        )}
        {/* Enterprise block — full width, below the 4-column grid */}
        {engines.length > 0 && (() => {
          const enterpriseGroup = partitionEnginesByGroup(engines).find(g => g.label === 'ENTERPRISE');
          return enterpriseGroup ? (
            <EngineGroupPanel label={enterpriseGroup.label} tiles={enterpriseGroup.tiles} variant="enterprise" />
          ) : null;
        })()}
      </div>

      {/* Org subscription table */}
      <OrgSubscriptionTable
        orgs={filteredOrgs}
        pagination={pagination}
        onPageChange={handlePageChange}
        pageSize={pageSize}
        onPageSizeChange={(newSize) => { setPageSize(newSize); setPage(1); }}
        activeFilter={activeFilter}
        onClearFilter={() => setActiveFilter(null)}
      />
    </div>
  );
}
