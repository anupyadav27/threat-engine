'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import {
  Download, Plus, RefreshCw, CheckCircle,
  Ban, X, RotateCcw, Search, CheckSquare, Square, Filter,
} from 'lucide-react';
import { fetchView, postToEngine, deleteFromEngine, getFromEngine } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import SeverityBadge from '@/components/shared/SeverityBadge';
import RuleBuilderWizard from '@/components/domain/RuleBuilderWizard';

const SUPPRESS_ROLES = ['org_admin', 'platform_admin'];

// ── Type badge ────────────────────────────────────────────────────────────
const TYPE_COLORS = {
  config:  { bg: 'rgba(59,130,246,0.12)',  text: '#60a5fa' },
  cdr:     { bg: 'rgba(168,85,247,0.12)',  text: '#c084fc' },
  threat:  { bg: 'rgba(239,68,68,0.12)',   text: '#f87171' },
  custom:  { bg: 'rgba(52,211,153,0.12)',  text: '#34d399' },
};
function TypeBadge({ type }) {
  const c = TYPE_COLORS[type] || TYPE_COLORS.config;
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
      style={{ backgroundColor: c.bg, color: c.text }}>{type}</span>
  );
}

// ── Suppress modal ────────────────────────────────────────────────────────
function BulkSuppressModal({ selectedRules, onClose, onSuccess }) {
  const [reason, setReason]   = useState('');
  const [expires, setExpires] = useState('');
  const [loading, setLoading] = useState(false);
  const [errors, setErrors]   = useState([]);

  const handleSubmit = async () => {
    setLoading(true); setErrors([]);
    const failed = [];
    for (const rule of selectedRules) {
      const res = await postToEngine('gateway', '/api/v1/rules/suppress', {
        scope_type: 'rule', scope_value: rule.rule_id, scope_level: 'tenant',
        provider: (rule.provider || '').toLowerCase() || null,
        reason: reason || null, expires_at: expires || null,
      });
      if (res?.error) failed.push({ rule_id: rule.rule_id, error: res.error });
    }
    setLoading(false);
    if (!failed.length) onSuccess(); else setErrors(failed);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-[440px] rounded-2xl border shadow-2xl" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between p-5 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <Ban className="w-4 h-4" style={{ color: '#f97316' }} />
            <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
              Suppress {selectedRules.length} Rule{selectedRules.length !== 1 ? 's' : ''}
            </span>
          </div>
          <button onClick={onClose}><X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} /></button>
        </div>
        <div className="p-5 space-y-4">
          <div className="rounded-lg p-3 text-xs" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
            {selectedRules.length} rule ID{selectedRules.length !== 1 ? 's' : ''} will be suppressed individually.
          </div>
          <div>
            <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-muted)' }}>Reason (optional)</label>
            <input value={reason} onChange={e => setReason(e.target.value)}
              placeholder="e.g. Accepted risk — reviewed 2026-05"
              className="w-full px-3 py-2 rounded-lg border text-sm bg-transparent"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-muted)' }}>Expires At (optional)</label>
            <input type="date" value={expires}
              onChange={e => setExpires(e.target.value ? e.target.value + 'T00:00:00Z' : '')}
              className="w-full px-3 py-2 rounded-lg border text-sm bg-transparent"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }} />
          </div>
          {errors.length > 0 && (
            <div className="rounded-lg p-3 text-xs space-y-1" style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444' }}>
              {errors.map((e, i) => <div key={i}>{e.rule_id}: {e.error}</div>)}
            </div>
          )}
        </div>
        <div className="flex justify-end gap-3 p-5 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--text-muted)' }}>Cancel</button>
          <button onClick={handleSubmit} disabled={loading}
            className="px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2"
            style={{ backgroundColor: 'rgba(249,115,22,0.15)', color: '#f97316' }}>
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />}
            {loading ? 'Suppressing…' : `Suppress ${selectedRules.length}`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Reactivate modal ──────────────────────────────────────────────────────
function ReactivateModal({ selectedRules, onClose, onSuccess }) {
  const [loading, setLoading] = useState(false);
  const handleReactivate = async () => {
    setLoading(true);
    const listRes = await getFromEngine('gateway', '/api/v1/rules/suppressions');
    const suppressions = listRes?.suppressions || [];
    for (const rule of selectedRules) {
      const match = suppressions.find(s => s.scope_type === 'rule' && s.scope_value === rule.rule_id);
      if (match) await deleteFromEngine('gateway', `/api/v1/rules/suppressions/${match.id}`);
    }
    setLoading(false); onSuccess();
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-[420px] rounded-2xl border shadow-2xl p-6 space-y-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center gap-2">
          <RotateCcw className="w-4 h-4 text-emerald-400" />
          <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>
            Reactivate {selectedRules.length} Rule{selectedRules.length !== 1 ? 's' : ''}
          </span>
        </div>
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
          This will lift rule-level suppressions for the selected rules.
        </p>
        <div className="flex justify-end gap-3 pt-2">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--text-muted)' }}>Cancel</button>
          <button onClick={handleReactivate} disabled={loading}
            className="px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2"
            style={{ backgroundColor: 'rgba(52,211,153,0.15)', color: '#34d399' }}>
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />}
            {loading ? 'Reactivating…' : 'Confirm Reactivate'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Rule detail panel ─────────────────────────────────────────────────────
function RuleDetailPanel({ rule, onClose }) {
  if (!rule) return null;
  return (
    <div className="fixed inset-y-0 right-0 w-[480px] z-40 border-l shadow-2xl flex flex-col"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="flex items-center justify-between p-5 border-b" style={{ borderColor: 'var(--border-primary)' }}>
        <span className="font-semibold text-sm truncate pr-4" style={{ color: 'var(--text-primary)' }}>{rule.rule_id}</span>
        <button onClick={onClose}><X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} /></button>
      </div>
      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        <div>
          <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Title</div>
          <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{rule.title || '—'}</div>
        </div>
        {rule.description && (
          <div>
            <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Description</div>
            <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>{rule.description}</div>
          </div>
        )}
        <div className="grid grid-cols-2 gap-3">
          {[
            ['Provider', rule.provider], ['Service',  rule.service],
            ['Severity', rule.severity], ['Type',     rule.rule_type],
            ['Domain',   rule.domain],   ['Status',   rule.status],
          ].map(([k, v]) => v && (
            <div key={k}>
              <div className="text-xs mb-0.5" style={{ color: 'var(--text-muted)' }}>{k}</div>
              <div className="text-sm capitalize" style={{ color: 'var(--text-primary)' }}>{v}</div>
            </div>
          ))}
        </div>
        {rule.is_suppressed && (
          <div className="rounded-lg p-3 text-xs" style={{ backgroundColor: 'rgba(249,115,22,0.08)', color: '#f97316' }}>
            <Ban className="w-3 h-3 inline mr-1" />This rule is currently suppressed
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────
export default function RulesPage() {
  const { role } = useAuth();
  const canSuppress = SUPPRESS_ROLES.includes(role);

  const [loading, setLoading]   = useState(true);
  const [rules, setRules]       = useState([]);
  const [summary, setSummary]   = useState({});
  const [searchQuery, setSearchQuery] = useState('');

  // Per-column active filter values (Set per column key)
  const [colFilters, setColFilters] = useState({});

  // Which filter popover is open + its fixed position
  const [openCol, setOpenCol]     = useState(null);
  const [popoverPos, setPopoverPos] = useState({ top: 0, left: 0 });
  const [popoverSearch, setPopoverSearch] = useState('');

  // Selection
  const [selectedIds, setSelectedIds] = useState(new Set());

  // Modals / panels
  const [suppressModal, setSuppressModal]     = useState(false);
  const [reactivateModal, setReactivateModal] = useState(false);
  const [detailRule, setDetailRule]           = useState(null);
  const [showWizard, setShowWizard]           = useState(false);

  // ── Fetch ───────────────────────────────────────────────────────────────
  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchView('rules');
      setRules(data?.rules || []);
      setSummary(data?.summary || {});
    } catch (e) { console.error('rules fetch', e); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { fetchRules(); }, [fetchRules]);

  // ── Unique values for each filterable column (all rules, no cap) ────────
  const uniqueVals = useMemo(() => ({
    rule_type: ['config', 'cdr', 'threat', 'custom'],
    provider:  [...new Set(rules.map(r => r.provider).filter(Boolean))].sort(),
    service:   [...new Set(rules.map(r => r.service).filter(Boolean))].sort(),
    severity:  ['critical', 'high', 'medium', 'low'],
    status:    ['active', 'suppressed'],
  }), [rules]);

  // ── Filtered view ───────────────────────────────────────────────────────
  const filteredRules = useMemo(() => {
    let out = rules;
    const typeSet     = colFilters.rule_type;
    const provSet     = colFilters.provider;
    const svcSet      = colFilters.service;
    const sevSet      = colFilters.severity;
    const statusSet   = colFilters.status;
    if (typeSet   && typeSet.size)   out = out.filter(r => typeSet.has(r.rule_type));
    if (provSet   && provSet.size)   out = out.filter(r => provSet.has(r.provider));
    if (svcSet    && svcSet.size)    out = out.filter(r => svcSet.has(r.service));
    if (sevSet    && sevSet.size)    out = out.filter(r => sevSet.has(r.severity));
    if (statusSet && statusSet.size) out = out.filter(r => statusSet.has(r.is_suppressed ? 'suppressed' : 'active'));
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      out = out.filter(r =>
        (r.rule_id || '').toLowerCase().includes(q) ||
        (r.title   || '').toLowerCase().includes(q) ||
        (r.service || '').toLowerCase().includes(q)
      );
    }
    return out;
  }, [rules, colFilters, searchQuery]);

  // Selected rule objects
  const selectedRules      = useMemo(() => filteredRules.filter(r => selectedIds.has(r.rule_id)), [filteredRules, selectedIds]);
  const selectedActive     = selectedRules.filter(r => !r.is_suppressed);
  const selectedSuppressed = selectedRules.filter(r =>  r.is_suppressed);

  // Select-all state
  const allChecked  = filteredRules.length > 0 && filteredRules.every(r => selectedIds.has(r.rule_id));
  const someChecked = selectedIds.size > 0;
  const toggleSelectAll = () => setSelectedIds(allChecked ? new Set() : new Set(filteredRules.map(r => r.rule_id)));
  const toggleRow = id => setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  // ── Filter popover helpers ──────────────────────────────────────────────
  const openFilter = (colKey, btnEl) => {
    const rect = btnEl.getBoundingClientRect();
    setPopoverPos({ top: rect.bottom + 4, left: Math.min(rect.left, window.innerWidth - 240) });
    setOpenCol(colKey);
    setPopoverSearch('');
  };
  const toggleFilterVal = (colKey, val) => {
    setColFilters(prev => {
      const cur = new Set(prev[colKey] || []);
      cur.has(val) ? cur.delete(val) : cur.add(val);
      return { ...prev, [colKey]: cur };
    });
    setSelectedIds(new Set());
  };
  const clearFilter = colKey => { setColFilters(prev => ({ ...prev, [colKey]: new Set() })); setOpenCol(null); };
  const activeCount = colKey => (colFilters[colKey]?.size || 0);

  // Popover closes via backdrop click (see render section)

  // ── Export ──────────────────────────────────────────────────────────────
  const handleExport = () => {
    const csv = [
      ['Rule ID','Type','Provider','Service','Severity','Status','Title'].join(','),
      ...filteredRules.map(r => [
        r.rule_id, r.rule_type, r.provider, r.service, r.severity,
        r.is_suppressed ? 'suppressed' : 'active',
        `"${(r.title||'').replace(/"/g,'""')}"`,
      ].join(',')),
    ].join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = 'rule-library.csv'; a.click();
  };

  const onSuppressSuccess   = () => { setSuppressModal(false);   setSelectedIds(new Set()); fetchRules(); };
  const onReactivateSuccess = () => { setReactivateModal(false); setSelectedIds(new Set()); fetchRules(); };

  // ── Render ──────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="p-6 space-y-4">
        <div className="h-24 rounded-2xl animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        <div className="h-96 rounded-2xl animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-5">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Summary line */}
        <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{(summary.total || rules.length).toLocaleString()}</span> rules
          {summary.suppressed > 0 && <> · <span style={{ color: '#f97316', fontWeight: 600 }}>{summary.suppressed.toLocaleString()}</span> suppressed</>}
          {filteredRules.length < rules.length && <> · <span style={{ color: '#60a5fa', fontWeight: 600 }}>{filteredRules.length.toLocaleString()}</span> matching filters</>}
        </div>
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
          <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search rule ID, title, service…"
            className="w-full pl-8 pr-3 py-2 rounded-lg border text-sm bg-transparent"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }} />
        </div>
        <div className="flex-1" />
        {canSuppress && (
          <>
            <button
              onClick={() => selectedActive.length > 0 && setSuppressModal(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-semibold transition-colors"
              style={{
                backgroundColor: selectedActive.length > 0 ? 'rgba(249,115,22,0.12)' : 'var(--bg-secondary)',
                color: selectedActive.length > 0 ? '#f97316' : 'var(--text-muted)',
                opacity: selectedActive.length > 0 ? 1 : 0.5, cursor: selectedActive.length > 0 ? 'pointer' : 'not-allowed',
              }}>
              <Ban className="w-3.5 h-3.5" />
              Suppress{selectedActive.length > 0 ? ` (${selectedActive.length})` : ''}
            </button>
            <button
              onClick={() => selectedSuppressed.length > 0 && setReactivateModal(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-semibold transition-colors"
              style={{
                backgroundColor: selectedSuppressed.length > 0 ? 'rgba(52,211,153,0.12)' : 'var(--bg-secondary)',
                color: selectedSuppressed.length > 0 ? '#34d399' : 'var(--text-muted)',
                opacity: selectedSuppressed.length > 0 ? 1 : 0.5, cursor: selectedSuppressed.length > 0 ? 'pointer' : 'not-allowed',
              }}>
              <RotateCcw className="w-3.5 h-3.5" />
              Reactivate{selectedSuppressed.length > 0 ? ` (${selectedSuppressed.length})` : ''}
            </button>
          </>
        )}
        <button onClick={handleExport}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm"
          style={{ borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}>
          <Download className="w-3.5 h-3.5" />Export
        </button>
        {canSuppress && (
          <button onClick={() => setShowWizard(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium"
            style={{ backgroundColor: 'rgba(99,102,241,0.15)', color: '#818cf8' }}>
            <Plus className="w-3.5 h-3.5" />New Rule
          </button>
        )}
      </div>

      {/* Selection bar */}
      {someChecked && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm"
          style={{ backgroundColor: 'rgba(249,115,22,0.08)', border: '1px solid rgba(249,115,22,0.2)' }}>
          <CheckSquare className="w-4 h-4" style={{ color: '#f97316' }} />
          <span style={{ color: 'var(--text-primary)' }}>
            <strong>{selectedIds.size}</strong> selected
            {selectedSuppressed.length > 0 && ` (${selectedSuppressed.length} suppressed)`}
          </span>
          <button onClick={() => setSelectedIds(new Set())} className="ml-auto text-xs" style={{ color: 'var(--text-muted)' }}>Clear</button>
        </div>
      )}

      {/* Table wrapper — no overflow-y constraint so filter popover at page level can float freely */}
      <div className="rounded-2xl border" style={{ borderColor: 'var(--border-primary)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-primary)' }}>
                {canSuppress && (
                  <th className="w-10 px-4 py-3 text-left">
                    <button onClick={toggleSelectAll}>
                      {allChecked
                        ? <CheckSquare className="w-4 h-4" style={{ color: '#f97316' }} />
                        : <Square className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />}
                    </button>
                  </th>
                )}
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Rule ID</th>
                {['rule_type','provider','service','severity','status'].map(col => (
                  <th key={col} className="px-4 py-3 text-left" style={{ whiteSpace: 'nowrap' }}>
                    <div className="flex items-center gap-1">
                      <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: activeCount(col) > 0 ? '#3b82f6' : 'var(--text-muted)' }}>
                        {{ rule_type:'Type', provider:'Provider', service:'Service', severity:'Severity', status:'Status' }[col]}
                      </span>
                      <button
                        onClick={e => { e.stopPropagation(); openFilter(col, e.currentTarget); }}
                        className="p-0.5 rounded hover:opacity-75 relative"
                        title={`Filter ${col}`}
                        style={{ color: activeCount(col) > 0 ? '#3b82f6' : 'var(--text-muted)' }}>
                        <Filter className="w-3 h-3" style={{ fill: activeCount(col) > 0 ? '#3b82f6' : 'none' }} />
                        {activeCount(col) > 0 && (
                          <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full text-[9px] font-bold flex items-center justify-center"
                            style={{ backgroundColor: '#3b82f6', color: '#fff' }}>{activeCount(col)}</span>
                        )}
                      </button>
                    </div>
                  </th>
                ))}
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Title</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={canSuppress ? 8 : 7} className="px-4 py-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                    No rules match the current filters
                  </td>
                </tr>
              ) : (
                filteredRules.slice(0, 500).map((rule, idx) => {
                  const checked = selectedIds.has(rule.rule_id);
                  return (
                    <tr key={rule.rule_id || idx} onClick={() => setDetailRule(rule)} className="cursor-pointer"
                      style={{ borderBottom: '1px solid var(--border-primary)', backgroundColor: checked ? 'rgba(249,115,22,0.04)' : undefined }}
                      onMouseEnter={e => { if (!checked) e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'; }}
                      onMouseLeave={e => { e.currentTarget.style.backgroundColor = checked ? 'rgba(249,115,22,0.04)' : ''; }}>
                      {canSuppress && (
                        <td className="px-4 py-3" onClick={e => { e.stopPropagation(); toggleRow(rule.rule_id); }}>
                          {checked
                            ? <CheckSquare className="w-4 h-4" style={{ color: '#f97316' }} />
                            : <Square className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />}
                        </td>
                      )}
                      <td className="px-4 py-3">
                        <code className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                          {(rule.rule_id || '').length > 48 ? rule.rule_id.slice(0, 48) + '…' : rule.rule_id}
                        </code>
                      </td>
                      <td className="px-4 py-3"><TypeBadge type={rule.rule_type} /></td>
                      <td className="px-4 py-3 text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{rule.provider || '—'}</td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{rule.service || '—'}</td>
                      <td className="px-4 py-3"><SeverityBadge severity={rule.severity} /></td>
                      <td className="px-4 py-3">
                        {rule.is_suppressed
                          ? <span className="inline-flex items-center gap-1 text-xs font-semibold" style={{ color: '#f97316' }}><Ban className="w-3 h-3" />Suppressed</span>
                          : <span className="inline-flex items-center gap-1 text-xs font-semibold" style={{ color: '#34d399' }}><CheckCircle className="w-3 h-3" />Active</span>}
                      </td>
                      <td className="px-4 py-3 text-xs max-w-[240px] truncate" style={{ color: 'var(--text-muted)' }}>{rule.title || '—'}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {filteredRules.length > 500 && (
          <div className="px-4 py-2.5 text-xs text-center" style={{ color: 'var(--text-muted)', borderTop: '1px solid var(--border-primary)' }}>
            Showing first 500 of {filteredRules.length.toLocaleString()} — use filters to narrow results
          </div>
        )}
      </div>

      {/* ── Filter popover — backdrop + popover both at page root (escapes overflow-x-auto) ── */}
      {openCol && (() => {
        const opts    = uniqueVals[openCol] || [];
        const q       = popoverSearch.toLowerCase();
        const visible = q ? opts.filter(v => v.toLowerCase().includes(q)) : opts;
        const active  = colFilters[openCol] || new Set();
        return (
          <>
            {/* Transparent backdrop — click outside closes popover */}
            <div
              style={{ position: 'fixed', inset: 0, zIndex: 9998 }}
              onClick={() => setOpenCol(null)}
            />
            {/* Popover — above backdrop */}
            <div
              style={{
                position: 'fixed',
                top: popoverPos.top,
                left: popoverPos.left,
                zIndex: 9999,
                minWidth: 200,
                maxWidth: 280,
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-primary)',
                borderRadius: 12,
                boxShadow: '0 8px 32px rgba(0,0,0,0.25)',
              }}
            >
              <div className="p-2 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                <input
                  autoFocus type="text" placeholder="Search values…"
                  value={popoverSearch}
                  onChange={e => setPopoverSearch(e.target.value)}
                  className="w-full px-2 py-1 text-xs rounded border focus:outline-none"
                  style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
                />
              </div>
              <div className="p-2">
                <label className="flex items-center gap-2 text-xs cursor-pointer py-1 px-1 rounded hover:opacity-75">
                  <input type="checkbox" checked={active.size === 0} onChange={() => { clearFilter(openCol); }} style={{ accentColor: '#3b82f6' }} />
                  <span style={{ color: 'var(--text-secondary)' }}>All (clear filter)</span>
                </label>
              </div>
              <div className="max-h-52 overflow-y-auto pb-2">
                {visible.map(val => (
                  <label key={val} className="flex items-center gap-2 text-xs cursor-pointer py-1 px-3 hover:opacity-75">
                    <input
                      type="checkbox"
                      checked={active.has(String(val))}
                      onChange={() => toggleFilterVal(openCol, String(val))}
                      style={{ accentColor: '#3b82f6' }}
                    />
                    <span style={{ color: 'var(--text-primary)' }}>{val}</span>
                  </label>
                ))}
                {visible.length === 0 && (
                  <div className="px-3 py-2 text-xs" style={{ color: 'var(--text-muted)' }}>No matches</div>
                )}
              </div>
            </div>
          </>
        );
      })()}

      {/* Modals */}
      {suppressModal && canSuppress && selectedActive.length > 0 && (
        <BulkSuppressModal selectedRules={selectedActive} onClose={() => setSuppressModal(false)} onSuccess={onSuppressSuccess} />
      )}
      {reactivateModal && canSuppress && selectedSuppressed.length > 0 && (
        <ReactivateModal selectedRules={selectedSuppressed} onClose={() => setReactivateModal(false)} onSuccess={onReactivateSuccess} />
      )}
      {detailRule && <RuleDetailPanel rule={detailRule} onClose={() => setDetailRule(null)} />}
      {showWizard && (
        <RuleBuilderWizard onClose={() => setShowWizard(false)} onSuccess={() => { setShowWizard(false); fetchRules(); }} />
      )}
    </div>
  );
}
