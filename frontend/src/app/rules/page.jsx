'use client';

import { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import {
  BookOpen, CheckCircle, Download, Plus,
  RefreshCw, Zap, ChevronDown,
  Ban, X, RotateCcw, Search, CheckSquare, Square,
} from 'lucide-react';
import { fetchView, postToEngine, deleteFromEngine, getFromEngine } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import RuleBuilderWizard from '@/components/domain/RuleBuilderWizard';

// Suppress requires org_admin or platform_admin
const SUPPRESS_ROLES = ['org_admin', 'platform_admin'];
const RULE_TYPE_OPTIONS = ['config', 'cdr', 'threat', 'custom'];

// ── Suppress modal (simplified — always suppresses by rule_id) ────────────
function BulkSuppressModal({ selectedRules, onClose, onSuccess }) {
  const [reason, setReason]   = useState('');
  const [expires, setExpires] = useState('');
  const [loading, setLoading] = useState(false);
  const [errors, setErrors]   = useState([]);

  const handleSubmit = async () => {
    setLoading(true);
    setErrors([]);
    const failed = [];
    for (const rule of selectedRules) {
      const body = {
        scope_type:  'rule',
        scope_value: rule.rule_id,
        scope_level: 'tenant',
        provider:    (rule.provider || '').toLowerCase() || null,
        reason:      reason || null,
        expires_at:  expires || null,
      };
      const res = await postToEngine('rule', '/api/v1/rules/suppress', body);
      if (res?.error) failed.push({ rule_id: rule.rule_id, error: res.error });
    }
    setLoading(false);
    if (failed.length === 0) onSuccess();
    else setErrors(failed);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-[440px] rounded-2xl border shadow-2xl" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between p-5 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <Ban className="w-4 h-4" style={{ color: '#f97316' }} />
            <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>
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
            <input
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="e.g. Accepted risk — reviewed 2026-05"
              className="w-full px-3 py-2 rounded-lg border text-sm bg-transparent"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>

          <div>
            <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-muted)' }}>Expires At (optional — blank = permanent)</label>
            <input
              type="date"
              value={expires}
              onChange={e => setExpires(e.target.value ? e.target.value + 'T00:00:00Z' : '')}
              className="w-full px-3 py-2 rounded-lg border text-sm bg-transparent"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>

          {errors.length > 0 && (
            <div className="rounded-lg p-3 text-xs space-y-1" style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444' }}>
              {errors.map((e, i) => <div key={i}>{e.rule_id}: {e.error}</div>)}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 p-5 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--text-muted)' }}>Cancel</button>
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2"
            style={{ backgroundColor: 'rgba(249,115,22,0.15)', color: '#f97316' }}
          >
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />}
            {loading ? 'Suppressing…' : `Suppress ${selectedRules.length}`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Reactivate confirmation ───────────────────────────────────────────────
function ReactivateModal({ selectedRules, onClose, onSuccess }) {
  const [loading, setLoading] = useState(false);

  const handleReactivate = async () => {
    setLoading(true);
    const listRes = await getFromEngine('rule', '/api/v1/rules/suppressions');
    const suppressions = listRes?.suppressions || [];
    for (const rule of selectedRules) {
      const match = suppressions.find(s => s.scope_type === 'rule' && s.scope_value === rule.rule_id);
      if (match) {
        await deleteFromEngine('rule', `/api/v1/rules/suppressions/${match.id}`);
      }
    }
    setLoading(false);
    onSuccess();
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
          This will lift rule-level suppressions for the selected rules. Service, Category, and Provider suppressions must be managed from the Suppressions page.
        </p>
        <div className="flex justify-end gap-3 pt-2">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--text-muted)' }}>Cancel</button>
          <button
            onClick={handleReactivate}
            disabled={loading}
            className="px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2"
            style={{ backgroundColor: 'rgba(52,211,153,0.15)', color: '#34d399' }}
          >
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
            ['Provider',  rule.provider],
            ['Service',   rule.service],
            ['Severity',  rule.severity],
            ['Type',      rule.rule_type],
            ['Domain',    rule.domain],
            ['Status',    rule.status],
          ].map(([k, v]) => v && (
            <div key={k}>
              <div className="text-xs mb-0.5" style={{ color: 'var(--text-muted)' }}>{k}</div>
              <div className="text-sm capitalize" style={{ color: 'var(--text-primary)' }}>{v}</div>
            </div>
          ))}
        </div>
        {rule.is_suppressed && (
          <div className="rounded-lg p-3 text-xs" style={{ backgroundColor: 'rgba(249,115,22,0.08)', color: '#f97316' }}>
            <Ban className="w-3 h-3 inline mr-1" />
            This rule is currently suppressed
          </div>
        )}
      </div>
    </div>
  );
}

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
      style={{ backgroundColor: c.bg, color: c.text }}>
      {type}
    </span>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────
export default function RulesPage() {
  const { hasPermission, role } = useAuth();
  const canSuppress = SUPPRESS_ROLES.includes(role);

  const [loading, setLoading]         = useState(true);
  const [rules, setRules]             = useState([]);
  const [templates, setTemplates]     = useState([]);
  const [kpi, setKpi]                 = useState({});

  // Filters (all live in column headers)
  const [filterType, setFilterType]         = useState('');
  const [filterProvider, setFilterProvider] = useState('');
  const [filterService, setFilterService]   = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterStatus, setFilterStatus]     = useState('');
  const [searchQuery, setSearchQuery]       = useState('');

  // Selection
  const [selectedIds, setSelectedIds] = useState(new Set());

  // Modals
  const [suppressModal, setSuppressModal]     = useState(false);
  const [reactivateModal, setReactivateModal] = useState(false);
  const [detailRule, setDetailRule]           = useState(null);
  const [showWizard, setShowWizard]           = useState(false);

  // ── Data fetch ──────────────────────────────────────────────────────────
  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchView('rules');
      setRules(data?.rules || []);
      setTemplates(data?.templates || []);
      setKpi(data?.kpi || {});
    } catch (e) {
      console.error('rules fetch failed', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchRules(); }, [fetchRules]);

  // ── Filtered rules ──────────────────────────────────────────────────────
  const filteredRules = useMemo(() => {
    let out = rules;
    if (filterType)     out = out.filter(r => r.rule_type === filterType);
    if (filterProvider) out = out.filter(r => r.provider === filterProvider);
    if (filterService)  out = out.filter(r => r.service === filterService);
    if (filterSeverity) out = out.filter(r => r.severity === filterSeverity);
    if (filterStatus === 'suppressed') out = out.filter(r => r.is_suppressed);
    if (filterStatus === 'active')     out = out.filter(r => !r.is_suppressed);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      out = out.filter(r =>
        (r.rule_id || '').toLowerCase().includes(q) ||
        (r.title || '').toLowerCase().includes(q) ||
        (r.service || '').toLowerCase().includes(q)
      );
    }
    return out;
  }, [rules, filterType, filterProvider, filterService, filterSeverity, filterStatus, searchQuery]);

  // Selected rule objects
  const selectedRules = useMemo(
    () => filteredRules.filter(r => selectedIds.has(r.rule_id)),
    [filteredRules, selectedIds]
  );
  const selectedSuppressed = selectedRules.filter(r => r.is_suppressed);
  const selectedActive     = selectedRules.filter(r => !r.is_suppressed);

  // ── Selection handlers ──────────────────────────────────────────────────
  const allChecked = filteredRules.length > 0 && filteredRules.every(r => selectedIds.has(r.rule_id));
  const someChecked = selectedIds.size > 0;

  const toggleSelectAll = () => {
    if (allChecked) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredRules.map(r => r.rule_id)));
    }
  };

  const toggleRow = (ruleId) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(ruleId) ? next.delete(ruleId) : next.add(ruleId);
      return next;
    });
  };

  // ── Dropdown filters ────────────────────────────────────────────────────
  const uniqueProviders = useMemo(() => [...new Set(rules.map(r => r.provider).filter(Boolean))].sort(), [rules]);
  const uniqueServices  = useMemo(() => [...new Set(rules.map(r => r.service).filter(Boolean))].sort(), [rules]);
  const uniqueSeverities = ['critical', 'high', 'medium', 'low'];

  // ── Export ──────────────────────────────────────────────────────────────
  const handleExport = () => {
    const csv = [
      ['Rule ID', 'Provider', 'Service', 'Type', 'Severity', 'Status', 'Title'].join(','),
      ...filteredRules.map(r => [
        r.rule_id, r.provider, r.service, r.rule_type, r.severity,
        r.is_suppressed ? 'suppressed' : 'active',
        `"${(r.title || '').replace(/"/g, '""')}"`,
      ].join(',')),
    ].join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    const a = document.createElement('a'); a.href = url; a.download = 'rule-library.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  // ── After suppress / reactivate success ────────────────────────────────
  const onSuppressSuccess = () => { setSuppressModal(false); setSelectedIds(new Set()); fetchRules(); };
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
      {/* KPI strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <KpiCard title="Total Rules"  value={(kpi.totalRules  || rules.length).toLocaleString()} subtitle="All rule types"      icon={<BookOpen className="w-5 h-5" />} color="blue" />
        <KpiCard title="Config"       value={(kpi.byType?.config  || 0).toLocaleString()}        subtitle="Posture rules"       icon={<CheckCircle className="w-5 h-5" />} color="blue" />
        <KpiCard title="CDR"          value={(kpi.byType?.cdr     || 0).toLocaleString()}        subtitle="Detection rules"     icon={<Zap className="w-5 h-5" />} color="purple" />
        <KpiCard title="Threat"       value={(kpi.byType?.threat  || 0).toLocaleString()}        subtitle="MITRE ATT&CK"        icon={<Zap className="w-5 h-5" />} color="red" />
        <KpiCard title="Custom"       value={(kpi.byType?.custom  || 0).toLocaleString()}        subtitle="YAML rules"          icon={<CheckCircle className="w-5 h-5" />} color="green" />
        <KpiCard title="Suppressed"   value={(kpi.suppressed      || 0).toLocaleString()}        subtitle="Muted rules"         icon={<Ban className="w-5 h-5" />} color="orange" />
      </div>

      {/* Toolbar — search + actions only (column filters are in table headers) */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
          <input
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search rule ID, title, service…"
            className="w-full pl-8 pr-3 py-2 rounded-lg border text-sm bg-transparent"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
          />
        </div>

        <div className="flex-1" />

        {/* Action buttons */}
        {canSuppress && (
          <>
            <SuppressButton
              count={selectedActive.length}
              onClick={() => setSuppressModal(true)}
            />
            <ReactivateButton
              count={selectedSuppressed.length}
              onClick={() => setReactivateModal(true)}
            />
          </>
        )}

        <button
          onClick={handleExport}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm"
          style={{ borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}
        >
          <Download className="w-3.5 h-3.5" />
          Export
        </button>

        {canSuppress && (
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium"
            style={{ backgroundColor: 'rgba(99,102,241,0.15)', color: '#818cf8' }}
          >
            <Plus className="w-3.5 h-3.5" />
            New Rule
          </button>
        )}
      </div>

      {/* Selection summary bar */}
      {someChecked && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm"
          style={{ backgroundColor: 'rgba(249,115,22,0.08)', border: '1px solid rgba(249,115,22,0.2)' }}>
          <CheckSquare className="w-4 h-4" style={{ color: '#f97316' }} />
          <span style={{ color: 'var(--text-primary)' }}>
            <strong>{selectedIds.size}</strong> rule{selectedIds.size !== 1 ? 's' : ''} selected
            {selectedSuppressed.length > 0 && ` (${selectedSuppressed.length} suppressed)`}
          </span>
          <button
            onClick={() => setSelectedIds(new Set())}
            className="ml-auto text-xs"
            style={{ color: 'var(--text-muted)' }}
          >
            Clear
          </button>
        </div>
      )}

      {/* Table */}
      <div className="rounded-2xl border" style={{ borderColor: 'var(--border-primary)' }}>
        <div className="overflow-x-auto overflow-y-visible">
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
                <ColumnFilterHeader label="Type"     value={filterType}     onChange={v => { setFilterType(v);     setSelectedIds(new Set()); }} options={RULE_TYPE_OPTIONS} />
                <ColumnFilterHeader label="Provider" value={filterProvider} onChange={v => { setFilterProvider(v); setSelectedIds(new Set()); }} options={uniqueProviders} />
                <ColumnFilterHeader label="Service"  value={filterService}  onChange={v => { setFilterService(v);  setSelectedIds(new Set()); }} options={uniqueServices} />
                <ColumnFilterHeader label="Severity" value={filterSeverity} onChange={v => { setFilterSeverity(v); setSelectedIds(new Set()); }} options={uniqueSeverities} />
                <ColumnFilterHeader label="Status"   value={filterStatus}   onChange={v => { setFilterStatus(v);   setSelectedIds(new Set()); }} options={['active', 'suppressed']} />
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Title</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={canSuppress ? 8 : 7} className="px-4 py-12 text-center text-sm"
                    style={{ color: 'var(--text-muted)' }}>
                    No rules match the current filters
                  </td>
                </tr>
              ) : (
                filteredRules.slice(0, 500).map((rule, idx) => {
                  const checked = selectedIds.has(rule.rule_id);
                  return (
                    <tr
                      key={rule.rule_id || idx}
                      onClick={() => setDetailRule(rule)}
                      className="cursor-pointer transition-colors"
                      style={{
                        borderBottom: '1px solid var(--border-primary)',
                        backgroundColor: checked ? 'rgba(249,115,22,0.04)' : undefined,
                      }}
                      onMouseEnter={e => { if (!checked) e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'; }}
                      onMouseLeave={e => { e.currentTarget.style.backgroundColor = checked ? 'rgba(249,115,22,0.04)' : undefined; }}
                    >
                      {canSuppress && (
                        <td className="px-4 py-3" onClick={e => { e.stopPropagation(); toggleRow(rule.rule_id); }}>
                          {checked
                            ? <CheckSquare className="w-4 h-4" style={{ color: '#f97316' }} />
                            : <Square className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />}
                        </td>
                      )}
                      <td className="px-4 py-3">
                        <code className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                          {rule.rule_id?.length > 48 ? rule.rule_id.slice(0, 48) + '…' : rule.rule_id}
                        </code>
                      </td>
                      <td className="px-4 py-3"><TypeBadge type={rule.rule_type} /></td>
                      <td className="px-4 py-3 text-xs font-medium" style={{ color: 'var(--text-secondary)' }}
                        onClick={e => { e.stopPropagation(); if (rule.provider) { setFilterProvider(p => p === rule.provider ? '' : rule.provider); setSelectedIds(new Set()); } }}>
                        <span className="cursor-pointer hover:underline hover:text-orange-400">{rule.provider || '—'}</span>
                      </td>
                      <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}
                        onClick={e => { e.stopPropagation(); if (rule.service) { setFilterService(s => s === rule.service ? '' : rule.service); setSelectedIds(new Set()); } }}>
                        <span className="cursor-pointer hover:underline hover:text-orange-400">{rule.service || '—'}</span>
                      </td>
                      <td className="px-4 py-3"
                        onClick={e => { e.stopPropagation(); if (rule.severity) { setFilterSeverity(s => s === rule.severity ? '' : rule.severity); setSelectedIds(new Set()); } }}>
                        <span className="cursor-pointer"><SeverityBadge severity={rule.severity} /></span>
                      </td>
                      <td className="px-4 py-3"
                        onClick={e => { e.stopPropagation(); const s = rule.is_suppressed ? 'suppressed' : 'active'; setFilterStatus(prev => prev === s ? '' : s); setSelectedIds(new Set()); }}>
                        {rule.is_suppressed
                          ? <span className="inline-flex items-center gap-1 text-xs font-semibold cursor-pointer hover:opacity-80" style={{ color: '#f97316' }}>
                              <Ban className="w-3 h-3" />Suppressed
                            </span>
                          : <span className="inline-flex items-center gap-1 text-xs font-semibold cursor-pointer hover:opacity-80" style={{ color: '#34d399' }}>
                              <CheckCircle className="w-3 h-3" />Active
                            </span>}
                      </td>
                      <td className="px-4 py-3 text-xs max-w-[240px] truncate" style={{ color: 'var(--text-muted)' }}>
                        {rule.title || '—'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {filteredRules.length > 500 && (
          <div className="px-4 py-2.5 text-xs text-center" style={{ color: 'var(--text-muted)', borderTop: '1px solid var(--border-primary)' }}>
            Showing first 500 of {filteredRules.length.toLocaleString()} rules — use filters to narrow results
          </div>
        )}
      </div>

      {/* Modals */}
      {suppressModal && canSuppress && selectedActive.length > 0 && (
        <BulkSuppressModal
          selectedRules={selectedActive}
          onClose={() => setSuppressModal(false)}
          onSuccess={onSuppressSuccess}
        />
      )}
      {reactivateModal && canSuppress && selectedSuppressed.length > 0 && (
        <ReactivateModal
          selectedRules={selectedSuppressed}
          onClose={() => setReactivateModal(false)}
          onSuccess={onReactivateSuccess}
        />
      )}

      {/* Rule detail side panel */}
      {detailRule && <RuleDetailPanel rule={detailRule} onClose={() => setDetailRule(null)} />}

      {/* Rule builder wizard */}
      {showWizard && (
        <RuleBuilderWizard
          onClose={() => setShowWizard(false)}
          onSuccess={() => { setShowWizard(false); fetchRules(); }}
        />
      )}
    </div>
  );
}

// ── Helper components ──────────────────────────────────────────────────────


function SuppressButton({ count, onClick }) {
  const disabled = count === 0;
  return (
    <button
      onClick={!disabled ? onClick : undefined}
      className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-semibold transition-colors"
      style={{
        backgroundColor: disabled ? 'var(--bg-secondary)' : 'rgba(249,115,22,0.12)',
        color: disabled ? 'var(--text-muted)' : '#f97316',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
      }}
    >
      <Ban className="w-3.5 h-3.5" />
      Suppress{count > 0 ? ` (${count})` : ''}
    </button>
  );
}

function ReactivateButton({ count, onClick }) {
  const disabled = count === 0;
  return (
    <button
      onClick={!disabled ? onClick : undefined}
      className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-semibold transition-colors"
      style={{
        backgroundColor: disabled ? 'var(--bg-secondary)' : 'rgba(52,211,153,0.12)',
        color: disabled ? 'var(--text-muted)' : '#34d399',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
      }}
    >
      <RotateCcw className="w-3.5 h-3.5" />
      Reactivate{count > 0 ? ` (${count})` : ''}
    </button>
  );
}

// Clickable column header with inline dropdown filter
function ColumnFilterHeader({ label, value, onChange, options }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  return (
    <th ref={ref} className="px-4 py-3 text-left relative" style={{ whiteSpace: 'nowrap' }}>
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wide transition-colors"
        style={{ color: value ? '#f97316' : 'var(--text-muted)' }}
      >
        {value || label}
        {value
          ? <X className="w-3 h-3" onClick={e => { e.stopPropagation(); onChange(''); setOpen(false); }} />
          : <ChevronDown className="w-3 h-3 opacity-60" />}
      </button>
      {open && (
        <div className="absolute top-full left-0 mt-1 min-w-[140px] max-h-56 overflow-y-auto rounded-xl border shadow-xl z-50"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {options.map(opt => (
            <button
              key={opt}
              onClick={() => { onChange(opt === value ? '' : opt); setOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm first:rounded-t-xl last:rounded-b-xl"
              style={{ color: opt === value ? '#f97316' : 'var(--text-primary)', backgroundColor: opt === value ? 'rgba(249,115,22,0.06)' : 'transparent' }}
              onMouseEnter={e => { if (opt !== value) e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'; }}
              onMouseLeave={e => { e.currentTarget.style.backgroundColor = opt === value ? 'rgba(249,115,22,0.06)' : 'transparent'; }}
            >
              {opt}
            </button>
          ))}
        </div>
      )}
    </th>
  );
}
