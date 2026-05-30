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
      <div className="w-[440px] rounded-2xl border shadow-2xl flex flex-col max-h-[90vh]" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between p-5 border-b flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <Ban className="w-4 h-4" style={{ color: '#f97316' }} />
            <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
              Suppress {selectedRules.length} Rule{selectedRules.length !== 1 ? 's' : ''}
            </span>
          </div>
          <button onClick={onClose}><X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
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
        <div className="flex justify-end gap-3 p-5 border-t flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
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

// ── Meta section helper ───────────────────────────────────────────────────
function MetaSection({ label, children }) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-wider mb-1.5"
        style={{ color: 'var(--text-muted)' }}>{label}</div>
      {children}
    </div>
  );
}

// ── Rule detail panel ─────────────────────────────────────────────────────
function RuleDetailPanel({ rule, onClose }) {
  if (!rule) return null;

  const severityColor = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280',
  }[rule.severity] || '#6b7280';

  const mitreT = rule.mitre_tactics  || [];
  const mitreTech = rule.mitre_techniques || [];
  const frameworks = rule.compliance_frameworks?.frameworks || [];
  const effortColor = { low: '#34d399', medium: '#eab308', high: '#f97316' }[rule.remediation_effort] || 'var(--text-muted)';

  return (
    <div className="fixed inset-y-0 right-0 w-[520px] z-40 border-l shadow-2xl flex flex-col"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

      {/* Header */}
      <div className="flex items-start justify-between p-5 border-b gap-3"
        style={{ borderColor: 'var(--border-primary)' }}>
        <div className="min-w-0">
          <div className="text-xs font-mono mb-1" style={{ color: 'var(--text-muted)' }}>{rule.rule_id}</div>
          <div className="text-sm font-semibold leading-snug" style={{ color: 'var(--text-primary)' }}>
            {rule.title || rule.rule_id}
          </div>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full"
              style={{ backgroundColor: `${severityColor}22`, color: severityColor }}>
              {rule.severity?.toUpperCase()}
            </span>
            <TypeBadge type={rule.rule_type} />
            {rule.is_suppressed && (
              <span className="flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full"
                style={{ backgroundColor: 'rgba(249,115,22,0.12)', color: '#f97316' }}>
                <Ban className="w-3 h-3" />Suppressed
              </span>
            )}
          </div>
        </div>
        <button onClick={onClose} className="flex-shrink-0 mt-0.5">
          <X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">

        {/* Identity grid */}
        <div className="grid grid-cols-3 gap-3 p-3 rounded-xl"
          style={{ backgroundColor: 'var(--bg-secondary)' }}>
          {[
            ['Provider',  rule.provider],
            ['Service',   rule.service],
            ['Resource',  rule.resource],
            ['Domain',    rule.domain],
            ['Category',  rule.posture_category || rule.subcategory],
            ['Effort',    rule.remediation_effort],
          ].map(([k, v]) => v ? (
            <div key={k}>
              <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-muted)' }}>{k}</div>
              <div className="text-xs font-medium capitalize"
                style={{ color: k === 'Effort' ? effortColor : 'var(--text-primary)' }}>{v}</div>
            </div>
          ) : null)}
          {rule.risk_score != null && (
            <div>
              <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-muted)' }}>Risk Score</div>
              <div className="text-xs font-bold" style={{ color: rule.risk_score >= 70 ? '#ef4444' : rule.risk_score >= 40 ? '#f97316' : '#34d399' }}>
                {rule.risk_score}/100
              </div>
            </div>
          )}
        </div>

        {/* Description */}
        {rule.description && (
          <MetaSection label="Description">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{rule.description}</p>
          </MetaSection>
        )}

        {/* Rationale */}
        {rule.rationale && (
          <MetaSection label="Rationale">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{rule.rationale}</p>
          </MetaSection>
        )}

        {/* Remediation */}
        {rule.remediation && (
          <MetaSection label="Remediation">
            <div className="rounded-lg p-3 text-sm leading-relaxed"
              style={{ backgroundColor: 'rgba(52,211,153,0.06)', color: 'var(--text-secondary)', border: '1px solid rgba(52,211,153,0.15)' }}>
              {rule.remediation}
            </div>
          </MetaSection>
        )}

        {/* MITRE */}
        {(mitreT.length > 0 || mitreTech.length > 0) && (
          <MetaSection label="MITRE ATT&CK">
            <div className="space-y-1.5">
              {mitreT.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {mitreT.map(t => (
                    <span key={t} className="text-xs px-2 py-0.5 rounded-full"
                      style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171' }}>{t}</span>
                  ))}
                </div>
              )}
              {mitreTech.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {mitreTech.map(t => (
                    <span key={t} className="text-xs px-2 py-0.5 rounded font-mono"
                      style={{ backgroundColor: 'rgba(239,68,68,0.06)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>{t}</span>
                  ))}
                </div>
              )}
            </div>
          </MetaSection>
        )}

        {/* Compliance frameworks */}
        {frameworks.length > 0 && (
          <MetaSection label="Compliance Frameworks">
            <div className="flex flex-wrap gap-1.5">
              {frameworks.map(f => (
                <span key={f} className="text-xs px-2 py-0.5 rounded"
                  style={{ backgroundColor: 'rgba(99,102,241,0.1)', color: '#a5b4fc' }}>
                  {f.replace(/_/g, ' ').toUpperCase()}
                </span>
              ))}
            </div>
          </MetaSection>
        )}

        {/* Rule ID (full, copyable) */}
        <MetaSection label="Rule ID">
          <code className="text-xs font-mono break-all block p-2 rounded"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-muted)' }}>
            {rule.rule_id}
          </code>
        </MetaSection>

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
                {/* Filterable columns in user-requested order */}
                {['provider','service','rule_type','status','severity'].map(col => (
                  <th key={col} className="px-4 py-3 text-left" style={{ whiteSpace: 'nowrap' }}>
                    <div className="flex items-center gap-1">
                      <span className="text-xs font-semibold uppercase tracking-wide"
                        style={{ color: activeCount(col) > 0 ? '#3b82f6' : 'var(--text-muted)' }}>
                        {{ provider:'Provider', service:'Service', rule_type:'Type', status:'Status', severity:'Severity' }[col]}
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
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide min-w-[260px]"
                  style={{ color: 'var(--text-muted)' }}>Title</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide"
                  style={{ color: 'var(--text-muted)' }}>Rule ID</th>
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
                    <tr key={rule.rule_id || idx}
                      onClick={() => setDetailRule(rule)}
                      className="cursor-pointer"
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
                      <td className="px-4 py-2.5 text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{rule.provider || '—'}</td>
                      <td className="px-4 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{rule.service || '—'}</td>
                      <td className="px-4 py-2.5"><TypeBadge type={rule.rule_type} /></td>
                      <td className="px-4 py-2.5">
                        {rule.is_suppressed
                          ? <span className="inline-flex items-center gap-1 text-xs font-semibold" style={{ color: '#f97316' }}><Ban className="w-3 h-3" />Suppressed</span>
                          : <span className="inline-flex items-center gap-1 text-xs font-semibold" style={{ color: '#34d399' }}><CheckCircle className="w-3 h-3" />Active</span>}
                      </td>
                      <td className="px-4 py-2.5"><SeverityBadge severity={rule.severity} /></td>
                      <td className="px-4 py-2.5 text-xs max-w-[300px]" style={{ color: 'var(--text-primary)' }}>
                        <div className="truncate">{rule.title || '—'}</div>
                        {rule.domain && <div className="text-[10px] mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>{rule.domain}</div>}
                      </td>
                      <td className="px-4 py-2.5">
                        <code className="text-[11px] font-mono" style={{ color: 'var(--text-muted)' }}>
                          {(rule.rule_id || '').length > 40 ? rule.rule_id.slice(0, 40) + '…' : rule.rule_id}
                        </code>
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
