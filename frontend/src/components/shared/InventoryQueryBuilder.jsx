'use client';

/**
 * InventoryQueryBuilder — Orca-style visual query builder for the inventory page.
 *
 * Layout:
 *   FIND  [ Asset Type ▾ ]                                  [ Search ]  [ ✕ ]
 *   ────────────────────────────────────────────────────────────────────────
 *   WITH  [ field ▾ ]  [ operator ▾ ]  [ value ]            [ × ]
 *   AND   [ field ▾ ]  [ operator ▾ ]  [ value ]            [ × ]
 *   + Add Filter
 *
 * Executes client-side filtering on the `assets` array passed as a prop,
 * calling `onResults(filteredAssets)` on every change.
 */

import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { ChevronDown, Plus, X, Search } from 'lucide-react';

// ── Field definitions ──────────────────────────────────────────────────────
const FIELDS = [
  { id: 'provider',             label: 'Cloud Provider',     type: 'enum',    values: ['aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud'] },
  { id: 'region',               label: 'Region',             type: 'text' },
  { id: 'service',              label: 'Service',            type: 'text' },
  { id: 'resource_type',        label: 'Resource Type',      type: 'text' },
  { id: 'status',               label: 'Status',             type: 'enum',    values: ['active', 'stopped', 'terminated', 'running'] },
  { id: 'severity',             label: 'Alert Severity',     type: 'enum',    values: ['critical', 'high', 'medium', 'low'] },
  { id: 'is_internet_exposed',  label: 'Internet Facing',    type: 'bool' },
  { id: 'can_access_pii',       label: 'Has PII Access',     type: 'bool' },
  { id: 'data_classification',  label: 'Data Classification',type: 'enum',    values: ['pii', 'phi', 'pci', 'confidential', 'restricted', 'internal', 'public', 'unknown'] },
  { id: 'is_on_attack_path',    label: 'On Attack Path',     type: 'bool' },
  { id: 'is_crown_jewel',       label: 'Crown Jewel',        type: 'bool' },
  { id: 'has_active_cdr_actor', label: 'CDR Activity',       type: 'bool' },
  { id: 'drift_detected',       label: 'Drift Detected',     type: 'bool' },
  { id: 'is_encrypted_at_rest', label: 'Encrypted at Rest',  type: 'bool' },
  { id: 'has_known_exploit',    label: 'Has Known Exploit',  type: 'bool' },
  { id: 'overall_posture_score',label: 'Risk Score',         type: 'number' },
  { id: 'vuln_critical_count',  label: 'Critical CVEs',      type: 'number' },
  { id: 'tag_key',              label: 'Tag Key',            type: 'text',    special: 'tag_key' },
  { id: 'tag_value',            label: 'Tag Value',          type: 'text',    special: 'tag_value' },
];

const OPERATORS_TEXT   = ['contains', 'equals', 'starts with', 'not contains'];
const OPERATORS_ENUM   = ['is', 'is not'];
const OPERATORS_BOOL   = ['is'];
const OPERATORS_NUMBER = ['=', '>', '<', '>=', '<='];

function getOperators(fieldDef) {
  if (!fieldDef) return OPERATORS_TEXT;
  if (fieldDef.type === 'bool')   return OPERATORS_BOOL;
  if (fieldDef.type === 'enum')   return OPERATORS_ENUM;
  if (fieldDef.type === 'number') return OPERATORS_NUMBER;
  return OPERATORS_TEXT;
}

function makeRow() {
  return { id: Date.now() + Math.random(), fieldId: 'provider', operator: 'is', value: '' };
}

// ── Client-side filter engine ────────────────────────────────────────────
function applyCondition(asset, row) {
  const fieldDef = FIELDS.find(f => f.id === row.fieldId);
  if (!fieldDef || !row.value) return true;

  const val = row.value;
  const op  = row.operator;

  // Tag special cases
  if (fieldDef.special === 'tag_key') {
    const tags = asset.tags || {};
    return Object.keys(tags).some(k => k.toLowerCase().includes(val.toLowerCase()));
  }
  if (fieldDef.special === 'tag_value') {
    const tags = asset.tags || {};
    return Object.values(tags).some(v => String(v).toLowerCase().includes(val.toLowerCase()));
  }

  const raw = asset[row.fieldId];

  if (fieldDef.type === 'bool') {
    const boolVal = val === 'true' || val === 'yes';
    return !!raw === boolVal;
  }

  if (fieldDef.type === 'number') {
    const n = Number(raw) || 0;
    const threshold = Number(val) || 0;
    if (op === '=')  return n === threshold;
    if (op === '>')  return n > threshold;
    if (op === '<')  return n < threshold;
    if (op === '>=') return n >= threshold;
    if (op === '<=') return n <= threshold;
    return true;
  }

  // enum + text
  const asStr = (raw || '').toString().toLowerCase();
  const valLow = val.toLowerCase();

  if (op === 'is' || op === 'equals')           return asStr === valLow;
  if (op === 'is not')                          return asStr !== valLow;
  if (op === 'contains')                        return asStr.includes(valLow);
  if (op === 'not contains')                    return !asStr.includes(valLow);
  if (op === 'starts with')                     return asStr.startsWith(valLow);

  return true;
}

function filterAssets(assets, assetTypeFilter, conditions) {
  let result = assets;

  // Asset type filter
  if (assetTypeFilter && assetTypeFilter !== '__all__') {
    const atLow = assetTypeFilter.toLowerCase();
    result = result.filter(a => {
      const svc = (a.service || '').toLowerCase();
      const rt  = (a.resource_type || '').toLowerCase();
      return svc === atLow || rt.startsWith(atLow) || rt.includes(atLow);
    });
  }

  // Condition rows — all must pass (AND logic)
  const activeConditions = conditions.filter(r => r.value !== '');
  for (const cond of activeConditions) {
    result = result.filter(a => applyCondition(a, cond));
  }

  return result;
}

// ── Sub-components ───────────────────────────────────────────────────────

function DropdownSelect({ value, options, onChange, placeholder, width = 160 }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const selectedLabel = options.find(o => (o.value ?? o) === value)?.label ?? value ?? placeholder;

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '4px 8px', borderRadius: 6,
          border: '1px solid var(--border-primary)',
          backgroundColor: 'var(--bg-card)', color: 'var(--text-primary)',
          fontSize: 12, cursor: 'pointer', whiteSpace: 'nowrap',
          minWidth: width, justifyContent: 'space-between',
        }}
      >
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{selectedLabel}</span>
        <ChevronDown size={11} style={{ flexShrink: 0, opacity: 0.6 }} />
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, zIndex: 999, minWidth: width,
          backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)',
          borderRadius: 8, boxShadow: '0 8px 24px rgba(0,0,0,0.3)', marginTop: 4,
          maxHeight: 220, overflowY: 'auto',
        }}>
          {options.map((opt) => {
            const optVal   = opt.value ?? opt;
            const optLabel = opt.label ?? opt;
            const active   = optVal === value;
            return (
              <div
                key={optVal}
                onClick={() => { onChange(optVal); setOpen(false); }}
                style={{
                  padding: '7px 12px', fontSize: 12, cursor: 'pointer',
                  color: active ? 'var(--accent-primary)' : 'var(--text-primary)',
                  backgroundColor: active ? 'var(--bg-subtle)' : 'transparent',
                  transition: 'background 0.1s',
                }}
                onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--bg-hover)'}
                onMouseLeave={e => e.currentTarget.style.backgroundColor = active ? 'var(--bg-subtle)' : 'transparent'}
              >
                {optLabel}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function BoolValueSelect({ value, onChange }) {
  return (
    <DropdownSelect
      value={value || 'true'}
      options={[{ value: 'true', label: 'Yes' }, { value: 'false', label: 'No' }]}
      onChange={onChange}
      width={80}
    />
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export default function InventoryQueryBuilder({ assets = [], onResults, taxonomyData = null }) {
  const [assetTypeFilter, setAssetTypeFilter] = useState('__all__');
  const [conditions, setConditions] = useState([]);
  const [hasSearched, setHasSearched] = useState(false);

  // Build asset type options from actual data or taxonomy
  const assetTypeOptions = useMemo(() => {
    const base = [{ value: '__all__', label: 'All Asset Types' }];
    const services = [...new Set(assets.map(a => a.service).filter(Boolean))].sort();
    return [...base, ...services.map(s => ({ value: s, label: s.toUpperCase() }))];
  }, [assets]);

  const addCondition = useCallback(() => {
    setConditions(prev => [...prev, makeRow()]);
  }, []);

  const removeCondition = useCallback((id) => {
    setConditions(prev => prev.filter(r => r.id !== id));
  }, []);

  const updateCondition = useCallback((id, patch) => {
    setConditions(prev => prev.map(r => {
      if (r.id !== id) return r;
      const next = { ...r, ...patch };
      // When field changes, reset operator to first valid operator and clear value
      if (patch.fieldId && patch.fieldId !== r.fieldId) {
        const fieldDef = FIELDS.find(f => f.id === patch.fieldId);
        const ops = getOperators(fieldDef);
        next.operator = ops[0];
        next.value = fieldDef?.type === 'bool' ? 'true' : '';
      }
      return next;
    }));
  }, []);

  const executeSearch = useCallback(() => {
    setHasSearched(true);
    const result = filterAssets(assets, assetTypeFilter, conditions);
    onResults?.(result);
  }, [assets, assetTypeFilter, conditions, onResults]);

  const clearAll = useCallback(() => {
    setAssetTypeFilter('__all__');
    setConditions([]);
    setHasSearched(false);
    onResults?.(assets);
  }, [assets, onResults]);

  // Auto-search when conditions are empty (reset to full list)
  useEffect(() => {
    if (conditions.length === 0 && assetTypeFilter === '__all__' && hasSearched) {
      onResults?.(assets);
    }
  }, [conditions, assetTypeFilter, hasSearched, assets, onResults]);

  const hasActiveFilter = assetTypeFilter !== '__all__' || conditions.some(c => c.value !== '');
  const fieldOptions = FIELDS.map(f => ({ value: f.id, label: f.label }));

  return (
    <div style={{
      backgroundColor: 'var(--bg-card)',
      border: '1px solid var(--border-primary)',
      borderRadius: 10,
      padding: '12px 16px',
      marginBottom: 16,
    }}>
      {/* ── FIND bar ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.06em', minWidth: 36 }}>
          FIND
        </span>
        <DropdownSelect
          value={assetTypeFilter}
          options={assetTypeOptions}
          onChange={setAssetTypeFilter}
          placeholder="All Asset Types"
          width={180}
        />
        <div style={{ flex: 1 }} />
        <button
          onClick={executeSearch}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '5px 14px', borderRadius: 6,
            backgroundColor: 'var(--accent-primary)', color: '#fff',
            border: 'none', fontSize: 12, fontWeight: 600, cursor: 'pointer',
          }}
        >
          <Search size={12} />
          Search
        </button>
        {hasActiveFilter && (
          <button
            onClick={clearAll}
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              padding: '5px 10px', borderRadius: 6,
              backgroundColor: 'transparent', color: 'var(--text-muted)',
              border: '1px solid var(--border-primary)', fontSize: 12, cursor: 'pointer',
            }}
          >
            <X size={11} />
            Clear
          </button>
        )}
      </div>

      {/* ── Condition rows ── */}
      {conditions.length > 0 && (
        <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {conditions.map((row, idx) => {
            const fieldDef  = FIELDS.find(f => f.id === row.fieldId);
            const operators = getOperators(fieldDef);
            return (
              <div key={row.id} style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                {/* WITH / AND label */}
                <span style={{
                  fontSize: 10, fontWeight: 700, color: 'var(--accent-primary)',
                  letterSpacing: '0.06em', minWidth: 36, textAlign: 'right',
                }}>
                  {idx === 0 ? 'WITH' : 'AND'}
                </span>

                {/* Field selector */}
                <DropdownSelect
                  value={row.fieldId}
                  options={fieldOptions}
                  onChange={(v) => updateCondition(row.id, { fieldId: v })}
                  width={170}
                />

                {/* Operator */}
                <DropdownSelect
                  value={row.operator}
                  options={operators}
                  onChange={(v) => updateCondition(row.id, { operator: v })}
                  width={100}
                />

                {/* Value input */}
                {fieldDef?.type === 'bool' ? (
                  <BoolValueSelect
                    value={row.value}
                    onChange={(v) => updateCondition(row.id, { value: v })}
                  />
                ) : fieldDef?.type === 'enum' ? (
                  <DropdownSelect
                    value={row.value}
                    options={(fieldDef.values || []).map(v => ({ value: v, label: v }))}
                    onChange={(v) => updateCondition(row.id, { value: v })}
                    placeholder="Select value..."
                    width={140}
                  />
                ) : (
                  <input
                    value={row.value}
                    onChange={(e) => updateCondition(row.id, { value: e.target.value })}
                    onKeyDown={(e) => { if (e.key === 'Enter') executeSearch(); }}
                    placeholder={fieldDef?.type === 'number' ? '0' : 'Value...'}
                    style={{
                      padding: '4px 10px', borderRadius: 6,
                      border: '1px solid var(--border-primary)',
                      backgroundColor: 'var(--bg-card)', color: 'var(--text-primary)',
                      fontSize: 12, width: 140, outline: 'none',
                    }}
                  />
                )}

                {/* Remove row */}
                <button
                  onClick={() => removeCondition(row.id)}
                  style={{
                    padding: '4px 6px', borderRadius: 5, border: 'none',
                    backgroundColor: 'transparent', color: 'var(--text-muted)',
                    cursor: 'pointer', display: 'flex', alignItems: 'center',
                  }}
                >
                  <X size={13} />
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Add Filter button ── */}
      <div style={{ marginTop: conditions.length > 0 ? 10 : 12 }}>
        <button
          onClick={addCondition}
          style={{
            display: 'flex', alignItems: 'center', gap: 5,
            padding: '4px 10px', borderRadius: 6,
            border: '1px dashed var(--border-primary)',
            backgroundColor: 'transparent', color: 'var(--text-muted)',
            fontSize: 12, cursor: 'pointer',
          }}
        >
          <Plus size={12} />
          Add Filter
        </button>
      </div>
    </div>
  );
}
