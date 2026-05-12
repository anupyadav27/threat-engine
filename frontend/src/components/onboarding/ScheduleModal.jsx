'use client';

/**
 * ScheduleModal — onboarding-D10
 *
 * Props:
 *   account          — account object { account_id, account_type, tenant_id, ... }
 *   existingSchedule — existing schedule object or null (creates new if null)
 *   onClose()        — close handler
 *   onSaved()        — called after successful save
 *   inlineMode       — if true, renders without the modal overlay wrapper (for wizard embed)
 *
 * Security:
 *   - All PATCH/POST calls go through /gateway (never direct engine URL)
 *   - tenant_id is never taken from form state — comes from account prop
 *   - Region and service values are constrained to typed strings
 */

import { useState } from 'react';
import { X, Calendar, ChevronDown, Loader2 } from 'lucide-react';
import { CRON_PRESETS, getNextRunTime, isCustomCron, SERVICE_CATEGORIES } from '@/lib/schedule-utils';
import { getAccountTypeById } from '@/lib/catalog';

// ── Engine defaults by account_type ────────────────────────────────────────

function getDefaultEngines(accountType) {
  const at = getAccountTypeById(accountType);
  return at?.scope_capabilities?.engines || ['discovery', 'check'];
}

// ── TagInput — shared chip/tag input ───────────────────────────────────────

function TagInput({ label, hint, value, onChange, placeholder, chipColor }) {
  const [input, setInput] = useState('');
  const color = chipColor || '#3b82f6';

  const add = (raw) => {
    const trimmed = raw.trim().replace(/,$/, '').trim();
    if (!trimmed || value.includes(trimmed)) { setInput(''); return; }
    onChange([...value, trimmed]);
    setInput('');
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      add(input);
    } else if (e.key === 'Backspace' && input === '' && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  };

  return (
    <div>
      {label && (
        <div className="text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
          {label}
        </div>
      )}
      {hint && (
        <div className="text-[11px] mb-1.5" style={{ color: 'var(--text-muted)' }}>{hint}</div>
      )}
      <div
        className="flex flex-wrap gap-1.5 p-2 rounded-lg border min-h-[38px] cursor-text"
        style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}
      >
        {value.map(v => (
          <span
            key={v}
            className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-mono"
            style={{ backgroundColor: `${color}18`, color }}
          >
            {v}
            <button
              type="button"
              onClick={() => onChange(value.filter(x => x !== v))}
              className="hover:opacity-60 text-base leading-none"
              aria-label={`Remove ${v}`}
            >
              ×
            </button>
          </span>
        ))}
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={() => input && add(input)}
          placeholder={value.length === 0 ? placeholder : ''}
          className="flex-1 min-w-[120px] text-xs bg-transparent outline-none"
          style={{ color: 'var(--text-primary)' }}
        />
      </div>
    </div>
  );
}

// ── Region multi-select ────────────────────────────────────────────────────

function RegionSelect({ included, excluded, onChange }) {
  return (
    <div className="space-y-3">
      <TagInput
        label="Include regions (leave empty = all regions)"
        value={included}
        onChange={inc => onChange(inc, excluded)}
        placeholder="e.g. us-east-1  (Enter or comma to add)"
        chipColor="#22c55e"
      />
      <TagInput
        label="Exclude regions"
        value={excluded}
        onChange={exc => onChange(included, exc)}
        placeholder="e.g. ap-south-1  (Enter or comma to add)"
        chipColor="#ef4444"
      />
    </div>
  );
}

// ── Service exclude multi-select ───────────────────────────────────────────

function ServiceExcludeSelect({ excluded, onChange }) {
  return (
    <TagInput
      label="Exclude services"
      hint="Services to skip during scan (leave empty to scan all). E.g. glacier, s3, rds"
      value={excluded}
      onChange={onChange}
      placeholder="e.g. glacier  (Enter or comma to add)"
      chipColor="#f59e0b"
    />
  );
}

// ── Engine selector ─────────────────────────────────────────────────────────

function EngineSelector({ available, selected, onChange }) {
  const toggle = (eng) => {
    onChange(selected.includes(eng) ? selected.filter(e => e !== eng) : [...selected, eng]);
  };

  return (
    <div className="flex flex-wrap gap-1.5">
      {available.map(eng => {
        const on = selected.includes(eng);
        return (
          <button
            key={eng}
            type="button"
            onClick={() => toggle(eng)}
            className="px-2.5 py-1 text-xs rounded-lg border transition-colors"
            style={{
              backgroundColor: on ? 'rgba(59,130,246,0.15)' : 'var(--bg-tertiary)',
              borderColor: on ? 'rgba(59,130,246,0.4)' : 'var(--border-primary)',
              color: on ? 'var(--accent-primary)' : 'var(--text-muted)',
            }}
          >
            {eng}
          </button>
        );
      })}
    </div>
  );
}

// ── Cron display helper ─────────────────────────────────────────────────────

const CRON_LABELS = {
  '0 2 * * *': 'Daily at 2:00 AM UTC',
  '0 0 * * *': 'Daily at 12:00 AM UTC',
  '0 6 * * *': 'Daily at 6:00 AM UTC',
  '0 2 * * 0': 'Weekly (Sunday 2:00 AM UTC)',
  '0 2 * * 1': 'Weekly (Monday 2:00 AM UTC)',
  '0 2 1 * *': 'Monthly (1st at 2:00 AM UTC)',
  '0 * * * *': 'Hourly',
};

function formatCron(expr) {
  return CRON_LABELS[expr] ?? expr;
}

// ── Main modal component ────────────────────────────────────────────────────

export default function ScheduleModal({
  account,
  existingSchedule,
  onClose,
  onSaved,
  inlineMode = false,
}) {
  const defaultEngines = getDefaultEngines(account?.account_type);
  const isCloud = account?.account_type === 'cloud_csp' ||
    ['aws', 'azure', 'gcp', 'oci', 'alicloud', 'ibm', 'k8s'].includes(account?.provider);

  const [form, setForm] = useState({
    cron_expression:   existingSchedule?.cron_expression   || '0 2 * * *',
    include_regions:   existingSchedule?.include_regions   || [],
    exclude_regions:   existingSchedule?.exclude_regions   || [],
    exclude_services:  existingSchedule?.exclude_services  || [],
    engines_requested: existingSchedule?.engines_requested || defaultEngines,
    enabled:           existingSchedule?.enabled ?? true,
  });

  const [customCron, setCustomCron] = useState(
    existingSchedule ? isCustomCron(existingSchedule.cron_expression) : false,
  );
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState('');

  const setField = (key, val) => setForm(f => ({ ...f, [key]: val }));

  const handlePreset = (val) => {
    if (val === 'custom') { setCustomCron(true); return; }
    setCustomCron(false);
    setField('cron_expression', val);
  };

  const handleSubmit = async () => {
    setSaving(true);
    setError('');
    try {
      const method = existingSchedule ? 'PATCH' : 'POST';
      const scheduleId = existingSchedule?.schedule_id || existingSchedule?.id;
      const url = existingSchedule
        ? `/gateway/api/v1/schedules/${scheduleId}`
        : `/gateway/api/v1/schedules/`;

      const body = {
        ...form,
        account_id: account?.account_id || account?.id,
        // tenant_id inferred by gateway from auth cookie — never from user input
      };

      const resp = await fetch(url, {
        method,
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || `Error ${resp.status}`);
      }

      if (onSaved) onSaved();
      onClose();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  // "Disable Schedule" — sends active: false immediately via PATCH
  const handleDisable = async () => {
    if (!existingSchedule) return;
    setSaving(true);
    setError('');
    try {
      const scheduleId = existingSchedule.schedule_id || existingSchedule.id;
      const resp = await fetch(`/gateway/api/v1/schedules/${scheduleId}`, {
        method: 'PATCH',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: false, enabled: false }),
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || `Error ${resp.status}`);
      }
      if (onSaved) onSaved();
      onClose();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const selectedPreset = CRON_PRESETS.find(p => p.value === form.cron_expression)?.value || 'custom';
  const nextRun = getNextRunTime(form.cron_expression);

  // ── Inner form content (reused in both modal and inline modes) ──────────

  const formContent = (
    <div className="p-5 space-y-5">

      {/* ── Current schedule summary (edit mode) ── */}
      {existingSchedule?.cron_expression && (
        <div
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
          style={{
            backgroundColor: 'rgba(59,130,246,0.06)',
            border: '1px solid rgba(59,130,246,0.2)',
            color: 'var(--text-secondary)',
          }}
        >
          <Calendar size={12} style={{ color: 'var(--accent-primary)' }} />
          <span>Current: </span>
          <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
            {formatCron(existingSchedule.cron_expression)}
          </span>
        </div>
      )}

      {/* ── Cron preset ── */}
      <div>
        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
          Scan Frequency
        </label>
        <div className="relative">
          <select
            value={customCron ? 'custom' : selectedPreset}
            onChange={e => handlePreset(e.target.value)}
            className="w-full appearance-none pl-3 pr-8 py-2 text-sm rounded-lg border outline-none"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              borderColor: 'var(--border-primary)',
              color: 'var(--text-primary)',
            }}
          >
            {CRON_PRESETS.map(p => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
          <ChevronDown
            size={12}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
            style={{ color: 'var(--text-muted)' }}
          />
        </div>

        {customCron && (
          <input
            value={form.cron_expression}
            onChange={e => setField('cron_expression', e.target.value)}
            placeholder="0 2 * * *"
            className="mt-2 w-full px-3 py-2 text-sm font-mono rounded-lg border outline-none"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              borderColor: 'var(--border-primary)',
              color: 'var(--text-primary)',
            }}
          />
        )}

        {form.cron_expression && (
          <div className="mt-1.5 text-[11px]" style={{ color: 'var(--text-muted)' }}>
            Next run: <span style={{ color: 'var(--accent-primary)' }}>{nextRun}</span>
          </div>
        )}
      </div>

      {/* ── Region scope (cloud accounts only) ── */}
      {isCloud && (
        <div>
          <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
            Region Scope
          </label>
          <RegionSelect
            included={form.include_regions}
            excluded={form.exclude_regions}
            onChange={(inc, exc) => setForm(f => ({
              ...f,
              include_regions: inc,
              exclude_regions: exc,
            }))}
          />
        </div>
      )}

      {/* ── Service exclusions (cloud accounts only) — AC5 ── */}
      {isCloud && (
        <div>
          <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
            Service Exclusions
          </label>
          <ServiceExcludeSelect
            excluded={form.exclude_services}
            onChange={exc => setField('exclude_services', exc)}
          />
        </div>
      )}

      {/* ── Engine selection ── */}
      <div>
        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
          Engines to Run
        </label>
        <EngineSelector
          available={defaultEngines}
          selected={form.engines_requested}
          onChange={v => setField('engines_requested', v)}
        />
      </div>

      {/* ── Enable/disable toggle — AC10 ── */}
      <div className="flex items-center justify-between py-1">
        <div className="flex items-center gap-2">
          <label className="relative inline-flex cursor-pointer">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={e => setField('enabled', e.target.checked)}
              className="sr-only peer"
            />
            <div
              className="w-8 h-4 rounded-full transition-colors relative"
              style={{
                backgroundColor: form.enabled ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                border: '1px solid var(--border-primary)',
              }}
            >
              <div
                className={`w-3 h-3 bg-white rounded-full absolute top-0.5 transition-transform ${form.enabled ? 'translate-x-4' : 'translate-x-0.5'}`}
              />
            </div>
          </label>
          <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            {form.enabled ? 'Schedule enabled' : 'Schedule disabled (adhoc/manual only)'}
          </span>
        </div>

        {/* Disable Schedule quick-action (edit mode) — AC10 */}
        {existingSchedule && form.enabled && (
          <button
            type="button"
            onClick={handleDisable}
            disabled={saving}
            className="text-xs px-2.5 py-1 rounded border hover:opacity-70 transition-opacity disabled:opacity-40"
            style={{ borderColor: 'rgba(239,68,68,0.3)', color: '#f87171' }}
          >
            Disable Schedule
          </button>
        )}
      </div>

      {/* ── Error ── */}
      {error && (
        <div
          className="text-xs p-2.5 rounded-lg border"
          style={{
            borderColor: 'rgba(239,68,68,0.3)',
            backgroundColor: 'rgba(239,68,68,0.08)',
            color: '#f87171',
          }}
        >
          {error}
        </div>
      )}

      {/* ── Excluded regions badge summary — AC8 ── */}
      {(form.exclude_regions.length > 0 || form.exclude_services.length > 0) && (
        <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
          {form.exclude_regions.length > 0 && (
            <span className="mr-3">
              <span
                className="inline-block px-1.5 py-0.5 rounded-full text-[10px] font-medium mr-1"
                style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#f87171' }}
              >
                {form.exclude_regions.length} region{form.exclude_regions.length !== 1 ? 's' : ''} excluded
              </span>
            </span>
          )}
          {form.exclude_services.length > 0 && (
            <span
              className="inline-block px-1.5 py-0.5 rounded-full text-[10px] font-medium"
              style={{ backgroundColor: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}
            >
              {form.exclude_services.length} service{form.exclude_services.length !== 1 ? 's' : ''} excluded
            </span>
          )}
        </div>
      )}

      {/* ── Actions ── */}
      <div className="flex gap-2 pt-1">
        {!inlineMode && (
          <button
            type="button"
            onClick={onClose}
            className="flex-1 py-2 text-sm rounded-lg border hover:opacity-80 transition-opacity"
            style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
          >
            Cancel
          </button>
        )}
        <button
          type="button"
          onClick={handleSubmit}
          disabled={saving}
          className="flex-1 py-2 text-sm font-medium rounded-lg disabled:opacity-50 transition-opacity hover:opacity-90 flex items-center justify-center gap-1.5"
          style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
        >
          {saving
            ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving…</>
            : existingSchedule ? 'Update Schedule' : 'Create Schedule'}
        </button>
      </div>
    </div>
  );

  // ── Inline mode (embedded in wizard step) — AC9 ─────────────────────────

  if (inlineMode) {
    return (
      <div className="space-y-1">
        {formContent}
      </div>
    );
  }

  // ── Modal overlay mode ───────────────────────────────────────────────────

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
    >
      <div
        className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-2xl border shadow-2xl"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-5 py-4 border-b sticky top-0"
          style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-card)' }}
        >
          <div className="flex items-center gap-2">
            <Calendar size={16} style={{ color: 'var(--accent-primary)' }} />
            <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
              {existingSchedule ? 'Edit Schedule' : 'Create Schedule'}
            </span>
            {existingSchedule && (
              <span
                className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
                style={{
                  backgroundColor: existingSchedule.enabled ? 'rgba(34,197,94,0.12)' : 'rgba(148,163,184,0.12)',
                  color: existingSchedule.enabled ? '#22c55e' : '#94a3b8',
                }}
              >
                {existingSchedule.enabled ? 'Active' : 'Disabled'}
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="hover:opacity-60 transition-opacity"
            style={{ color: 'var(--text-muted)' }}
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </div>

        {formContent}
      </div>
    </div>
  );
}
