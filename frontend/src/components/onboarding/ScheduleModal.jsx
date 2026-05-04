'use client';

import { useState } from 'react';
import { X, Calendar, ChevronDown } from 'lucide-react';
import { CRON_PRESETS, getNextRunTime, isCustomCron, SERVICE_CATEGORIES } from '@/lib/schedule-utils';
import { getAccountTypeById } from '@/lib/catalog';

// ── Engine defaults by account_type ────────────────────────────────────────

function getDefaultEngines(accountType) {
  const at = getAccountTypeById(accountType);
  return at?.scope_capabilities?.engines || ['discovery','check'];
}

// ── Region multi-select ────────────────────────────────────────────────────

function RegionSelect({ included, excluded, onChange }) {
  const [incInput, setIncInput] = useState('');
  const [excInput, setExcInput] = useState('');

  const addRegion = (list, setInput, inputVal, type) => {
    const v = inputVal.trim();
    if (!v) return;
    const next = [...list, v];
    setInput('');
    if (type === 'include') onChange(next, excluded);
    else onChange(included, next);
  };

  const removeRegion = (val, type) => {
    if (type === 'include') onChange(included.filter(r => r !== val), excluded);
    else onChange(included, excluded.filter(r => r !== val));
  };

  return (
    <div className="space-y-3">
      {[
        { label: 'Include regions (leave empty = all)', list: included, input: incInput, setInput: setIncInput, type: 'include', color: '#22c55e' },
        { label: 'Exclude regions', list: excluded, input: excInput, setInput: setExcInput, type: 'exclude', color: '#ef4444' },
      ].map(({ label, list, input, setInput, type, color }) => (
        <div key={type}>
          <div className="text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>{label}</div>
          <div className="flex gap-1.5 flex-wrap mb-1.5">
            {list.map(r => (
              <span key={r} className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full"
                style={{ backgroundColor: `${color}15`, color }}>
                {r}
                <button onClick={() => removeRegion(r, type)} className="hover:opacity-60">×</button>
              </span>
            ))}
          </div>
          <div className="flex gap-1.5">
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addRegion(list, setInput, input, type)}
              placeholder="e.g. us-east-1"
              className="flex-1 px-2.5 py-1.5 text-xs rounded-lg border outline-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
            <button
              onClick={() => addRegion(list, setInput, input, type)}
              className="px-2.5 py-1.5 text-xs rounded-lg border hover:opacity-80 transition-opacity"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
            >
              Add
            </button>
          </div>
        </div>
      ))}
    </div>
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
          <button key={eng} onClick={() => toggle(eng)}
            className="px-2.5 py-1 text-xs rounded-lg border transition-colors"
            style={{
              backgroundColor: on ? 'rgba(59,130,246,0.15)' : 'var(--bg-tertiary)',
              borderColor: on ? 'rgba(59,130,246,0.4)' : 'var(--border-primary)',
              color: on ? 'var(--accent-primary)' : 'var(--text-muted)',
            }}>
            {eng}
          </button>
        );
      })}
    </div>
  );
}

// ── Main modal ──────────────────────────────────────────────────────────────

export default function ScheduleModal({ account, existingSchedule, onClose, onSaved }) {
  const defaultEngines = getDefaultEngines(account?.account_type);

  const [form, setForm] = useState({
    cron_expression:  existingSchedule?.cron_expression  || '0 2 * * 0',
    include_regions:  existingSchedule?.include_regions  || [],
    exclude_regions:  existingSchedule?.exclude_regions  || [],
    include_services: existingSchedule?.include_services || [],
    engines_requested: existingSchedule?.engines_requested || defaultEngines,
    enabled:          existingSchedule?.enabled ?? true,
  });
  const [customCron, setCustomCron] = useState(
    existingSchedule ? isCustomCron(existingSchedule.cron_expression) : false
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
      const url = existingSchedule
        ? `/gateway/api/v1/schedules/${existingSchedule.schedule_id || existingSchedule.id}`
        : `/gateway/api/v1/schedules/`;
      const resp = await fetch(url, {
        method,
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...form,
          account_id: account.account_id || account.id,
          tenant_id: account.tenant_id,
        }),
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}>
      <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-2xl border shadow-2xl"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b sticky top-0" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-card)' }}>
          <div className="flex items-center gap-2">
            <Calendar size={16} style={{ color: 'var(--accent-primary)' }} />
            <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
              {existingSchedule ? 'Edit Schedule' : 'Create Schedule'}
            </span>
          </div>
          <button onClick={onClose} className="hover:opacity-60 transition-opacity" style={{ color: 'var(--text-muted)' }}>
            <X size={16} />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* Cron preset */}
          <div>
            <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
              Scan Frequency
            </label>
            <div className="relative">
              <select
                value={customCron ? 'custom' : selectedPreset}
                onChange={e => handlePreset(e.target.value)}
                className="w-full appearance-none pl-3 pr-8 py-2 text-sm rounded-lg border outline-none"
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              >
                {CRON_PRESETS.map(p => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
              <ChevronDown size={12} className="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
            </div>
            {customCron && (
              <input
                value={form.cron_expression}
                onChange={e => setField('cron_expression', e.target.value)}
                placeholder="0 2 * * *"
                className="mt-2 w-full px-3 py-2 text-sm font-mono rounded-lg border outline-none"
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              />
            )}
            {form.cron_expression && (
              <div className="mt-1.5 text-[11px]" style={{ color: 'var(--text-muted)' }}>
                Next run: <span style={{ color: 'var(--accent-primary)' }}>{nextRun}</span>
              </div>
            )}
          </div>

          {/* Region scope */}
          <div>
            <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
              Region Scope
            </label>
            <RegionSelect
              included={form.include_regions}
              excluded={form.exclude_regions}
              onChange={(inc, exc) => setForm(f => ({ ...f, include_regions: inc, exclude_regions: exc }))}
            />
          </div>

          {/* Engine selection */}
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

          {/* Enabled toggle */}
          <div className="flex items-center gap-2">
            <label className="relative inline-flex cursor-pointer">
              <input type="checkbox" checked={form.enabled} onChange={e => setField('enabled', e.target.checked)} className="sr-only peer" />
              <div className="w-8 h-4 rounded-full peer-checked:bg-blue-500 transition-colors"
                style={{ backgroundColor: form.enabled ? 'var(--accent-primary)' : 'var(--bg-tertiary)', border: '1px solid var(--border-primary)' }}>
                <div className={`w-3 h-3 bg-white rounded-full absolute top-0.5 transition-transform ${form.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
              </div>
            </label>
            <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Enable schedule</span>
          </div>

          {/* Error */}
          {error && (
            <div className="text-xs p-2.5 rounded-lg border" style={{ borderColor: 'rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.08)', color: '#f87171' }}>
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2 pt-1">
            <button onClick={onClose}
              className="flex-1 py-2 text-sm rounded-lg border hover:opacity-80 transition-opacity"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              Cancel
            </button>
            <button onClick={handleSubmit} disabled={saving}
              className="flex-1 py-2 text-sm font-medium rounded-lg disabled:opacity-50 transition-opacity hover:opacity-90"
              style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}>
              {saving ? 'Saving…' : existingSchedule ? 'Update Schedule' : 'Create Schedule'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
