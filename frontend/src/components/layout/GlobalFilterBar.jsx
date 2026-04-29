'use client';

/**
 * GlobalFilterBar — persistent multi-CSP scope selector.
 *
 * Renders between the Header and <main> on every authenticated page.
 * Drives data context for all tables, graphs, and KPIs across the app.
 *
 *  [🌐 All Providers ▾]  [📁 All Accounts ▾]  [🌍 All Regions ▾]  [🕐 Last 7 Days ▾]  [📌 Save View]
 *  [⚡ prod-aws ×]  [⚡ staging-azure ×]           (saved filter chips row)
 */

import { useState } from 'react';
import { useGlobalFilter, TIME_RANGE_OPTIONS } from '@/lib/global-filter-context';
import { useSavedFilters } from '@/lib/saved-filters-context';
import { Globe, ChevronDown, X, Clock, Pin, Bookmark } from 'lucide-react';
import { CLOUD_PROVIDERS } from '@/lib/constants';

// ── Provider dot colour ────────────────────────────────────────────────────────
function ProviderDot({ provider }) {
  const color = CLOUD_PROVIDERS[provider?.toLowerCase()]?.color || '#6366f1';
  return (
    <span
      className="inline-block w-2 h-2 rounded-full flex-shrink-0"
      style={{ backgroundColor: color }}
    />
  );
}

// ── Mini dropdown ──────────────────────────────────────────────────────────────
function FilterPill({ label, value, options, onChange, disabled = false, icon: Icon }) {
  const selectedLabel = options.find(o => o.value === value)?.label || null;
  return (
    <div className="relative flex-shrink-0">
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        disabled={disabled}
        className="appearance-none pl-7 pr-6 py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
        style={{
          backgroundColor: value ? 'var(--accent-primary)' + '18' : 'var(--bg-secondary)',
          borderColor:     value ? 'var(--accent-primary)' : 'var(--border-primary)',
          color:           value ? 'var(--accent-primary)' : 'var(--text-muted)',
          opacity:         disabled ? 0.45 : 1,
          minWidth:        140,
        }}
      >
        <option value="">{label}</option>
        {options.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>

      {/* Left icon */}
      <Icon
        className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none"
        style={{ color: value ? 'var(--accent-primary)' : 'var(--text-muted)' }}
      />

      {/* Right chevron */}
      <ChevronDown
        className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none"
        style={{ color: value ? 'var(--accent-primary)' : 'var(--text-muted)' }}
      />
    </div>
  );
}

// ── Provider icon select (shows coloured dot for selected provider) ─────────────
function ProviderSelect({ value, options, onChange }) {
  return (
    <div className="relative flex-shrink-0">
      <select
        value={value}
        onChange={e => onChange('provider', e.target.value)}
        className="appearance-none pl-7 pr-6 py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
        style={{
          backgroundColor: value ? 'var(--accent-primary)' + '18' : 'var(--bg-secondary)',
          borderColor:     value ? 'var(--accent-primary)' : 'var(--border-primary)',
          color:           value ? 'var(--accent-primary)' : 'var(--text-muted)',
          minWidth: 150,
        }}
      >
        <option value="">All Providers</option>
        {options.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>

      {/* Left — coloured dot or globe */}
      <span className="absolute left-2 top-1/2 -translate-y-1/2 flex items-center pointer-events-none">
        {value
          ? <ProviderDot provider={value} />
          : <Globe className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
        }
      </span>
      <ChevronDown
        className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none"
        style={{ color: value ? 'var(--accent-primary)' : 'var(--text-muted)' }}
      />
    </div>
  );
}

// ── Region flag helper ─────────────────────────────────────────────────────────
function RegionIcon() {
  return (
    <svg viewBox="0 0 14 14" fill="none" className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }}>
      <circle cx="7" cy="7" r="5.5" stroke="currentColor" strokeWidth="1.2"/>
      <path d="M7 1.5C7 1.5 4.5 4 4.5 7s2.5 5.5 2.5 5.5M7 1.5C7 1.5 9.5 4 9.5 7S7 12.5 7 12.5M2 7h10" stroke="currentColor" strokeWidth="1"/>
    </svg>
  );
}

// ── AccountIcon ────────────────────────────────────────────────────────────────
function AccountIcon() {
  return (
    <svg viewBox="0 0 14 14" fill="none" className="w-3.5 h-3.5">
      <rect x="1.5" y="3" width="11" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.2"/>
      <path d="M4.5 6h5M4.5 8.5h3" stroke="currentColor" strokeWidth="1" strokeLinecap="round"/>
    </svg>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function GlobalFilterBar() {
  const {
    provider, account, region, timeRange,
    setFilter, clearAll, hasActiveFilters, filterSummary,
    providerOptions, accountOptions, regionOptions,
  } = useGlobalFilter();

  const { savedFilters, saveFilter, deleteFilter } = useSavedFilters();
  const [showSavePopover, setShowSavePopover] = useState(false);
  const [saveName, setSaveName] = useState('');

  const handleSave = () => {
    if (!saveName.trim()) return;
    saveFilter(saveName, { provider, account, region, timeRange });
    setSaveName('');
    setShowSavePopover(false);
  };

  const applyPreset = (sf) => {
    setFilter('provider', sf.filters.provider || '');
    setFilter('account', sf.filters.account || '');
    setFilter('region', sf.filters.region || '');
    setFilter('timeRange', sf.filters.timeRange || '7d');
  };

  return (
    <div
      className="border-b"
      style={{
        backgroundColor: 'var(--bg-secondary)',
        borderColor:     'var(--border-primary)',
      }}
    >
      {/* ── Main filter row ───────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 px-4 py-2 flex-wrap">
        {/* Scope label */}
        <span
          className="text-[10px] font-bold uppercase tracking-widest flex-shrink-0 mr-1"
          style={{ color: 'var(--text-muted)' }}
        >
          Scope
        </span>

        {/* Provider */}
        <ProviderSelect
          value={provider}
          options={providerOptions}
          onChange={setFilter}
        />

        {/* Account */}
        <div className="relative flex-shrink-0">
          <select
            value={account}
            onChange={e => setFilter('account', e.target.value)}
            disabled={!provider}
            className="appearance-none pl-7 pr-6 py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
            style={{
              backgroundColor: account ? 'var(--accent-primary)' + '18' : 'var(--bg-secondary)',
              borderColor:     account ? 'var(--accent-primary)' : 'var(--border-primary)',
              color:           account ? 'var(--accent-primary)' : 'var(--text-muted)',
              opacity:         !provider ? 0.45 : 1,
              minWidth: 155,
            }}
          >
            <option value="">All Accounts</option>
            {accountOptions.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <span className="absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none"
            style={{ color: account ? 'var(--accent-primary)' : 'var(--text-muted)' }}>
            <AccountIcon />
          </span>
          <ChevronDown className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none"
            style={{ color: account ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
        </div>

        {/* Region */}
        <div className="relative flex-shrink-0">
          <select
            value={region}
            onChange={e => setFilter('region', e.target.value)}
            disabled={!account}
            className="appearance-none pl-7 pr-6 py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
            style={{
              backgroundColor: region ? 'var(--accent-primary)' + '18' : 'var(--bg-secondary)',
              borderColor:     region ? 'var(--accent-primary)' : 'var(--border-primary)',
              color:           region ? 'var(--accent-primary)' : 'var(--text-muted)',
              opacity:         !account ? 0.45 : 1,
              minWidth: 145,
            }}
          >
            <option value="">All Regions</option>
            {regionOptions.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <span className="absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none"
            style={{ color: region ? 'var(--accent-primary)' : 'var(--text-muted)' }}>
            <RegionIcon />
          </span>
          <ChevronDown className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none"
            style={{ color: region ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
        </div>

        {/* Vertical separator */}
        <div className="h-5 w-px flex-shrink-0" style={{ backgroundColor: 'var(--border-primary)' }} />

        {/* Time Range */}
        <div className="relative flex-shrink-0">
          <select
            value={timeRange}
            onChange={e => setFilter('timeRange', e.target.value)}
            className="appearance-none pl-7 pr-6 py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
            style={{
              backgroundColor: timeRange !== '7d' ? 'var(--accent-primary)' + '18' : 'var(--bg-secondary)',
              borderColor:     timeRange !== '7d' ? 'var(--accent-primary)' : 'var(--border-primary)',
              color:           timeRange !== '7d' ? 'var(--accent-primary)' : 'var(--text-muted)',
              minWidth: 130,
            }}
          >
            {TIME_RANGE_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <Clock className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none"
            style={{ color: timeRange !== '7d' ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
          <ChevronDown className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none"
            style={{ color: timeRange !== '7d' ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
        </div>

        {/* ── Save View button ─────────────────────────────────────────────── */}
        <div className="relative flex-shrink-0">
          <button
            onClick={() => setShowSavePopover(p => !p)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium hover:opacity-80 transition-opacity"
            style={{
              borderColor: 'var(--border-secondary)',
              color: 'var(--text-muted)',
              backgroundColor: 'transparent',
            }}
            title="Save current scope as a named preset"
          >
            <Pin className="w-3 h-3" />
            Save View
          </button>
          {showSavePopover && (
            <div
              className="absolute left-0 top-full mt-1 z-50 rounded-xl border shadow-xl p-3"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-primary)',
                minWidth: 220,
              }}
            >
              <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
                NAME THIS VIEW
              </p>
              <div className="flex gap-1.5">
                <input
                  type="text"
                  value={saveName}
                  onChange={e => setSaveName(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') handleSave(); if (e.key === 'Escape') setShowSavePopover(false); }}
                  placeholder="e.g. prod-aws"
                  className="flex-1 px-2 py-1.5 rounded-lg border text-xs focus:outline-none focus:ring-1"
                  style={{
                    backgroundColor: 'var(--bg-input)',
                    borderColor: 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                  autoFocus
                />
                <button
                  onClick={handleSave}
                  disabled={!saveName.trim()}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-opacity disabled:opacity-40"
                  style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
                >
                  Save
                </button>
              </div>
              {(provider || account || region) && (
                <p className="text-[10px] mt-2" style={{ color: 'var(--text-muted)' }}>
                  Saves: {[provider, account, region, timeRange !== '7d' ? timeRange : null].filter(Boolean).join(' › ')}
                </p>
              )}
            </div>
          )}
        </div>

        {/* Active filter summary + clear */}
        {hasActiveFilters && filterSummary && (
          <div className="ml-auto flex items-center gap-2 flex-shrink-0">
            <span
              className="text-[11px] px-2.5 py-1 rounded-full font-medium flex items-center gap-1.5"
              style={{
                backgroundColor: 'var(--accent-primary)' + '18',
                color: 'var(--accent-primary)',
                border: '1px solid var(--accent-primary)' + '40',
              }}
            >
              {provider && <ProviderDot provider={provider} />}
              {filterSummary}
            </span>
            <button
              onClick={clearAll}
              className="flex items-center gap-1 text-[11px] font-medium px-2 py-1 rounded-lg transition-opacity hover:opacity-70"
              style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-tertiary)' }}
            >
              <X className="w-3 h-3" />
              Clear
            </button>
          </div>
        )}

        {/* When only timeRange is non-default, show clear */}
        {hasActiveFilters && !filterSummary && (
          <div className="ml-auto">
            <button
              onClick={clearAll}
              className="flex items-center gap-1 text-[11px] font-medium px-2 py-1 rounded-lg transition-opacity hover:opacity-70"
              style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-tertiary)' }}
            >
              <X className="w-3 h-3" />
              Reset filters
            </button>
          </div>
        )}
      </div>

      {/* ── Saved filter chip row (only when presets exist) ───────────────────── */}
      {savedFilters.length > 0 && (
        <div
          className="flex flex-wrap items-center gap-1.5 px-4 pb-2"
        >
          <span
            className="text-[10px] flex items-center gap-1 flex-shrink-0"
            style={{ color: 'var(--text-muted)' }}
          >
            <Bookmark className="w-3 h-3" />
            Saved:
          </span>
          {savedFilters.map(sf => (
            <span
              key={sf.id}
              className="inline-flex items-center gap-0.5 pl-2 pr-1 py-0.5 rounded-full text-[11px] font-medium border"
              style={{
                borderColor: 'var(--accent-primary)' + '60',
                color: 'var(--accent-primary)',
                backgroundColor: 'var(--accent-primary)' + '12',
              }}
            >
              <button
                onClick={() => applyPreset(sf)}
                className="hover:opacity-80 transition-opacity"
                title={`Apply: ${Object.values(sf.filters).filter(Boolean).join(' › ')}`}
              >
                {sf.name}
              </button>
              <button
                onClick={() => deleteFilter(sf.id)}
                className="ml-1 hover:opacity-70 transition-opacity flex-shrink-0"
                style={{ color: 'var(--accent-primary)' }}
                title="Remove preset"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
