'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { useGlobalFilter, TIME_RANGE_OPTIONS } from '@/lib/global-filter-context';
import { useSavedFilters } from '@/lib/saved-filters-context';
import { useTenant } from '@/lib/tenant-context';
import { useAuth } from '@/lib/auth-context';
import { ChevronDown, X, Clock, Pin, Bookmark, Building2, Users, Server, Globe } from 'lucide-react';
import { CLOUD_PROVIDERS } from '@/lib/constants';

// ── Shared hook: fixed-position dropdown ───────────────────────────────────────
// Uses getBoundingClientRect so overflow-x:hidden on AppShell never clips the panel.
function useDropdown() {
  const [open, setOpen]   = useState(false);
  const [pos,  setPos]    = useState({ top: 0, left: 0 });
  const triggerRef        = useRef(null);
  const panelRef          = useRef(null);

  const toggle = useCallback(() => {
    if (!open && triggerRef.current) {
      const r = triggerRef.current.getBoundingClientRect();
      setPos({ top: r.bottom + 4, left: r.left });
    }
    setOpen(o => !o);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (
        triggerRef.current && triggerRef.current.contains(e.target)) return;
      if (panelRef.current && panelRef.current.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return { open, pos, toggle, triggerRef, panelRef };
}

// ── Checkbox row ───────────────────────────────────────────────────────────────
function CheckRow({ checked, label, count, extra, onClick }) {
  return (
    <button
      onClick={onClick}
      className="w-full flex items-center gap-2.5 px-3 py-2.5 text-xs border-b last:border-b-0 hover:opacity-80 transition-opacity"
      style={{
        borderColor: 'var(--border-primary)',
        backgroundColor: checked ? 'rgba(99,102,241,0.06)' : 'transparent',
        color: checked ? 'var(--accent-primary)' : 'var(--text-secondary)',
      }}
    >
      <span
        className="flex-shrink-0 flex items-center justify-center rounded"
        style={{
          width: 14, height: 14,
          border: `1.5px solid ${checked ? 'var(--accent-primary)' : 'var(--border-secondary)'}`,
          backgroundColor: checked ? 'var(--accent-primary)' : 'transparent',
        }}
      >
        {checked && (
          <svg width="8" height="6" viewBox="0 0 8 6" fill="none">
            <path d="M1 3L3 5L7 1" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        )}
      </span>
      {extra}
      <span style={{ flex: 1, textAlign: 'left', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {label}
      </span>
      {count != null && (
        <span className="flex-shrink-0 text-[10px]" style={{ color: 'var(--text-muted)' }}>{count}</span>
      )}
    </button>
  );
}

// ── Panel wrapper (fixed position, viewport-level) ─────────────────────────────
function DropPanel({ pos, panelRef, header, children }) {
  return (
    <div
      ref={panelRef}
      style={{
        position: 'fixed',
        top: pos.top,
        left: pos.left,
        zIndex: 9999,
        minWidth: 210,
        maxHeight: 320,
        borderRadius: 12,
        border: '1px solid var(--border-primary)',
        backgroundColor: 'var(--bg-card)',
        boxShadow: '0 8px 32px rgba(0,0,0,0.28)',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {header}
      <div style={{ overflowY: 'auto', flex: 1 }}>{children}</div>
    </div>
  );
}

// ── Trigger button ─────────────────────────────────────────────────────────────
function TriggerBtn({ triggerRef, onClick, active, icon: Icon, text }) {
  return (
    <button
      ref={triggerRef}
      onClick={onClick}
      className="flex items-center gap-1.5 py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
      style={{
        backgroundColor: active ? 'rgba(99,102,241,0.08)' : 'var(--bg-secondary)',
        borderColor:     active ? 'var(--accent-primary)' : 'var(--border-primary)',
        color:           active ? 'var(--accent-primary)' : 'var(--text-muted)',
        paddingLeft: 28, paddingRight: 22,
        minWidth: 150, maxWidth: 210,
        position: 'relative',
      }}
    >
      <Icon
        style={{
          position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)',
          width: 14, height: 14, flexShrink: 0,
          color: active ? 'var(--accent-primary)' : 'var(--text-muted)',
          pointerEvents: 'none',
        }}
      />
      <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'left' }}>
        {text}
      </span>
      <ChevronDown
        style={{
          position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)',
          width: 12, height: 12, pointerEvents: 'none',
          color: active ? 'var(--accent-primary)' : 'var(--text-muted)',
        }}
      />
    </button>
  );
}

function PanelHeader({ title, hasSelection, onClear }) {
  return (
    <div
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '8px 12px',
        borderBottom: '1px solid var(--border-primary)',
        backgroundColor: 'var(--bg-secondary)',
        flexShrink: 0,
      }}
    >
      <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
        {title}
      </span>
      {hasSelection && (
        <button onClick={onClear} style={{ fontSize: 10, color: 'var(--accent-primary)' }} className="hover:opacity-70">
          Clear all
        </button>
      )}
    </div>
  );
}

// ── Provider dot ───────────────────────────────────────────────────────────────
function ProviderDot({ provider }) {
  const color = CLOUD_PROVIDERS[provider?.toLowerCase()]?.color || '#6366f1';
  return <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', backgroundColor: color, flexShrink: 0 }} />;
}

// ── Tenant multi-select ────────────────────────────────────────────────────────
function TenantSelect({ options, selected, onToggle, onClear }) {
  const { open, pos, toggle, triggerRef, panelRef } = useDropdown();
  const hasSelection = selected.size > 0;
  const selectedLabels = options.filter(o => selected.has(o.value));
  const text = hasSelection
    ? selectedLabels.length === 1 ? selectedLabels[0].label : `${selected.size} tenants`
    : 'All Tenants';

  return (
    <>
      <TriggerBtn triggerRef={triggerRef} onClick={toggle} active={hasSelection} icon={Users} text={text} />
      {open && (
        <DropPanel pos={pos} panelRef={panelRef}
          header={<PanelHeader title={hasSelection ? `${selected.size} selected` : 'Tenant'} hasSelection={hasSelection} onClear={onClear} />}
        >
          {options.length === 0
            ? <div style={{ padding: '16px 12px', textAlign: 'center', fontSize: 11, color: 'var(--text-muted)' }}>No tenants</div>
            : options.map(o => (
                <CheckRow key={o.value} checked={selected.has(o.value)} label={o.label} count={o.count}
                  onClick={() => onToggle(o.value)} />
              ))
          }
        </DropPanel>
      )}
    </>
  );
}

// ── Provider multi-select ──────────────────────────────────────────────────────
function ProviderSelect({ options, selected, onToggle, onClear }) {
  const { open, pos, toggle, triggerRef, panelRef } = useDropdown();
  const hasSelection = selected.size > 0;
  const selectedItems = options.filter(o => selected.has(o.value));
  const text = hasSelection
    ? selectedItems.length === 1 ? selectedItems[0].label : `${selected.size} providers`
    : 'All Providers';

  const iconEl = hasSelection && selectedItems.length === 1
    ? <ProviderDot provider={selectedItems[0].value} />
    : <Globe style={{ width: 14, height: 14, color: hasSelection ? 'var(--accent-primary)' : 'var(--text-muted)', pointerEvents: 'none', position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)' }} />;

  return (
    <>
      <button
        ref={triggerRef}
        onClick={toggle}
        className="flex items-center gap-1.5 py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
        style={{
          backgroundColor: hasSelection ? 'rgba(99,102,241,0.08)' : 'var(--bg-secondary)',
          borderColor:     hasSelection ? 'var(--accent-primary)' : 'var(--border-primary)',
          color:           hasSelection ? 'var(--accent-primary)' : 'var(--text-muted)',
          paddingLeft: 28, paddingRight: 22,
          minWidth: 150, maxWidth: 200,
          position: 'relative',
        }}
      >
        {hasSelection && selectedItems.length === 1
          ? <span style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }}>
              <ProviderDot provider={selectedItems[0].value} />
            </span>
          : iconEl
        }
        <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'left' }}>{text}</span>
        <ChevronDown style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)', width: 12, height: 12, pointerEvents: 'none', color: hasSelection ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
      </button>

      {open && (
        <DropPanel pos={pos} panelRef={panelRef}
          header={<PanelHeader title={hasSelection ? `${selected.size} selected` : 'Cloud Provider'} hasSelection={hasSelection} onClear={onClear} />}
        >
          {options.length === 0
            ? <div style={{ padding: '16px 12px', textAlign: 'center', fontSize: 11, color: 'var(--text-muted)' }}>No providers available</div>
            : options.map(o => (
                <CheckRow key={o.value} checked={selected.has(o.value)} label={o.label}
                  extra={<ProviderDot provider={o.value} />}
                  onClick={() => onToggle(o.value)} />
              ))
          }
        </DropPanel>
      )}
    </>
  );
}

// ── Account multi-select ───────────────────────────────────────────────────────
function AccountSelect({ options, selected, onToggle, onClear }) {
  const { open, pos, toggle, triggerRef, panelRef } = useDropdown();
  const hasSelection = selected.size > 0;
  const selectedItems = options.filter(o => selected.has(o.value));
  const text = hasSelection
    ? selectedItems.length === 1 ? selectedItems[0].label : `${selected.size} accounts`
    : 'All Accounts';

  return (
    <>
      <TriggerBtn triggerRef={triggerRef} onClick={toggle} active={hasSelection} icon={Server} text={text} />
      {open && (
        <DropPanel pos={pos} panelRef={panelRef}
          header={<PanelHeader title={hasSelection ? `${selected.size} selected` : 'Account'} hasSelection={hasSelection} onClear={onClear} />}
        >
          {options.length === 0
            ? <div style={{ padding: '16px 12px', textAlign: 'center', fontSize: 11, color: 'var(--text-muted)' }}>No accounts available</div>
            : options.map(o => (
                <CheckRow key={o.value} checked={selected.has(o.value)} label={o.label}
                  onClick={() => onToggle(o.value)} />
              ))
          }
        </DropPanel>
      )}
    </>
  );
}

// ── Chevron separator ──────────────────────────────────────────────────────────
function Sep() {
  return <span style={{ color: 'var(--border-secondary)', fontSize: 14, userSelect: 'none', flexShrink: 0 }}>›</span>;
}

// ── Main bar ───────────────────────────────────────────────────────────────────
export default function GlobalFilterBar() {
  const {
    timeRange, setFilter, clearAll,
    providerOptions, accountOptions,
    selectedTenantIds, selectedProviderIds, selectedAccountIds,
    toggleTenantFilter, toggleProviderFilter, toggleAccountFilter,
    clearTenantFilter, clearProviderFilter, clearAccountFilter,
  } = useGlobalFilter();

  const { tenants } = useTenant();
  const { user, level } = useAuth();
  const { savedFilters, saveFilter, deleteFilter } = useSavedFilters();
  const [showSave, setShowSave] = useState(false);
  const [saveName, setSaveName] = useState('');

  const isPlatformAdmin = level === 1;
  const customerName = user?.customer_name || user?.org_name
    || (user?.email ? user.email.split('@')[1]?.split('.')[0] : null)
    || 'Organization';

  const tenantOptions = tenants.map(t => ({
    value: t.tenant_id,
    label: t.tenant_name,
    count: t.account_count ?? null,
  }));

  const totalActive = selectedTenantIds.size + selectedProviderIds.size + selectedAccountIds.size + (timeRange !== '7d' ? 1 : 0);

  const handleSave = () => {
    if (!saveName.trim()) return;
    saveFilter(saveName, { timeRange });
    setSaveName('');
    setShowSave(false);
  };

  return (
    <div className="border-b" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
      <div className="flex items-center gap-2 px-4 py-2 flex-wrap">

        {/* Scope label */}
        <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)', flexShrink: 0, marginRight: 4 }}>
          Scope
        </span>

        {/* Customer — static pill */}
        <div
          className="flex items-center gap-1.5 rounded-lg border flex-shrink-0"
          style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-muted)', fontSize: 12, padding: '5px 10px 5px 8px' }}
          title="Your organization"
        >
          <Building2 style={{ width: 14, height: 14, flexShrink: 0 }} />
          <span style={{ fontWeight: 500, whiteSpace: 'nowrap', textTransform: 'capitalize' }}>
            {isPlatformAdmin ? 'All Orgs' : customerName}
          </span>
        </div>

        <Sep />

        {/* Tenant */}
        <TenantSelect
          options={tenantOptions}
          selected={selectedTenantIds}
          onToggle={toggleTenantFilter}
          onClear={clearTenantFilter}
        />

        <Sep />

        {/* Provider */}
        <ProviderSelect
          options={providerOptions}
          selected={selectedProviderIds}
          onToggle={toggleProviderFilter}
          onClear={clearProviderFilter}
        />

        <Sep />

        {/* Account */}
        <AccountSelect
          options={accountOptions}
          selected={selectedAccountIds}
          onToggle={toggleAccountFilter}
          onClear={clearAccountFilter}
        />

        {/* Divider */}
        <div style={{ width: 1, height: 20, backgroundColor: 'var(--border-primary)', flexShrink: 0, margin: '0 4px' }} />

        {/* Time Range */}
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <select
            value={timeRange}
            onChange={e => setFilter('timeRange', e.target.value)}
            className="appearance-none py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
            style={{
              backgroundColor: timeRange !== '7d' ? 'rgba(99,102,241,0.08)' : 'var(--bg-secondary)',
              borderColor:     timeRange !== '7d' ? 'var(--accent-primary)' : 'var(--border-primary)',
              color:           timeRange !== '7d' ? 'var(--accent-primary)' : 'var(--text-muted)',
              minWidth: 130, paddingLeft: 28, paddingRight: 22,
            }}
          >
            {TIME_RANGE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <Clock style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, pointerEvents: 'none', color: timeRange !== '7d' ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
          <ChevronDown style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)', width: 12, height: 12, pointerEvents: 'none', color: timeRange !== '7d' ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
        </div>

        {/* Save View */}
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <button
            onClick={() => setShowSave(p => !p)}
            className="flex items-center gap-1.5 rounded-lg border text-xs font-medium hover:opacity-80 transition-opacity"
            style={{ borderColor: 'var(--border-secondary)', color: 'var(--text-muted)', backgroundColor: 'transparent', padding: '5px 10px' }}
          >
            <Pin style={{ width: 12, height: 12 }} />
            Save View
          </button>
          {showSave && (
            <div style={{ position: 'absolute', left: 0, top: 'calc(100% + 4px)', zIndex: 9999, borderRadius: 12, border: '1px solid var(--border-primary)', backgroundColor: 'var(--bg-card)', padding: 12, minWidth: 220, boxShadow: '0 8px 32px rgba(0,0,0,0.28)' }}>
              <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 8 }}>NAME THIS VIEW</p>
              <div className="flex gap-1.5">
                <input
                  type="text" value={saveName} onChange={e => setSaveName(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') handleSave(); if (e.key === 'Escape') setShowSave(false); }}
                  placeholder="e.g. prod-aws"
                  className="flex-1 rounded-lg border text-xs focus:outline-none"
                  style={{ backgroundColor: 'var(--bg-input)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)', padding: '5px 8px' }}
                  autoFocus
                />
                <button onClick={handleSave} disabled={!saveName.trim()}
                  className="rounded-lg text-xs font-semibold disabled:opacity-40"
                  style={{ backgroundColor: 'var(--accent-primary)', color: '#fff', padding: '5px 12px' }}>
                  Save
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Clear all */}
        {totalActive > 0 && (
          <div className="ml-auto flex-shrink-0">
            <button onClick={clearAll}
              className="flex items-center gap-1 text-xs font-medium rounded-lg hover:opacity-70 transition-opacity"
              style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-tertiary)', padding: '4px 8px' }}>
              <X style={{ width: 12, height: 12 }} />
              Clear ({totalActive})
            </button>
          </div>
        )}
      </div>

      {/* Saved filter chips */}
      {savedFilters.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 px-4 pb-2">
          <span className="flex items-center gap-1" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
            <Bookmark style={{ width: 12, height: 12 }} />
            Saved:
          </span>
          {savedFilters.map(sf => (
            <span key={sf.id} className="inline-flex items-center gap-0.5 rounded-full text-xs font-medium border"
              style={{ borderColor: 'var(--accent-primary)', color: 'var(--accent-primary)', backgroundColor: 'rgba(99,102,241,0.08)', paddingLeft: 8, paddingRight: 4, paddingTop: 2, paddingBottom: 2 }}>
              <button onClick={() => setFilter('timeRange', sf.filters.timeRange || '7d')} className="hover:opacity-80">{sf.name}</button>
              <button onClick={() => deleteFilter(sf.id)} className="ml-1 hover:opacity-70" style={{ color: 'var(--accent-primary)' }}>
                <X style={{ width: 12, height: 12 }} />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
