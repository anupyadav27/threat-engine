'use client';

import { useRouter } from 'next/navigation';
import { useState, useRef, useEffect } from 'react';
import { useTheme } from '@/lib/theme-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { useTenant } from '@/lib/tenant-context';
import { useAuth } from '@/lib/auth-context';
import {
  Sun, Moon, Bell, ChevronDown, LogOut, User, Settings,
  Building2, Layers, Globe, Check,
} from 'lucide-react';

// ── Reusable checkbox row ──────────────────────────────────────────────────────
function CheckRow({ checked, onToggle, label, sub, isAll = false }) {
  return (
    <button
      onClick={onToggle}
      className="w-full flex items-center gap-2 px-3 py-2 text-xs hover:opacity-80 text-left"
      style={{
        backgroundColor: checked ? 'rgba(59,130,246,0.08)' : 'transparent',
        color: 'var(--text-secondary)',
        borderBottom: '1px solid var(--border-primary)',
      }}
    >
      <span
        className="flex-shrink-0 flex items-center justify-center w-3.5 h-3.5 rounded border"
        style={{
          borderColor: checked ? '#3b82f6' : 'var(--border-primary)',
          backgroundColor: checked ? '#3b82f6' : 'transparent',
        }}
      >
        {checked && <Check size={9} color="white" strokeWidth={3} />}
      </span>
      <span className="flex-1 min-w-0">
        <span className={`block truncate ${isAll ? 'font-semibold' : 'font-medium'}`}>{label}</span>
        {sub && <span className="block text-[10px] truncate" style={{ color: 'var(--text-muted)' }}>{sub}</span>}
      </span>
    </button>
  );
}

// ── Scope chip button (interactive dropdown trigger) ───────────────────────────
function ScopeChip({ icon: Icon, label, active, onClick, disabled = false }) {
  return (
    <button
      onClick={disabled ? undefined : onClick}
      className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition-opacity ${disabled ? 'cursor-default' : 'hover:opacity-75'}`}
      style={{
        backgroundColor: active ? 'rgba(59,130,246,0.12)' : 'var(--bg-tertiary)',
        color: active ? '#60a5fa' : 'var(--text-secondary)',
        border: `1px solid ${active ? 'rgba(59,130,246,0.35)' : 'var(--border-primary)'}`,
      }}
    >
      <Icon size={11} className="flex-shrink-0" />
      <span className="max-w-[140px] truncate">{label}</span>
      {!disabled && <ChevronDown size={11} className="flex-shrink-0 opacity-60" />}
    </button>
  );
}

// ── Scope chip — static display only (no dropdown) ────────────────────────────
function StaticChip({ icon: Icon, label }) {
  return (
    <span
      className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium"
      style={{
        backgroundColor: 'var(--bg-tertiary)',
        color: 'var(--text-muted)',
        border: '1px solid var(--border-primary)',
      }}
    >
      <Icon size={11} className="flex-shrink-0" />
      <span className="max-w-[140px] truncate">{label}</span>
    </span>
  );
}

export default function Header() {
  const router = useRouter();
  const { theme, toggleTheme } = useTheme();

  const { tenants, activeTenant, setActiveTenant } = useTenant();
  const { switchTenant, level, role, user, logout } = useAuth();
  const {
    clients, selectedClients, selectedTenants, selectedAccounts,
    accountOptions, setFilter,
  } = useGlobalFilter();

  // Role detection
  const isPlatformAdmin = level === 1;
  const isOrgAdmin      = level === 2 || role === 'org_admin';
  const isTenantLevel   = !isPlatformAdmin && !isOrgAdmin;  // tenant_admin, analyst, viewer

  // Derive "Client" display label for org-level roles
  const clientLabel = (() => {
    if (isPlatformAdmin) {
      if (selectedClients.length === 0)   return 'All Clients';
      if (selectedClients.length === 1) {
        const c = clients.find(c => c.value === selectedClients[0]);
        return c?.label || selectedClients[0];
      }
      return `${selectedClients.length} Clients`;
    }
    // org_admin / tenant_admin: derive org name from email domain
    if (user?.email) {
      const domain = user.email.split('@')[1] || '';
      const part = domain.split('.')[0];
      return part.charAt(0).toUpperCase() + part.slice(1) || 'My Org';
    }
    return 'My Org';
  })();

  // Tenant chip label
  const tenantLabel = (() => {
    if (selectedTenants.length === 0) return activeTenant?.tenant_name || 'All Tenants';
    if (selectedTenants.length === 1) {
      const t = tenants.find(t => t.tenant_id === selectedTenants[0]);
      return t?.tenant_name || selectedTenants[0];
    }
    return `${selectedTenants.length} Tenants`;
  })();

  // Account chip label
  const accountLabel = (() => {
    if (selectedAccounts.length === 0) return 'All Accounts';
    if (selectedAccounts.length === 1) {
      const opt = accountOptions.find(a => a.value === selectedAccounts[0]);
      return opt?.label || selectedAccounts[0];
    }
    return `${selectedAccounts.length} Accounts`;
  })();

  const hasClientFilter  = selectedClients.length > 0;
  const hasTenantFilter  = selectedTenants.length > 0;
  const hasAccountFilter = selectedAccounts.length > 0;

  const [showClientMenu,  setShowClientMenu]  = useState(false);
  const [showTenantMenu,  setShowTenantMenu]  = useState(false);
  const [showAccountMenu, setShowAccountMenu] = useState(false);
  const [showUserMenu,    setShowUserMenu]    = useState(false);

  const clientMenuRef  = useRef(null);
  const tenantMenuRef  = useRef(null);
  const accountMenuRef = useRef(null);
  const userMenuRef    = useRef(null);

  const displayName  = user?.name || user?.email || 'User';
  const displayEmail = user?.email || '';
  const initials     = displayName.split(' ').map(p => p[0]).slice(0, 2).join('').toUpperCase() || 'U';

  useEffect(() => {
    const handler = (e) => {
      if (clientMenuRef.current  && !clientMenuRef.current.contains(e.target))  setShowClientMenu(false);
      if (tenantMenuRef.current  && !tenantMenuRef.current.contains(e.target))  setShowTenantMenu(false);
      if (accountMenuRef.current && !accountMenuRef.current.contains(e.target)) setShowAccountMenu(false);
      if (userMenuRef.current    && !userMenuRef.current.contains(e.target))    setShowUserMenu(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleTenantToggle = (tenantId) => {
    const next = selectedTenants.includes(tenantId)
      ? selectedTenants.filter(id => id !== tenantId)
      : [...selectedTenants, tenantId];

    setFilter('toggleTenant', tenantId);

    if (next.length === 1) {
      const t = tenants.find(t => t.tenant_id === next[0]);
      if (t) { setActiveTenant(t); switchTenant(t.tenant_id); }
    } else if (next.length === 0) {
      setActiveTenant(null); switchTenant(null);
    }
  };

  return (
    <header
      className="h-12 flex items-center justify-between px-4 gap-3 transition-colors"
      style={{ backgroundColor: 'var(--header-bg)', borderBottom: '1px solid var(--border-primary)' }}
    >
      {/* ── Left: Logo + Scope Bar ───────────────────────────────────────────── */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Logo */}
        <span className="text-xs font-semibold flex-shrink-0" style={{ color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
          THREAT ENGINE
        </span>

        {/* Separator */}
        <span className="h-4 w-px flex-shrink-0" style={{ backgroundColor: 'var(--border-primary)' }} />

        {/* ── Client scope ─────────────────────────────────────────────────── */}
        {isPlatformAdmin && clients.length > 0 ? (
          <div className="relative flex-shrink-0" ref={clientMenuRef}>
            <ScopeChip
              icon={Globe}
              label={clientLabel}
              active={hasClientFilter}
              onClick={() => setShowClientMenu(!showClientMenu)}
            />
            {showClientMenu && (
              <div className="absolute top-full left-0 mt-1 w-64 rounded-lg border shadow-lg z-50 overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <CheckRow
                  checked={selectedClients.length === 0}
                  onToggle={() => setFilter('clearClients')}
                  label="All Clients"
                  sub={`${clients.length} organizations`}
                  isAll
                />
                <div className="max-h-56 overflow-y-auto">
                  {clients.map(c => (
                    <CheckRow
                      key={c.value}
                      checked={selectedClients.includes(c.value)}
                      onToggle={() => setFilter('toggleClient', c.value)}
                      label={c.label}
                    />
                  ))}
                </div>
                {hasClientFilter && (
                  <button onClick={() => setFilter('clearClients')}
                    className="w-full px-3 py-1.5 text-[10px] font-medium text-center hover:opacity-75"
                    style={{ color: '#60a5fa', borderTop: '1px solid var(--border-primary)' }}>
                    Clear selection
                  </button>
                )}
              </div>
            )}
          </div>
        ) : (
          /* Static client label for org_admin and tenant-level roles */
          <StaticChip icon={Globe} label={clientLabel} />
        )}

        {/* ── Tenant scope ─────────────────────────────────────────────────── */}
        {isTenantLevel ? (
          /* tenant_admin / analyst / viewer — tenant is fixed */
          <StaticChip icon={Building2} label={activeTenant?.tenant_name || tenantLabel} />
        ) : (
          /* platform_admin / org_admin — tenant is selectable */
          (tenants.length > 0 || isPlatformAdmin || isOrgAdmin) && (
            <div className="relative flex-shrink-0" ref={tenantMenuRef}>
              <ScopeChip
                icon={Building2}
                label={tenantLabel}
                active={hasTenantFilter}
                onClick={() => setShowTenantMenu(!showTenantMenu)}
              />
              {showTenantMenu && (
                <div className="absolute top-full left-0 mt-1 w-64 rounded-lg border shadow-lg z-50 overflow-hidden"
                  style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                  <CheckRow
                    checked={selectedTenants.length === 0}
                    onToggle={() => { setFilter('clearTenants'); setActiveTenant(null); switchTenant(null); }}
                    label="All Tenants"
                    sub={`${tenants.length} tenants available`}
                    isAll
                  />
                  <div className="max-h-56 overflow-y-auto">
                    {tenants.map(t => (
                      <CheckRow
                        key={t.tenant_id}
                        checked={selectedTenants.includes(t.tenant_id)}
                        onToggle={() => handleTenantToggle(t.tenant_id)}
                        label={t.tenant_name}
                        sub={`${t.account_count ?? 0} accounts`}
                      />
                    ))}
                  </div>
                  {hasTenantFilter && (
                    <button onClick={() => { setFilter('clearTenants'); setActiveTenant(null); switchTenant(null); }}
                      className="w-full px-3 py-1.5 text-[10px] font-medium text-center hover:opacity-75"
                      style={{ color: '#60a5fa', borderTop: '1px solid var(--border-primary)' }}>
                      Clear selection
                    </button>
                  )}
                </div>
              )}
            </div>
          )
        )}

        {/* ── Account scope (all roles) ──────────────────────────────────── */}
        <div className="relative flex-shrink-0" ref={accountMenuRef}>
          <ScopeChip
            icon={Layers}
            label={accountLabel}
            active={hasAccountFilter}
            onClick={() => setShowAccountMenu(!showAccountMenu)}
          />
          {showAccountMenu && (
            <div className="absolute top-full left-0 mt-1 w-64 rounded-lg border shadow-lg z-50 overflow-hidden"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <CheckRow
                checked={selectedAccounts.length === 0}
                onToggle={() => setFilter('clearAccounts')}
                label="All Accounts"
                sub={`${accountOptions.length} accounts available`}
                isAll
              />
              <div className="max-h-56 overflow-y-auto">
                {accountOptions.length === 0 ? (
                  <div className="px-3 py-4 text-center text-[11px]" style={{ color: 'var(--text-muted)' }}>
                    No accounts available
                  </div>
                ) : accountOptions.map(opt => (
                  <CheckRow
                    key={opt.value}
                    checked={selectedAccounts.includes(opt.value)}
                    onToggle={() => setFilter('toggleAccount', opt.value)}
                    label={opt.label}
                    sub={opt.value}
                  />
                ))}
              </div>
              {hasAccountFilter && (
                <button onClick={() => setFilter('clearAccounts')}
                  className="w-full px-3 py-1.5 text-[10px] font-medium text-center hover:opacity-75"
                  style={{ color: '#60a5fa', borderTop: '1px solid var(--border-primary)' }}>
                  Clear selection
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── Right: Notifications · Theme · Avatar ───────────────────────────── */}
      <div className="flex items-center gap-2 flex-shrink-0">
        {/* Notifications */}
        <button
          onClick={() => router.push('/notifications')}
          className="relative p-1.5 rounded-lg hover:opacity-75"
          style={{ color: 'var(--text-tertiary)' }}
          title="Notifications"
        >
          <Bell size={16} />
        </button>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-1.5 rounded-lg hover:opacity-75"
          style={{ color: 'var(--text-tertiary)' }}
          title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>

        {/* User Avatar */}
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center justify-center w-7 h-7 rounded-full font-semibold text-xs hover:opacity-75"
            style={{ backgroundColor: 'rgb(59,130,246)', color: 'white' }}
            title={displayName}
          >
            {initials}
          </button>
          {showUserMenu && (
            <div className="absolute top-full right-0 mt-1 w-52 rounded-lg border shadow-lg z-50"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-3 py-2 border-b" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="font-medium text-xs" style={{ color: 'var(--text-primary)' }}>{displayName}</div>
                <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{displayEmail}</div>
              </div>
              {[
                { icon: User,    label: 'Profile',  action: () => { router.push('/profile');  setShowUserMenu(false); } },
                { icon: Settings, label: 'Settings', action: () => { router.push('/settings'); setShowUserMenu(false); } },
                { icon: LogOut,  label: 'Logout',   action: async () => { setShowUserMenu(false); await logout(); router.push('/auth/login'); } },
              ].map(({ icon: Icon, label, action }) => (
                <button key={label} onClick={action}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs border-b last:border-b-0 hover:opacity-75"
                  style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-primary)' }}>
                  <Icon size={14} /><span>{label}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
