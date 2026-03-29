'use client';

import { useRouter } from 'next/navigation';
import { useState, useRef, useEffect } from 'react';
import { useTheme } from '@/lib/theme-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { CLOUD_PROVIDERS } from '@/lib/constants';
import { Sun, Moon, Bell, ChevronDown, LogOut, User, Settings, Globe } from 'lucide-react';

function ProviderDot({ provider }) {
  const color = CLOUD_PROVIDERS[provider?.toLowerCase()]?.color || '#6366f1';
  return <span className="inline-block w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />;
}

export default function Header() {
  const router = useRouter();
  const { theme, toggleTheme } = useTheme();
  const {
    provider, account, region,
    setFilter, clearAll, hasActiveFilters,
    providerOptions, accountOptions, regionOptions,
  } = useGlobalFilter();

  const [showTenantMenu, setShowTenantMenu] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const tenantMenuRef = useRef(null);
  const userMenuRef = useRef(null);

  const tenants = [
    { id: 't1', name: 'Acme Corp' },
    { id: 't2', name: 'TechStart Inc' },
    { id: 't3', name: 'Global Finance' },
  ];
  const [currentTenant, setCurrentTenant] = useState('t1');
  const currentTenantName = tenants.find(t => t.id === currentTenant)?.name || 'Select Tenant';

  const mockUser = { name: 'Anup Yadav', email: 'yadav.anup@gmail.com', role: 'Admin', initials: 'AY' };
  const unreadNotifications = 3;

  useEffect(() => {
    const handler = (e) => {
      if (tenantMenuRef.current && !tenantMenuRef.current.contains(e.target)) setShowTenantMenu(false);
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) setShowUserMenu(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const scopeSelect = (value, onChange, options, placeholder, disabled = false, icon) => (
    <div className="relative flex-shrink-0">
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        disabled={disabled}
        className="appearance-none pl-6 pr-5 py-1 text-xs rounded border cursor-pointer transition-colors"
        style={{
          backgroundColor: value ? 'rgba(59,130,246,0.1)' : 'var(--bg-tertiary)',
          borderColor: value ? 'rgba(59,130,246,0.4)' : 'var(--border-primary)',
          color: value ? 'var(--accent-primary)' : 'var(--text-muted)',
          opacity: disabled ? 0.4 : 1,
          minWidth: 120,
        }}
      >
        <option value="">{placeholder}</option>
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <span className="absolute left-1.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: value ? 'var(--accent-primary)' : 'var(--text-muted)' }}>
        {icon}
      </span>
      <ChevronDown className="absolute right-1 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
    </div>
  );

  return (
    <header
      className="h-12 flex items-center justify-between px-4 gap-3 transition-colors"
      style={{ backgroundColor: 'var(--header-bg)', borderBottom: '1px solid var(--border-primary)' }}
    >
      {/* ── Left: Scope filters ── */}
      <div className="flex items-center gap-2">
        <span className="text-[9px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>Scope</span>

        {scopeSelect(provider, (v) => setFilter('provider', v), providerOptions, 'All Providers', false,
          provider ? <ProviderDot provider={provider} /> : <Globe className="w-3 h-3" />
        )}
        {scopeSelect(account, (v) => setFilter('account', v), accountOptions, 'All Accounts', !provider,
          <svg viewBox="0 0 14 14" fill="none" className="w-3 h-3"><rect x="1.5" y="3" width="11" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.2"/><path d="M4.5 6h5M4.5 8.5h3" stroke="currentColor" strokeWidth="1" strokeLinecap="round"/></svg>
        )}
        {scopeSelect(region, (v) => setFilter('region', v), regionOptions, 'All Regions', !account,
          <svg viewBox="0 0 14 14" fill="none" className="w-3 h-3" style={{ color: 'currentColor' }}><circle cx="7" cy="7" r="5.5" stroke="currentColor" strokeWidth="1.2"/><path d="M7 1.5C7 1.5 4.5 4 4.5 7s2.5 5.5 2.5 5.5M7 1.5C7 1.5 9.5 4 9.5 7S7 12.5 7 12.5M2 7h10" stroke="currentColor" strokeWidth="1"/></svg>
        )}

        {hasActiveFilters && (
          <button onClick={clearAll} className="text-[10px] px-1.5 py-0.5 rounded hover:opacity-75" style={{ color: 'var(--text-muted)' }}>
            Clear
          </button>
        )}
      </div>

      {/* ── Right: Notification, Tenant, Theme, Profile ── */}
      <div className="flex items-center gap-2">
        {/* Notifications */}
        <button onClick={() => router.push('/notifications')} className="relative p-1.5 rounded-lg hover:opacity-75" style={{ color: 'var(--text-tertiary)' }} title="Notifications">
          <Bell size={16} />
          {unreadNotifications > 0 && (
            <div className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-3.5 h-3.5 rounded-full bg-red-500 text-white text-[9px] font-bold">
              {unreadNotifications}
            </div>
          )}
        </button>

        {/* Tenant Switcher */}
        <div className="relative" ref={tenantMenuRef}>
          <button
            onClick={() => setShowTenantMenu(!showTenantMenu)}
            className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium hover:opacity-75"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}
          >
            {currentTenantName}
            <ChevronDown size={12} />
          </button>
          {showTenantMenu && (
            <div className="absolute top-full right-0 mt-1 w-48 rounded-lg border shadow-lg z-50" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              {tenants.map(t => (
                <button key={t.id} onClick={() => { setCurrentTenant(t.id); setShowTenantMenu(false); }}
                  className="w-full text-left px-3 py-2 text-sm border-b last:border-b-0 hover:opacity-75"
                  style={{ backgroundColor: currentTenant === t.id ? 'var(--bg-tertiary)' : 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--border-primary)' }}>
                  <div className="font-medium text-xs">{t.name}</div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Theme Toggle */}
        <button onClick={toggleTheme} className="p-1.5 rounded-lg hover:opacity-75" style={{ color: 'var(--text-tertiary)' }}
          title={theme === 'dark' ? 'Light mode' : 'Dark mode'}>
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>

        {/* User Avatar */}
        <div className="relative" ref={userMenuRef}>
          <button onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center justify-center w-7 h-7 rounded-full font-semibold text-xs hover:opacity-75"
            style={{ backgroundColor: 'rgb(59,130,246)', color: 'white' }}
            title={`${mockUser.name} - ${mockUser.role}`}>
            {mockUser.initials}
          </button>
          {showUserMenu && (
            <div className="absolute top-full right-0 mt-1 w-52 rounded-lg border shadow-lg z-50" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-3 py-2 border-b" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="font-medium text-xs" style={{ color: 'var(--text-primary)' }}>{mockUser.name}</div>
                <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{mockUser.email}</div>
              </div>
              {[
                { icon: User, label: 'Profile', action: () => { router.push('/profile'); setShowUserMenu(false); } },
                { icon: Settings, label: 'Settings', action: () => { router.push('/settings'); setShowUserMenu(false); } },
                { icon: LogOut, label: 'Logout', action: () => { router.push('/auth/login'); setShowUserMenu(false); } },
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
