'use client';

import { useRouter } from 'next/navigation';
import { useState, useRef, useEffect } from 'react';
import { useTheme } from '@/lib/theme-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { useTenant } from '@/lib/tenant-context';
import { useAuth } from '@/lib/auth-context';
import { CLOUD_PROVIDERS } from '@/lib/constants';
import { Sun, Moon, Bell, ChevronDown, LogOut, User, Settings, Globe } from 'lucide-react';
import TrialCountdownChip from '@/components/billing/TrialCountdownChip';
import OrgTenantSwitcher from '@/components/nav/OrgTenantSwitcher';

const _TENANT_TYPE_STYLES = {
  cloud:        { bg: 'rgba(59,130,246,0.15)',  color: '#60a5fa' },
  security:     { bg: 'rgba(239,68,68,0.15)',   color: '#f87171' },
  vulnerability:{ bg: 'rgba(245,158,11,0.15)',  color: '#fbbf24' },
  database:     { bg: 'rgba(16,185,129,0.15)',  color: '#34d399' },
  middleware:   { bg: 'rgba(139,92,246,0.15)',  color: '#a78bfa' },
  technology:   { bg: 'rgba(236,72,153,0.15)',  color: '#f472b6' },
};
function _tenantTypeBg(t)    { return (_TENANT_TYPE_STYLES[t] || { bg: 'rgba(100,116,139,0.15)' }).bg; }
function _tenantTypeColor(t) { return (_TENANT_TYPE_STYLES[t] || { color: '#94a3b8' }).color; }

function ProviderDot({ provider }) {
  const color = CLOUD_PROVIDERS[provider?.toLowerCase()]?.color || '#6366f1';
  return <span className="inline-block w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />;
}

export default function Header() {
  const router = useRouter();
  const { theme, toggleTheme } = useTheme();
  useGlobalFilter(); // keep context alive for downstream consumers

  const [showTenantMenu, setShowTenantMenu] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const tenantMenuRef = useRef(null);
  const userMenuRef = useRef(null);

  const { tenants, activeTenant, setActiveTenant } = useTenant();
  const { switchTenant, level, role, user, logout } = useAuth();
  const isPlatformAdmin = level === 1;
  const isOrgAdmin = role === 'org_admin' || level <= 2;
  const currentTenantName = activeTenant?.tenant_name ?? 'All Tenants';

  const displayName = user?.name || user?.email || 'User';
  const displayEmail = user?.email || '';
  const initials = displayName
    .split(' ')
    .map((p) => p[0])
    .slice(0, 2)
    .join('')
    .toUpperCase() || 'U';
  const unreadNotifications = 3;

  useEffect(() => {
    const handler = (e) => {
      if (tenantMenuRef.current && !tenantMenuRef.current.contains(e.target)) setShowTenantMenu(false);
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) setShowUserMenu(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <header
      className="h-12 flex items-center justify-between px-4 gap-3 transition-colors"
      style={{ backgroundColor: 'var(--header-bg)', borderBottom: '1px solid var(--border-primary)' }}
    >
      {/* ── Left: Logo wordmark (scope filters removed — show all by default) ── */}
      <div className="flex items-center gap-2">
        <span className="text-xs font-semibold" style={{ color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
          THREAT ENGINE
        </span>
      </div>

      {/* ── Right: Notification, Tenant, Theme, Profile ── */}
      <div className="flex items-center gap-2">
        {/* Trial countdown chip — amber pill; renders only in last 7 days of trial */}
        <TrialCountdownChip />

        {/* Notifications */}
        <button onClick={() => router.push('/notifications')} className="relative p-1.5 rounded-lg hover:opacity-75" style={{ color: 'var(--text-tertiary)' }} title="Notifications">
          <Bell size={16} />
          {unreadNotifications > 0 && (
            <div className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-3.5 h-3.5 rounded-full bg-red-500 text-white text-[9px] font-bold">
              {unreadNotifications}
            </div>
          )}
        </button>

        {/* Tenant Switcher — two paths:
              1. org_admin / platform_admin → full OrgTenantSwitcher (BFF-driven,
                 shows tenant_type badge, loading skeleton, dropdown) [AC4–AC10]
              2. other roles (tenant_admin, analyst, viewer) → simple static pill
                 or legacy dropdown sourced from auth context tenants          */}
        {isOrgAdmin ? (
          <OrgTenantSwitcher />
        ) : tenants.length === 1 ? (
          /* ── Static pill for single-tenant non-admin users ── */
          <span
            className="flex items-center px-2.5 py-1 rounded text-xs font-medium"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}
          >
            {tenants[0].tenant_name}
          </span>
        ) : tenants.length > 1 ? (
          /* ── Lightweight dropdown for multi-tenant non-admin users ── */
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
              <div className="absolute top-full right-0 mt-1 w-56 rounded-lg border shadow-lg z-50" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

                {/* All Tenants row — only visible to platform_admin */}
                {isPlatformAdmin && (
                  <button
                    onClick={() => { setActiveTenant(null); switchTenant(null); setShowTenantMenu(false); router.refresh(); }}
                    className="w-full text-left px-3 py-2 text-xs border-b hover:opacity-75"
                    style={{ backgroundColor: activeTenant === null ? 'var(--bg-tertiary)' : 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--border-primary)' }}
                  >
                    <div className="flex items-center gap-1.5">
                      <Globe size={11} />
                      <span className="font-medium">All Tenants</span>
                    </div>
                    <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>Cross-tenant view</div>
                  </button>
                )}

                {/* Individual tenant rows */}
                {tenants.map(t => (
                  <button
                    key={t.tenant_id}
                    onClick={() => { setActiveTenant(t); switchTenant(t.engine_tenant_id || t.tenant_id); setShowTenantMenu(false); router.refresh(); }}
                    className="w-full text-left px-3 py-2 text-xs border-b last:border-b-0 hover:opacity-75"
                    style={{ backgroundColor: activeTenant?.tenant_id === t.tenant_id ? 'var(--bg-tertiary)' : 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--border-primary)' }}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="font-medium">{t.tenant_name}</span>
                    </div>
                    <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>{t.account_count ?? 0} accounts</div>
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : null}

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
            title={`${displayName}`}>
            {initials}
          </button>
          {showUserMenu && (
            <div className="absolute top-full right-0 mt-1 w-52 rounded-lg border shadow-lg z-50" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-3 py-2 border-b" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="font-medium text-xs" style={{ color: 'var(--text-primary)' }}>{displayName}</div>
                <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{displayEmail}</div>
              </div>
              {[
                { icon: User, label: 'Profile', action: () => { router.push('/profile'); setShowUserMenu(false); } },
                { icon: Settings, label: 'Settings', action: () => { router.push('/settings'); setShowUserMenu(false); } },
                { icon: LogOut, label: 'Logout', action: async () => { setShowUserMenu(false); await logout(); router.push('/auth/login'); } },
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
