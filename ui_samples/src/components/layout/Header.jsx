'use client';

import { usePathname, useRouter } from 'next/navigation';
import { useState, useRef, useEffect } from 'react';
import { TENANT_ID } from '@/lib/constants';
import { useTheme } from '@/lib/theme-context';
import { Sun, Moon, Bell, ChevronDown, LogOut, User, Settings } from 'lucide-react';

export default function Header() {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, toggleTheme } = useTheme();
  const [currentTenant, setCurrentTenant] = useState('t1');
  const [showTenantMenu, setShowTenantMenu] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const tenantMenuRef = useRef(null);
  const userMenuRef = useRef(null);

  const tenants = [
    { id: 't1', name: 'Acme Corp' },
    { id: 't2', name: 'TechStart Inc' },
    { id: 't3', name: 'Global Finance' },
  ];

  const currentTenantName = tenants.find((t) => t.id === currentTenant)?.name || 'Select Tenant';

  const mockUser = {
    name: 'Anup Yadav',
    email: 'yadav.anup@gmail.com',
    role: 'Admin',
    initials: 'AY',
  };

  const unreadNotifications = 3;

  const getPageTitle = () => {
    if (pathname === '/' || pathname === '/dashboard') return 'Dashboard';
    const segments = pathname.split('/').filter(Boolean);
    if (segments.length === 0) return 'Dashboard';
    return segments
      .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
      .join(' / ');
  };

  // Close menus on outside click
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (tenantMenuRef.current && !tenantMenuRef.current.contains(e.target)) {
        setShowTenantMenu(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) {
        setShowUserMenu(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleTenantSwitch = (tenantId) => {
    setCurrentTenant(tenantId);
    setShowTenantMenu(false);
  };

  const handleNotifications = () => {
    router.push('/notifications');
  };

  const handleProfile = () => {
    router.push('/profile');
    setShowUserMenu(false);
  };

  const handleSettings = () => {
    router.push('/settings');
    setShowUserMenu(false);
  };

  const handleLogout = () => {
    router.push('/auth/login');
    setShowUserMenu(false);
  };

  return (
    <header
      className="h-14 flex items-center justify-between px-6 transition-colors duration-200"
      style={{
        backgroundColor: 'var(--header-bg)',
        borderBottom: '1px solid var(--border-primary)',
      }}
    >
      <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
        {getPageTitle()}
      </div>

      <div className="flex items-center gap-3">
        {/* Notifications Bell */}
        <button
          onClick={handleNotifications}
          className="relative p-2 rounded-lg transition-colors hover:opacity-75"
          style={{ color: 'var(--text-tertiary)' }}
          title="Notifications"
        >
          <Bell size={18} />
          {unreadNotifications > 0 && (
            <div className="absolute top-1 right-1 flex items-center justify-center w-4 h-4 rounded-full bg-red-500 text-white text-xs font-bold">
              {unreadNotifications}
            </div>
          )}
        </button>

        {/* Tenant Switcher */}
        <div className="relative" ref={tenantMenuRef}>
          <button
            onClick={() => setShowTenantMenu(!showTenantMenu)}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors hover:opacity-75"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-primary)',
            }}
          >
            {currentTenantName}
            <ChevronDown size={14} />
          </button>

          {showTenantMenu && (
            <div
              className="absolute top-full right-0 mt-2 w-48 rounded-lg border shadow-lg z-50"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-primary)',
              }}
            >
              {tenants.map((tenant) => (
                <button
                  key={tenant.id}
                  onClick={() => handleTenantSwitch(tenant.id)}
                  className="w-full text-left px-4 py-2.5 text-sm transition-colors border-b last:border-b-0 hover:opacity-75"
                  style={{
                    backgroundColor: currentTenant === tenant.id ? 'var(--bg-tertiary)' : 'transparent',
                    color: 'var(--text-secondary)',
                    borderColor: 'var(--border-primary)',
                  }}
                >
                  <div className="font-medium">{tenant.name}</div>
                  <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    ID: {tenant.id}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg transition-colors hover:opacity-75"
          style={{ color: 'var(--text-tertiary)' }}
          title={theme === 'dark' ? 'Switch to Light' : 'Switch to Dark'}
        >
          {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        {/* User Avatar & Menu */}
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center justify-center w-8 h-8 rounded-full font-semibold text-sm transition-colors hover:opacity-75"
            style={{
              backgroundColor: 'rgb(59, 130, 246)',
              color: 'white',
              border: '1px solid var(--border-primary)',
            }}
            title={`${mockUser.name} - ${mockUser.role}`}
          >
            {mockUser.initials}
          </button>

          {showUserMenu && (
            <div
              className="absolute top-full right-0 mt-2 w-56 rounded-lg border shadow-lg z-50"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-primary)',
              }}
            >
              {/* User Info Header */}
              <div
                className="px-4 py-3 border-b"
                style={{
                  borderColor: 'var(--border-primary)',
                  backgroundColor: 'var(--bg-tertiary)',
                }}
              >
                <div
                  className="font-medium text-sm"
                  style={{ color: 'var(--text-primary)' }}
                >
                  {mockUser.name}
                </div>
                <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  {mockUser.email}
                </div>
                <div className="mt-1">
                  <span
                    className="text-xs px-2 py-0.5 rounded"
                    style={{
                      backgroundColor: 'rgb(59, 130, 246)',
                      color: 'white',
                    }}
                  >
                    {mockUser.role}
                  </span>
                </div>
              </div>

              {/* Menu Items */}
              <button
                onClick={handleProfile}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors hover:opacity-75 border-b"
                style={{
                  color: 'var(--text-secondary)',
                  borderColor: 'var(--border-primary)',
                }}
              >
                <User size={16} />
                <span>Profile</span>
              </button>

              <button
                onClick={handleSettings}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors hover:opacity-75 border-b"
                style={{
                  color: 'var(--text-secondary)',
                  borderColor: 'var(--border-primary)',
                }}
              >
                <Settings size={16} />
                <span>Settings</span>
              </button>

              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors hover:opacity-75"
                style={{ color: 'var(--text-secondary)' }}
              >
                <LogOut size={16} />
                <span>Logout</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
