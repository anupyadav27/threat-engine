'use client';

import { useRouter } from 'next/navigation';
import { useState, useRef, useEffect } from 'react';
import { useTheme } from '@/lib/theme-context';
import { useAuth } from '@/lib/auth-context';
import { Sun, Moon, Bell, LogOut, User, Settings } from 'lucide-react';
import TrialCountdownChip from '@/components/billing/TrialCountdownChip';

export default function Header() {
  const router = useRouter();
  const { theme, toggleTheme } = useTheme();
  const { user, logout } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const userMenuRef = useRef(null);

  const displayName  = user?.name  || user?.email || 'User';
  const displayEmail = user?.email || '';
  const initials     = displayName
    .split(' ')
    .map(p => p[0])
    .slice(0, 2)
    .join('')
    .toUpperCase() || 'U';

  useEffect(() => {
    const handler = (e) => {
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
      {/* ── Left: product logo ── */}
      <div className="flex items-center gap-2">
        <span className="text-xs font-bold tracking-wide" style={{ color: 'var(--accent-primary)' }}>
          Onam Security
        </span>
      </div>

      {/* ── Right: Trial chip · Notifications · Theme · Profile ── */}
      <div className="flex items-center gap-2">
        <TrialCountdownChip />

        {/* Notifications */}
        <button
          onClick={() => router.push('/notifications')}
          className="relative p-1.5 rounded-lg hover:opacity-75"
          style={{ color: 'var(--text-tertiary)' }}
          title="Notifications"
        >
          <Bell size={16} />
        </button>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="p-1.5 rounded-lg hover:opacity-75"
          style={{ color: 'var(--text-tertiary)' }}
          title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>

        {/* User avatar + dropdown */}
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => setShowUserMenu(p => !p)}
            className="flex items-center justify-center w-7 h-7 rounded-full font-semibold text-xs hover:opacity-75"
            style={{ backgroundColor: 'rgb(59,130,246)', color: 'white' }}
            title={displayName}
          >
            {initials}
          </button>

          {showUserMenu && (
            <div
              className="absolute top-full right-0 mt-1 w-52 rounded-lg border shadow-lg z-50"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
            >
              <div
                className="px-3 py-2 border-b"
                style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}
              >
                <div className="font-medium text-xs" style={{ color: 'var(--text-primary)' }}>{displayName}</div>
                <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{displayEmail}</div>
              </div>
              {[
                { icon: User,    label: 'Profile',  action: () => { router.push('/profile');  setShowUserMenu(false); } },
                { icon: Settings,label: 'Settings', action: () => { router.push('/settings'); setShowUserMenu(false); } },
                { icon: LogOut,  label: 'Logout',   action: async () => { setShowUserMenu(false); await logout(); router.push('/auth/login'); } },
              ].map(({ icon: Icon, label, action }) => (
                <button
                  key={label}
                  onClick={action}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs border-b last:border-b-0 hover:opacity-75"
                  style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-primary)' }}
                >
                  <Icon size={14} />
                  <span>{label}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
