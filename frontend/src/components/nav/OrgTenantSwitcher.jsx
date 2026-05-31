'use client';

import { useState, useRef, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { ChevronDown, Building2, Globe } from 'lucide-react';
import { useTenant } from '@/lib/tenant-context';

const TENANT_TYPE_COLORS = {
  cloud:         { bg: 'rgba(59,130,246,0.15)',  color: '#60a5fa' },
  security:      { bg: 'rgba(239,68,68,0.15)',   color: '#f87171' },
  vulnerability: { bg: 'rgba(245,158,11,0.15)',  color: '#fbbf24' },
  database:      { bg: 'rgba(16,185,129,0.15)',  color: '#34d399' },
  middleware:    { bg: 'rgba(139,92,246,0.15)',  color: '#a78bfa' },
  technology:    { bg: 'rgba(236,72,153,0.15)',  color: '#f472b6' },
};

function TypeBadge({ type }) {
  if (!type) return null;
  const s = TENANT_TYPE_COLORS[type] || { bg: 'rgba(100,116,139,0.15)', color: '#94a3b8' };
  return (
    <span className="ml-1 text-[10px] px-1.5 py-0.5 rounded font-medium" style={s}>
      {type}
    </span>
  );
}

export default function OrgTenantSwitcher() {
  const router = useRouter();
  const { tenants, activeTenant, setActiveTenant } = useTenant();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const currentName = activeTenant?.tenant_name ?? 'All Tenants';
  const currentType = activeTenant?.tenant_type ?? null;

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-sm font-medium transition-colors hover:opacity-75"
        style={{ color: 'var(--text-primary)', border: '1px solid var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}
      >
        <Building2 className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
        <span className="max-w-[120px] truncate">{currentName}</span>
        {currentType && <TypeBadge type={currentType} />}
        <ChevronDown className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
      </button>

      {open && (
        <div
          className="absolute right-0 mt-1.5 w-60 rounded-xl border shadow-lg z-50 overflow-hidden py-1"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          {/* All Tenants option */}
          <button
            onClick={() => { setActiveTenant(null); setOpen(false); router.refresh(); }}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-left transition-colors hover:bg-white/5"
            style={{ color: !activeTenant ? 'var(--accent-primary)' : 'var(--text-secondary)' }}
          >
            <Globe className="w-3.5 h-3.5 flex-shrink-0" />
            <span>All Tenants</span>
          </button>

          {tenants.length > 0 && (
            <div className="my-1 border-t" style={{ borderColor: 'var(--border-primary)' }} />
          )}

          {tenants.map(t => {
            const isActive = t.tenant_id === activeTenant?.tenant_id;
            return (
              <button
                key={t.tenant_id}
                onClick={() => { setActiveTenant(t); setOpen(false); router.refresh(); }}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm text-left transition-colors hover:bg-white/5"
                style={{ color: isActive ? 'var(--accent-primary)' : 'var(--text-primary)' }}
              >
                <Building2 className="w-3.5 h-3.5 flex-shrink-0" />
                <span className="truncate flex-1">{t.tenant_name || t.tenant_id}</span>
                {t.tenant_type && <TypeBadge type={t.tenant_type} />}
              </button>
            );
          })}

          {tenants.length === 0 && (
            <p className="px-3 py-2 text-xs" style={{ color: 'var(--text-muted)' }}>No tenants found.</p>
          )}
        </div>
      )}
    </div>
  );
}
