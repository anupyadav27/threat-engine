'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import {
  LayoutDashboard,
  UserPlus,
  Radar,
  Server,
  ShieldAlert,
  ClipboardCheck,
  KeyRound,
  Database,
  Code,
  TrendingUp,
  Settings,
  ChevronDown,
  ChevronRight,
  Sun,
  Moon,
  Shield,
  Bell,
  Bug,
  FileCheck,
  FileText,
} from 'lucide-react';
import { NAV_ITEMS } from '@/lib/constants';
import { useTheme } from '@/lib/theme-context';

const ICON_MAP = {
  LayoutDashboard,
  UserPlus,
  Radar,
  Server,
  ShieldAlert,
  ClipboardCheck,
  KeyRound,
  Database,
  Code,
  TrendingUp,
  Settings,
  Bell,
  Bug,
  FileCheck,
  FileText,
};

// Sidebar width constants
const COLLAPSED_W   = 64;   // icon-only mode
const DEFAULT_W     = 240;  // default expanded width
const MIN_EXPAND_W  = 180;  // min width before snapping to collapsed
const MAX_W         = 380;  // max resizable width
const SNAP_COLLAPSE = 120;  // drag below this → collapse

export default function Sidebar({ collapsed = false, onToggle }) {
  const pathname   = usePathname();
  const { theme, toggleTheme } = useTheme();
  const [expanded, setExpanded] = useState({});

  // Tracks the expanded width the user has dragged to
  const [sidebarWidth, setSidebarWidth] = useState(DEFAULT_W);
  const [hoverEdge, setHoverEdge]       = useState(false);
  const [dragging, setDragging]         = useState(false);
  const dragRef = useRef(null); // { startX, startWidth, moved }

  // ── Initialise CSS custom property on mount ────────────────────────────────
  useEffect(() => {
    document.documentElement.style.setProperty('--sidebar-width', DEFAULT_W + 'px');
  }, []);

  // ── Keep CSS var in sync with collapsed state / sidebarWidth ───────────────
  useEffect(() => {
    const w = collapsed ? COLLAPSED_W : sidebarWidth;
    document.documentElement.style.setProperty('--sidebar-width', w + 'px');
  }, [collapsed, sidebarWidth]);

  // ── Edge handle: start drag ────────────────────────────────────────────────
  const startDrag = useCallback((e) => {
    e.preventDefault();
    dragRef.current = {
      startX:     e.clientX,
      startWidth: collapsed ? COLLAPSED_W : sidebarWidth,
      moved:      false,
    };
    setDragging(true);
  }, [collapsed, sidebarWidth]);

  // ── Edge handle: track drag / release ─────────────────────────────────────
  useEffect(() => {
    if (!dragging || !dragRef.current) return;

    const onMove = (e) => {
      const delta   = e.clientX - dragRef.current.startX;
      if (Math.abs(delta) > 3) dragRef.current.moved = true;

      const clamped = Math.min(MAX_W, Math.max(COLLAPSED_W, dragRef.current.startWidth + delta));

      // Update CSS var directly for smooth 60fps dragging (bypasses React render)
      document.documentElement.style.setProperty('--sidebar-width', clamped + 'px');
    };

    const onUp = (e) => {
      setDragging(false);

      // ── Click (no drag movement) → toggle collapse/expand
      if (!dragRef.current.moved) {
        onToggle();
        return;
      }

      // ── Drag ended → snap decision
      const delta      = e.clientX - dragRef.current.startX;
      const finalWidth = Math.min(MAX_W, Math.max(COLLAPSED_W, dragRef.current.startWidth + delta));

      if (finalWidth < SNAP_COLLAPSE) {
        // Snap to collapsed
        if (!collapsed) onToggle();
        document.documentElement.style.setProperty('--sidebar-width', COLLAPSED_W + 'px');
      } else {
        // Ensure expanded
        if (collapsed) onToggle();
        const snapped = Math.max(MIN_EXPAND_W, finalWidth);
        setSidebarWidth(snapped);
        document.documentElement.style.setProperty('--sidebar-width', snapped + 'px');
      }
    };

    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup',   onUp);
    return () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup',   onUp);
    };
  }, [dragging, collapsed, onToggle]);

  // ── Nav helpers ────────────────────────────────────────────────────────────
  const isActive = (href) => {
    if (href === '/dashboard') return pathname === '/dashboard' || pathname === '/';
    return pathname === href || pathname.startsWith(href + '/');
  };

  const isParentActive = (item) => {
    if (isActive(item.href)) return true;
    if (item.children) return item.children.some((c) => isActive(c.href));
    return false;
  };

  const toggleExpand = (label) =>
    setExpanded((prev) => ({ ...prev, [label]: !prev[label] }));

  const isExpanded = (item) => {
    if (collapsed) return false;
    if (expanded[item.label] !== undefined) return expanded[item.label];
    if (item.children) return item.children.some((c) => isActive(c.href));
    return false;
  };

  // ── Compute actual pixel width for the <aside> ────────────────────────────
  const actualWidth = collapsed ? COLLAPSED_W : sidebarWidth;

  return (
    <aside
      style={{
        width:           actualWidth,
        backgroundColor: 'var(--sidebar-bg)',
        borderRight:     '1px solid var(--border-primary)',
        zIndex:          40,
        position:        'fixed',
        left:            0,
        top:             0,
        height:          '100vh',
        display:         'flex',
        flexDirection:   'column',
        // Disable transition while dragging for smooth real-time resize
        transition:      dragging ? 'none' : 'width 200ms ease',
      }}
    >
      {/* ── Logo ──────────────────────────────────────────────────────────── */}
      <div
        className={`h-14 flex items-center gap-2.5 flex-shrink-0 ${collapsed ? 'justify-center px-0' : 'px-5'}`}
        style={{ borderBottom: '1px solid var(--border-primary)' }}
      >
        <Shield size={22} className="text-blue-500 flex-shrink-0" />
        {!collapsed && (
          <span className="text-base font-bold truncate" style={{ color: 'var(--text-primary)' }}>
            THREAT ENGINE
          </span>
        )}
      </div>

      {/* ── Navigation ────────────────────────────────────────────────────── */}
      <nav className="flex-1 overflow-y-auto py-3">
        {NAV_ITEMS.map((item) => {
          const Icon        = ICON_MAP[item.icon];
          const active      = isParentActive(item);
          const hasChildren = item.children && item.children.length > 0;
          const open        = isExpanded(item);

          return (
            <div key={item.label}>
              <div className="flex items-center">
                <Link
                  href={item.href}
                  title={collapsed ? item.label : undefined}
                  className={`flex-1 flex items-center gap-3 py-2.5 text-sm font-medium transition-colors duration-150 ${collapsed ? 'justify-center px-0' : 'px-5'}`}
                  style={{
                    backgroundColor: active ? 'var(--sidebar-active)' : 'transparent',
                    color:           active ? 'var(--sidebar-active-text)' : 'var(--text-tertiary)',
                    borderLeft:      !collapsed && active
                      ? '3px solid var(--sidebar-active-text)'
                      : !collapsed ? '3px solid transparent' : 'none',
                  }}
                  onMouseEnter={(e) => { if (!active) e.currentTarget.style.backgroundColor = 'var(--sidebar-hover)'; }}
                  onMouseLeave={(e) => { if (!active) e.currentTarget.style.backgroundColor = 'transparent'; }}
                >
                  {Icon && <Icon size={18} className="flex-shrink-0" />}
                  {!collapsed && <span className="truncate">{item.label}</span>}
                </Link>

                {!collapsed && hasChildren && (
                  <button
                    onClick={() => toggleExpand(item.label)}
                    className="pr-4 py-2.5 transition-colors"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </button>
                )}
              </div>

              {!collapsed && hasChildren && open && (
                <div className="ml-5 border-l" style={{ borderColor: 'var(--border-primary)' }}>
                  {item.children.map((child) => {
                    const childActive = isActive(child.href);
                    return (
                      <Link
                        key={child.href}
                        href={child.href}
                        className="block pl-7 pr-4 py-2 text-xs font-medium transition-colors duration-150"
                        style={{
                          color:           childActive ? 'var(--sidebar-active-text)' : 'var(--text-muted)',
                          backgroundColor: childActive ? 'var(--sidebar-active)' : 'transparent',
                        }}
                        onMouseEnter={(e) => { if (!childActive) e.currentTarget.style.backgroundColor = 'var(--sidebar-hover)'; }}
                        onMouseLeave={(e) => { if (!childActive) e.currentTarget.style.backgroundColor = 'transparent'; }}
                      >
                        {child.label}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* ── Theme toggle ──────────────────────────────────────────────────── */}
      <div
        className="p-3 pb-4 flex-shrink-0"
        style={{ borderTop: '1px solid var(--border-primary)' }}
      >
        <button
          onClick={toggleTheme}
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          className={`w-full flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-200 ${collapsed ? 'justify-center' : ''}`}
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
          onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--sidebar-hover)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)'; }}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          {!collapsed && (theme === 'dark' ? 'Light Mode' : 'Dark Mode')}
        </button>
      </div>

      {/* ── Edge drag / collapse handle ───────────────────────────────────── */}
      {/* Invisible 10px hit-zone straddling the right border */}
      <div
        onMouseDown={startDrag}
        onMouseEnter={() => setHoverEdge(true)}
        onMouseLeave={() => { if (!dragging) setHoverEdge(false); }}
        title={collapsed ? 'Drag or click to expand' : 'Drag to resize · Click to collapse'}
        style={{
          position: 'absolute',
          top:      0,
          right:    0,        // flush with right border
          width:    8,
          height:   '100%',
          cursor:   'col-resize',
          zIndex:   50,
          display:  'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {/* Blue pill indicator */}
        <div
          style={{
            width:        3,
            borderRadius: 99,
            backgroundColor: hoverEdge || dragging ? 'var(--accent-primary)' : 'transparent',
            height:       hoverEdge || dragging ? 56 : 0,
            opacity:      hoverEdge || dragging ? 1  : 0,
            transition:   dragging ? 'none' : 'height 0.18s ease, opacity 0.18s ease',
            boxShadow:    hoverEdge || dragging ? '0 0 10px var(--accent-primary)' : 'none',
          }}
        />
      </div>
    </aside>
  );
}
