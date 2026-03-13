'use client';

import { useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Plus,
  Minus,
  RefreshCw,
  Shield,
  Network,
  Tag,
  Settings,
  Box,
} from 'lucide-react';
import CloudServiceIcon from './CloudServiceIcon';

/**
 * Category metadata for drift field groupings.
 * Maps BFF category keys to display labels, icons, and colors.
 */
const CATEGORY_META = {
  security: { label: 'Security', icon: Shield, color: '#ef4444' },
  network:  { label: 'Network',  icon: Network, color: '#3b82f6' },
  tags:     { label: 'Tags',     icon: Tag,     color: '#8b5cf6' },
  config:   { label: 'Config',   icon: Settings, color: '#f59e0b' },
};

/** Map change_type to display properties. */
const CHANGE_TYPE_META = {
  modified: { label: 'Modified', icon: RefreshCw, color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.1)' },
  added:    { label: 'Added',    icon: Plus,      color: '#22c55e', bg: 'rgba(34, 197, 94, 0.1)' },
  removed:  { label: 'Removed',  icon: Minus,     color: '#ef4444', bg: 'rgba(239, 68, 68, 0.1)' },
};

const SEVERITY_COLORS = {
  high:   '#ef4444',
  medium: '#f59e0b',
  low:    '#3b82f6',
};

/**
 * Renders a single field change row with before/after values.
 */
function FieldChangeRow({ field }) {
  const [expanded, setExpanded] = useState(false);
  const meta = CHANGE_TYPE_META[field.change_type] || CHANGE_TYPE_META.modified;
  const ChangeIcon = meta.icon;

  const beforeStr = field.before != null ? JSON.stringify(field.before) : '—';
  const afterStr  = field.after  != null ? JSON.stringify(field.after)  : '—';
  const isLong = beforeStr.length > 40 || afterStr.length > 40;

  return (
    <div
      className="flex items-start gap-3 py-2 px-3 rounded text-sm cursor-pointer hover:brightness-95 transition-all"
      style={{ backgroundColor: meta.bg }}
      onClick={() => isLong && setExpanded(!expanded)}
    >
      <ChangeIcon size={14} style={{ color: meta.color, marginTop: 2, flexShrink: 0 }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono font-medium" style={{ color: 'var(--text-primary)' }}>
            {field.field}
          </span>
          <span
            className="text-xs px-1.5 py-0.5 rounded"
            style={{ backgroundColor: meta.bg, color: meta.color, border: `1px solid ${meta.color}30` }}
          >
            {meta.label}
          </span>
        </div>
        {(field.change_type === 'modified' || expanded || !isLong) && (
          <div className={`mt-1 font-mono text-xs ${isLong && !expanded ? 'truncate' : ''}`}>
            {field.before != null && (
              <span style={{ color: 'var(--accent-danger)' }}>
                - {isLong && !expanded ? beforeStr.slice(0, 40) + '...' : beforeStr}
              </span>
            )}
            {field.before != null && field.after != null && <br />}
            {field.after != null && (
              <span style={{ color: 'var(--accent-success)' }}>
                + {isLong && !expanded ? afterStr.slice(0, 40) + '...' : afterStr}
              </span>
            )}
          </div>
        )}
      </div>
      {isLong && (
        expanded
          ? <ChevronDown size={14} style={{ color: 'var(--text-tertiary)', marginTop: 2 }} />
          : <ChevronRight size={14} style={{ color: 'var(--text-tertiary)', marginTop: 2 }} />
      )}
    </div>
  );
}

/**
 * Renders a category group (Security, Network, Tags, Config)
 * with its field changes, collapsible.
 */
function CategoryGroup({ category, fields }) {
  const [open, setOpen] = useState(true);
  const meta = CATEGORY_META[category] || { label: category, icon: Box, color: '#6b7280' };
  const CatIcon = meta.icon;

  return (
    <div
      className="rounded-lg border overflow-hidden"
      style={{ borderColor: `${meta.color}30` }}
    >
      <button
        className="w-full flex items-center gap-2 px-4 py-2.5 text-sm font-medium"
        style={{ backgroundColor: `${meta.color}08`, color: 'var(--text-primary)' }}
        onClick={() => setOpen(!open)}
      >
        <CatIcon size={16} style={{ color: meta.color }} />
        <span>{meta.label}</span>
        <span
          className="ml-1 text-xs px-1.5 py-0.5 rounded-full"
          style={{ backgroundColor: `${meta.color}20`, color: meta.color }}
        >
          {fields.length}
        </span>
        <span className="flex-1" />
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {open && (
        <div className="px-3 py-2 space-y-1" style={{ backgroundColor: 'var(--bg-card)' }}>
          {fields.map((f, i) => (
            <FieldChangeRow key={`${f.field}-${i}`} field={f} />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Renders a single scan transition block with categories.
 */
function TransitionBlock({ transition, index }) {
  const [open, setOpen] = useState(index === 0); // first transition expanded by default
  const sevColor = SEVERITY_COLORS[transition.drift_severity] || SEVERITY_COLORS.medium;

  return (
    <div
      className="rounded-lg border"
      style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-card)' }}
    >
      <button
        className="w-full flex items-center gap-3 px-5 py-3.5"
        onClick={() => setOpen(!open)}
      >
        {/* Scan dot */}
        <div
          className="w-3 h-3 rounded-full flex-shrink-0"
          style={{ backgroundColor: sevColor }}
        />
        <div className="text-left flex-1 min-w-0">
          <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
            Scan {transition.detected_at ? new Date(transition.detected_at).toLocaleDateString() : '—'}
          </div>
          <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
            {transition.detected_at ? new Date(transition.detected_at).toLocaleTimeString() : ''}
            {' · '}
            {transition.total_fields_changed} field{transition.total_fields_changed !== 1 ? 's' : ''} changed
          </div>
        </div>

        {/* Change type pills */}
        <div className="flex gap-1.5">
          {Object.entries(transition.counts || {}).map(([type, count]) => {
            if (!count) return null;
            const meta = CHANGE_TYPE_META[type];
            if (!meta) return null;
            return (
              <span
                key={type}
                className="text-xs px-2 py-0.5 rounded-full font-medium"
                style={{ backgroundColor: meta.bg, color: meta.color }}
              >
                {count} {meta.label}
              </span>
            );
          })}
        </div>

        {/* Drift severity badge */}
        <span
          className="text-xs px-2 py-1 rounded font-medium uppercase"
          style={{ backgroundColor: `${sevColor}15`, color: sevColor }}
        >
          {transition.drift_severity}
        </span>

        {open ? <ChevronDown size={16} style={{ color: 'var(--text-tertiary)' }} /> :
                <ChevronRight size={16} style={{ color: 'var(--text-tertiary)' }} />}
      </button>

      {open && (
        <div className="px-5 pb-4 space-y-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="pt-3" />
          {(transition.categories || []).map((cat) => (
            <CategoryGroup
              key={cat.category}
              category={cat.category}
              fields={cat.fields}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * DriftTimeline — main component for the asset detail Drift tab.
 *
 * Renders a vertical timeline of scan transitions with categorised
 * field-level changes and expandable diffs.
 *
 * Props:
 *   drift — BFF-transformed drift timeline object (from _build_drift_timeline)
 *   service — the asset's service type for the header icon
 */
export default function DriftTimeline({ drift, service }) {
  if (!drift || (!drift.has_drift && !drift.transitions?.length)) {
    return (
      <div className="space-y-4">
        <div
          className="rounded-lg p-6 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            Drift Detection
          </h2>

          {/* Status indicator */}
          <div className="flex items-center gap-2 mb-4">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: 'var(--accent-success)' }}
            />
            <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
              No Drift Detected
            </span>
          </div>

          <div
            className="rounded p-4 text-center text-sm"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}
          >
            {drift?.last_check
              ? `Last checked ${new Date(drift.last_check).toLocaleString()} — no configuration drift found`
              : 'No drift data available — drift detection requires at least two scans'}
          </div>
        </div>
      </div>
    );
  }

  const transitions = drift.transitions || [];
  const summary = drift.summary || {};
  const scans = drift.scans || [];

  return (
    <div className="space-y-4">
      {/* ── Header Card ───────────────────────────────── */}
      <div
        className="rounded-lg p-5 border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <CloudServiceIcon service={service || 'generic'} size={28} />
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                Drift Timeline
              </h2>
              <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                Last checked {drift.last_check ? new Date(drift.last_check).toLocaleString() : 'N/A'}
                {' · '}{scans.length} scan{scans.length !== 1 ? 's' : ''} tracked
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: 'var(--accent-danger)' }}
            />
            <span className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>
              Drift Detected
            </span>
          </div>
        </div>

        {/* ── Summary Cards ─────────────────────────────── */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Modified', count: summary.modified || 0, ...CHANGE_TYPE_META.modified },
            { label: 'Added',    count: summary.added    || 0, ...CHANGE_TYPE_META.added },
            { label: 'Removed',  count: summary.removed  || 0, ...CHANGE_TYPE_META.removed },
          ].map((item) => (
            <div
              key={item.label}
              className="rounded-lg p-3 text-center border"
              style={{ backgroundColor: item.bg, borderColor: `${item.color}20` }}
            >
              <div className="text-2xl font-bold" style={{ color: item.color }}>
                {item.count}
              </div>
              <div className="text-xs font-medium" style={{ color: item.color }}>
                {item.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Timeline Rail + Transition Blocks ──────────── */}
      <div className="relative">
        {/* Vertical rail line */}
        {transitions.length > 1 && (
          <div
            className="absolute left-[22px] top-6 bottom-6 w-0.5"
            style={{ backgroundColor: 'var(--border-primary)' }}
          />
        )}

        <div className="space-y-3">
          {transitions.map((t, i) => (
            <TransitionBlock key={t.scan_run_id || i} transition={t} index={i} />
          ))}
        </div>
      </div>

      {/* ── Legend ──────────────────────────────────────── */}
      <div
        className="rounded-lg px-5 py-3 border flex items-center gap-6 text-xs"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
          color: 'var(--text-tertiary)',
        }}
      >
        <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>Legend:</span>
        {Object.entries(CHANGE_TYPE_META).map(([key, meta]) => {
          const Icon = meta.icon;
          return (
            <span key={key} className="flex items-center gap-1">
              <Icon size={12} style={{ color: meta.color }} />
              {meta.label}
            </span>
          );
        })}
        {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
          <span key={sev} className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
            {sev.charAt(0).toUpperCase() + sev.slice(1)} drift
          </span>
        ))}
      </div>
    </div>
  );
}
