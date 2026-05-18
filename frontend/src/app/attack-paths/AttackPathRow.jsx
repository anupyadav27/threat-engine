'use client';

/**
 * AttackPathRow — single path row in the accordion list.
 *
 * Props:
 *   path           {object}    — path data from paths[]
 *   isExpanded     {boolean}   — whether this row is currently open
 *   onToggle       {function}  — called with path.path_id to expand/collapse
 *   chokeHighlight {boolean}   — amber left border when choke filter matches
 *   isViewer       {boolean}   — viewer role: row shown but no expand
 */

import { Zap, ChevronDown, ChevronUp } from 'lucide-react';
import styles from './attack-paths.module.css';

const SEV_COLOR  = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#6b7280' };
const SEV_BG     = { critical: 'rgba(239,68,68,0.12)', high: 'rgba(249,115,22,0.12)', medium: 'rgba(234,179,8,0.12)', low: 'rgba(107,114,128,0.12)' };
const SEV_BORDER = { critical: 'rgba(239,68,68,0.35)', high: 'rgba(249,115,22,0.35)', medium: 'rgba(234,179,8,0.35)', low: 'rgba(107,114,128,0.35)' };

function SevBadge({ severity }) {
  const color  = SEV_COLOR[severity]  || '#6b7280';
  const bg     = SEV_BG[severity]     || 'rgba(107,114,128,0.12)';
  const border = SEV_BORDER[severity] || 'rgba(107,114,128,0.35)';
  return (
    <span
      className="text-[9px] font-bold px-1.5 py-0.5 rounded-full uppercase tracking-wide flex-shrink-0"
      style={{ backgroundColor: bg, color, border: `1px solid ${border}` }}
    >
      {severity}
    </span>
  );
}

export default function AttackPathRow({
  path,
  isExpanded,
  onToggle,
  chokeHighlight,
  isViewer,
}) {
  const sevColor = SEV_COLOR[path.severity] || '#6b7280';
  const chainLabel = (path.chain_type || '').replace(/_/g, ' → ');
  const hops = path.depth ?? (path.node_uids?.length ?? 0);

  const rowStyle = {
    backgroundColor: isExpanded ? `${sevColor}08` : 'var(--bg-card)',
    borderColor: isExpanded
      ? `${sevColor}40`
      : chokeHighlight
      ? '#f59e0b'
      : 'rgba(255,255,255,0.07)',
    borderLeftWidth: isExpanded || chokeHighlight ? 3 : 1,
    borderLeftColor: isExpanded
      ? sevColor
      : chokeHighlight
      ? '#f59e0b'
      : 'rgba(255,255,255,0.07)',
    borderRadius: isExpanded ? '10px 10px 0 0' : 10,
  };

  function handleClick() {
    if (isViewer) return;
    onToggle(path.path_id);
  }

  function handleKeyDown(e) {
    if (isViewer) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onToggle(path.path_id);
    }
    if (e.key === 'Escape' && isExpanded) {
      onToggle(null);
    }
  }

  return (
    <button
      className={`w-full text-left border transition-all ${styles.pathRow}`}
      style={rowStyle}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      aria-expanded={isExpanded}
      aria-disabled={isViewer}
      tabIndex={0}
    >
      {/* Top row: severity + score + chain + CDR + group size */}
      <div className="flex items-center gap-2 flex-wrap">
        <SevBadge severity={path.severity} />

        <span
          className="text-[11px] font-bold tabular-nums flex-shrink-0"
          style={{ color: sevColor }}
        >
          {path.path_score ?? 0}
        </span>

        <span
          className="text-[10px] flex-1 truncate min-w-0"
          style={{ color: 'var(--text-primary)' }}
        >
          {path.attack_name || path.title || chainLabel || 'Attack Path'}
        </span>

        {path.has_active_cdr_actor && (
          <span
            className={`text-[8px] font-bold px-1.5 py-0.5 rounded animate-pulse flex-shrink-0 flex items-center gap-0.5 ${styles.cdrLiveBadge}`}
            style={{ backgroundColor: '#ef4444', color: '#fff' }}
          >
            <Zap style={{ width: 8, height: 8 }} /> LIVE
          </span>
        )}

        {path.group_size > 1 && path.is_representative && (
          <span
            className="text-[8px] font-semibold px-1.5 py-0.5 rounded-full flex-shrink-0"
            style={{ backgroundColor: 'rgba(168,85,247,0.15)', color: '#a855f7' }}
          >
            {path.group_size} similar
          </span>
        )}

        {!isViewer && (
          isExpanded
            ? <ChevronUp style={{ width: 12, height: 12, color: 'var(--text-secondary)', flexShrink: 0 }} />
            : <ChevronDown style={{ width: 12, height: 12, color: 'var(--text-secondary)', flexShrink: 0 }} />
        )}
      </div>

      {/* Bottom row: metadata */}
      <div
        className="flex items-center gap-3 mt-1 text-[9px]"
        style={{ color: 'var(--text-secondary)' }}
      >
        {hops > 0 && <span>{hops} hop{hops !== 1 ? 's' : ''}</span>}
        {path.open_days > 0 && <span>{path.open_days}d open</span>}
        {path.entry_point_type && (
          <span className="capitalize">{path.entry_point_type.replace(/_/g, ' ')}</span>
        )}
        {path.chain_type && (
          <span style={{ color: 'rgba(255,255,255,0.3)' }}>
            {chainLabel.slice(0, 32)}
          </span>
        )}
      </div>
    </button>
  );
}
