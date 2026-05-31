'use client';

/**
 * AttackPathRow — single path row in the left path list (Orca 3-zone layout).
 *
 * Click selects the path (shows it on the canvas). No accordion expand.
 *
 * Props:
 *   path           {object}    — path data from paths[]
 *   isSelected     {boolean}   — whether this path is loaded on the canvas
 *   onSelect       {function}  — called with path.path_id when clicked
 *   chokeHighlight {boolean}   — amber left border when choke filter matches
 *   isViewer       {boolean}   — viewer role: row shown but no select
 */

import { Zap } from 'lucide-react';
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
  isSelected,
  onSelect,
  chokeHighlight,
  isViewer,
}) {
  const sevColor = SEV_COLOR[path.severity] || '#6b7280';
  const chainLabel = (path.chain_type || '').replace(/_/g, ' → ');
  const hops = path.depth ?? (path.node_uids?.length ?? 0);

  const rowStyle = {
    backgroundColor: isSelected ? `${sevColor}0e` : 'transparent',
    borderColor: isSelected
      ? `${sevColor}50`
      : chokeHighlight
      ? '#f59e0b'
      : 'rgba(255,255,255,0.07)',
    borderLeftWidth: isSelected || chokeHighlight ? 3 : 1,
    borderLeftColor: isSelected
      ? sevColor
      : chokeHighlight
      ? '#f59e0b'
      : 'rgba(255,255,255,0.07)',
    borderRadius: 8,
  };

  function handleClick() {
    if (isViewer) return;
    onSelect(path.path_id);
  }

  function handleKeyDown(e) {
    if (isViewer) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onSelect(path.path_id);
    }
  }

  return (
    <button
      className={`w-full text-left border transition-all ${styles.pathRow}`}
      style={rowStyle}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      aria-pressed={isSelected}
      aria-disabled={isViewer}
      tabIndex={0}
    >
      {/* Top row: severity + score + name + CDR badge */}
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
          style={{ color: isSelected ? 'rgba(255,255,255,0.95)' : 'var(--text-primary)' }}
        >
          {path.attack_name || path.title || chainLabel || 'Attack Path'}
        </span>

        {path.has_active_cdr_actor && (
          <span
            className={`text-[8px] font-bold px-1.5 py-0.5 rounded flex items-center gap-0.5 flex-shrink-0 ${styles.cdrLiveBadge}`}
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
            {path.group_size}×
          </span>
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
        {path.confidence_level && (
          <span style={{ color: 'rgba(255,255,255,0.3)' }}>{path.confidence_level}</span>
        )}
      </div>
    </button>
  );
}
