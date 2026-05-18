'use client';

/**
 * EdgeArrow — connector between two NodeBox components (accordion version).
 *
 * Copied from threats/attack-paths/EdgeArrow.jsx and extended with:
 *   onHoverStart / onHoverEnd props for edge tooltip in AttackPathExpanded.
 *
 * Props:
 *   edge          {object}    — from steps[]: { edge_to_next, edge_category, traversal_reason, sg_rule }
 *   onHoverStart  {function}  — called with MouseEvent when pointer enters
 *   onHoverEnd    {function}  — called when pointer leaves
 */

const EDGE_COLOR_MAP = {
  ASSUMES:         '#a855f7',
  CAN_ACCESS:      '#3b82f6',
  EXPOSES:         '#ef4444',
  CONNECTED_TO:    '#0ea5e9',
  FLOWS_TO:        '#22c55e',
  EXECUTES_IN:     '#f97316',
  CAN_ESCALATE_TO: '#ec4899',
  HAS_ROLE:        '#a855f7',
  HAS_PERMISSION:  '#a855f7',
  STORES:          '#22c55e',
  RUNS:            '#f97316',
};

function edgeColor(typeStr) {
  const up = (typeStr || '').toUpperCase().replace(/ /g, '_');
  for (const [key, color] of Object.entries(EDGE_COLOR_MAP)) {
    if (up.includes(key)) return color;
  }
  return '#475569';
}

export default function EdgeArrow({ edge, onHoverStart, onHoverEnd }) {
  const label = (edge?.edge_to_next || edge?.edge_category || '')
    .replace(/_/g, ' ')
    .slice(0, 14);
  const color = edgeColor(edge?.edge_to_next || edge?.edge_category);

  return (
    <div
      className="flex flex-col items-center justify-center flex-shrink-0"
      style={{ width: 52, gap: 2, cursor: 'default' }}
      onMouseEnter={onHoverStart}
      onMouseLeave={onHoverEnd}
    >
      {label && (
        <span
          className="text-[7px] font-bold text-center uppercase tracking-wide leading-none"
          style={{ color, maxWidth: 50, wordBreak: 'break-word' }}
        >
          {label}
        </span>
      )}
      <div className="flex items-center w-full">
        <div
          className="flex-1"
          style={{ height: 1.5, backgroundColor: color, opacity: 0.65 }}
        />
        <svg width="8" height="8" viewBox="0 0 8 8" style={{ flexShrink: 0 }}>
          <polygon points="0,0 8,4 0,8" fill={color} opacity={0.75} />
        </svg>
      </div>
    </div>
  );
}
