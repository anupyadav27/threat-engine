'use client';

/**
 * ChokeBar — sticky bar showing top-5 choke point chips.
 *
 * Props:
 *   chokePoints     {Array}   — choke_points_preview[] from main fetchView response
 *   activeChoke     {string|null} — currently active choke node_uid filter
 *   onChipClick     {function}    — called with node_uid (or null to clear)
 */

import { X, ShieldAlert } from 'lucide-react';
import styles from './attack-paths.module.css';

export default function ChokeBar({ chokePoints = [], activeChoke, onChipClick }) {
  if (!chokePoints || chokePoints.length === 0) return null;

  const top5 = chokePoints.slice(0, 5);

  return (
    <div className={styles.chokeBar} role="region" aria-label="Choke points">
      <div className="flex items-center gap-1.5 flex-shrink-0">
        <ShieldAlert style={{ width: 13, height: 13, color: '#f59e0b', flexShrink: 0 }} />
        <span
          className="text-[10px] font-bold uppercase tracking-wide flex-shrink-0"
          style={{ color: '#f59e0b' }}
        >
          Choke Points
        </span>
      </div>

      <div className="flex items-center gap-2 flex-wrap flex-1">
        {top5.map((cp) => {
          const isActive = activeChoke === cp.node_uid;
          const shortName = (cp.node_uid || cp.node_name || '').slice(-20);
          const breakCount = cp.paths_blocked_if_fixed ?? cp.path_count ?? 0;

          return (
            <button
              key={cp.node_uid}
              onClick={() => onChipClick(isActive ? null : cp.node_uid)}
              className={`${styles.chokeChip} ${isActive ? styles.chokeChipActive : ''}`}
              title={cp.node_uid}
            >
              <span>{shortName}</span>
              <span
                className="text-[9px]"
                style={{ color: isActive ? '#fde68a' : 'rgba(245,158,11,0.7)' }}
              >
                breaks {breakCount} path{breakCount !== 1 ? 's' : ''}
              </span>
              {isActive && <X style={{ width: 9, height: 9 }} />}
            </button>
          );
        })}
      </div>

      {activeChoke && (
        <button
          onClick={() => onChipClick(null)}
          className="flex items-center gap-1 text-[10px] font-medium flex-shrink-0 hover:opacity-80"
          style={{ color: 'rgba(245,158,11,0.7)' }}
        >
          <X style={{ width: 10, height: 10 }} /> Clear filter
        </button>
      )}
    </div>
  );
}
