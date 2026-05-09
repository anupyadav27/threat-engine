'use client';

import { useState } from 'react';

/**
 * Hover tooltip for non-technical explanations.
 * Wrap any element: <Tooltip text="plain-English explanation">...</Tooltip>
 */
export default function Tooltip({ children, text, position = 'top', maxWidth = 260 }) {
  const [show, setShow] = useState(false);
  if (!text) return children;

  const above = position !== 'bottom';

  return (
    <span
      style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      {children}
      {show && (
        <div
          role="tooltip"
          style={{
            position: 'absolute',
            zIndex: 9999,
            ...(above ? { bottom: 'calc(100% + 8px)' } : { top: 'calc(100% + 8px)' }),
            left: '50%',
            transform: 'translateX(-50%)',
            maxWidth,
            width: 'max-content',
            backgroundColor: '#0f172a',
            color: '#e2e8f0',
            fontSize: 12,
            lineHeight: 1.6,
            padding: '9px 13px',
            borderRadius: 8,
            boxShadow: '0 6px 20px rgba(0,0,0,0.55)',
            border: '1px solid rgba(255,255,255,0.09)',
            pointerEvents: 'none',
            whiteSpace: 'normal',
            textAlign: 'left',
            fontWeight: 400,
          }}
        >
          {/* arrow */}
          <span style={{
            position: 'absolute',
            ...(above ? { bottom: -5 } : { top: -5 }),
            left: '50%',
            transform: 'translateX(-50%) rotate(45deg)',
            width: 9, height: 9,
            backgroundColor: '#0f172a',
            border: above
              ? '1px solid rgba(255,255,255,0.09)'
              : '1px solid rgba(255,255,255,0.09)',
            borderTop: above ? 'none' : undefined,
            borderLeft: above ? 'none' : undefined,
            borderBottom: above ? undefined : 'none',
            borderRight: above ? undefined : 'none',
          }} />
          {text}
        </div>
      )}
    </span>
  );
}
