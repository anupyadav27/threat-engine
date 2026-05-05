'use client';

import { useState } from 'react';
import { ChevronDown, Info, RefreshCw } from 'lucide-react';

/**
 * EngineShell — shared page-header shell for engine pages.
 *
 * Replaces the duplicated heading + Refresh button block that lives at the top
 * of every engine page. Renders:
 *   • icon + title + optional risk-pill badge (rightOfTitle slot)
 *   • description (brief)
 *   • optional collapsible "Best practices" (details list)
 *   • Refresh button (top-right) wired via onRefresh
 *
 * The page passes its existing layout (KPIs, charts, PageLayout) as `children`.
 *
 * Props:
 *   icon          - lucide-react icon component (rendered to the left of the title)
 *   title         - page title string
 *   description   - one-line brief
 *   details       - optional array of strings rendered as collapsible bullet list
 *   rightOfTitle  - optional ReactNode rendered next to the title (e.g. risk pill)
 *   onRefresh     - click handler for the Refresh button (no-op if omitted)
 *   refreshing    - boolean — disables button & spins icon when true
 *   refreshLabel  - override the button label (default: "Refresh")
 *   children      - body content
 */
export default function EngineShell({
  icon: Icon,
  title,
  description,
  details,
  rightOfTitle = null,
  onRefresh,
  refreshing = false,
  refreshLabel = 'Refresh',
  children,
}) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const hasDetails = Array.isArray(details) && details.length > 0;

  return (
    <div className="space-y-5">
      {/* Heading */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            {Icon && <Icon className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />}
            {title && (
              <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>
                {title}
              </h1>
            )}
            {rightOfTitle}
          </div>
          {description && (
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              {description}
            </p>
          )}
          {hasDetails && (
            <>
              <button
                onClick={() => setDetailsOpen(d => !d)}
                className="flex items-center gap-1 text-xs mt-1 hover:underline"
                style={{ color: 'var(--accent-primary)' }}
              >
                <Info className="w-3.5 h-3.5" />
                {detailsOpen ? 'Hide' : 'Best practices'}
                <ChevronDown className={`w-3.5 h-3.5 transition-transform ${detailsOpen ? 'rotate-180' : ''}`} />
              </button>
              {detailsOpen && (
                <ul
                  className="mt-2 ml-4 space-y-1 text-xs list-disc"
                  style={{ color: 'var(--text-tertiary)' }}
                >
                  {details.map((d, i) => <li key={i}>{d}</li>)}
                </ul>
              )}
            </>
          )}
        </div>

        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-opacity hover:opacity-80 disabled:opacity-60"
            style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshLabel}
          </button>
        )}
      </div>

      {children}
    </div>
  );
}
