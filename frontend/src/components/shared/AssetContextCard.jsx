'use client';

import { Layers } from 'lucide-react';

const ENGINE_META = [
  { key: 'check',         label: 'Posture',    route: '/misconfig'          },
  { key: 'network',       label: 'Network',    route: '/network-security'   },
  { key: 'iam',           label: 'IAM',        route: '/iam'                },
  { key: 'threat',        label: 'Threats',    route: '/threats'            },
  { key: 'vulnerability', label: 'Vulns',      route: '/vulnerability'      },
  { key: 'datasec',       label: 'Data',       route: '/datasec'            },
  { key: 'encryption',    label: 'Encryption', route: '/encryption'         },
  { key: 'container',     label: 'Container',  route: '/container-security' },
  { key: 'dbsec',         label: 'Database',   route: '/database-security'  },
  { key: 'ai_security',   label: 'AI',         route: '/ai-security'        },
  { key: 'ciem',          label: 'CIEM',       route: '/ciem'               },
];

const SEV_STYLE = {
  critical: { bg: 'rgba(239,68,68,0.15)',  text: '#ef4444', border: 'rgba(239,68,68,0.3)'  },
  high:     { bg: 'rgba(249,115,22,0.15)', text: '#f97316', border: 'rgba(249,115,22,0.3)' },
  medium:   { bg: 'rgba(234,179,8,0.15)',  text: '#eab308', border: 'rgba(234,179,8,0.3)'  },
  low:      { bg: 'rgba(34,197,94,0.15)',  text: '#22c55e', border: 'rgba(34,197,94,0.3)'  },
};

// ── Skeleton card ──────────────────────────────────────────────────────────
function EngineCardSkeleton() {
  return (
    <div
      className="rounded-lg p-2.5 animate-pulse"
      style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}
    >
      <div className="h-2.5 w-10 rounded mb-2" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
      <div className="h-4 w-7 rounded"          style={{ backgroundColor: 'var(--bg-tertiary)' }} />
    </div>
  );
}

// ── Single engine card ─────────────────────────────────────────────────────
function EngineCard({ meta, summary, resourceUid, isCurrent }) {
  const hasFindings  = summary?.available && (summary?.finding_count ?? 0) > 0;
  const isUnavail    = summary != null && !summary.available;
  const sevStyle     = summary?.max_severity ? SEV_STYLE[summary.max_severity] : null;
  const isClickable  = hasFindings && !isCurrent;

  const borderColor = isCurrent       ? 'var(--border-primary)'
    : hasFindings && sevStyle         ? sevStyle.border
    : 'var(--border-primary)';

  function handleClick() {
    if (!isClickable) return;
    // Navigate to engine page pre-filtered to this resource
    window.location.href = `${meta.route}?resource_uid=${encodeURIComponent(resourceUid)}`;
  }

  return (
    <div
      role={isClickable ? 'button' : undefined}
      tabIndex={isClickable ? 0 : undefined}
      onClick={handleClick}
      onKeyDown={e => { if (isClickable && (e.key === 'Enter' || e.key === ' ')) handleClick(); }}
      className="rounded-lg p-2.5 relative group"
      style={{
        backgroundColor: 'var(--bg-secondary)',
        border: `1px solid ${borderColor}`,
        opacity: isCurrent ? 0.4 : 1,
        cursor: isClickable ? 'pointer' : 'default',
        transition: 'opacity 0.15s, border-color 0.15s',
      }}
      title={
        isCurrent ? `Currently viewing ${meta.label}`
        : hasFindings ? `View ${meta.label} findings for this resource`
        : undefined
      }
    >
      {/* Engine label */}
      <p className="text-xs font-medium mb-1.5 truncate" style={{ color: 'var(--text-muted)' }}>
        {meta.label}
      </p>

      {/* Status indicator */}
      {isUnavail ? (
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>—</span>
      ) : !summary || summary.finding_count === 0 ? (
        <span className="text-xs font-semibold" style={{ color: '#22c55e' }}>✓ Clean</span>
      ) : (
        <div className="flex items-center gap-1">
          <span
            className="text-xs font-bold px-1.5 py-0.5 rounded"
            style={{ backgroundColor: sevStyle?.bg, color: sevStyle?.text }}
          >
            {summary.finding_count}
          </span>
          <span className="text-xs capitalize truncate" style={{ color: sevStyle?.text }}>
            {summary.max_severity}
          </span>
        </div>
      )}

      {/* Hover tooltip: top finding title */}
      {isClickable && summary?.top_findings?.[0] && (
        <div
          className="absolute left-0 right-0 bottom-0 translate-y-full pt-1 z-20
                     hidden group-hover:block group-focus:block pointer-events-none"
        >
          <div
            className="rounded-md px-2.5 py-2 text-xs shadow-xl"
            style={{
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-primary)',
              color: 'var(--text-secondary)',
              maxWidth: '220px',
              wordBreak: 'break-word',
            }}
          >
            <span className="font-medium">{summary.top_findings[0].title}</span>
            {summary.finding_count > 1 && (
              <span style={{ color: 'var(--text-muted)' }}>
                {' '}+{summary.finding_count - 1} more
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main export ────────────────────────────────────────────────────────────
export default function AssetContextCard({ resourceUid, data, loading, currentEngine }) {

  // Loading: show skeleton grid
  if (loading) {
    return (
      <div className="grid grid-cols-4 gap-2">
        {Array.from({ length: 8 }).map((_, i) => <EngineCardSkeleton key={i} />)}
      </div>
    );
  }

  // Fetch failed / no data
  if (!data) {
    return (
      <p className="text-xs italic" style={{ color: 'var(--text-muted)' }}>
        Cross-engine context unavailable
      </p>
    );
  }

  const enginesWithFindings = ENGINE_META.filter(m =>
    m.key !== currentEngine &&
    data[m.key]?.available &&
    (data[m.key]?.finding_count ?? 0) > 0
  );

  return (
    <div className="space-y-3">

      {/* Headline */}
      {enginesWithFindings.length > 0 ? (
        <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          <span className="font-semibold" style={{ color: '#f97316' }}>
            {enginesWithFindings.length} other engine{enginesWithFindings.length !== 1 ? 's' : ''}
          </span>{' '}
          also have findings on this resource — click a card to investigate.
        </p>
      ) : (
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          No findings in other engines for this resource.
        </p>
      )}

      {/* Engine grid: 4 columns, wraps naturally */}
      <div className="grid grid-cols-4 gap-2">
        {ENGINE_META.map(meta => (
          <EngineCard
            key={meta.key}
            meta={meta}
            summary={data[meta.key] ?? null}
            resourceUid={resourceUid}
            isCurrent={meta.key === currentEngine}
          />
        ))}
      </div>

      {/* Footer link */}
      <a
        href={`/inventory/${encodeURIComponent(resourceUid)}`}
        className="inline-flex items-center gap-1.5 text-xs font-medium hover:opacity-75 transition-opacity"
        style={{ color: 'var(--accent-primary)' }}
      >
        <Layers className="w-3 h-3" />
        View full asset in Inventory
      </a>

    </div>
  );
}
