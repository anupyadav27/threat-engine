# STORY-UI-02: AssetContextCard Component

## Track
Investigation Flow — Critical Path Sprint

## Priority
P0 — Required by STORY-UI-01 (FindingDetailPanel). Must be created before STORY-UI-01 is merged.

## Story
As a security analyst in the finding detail panel, I need a compact engine-grid that shows what every other security engine has found on this same resource, so I can see correlated risk at a glance and click through to any engine's findings directly.

## Current State

No such component exists. `FindingDetailPanel.jsx` has no cross-engine section today. This is a new pure-UI component — no BFF changes, no engine changes. It consumes the `AssetContextResponse` shape returned by the STORY-GATEWAY-01 endpoint, passed in as a prop by the panel.

## Files to Create

- `frontend/src/components/shared/AssetContextCard.jsx` — **NEW**

## Component Specification

### Props

```typescript
interface AssetContextCardProps {
  resourceUid: string;                  // used in "View all" navigation links
  data: AssetContextResponse | null;    // null while loading or on error
  loading: boolean;
  currentEngine?: string;               // key to dim (e.g. "network") — already open
}

// Shape returned by GET /gateway/api/v1/asset-context/{uid}
interface AssetContextResponse {
  resource_uid: string;
  resource_name: string;
  resource_type?: string;
  account_id?: string;
  provider?: string;
  region?: string;
  overall_risk_score?: number | null;
  check?: EngineAssetSummary | null;
  network?: EngineAssetSummary | null;
  iam?: EngineAssetSummary | null;
  datasec?: EngineAssetSummary | null;
  encryption?: EngineAssetSummary | null;
  threat?: EngineAssetSummary | null;
  vulnerability?: EngineAssetSummary | null;
  container?: EngineAssetSummary | null;
  dbsec?: EngineAssetSummary | null;
  ai_security?: EngineAssetSummary | null;
  ciem?: EngineAssetSummary | null;
}

interface EngineAssetSummary {
  available: boolean;
  finding_count: number;
  max_severity: 'critical' | 'high' | 'medium' | 'low' | null;
  top_findings: Array<{
    finding_id: string;
    title: string;
    severity: string;
    status: string;
    rule_id?: string;
  }>;
}
```

### Static config (inside component, not props)

```jsx
const ENGINE_META = [
  { key: 'check',         label: 'Posture',     route: '/misconfig'          },
  { key: 'network',       label: 'Network',     route: '/network-security'   },
  { key: 'iam',           label: 'IAM',         route: '/iam'                },
  { key: 'threat',        label: 'Threats',     route: '/threats'            },
  { key: 'vulnerability', label: 'Vulns',       route: '/vulnerability'      },
  { key: 'datasec',       label: 'Data',        route: '/datasec'            },
  { key: 'encryption',    label: 'Encryption',  route: '/encryption'         },
  { key: 'container',     label: 'Container',   route: '/container-security' },
  { key: 'dbsec',         label: 'Database',    route: '/database-security'  },
  { key: 'ai_security',   label: 'AI',          route: '/ai-security'        },
  { key: 'ciem',          label: 'CIEM',        route: '/ciem'               },
];

const SEV_STYLE = {
  critical: { bg: 'rgba(239,68,68,0.15)',  text: '#ef4444', border: 'rgba(239,68,68,0.3)' },
  high:     { bg: 'rgba(249,115,22,0.15)', text: '#f97316', border: 'rgba(249,115,22,0.3)' },
  medium:   { bg: 'rgba(234,179,8,0.15)',  text: '#eab308', border: 'rgba(234,179,8,0.3)' },
  low:      { bg: 'rgba(34,197,94,0.15)',  text: '#22c55e', border: 'rgba(34,197,94,0.3)' },
};
```

## Full Component Implementation

```jsx
'use client';

import { Layers } from 'lucide-react';

const ENGINE_META = [ /* as above */ ];
const SEV_STYLE   = { /* as above */ };

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
```

## State Table

| State | Trigger | Rendered Output |
|---|---|---|
| Loading | `loading=true` | 8 skeleton cards (animate-pulse), 4-column grid |
| Error / unavailable | `loading=false, data=null` | `"Cross-engine context unavailable"` in muted italic |
| Engine unavailable | `data[key].available === false` | `—` in muted (engine down — not a clean bill of health) |
| Engine clean | `available=true, finding_count=0` | `✓ Clean` in green |
| Engine has findings | `finding_count > 0` | Severity-colored count badge + max_severity label |
| Hovered (with findings) | Mouse hover on card | Tooltip with top finding title + overflow count |
| Current engine | `meta.key === currentEngine` | Dimmed (opacity 0.4), not clickable, no hover tooltip |

## Acceptance Criteria

- [ ] Grid renders 11 engine cards in a `grid-cols-4` layout
- [ ] `loading=true` → 8 skeleton cards with `animate-pulse` (not 11 — grid wraps naturally)
- [ ] Current engine (`currentEngine` prop) card is visually dimmed and not clickable
- [ ] `available=false` → `—` (muted dash) — NOT `0` or error styling
- [ ] `finding_count=0, available=true` → `✓ Clean` in green — NOT `0` or a badge
- [ ] Finding count badge color matches `max_severity` (critical=red, high=orange, medium=yellow, low=green)
- [ ] Hover over a card with findings shows top finding title tooltip
- [ ] Clicking a finding card navigates to `/{engine-route}?resource_uid={encodedUid}`
- [ ] `keyboard: Enter / Space` on a clickable card triggers navigation (a11y)
- [ ] `"View full asset in Inventory"` link is always shown when `data` is not null
- [ ] No count badge shows green unless it represents `✓ Clean` (finding_count=0)
- [ ] Component renders without errors when all engine values in `data` are `null`

## Security Checklist

- [ ] `resourceUid` passed through `encodeURIComponent()` in all `href` and navigation constructions
- [ ] No `tenant_id`, `credential_ref`, or scan credentials rendered in component output
- [ ] All navigation links are relative paths — no hardcoded domain or port

## Definition of Done

- [ ] Component renders correctly with the following mock data scenarios:
  - All 11 engines `available=true, finding_count=0` → all show `✓ Clean`
  - Mix: 3 engines with findings (varying severities), 4 unavailable, 4 clean
  - `currentEngine="network"` → network card dimmed
  - `loading=true` → skeleton grid
  - `data=null` → unavailable message
- [ ] FindingDetailPanel integration (STORY-UI-01): engine grid appears within 2 s
- [ ] Clicking IAM card from any panel → navigates to `/iam?resource_uid={uid}`
- [ ] No console errors across all 5 state scenarios
- [ ] Visual: count badge colors match the CSPM severity palette used elsewhere (SeverityBadge colors)