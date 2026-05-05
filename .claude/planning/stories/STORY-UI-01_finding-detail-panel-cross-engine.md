# STORY-UI-01: Extend FindingDetailPanel with Cross-Engine Context Section

## Track
Investigation Flow — Critical Path Sprint

## Priority
P0 — Core investigation flow upgrade. Depends on STORY-GATEWAY-01 (asset-context endpoint) and STORY-UI-02 (AssetContextCard component).

## Story
As a security analyst, when I click a finding row in any engine's table, I need the side panel to show not just this finding's details but also a summary of what other engines have found on the same resource, so I can see the full risk picture without navigating away.

## Current State

`frontend/src/components/shared/FindingDetailPanel.jsx` exists and renders:
severity/status header, resource fields, description, evidence (checked_fields / actual_values), remediation, classification badges, compliance frameworks, MITRE ATT&CK, and a "View in Inventory" link.

**What it does NOT do today:**
- Fetch additional data from any engine (uses only the `finding` prop passed by the parent)
- Fetch or display cross-engine context for the same `resource_uid`
- Show a loading state for secondary data
- Have a stale-fetch guard (AbortController on unmount)

The panel is opened by all engine pages passing `finding={rowData}` — no internal fetch happens today.

## Files to Modify / Create

- `frontend/src/components/shared/FindingDetailPanel.jsx` — **MODIFY**
- `frontend/src/components/shared/AssetContextCard.jsx` — **NEW** (STORY-UI-02 creates this; this story only imports it)

## Exact Changes to `FindingDetailPanel.jsx`

### Add imports (replace existing import block at top)

```jsx
'use client';

import { useEffect, useState } from 'react';
import { X, ExternalLink, Copy, Check, ShieldCheck, Layers } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import AssetContextCard from './AssetContextCard';
```

### Replace export signature + add state + fetch (replaces line 55 onwards through the existing `if (!finding) return null`)

```jsx
/**
 * @param {object}   finding           — finding row object from any engine table
 * @param {function} onClose           — called when ✕ is clicked or backdrop clicked
 * @param {object}   [context]         — optional page-specific config
 * @param {string}   [context.engine]  — engine key (e.g. "network") — dims that card in AssetContextCard
 * @param {Array}    [context.fields]  — extra { label, value, mono } rows for the Resource section
 */
export default function FindingDetailPanel({ finding, onClose, context = {} }) {
  // ── Secondary fetch: cross-engine context ──────────────────────────────
  const [assetCtx, setAssetCtx]     = useState(null);
  const [ctxLoading, setCtxLoading] = useState(false);

  const resourceId = finding?.resource_uid || finding?.resource_arn || finding?.resource_id || '';

  useEffect(() => {
    if (!resourceId || !finding) return;
    let cancelled = false;
    setAssetCtx(null);
    setCtxLoading(true);

    fetch(`/gateway/api/v1/asset-context/${encodeURIComponent(resourceId)}`, {
      credentials: 'include',
    })
      .then(r => (r.ok ? r.json() : null))
      .then(data  => { if (!cancelled) setAssetCtx(data);  })
      .catch(()   => { if (!cancelled) setAssetCtx(null);  })
      .finally(() => { if (!cancelled) setCtxLoading(false); });

    return () => { cancelled = true; };
  }, [resourceId]);

  if (!finding) return null;

  // ── Existing field normalisations (keep all unchanged) ─────────────────
  // ... (all existing lines from const resourceId through const extraFields unchanged) ...
```

### Add Cross-Engine Context section inside the panel body

Insert this block **before** the existing "View in Inventory" footer (before the final `{resourceId && (` block at the bottom of the scroll area):

```jsx
          {/* ── Risk Across Engines ── */}
          <Section title="Risk Across Engines">
            <AssetContextCard
              resourceUid={resourceId}
              data={assetCtx}
              loading={ctxLoading}
              currentEngine={context.engine}
            />
          </Section>
```

### Replace the "View in Inventory" footer with updated CTAs

```jsx
          {/* ── CTAs ── */}
          {resourceId && (
            <div className="pt-2 border-t flex items-center gap-3 flex-wrap"
              style={{ borderColor: 'var(--border-primary)' }}>
              <a
                href={`/inventory/${encodeURIComponent(resourceId)}`}
                className="inline-flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-lg transition-opacity hover:opacity-80"
                style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
              >
                <Layers className="w-4 h-4" /> View Full Asset
              </a>
              <a
                href={`/inventory/${encodeURIComponent(resourceId)}`}
                className="inline-flex items-center gap-2 text-xs px-3 py-2 rounded-lg transition-opacity hover:opacity-70"
                style={{ color: 'var(--text-muted)', border: '1px solid var(--border-primary)' }}
              >
                <ExternalLink className="w-3.5 h-3.5" /> Inventory
              </a>
            </div>
          )}
```

## Data Flow

```
User clicks finding row in any engine table
  │
  ├─ [sync] Parent sets state: { panelOpen: true, panelFinding: rowData }
  │    └─ FindingDetailPanel receives finding prop — renders immediately (no delay)
  │
  └─ [async, inside panel] useEffect fires when resourceId changes
       fetch /gateway/api/v1/asset-context/{resource_uid}  (credentials: include)
       ├─ While pending: ctxLoading=true → AssetContextCard shows skeleton
       └─ On resolve:    setAssetCtx(data) → AssetContextCard renders engine grid
       On error:         setAssetCtx(null) → AssetContextCard shows "unavailable" message
       On unmount:       cancelled=true → no setState after unmount
```

## How Existing Engine Pages Pass `context.engine`

Each engine page that opens the panel must pass its engine key so AssetContextCard can dim the current engine's card. Add `context={{ engine: '{key}' }}` to the existing panel open call:

| Page | context.engine value |
|------|---------------------|
| `/network-security` | `"network"` |
| `/iam` | `"iam"` |
| `/ciem` | `"ciem"` |
| `/container-security` | `"container"` |
| `/database-security` | `"dbsec"` |
| `/ai-security` | `"ai_security"` |
| `/datasec` | `"datasec"` |
| `/encryption` | `"encryption"` |
| `/misconfig` or `/check` | `"check"` |
| `/threats` | `"threat"` |
| `/vulnerability` | `"vulnerability"` |

Engine pages that do not pass `context.engine` are safe — AssetContextCard renders all 11 cards without dimming any.

## Acceptance Criteria

- [ ] Panel opens immediately with finding row data — no visible delay on primary sections
- [ ] "Risk Across Engines" section starts as skeleton immediately on panel open
- [ ] Skeleton resolves to engine grid within 2 s (asset-context fetch)
- [ ] If fetch fails (network error / 500), section shows `"Cross-engine context unavailable"` — all other panel sections still fully functional
- [ ] `context.engine` passed from parent → that engine's card is visually dimmed and not clickable
- [ ] "View Full Asset" CTA links to `/inventory/{encodedResourceId}`
- [ ] Panel closes on `×` click and backdrop click
- [ ] No `setState` after unmount — stale fetch guard (AbortController / `cancelled` flag) in place
- [ ] No console errors when opened with findings from IAM, network, CIEM, container, dbsec, ai-security pages
- [ ] Existing sections (resource, evidence, remediation, compliance, MITRE) visually unchanged

## Security Checklist

- [ ] `resourceId` is `encodeURIComponent`-encoded in the fetch URL
- [ ] `credentials: 'include'` on fetch — auth cookie sent; no manual token in URL or header
- [ ] No `tenant_id` constructed or sent from frontend — gateway resolves it from cookie
- [ ] No engine internal URLs in component — always relative `/gateway/api/v1/...` path

## Definition of Done

- [ ] Open panel from network-security page → primary network finding renders instantly → cross-engine grid appears within 2 s with real counts from IAM + check engines
- [ ] Open panel with a resource that has 0 findings in any other engine → those cards show `✓ Clean`
- [ ] Open panel → kill gateway pod mid-fetch → section shows `"Cross-engine context unavailable"` without breaking panel
- [ ] `context.engine="network"` → network card dimmed in grid; all other cards clickable
- [ ] No console errors on 10 consecutive open/close cycles
