# Story DI-08: `NodeInvestigationPanel` React Component

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 4
**Depends On:** DI-04 (enriched attack chain step shape)
**Blocks:** None

## Context

The Attack Path tab in Threat Detail shows an SVG visualization of how an attacker moves between cloud resources. When a user clicks a hop node in the SVG, a slide-over panel should open showing that specific resource's details: its name, ARN, resource type, MITRE technique enabling that hop, and misconfigurations detected on it. This panel provides inline triage without navigating away from the threat context. It also provides a "View Full Asset" deep-link to the inventory investigation journey.

## Scope

Create `NodeInvestigationPanel` as a new standalone React component. Wire it up to `AttackPathTab` via callback prop already added in DI-07.

**Out of scope:** TechniqueDetailModal (DI-09), any BFF changes, CIEM data in this panel (explicitly prohibited).

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/frontend/src/components/threats/NodeInvestigationPanel.jsx` — create new file
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/[threatId]/page.jsx` — import and render `NodeInvestigationPanel` (already has `selectedNode` state from DI-07)

## Implementation Notes

### Props interface

```jsx
// NodeInvestigationPanel.jsx
/**
 * Props:
 *   step      {object}  — Enriched attack chain step from BFF (from DI-04):
 *                          { from, fromName, fromResourceType,
 *                            to, toName, toResourceType,
 *                            relationship, category, technique,
 *                            riskScore, isTarget, isEntry, isInternetReachable }
 *   mitre     {object}  — Full mitre object from BFF: { allTechniques: [{id, name, url}] }
 *   onClose   {func}    — Called when user closes panel (X button or backdrop click)
 *   isOpen    {bool}    — Controls panel visibility
 */
```

### Panel behavior

- Slide in from the right when `isOpen === true`
- Close on X button click OR backdrop click (outside panel area) OR Escape key press
- Does NOT close when clicking inside panel

**Escape key handler:**
```js
useEffect(() => {
  const handleKeyDown = (e) => {
    if (e.key === 'Escape' && isOpen) onClose();
  };
  document.addEventListener('keydown', handleKeyDown);
  return () => document.removeEventListener('keydown', handleKeyDown);
}, [isOpen, onClose]);
```

### Internet entry node special case

If `step.isEntry && step.isInternetReachable` (or `step.from` is falsy/empty):
- Show globe icon (`Globe` from lucide-react) + "Internet" as the resource name
- Show "Entry point from Internet" as the resource type label
- Do NOT show ARN field
- Do NOT show misconfigurations section
- Do NOT show "View Full Asset" link
- Show only: name block + technique block (if technique is present)

### MITRE technique name lookup

```js
const techniqueName = useMemo(() => {
  if (!step?.technique || !mitre?.allTechniques) return '';
  const found = mitre.allTechniques.find((t) => t.id === step.technique);
  return found?.name || '';
}, [step, mitre]);

const techniqueUrl = useMemo(() => {
  if (!step?.technique) return '';
  const found = mitre?.allTechniques?.find((t) => t.id === step.technique);
  return found?.url || `https://attack.mitre.org/techniques/${step.technique}/`;
}, [step, mitre]);
```

### Misconfigs data loading

```js
const [misconfigs, setMisconfigs] = useState([]);
const [misconfigLoading, setMisconfigLoading] = useState(false);
const [misconfigError, setMisconfigError] = useState(null);

useEffect(() => {
  if (!isOpen || !step?.to || (step.isEntry && step.isInternetReachable)) return;

  setMisconfigLoading(true);
  setMisconfigError(null);

  // fetchView hits: GET /api/v1/views/threats/resources/{resource_uid}/posture
  // This existing endpoint returns misconfigs for a resource in threat context
  fetchView(`threats/resources/${encodeURIComponent(step.to)}/posture`)
    .then((data) => {
      const findings = data?.findings || data?.misconfigs || data || [];
      setMisconfigs(Array.isArray(findings) ? findings.slice(0, 10) : []);
      setMisconfigLoading(false);
    })
    .catch(() => {
      setMisconfigError('Could not load misconfigurations');
      setMisconfigLoading(false);
    });
}, [isOpen, step?.to]);
```

**Note:** `fetchView` is imported from `@/lib/api`. It calls `GET /api/v1/views/{page}` via the gateway.

### Copy to clipboard

```js
const [copied, setCopied] = useState(false);
const handleCopy = () => {
  if (step?.to) {
    navigator.clipboard.writeText(step.to);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
};
```

### Layout structure (using project CSS variables)

```jsx
<>
  {/* Backdrop */}
  {isOpen && (
    <div
      className="fixed inset-0 z-40 bg-black/40"
      onClick={onClose}
    />
  )}

  {/* Panel */}
  <div
    className={`fixed right-0 top-0 h-full w-96 z-50 shadow-2xl transition-transform duration-300 ${
      isOpen ? 'translate-x-0' : 'translate-x-full'
    } flex flex-col`}
    style={{ backgroundColor: 'var(--bg-card)', borderLeft: '1px solid var(--border-primary)' }}
  >
    {/* Header */}
    <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
      <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
        Node Investigation
      </h2>
      <button onClick={onClose} className="p-1 rounded hover:bg-opacity-10">
        <X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
      </button>
    </div>

    {/* Body — scrollable */}
    <div className="flex-1 overflow-y-auto p-4 space-y-4">

      {/* Resource header block */}
      <div>
        {isInternetNode ? (
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5" style={{ color: 'var(--text-secondary)' }} />
            <span className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>Internet</span>
          </div>
        ) : (
          <>
            <p className="text-base font-bold truncate" style={{ color: 'var(--text-primary)' }}>
              {step.toName}
            </p>
            <div className="flex flex-wrap gap-2 mt-1">
              <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                {step.toResourceType}
              </span>
            </div>
            {/* Full ARN with copy */}
            <div className="flex items-center gap-2 mt-2">
              <code className="text-xs truncate flex-1" style={{ color: 'var(--text-muted)' }}>
                {step.to}
              </code>
              <button onClick={handleCopy} className="flex-shrink-0" title="Copy ARN">
                {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />}
              </button>
            </div>
          </>
        )}
      </div>

      {/* Technique block */}
      {step?.technique && (
        <div className="p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
          <p className="text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
            Technique enabling this hop
          </p>
          <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            {step.technique}{techniqueName ? ` — ${techniqueName}` : ''}
          </p>
        </div>
      )}

      {/* Misconfigs block */}
      {!isInternetNode && (
        <div>
          <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>
            Misconfigurations on this resource
          </p>
          {misconfigLoading && <MisconfigSkeleton />}
          {misconfigError && (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{misconfigError}</p>
          )}
          {!misconfigLoading && !misconfigError && misconfigs.length === 0 && (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>No misconfigurations found.</p>
          )}
          {!misconfigLoading && !misconfigError && misconfigs.map((mc, idx) => (
            <div key={idx} className="flex items-center justify-between py-2 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <span className="text-xs flex-1 pr-2" style={{ color: 'var(--text-secondary)' }}>
                {mc.rule_title || mc.title || mc.rule_id || 'Unknown rule'}
              </span>
              <SeverityBadge severity={mc.severity} />
            </div>
          ))}
        </div>
      )}

    </div>

    {/* Footer — View Full Asset link */}
    {!isInternetNode && step?.to && (
      <div className="p-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
        <button
          onClick={() => router.push(`/inventory/${encodeURIComponent(step.to)}`)}
          className="w-full flex items-center justify-center gap-2 py-2 text-sm font-medium rounded-lg"
          style={{ backgroundColor: 'var(--accent-primary)', color: 'var(--bg-primary)' }}
        >
          View Full Asset
          <ExternalLink className="w-4 h-4" />
        </button>
      </div>
    )}
  </div>
</>
```

### MisconfigSkeleton component (inline in same file)

```jsx
function MisconfigSkeleton() {
  return (
    <div className="space-y-2">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-8 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      ))}
    </div>
  );
}
```

### Wiring in page.jsx (DI-07 already adds `selectedNode` state)

At the bottom of the JSX returned by `ThreatDetailPage` component, before the closing `</div>`, add:

```jsx
<NodeInvestigationPanel
  step={selectedNode}
  mitre={mitre}
  onClose={() => setSelectedNode(null)}
  isOpen={selectedNode !== null}
/>
```

Import at top of file:
```js
import NodeInvestigationPanel from '@/components/threats/NodeInvestigationPanel';
```

### Imports needed in `NodeInvestigationPanel.jsx`

```js
import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { X, Copy, Check, Globe, ExternalLink } from 'lucide-react';
import { fetchView } from '@/lib/api';
import SeverityBadge from '@/components/shared/SeverityBadge';
```

### Security constraint B-9: NO CIEM data in this panel

This panel must not call any CIEM BFF endpoint, must not display any identity or entitlement data, and must not pass the `ciem:sensitive` permission check. The only data shown is: resource metadata from the enriched step object (DI-04) + misconfigurations from `fetchView('threats/resources/{uid}/posture')`.

## Acceptance Criteria

- [ ] Panel opens (slides in from right) when `AttackPathTab` calls `onNodeClick(step)` with a non-null step
- [ ] Panel closes on X button click, backdrop click, and Escape key press
- [ ] Resource name (`toName`), resource type (`toResourceType`) displayed in header
- [ ] Full ARN (`to`) displayed with copy-to-clipboard button
- [ ] Clicking copy → clipboard contains full ARN; button shows check icon for 2 seconds
- [ ] Technique ID and name (from `mitre.allTechniques` lookup) displayed in technique block
- [ ] Misconfigs loaded via `fetchView('threats/resources/{uid}/posture')` — max 10 shown
- [ ] Misconfig rows show rule title and severity badge
- [ ] Loading state: skeleton rows displayed during fetch
- [ ] Error state: "Could not load misconfigurations" on fetch failure
- [ ] "View Full Asset" button navigates to `/inventory/{encodeURIComponent(step.to)}`
- [ ] Internet entry node (`isEntry && isInternetReachable`): shows "Internet" + globe icon; no ARN; no misconfigs; no "View Full Asset"
- [ ] No CIEM data present in panel for any role
- [ ] No `dangerouslySetInnerHTML` in the component (grep confirms)
- [ ] All text content via React `{value}` interpolation

## Security Gates

- **B-9 (no CIEM data):** Component makes no calls to `/api/v1/views/inventory/{id}/ciem` or any CIEM endpoint; verified by grep on component file
- **B-7 (no dangerouslySetInnerHTML):** grep `NodeInvestigationPanel.jsx` for `dangerouslySetInnerHTML` → 0 matches
- **B-10 (URL encoding):** `encodeURIComponent(step.to)` used in all navigation links to prevent ARN characters from breaking routing

## Definition of Done

- [ ] Code written and passes ESLint
- [ ] Component renders correctly for standard resource node
- [ ] Component renders "Internet" view for entry node
- [ ] No `dangerouslySetInnerHTML` anywhere
- [ ] No CIEM endpoint calls
- [ ] bmad-qa acceptance test run (click node in Attack Path SVG, verify panel)