# Story DI-09: `TechniqueDetailModal` React Component

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 3
**Depends On:** DI-06 (technique detail BFF endpoint)
**Blocks:** None

## Context

When users see a MITRE technique ID (e.g., `T1530`) in the Attack Path visualization or the hop steps table, clicking it should open a modal with rich technique context: what the technique is, how it's used in the MITRE ATT&CK framework, how many resources in the tenant are affected, D3FEND defensive countermeasures, and any compliance control mappings. This closed the investigation loop — users can understand the attack technique without leaving the threat context.

## Scope

Create `TechniqueDetailModal` as a new standalone React component. Wire it to `AttackPathTab` via the `onTechniqueClick` callback already added in DI-07.

**Out of scope:** BFF endpoint (DI-06), NodeInvestigationPanel (DI-08), any backend changes.

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/frontend/src/components/threats/TechniqueDetailModal.jsx` — create new file
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/[threatId]/page.jsx` — import and render `TechniqueDetailModal` (already has `selectedTechnique` state from DI-07)

## Implementation Notes

### Props interface

```jsx
/**
 * Props:
 *   techniqueId  {string|null}  — MITRE technique ID e.g. "T1530" or null when closed
 *   onClose      {func}         — Called to close the modal
 *   isOpen       {bool}         — Controls modal visibility
 */
```

### Data loading

```js
import { fetchView } from '@/lib/api';

const [techniqueData, setTechniqueData] = useState(null);
const [loading, setLoading] = useState(false);
const [error, setError] = useState(null);

useEffect(() => {
  if (!isOpen || !techniqueId) return;

  setLoading(true);
  setError(null);
  setTechniqueData(null);

  // Hits: GET /api/v1/views/threats/technique/{techniqueId}
  fetchView(`threats/technique/${techniqueId}`)
    .then((data) => {
      if (data?.detail === 'Technique not found' || !data?.techniqueId) {
        setError('Technique details not available');
      } else {
        setTechniqueData(data);
      }
      setLoading(false);
    })
    .catch(() => {
      setError('Technique details not available');
      setLoading(false);
    });
}, [isOpen, techniqueId]);
```

**Response shape (from DI-06):**
```json
{
  "techniqueId": "T1530",
  "techniqueName": "Data from Cloud Storage",
  "tactics": ["Collection"],
  "severityBase": "high",
  "url": "https://attack.mitre.org/techniques/T1530/",
  "affectedResources": 7,
  "detectionCount": 12,
  "d3fendMappings": [
    {"id": "D3-EAL", "label": "Executable Allowlisting"},
    {"id": "D3-PLM", "label": "Platform Monitoring"}
  ],
  "complianceControls": {}
}
```

### Escape key handler

```js
useEffect(() => {
  const handler = (e) => { if (e.key === 'Escape' && isOpen) onClose(); };
  document.addEventListener('keydown', handler);
  return () => document.removeEventListener('keydown', handler);
}, [isOpen, onClose]);
```

### Modal layout

```jsx
{isOpen && (
  <>
    {/* Backdrop */}
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>

      {/* Modal panel — stop propagation to prevent backdrop click closing when clicking inside */}
      <div
        className="relative w-full max-w-lg rounded-2xl shadow-2xl"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div>
            <h2 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
              {loading ? techniqueId : `${techniqueData?.techniqueId || techniqueId} — ${techniqueData?.techniqueName || ''}`}
            </h2>
            {techniqueData?.tactics?.length > 0 && (
              <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
                Tactic: {techniqueData.tactics.join(', ')}
              </p>
            )}
          </div>
          <button onClick={onClose} className="ml-4 p-1 rounded hover:bg-opacity-10 flex-shrink-0">
            <X className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 max-h-[60vh] overflow-y-auto">

          {loading && <ModalSkeleton />}

          {error && (
            <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>
              {error}
            </p>
          )}

          {!loading && !error && techniqueData && (
            <>
              {/* MITRE ATT&CK link */}
              <a
                href={techniqueData.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-sm font-medium"
                style={{ color: 'var(--accent-primary)' }}
              >
                View on MITRE ATT&CK
                <ExternalLink className="w-3 h-3" />
              </a>

              {/* In your environment */}
              <div className="p-4 rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>
                  In your environment
                </p>
                <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
                  {techniqueData.affectedResources}
                  <span className="text-sm font-normal ml-2" style={{ color: 'var(--text-secondary)' }}>
                    resources affected
                  </span>
                </p>
                <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
                  {techniqueData.detectionCount} detections
                </p>
              </div>

              {/* D3FEND Countermeasures — hide section entirely if empty */}
              {techniqueData.d3fendMappings?.length > 0 && (
                <div>
                  <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>
                    D3FEND Countermeasures
                  </p>
                  <ul className="space-y-1">
                    {techniqueData.d3fendMappings.map((m) => (
                      <li key={m.id} className="text-sm flex items-start gap-2" style={{ color: 'var(--text-secondary)' }}>
                        <span className="mt-1 flex-shrink-0 w-1.5 h-1.5 rounded-full" style={{ backgroundColor: 'var(--accent-primary)' }} />
                        <span>
                          <code className="text-xs mr-2" style={{ color: 'var(--text-muted)' }}>{m.id}</code>
                          {m.label}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Compliance Controls — hide section entirely if empty */}
              {techniqueData.complianceControls && Object.keys(techniqueData.complianceControls).length > 0 && (
                <div>
                  <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>
                    Compliance Controls
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(techniqueData.complianceControls).map(([framework, control]) => (
                      <span
                        key={framework}
                        className="text-xs px-2 py-1 rounded"
                        style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
                      >
                        {framework}: {typeof control === 'string' ? control : JSON.stringify(control)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  </>
)}
```

### ModalSkeleton component (inline)

```jsx
function ModalSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-4 rounded w-24" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      <div className="h-16 rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      <div className="h-4 rounded w-48" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      <div className="h-4 rounded w-36" style={{ backgroundColor: 'var(--bg-secondary)' }} />
    </div>
  );
}
```

### Wiring in page.jsx (DI-07 already adds `selectedTechnique` state)

At the bottom of the page JSX (alongside `NodeInvestigationPanel`), add:

```jsx
<TechniqueDetailModal
  techniqueId={selectedTechnique}
  onClose={() => setSelectedTechnique(null)}
  isOpen={selectedTechnique !== null}
/>
```

Import at top:
```js
import TechniqueDetailModal from '@/components/threats/TechniqueDetailModal';
```

### Triggering from `AttackPathTab`

In `AttackPathTab`, when rendering technique labels in hop rows or SVG nodes, add a click handler:
```jsx
<button
  onClick={() => onTechniqueClick && onTechniqueClick(step.technique)}
  className="text-xs underline"
  style={{ color: 'var(--accent-primary)', background: 'none', border: 'none', cursor: 'pointer' }}
>
  {step.technique}
</button>
```

The `onTechniqueClick` prop is passed from `page.jsx` via DI-07's `AttackPathTab` render block.

### Imports needed

```js
import { useState, useEffect } from 'react';
import { X, ExternalLink } from 'lucide-react';
import { fetchView } from '@/lib/api';
```

## Acceptance Criteria

- [ ] Modal opens when `onTechniqueClick(techniqueId)` is called with a non-null technique ID
- [ ] Modal closes on X button click, backdrop click, and Escape key press
- [ ] Clicking inside modal (non-backdrop area) does NOT close it (stopPropagation)
- [ ] Loading state: skeleton displayed during fetch; no flash of empty content
- [ ] Technique ID and name displayed in header (`"T1530 — Data from Cloud Storage"`)
- [ ] Tactics displayed below title (`"Tactic: Collection"`)
- [ ] "View on MITRE ATT&CK" link opens `https://attack.mitre.org/techniques/T1530/` in new tab
- [ ] "In your environment" block shows `affectedResources` (large number) and `detectionCount`
- [ ] D3FEND countermeasures section shown only when `d3fendMappings.length > 0`; hidden when empty
- [ ] Compliance controls section shown only when `complianceControls` has keys; hidden when empty
- [ ] Unknown technique (404 from BFF) → shows "Technique details not available" gracefully
- [ ] No `dangerouslySetInnerHTML` anywhere in component
- [ ] All text via React `{value}` interpolation — technique name, tactic, labels are all text content

## Security Gates

- **B-7 (no dangerouslySetInnerHTML):** grep `TechniqueDetailModal.jsx` → 0 matches
- **B-11 (external link safety):** MITRE ATT&CK link has `rel="noopener noreferrer"` alongside `target="_blank"`
- **No client-side engine calls:** Data loaded exclusively via `fetchView()` BFF proxy — no direct engine calls

## Definition of Done

- [ ] Code written and passes ESLint
- [ ] Modal renders correctly with real BFF data
- [ ] 404 graceful degradation verified
- [ ] No `dangerouslySetInnerHTML` anywhere
- [ ] External link has `noopener noreferrer`
- [ ] bmad-qa acceptance test run (click T#### in Attack Path, verify modal)