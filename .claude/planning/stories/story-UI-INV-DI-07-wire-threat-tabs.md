# Story DI-07: Wire 4 Dead Tabs in `/threats/[threatId]/page.jsx`

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 3
**Depends On:** DI-03 (evidence strip), DI-04 (attack chain enrichment)
**Blocks:** None

## Context

The Threat Detail page at `/threats/[threatId]` currently shows only 2 tabs: Overview and Timeline. The page already has `AttackPathTab`, `BlastRadiusTab`, `EvidenceTab`, and `RemediationTab` components defined in the same file (lines 916, 1138, 1387, 1509) but they are not in the `TABS` array and have no render cases. This story adds 4 tabs to the tab bar and wires up the render switch. It also removes a client-side call to the non-existent `/remediation` engine endpoint (if `RemediationTab` makes it directly) and verifies no `dangerouslySetInnerHTML` exists in the attack path rendering.

## Scope

Modify `frontend/src/app/threats/[threatId]/page.jsx` to extend the TABS array and add 4 tab render cases. Verify security constraints in existing tab components.

**Out of scope:** Attack Path SVG node click (DI-08), TechniqueDetailModal (DI-09), BFF changes (done in DI-04).

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/[threatId]/page.jsx` — 4 changes

## Implementation Notes

### Change 1: Replace TABS array (lines ~497-500)

**Current:**
```js
const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'timeline', label: 'Timeline', badge: timeline?.length || 0 },
];
```

**Replace with:**
```js
const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'attackPath', label: 'Attack Path', badge: data?.attackPath?.steps?.length || 0 },
  { id: 'blastRadius', label: 'Blast Radius', badge: data?.blastRadius?.reachableCount || 0 },
  { id: 'evidence', label: 'Evidence' },
  { id: 'remediation', label: 'Remediation', badge: data?.remediation?.steps?.length || 0 },
  { id: 'timeline', label: 'Timeline', badge: timeline?.length || 0 },
];
```

Note: `data` is the state variable holding the BFF response. Confirm the actual variable name by reading how the component stores BFF data — it may be `threatData` or `data`. Check `const [data, setData] = useState(null)` or equivalent around line 50-80 of the file. Use whatever variable name the component already uses for BFF data.

### Change 2: Add 4 cases in the tab render switch

Find the tab content render section (search for `activeTab === 'overview'` or the switch/if-else block around line 664). Add the following cases alongside the existing `'overview'` and `'timeline'` cases:

```jsx
{activeTab === 'attackPath' && (
  <AttackPathTab
    attackPath={data?.attackPath}
    mitre={data?.mitre}
    onNodeClick={(step) => setSelectedNode(step)}
    onTechniqueClick={(techniqueId) => setSelectedTechnique(techniqueId)}
  />
)}

{activeTab === 'blastRadius' && (
  <BlastRadiusTab
    blastRadius={data?.blastRadius}
    resourceUid={data?.threat?.resourceUid}
    router={router}
  />
)}

{activeTab === 'evidence' && (
  <EvidenceTab
    threat={data?.threat}
    evidence={data?.evidence}
  />
)}

{activeTab === 'remediation' && (
  <RemediationTab
    remediation={data?.remediation}
  />
)}
```

If the component uses `threat`, `attackPath`, etc. as top-level destructured state variables instead of `data?.attackPath`, adjust accordingly. Read lines 495 and the `const { ... } = data` destructuring to confirm.

Existing destructuring (line 495 from earlier read):
```js
const { threat, exposure, mitre, affectedResources, supportingFindings, attackPath, blastRadius, remediation, timeline, evidence, riskBreakdown } = data;
```
So use `attackPath`, `blastRadius`, `remediation`, `evidence`, `mitre`, `threat` directly (not `data?.attackPath`).

**Corrected render block:**
```jsx
{activeTab === 'attackPath' && (
  <AttackPathTab
    attackPath={attackPath}
    mitre={mitre}
    onNodeClick={(step) => setSelectedNode(step)}
    onTechniqueClick={(techniqueId) => setSelectedTechnique(techniqueId)}
  />
)}

{activeTab === 'blastRadius' && (
  <BlastRadiusTab blastRadius={blastRadius} resourceUid={threat?.resourceUid} router={router} />
)}

{activeTab === 'evidence' && (
  <EvidenceTab threat={threat} evidence={evidence} />
)}

{activeTab === 'remediation' && (
  <RemediationTab remediation={remediation} />
)}
```

Add `setSelectedNode` and `setSelectedTechnique` state vars near the top of the component (for DI-08 and DI-09 to consume):
```js
const [selectedNode, setSelectedNode] = useState(null);
const [selectedTechnique, setSelectedTechnique] = useState(null);
```

### Change 3: Verify `RemediationTab` does NOT call `/remediation` engine endpoint

Read `RemediationTab` (starting around line 1509). Check if it has a `useEffect` or `fetch` call targeting `/remediation` or any engine URL directly. If found, remove that fetch. Steps come from the `remediation` prop — `remediation.steps` array.

The `RemediationTab` should render:
```jsx
function RemediationTab({ remediation }) {
  const steps = remediation?.steps || [];
  const sla = remediation?.sla || {};
  // render steps as text content — no fetch, no dangerouslySetInnerHTML
}
```

If the component has a hardcoded SLA, replace with `sla.target` from the BFF (which now derives it from severity via `SLA_MAP` in DI-04).

### Change 4: Verify security constraints in `AttackPathTab` (line ~916)

Read `AttackPathTab` from line 916. Confirm:
1. No `dangerouslySetInnerHTML` anywhere in the component
2. All text rendering uses React `{value}` interpolation
3. ARN values in SVG nodes use `<text>{arn}</text>` or `<tspan>{arn}</tspan>`, NOT `innerHTML`

If `dangerouslySetInnerHTML` exists, replace with React text content. Example:
```jsx
// BAD
<div dangerouslySetInnerHTML={{ __html: step.fromName }} />
// GOOD
<div>{step.fromName}</div>
```

Also verify `RemediationTab` (line ~1509) renders `step.command`, `step.action`, `step.impact` as React text content (not as HTML).

### SLA badge in RemediationTab

Add a visual SLA indicator at the top of the remediation tab:
```jsx
{sla?.target && (
  <div className="mb-4 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
    <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>
      Remediation SLA:
    </span>
    <span className="ml-2 text-sm font-bold" style={{ color: 'var(--accent-primary)' }}>
      {sla.target}
    </span>
    {sla.severity && (
      <span className="ml-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
        (for {sla.severity} severity)
      </span>
    )}
  </div>
)}
```

### Empty states

Each tab should show a consistent empty state when data is missing:
- Attack Path: `"No attack path data available for this threat."` (centered, muted text)
- Blast Radius: `"Blast radius data not computed for this threat."`
- Evidence: `"No evidence data available."` (or redacted message if BFF returned stripped evidence with no visible fields)
- Remediation: `"No remediation steps available."`

The existing tab components may already handle these — verify and add if missing.

## Acceptance Criteria

- [ ] Tab bar shows all 6 tabs: Overview, Attack Path, Blast Radius, Evidence, Remediation, Timeline
- [ ] Attack Path tab badge shows `steps.length` (number of hops) or 0 when empty
- [ ] Blast Radius tab badge shows `reachableCount` or 0
- [ ] Remediation tab badge shows `steps.length` or 0
- [ ] Clicking Attack Path tab renders `AttackPathTab` component (not blank screen)
- [ ] Clicking Blast Radius tab renders `BlastRadiusTab` component
- [ ] Clicking Evidence tab renders `EvidenceTab` component
- [ ] Clicking Remediation tab renders `RemediationTab` component with `sla.target` badge
- [ ] `RemediationTab` has no `fetch`/`useEffect` calling any engine endpoint directly
- [ ] No `dangerouslySetInnerHTML` anywhere in `AttackPathTab` (grep confirms)
- [ ] No `dangerouslySetInnerHTML` anywhere in `RemediationTab` (grep confirms)
- [ ] Empty state messages shown when respective data is missing/empty
- [ ] `setSelectedNode` and `setSelectedTechnique` state vars added to page component (consumed by DI-08 and DI-09)

## Security Gates

- **B-7 (no dangerouslySetInnerHTML in AttackPathTab):** Grep `frontend/src/app/threats/\[threatId\]/page.jsx` for `dangerouslySetInnerHTML` — must return 0 matches in AttackPathTab component block
- **B-8 (no dangerouslySetInnerHTML in RemediationTab):** Same grep — 0 matches in RemediationTab
- **No client-side engine calls:** RemediationTab must not call engine directly — all data from BFF via `fetchView()`

## Definition of Done

- [ ] Code written and passes linter (ESLint, no React warnings in dev console)
- [ ] All 6 tabs visible and clickable in browser
- [ ] No `dangerouslySetInnerHTML` in modified/verified components
- [ ] `RemediationTab` has no direct engine fetch
- [ ] bmad-qa acceptance test run (smoke: open /threats/[threatId], click each tab)
