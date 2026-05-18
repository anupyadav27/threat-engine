# JNY-07: PivotLink primitive component + storybook

## Track
Investigation Journey Unification — Phase B

## Priority
P0 — The single primitive that fixes G-7 (no `<a href>`), G-12..G-19 (orphaned rows across 7 engines), and unifies cross-engine navigation.

## Status
done — PivotLink.jsx (real <a>, 400ms delayed tooltip, telemetry emit, 11 entity types) + pivot-routes.js (resolvePivotUrl + ENTITY_REGISTRY) implemented; secops returns null (pending STORY-ENG-SECOPS-FINDING-TABLE)

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | — | — |
| UI / BFF / Gateway dev | `cspm-ui-dev` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-architect` + `bmad-agent-ux-designer` + `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | — | — |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §3.1 L2, every cross-engine navigation must go through one shared component. The component must render a real `<a href>` (so middle-click and copy-link work — closes G-7), show entity icon + truncated name, expose hover tooltip with engine + severity, and emit a click event for telemetry. It replaces every `onClick={() => router.push(...)}` and every bare resource_uid/rule_id/principal text cell across 14 engine pages.

## What to build
1. New component: `/Users/apple/Desktop/threat-engine/frontend/src/components/shared/PivotLink.jsx`
2. Entity registry: `/Users/apple/Desktop/threat-engine/frontend/src/components/shared/pivotEntityRegistry.js`
   ```js
   {
     asset:      { route: (id) => `/inventory/${encodeURIComponent(id)}`, icon: ServerIcon, label: 'Asset' },
     threat:     { route: (id) => `/threats/${id}`, icon: AlertIcon, label: 'Threat' },
     finding:    { route: (engine, id) => `/finding/${engine}/${id}`, icon: ShieldIcon, label: 'Finding' },
     technique:  { route: (id) => `/threats/technique/${id}`, icon: MitreIcon, label: 'Technique' },
     identity:   { route: (id) => `/ciem/identity/${encodeURIComponent(id)}`, icon: UserIcon, label: 'Identity' },
     scenario:   { route: (id) => `/risk/scenario/${id}`, icon: GaugeIcon, label: 'Scenario' },
     framework:  { route: (id) => `/compliance/${id}`, icon: BookIcon, label: 'Framework' },
   }
   ```
3. Props API:
   ```jsx
   <PivotLink to="finding" engine="iam" id={findingId} provider={provider} severity="high" label={ruleName}>{children}</PivotLink>
   ```
4. Hover tooltip with engine, severity, last_seen_at (optional prefetch via `onMouseEnter`).
5. Telemetry hook: call existing `trackEvent('pivot_click', { from, to, entity, id })`.
6. Storybook stories: every entity type, every severity, truncated text, RTL.
7. Provider scoping: `provider` prop passed through to detail routes that need it.

## Acceptance criteria
- [ ] Renders `<a href={...}>` — verified via DOM snapshot
- [ ] Middle-click opens new tab; right-click → copy link → paste → renders correct page
- [ ] Hover tooltip shows engine + severity + entity label
- [ ] All 7 entity types registered and routable
- [ ] Truncates long ids with title attribute = full id
- [ ] Zero new fetch calls on page load (prefetch only on hover)
- [ ] Storybook covers all states; snapshots checked in
- [ ] Component < 200 LOC, no engine-specific logic inside

## Dependencies
- Blocks: JNY-08, JNY-11, JNY-12
- Blocked by: JNY-05 (finding route exists), JNY-04 (deploy)

## Constitution check
- One primitive, no per-engine duplication.
- No BFF fallback — link target either exists or 404 (handled by JNY-05/06).
- Multi-cloud — `provider` flows through.

## Out of scope
- Permission-aware hiding (lower-role users still see the link, target page enforces auth).
- Fancy preview cards on hover (basic tooltip only).
- Bulk-pivot primitives.

## Files touched (estimate)
- `frontend/src/components/shared/PivotLink.jsx` — new
- `frontend/src/components/shared/pivotEntityRegistry.js` — new
- `frontend/src/components/shared/PivotLink.stories.jsx` — storybook
- `frontend/src/components/shared/__tests__/PivotLink.test.jsx` — unit
- `.claude/documentation/contracts/pivot-link-contract.md` — component contract for JNY-08 reviewers

## Test plan
- Unit: every entity type renders correct href; `provider` is passed; severity class applied
- UI smoke: place in storybook, screenshot diff
- Accessibility: keyboard navigation works; aria-label populated
- Telemetry: click fires `trackEvent` exactly once
