# JNY-11: EngineShell + EmptyState + RefreshBus shared primitives

## Track
Investigation Journey Unification — Phase E

## Priority
P2/P3 cluster — addresses G-23 (refresh button repeated), G-24 (KPI strip + tab counts boilerplate), G-25 (no shared empty-state).

## Status
draft

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | — | — |
| UI / BFF / Gateway dev | `cspm-ui-dev` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-architect` + `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Every engine page today re-implements its own KPI strip, tab counts, refresh button, and empty state, producing 14 near-identical chunks of layout boilerplate (G-24/G-25) and inconsistent refresh semantics (G-23). This story extracts three shared primitives and migrates 2-3 engine pages onto them as proof; the rest follow in a later cleanup sprint.

## What to build
1. `/Users/apple/Desktop/threat-engine/frontend/src/components/shared/EngineShell.jsx` — slot-based layout: `<EngineShell title kpis tabs onRefresh>{children}</EngineShell>` with KPI strip on top, tab nav below, content area, single Refresh button.
2. `/Users/apple/Desktop/threat-engine/frontend/src/components/shared/EmptyState.jsx` — slot-based empty state with icon, headline, body, optional CTA. Used in any tab when `available: false` or `count: 0`.
3. `/Users/apple/Desktop/threat-engine/frontend/src/lib/refreshBus.js` — pub/sub bus so a single global `R` keypress or one Refresh button refetches every visible tab on the current page. Replaces ad-hoc `useState(refreshKey)` patterns.
4. Migrate 2 reference engine pages onto EngineShell (proof of pattern): pick low-risk pages (e.g. `encryption/page.jsx`, `ai-security/page.jsx`).
5. Storybook entries for each primitive.

## Acceptance criteria
- [ ] EngineShell exposes a stable contract (props + slots) documented in `pivot-link-contract.md` companion file
- [ ] EmptyState replaces inline empty-state divs in the 2 migrated pages
- [ ] RefreshBus: single Refresh button refetches every subscribed tab; keyboard shortcut `R` triggers refresh on current page
- [ ] No visual regression — pixel diff < 1% on the 2 migrated pages
- [ ] Storybook covers happy + empty + error states for each primitive
- [ ] Lighthouse score not lowered on migrated pages
- [ ] Other engine pages untouched (full rollout deferred to later sprint)

## Dependencies
- Blocks: future engine-page cleanup sprint (out of scope here)
- Blocked by: JNY-07 (PivotLink imported by EngineShell tab counts), JNY-04 (deploy)

## Constitution check
- UI competitive standards: consistent shell across engines.
- No-fallback: EmptyState surfaces `available: false` clearly, doesn't hide it.
- Multi-cloud agnostic.

## Out of scope
- Migrating all 14 engine pages (only 2 in this story).
- Theming/dark-mode redesign.
- Replacing existing dashboard cards on overview pages.

## Files touched (estimate)
- `frontend/src/components/shared/EngineShell.jsx` — new
- `frontend/src/components/shared/EmptyState.jsx` — new
- `frontend/src/lib/refreshBus.js` — new
- `frontend/src/components/shared/EngineShell.stories.jsx` — new
- `frontend/src/components/shared/EmptyState.stories.jsx` — new
- `frontend/src/app/encryption/page.jsx` — migrated
- `frontend/src/app/ai-security/page.jsx` — migrated
- `.claude/documentation/contracts/engine-shell-contract.md` — new

## Test plan
- Unit: EngineShell slots render in order; RefreshBus subscribe/unsubscribe leak-free
- UI smoke: migrated pages render identically; refresh button refetches data
- Accessibility: tab order preserved; aria-labels on buttons; keyboard shortcut documented
- Visual regression: snapshot diff on 2 migrated pages
