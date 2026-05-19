# JNY-14: UI ↔ BFF contract diff (Layer 3) + CI gate (Layer 4)

## Track
Investigation Journey Unification — Phase H

## Priority
P1 — This is the layer that catches the silent killer: UI reads `data.attackPath.steps[0].technique` while BFF returns `mitre_technique`. Without it, JNY-13 only validates that the BFF is internally consistent, not that the UI agrees.

## Status
done — extract-bff-fields.js AST walker, test_ui_bff_contract.py diff gate, contract.yml required CI check on main, 7 views modelled

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | — | — |
| UI / BFF / Gateway dev | `cspm-ui-dev` + `cspm-bff-dev` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-architect` (A) + `bmad-dev` | R/A |
| QA | `bmad-qa` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §2.2 the recurring failure mode (informally "F4 silent contract drift") is that frontend pages access response paths that the BFF stopped returning, and nobody notices until a manual click finds a blank tab. ADR §3.1.b Layer 3 prescribes an AST-based diff: extract every property access in every `page.jsx` against the Pydantic schema set produced by JNY-13. Layer 4 elevates that diff into a CI gate.

## What to build

1. AST extractor — `/Users/apple/Desktop/threat-engine/scripts/extract-bff-fields.js`
   - Babel parser walks `frontend/src/app/**/page.jsx` (+ co-located components imported by them).
   - For each call to `fetchView('<page>')` (or fetch to `/gateway/api/v1/views/...`), capture the variable bound to the response and record every `MemberExpression` chain on it.
   - Output: `tests/contracts/ui-consumed-fields.json` keyed by view name → flat dot-paths (`["assets[].resource_uid", "assets[].provider", "blast_radius.affected_count", ...]`).
2. Schema flattener (Python) — within `tests/contracts/test_ui_bff_contract.py`:
   - Import every Pydantic model from `shared/api_gateway/bff/_schemas.py`, recursively walk fields, emit the same dot-path form.
   - Diff the two sets per view; assert UI-consumed ⊆ BFF-provided.
   - On mismatch, print a precise table: `view, missing_path, page_file:line, suggested_field`.
3. Optional codegen — `npm run gen:bff-types` driving `openapi-typescript` against `/gateway/openapi.json` → `frontend/src/types/bff.ts`. Encourages but does not yet require the UI to import these types.
4. CI gate (Layer 4) — `.github/workflows/contract.yml`:
   - Run `node scripts/extract-bff-fields.js` then `pytest tests/contracts/`.
   - Required check on `main` and PRs that touch `frontend/src/app/**/page.jsx` or `shared/api_gateway/bff/**`.
   - Fails the build on any unexpected field.
5. Initial fix-up commit — drive the diff to zero on `main` before flipping the gate to required (record the baseline fixes in this story's PR).

## Acceptance criteria
- [ ] `scripts/extract-bff-fields.js` runs cleanly on the current `frontend/src/app/` and emits at least 14 page entries (one per shipped engine page).
- [ ] `tests/contracts/test_ui_bff_contract.py` passes with diff == ∅ across all views.
- [ ] CI workflow `contract.yml` is registered as a required check on `main`.
- [ ] A deliberate breakage (rename one BFF field on a throwaway branch) fails the gate with a readable error pointing at the consuming page file and line.
- [ ] `frontend/src/types/bff.ts` is generated and committed (or `.gitignore`'d with a pre-commit hook regenerating it — pick one and document).
- [ ] Diff covers all 53 BFF views (matches JNY-13's count).
- [ ] Baseline run on `main` after fix-ups: 0 unexpected fields.
- [ ] Documentation note added to `.claude/documentation/CSPM_CONSTITUTION.md` § testing pointing at this gate (full text added in JNY-18).

## Dependencies
- Blocks: JNY-18 (constitution amendment cites this gate).
- Blocked by: JNY-13 (needs the Pydantic schema set).

## Constitution check
- DB-first: this gate enforces that the UI reads only what the BFF (and ultimately the DB) actually provides.
- No BFF fallbacks: any UI access to a missing field becomes a build failure, not a runtime undefined-shaped hole.

## Out of scope
- Engine-side direct-fetch diff (JNY-16).
- Migrating the four direct-engine bypasses (JNY-17).
- Type-tightening every UI prop (only consumed paths are diffed; component props are out of scope).

## Files touched (estimate)
- `scripts/extract-bff-fields.js` — new (~250 lines, Babel)
- `scripts/package.json` (or root) — add `@babel/parser`, `@babel/traverse` devDeps
- `tests/contracts/test_ui_bff_contract.py` — new
- `tests/contracts/ui-consumed-fields.json` — generated artifact (committed for review diffs)
- `frontend/src/types/bff.ts` — generated
- `frontend/package.json` — add `gen:bff-types` script + `openapi-typescript` devDep
- `.github/workflows/contract.yml` — new

## Test plan
- Unit: AST extractor tested on a fixture page.jsx with known property chains.
- Integration: full repo run produces zero diff on green main.
- Negative: rename a BFF field locally → gate fails with line-accurate error.
- Regression: add a new BFF view with a new page → both sides update or build fails.
- Performance: full extract + diff completes in < 30 s.
