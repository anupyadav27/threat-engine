# JNY-16: Direct-engine UI bypass contract diff (Layer 3 extension)

## Track
Investigation Journey Unification — Phase H

## Priority
P2 — The four direct-engine bypasses (per ADR §3.1.c) are unprotected by the JNY-14 BFF diff. Until JNY-17 migrates them, this story is the safety net.

## Status
draft

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | `onboarding` + `vulnerability` + `cspm-django-engineer` | C |
| UI / BFF / Gateway dev | `cspm-ui-dev` + `cspm-bff-dev` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | — | — |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
ADR §3.1.c lists current direct-engine bypasses in `frontend/next.config.js`:
1. `/onboarding/api/v1/cloud-accounts` — to migrate.
2. `/vulnerability/api/v1/*` (scans, vulnerabilities, reports, agents) — to migrate.
3. `/sbom/api/v1/*` — to migrate.
4. (potential 4th surfaced during this story's audit; document if found, otherwise note "none").

Plus the keepers: `/cspm/api/auth/*`, `/api/v1/agents/bootstrap`, Stripe webhook — those don't need this gate (auth handshake / public bootstrap / signed webhook).

While migration (JNY-17) is in flight, the silent-drift gap on these paths is wider than on BFF paths because they bypass JNY-13 entirely. This story extends the JNY-14 AST extractor and contract diff to cover them, using the engine Pydantic schemas from JNY-15.

## What to build

1. Extend `scripts/extract-bff-fields.js` (from JNY-14):
   - Also detect fetches whose URL prefix matches `/onboarding/`, `/vulnerability/`, `/sbom/`.
   - Group consumed paths under a synthetic key `direct:<engine>:<route>` in the output JSON.
2. Extend `tests/contracts/test_ui_bff_contract.py` (or new sibling `test_ui_engine_contract.py`):
   - For each `direct:` entry, locate the matching engine Pydantic model from JNY-15 (`engines/<engine>/api/_schemas.py`), flatten dot-paths, diff.
3. Document the four bypasses in `.claude/documentation/ALLOWED_BYPASSES.md` (created here, used by JNY-18):
   - Path, justification (auth / deployment artifact / webhook), owning engine, consumed UI paths.
4. CI gate: existing `.github/workflows/contract.yml` picks up the new test file automatically; no infra change required.
5. Audit pass: walk `frontend/next.config.js` and the AST output once to confirm the bypass list. Record any found-but-undocumented bypass as a P1 follow-up before merging.

## Acceptance criteria
- [ ] Extractor identifies all direct-engine fetches in `frontend/src/app/**`.
- [ ] Contract diff covers each documented bypass: onboarding cloud_accounts, vulnerability (scans + vulnerabilities + reports + agents), sbom, +1 if found.
- [ ] `.claude/documentation/ALLOWED_BYPASSES.md` lists every bypass with engine schema link and consumed paths.
- [ ] A deliberate engine-side rename on a throwaway branch fails the gate with a readable error pointing at the consuming page.
- [ ] Zero unexpected fields on baseline `main`.
- [ ] Bypasses not on the allow-list cause the gate to fail (forces them through JNY-18 ESLint rule once shipped).
- [ ] Story ships even if JNY-15 is still finalizing engine schemas for non-bypass engines — diff only requires schemas for bypass engines (onboarding, vulnerability).

## Dependencies
- Blocks: JNY-17 (migration uses this story's audit as the canonical bypass list); JNY-18 (constitution allow-list cites the documentation file).
- Blocked by: JNY-14 (extractor base), JNY-15 (engine Pydantic schemas for onboarding + vulnerability at minimum).

## Constitution check
- BFF-only target architecture: this gate makes the cost of every additional bypass visible (more diff coverage required); aligns incentives toward JNY-17.
- No silent drift: closes the loophole that JNY-13/14 alone leave open.

## Out of scope
- Migrating bypasses to BFF (JNY-17).
- ESLint enforcement (JNY-18).
- Auth handshake paths and Stripe webhook (intentionally excluded per ADR §3.1.c keep-list).

## Files touched (estimate)
- `scripts/extract-bff-fields.js` — extend with direct-engine prefix matcher
- `tests/contracts/test_ui_engine_contract.py` — new (or extend `test_ui_bff_contract.py`)
- `.claude/documentation/ALLOWED_BYPASSES.md` — new
- `tests/contracts/ui-consumed-fields.json` — regenerated (now includes `direct:` keys)

## Test plan
- Unit: AST extractor unit tests cover each bypass URL pattern.
- Integration: full repo run shows zero diff against engine schemas for documented bypasses.
- Negative: rename a field in the onboarding `CloudAccountResponse` on a throwaway branch → gate fails with line-accurate error in the page that consumes it.
- Audit: confirm `next.config.js` rewrites and `frontend/src/app/**` fetches agree with `ALLOWED_BYPASSES.md`.
- Regression: adding a new direct-engine fetch without updating the allow-list fails the gate.
