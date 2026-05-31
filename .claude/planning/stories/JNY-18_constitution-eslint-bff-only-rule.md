# JNY-18: Constitution §UI-Backend amendment + ESLint BFF-only rule

## Track
Investigation Journey Unification — Phase H

## Priority
P2 — Codifies the rule that the rest of Phase H enforces. Without this gate, future PRs can re-introduce the same bypasses we just removed in JNY-17.

## Status
done — .eslintrc.json no-direct-engine-fetch rule (warn, flips to error after deferred bypasses migrate), allowed-bypasses.js allowlist, CSPM_CONSTITUTION.md §4.5 UI-Backend Contract section

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | — | — |
| UI / BFF / Gateway dev | `cspm-standards-guardian` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-architect` | A |
| QA | `bmad-qa` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
ADR §3.1.c proposes the §UI-Backend Contract amendment to `.claude/documentation/CSPM_CONSTITUTION.md` and an ESLint rule that fails the build when frontend code fetches engine paths outside the allow-list. With JNY-17 having removed the four migratable bypasses, the residual allow-list is small: gateway BFF, gateway asset-context, the auth handshake, and any documented direct bypass (e.g. agent bootstrap, Stripe webhook surface). This is the story that closes the loop — make the constitution authoritative and make ESLint the cop.

This addresses the "BFF-only constitution gap" (ADR §2.2): until now there has been no machine-checked rule preventing future direct-engine fetches from creeping back into the UI.

## What to build

1. Amend `.claude/documentation/CSPM_CONSTITUTION.md` — add a `§UI-Backend Contract` section using the verbatim text from ADR §3.1.c:
   - Allowed origins: gateway NLB only.
   - Allowed paths: `/gateway/api/v1/views/*`, `/gateway/api/v1/asset-context/*`, `/cspm/api/auth/*` (auth handshake — login/logout/me/csrf/SSO callbacks only), paths in `ALLOWED_DIRECT_ENGINE_BYPASSES`.
   - Adding any new direct-engine bypass requires a `bmad-architect`-signed ADR.
   - ESLint must fail the build on any non-allowed engine prefix fetch.
2. Create `frontend/src/lib/allowed-bypasses.js`:
   ```js
   export const ALLOWED_DIRECT_ENGINE_BYPASSES = [
     '/cspm/api/auth/login',
     '/cspm/api/auth/logout',
     '/cspm/api/auth/me',
     '/cspm/api/auth/csrf',
     '/cspm/api/auth/google/',
     '/cspm/api/auth/saml/',
     '/cspm/api/auth/register',
     '/cspm/api/auth/invite/accept',
     '/api/v1/agents/bootstrap',
     // Stripe webhook is server-to-server; not fetched from UI.
   ];
   ```
3. ESLint enforcement — pick the simpler of two implementations:
   - (a) Custom rule under `frontend/eslint-rules/no-direct-engine-fetch.js` that walks `CallExpression`s for `fetch`, `axios.get`, etc., extracts the URL literal, and fails if the prefix matches `/onboarding/`, `/vulnerability/`, `/sbom/`, `/<engine>/api/` and is not in `ALLOWED_DIRECT_ENGINE_BYPASSES`.
   - (b) `no-restricted-syntax` config with regex selectors targeting `fetch('/onboarding/...')` etc. — simpler, less precise.
   Default to (a).
4. Wire into `frontend/.eslintrc.js` (or `eslint.config.js`) and ensure `npm run lint` runs in CI on every frontend PR.
5. Documentation cross-links — point `CSPM_CONSTITUTION.md` at `.claude/documentation/ALLOWED_BYPASSES.md` (from JNY-16) for the canonical list of currently-permitted bypasses with justifications.

## Acceptance criteria
- [ ] `.claude/documentation/CSPM_CONSTITUTION.md` contains a new `§UI-Backend Contract` section matching ADR §3.1.c.
- [ ] `frontend/src/lib/allowed-bypasses.js` exists and is the single source of truth for the allow-list.
- [ ] ESLint rule (custom or restricted-syntax) is registered in the frontend lint config.
- [ ] `npm run lint` flags a deliberate violation: adding `fetch('/onboarding/api/v1/cloud-accounts')` to any page.jsx fails the lint.
- [ ] `npm run lint` passes on the post-JNY-17 baseline (no allow-list violations).
- [ ] CI gates frontend PRs on `npm run lint`.
- [ ] `cspm-standards-guardian` review on the constitution diff is recorded in PR.
- [ ] `bmad-architect` signs off the constitution amendment.

## Dependencies
- Blocks: nothing (closing story for Phase H).
- Blocked by: JNY-17 (allow-list is meaningful only after the four bypasses are gone), JNY-16 (`ALLOWED_BYPASSES.md` is the documentation reference).

## Constitution check
- This story IS a constitution amendment. Self-checks: amendment is concrete, machine-enforceable, and includes an escape hatch (ADR-signed addition to allow-list).
- BFF-only: codified.
- No BFF fallbacks: cross-referenced; constitution already forbids BFF fallbacks separately, this story complements that.

## Out of scope
- Migrating any new bypass — that is by-design a future-ADR action.
- Tightening the auth handshake path list further (handled in onboarding/auth sprint per `MEMORY.md`).
- Replacing ESLint with a different linter.

## Files touched (estimate)
- `.claude/documentation/CSPM_CONSTITUTION.md` — append new section
- `.claude/documentation/ALLOWED_BYPASSES.md` — link from constitution
- `frontend/src/lib/allowed-bypasses.js` — new
- `frontend/eslint-rules/no-direct-engine-fetch.js` — new (option a)
- `frontend/.eslintrc.js` (or `eslint.config.js`) — register rule
- `frontend/package.json` — `lint` script if missing
- `.github/workflows/ci.yml` — ensure `npm run lint` runs on frontend PRs

## Test plan
- Unit: ESLint rule unit-tested with `RuleTester` against pass / fail fixtures (`/gateway/api/v1/views/x` ✅, `/onboarding/api/v1/cloud-accounts` ❌, `/cspm/api/auth/login` ✅, `/vulnerability/api/v1/scans` ❌).
- Integration: full `npm run lint` clean on `main`; deliberate violation branch fails CI.
- Documentation: verify constitution renders cleanly and cross-links resolve.
- Regression: removing an entry from `allowed-bypasses.js` should immediately fail lint on any page that depends on it — confirms the allow-list is wired.
- Governance: PR template prompts authors to file an ADR before adding to `ALLOWED_DIRECT_ENGINE_BYPASSES`.
