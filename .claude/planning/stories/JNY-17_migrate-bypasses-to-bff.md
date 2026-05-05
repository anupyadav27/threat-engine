# JNY-17: Migrate 4 direct-engine bypasses to BFF views

## Track
Investigation Journey Unification — Phase H

## Priority
P1 — Closes the architectural divergence flagged in ADR §3.1.c. Each bypass is a permanent silent-drift surface and a deviation from the BFF-only constitution.

## Status
draft

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | 4 sub-tasks (one per bypass — see Sub-tasks) | R |
| UI / BFF / Gateway dev | `cspm-ui-dev` + `cspm-bff-dev` | R |
| Security architect (design) | `bmad-security-architect` | A |
| Security reviewer (code) | `cspm-security-reviewer` + `bmad-security-reviewer` | R |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-3 (auth-termination gate, end of D14) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §3.1.c verdict table, four current bypasses must move behind BFF views:

| Current bypass | Target BFF view |
|---|---|
| `/onboarding/api/v1/cloud-accounts` | `GET /api/v1/views/onboarding/cloud_accounts` |
| `/vulnerability/api/v1/scans`, `/vulnerabilities`, `/reports`, `/agents` | `/api/v1/views/vulnerability/{scans,vulnerabilities,reports,agents}` |
| `/sbom/api/v1/*` | `/api/v1/views/sbom/*` |
| (4th if surfaced by JNY-16 audit) | TBD — if JNY-16 finds none, this row is dropped from scope |

Keep (ADR §3.1.c): `/cspm/api/auth/*` (login, logout, me, csrf, SSO callbacks ONLY), `/api/v1/agents/bootstrap` (public bootstrap), Stripe webhook.

The "API-key auth" excuse for the vulnerability bypass is a deployment artifact — the gateway already forwards `Authorization: Bearer` headers via `_fetch_engine`, so terminating auth at the gateway and proxying through BFF is mechanically straightforward.

## What to build

1. New BFF view files (one per bypass group):
   - `shared/api_gateway/bff/onboarding.py` — `cloud_accounts` view (may extend existing module).
   - `shared/api_gateway/bff/vulnerability.py` — `scans`, `vulnerabilities`, `reports`, `agents` views.
   - `shared/api_gateway/bff/sbom.py` — proxy views matching the engine routes the UI actually consumes (use JNY-16 consumed-paths JSON to avoid over-building).
2. Each view uses the standard `_fetch_engine(...)` helper, attaches `Authorization: Bearer <gateway-issued-token>`, and declares a `response_model=...` Pydantic schema (extending JNY-13's `_schemas.py`).
3. UI updates — replace each bypass call with `fetchView('<page>')`:
   - `frontend/src/app/onboarding/**/page.jsx` — cloud accounts list/detail.
   - `frontend/src/app/vulnerability/**/page.jsx` — scans, vulnerabilities, reports, agents pages.
   - `frontend/src/app/sbom/**/page.jsx` (if present) — same.
4. Remove rewrites from `frontend/next.config.js` for the four bypasses. Keepers (`/cspm/api/auth/*`, `/api/v1/agents/bootstrap`, Stripe) untouched.
5. Update `frontend/src/lib/allowed-bypasses.js` (introduced in JNY-18) — these four are no longer on the list.
6. Update `.claude/documentation/ALLOWED_BYPASSES.md` (from JNY-16) to mark the four entries as MIGRATED with date.

## Sub-tasks

Per [ADR §4.3.2](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#432-multi-engine-sub-task-breakdown), one sub-task per bypass migration.

| Sub | Bypass | Engine agent | UI/BFF lead |
|-----|--------|--------------|-------------|
| JNY-17.1 | `/onboarding/api/v1/cloud-accounts` | `onboarding` (R) | `cspm-bff-dev` + `cspm-ui-dev` (R) |
| JNY-17.2 | `/vulnerability/api/v1/*` | `vulnerability` (R) | `cspm-bff-dev` + `cspm-ui-dev` (R) |
| JNY-17.3 | `/sbom/api/v1/*` | `vulnerability` (R) | `cspm-bff-dev` + `cspm-ui-dev` (R) |
| JNY-17.4 | Lock-down `/cspm/api/auth/*` to whitelist | `cspm-django-engineer` (R) | `cspm-gateway-dev` (R) |

## Acceptance criteria
- [ ] All four bypass entries are removed from `frontend/next.config.js` rewrites.
- [ ] No `page.jsx` under `frontend/src/app/{onboarding,vulnerability,sbom}/**` calls a path starting with `/onboarding/api/`, `/vulnerability/api/`, or `/sbom/api/` — grep clean.
- [ ] New BFF views exist with `response_model=` and pass JNY-13's matrix.
- [ ] JNY-14 contract diff is green (UI-consumed paths ⊆ new BFF Pydantic schema).
- [ ] Auth handshake (`/cspm/api/auth/*`), agent bootstrap (`/api/v1/agents/bootstrap`), and Stripe webhook all still work — smoke-tested.
- [ ] Manual smoke: cloud-accounts list, vulnerability scans list, vulnerabilities list, reports, agents list all render with real data via the new BFF endpoints.
- [ ] Gateway image rebuilt + deployed; tag recorded in `MEMORY.md` image tag table.
- [ ] Frontend image rebuilt + deployed; tag recorded.

## Dependencies
- Blocks: JNY-18 (ESLint rule's allow-list shrinks once these four are gone).
- Blocked by: JNY-13 (BFF schema infra), JNY-15 (engine schemas for onboarding + vulnerability), JNY-16 (audit confirms the bypass set).

## Constitution check
- BFF-only contract (ADR §3.1.c): this is the story that closes it for the four migratable paths.
- No BFF fallbacks: new views proxy and validate, no merging or papering over engine gaps.
- DB-first: views read engine outputs that themselves read DB; no synthetic shapes.
- Standard columns preserved end-to-end where the engine returns finding rows.

## Out of scope
- Re-architecting the vulnerability engine's API-key auth (gateway-issued bearer is sufficient).
- Migrating the keep-list (auth handshake, agent bootstrap, Stripe webhook).
- Adding new functionality — this is a transport/architecture migration only.

## Files touched (estimate)
- `shared/api_gateway/bff/onboarding.py` — new or extended (+1 view)
- `shared/api_gateway/bff/vulnerability.py` — new or extended (+4 views)
- `shared/api_gateway/bff/sbom.py` — new (paths driven by JNY-16 audit)
- `shared/api_gateway/bff/_schemas.py` — extended with new Pydantic models
- `frontend/next.config.js` — remove 4 rewrite blocks
- `frontend/src/app/onboarding/**/page.jsx` — switch to `fetchView`
- `frontend/src/app/vulnerability/**/page.jsx` — switch to `fetchView` (scans, vulnerabilities, reports, agents)
- `frontend/src/app/sbom/**/page.jsx` — switch to `fetchView` (if applicable)
- `frontend/src/lib/allowed-bypasses.js` — remove 4 entries
- `.claude/documentation/ALLOWED_BYPASSES.md` — mark MIGRATED
- Image tag rows in `MEMORY.md`

## Test plan
- Integration: BFF matrix (JNY-13) covers the new views; engine matrix (JNY-15) untouched.
- Contract: JNY-14 diff is green post-migration.
- Smoke: each migrated UI surface (cloud-accounts, scans, vulnerabilities, reports, agents, sbom views) loads real data and renders without console errors.
- Regression: `/cspm/api/auth/login` flow, `/api/v1/agents/bootstrap`, and Stripe webhook still function (record-only smoke).
- Security: gateway-issued bearer is correctly forwarded; engine still rejects unauthenticated calls when hit directly bypassing gateway.
- Deploy: cspm-frontend + api-gateway image tags rolled out cleanly per `cspm-deploy` skill.
