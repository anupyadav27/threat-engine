# JNY-10: CIEM Stage 2 empty-data root cause + actor_principal normalization

## Track
Investigation Journey Unification — Phase D

## Priority
P1 — CIEM `/ciem/identity/[principal]` Stage 2 returns empty findings/hourly/dow for principals listed in Stage 1 (G-6).

## Status
done — root cause: path param {principal_encoded}/hourly-activity broke on slashes in IAM ARNs (FastAPI decoded %2F). Fix: (1) CDR engine endpoint changed to query param /hourly-activity?actor_principal=...; (2) BFF cdr_identity.py updated to call new endpoint; (3) actor_principal LIKE→exact match; (4) identity lookup is now case-insensitive

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | `ciem` | R |
| UI / BFF / Gateway dev | — | — |
| Security architect (design) | — | — |
| Security reviewer (code) | `cspm-security-reviewer` + `bmad-security-reviewer` | R |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | — | — |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §2.2 G-6, Stage 1 lists principals (e.g. `arn:aws:iam::...:user/foo`) but Stage 2's profile endpoint returns empty findings/heatmap. Likely root cause: the value used as `actor_principal` in the listing query differs in format/casing from the WHERE clause in the Stage 2 endpoint (e.g. ARN vs username, or trailing whitespace, or normalized lowercase). Per Sprint §6, this story is time-boxed to 3 days; if root cause is in the writer, spin off a CIEM-NN follow-up and ship a Stage-2-empty workaround.

## What to build
1. Investigate: dump `SELECT DISTINCT actor_principal FROM ciem_findings WHERE tenant_id = $1` and compare with the values returned by Stage 1 listing.
2. Identify normalization mismatch (likely candidates: ARN vs friendly name; case; URL-encoding in the path param; trailing whitespace).
3. Pick a canonical form for `actor_principal` (recommend: full ARN/principal-id as written by the source CSP) and normalize at:
   - Writer: `engines/ciem/ciem_engine/evaluator/*.py`
   - Reader (BFF): `shared/api_gateway/bff/views/ciem_identity.py`
   - URL handler: decode `[principal]` path param exactly once at the route
4. Add a test fixture asserting Stage 1 listing principal == Stage 2 lookup principal byte-for-byte.
5. If root-cause is upstream of CIEM (CloudTrail enrichment or actor_principal_type empty issue from CIEM-00) — document and spin off `STORY-CIEM-NN`.

## Acceptance criteria
- [ ] At least one Stage-1 principal returns non-empty findings/hourly/dow on Stage 2 in production data
- [ ] Test fixture: take a principal returned by Stage 1, request Stage 2, assert findings_count > 0
- [ ] Documented normalization rule (canonical form) added to `engines/ciem/README.md` or schema header
- [ ] No regression in correlation evaluator output
- [ ] If a deeper writer-side issue is found, follow-up story file created in `.claude/planning/stories/STORY-CIEM-NN_*.md`
- [ ] Browser network tab on `/ciem/identity/[principal]` shows 200 with non-empty payload
- [ ] strip_sensitive_fields still applied for auth_level >= 4 (regression check)

## Dependencies
- Blocks: sprint exit walk-through
- Blocked by: JNY-03 (auth must pass first), JNY-04 (deploy)

## Constitution check
- Tenant_id MANDATORY in every CIEM query.
- No BFF data merge to mask the issue (per `feedback_no_bff_fallbacks`).
- Standard columns retained — `actor_principal` is the column being normalized, not replaced.

## Out of scope
- Stage 3/4/5 of CIEM journey.
- New actor_principal_type values.
- Writer-pipeline rewrites (spin off STORY-CIEM-NN if hit).
- CIEM-00 contributing_steps work (separate story already exists).

## Files touched (estimate)
- `engines/ciem/ciem_engine/evaluator/correlation_evaluator.py` — normalize on write if needed
- `engines/ciem/ciem_engine/evaluator/baseline_evaluator.py` — same
- `engines/ciem/ciem_engine/evaluator/rule_evaluator.py` — same
- `shared/api_gateway/bff/views/ciem_identity.py` — normalize on lookup; URL-decode once
- `shared/api_gateway/bff/views/ciem_listing.py` — confirm same canonical form returned
- `engines/ciem/tests/test_actor_principal_normalization.py` — new
- `engines/ciem/README.md` — documented canonical form

## Test plan
- Unit: normalization function idempotent and case-stable
- BFF contract: Stage 1 principal piped through Stage 2 returns non-empty
- Security: cross-tenant principal lookup → empty (not 500); actor_ip stripped at auth_level >= 4
- E2E: live CIEM scan, pick principal from Stage 1 list, click → land on Stage 2 with data
