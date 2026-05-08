# STORY-ENG-PYDANTIC-COVERAGE — Engine Pydantic Adoption Tracker

## Track
Phase H follow-up — spawned by JNY-15.

## Priority
P2 — defense-in-depth contract typing on engine HTTP responses. Phase H ships smoke tests; per-engine Pydantic adoption is each engine team's responsibility.

## Status
draft (umbrella tracker)

## Coverage matrix (as of JNY-15 completion)

### Engines WITH `response_model=` (13)
- discoveries
- inventory
- check
- threat
- iam
- secops
- network-security
- ciem
- ai-security
- container-security
- dbsec
- vulnerability
- onboarding

### Engines WITHOUT (9 — file individual stories below)

| Engine | Lead agent | Story ID |
|---|---|---|
| compliance | `compliance` | STORY-ENG-PYDANTIC-COMPLIANCE |
| encryption | `encryption` | STORY-ENG-PYDANTIC-ENCRYPTION |
| risk | `risk` | STORY-ENG-PYDANTIC-RISK |
| rule | `cspm-rule-catalog-engineer` | STORY-ENG-PYDANTIC-RULE |
| cnapp | `cnapp` | STORY-ENG-PYDANTIC-CNAPP |
| cwpp | `cwpp` | STORY-ENG-PYDANTIC-CWPP |
| billing | `billing` | STORY-ENG-PYDANTIC-BILLING |
| platform-admin | `platform-admin` | STORY-ENG-PYDANTIC-PLATFORM-ADMIN |
| datasec | `datasec` | STORY-ENG-PYDANTIC-DATASEC |

## What each spin-off story does

For each engine without coverage:
1. Read `engines/<engine>/.../api_server.py` (or sub-routers)
2. For every `@app.get` / `@app.post` / `@router.*` decorator that returns a JSON response, add a Pydantic `response_model=`.
3. Add the response classes near the top of the file (or in a new `<engine>/_schemas.py`).
4. Match camelCase keys to the existing UI consumption (verify against frontend grep).
5. Add `Field(exclude=True)` for any `credential_*`, `secret_*`, `raw_event` fields per CSPM_CONSTITUTION §1.3a.

## Smoke tests (Phase H — DONE in JNY-15)

`tests/engines/test_engine_smoke.py` already runs ~27 black-box checks against the live cluster NLB. After each per-engine Pydantic story lands, extend the smoke test to assert response shape via the new model — tracked individually in each story.

## Out of scope for these spin-offs
- Engine refactoring beyond `response_model=` annotations
- Schema migrations
- New endpoints
