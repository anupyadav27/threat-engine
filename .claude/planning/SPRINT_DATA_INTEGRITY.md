# Sprint: Data Integrity & Auth Scope

**Sprint Goal:** Eliminate the "no data showing in UI" bug class by fixing tenant ID routing at every layer of the stack — from session creation through auth context, BFF scoping, field normalization, DB schema alignment, and UI empty state handling.

**Duration:** 2 weeks (10 working days)
**Team:** 2-3 engineers in parallel (1 backend, 1 full-stack, 1 QA/analyst)
**Priority:** This sprint unblocks customer-facing reliability. All stories before Track 4 are P0/P1.

---

## Sprint Stories

| ID | Title | Track | Days | Depends On | Priority |
|----|-------|-------|------|------------|----------|
| DI-01 | Header: "Workspace" → "Tenant" terminology | 1 | 0.5 | — | P0 |
| DI-02 | AuthContext: Add engine_tenant_id as first-class field | 1 | 1 | — | P0 |
| DI-03 | Django: UserAccountAccess model + migration | 1 | 1 | DI-02 | P1 |
| DI-04 | BFF: resolve_tenant_id() + account_filter() helpers | 1 | 1 | DI-02 | P0 |
| DI-05 | BFF: Remove tenant_id Query param — Batch 1 (9 views) | 1 | 1 | DI-04 | P0 |
| DI-06 | BFF: Remove tenant_id Query param — Batch 2 (25 views) | 1 | 1 | DI-04 | P0 |
| DI-07 | Frontend: Remove manual tenant_id passing | 1 | 0.5 | DI-05, DI-06 | P1 |
| DI-08 | BFF: Contract tests (one per view, 401 tests) | 1 | 1 | DI-05, DI-06 | P1 |
| DI-09 | BFF: TypedDict schemas for all view responses | 2 | 1 | — | P1 |
| DI-10 | BFF: Fix field name mismatches (snake → camelCase) | 2 | 1 | DI-09 | P0 |
| DI-11 | BFF: Missing fields audit + fixes | 2 | 2 | DI-09 | P1 |
| DI-12 | BFF: Threat sub-pages contract audit (9 views) | 2 | 1.5 | DI-09 | P1 |
| DI-13 | DB: Automated schema gap report script | 3 | 1 | — | P1 |
| DI-14 | DB: Schema migrations from gap report | 3 | 1 | DI-13 | P1 |
| DI-15 | Threat: Backfill mitre_tactics from rule_metadata | 3 | 1 | DI-13 | P0 |
| DI-16 | UI: Empty state audit — classify all "no data" occurrences | 4 | 1.5 | — | P1 |
| DI-17 | UI: Fix wrong queries, missing routes, empty state copy | 4 | 1 | DI-16 | P1 |

**Total: 17 stories, ~16.5 engineer-days**

---

## Dependency Graph

```
DI-01 (standalone, 0.5d)

DI-02 ──────────────────────────────────────────┐
  └── DI-03 (1d, can trail DI-02 by 1d)         │
  └── DI-04 ──────────────────────────────────── │
        └── DI-05 (parallel with DI-06) ─────── │
        └── DI-06 (parallel with DI-05) ─────── │
              └── DI-07 (after both deployed)    │
              └── DI-08 (after both deployed)    │
                                                 │
DI-09 (standalone) ──────────────────────────── │
  └── DI-10 (1d) ──────────────────────────── ──┘
  └── DI-11 (2d)
  └── DI-12 (1.5d)

DI-13 (standalone) ─────────────────────────────
  └── DI-14 (1d)
  └── DI-15 (1d, parallel with DI-14) ← P0

DI-16 (standalone, parallel with tracks 1-3) ───
  └── DI-17 (1d)
```

---

## Parallel Work Streams

### Week 1 (Days 1-5)

**Engineer A (Backend/Platform):**
- Day 1: DI-02 (AuthContext engine_tenant_id)
- Day 2: DI-03 (UserAccountAccess model) + DI-04 (BFF helpers)
- Days 3-4: DI-05 (BFF Batch 1 — 9 views)
- Day 5: DI-13 (DB gap report script)

**Engineer B (Full-stack):**
- Day 1: DI-01 (header fix) + DI-09 (TypedDict schemas)
- Days 2-3: DI-10 (field mismatch fixes) + DI-06 (BFF Batch 2 — 25 views)
- Day 4: DI-16 (empty state audit)
- Day 5: DI-15 (MITRE backfill — run the script)

### Week 2 (Days 6-10)

**Engineer A:**
- Days 6-7: DI-11 (missing fields audit + fixes)
- Day 8: DI-07 (frontend tenant_id removal) + DI-14 (DB migrations)
- Days 9-10: DI-08 (contract tests)

**Engineer B:**
- Day 6: DI-12 (threat sub-pages audit)
- Days 7-8: DI-12 fixes + DI-17 (empty state fixes)
- Days 9-10: QA validation, contract test runs, manual walkthrough

---

## Skills Map

| Skills | Stories |
|--------|---------|
| Django ORM, models, migrations | DI-02 (partial), DI-03 |
| FastAPI middleware, request.state | DI-04 |
| Python BFF refactor (bulk edit) | DI-05, DI-06 |
| React / Next.js frontend | DI-01, DI-07, DI-17 |
| Python TypedDict / API schema design | DI-09, DI-10 |
| Full-stack data tracing (JSX → BFF → engine) | DI-11, DI-12 |
| SQL / PostgreSQL (information_schema, migrations) | DI-13, DI-14 |
| Engine data pipeline knowledge (threat engine) | DI-15 |
| QA / product sense (empty state classification) | DI-16 |
| pytest / integration testing | DI-08 |

---

## Key Files Reference

### Auth Layer
- `/Users/apple/Desktop/threat-engine/shared/auth/core/models.py` — AuthContext dataclass
- `/Users/apple/Desktop/threat-engine/shared/auth/fastapi/middleware.py` — AuthMiddleware (gateway)
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/utils/auth_utils.py` — compute_auth_caches()
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/models.py` — UserSessions (scope_cache field)
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/tenant_management/models.py` — Tenants, TenantUsers

### BFF Layer
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_shared.py` — fetch_many, ENGINE_URLS
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_transforms.py` — normalize_threat(), etc.
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/__init__.py` — router registration
- All 40 view files in `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/`

### Frontend
- `/Users/apple/Desktop/threat-engine/frontend/src/lib/use-view-fetch.js` — useViewFetch hook
- `/Users/apple/Desktop/threat-engine/frontend/src/lib/auth-context.js` — AuthProvider, selectedTenant
- `/Users/apple/Desktop/threat-engine/frontend/src/lib/tenant-context.js` — TenantProvider
- `/Users/apple/Desktop/threat-engine/frontend/src/components/layout/Header.jsx` — tenant switcher UI
- `/Users/apple/Desktop/threat-engine/frontend/src/lib/api.js` — fetchView, getFromEngine

### Data
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/` — existing migration files
- `/Users/apple/Desktop/threat-engine/scripts/` — utility scripts (new files go here)

---

## Security Notes for This Sprint

Every story in Track 1 touches the auth boundary. Review checklist for DI-02, DI-04, DI-05, DI-06:

- [ ] STRIDE: `tenant_id` from query string was a Tampering threat. DI-04/05/06 eliminate it.
- [ ] OWASP SAMM: Moving to session-derived tenant_id is an Implementation Security Practice improvement (horizontal privilege escalation prevention).
- [ ] Data residency: `engine_tenant_id` resolution happens server-side — no client input propagates into DB queries.
- [ ] `DEV_BYPASS_AUTH` must NOT be re-added under any circumstances (per RBAC constitution).

---

## Definition of Done for the Sprint

**Sprint is complete when ALL of these are true:**

### Track 1 — Auth Context + Tenant Scoping
- [ ] `AuthContext.engine_tenant_id` populated on every authenticated request
- [ ] Zero BFF views accept `tenant_id` as a query string (except `platform_admin.py`)
- [ ] `useViewFetch` does not pass `tenant_id` in params
- [ ] `UserAccountAccess` model and migration deployed
- [ ] Contract tests confirm 401 for unauthenticated requests to all views

### Track 2 — BFF Contract Audit
- [ ] TypedDict schemas exist for all 15+ views
- [ ] All identified camelCase field name mismatches fixed
- [ ] Threat page MITRE tab shows non-empty data (mitreTactics populated)
- [ ] Risk page shows riskScore values (not zero from camelCase mismatch)
- [ ] All 9 threat sub-views audited and gaps fixed or filed

### Track 3 — DB Schema Alignment
- [ ] Gap report script run against all 5 major engine DBs
- [ ] All "MISSING column" gaps have migrations
- [ ] `threat_detections.mitre_tactics` backfill complete — count > 0 for my-tenant
- [ ] DI-13 script run post-migrations shows zero "MISSING" for updated tables

### Track 4 — Empty State Audit
- [ ] Classification table covering 30+ components committed
- [ ] All Class C (wrong query) bugs fixed
- [ ] All Class D (missing route) bugs fixed
- [ ] Class A empty states use honest copy (not generic "No data")
- [ ] No component shows empty state when data exists in the DB

---

## Risk Log

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Old sessions break after DI-02 (scope_cache change) | Low | Medium | Graceful fallback: old sessions use tenant_ids[0] until re-login |
| DI-05/06 BFF change breaks frontend before DI-07 | Low | Low | BFF ignores extra query params; old tenant_id param is harmless until removed |
| MITRE backfill (DI-15) takes too long on large tenant | Medium | Low | Run with LIMIT 1000 in batches; add WHERE clause to limit rows |
| DI-13 gap report can't connect to engine pod | Medium | Low | Use kubectl exec fallback; document manual SQL alternative |
| Track 2 audit finds 20+ missing fields (scope creep) | Medium | High | Timebox audit to 1 day; file overflow as separate stories, not blocking sprint |

---

## Post-Sprint Tasks (not in scope, file separately)
- Account-level API for granting/revoking `UserAccountAccess` (admin UI)
- Selected-tenant persistence: switchTenant() should POST to backend to update scope_cache (not just sessionStorage)
- Cross-tenant query API for platform_admin role (scoped admin dashboard)
- Data residency EU tag on engine_tenant_id routing
