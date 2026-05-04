# Sprint Plan — Auth, Onboarding & Scheduling

**Date:** 2026-05-03  
**Architect sign-off:** Architecture complete (ARCHITECTURE-AUTH-ONBOARDING-SCHEDULING.md)  
**Security sign-off:** 12 BLOCKs mapped to stories (all covered)  
**Sprint order:** A → B → C → D (each sprint may start once its predecessor deploys)

---

## Summary

| Sprint | Focus | Stories | Points | Duration | Deploys |
|--------|-------|---------|--------|----------|---------|
| A | cspm DB Foundation | 3 | 5 | 1 week | cspm-backend image |
| B | Auth Security Fixes | 4 | 7 | 1.5 weeks | cspm-backend image |
| C | Onboarding Engine | 10 | 14 | 2.5 weeks | engine-onboarding image |
| D | Frontend Wizard + Django APIs | 12 | 17 | 3 weeks | frontend + cspm-backend images |
| **Total** | | **29** | **43** | **~8 weeks** | |

Points scale: XS=0.5, S=1, M=2, L=3, XL=5

---

## Sprint A — cspm DB Foundation

**Goal:** Apply the DB cleanup migration, update Django models and `provision_tenant_for_new_user()`, wire async Celery sync. All other sprints depend on A.

**Gate to start Sprint B:** Migration applied and verified. `customer_id` backfilled on all users and tenants. cspm-backend pod health-check green.

| Story ID | Title | Points | BLOCK | Depends On |
|----------|-------|--------|-------|------------|
| auth-A1 | Django migrations (cleanup + customer_id + group tables) | 2 | BLOCK-12 (partial) | none — first |
| auth-A2 | `provision_tenant_for_new_user()` replaces `provision_first_tenant()` | 2 | — | A1 |
| auth-A3 | Async Celery tenant sync + resync endpoint | 1 | BLOCK-12 | A2 |

**Risk:** backfill of `customer_id` on existing users/tenants must complete before B4 can enforce org boundary. Verify with: `SELECT COUNT(*) FROM user_auth_users WHERE customer_id IS NULL;` → 0

**Deployment:** Migration first (no code deploy). Verify backfill. Then deploy cspm-backend.

---

## Sprint B — Auth Security Fixes

**Goal:** Close all 7 BLOCK items in the Django platform layer. Deploy before Sprint C opens.

**Gate to start Sprint C:** B1+B2 deployed (any order). B3 deployed. B4 deployed (depends on A). cspm-backend pod health green.

| Story ID | Title | Points | BLOCK(s) | Depends On |
|----------|-------|--------|----------|------------|
| auth-B1 | Email enumeration fix + rate limiting + CAPTCHA | 1 | BLOCK-01, BLOCK-02 | none |
| auth-B2 | Google OAuth hd domain validation | 1 | BLOCK-03 | none |
| auth-B3 | TenantViewSet DRF auth + export filter + IDP rate limit | 2 | BLOCK-08, BLOCK-09, BLOCK-10 | B1 (throttle classes needed) |
| auth-B4 | org_admin org-boundary + remove developer bypass | 3 | BLOCK-07, BLOCK-11 | A1 (customer_id column must exist) |

**Risk:** B3 adds DRF `CookieTokenAuthentication` to `TenantViewSet`. Test all callers (frontend tenant switcher, Celery `sync_tenant_to_onboarding`) are sending the cookie. B4 filters tenants by `customer_id` — backfill from A must be complete.

**Deployment order:** B1+B2 can deploy in parallel. B3 after B1. B4 after A deploys.

---

## Sprint C — Onboarding Engine

**Goal:** Apply pending onboarding DB migration, add RBAC, fix scheduling gaps, add agent PKCE bootstrap. Engine gets a new image tag.

**Gate to start Sprint D:** C1 (migration) applied. C8 (auth middleware) deployed. D frontend stories can begin after A+C1+C8 are live.

| Story ID | Title | Points | Gap/BLOCK | Depends On |
|----------|-------|--------|-----------|------------|
| onboarding-C-1 | Apply account_type + agent_registrations migration | 1 | S-03 | none — first |
| onboarding-C-2 | Fix scan_runs vs scan_orchestration naming | 0.5 | bug fix | C1 |
| onboarding-C-3 | Auth middleware (BLOCK-05) + PATCH allow-list (BLOCK-06) | 1 | BLOCK-05, BLOCK-06 | none |
| onboarding-C-4 | PKCE agent bootstrap + heartbeat endpoint | 1.5 | BLOCK-04 | C1, C3 |
| onboarding-C-5 | account_type validation against tenant_type | 0.5 | validation | C1 |
| onboarding-C-6 | RBAC on schedule + cloud_account endpoints | 1 | S-01 | C3 |
| onboarding-C-7 | Ad-hoc scan endpoint (no schedule required) | 1 | S-02 | C6 |
| onboarding-C-8 | exclude_regions / include_regions on Schedule ORM | 1 | S-04 | C1 |
| onboarding-C-9 | Bulk run-all schedules endpoint | 1 | S-05 | C6 |
| onboarding-C-10 | Credential expiry Celery health-check task | 1 | S-06 | C1 |

**Total C points: 9.5 → round to 10**

**Risk:** C3 (auth middleware) must deploy before C6 (RBAC). Verify that the Argo pipeline callback and Celery `sync_tenant_to_onboarding` task authenticate correctly to the onboarding engine after C3 deploys.

**Deployment order:** C1 first. Then C3 (auth middleware). Then C4-C10 in any order.

---

## Sprint D — Frontend Wizard + Django APIs

**Goal:** Build the full onboarding wizard UI (catalog-driven), schedule management, agent install flow, user/group management pages.

| Story ID | Title | Points | Depends On |
|----------|-------|--------|------------|
| onboarding-D-1 | Group management API (Django) — create/read/update/delete groups | 2 | A1 (group tables) |
| onboarding-D-2 | User invite flow API (Django) — invite, accept, cross-org cap | 2 | A2 (customer_id on users/tenants) |
| onboarding-D-3 | Group access assignment API (Django) — assign groups to tenants/accounts | 1 | D1 |
| onboarding-D-4 | Org profile + tenant-type API (Django) — org profile read/update, tenant_type | 1 | A1 |
| onboarding-D-5 | Schedule CRUD API with region/service scope (Django BFF layer) | 1 | C6, C8 |
| onboarding-D-6 | Scan run history + re-run API (Django BFF layer) | 1 | C7 |
| onboarding-D-7 | Frontend: tenant-type selector + org/tenant switcher | 2 | A deploys |
| onboarding-D-8 | Frontend: onboarding wizard credential form (catalog-driven) | 3 | C1, D7 |
| onboarding-D-9 | Frontend: agent install flow (PKCE) UI | 2 | C4, D8 |
| onboarding-D-10 | Frontend: schedule modal + region/service scope selection | 2 | C6, C8, D8 |
| onboarding-D-11 | Frontend: run-now + bulk scan-all + scan progress page | 1 | C7, C9, D10 |
| onboarding-D-12 | Frontend: user/group management pages | 2 | D1, D2, D3 |

**Total D points: 20**

**Risk:** D8 (wizard credential form) is the longest frontend story — catalog YAML drives form field rendering. Start D7+D8 immediately after A+C1+C3 deploy. D9 (agent PKCE UI) depends on C4. D12 (group management) is the most complex Django view work.

**Deployment order:** D1-D6 (Django APIs) can deploy incrementally. D7-D12 ship as one frontend image build after all backend APIs are live.

---

## Dependency Graph

```
A1 ──► A2 ──► A3
 │              │
 │    B1 ──► B3 │
 │    B2        │
 └──────────► B4
              │
              ▼
    C1 ──► C3 ──► C6 ──► C7
    C1 ──► C4         ──► C9
    C1 ──► C5
    C1 ──► C8
    C1 ──► C10
              │
    A1 ──► D1 ──► D3
    A2 ──► D2
    A1 ──► D4
    C6,C8 ► D5
    C7 ──► D6
    A deploys ► D7 ──► D8 ──► D9
                       D8 ──► D10 ──► D11
               D1,D2,D3 ──► D12
```

---

## Definition of Ready (all stories)

- [ ] Acceptance criteria written as testable assertions
- [ ] Key files listed with line-number references where relevant
- [ ] Security framework tags filled (OWASP SAMM, NIST CSF, CSA CCM)
- [ ] BLOCK references noted (if any)
- [ ] `depends_on` and `blocks` frontmatter filled
- [ ] No reference to `organizations` table or `org_id` field (use `customer_id`)
- [ ] bmad-sm sign-off on story

## Definition of Done (all stories)

- [ ] All acceptance criteria pass
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits in changed files
- [ ] Unit tests added for changed functions
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] kubectl rollout status shows AVAILABLE
- [ ] kubectl logs: no ERROR lines in first 60 seconds after rollout
- [ ] Post-deploy BFF smoke: curl gateway health-check returns 200

---

## Security BLOCK Coverage

| BLOCK | Sprint | Story | Status |
|-------|--------|-------|--------|
| BLOCK-01 email enumeration | B | B1 | story exists ✓ |
| BLOCK-02 rate limiting | B | B1 | story exists ✓ |
| BLOCK-03 Google hd validation | B | B2 | story exists ✓ |
| BLOCK-04 PKCE agent token | C | C4 | story exists ✓ |
| BLOCK-05 onboarding auth middleware | C | C3 | story exists ✓ |
| BLOCK-06 PATCH allow-list | C | C3 | story exists ✓ |
| BLOCK-07 developer role bypass | B | B4 | story rewritten ✓ |
| BLOCK-08 TenantViewSet DRF auth | B | B3 | story exists ✓ |
| BLOCK-09 export filter | B | B3 | story exists ✓ |
| BLOCK-10 IDP rate limit | B | B3 | story exists ✓ |
| BLOCK-11 org_admin boundary | B | B4 | story rewritten ✓ |
| BLOCK-12 async tenant sync | A | A3 | story exists ✓ |

All 12 BLOCKs covered. No uncovered blockers.

---

## Scheduling Gap Coverage

| Gap ID | Description | Sprint | Story |
|--------|-------------|--------|-------|
| S-01 | RBAC missing on schedule endpoints | C | C6 |
| S-02 | No ad-hoc scan without schedule | C | C7 |
| S-03 | account_type + agent_registrations migration not applied | C | C1 |
| S-04 | exclude_regions not on Schedule ORM | C | C8 |
| S-05 | No bulk scan-all | C | C9 |
| S-06 | No credential expiry health-check | C | C10 |
| S-07 | Agent scan signal (run_now in heartbeat response) | C | C4 |

All 7 scheduling gaps covered.

---

## Post-Deploy Manual Steps

After B4 deploys and org-boundary enforcement is validated:
```sql
-- Enable org_admin writes — run only after B4 confirmed working in prod
INSERT INTO role_permissions (id, role_id, permission_id, created_at, updated_at)
SELECT gen_random_uuid()::text, r.id, p.id, NOW(), NOW()
FROM roles r, permissions p
WHERE r.name = 'org_admin' AND p.key IN ('orgs:write', 'users:write')
ON CONFLICT DO NOTHING;
```

After Step 7 (deferred from A1 migration):
```sql
-- Once backfill verified: make customer_id NOT NULL
ALTER TABLE user_auth_users ALTER COLUMN customer_id SET NOT NULL;
ALTER TABLE tenant_management_tenants ALTER COLUMN customer_id SET NOT NULL;
```