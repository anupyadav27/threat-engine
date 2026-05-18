# JNY-03: Django — grant `ciem:sensitive` to analyst+ roles (analyst, tenant_admin, org_admin, platform_admin)

## Track
Investigation Journey Unification — Phase A

## Priority
P1 — Inventory CIEM tab and `/ciem/identity/[principal]` Stage 2 hit 403 for the default admin (G-3); blocks the cross-engine pivot from asset → identity.

## Status
done — Django migrations 0015-0018 applied via v-jny03-1 image; cdr:sensitive=True for analyst/tenant_admin/org_admin/platform_admin, False for viewer; verified in live DB

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | — | — |
| UI / BFF / Gateway dev | `cspm-django-engineer` + `cspm-rbac-guardian` | R |
| Security architect (design) | `bmad-security-architect` | A |
| Security reviewer (code) | `bmad-security-reviewer` + `bmad-security-reviewer` | R |
| BMad lead | `bmad-security-po` | R |
| QA | `bmad-qa` | R |
| Standards | `cspm-rbac-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-1 (design gate, end of D2) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §2.2 G-3, no role had `ciem:sensitive` permission. The Inventory Asset CIEM tab and the CIEM identity profile call BFF endpoints decorated with `require_permission("ciem:sensitive")` and 403 for every customer. Migration 0013 (already in repo, untracked at design time) **grants the permission to 4 roles: analyst, tenant_admin, org_admin, platform_admin** — per least-privilege analysis in [bmad-security-architect handoff §3](JNY-03_handoff_bmad-security-architect.md): analysts run investigations, denying breaks the journey unification goal, and these 4 roles already see same-class data (threat findings, IAM findings) — no new data class exposure. Lower-privilege roles (viewer, auditor, dev, security_engineer) remain denied.

**CP-1 also closed a security regression** — the new `/ciem_identity` BFF route (untracked sprint code) was missing both the `ciem:sensitive` gate and the audit log. JNY-03 now covers MF-3 (gate the route) and MF-4 (audit log on view_asset_ciem) inline.

## What to build
1. Django data migration: `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/migrations/00XX_grant_ciem_sensitive_to_platform_admin.py`
2. Idempotent forward + reverse: add `ciem:sensitive` to `platform_admin.permissions` JSONB if not present; remove on reverse.
3. Update the role-seed fixture used on first-boot in `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/seeds/roles.py` so new tenants ship with the correct grant.
4. Audit-log entry on the migration apply (per RBAC guardian standard) — record who/when/what permissions were added.

## Acceptance criteria
- [ ] Migration 0013 runs cleanly forward + reverse on a fresh DB
- [ ] After migration, all 4 roles (analyst, tenant_admin, org_admin, platform_admin) receive 200 on `/api/v1/views/inventory/asset/{uid}/ciem` and `/api/v1/views/ciem_identity`
- [ ] Lower-privilege roles (`viewer`, `auditor`, `dev`, `security_engineer`) receive 403 on both endpoints
- [ ] **MF-3 closure**: `/api/v1/views/ciem_identity` checks `ciem:sensitive` permission and emits audit log on 200/403
- [ ] **MF-4 closure**: `/api/v1/views/inventory/asset/{uid}/ciem` (view_asset_ciem) emits audit log with top-5 identity_arns + result + request_id on 200/403
- [ ] Audit log entries are JSON-serialized via `api-gateway.audit` named logger
- [ ] No other permission in the 27-permission matrix is touched
- [ ] **MF-5 closure**: RBAC.md updated with `ciem:sensitive` row + Sensitive Data Permissions subsection

## Dependencies
- Blocks: JNY-04 (rollout), JNY-10 (CIEM Stage 2 fix needs auth path working first)
- Blocked by: none

## Constitution check
- RBAC delta limited to one permission, one role — minimum surface change.
- Tenant-scoped — applies to all tenants' platform_admin role; no per-tenant deviation.
- Audit-logged grant per security baseline.
- No widening of `ciem:sensitive` to lower-privilege roles.

## Out of scope
- Re-design of the 27-permission matrix.
- New permissions for Stage 3/4/5 of CIEM journey.
- Front-end role-aware UI hiding (separate UI story).

## Files touched (estimate)
- `platform/cspm-backend/user_auth/migrations/00XX_grant_ciem_sensitive_to_platform_admin.py` — new
- `platform/cspm-backend/user_auth/seeds/roles.py` — append permission to platform_admin seed
- `platform/cspm-backend/user_auth/tests/test_role_permissions.py` — assert grant
- `.claude/documentation/RBAC.md` — note the grant
- `engines/ciem/tests/test_auth.py` — confirm 200 for platform_admin (regression)

## Test plan
- Unit: migration apply + reverse on sqlite in-memory
- Integration: cspm-backend test client logs in as admin, hits both endpoints, asserts 200
- Security: `bmad-security-reviewer` confirms no other role gained the permission; `cspm-rbac-guardian` confirms strip_sensitive_fields still enforces auth_level field stripping for lower roles
- E2E smoke: Inventory Asset journey CIEM tab loads; CIEM Stage 2 page loads (data correctness handled in JNY-10)
