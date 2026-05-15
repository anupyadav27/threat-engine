# Story AP-P1-02: Crown Jewel Manual Override API

## Status: ready

## Metadata
- **Phase**: P1 — Crown Jewels
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P1
- **Depends on**: AP-P2-01 (crown_jewel_overrides table must exist), AP-P2-02 (engine scaffold must exist for PATCH endpoint)
- **Blocks**: AP-P1-01 (classifier reads overrides), AP-P2-07 (override data needed for full scan)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory (new endpoint with write mutation). bmad-security-architect must review PATCH endpoint design (STRIDE, PASTA — analyst override attack surface).

## User Story

As a tenant admin, I want to manually tag or untag any resource as a crown jewel via `PATCH /api/v1/crown-jewels/{resource_uid}` so that the platform's classification reflects my organisation's actual data sensitivity designations, and paths to build-artifact buckets or dev databases are not falsely elevated.

## Context

Auto-classification covers the common cases but is not perfect for every tenant. A tenant might have an S3 bucket that looks like PII storage by name but actually holds build artifacts. Or they may have a custom database not matched by resource type alone.

The override API stores the analyst's intent in `crown_jewel_overrides` and it takes effect in the next scan run when `CrownJewelClassifier` reads it. The override is audit-logged with `set_by` (user email from AuthContext).

This story creates the PATCH endpoint. The GET /api/v1/crown-jewels list endpoint is created in AP-P2-02 (engine scaffold).

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [x] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
PR.AC-4 (access permissions managed), ID.RA-6 (risk response)

**CSA CCM v4 Domain(s)**
- IAM-09 (Access Control), DSP-07 (Data Classification), GRC-06 (Audit Logging)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | PATCH endpoint | Attacker forges AuthContext header to tag crown jewels as non-crown-jewels | require_permission("attack_path:write") validates token independently; gateway AuthMiddleware |
| Tampering | crown_jewel_overrides | Insider marks PII database as non-crown-jewel to suppress attack path visibility | `set_by` always populated from AuthContext.user_email; audit trail is immutable (no DELETE) |
| Repudiation | override audit | Analyst denies having suppressed a crown jewel | `set_by` is the authenticated user email; recorded with timestamp |
| Elevation | viewer override | viewer role attempts to tag resources as non-crown-jewels | attack_path:write required; viewer role does not have this permission → 403 |

### PASTA Analysis
**Asset at risk**: Crown jewel classification integrity — if an attacker can suppress a real crown jewel via this endpoint, all attack paths to that asset are hidden.

**Mitigations**:
- Permission gating: only tenant_admin, org_admin, platform_admin (roles with attack_path:write) can call PATCH
- Audit trail: `set_by` + `created_at` + `updated_at` in `crown_jewel_overrides` — every change is traceable
- Override does NOT delete paths retroactively — only affects next scan run

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1562.001 | Impair Defenses: Disable Security Tools | RBAC prevents analyst from disabling crown jewel classification via this endpoint |

## Acceptance Criteria

### Functional
- [ ] AC-1: `PATCH /api/v1/crown-jewels/{resource_uid}` endpoint implemented in `engines/attack-path/attack_path_engine/api/routes.py`
- [ ] AC-2: Request body: `{ "is_crown_jewel": bool, "crown_jewel_type": str (optional), "reason": str (optional) }`
- [ ] AC-3: Response body: updated `crown_jewel_overrides` row as JSON
- [ ] AC-4: `set_by` field populated from `AuthContext.user_email` (not from request body — never trust client-provided identity)
- [ ] AC-5: Override stored in `crown_jewel_overrides` table with `UNIQUE(resource_uid, tenant_id)` — second PATCH to same resource updates the row (not inserts a duplicate)
- [ ] AC-6: `tenant_id` always taken from `AuthContext.engine_tenant_id` — never from request body or path parameter
- [ ] AC-7: PATCH with `is_crown_jewel=false` and no `crown_jewel_type` is accepted — untagging does not require a type

### RBAC Matrix (5 roles × 1 endpoint)
- [ ] AC-8: `platform_admin` — 200 OK, override stored
- [ ] AC-9: `org_admin` — 200 OK, override stored
- [ ] AC-10: `tenant_admin` — 200 OK, override stored
- [ ] AC-11: `analyst` — 403 Forbidden (attack_path:write not in analyst permissions)
- [ ] AC-12: `viewer` — 403 Forbidden

### Security (must pass bmad-security-reviewer)
- [ ] AC-13: `require_permission("attack_path:write")` called via `Depends()` on the PATCH endpoint
- [ ] AC-14: No DEV_BYPASS_AUTH
- [ ] AC-15: `resource_uid` in path parameter validated (not empty, not > 512 chars) — reject malformed UIDs with 422
- [ ] AC-16: SQL uses parameterized query — no string interpolation of resource_uid into the statement
- [ ] AC-17: `set_by` max length validated (user_email ≤ 255 chars)
- [ ] AC-18: Response does not echo back any credential_ref or internal resource fields

## Technical Notes

**Engine**: `engine-attack-path` (created in AP-P2-02). This story implements the PATCH endpoint; the engine scaffold must exist first.

**Endpoint**: `PATCH /api/v1/crown-jewels/{resource_uid}`

**DB table**: `crown_jewel_overrides` (created in AP-P2-01). This story writes to it.

**Upsert SQL pattern**:
```sql
INSERT INTO crown_jewel_overrides
    (resource_uid, tenant_id, is_crown_jewel, crown_jewel_type, reason, set_by)
VALUES (%s, %s, %s, %s, %s, %s)
ON CONFLICT (resource_uid, tenant_id) DO UPDATE SET
    is_crown_jewel = EXCLUDED.is_crown_jewel,
    crown_jewel_type = EXCLUDED.crown_jewel_type,
    reason = EXCLUDED.reason,
    set_by = EXCLUDED.set_by,
    updated_at = NOW()
RETURNING *;
```

**Permission seeding**: The Django migration for `attack_path:read` and `attack_path:write` permissions must be applied before this endpoint is tested. Permission seeding is part of AP-P2-02 (engine scaffold story).

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/api/routes.py` (add PATCH endpoint)

## Definition of Done
- [ ] PATCH endpoint implemented and responding correctly to all 5 roles
- [ ] Override stored in crown_jewel_overrides with correct set_by from AuthContext
- [ ] Second PATCH to same resource_uid updates (no duplicate rows)
- [ ] PATCH with is_crown_jewel=false accepted without crown_jewel_type
- [ ] RBAC test: analyst and viewer receive 403; others receive 200
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-security-architect: PATCH endpoint design sign-off recorded