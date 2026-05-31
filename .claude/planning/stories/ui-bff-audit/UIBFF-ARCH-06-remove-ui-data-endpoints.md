# Story UIBFF-ARCH-06: Remove /ui-data Endpoints from Engines (Post-Migration Cleanup)

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-ARCH — Two-Table BFF Architecture Migration
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 2
- **Priority**: P3 (cleanup only — engines still work without this)
- **Depends on**: ALL ARCH-01 through ARCH-05 must be complete and deployed
- **Blocks**: Nothing (cleanup story)

## User Story

As a developer, I want to remove the `/ui-data` HTTP endpoints from engine services after the BFF migration is complete, so that engines are leaner and the BFF cannot accidentally fall back to engine HTTP calls.

## Context

Each engine has a `/api/v1/{engine}/ui-data` endpoint built specifically for BFF consumption. After the BFF migration to `security_findings` + `resource_security_posture`:
- These endpoints are no longer called from BFF handlers
- They remain as dead code and unnecessary maintenance surface
- Their removal enforces that BFF reads from DB only (no regression to HTTP calls)

**Engines with `/ui-data` endpoints to remove:**
- `engines/threat/` → `/api/v1/threat/ui-data`
- `engines/iam/` → `/api/v1/iam-security/ui-data`
- `engines/network-security/` → `/api/v1/network-security/ui-data`
- `engines/datasec/` → `/api/v1/datasec/ui-data`
- `engines/cdr/` → `/api/v1/cdr/ui-data`
- `engines/encryption/` → `/api/v1/encryption/ui-data`
- `engines/container-security/` → `/api/v1/container-security/ui-data`

**Endpoints to KEEP (still called from BFF):**
- CDR: `/api/v1/cdr/identities` (identity aggregation)
- CDR: `/api/v1/cdr/heatmap` (heatmap matrix)
- Encryption: `/api/v1/encryption/keys/{id}/dependencies` (key detail)
- Encryption: `/api/v1/encryption/keys/{id}/blast-radius` (key detail)
- Encryption: `/api/v1/encryption/ui-data` → rename to `/api/v1/encryption/resource-objects` (keys/certs/secrets — not findings)
- Container: `/api/v1/container-security/ui-data` → rename to `/api/v1/container-security/clusters`

## What to Build

### 1. Pre-removal verification

Before removing any endpoint, verify it is not called anywhere:
```bash
grep -rn "ui-data" shared/api_gateway/bff/
grep -rn "ui-data" frontend/src/
```
Must return 0 hits for the specific engine before removing it.

### 2. Remove `/ui-data` from each engine

For each engine listed above, in `routes.py` or equivalent:
```python
# DELETE the /ui-data route handler entirely:
@router.get("/threat/ui-data")  # DELETE THIS
async def get_ui_data(...):    # DELETE THIS
    ...                         # DELETE THIS
```

Remove the function and any supporting functions only used by it (check for `_build_ui_response`, `_aggregate_for_ui` helpers).

### 3. Rename resource-object endpoints to clearer names

```python
# Encryption — rename to avoid confusion:
# OLD: GET /api/v1/encryption/ui-data → returns {keys, certs, secrets}
# NEW: GET /api/v1/encryption/resource-objects → same response

# Container — rename:
# OLD: GET /api/v1/container-security/ui-data → returns {clusters, domain_scores}
# NEW: GET /api/v1/container-security/clusters → same response
```

Update BFF calls to use new endpoint names.

### 4. Update engine OpenAPI docs / health endpoints

Remove `/ui-data` from any route documentation or internal load tests that reference them.

## Acceptance Criteria

### AC-01 — No BFF calls to `/ui-data` for migrated engines
`grep -rn "/ui-data" shared/api_gateway/bff/` returns 0 hits for: threat, iam, network, datasec, cdr (findings), encryption (findings), container (findings).

### AC-02 — Engine health endpoints unaffected
`/health/live` and `/health/ready` on all engines still return 200.

### AC-03 — All pages still render
Run end-to-end smoke test on: misconfig, IAM, network-security, datasec, CDR, encryption, container-security pages — all load without errors.

### AC-04 — Resource-object endpoints still work
Encryption keys/certs/secrets still render on the encryption page via renamed endpoint.
Container clusters still render via renamed endpoint.

## Cleanup Steps (After Testing)

1. `grep -rn "ui-data" shared/api_gateway/bff/` → only remaining hits should be for non-migrated engines (if any)
2. `grep -rn "ui-data" frontend/src/` → 0 hits
3. Rebuild all affected engine images with `-cleanup1` tag suffix
4. Apply new images one at a time — verify each engine's health after deploy
5. Run full smoke suite: all security pages load, no 500 errors in logs

## Definition of Done

- [ ] `/ui-data` removed from: threat, iam, network-security, datasec, cdr (findings), encryption (findings), container (findings)
- [ ] Resource-object endpoints renamed for encryption and container
- [ ] BFF calls updated to new endpoint names
- [ ] AC-01 through AC-04 verified
- [ ] All affected engine images rebuilt
- [ ] Full smoke test passes