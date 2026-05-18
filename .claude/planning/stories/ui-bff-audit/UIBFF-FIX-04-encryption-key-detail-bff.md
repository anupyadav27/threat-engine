# Story UIBFF-FIX-04: Encryption Key Detail — Wrap in BFF

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-FIX — Direct Engine Call Elimination
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P1 (direct engine calls bypass tenant isolation and RBAC)
- **Depends on**: None
- **Blocks**: None

## User Story

As a security engineer, I want the Encryption Key Detail page to use the BFF so that tenant isolation, RBAC, and field normalization are consistently applied.

## Context

Audit finding: `encryption/key-detail/page.jsx` uses two direct `getFromEngine()` calls:
```javascript
// line 126:
getFromEngine('encryption', `/api/v1/encryption/keys/${keyId}/dependencies`)
// line 129:
getFromEngine('encryption', `/api/v1/encryption/keys/${keyId}/blast-radius`)
```

These bypass the BFF entirely. No `tenant_id` scoping is verified at the BFF layer. Fields from engine responses (`key_metadata`, `resources`, `score`, `affected_resources`, `by_severity`, `by_type`) are consumed without normalization.

## What to Build

### 1. Add BFF endpoint `encryption/key/{key_id}` to `encryption.py`

```python
@router.get("/encryption/key/{key_id}")
async def view_key_detail(
    key_id: str,
    auth: AuthContext = Depends(require_permission("encryption:read")),
):
    """Key detail: metadata, dependencies, blast radius. Tenant-scoped."""
    import asyncio

    deps_task = call_engine(
        "encryption",
        f"/api/v1/encryption/keys/{key_id}/dependencies",
        params={"tenant_id": auth.tenant_id},
        auth_headers=build_auth_headers(auth),
    )
    blast_task = call_engine(
        "encryption",
        f"/api/v1/encryption/keys/{key_id}/blast-radius",
        params={"tenant_id": auth.tenant_id},
        auth_headers=build_auth_headers(auth),
    )

    deps_result, blast_result = await asyncio.gather(
        deps_task, blast_task, return_exceptions=True
    )

    deps = deps_result if not isinstance(deps_result, Exception) else {}
    blast = blast_result if not isinstance(blast_result, Exception) else {}

    return {
        "keyMetadata":        deps.get("key_metadata") or {},
        "resources":          deps.get("resources") or [],
        "blastRadius": {
            "score":              blast.get("score", 0),
            "affectedResources":  blast.get("affected_resources") or [],
            "bySeverity":         blast.get("by_severity") or {},
            "byType":             blast.get("by_type") or {},
        },
    }
```

Register in gateway routing under `/api/v1/views/encryption/key/{key_id}`.

### 2. Update `encryption/key-detail/page.jsx`

Replace lines 126–132:
```javascript
// BEFORE:
const [depResult, blastResult] = await Promise.all([
  getFromEngine('encryption', `/api/v1/encryption/keys/${keyId}/dependencies`),
  getFromEngine('encryption', `/api/v1/encryption/keys/${keyId}/blast-radius`),
]);
const keyMeta = depResult?.key_metadata || {};
const resources = depResult?.resources || [];
const blastRadius = blastResult || {};

// AFTER:
const result = await fetchView(`encryption/key/${keyId}`);
const keyMeta = result?.keyMetadata || {};
const resources = result?.resources || [];
const blastRadius = result?.blastRadius || {};
```

### 3. Update field access for normalized names

The BFF normalizes snake_case → camelCase for blast radius. Update page reads:
```javascript
// BEFORE: blastRadius.affected_resources, blastRadius.by_severity, blastRadius.by_type
// AFTER:  blastRadius.affectedResources, blastRadius.bySeverity, blastRadius.byType
```

## Acceptance Criteria

### AC-01 — BFF endpoint responds
`GET /api/v1/views/encryption/key/{key_id}` returns 200 with `keyMetadata`, `resources`, `blastRadius`.

### AC-02 — Tenant isolation enforced
`tenant_id` always taken from `AuthContext`, passed to engine. Cross-tenant key IDs return 404 or empty.

### AC-03 — No direct engine calls
`grep "getFromEngine.*encryption.*keys" frontend/src/app/encryption/` returns 0 hits.

### AC-04 — Engine error handled gracefully
If engine returns 404 for the key, BFF returns `{"keyMetadata": {}, "resources": [], "blastRadius": {...}}` and page shows empty state rather than crashing.

### AC-05 — Viewer role sees 403
`encryption:read` permission check: verify viewer does not have encryption:read per RBAC.md; if so, page should show 403 state.

## Cleanup Steps (After Testing)

1. `grep -rn "getFromEngine.*encryption.*keys" frontend/src/` — confirm 0 hits
2. Remove any `console.log` added during debugging
3. Rebuild gateway image and verify rollout: `kubectl rollout status deployment/api-gateway -n threat-engine-engines`
4. Run post-deploy smoke: `GET /api/v1/views/encryption/key/test-key-id` returns valid structure (200 or 404, not 500)

## Definition of Done

- [ ] BFF endpoint added to `encryption.py` and registered in routing
- [ ] `encryption/key-detail/page.jsx` updated to use `fetchView`
- [ ] Field name updates for camelCase normalized names
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup steps run — 0 direct engine call hits
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-encryption-key1`
