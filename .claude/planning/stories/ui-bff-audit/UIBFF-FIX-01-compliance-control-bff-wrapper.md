# Story UIBFF-FIX-01: Compliance Control Detail — Wrap Direct Engine Calls in BFF

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-FIX — Direct Engine Call Elimination
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P1 (bypasses BFF security layer — no tenant isolation enforcement)
- **Depends on**: None
- **Blocks**: None

## User Story

As a security engineer, I want compliance control details (findings by control, control descriptions, remediation) to flow through the BFF so that RBAC, tenant isolation, and field normalization are consistently enforced.

## Context

Audit finding: `compliance/page.jsx` makes two direct `getFromEngine()` calls that completely bypass the BFF:

```javascript
// compliance/page.jsx line 112
getFromEngine('compliance', '/api/v1/compliance/findings/by-control', {
  framework_id, control_id, tenant_id, account_id, region
})

// compliance/page.jsx line 115
getFromEngine('compliance', `/api/v1/compliance/control/${ctrl.control_id}`, {
  tenant_id
})
```

These bypass `require_permission()` enforcement at the BFF layer and could leak cross-tenant data if the engine's tenant scoping has any gap.

## What to Build

### 1. Add two BFF endpoints to `compliance.py`

**Endpoint A: Control findings**
```python
@router.get("/compliance/control/{control_id}/findings")
async def view_control_findings(
    control_id: str,
    framework_id: str = Query(...),
    account_id: str = Query(None),
    region: str = Query(None),
    auth: AuthContext = Depends(require_permission("compliance:read")),
):
    """Paginated findings for a specific compliance control. Tenant-scoped."""
    result = await call_engine(
        "compliance",
        f"/api/v1/compliance/findings/by-control",
        params={
            "framework_id": framework_id,
            "control_id": control_id,
            "tenant_id": auth.tenant_id,   # always auth context, never query param
            "account_id": account_id,
            "region": region,
        },
        auth_headers=build_auth_headers(auth),
    )
    return result or {"config_checks": [], "cdr_checks": []}
```

**Endpoint B: Control detail**
```python
@router.get("/compliance/control/{control_id}")
async def view_control_detail(
    control_id: str,
    auth: AuthContext = Depends(require_permission("compliance:read")),
):
    """Control metadata: description, rationale, testing procedures, remediation."""
    result = await call_engine(
        "compliance",
        f"/api/v1/compliance/control/{control_id}",
        params={"tenant_id": auth.tenant_id},
        auth_headers=build_auth_headers(auth),
    )
    return result or {}
```

Both endpoints must be registered in `shared/api_gateway/views/` routing (wherever the compliance views are mounted — check `shared/api_gateway/main.py`).

### 2. Update `compliance/page.jsx` to use BFF

Replace lines 112–115:
```javascript
// BEFORE:
const [ctrlFindings, ctrlDetail] = await Promise.all([
  getFromEngine('compliance', '/api/v1/compliance/findings/by-control', {...}),
  getFromEngine('compliance', `/api/v1/compliance/control/${ctrl.control_id}`, {...}),
]);

// AFTER:
const [ctrlFindings, ctrlDetail] = await Promise.all([
  fetchView(`compliance/control/${ctrl.control_id}/findings`, {
    framework_id: selectedFw.id,
    account_id: filters.account_id,
    region: filters.region,
  }),
  fetchView(`compliance/control/${ctrl.control_id}`),
]);
```

`fetchView` resolves to `/gateway/api/v1/views/{path}` which routes through BFF.

## Acceptance Criteria

### AC-01 — BFF endpoints respond
`GET /api/v1/views/compliance/control/{id}/findings` and `GET /api/v1/views/compliance/control/{id}` return 200 with the same shape as before.

### AC-02 — Tenant isolation enforced
Requesting findings for a control while authenticated as tenant-A returns only tenant-A findings. `tenant_id` always taken from `AuthContext`, not query param.

### AC-03 — No direct engine calls in compliance page
`grep -n "getFromEngine.*compliance.*findings/by-control\|getFromEngine.*compliance/control" frontend/src/app/compliance/page.jsx` returns 0 hits.

### AC-04 — Viewer role receives 403
Compliance endpoint with viewer token (compliance:read not in viewer permissions per RBAC.md) returns 403.

### AC-05 — Empty control returns graceful empty
If compliance engine returns no findings for a control, BFF returns `{"config_checks": [], "cdr_checks": []}` and page renders empty state.

## Technical Notes

- Check `shared/api_gateway/views/` or `shared/api_gateway/main.py` for how compliance routes are registered — ensure new endpoints are included
- The `call_engine()` and `build_auth_headers()` helpers already exist in `_shared.py`
- Viewer role check: verify if `compliance:read` is in viewer's permission set in `RBAC.md` before adding 403 test
- Do NOT change the compliance engine itself — BFF is a thin proxy here

## Definition of Done

- [ ] Two BFF endpoints added to `compliance.py`
- [ ] Both registered in gateway routing
- [ ] `compliance/page.jsx` lines 112–115 updated to use `fetchView`
- [ ] AC-01 through AC-05 verified
- [ ] Gateway image rebuilt: `yadavanup84/threat-engine-api-gateway:v-bff-compliance1`