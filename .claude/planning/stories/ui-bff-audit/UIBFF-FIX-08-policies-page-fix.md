# Story UIBFF-FIX-08: Policies Page — Fix Data Mismatch (BFF Returns Suppressions, Page Expects Policies)

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-FIX — Direct Engine Call Elimination
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P1 (critical data mismatch — page is completely broken / showing wrong data)
- **Depends on**: None
- **Blocks**: None

## User Story

As a security engineer, I want the Policies page to show real security policies (from compliance framework controls) rather than suppression rules, so I can manage my policy library.

## Context

Audit finding — **critical data mismatch**:
- `policies/page.jsx` line 49: `fetchView('policies')` expects `data.policies[]` array with fields `name`, `category`, `severity`, `violations`, `exceptions`, `version_history`, `pass_rate`
- `shared/api_gateway/bff/policies.py` line 143: `/policies` endpoint is a **legacy alias for suppressions** and returns `suppressions`, `rule_suppressions`, `finding_suppressions`, `kpi`

The page renders nothing meaningful because `data.policies` is always `undefined`.

**Two valid approaches:**

**Option A (Recommended):** Rename `/policies` BFF to serve real compliance-derived policy data. Map compliance controls → policy objects.

**Option B:** Repurpose the policies page to be a "Policy Exceptions" page that correctly shows suppressions. This requires UI redesign.

This story implements **Option A** — the policies page shows compliance controls as policies.

## What to Build

### 1. Add `view_policies()` in `policies.py` that returns compliance control data

```python
@router.get("/policies")
async def view_policies(
    framework: str = Query(None),
    severity: str = Query(None),
    auth: AuthContext = Depends(require_permission("compliance:read")),
):
    """Security policies derived from compliance framework controls.
    Each 'policy' represents a control the org has enabled for assessment.
    """
    # Fetch compliance frameworks summary
    frameworks_result = await call_engine(
        "compliance",
        "/api/v1/compliance/frameworks",
        params={"tenant_id": auth.tenant_id},
        auth_headers=build_auth_headers(auth),
    )
    frameworks = frameworks_result if isinstance(frameworks_result, list) else []

    policies = []
    for fw in frameworks:
        fw_id = fw.get("id") or fw.get("framework_id")
        fw_name = fw.get("name", "")
        # Get controls for this framework
        detail = await call_engine(
            "compliance",
            f"/api/v1/compliance/framework/{fw_id}/controls",
            params={"tenant_id": auth.tenant_id},
            auth_headers=build_auth_headers(auth),
        ) or {}
        controls = detail.get("controls") or detail.get("families_flat") or []

        for ctrl in controls:
            policies.append({
                "id":            ctrl.get("control_id", ""),
                "name":          ctrl.get("control_name", ctrl.get("name", "")),
                "framework":     fw_name,
                "framework_id":  fw_id,
                "category":      ctrl.get("control_family", ctrl.get("domain", "")),
                "severity":      ctrl.get("severity", "medium"),
                "status":        ctrl.get("status", "active"),
                "pass_count":    ctrl.get("pass_count", 0),
                "fail_count":    ctrl.get("fail_count", 0),
                "total_resources": ctrl.get("total_resources", 0),
                "pass_rate":     _calc_pass_rate(ctrl),
                "violations":    ctrl.get("fail_count", 0),
                "exceptions":    [],   # suppressions for this control — v2
                "last_updated":  ctrl.get("last_assessed_at"),
            })

    # Apply filters
    if framework:
        policies = [p for p in policies if p["framework_id"] == framework]
    if severity:
        policies = [p for p in policies if p["severity"] == severity]

    return {
        "policies":   policies,
        "total":      len(policies),
        "frameworks": [{"id": fw.get("id"), "name": fw.get("name")} for fw in frameworks],
        "kpi": {
            "total":    len(policies),
            "active":   sum(1 for p in policies if p["status"] == "active"),
            "failing":  sum(1 for p in policies if p["violations"] > 0),
            "pass_rate": round(sum(p["pass_rate"] for p in policies) / max(len(policies), 1), 1),
        },
    }
```

Keep the existing `/suppressions` endpoint as-is (already correct for `/suppressions` page).

### 2. Update `policies/page.jsx` to use the new shape

The page already calls `fetchView('policies')` and reads `data.policies`. It should now work correctly once the BFF returns the right shape. Verify field access in the page matches:
- `policy.name` ✓
- `policy.category` ✓ (mapped from control_family)
- `policy.severity` ✓
- `policy.violations` ✓ (mapped from fail_count)
- `policy.pass_rate` ✓
- `policy.exceptions` ✓ (empty array for now — v2 will populate)
- `policy.last_updated` ✓

### 3. Wire framework filter in page

If page has a framework dropdown filter, pass `framework` as query param to `useViewFetch`.

## Acceptance Criteria

### AC-01 — Policies page shows compliance controls
After a compliance scan, the Policies page renders rows with control names, frameworks, severity, and pass rate.

### AC-02 — `data.policies` is an array (not undefined)
`fetchView('policies')` returns `{"policies": [...], "kpi": {...}, "frameworks": [...]}`.

### AC-03 — Suppressions page unaffected
`fetchView('suppressions')` still returns `rule_suppressions`, `finding_suppressions`, `kpi` — the suppressions page is unaffected.

### AC-04 — Tenant isolation
Policies query scoped by `auth.tenant_id`.

### AC-05 — Empty state when no frameworks scanned
When no compliance scans have run, `policies: []` and page shows "No policies yet — run a compliance scan".

## Cleanup Steps (After Testing)

1. `GET /api/v1/views/policies` — confirm `data.policies` is an array
2. `GET /api/v1/views/suppressions` — confirm suppressions page still works
3. Rebuild gateway, verify rollout
4. Post-deploy: load /policies — table shows compliance controls not suppression entries
5. Load /suppressions — suppression table still works correctly

## Definition of Done

- [ ] `view_policies()` in `policies.py` returns compliance controls as policies
- [ ] Legacy `/suppressions` endpoint unchanged
- [ ] `policies/page.jsx` field access verified against new BFF shape
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup steps completed
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-policies1`