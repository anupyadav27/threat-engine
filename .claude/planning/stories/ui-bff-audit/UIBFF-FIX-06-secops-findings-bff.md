# Story UIBFF-FIX-06: SecOps — Create BFF Findings Endpoint, Remove Direct Engine Calls

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-FIX — Direct Engine Call Elimination
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 5
- **Priority**: P1 (findings loaded via direct engine calls — no RBAC/tenant enforcement)
- **Depends on**: None
- **Blocks**: None

## User Story

As a security engineer, I want SecOps scan findings normalized and routed through the BFF so RBAC, tenant isolation, and field mapping between SAST/DAST/SCA are consistently enforced.

## Context

Audit findings:
1. `secops/page.jsx` lines 846–860: lazy-loads findings via `getFromEngine('secops', ...)` and `fetchApi()` for SCA
2. `secops/[scanId]/page.jsx`, `secops/dast/[scanId]/page.jsx`, `secops/projects/page.jsx`, `secops/reports/page.jsx`: all use `getFromEngine()` directly

All bypass BFF. Finding field names differ between SAST, DAST, and SCA:
- SAST: `severity`, `rule_id`, `message`, `file_path`, `line_number`, `language`
- DAST: `severity`, `rule_id`, `description`, `endpoint_url`, `vulnerability_type`
- SCA: `vulnerable_components[].vulnerability_ids`, `name`, `version`

## What to Build

### 1. Add `secops/scan/{scan_id}/findings` BFF endpoint to `secops.py`

```python
@router.get("/secops/scan/{scan_id}/findings")
async def view_secops_findings(
    scan_id: str,
    scan_type: str = Query("sast", description="sast|dast|sca"),
    severity: str = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(require_permission("secops:read")),
):
    """Normalized findings for a specific scan. Tenant-scoped."""
    if scan_type == "sast":
        endpoint = f"/api/v1/secops/sast/scan/{scan_id}/findings"
    elif scan_type == "dast":
        endpoint = f"/api/v1/secops/dast/scan/{scan_id}/findings"
    else:
        endpoint = f"/api/v1/secops/sca/scan/{scan_id}/findings"

    params = {"tenant_id": auth.tenant_id, "limit": limit, "offset": offset}
    if severity:
        params["severity"] = severity

    result = await call_engine("secops", endpoint, params=params,
                               auth_headers=build_auth_headers(auth))
    if not result:
        return {"findings": [], "total": 0}

    raw = result if isinstance(result, list) else result.get("findings", [])
    return {
        "findings": [_normalize_secops_finding(f, scan_type) for f in raw],
        "total":    result.get("total", len(raw)) if isinstance(result, dict) else len(raw),
        "scanType": scan_type,
    }
```

Add `_normalize_secops_finding(f, scan_type)` helper:
```python
def _normalize_secops_finding(f: dict, scan_type: str) -> dict:
    severity = _sev(f)
    if scan_type == "sast":
        return {
            "id":          f.get("id") or f.get("result_id", ""),
            "rule_id":     f.get("rule_id", ""),
            "severity":    severity,
            "title":       f.get("message") or f.get("title", ""),
            "file_path":   f.get("file_path"),
            "line_number": f.get("line_number"),
            "language":    f.get("language"),
            "status":      f.get("status", "open"),
            "scan_type":   "sast",
        }
    elif scan_type == "dast":
        return {
            "id":               f.get("id") or f.get("result_id", ""),
            "rule_id":          f.get("rule_id", ""),
            "severity":         severity,
            "title":            f.get("description") or f.get("title", ""),
            "endpoint_url":     f.get("endpoint_url"),
            "vulnerability_type": f.get("vulnerability_type"),
            "status":           f.get("status", "open"),
            "scan_type":        "dast",
        }
    else:  # sca
        return {
            "id":          f.get("id", ""),
            "severity":    severity,
            "title":       f.get("name", ""),
            "version":     f.get("version"),
            "cves":        f.get("vulnerability_ids") or [],
            "status":      "open",
            "scan_type":   "sca",
        }
```

### 2. Update `secops/page.jsx` lines 846–860

```javascript
// BEFORE:
const sastFindings = await getFromEngine('secops', `/api/v1/secops/sast/scan/${id}/findings`);

// AFTER:
const sastFindings = await fetchView(`secops/scan/${id}/findings`, { scan_type: 'sast' });
```

Same pattern for DAST and SCA findings.

### 3. Update secops sub-pages

For `secops/[scanId]/page.jsx`, `secops/dast/[scanId]/page.jsx`: replace `getFromEngine` calls with `fetchView('secops/scan/{id}/findings', {scan_type})`.

Sub-pages that only show scan metadata (not findings) can keep `getFromEngine` for the scan status endpoint — per constitution, raw paginated tables can use gateway.

## Acceptance Criteria

### AC-01 — BFF findings endpoint responds
`GET /api/v1/views/secops/scan/{id}/findings?scan_type=sast` returns normalized findings array.

### AC-02 — Normalized field names
SAST findings have `title`, `file_path`, `line_number`, `language`. DAST findings have `title`, `endpoint_url`, `vulnerability_type`. SCA findings have `title`, `version`, `cves`.

### AC-03 — Tenant isolation
BFF always passes `tenant_id` from `AuthContext` to engine. Cross-tenant scan IDs return empty.

### AC-04 — No direct findings calls in secops page
`grep -n "getFromEngine.*sast.*findings\|getFromEngine.*dast.*findings" frontend/src/app/secops/page.jsx` returns 0 hits.

### AC-05 — RBAC enforced
Viewer role with `secops:read` denied (if secops:read not in viewer permissions) returns 403.

## Cleanup Steps (After Testing)

1. `grep -rn "getFromEngine.*secops.*findings" frontend/src/app/secops/` — confirm 0 hits
2. Remove any `console.log` from findings fetching code
3. Check `fetchApi` helper is still needed after migration; remove import if unused
4. Rebuild gateway image, verify rollout
5. Run post-deploy: load a SAST scan detail page — findings table must populate

## Definition of Done

- [ ] `secops/scan/{id}/findings` BFF endpoint added with SAST/DAST/SCA normalization
- [ ] `secops/page.jsx` lazy-load findings updated to `fetchView`
- [ ] Sub-pages `secops/[scanId]`, `secops/dast/[scanId]` updated
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup completed (0 grep hits for direct finding calls)
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-secops1`