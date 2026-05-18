# Story UIBFF-ARCH-02: IAM BFF — Migrate from Engine HTTP to security_findings Table

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-ARCH — Two-Table BFF Architecture Migration
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P2
- **Depends on**: UIBFF-BFF-01, UIBFF-BFF-02, IAM engine writing to security_findings (already done via SF-P1-01)
- **Blocks**: None

## User Story

As a developer, I want the IAM BFF to read from `security_findings` and `resource_security_posture` instead of the IAM engine HTTP endpoint, making the IAM page resilient to engine unavailability.

## Context

`shared/api_gateway/bff/iam.py` calls:
```python
("iam", "/api/v1/iam-security/ui-data", {...})
```
Then has 3-tier fallback chains that derive roles/keys/identities from check engine findings when IAM engine returns nothing.

After migration: read directly from `security_findings` (`source_engine="iam"`) for findings, and from `resource_security_posture` for posture dimensions (`iam_detail`, `iam_score`).

## What to Build

### 1. Rewrite `view_iam()` to use shared helpers

```python
from ._shared import read_findings, read_posture, fetch_scan_trend

async def view_iam(tenant_id, account_id=None, provider=None, region=None, auth_headers={}) -> dict:
    # 1. IAM findings from security_findings
    findings_result = await read_findings(
        tenant_id=tenant_id,
        source_engines=["iam"],
        account_id=account_id,
        provider=provider,
        region=region,
        limit=2000,
    )
    findings = findings_result["findings"]
    by_severity = findings_result["by_severity"]

    # 2. IAM posture dimensions from resource_security_posture
    posture_result = await read_posture(
        tenant_id=tenant_id,
        account_id=account_id,
        provider=provider,
        limit=1000,
    )
    posture_rows = posture_result["posture"]

    # 3. Derive IAM-specific data from posture iam_detail JSONB
    identities, roles, access_keys, priv_esc = _extract_iam_from_posture(posture_rows)

    # 4. Scan trend
    scan_trend = await fetch_scan_trend(tenant_id, auth_headers, days=30)

    # Keep existing output shape
    return {
        "kpiGroups":          _build_kpi_groups(by_severity, identities, roles, access_keys),
        "findings":           [_normalize_finding(f) for f in findings],
        "findingsByModule":   _group_by_module(findings),
        "identities":         identities,
        "roles":              roles,
        "accessKeys":         access_keys,
        "privilegeEscalation": priv_esc,
        "byAccount":          _group_by_account(findings),
        "byRegion":           _group_by_region(findings),
        "scanTrend":          scan_trend,
        "serviceAccounts":    [],
        "filterSchema":       _build_filter_schema(findings),
    }
```

Add `_extract_iam_from_posture()` to derive IAM entities from `iam_detail` JSONB:
```python
def _extract_iam_from_posture(posture_rows: list) -> tuple:
    identities = []
    roles = []
    access_keys = []
    priv_esc = []
    for row in posture_rows:
        detail = row.get("iam_detail") or {}
        if detail.get("role_arns"):
            for arn in detail["role_arns"]:
                roles.append({"role_arn": arn, "resource_uid": row["resource_uid"],
                               "is_admin": detail.get("is_admin", False)})
        # ... build identities, access_keys, priv_esc from detail fields
    return identities, roles, access_keys, priv_esc
```

### 2. Remove IAM engine HTTP call and all fallback chains

Delete:
- `("iam", "/api/v1/iam-security/ui-data", {...})` call
- Lines 59–137: check engine fallback chain (no longer needed)
- Lines 113–137: secondary check engine call

### 3. Keep output shape identical — UI contract unchanged

## Acceptance Criteria

### AC-01 — IAM page loads with real data
`/api/v1/views/iam` returns `findings[]`, `identities[]`, `roles[]`, `accessKeys[]` from DB, not from IAM engine HTTP.

### AC-02 — IAM engine unavailability does not break page
Kill `engine-iam` pod temporarily — IAM page still loads with `security_findings` data.

### AC-03 — Output shape unchanged
`identities`, `roles`, `accessKeys`, `privilegeEscalation`, `kpiGroups`, `scanTrend` all present.

### AC-04 — Fallback chains removed
`grep "fallback\|Fallback\|secondary.*check" shared/api_gateway/bff/iam.py` → 0 hits (fallback code deleted).

### AC-05 — Tenant isolation
`read_findings()` and `read_posture()` both called with `tenant_id` from `AuthContext`.

## Cleanup Steps (After Testing)

1. Kill IAM engine pod, load IAM page — must still show data
2. Restart IAM engine pod
3. `grep "iam-security/ui-data" shared/api_gateway/bff/iam.py` → 0 hits
4. Rebuild gateway, verify rollout

## Definition of Done

- [ ] `view_iam()` reads from `security_findings` + `resource_security_posture`
- [ ] Engine HTTP call and fallback chains removed
- [ ] `_extract_iam_from_posture()` derives IAM entities from `iam_detail` JSONB
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup completed
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-arch-iam1`
