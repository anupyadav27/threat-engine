# Story UIBFF-ARCH-01: Misconfig BFF — Migrate from Engine HTTP to security_findings Table

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-ARCH — Two-Table BFF Architecture Migration
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P2 (current engine call works; migration improves reliability and cross-engine data)
- **Depends on**: UIBFF-BFF-01 (read_findings helper), check engine writing to security_findings (already done via SF-P1-01)
- **Blocks**: None (can ship incrementally)

## User Story

As a developer, I want the misconfig BFF to read findings directly from `security_findings` instead of calling the threat engine HTTP endpoint, so the misconfig page always has data even if the threat engine is temporarily unavailable.

## Context

`shared/api_gateway/bff/misconfig.py` currently calls:
```python
("threat", "/api/v1/threat/ui-data", {...})
```
Returns findings that include `posture_category`, `severity`, `service`, `scan_trend` etc.

After this migration, misconfig BFF reads directly from `security_findings` using `read_findings()` helper with `source_engines=["check"]` (misconfig = check engine findings).

The `scanTrend` field is handled separately by `UIBFF-S01-01` (`fetch_scan_trend()`).

## What to Build

### 1. Rewrite `view_misconfig()` to use `read_findings()`

```python
from ._shared import read_findings, fetch_scan_trend

async def view_misconfig(
    tenant_id: str,
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    region: Optional[str] = None,
    auth_headers: dict = {},
) -> dict:
    # 1. Read findings from security_findings (check engine)
    findings_result = await read_findings(
        tenant_id=tenant_id,
        source_engines=["check"],
        account_id=account_id,
        provider=provider,
        region=region,
        limit=2000,
    )
    findings = findings_result["findings"]
    by_severity = findings_result["by_severity"]

    # 2. Scan trend from scan_orchestration
    scan_trend = await fetch_scan_trend(tenant_id, auth_headers, days=30)

    # 3. Build existing output shape (unchanged for UI contract)
    filtered = findings  # already scoped by account/provider/region
    services = _build_by_service(filtered)
    heatmap = _build_heatmap(filtered)
    quick_wins = _build_quick_wins(filtered)

    posture_score = _compute_posture_score(by_severity)

    return {
        "kpiGroups": _build_kpi_groups(by_severity, posture_score),
        "findings":  [_normalize_finding(f) for f in filtered],
        "heatmap":   heatmap,
        "quickWins": quick_wins,
        "byService": services,
        "kpi":       {"posture_score": posture_score, **by_severity},
        "scanTrend": scan_trend,
    }
```

Keep all existing helper functions (`_build_heatmap`, `_build_quick_wins`, `_build_by_service`) — only the data source changes.

### 2. Remove engine HTTP call

Delete:
```python
("threat", "/api/v1/threat/ui-data", {...})
```
from `view_misconfig()`.

### 3. Verify `_normalize_finding()` maps security_findings columns to UI fields

The page reads: `f.severity`, `f.posture_category`, `f.service`, `f.resource_uid`, `f.resource_type`, `f.title`, `f.rule_id`, `f.status`, `f.account_id`, `f.provider`, `f.region`, `f.finding_id`, `f.sla_status`.

`security_findings` has all these columns directly. Add `sla_status` computation:
```python
def _normalize_finding(f: dict) -> dict:
    age_days = (datetime.utcnow() - f["last_seen_at"]).days if f.get("last_seen_at") else 0
    return {
        **f,
        "sla_status": compute_sla_status(f.get("severity", "low"), age_days),
        "service": _extract_service_from_sf(f),
    }
```

## Acceptance Criteria

### AC-01 — Misconfig page loads with real data
After migration, `/api/v1/views/misconfig` returns `findings[]` from `security_findings` table, not from threat engine HTTP.

### AC-02 — Output shape unchanged
BFF response still has `kpiGroups`, `findings`, `heatmap`, `quickWins`, `byService`, `kpi`, `scanTrend`. UI does not require changes.

### AC-03 — Threat engine unavailability does not break page
Kill the threat engine pod temporarily. Misconfig BFF still returns data from DB.

### AC-04 — Tenant isolation
All `read_findings()` calls pass `tenant_id` from `AuthContext`.

### AC-05 — `sla_status` present on each finding
Every finding in response has `sla_status` ∈ `{"breached", "at_risk", "ok"}`.

## Cleanup Steps (After Testing)

1. Confirm no HTTP call to `engine-threat` in `misconfig.py`: `grep "threat.*ui-data" shared/api_gateway/bff/misconfig.py` → 0 hits
2. Kill threat engine pod and verify misconfig page still loads
3. Restart threat engine pod
4. Rebuild gateway, verify rollout

## Definition of Done

- [ ] `view_misconfig()` reads from `security_findings` via `read_findings()`
- [ ] Engine HTTP call removed
- [ ] `sla_status` computed per finding
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup completed
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-arch-misconfig1`
