# Story UIBFF-ARCH-03: Network-Security + DataSec BFF — Migrate to security_findings Table

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-ARCH — Two-Table BFF Architecture Migration
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P2
- **Depends on**: UIBFF-BFF-01, UIBFF-BFF-02, network+datasec writing to security_findings (already done)
- **Blocks**: None

## User Story

As a developer, I want the Network Security and DataSec BFF handlers to read from `security_findings` instead of their engine HTTP endpoints, improving reliability and response time.

## Context

Two engines already write to `security_findings`:
- Network: `source_engine="network"`, `posture_category="network_exposure"` (SF-P1-01)
- DataSec: `source_engine="datasec"`, `posture_category="data_violation"` (SF-P1-02)

Both BFF handlers (`network_security.py`, `datasec.py`) currently call engine `/ui-data` endpoints. This story migrates both to `read_findings()`.

## What to Build

### 1. Migrate `network_security.py` `view_network_security()`

```python
from ._shared import read_findings, read_posture, fetch_scan_trend

async def view_network_security(tenant_id, account_id=None, provider=None, region=None, auth_headers={}) -> dict:
    findings_result = await read_findings(
        tenant_id=tenant_id,
        source_engines=["network"],
        account_id=account_id,
        provider=provider,
        region=region,
        limit=2000,
    )
    findings = findings_result["findings"]
    by_severity = findings_result["by_severity"]

    posture_result = await read_posture(
        tenant_id=tenant_id,
        account_id=account_id,
        provider=provider,
    )

    scan_trend = await fetch_scan_trend(tenant_id, auth_headers)

    return {
        "findings":        [_enrich_for_ui(f) for f in findings],
        "security_groups": _extract_sg_findings(findings),
        "internet_exposure": _extract_exposure_findings(findings),
        "topology":        _build_topology(posture_result["posture"]),
        "waf":             _extract_waf_findings(findings),
        "kpiGroups":       _build_kpi_groups(by_severity),
        "scanTrend":       scan_trend,
        "domainBreakdown": _build_domain_breakdown(findings),
        "pageContext":     _build_page_context(),
    }
```

Keep all existing `_enrich_for_ui()`, `_extract_sg_findings()` etc. helpers — only data source changes.

Remove: `("network", "/api/v1/network-security/ui-data", {...})` HTTP call.

### 2. Migrate `datasec.py` `view_datasec()`

```python
async def view_datasec(tenant_id, account_id=None, provider=None, region=None, auth_headers={}) -> dict:
    findings_result = await read_findings(
        tenant_id=tenant_id,
        source_engines=["datasec"],
        account_id=account_id,
        limit=2000,
    )
    findings = findings_result["findings"]

    scan_trend = await fetch_scan_trend(tenant_id, auth_headers)

    # Keep lineage from engine (not in security_findings — keep HTTP call for lineage only)
    lineage_raw = await call_engine("datasec", "/api/v1/datasec/lineage",
        params={"tenant_id": tenant_id}, auth_headers=auth_headers) or {}
    lineage = {"lineage_chains": [_normalize_chain(c) for c in lineage_raw.get("chains", [])]}

    return {
        "findings":        findings,
        "catalog":         _build_catalog(findings),
        "dlp":             _extract_dlp(findings),
        "residency":       _extract_residency(findings),
        "accessMonitoring": _extract_access_monitoring(findings),
        "scanTrend":       scan_trend,
        "lineage":         lineage,
        "kpiGroups":       _build_kpi_groups(findings_result["by_severity"]),
    }
```

Note: datasec **keeps** the lineage HTTP call — lineage chains are not in `security_findings`.

## Acceptance Criteria

### AC-01 — Network page loads from DB
`/api/v1/views/network-security` returns findings from `security_findings WHERE source_engine='network'`.

### AC-02 — DataSec page loads from DB
`/api/v1/views/datasec` returns findings from `security_findings WHERE source_engine='datasec'`.

### AC-03 — Engine unavailability resilience
Kill network engine pod — network security page still shows existing findings from DB.
Kill datasec engine pod — datasec page shows findings from DB (lineage shows empty, not crash).

### AC-04 — Output shapes unchanged
Both pages render correctly — no UI changes required.

### AC-05 — Tenant isolation
All `read_findings()` calls pass `tenant_id`.

## Cleanup Steps (After Testing)

1. `grep "network-security/ui-data\|datasec/ui-data" shared/api_gateway/bff/` → 0 hits
2. Kill network engine, verify page still loads
3. Kill datasec engine, verify findings page still loads, lineage shows empty
4. Restart both engines
5. Rebuild gateway, verify rollout

## Definition of Done

- [ ] `network_security.py` reads from `security_findings`
- [ ] `datasec.py` reads findings from `security_findings`, keeps lineage HTTP call
- [ ] Engine HTTP calls for findings removed from both BFF files
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup completed
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-arch-net-ds1`