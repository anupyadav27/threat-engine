# Story UIBFF-ARCH-04: CDR + Encryption + Container BFF — Migrate to security_findings Table

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-ARCH — Two-Table BFF Architecture Migration
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P2
- **Depends on**: UIBFF-BFF-01, UIBFF-WRITER-04 (encryption writer), CDR+container already writing to security_findings
- **Blocks**: None

## User Story

As a developer, I want CDR, Encryption, and Container Security BFF handlers to read from `security_findings` so they are resilient to engine downtime and data is consistent across all pages.

## Context

All three engines already write to `security_findings`:
- CDR: `source_engine="cdr"`, `posture_category="threat_detection"` (SF-P1-02)
- Container: `source_engine="container"` (SF-P1-02)
- Encryption: `source_engine="encryption"` after WRITER-04 ships

## What to Build

### 1. Migrate `cdr.py` findings fetch

```python
async def view_cdr(tenant_id, account_id=None, provider=None, auth_headers={}) -> dict:
    # Findings from security_findings
    findings_result = await read_findings(
        tenant_id=tenant_id,
        source_engines=["cdr"],
        account_id=account_id,
        limit=2000,
    )
    findings = findings_result["findings"]

    # Identity aggregation still calls CDR engine (identities not in security_findings)
    identities_raw = await call_engine("cdr", "/api/v1/cdr/identities",
        params={"tenant_id": tenant_id, "limit": 100}, auth_headers=auth_headers) or []

    scan_trend = await fetch_scan_trend(tenant_id, auth_headers)

    return {
        # ... existing shape using findings from DB + identities from engine
        "findings":        findings,
        "identities":      [_normalize_identity(i) for i in identities_raw],
        "totalFindings":   findings_result["total"],
        "scanTrend":       scan_trend,
        "kpiGroups":       _build_kpi_groups(findings_result["by_severity"]),
        # heatmap, topCritical, topRules, logSources still from engine call
    }
```

CDR **keeps** identity + heatmap + log sources from engine calls (these are not in security_findings).

### 2. Migrate `encryption.py` findings fetch

```python
async def view_encryption(tenant_id, account_id=None, provider=None, auth_headers={}) -> dict:
    findings_result = await read_findings(
        tenant_id=tenant_id,
        source_engines=["encryption"],
        account_id=account_id,
        limit=2000,
    )
    findings = findings_result["findings"]
    scan_trend = await fetch_scan_trend(tenant_id, auth_headers)

    # Keys, certs, secrets still from engine (not in security_findings)
    engine_data = await call_engine("encryption", "/api/v1/encryption/ui-data",
        params={"tenant_id": tenant_id}, auth_headers=auth_headers) or {}

    return {
        "findings":        [_enrich_finding(f) for f in findings],
        "keys":            engine_data.get("keys", []),
        "certificates":    engine_data.get("certificates", []),
        "secrets":         engine_data.get("secrets", []),
        "kpiGroups":       _build_kpi_groups(findings_result["by_severity"]),
        "scanTrend":       scan_trend,
        "domainBreakdown": _build_domain_breakdown(findings),
        "pageContext":     _build_page_context(),
    }
```

Encryption **keeps** keys/certs/secrets from engine (these are resource objects, not findings).

### 3. Migrate `container_security.py` findings fetch

```python
async def view_container_security(tenant_id, account_id=None, provider=None, auth_headers={}) -> dict:
    findings_result = await read_findings(
        tenant_id=tenant_id,
        source_engines=["container"],
        account_id=account_id,
        limit=2000,
    )
    findings = findings_result["findings"]
    scan_trend = await fetch_scan_trend(tenant_id, auth_headers)

    # Clusters from engine (not in security_findings)
    engine_data = await call_engine("container-security", "/api/v1/container-security/ui-data",
        params={"tenant_id": tenant_id}, auth_headers=auth_headers) or {}

    return {
        "findings":        findings,
        "clusters":        engine_data.get("clusters", []),
        "domain_scores":   engine_data.get("domain_scores", {}),
        "kpiGroups":       _build_kpi_groups(findings_result["by_severity"]),
        "scanTrend":       scan_trend,
        "domainBreakdown": _build_domain_breakdown(findings),
        "pageContext":     _build_page_context(),
    }
```

## Acceptance Criteria

### AC-01 — CDR findings from DB
`/api/v1/views/cdr` returns `findings[]` from `security_findings WHERE source_engine='cdr'`.

### AC-02 — Encryption findings from DB (after WRITER-04)
`/api/v1/views/encryption` returns `findings[]` from `security_findings WHERE source_engine='encryption'`.

### AC-03 — Container findings from DB
`/api/v1/views/container-security` returns `findings[]` from `security_findings WHERE source_engine='container'`.

### AC-04 — Resource objects still from engine
CDR identities, encryption keys/certs/secrets, container clusters still fetched from engine HTTP (these are resource-level objects, not findings).

### AC-05 — Tenant isolation for all three
All `read_findings()` calls tenant-scoped.

## Cleanup Steps (After Testing)

1. `grep "cdr/ui-data\|encryption/ui-data\|container-security/ui-data" shared/api_gateway/bff/` → 0 hits for findings queries
2. Kill CDR engine, verify CDR page shows findings from DB; identities section shows empty
3. Rebuild gateway, verify rollout

## Definition of Done

- [ ] `cdr.py` findings from `security_findings`; identities/heatmap/log-sources keep engine calls
- [ ] `encryption.py` findings from `security_findings`; keys/certs/secrets keep engine calls
- [ ] `container_security.py` findings from `security_findings`; clusters keep engine calls
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup completed
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-arch-cdr-enc-ctr1`