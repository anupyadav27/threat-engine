# Story APISEC-S1-12: Wire to security_findings Unified Table

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 2
- **Depends on**: APISEC-S1-02 (adds `api_security` to `_ALLOWED_ENGINES`), APISEC-S1-05
- **Blocks**: nothing (SF layer is additive)
- **Security Gate**: bmad-security-reviewer (`source_engine` value must match _ALLOWED_ENGINES exactly)

## Context

`shared/common/security_findings_writer.py` contains `upsert_findings()` which writes to the
`security_findings` table in `threat_engine_inventory`. APISEC-S1-02 adds `'api_security'` to
`_ALLOWED_ENGINES`. This story wires the actual call in `run_scan.py`.

The call is already present in the APISEC-S1-05 `run_scan.py` code:

```python
from engine_common.security_findings_writer import upsert_findings
upsert_findings(inv_conn, findings, source_engine="api_security",
                finding_type="api_exposure")
```

This story validates the call is correct and ensures `upsert_findings()` supports
`finding_type="api_exposure"` without schema changes.

## Changes Required

### 1. Verify `finding_type` column accepts `api_exposure`

`finding_type` in `security_findings` is `VARCHAR(30)` (not an ENUM) — confirmed in
migration `025_security_findings.sql`. No DDL change needed.

### 2. Mapping in `security_findings_writer.py`

The `upsert_findings()` call maps finding fields to `security_findings` columns:

```python
# shared/common/security_findings_writer.py
# This mapping is already in upsert_findings(); verify these keys exist in api_security findings:

_FIELD_MAP = {
    "source_engine":     "api_security",      # constant
    "source_finding_id": finding["rule_id"] + "|" + finding["resource_uid"],
    "tenant_id":         tenant_id,           # from run_scan param
    "account_id":        finding.get("account_id", ""),
    "provider":          finding.get("provider", ""),
    "region":            finding.get("region", ""),
    "resource_uid":      finding.get("resource_uid", ""),
    "resource_type":     finding.get("resource_type", ""),
    "severity":          finding.get("severity", "low"),
    "finding_type":      finding_type,        # "api_exposure"
    "title":             finding.get("title", ""),
    "description":       finding.get("description", ""),
    "remediation":       finding.get("remediation", ""),
    "status":            "open",
    "rule_id":           finding.get("rule_id", ""),
    "first_seen_at":     "NOW()",
    "last_seen_at":      "NOW()",
}
```

### 3. No changes needed to `security_findings` table schema

The `finding_type = 'api_exposure'` value is new but the column is VARCHAR(30) — it accepts
any string up to 30 chars. No migration required.

## Acceptance Criteria

- [ ] AC-1: After scan completes, `SELECT COUNT(*) FROM security_findings WHERE source_engine='api_security'` returns non-zero for scans with API gateway findings
- [ ] AC-2: `upsert_findings(source_engine='api_security', finding_type='api_exposure', ...)` does NOT raise `ValueError` (source_engine in _ALLOWED_ENGINES)
- [ ] AC-3: `source_finding_id` = `rule_id|resource_uid` — UNIQUE across all api_security findings for a tenant
- [ ] AC-4: Finding appears in `security_findings` with `finding_type='api_exposure'` — confirms new type stored correctly
- [ ] AC-5: Verify `finding_type` column is VARCHAR(30) not ENUM: `SELECT data_type, character_maximum_length FROM information_schema.columns WHERE table_name='security_findings' AND column_name='finding_type'` → `character varying | 30`

## Definition of Done
- [ ] `run_scan.py` `upsert_findings()` call in place (already in APISEC-S1-05 code)
- [ ] APISEC-S1-02 `_ALLOWED_ENGINES` update confirmed deployed
- [ ] AC-1 query returns rows after a real scan against an AWS account with API gateways
