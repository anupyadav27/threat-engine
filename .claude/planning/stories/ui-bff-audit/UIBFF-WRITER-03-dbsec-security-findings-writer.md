# Story UIBFF-WRITER-03: DBSec Engine → security_findings Writer

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-WRITER — Fill Missing Engine Writers
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 2
- **Priority**: P2 (database security findings absent from unified layer)
- **Depends on**: None
- **Blocks**: UIBFF-ARCH (dbsec BFF migration)

## User Story

As a security engineer, I want database security findings written to `security_findings` so that RDS/database assets in the inventory detail page show their DBSec posture alongside check and network findings.

## Context

The DBSec engine (`engines/dbsec/`) scans database services and writes to its own `dbsec_findings` table. It does NOT currently write to `security_findings`. Current image `v-dbsec-pc2` added posture signals but no unified findings writer.

The `posture_category` for DBSec rows should be `'database_security'`.

## What to Build

### 1. Add `_emit_dbsec_findings()` to DBSec `run_scan.py`

```python
from engine_common.security_findings_writer import upsert_findings
from engine_common.db_connections import get_dbsec_conn, get_inventory_conn

def _emit_dbsec_findings(scan_run_id: str, tenant_id: str) -> None:
    with get_dbsec_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    finding_id::text    AS source_finding_id,
                    tenant_id,
                    account_id,
                    provider,
                    region,
                    resource_uid,
                    resource_type,
                    rule_id,
                    severity,
                    status,
                    title,
                    description,
                    remediation,
                    first_seen_at,
                    last_seen_at
                FROM dbsec_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                  AND severity IN ('critical', 'high', 'medium', 'low')
            """, (scan_run_id, tenant_id))
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]

    if not rows:
        return

    findings = []
    for row in rows:
        d = dict(zip(cols, row))
        findings.append({
            "source_engine":     "dbsec",
            "source_finding_id": d["source_finding_id"],
            "tenant_id":         tenant_id,
            "scan_run_id":       scan_run_id,
            "account_id":        d.get("account_id", ""),
            "provider":          d.get("provider", ""),
            "region":            d.get("region"),
            "resource_uid":      d.get("resource_uid", ""),
            "resource_type":     d.get("resource_type", ""),
            "rule_id":           d.get("rule_id", ""),
            "severity":          d.get("severity", "medium"),
            "status":            d.get("status", "open"),
            "title":             d.get("title", ""),
            "description":       d.get("description"),
            "remediation":       d.get("remediation"),
            "posture_category":  "database_security",
            "details":           {},
            "first_seen_at":     d.get("first_seen_at"),
            "last_seen_at":      d.get("last_seen_at"),
        })

    with get_inventory_conn() as iconn:
        upsert_findings(iconn, findings)
```

Call after the main scan loop in `run_scan.py`.

### 2. Add `"dbsec"` to risk ETL `_wired_engines`

Prevent double-counting when risk ETL migrates to reading `security_findings`.

## Acceptance Criteria

### AC-01 — DBSec findings written after scan
After a DBSec scan, `security_findings` contains `source_engine = 'dbsec'` rows with `posture_category = 'database_security'`.

### AC-02 — Multi-tenant isolation
Findings scoped by `tenant_id`. No cross-tenant leakage.

### AC-03 — ON CONFLICT upsert
Re-scan updates `last_seen_at` without duplicating rows.

### AC-04 — No crash on empty scan
Zero findings → early return.

## Technical Notes

- Verify `dbsec_findings` table columns with `\d dbsec_findings` before running — column names may differ from `dbsec_findings` pattern
- The `"dbsec"` source_engine value must be in `security_findings` CHECK constraint
- Current image `v-dbsec-pc2` — new image will be `v-dbsec-sf1`

## Definition of Done

- [ ] `_emit_dbsec_findings()` added and called
- [ ] `"dbsec"` added to risk ETL `_wired_engines`
- [ ] AC-01 through AC-04 verified
- [ ] New image: `yadavanup84/engine-dbsec:v-dbsec-sf1`