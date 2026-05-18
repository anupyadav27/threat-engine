# Story UIBFF-WRITER-04: Encryption Engine → security_findings Writer

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-WRITER — Fill Missing Engine Writers
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 2
- **Priority**: P2
- **Depends on**: None
- **Blocks**: UIBFF-FIX-04 (encryption key-detail BFF), UIBFF-ARCH encryption migration

## User Story

As a security engineer, I want encryption findings (unrotated keys, expiring certs, unencrypted resources) written to `security_findings` so that asset detail pages can show encryption posture inline with other findings.

## Context

Encryption engine (`engines/encryption/`) writes posture signals to `resource_security_posture` (PC-P1-01, image `v-encryption-pc1`) but does NOT write individual findings to `security_findings`.

This story adds the writer for encryption-specific finding rows (`posture_category = 'encryption'`).

## What to Build

### 1. Add `_emit_encryption_findings()` to `run_scan.py`

```python
from engine_common.security_findings_writer import upsert_findings
from engine_common.db_connections import get_encryption_conn, get_inventory_conn

def _emit_encryption_findings(scan_run_id: str, tenant_id: str) -> None:
    with get_encryption_conn() as conn:
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
                FROM encryption_findings
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
            "source_engine":     "encryption",
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
            "posture_category":  "encryption",
            "details":           {},
            "first_seen_at":     d.get("first_seen_at"),
            "last_seen_at":      d.get("last_seen_at"),
        })

    with get_inventory_conn() as iconn:
        upsert_findings(iconn, findings)
```

Call after the main scan loop. Add `"encryption"` to risk ETL `_wired_engines`.

### 2. Verify encryption_findings table exists

Encryption engine may store findings in a different table (e.g., `kms_findings`, `cert_findings`). Check actual schema before writing query:
```bash
kubectl exec -n threat-engine-engines deployment/engine-encryption -- python3 -c "
from engine_common.db_connections import get_encryption_conn
with get_encryption_conn() as c:
    with c.cursor() as cur:
        cur.execute(\"SELECT table_name FROM information_schema.tables WHERE table_schema='public'\")
        print([r[0] for r in cur.fetchall()])
"
```

If findings are split across multiple tables (kms, cert, secrets), run separate queries for each and merge into the `findings` list with different `rule_id` prefixes.

## Acceptance Criteria

### AC-01 — Encryption findings written after scan
After encryption scan, `security_findings` contains `source_engine = 'encryption'` rows.

### AC-02 — Multi-tenant isolation
Findings scoped by `tenant_id`.

### AC-03 — Upsert deduplication
Re-scan does not duplicate rows.

### AC-04 — No crash on empty
Zero findings → early return.

## Technical Notes

- The `"encryption"` source_engine value must be in `security_findings` CHECK constraint — if not, add it to migration SQL
- Current image: `v-encryption-pc1` → new image: `v-encryption-sf1`

## Definition of Done

- [ ] `_emit_encryption_findings()` added and called
- [ ] `"encryption"` in risk ETL `_wired_engines`
- [ ] AC-01 through AC-04 verified
- [ ] New image: `yadavanup84/engine-encryption:v-encryption-sf1`