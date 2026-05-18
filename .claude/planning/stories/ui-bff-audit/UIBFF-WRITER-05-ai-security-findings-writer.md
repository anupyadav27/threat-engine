# Story UIBFF-WRITER-05: AI Security Engine → security_findings Writer

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-WRITER — Fill Missing Engine Writers
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 2
- **Priority**: P2
- **Depends on**: None
- **Blocks**: UIBFF-ARCH AI-security migration

## User Story

As a security engineer, I want AI/ML security findings (shadow AI, misconfigured SageMaker/Bedrock endpoints) written to `security_findings` so they appear in asset detail pages alongside other engine findings.

## Context

AI Security engine (`engines/ai-security/`, image `v-ai-journey1`) writes posture signals to `resource_security_posture` but does NOT write findings to `security_findings`.

`posture_category` for AI Security rows = `'ai_security'`.

## What to Build

### 1. Verify AI security findings table name

```bash
kubectl exec -n threat-engine-engines deployment/engine-ai-security -- python3 -c "
from engine_common.db_connections import get_ai_security_conn
with get_ai_security_conn() as c:
    with c.cursor() as cur:
        cur.execute(\"SELECT table_name FROM information_schema.tables WHERE table_schema='public'\")
        print([r[0] for r in cur.fetchall()])
"
```

### 2. Add `_emit_ai_security_findings()` to `run_scan.py`

```python
from engine_common.security_findings_writer import upsert_findings
from engine_common.db_connections import get_ai_security_conn, get_inventory_conn

def _emit_ai_security_findings(scan_run_id: str, tenant_id: str) -> None:
    with get_ai_security_conn() as conn:
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
                FROM ai_security_findings
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
            "source_engine":     "ai_security",
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
            "posture_category":  "ai_security",
            "details":           {},
            "first_seen_at":     d.get("first_seen_at"),
            "last_seen_at":      d.get("last_seen_at"),
        })

    with get_inventory_conn() as iconn:
        upsert_findings(iconn, findings)
```

Call after main scan loop. Add `"ai_security"` to risk ETL `_wired_engines`.

## Acceptance Criteria

### AC-01 — AI Security findings written after scan
After AI Security scan, `security_findings` contains `source_engine = 'ai_security'` rows with `posture_category = 'ai_security'`.

### AC-02 — Multi-tenant isolation
Findings scoped by `tenant_id`.

### AC-03 — Upsert deduplication
Re-scan does not duplicate rows.

### AC-04 — No crash on empty
Zero findings → early return.

## Technical Notes

- source_engine value `"ai_security"` (with underscore) must match the CHECK constraint
- Current image: `v-ai-journey1` → new: `v-ai-sf1`

## Definition of Done

- [ ] `_emit_ai_security_findings()` added and called
- [ ] `"ai_security"` in risk ETL `_wired_engines`
- [ ] AC-01 through AC-04 verified
- [ ] New image: `yadavanup84/engine-ai-security:v-ai-sf1`