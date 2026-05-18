# Story UIBFF-WRITER-02: SecOps Engine → security_findings Writer

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-WRITER — Fill Missing Engine Writers
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P1 (SAST/DAST/SCA findings absent from unified findings layer)
- **Depends on**: None (secops DB schema already has required columns)
- **Blocks**: UIBFF-ARCH (secops BFF migration)

## User Story

As a security engineer, I want SAST, DAST, and SCA findings from the SecOps engine written to `security_findings` so that asset detail pages and risk scoring can include code security findings alongside cloud posture findings.

## Context

The SecOps engine (`engines/secops/`) stores results in:
- `sast_scan_results` table — code findings by file/line/rule
- `dast_scan_results` table — API endpoint findings
- `secops_latest_scan` table — latest scan summary per repo

Neither writes to `security_findings`. The unified table needs `source_engine = 'secops'` rows to appear in inventory asset detail "SecOps" tab.

Key difference from other writers: SecOps findings are scoped to **repos/projects** (not cloud resource UIDs). The `resource_uid` field should be the repo URL or project ID. The `posture_category` should be `'code_security'`.

## What to Build

### 1. Add `_emit_secops_findings()` to SecOps scan completion

File: `engines/secops/run_scan.py` (or wherever the scan completion hook is — check for existing `_on_scan_complete` or similar).

```python
from engine_common.security_findings_writer import upsert_findings
from engine_common.db_connections import get_secops_conn, get_inventory_conn

def _emit_secops_findings(scan_run_id: str, tenant_id: str) -> None:
    """Emit SAST + DAST findings to security_findings after scan completes."""
    with get_secops_conn() as conn:
        with conn.cursor() as cur:
            # SAST findings
            cur.execute("""
                SELECT
                    r.result_id::text        AS source_finding_id,
                    r.scan_run_id,
                    r.tenant_id,
                    r.severity,
                    r.rule_id,
                    r.message               AS title,
                    r.description,
                    r.remediation,
                    r.file_path,
                    r.language,
                    s.repo_url              AS resource_uid,
                    s.account_id,
                    s.provider,
                    r.created_at            AS first_seen_at,
                    r.created_at            AS last_seen_at
                FROM sast_scan_results r
                JOIN secops_scans s ON s.scan_id = r.scan_id
                WHERE r.scan_run_id = %s AND r.tenant_id = %s
                  AND r.severity IN ('critical', 'high', 'medium', 'low')
            """, (scan_run_id, tenant_id))
            sast_rows = cur.fetchall()
            sast_cols = [d[0] for d in cur.description]

            # DAST findings
            cur.execute("""
                SELECT
                    r.result_id::text        AS source_finding_id,
                    r.scan_run_id,
                    r.tenant_id,
                    r.severity,
                    r.rule_id,
                    r.description           AS title,
                    r.description,
                    r.remediation,
                    r.endpoint_url          AS resource_uid,
                    s.account_id,
                    s.provider,
                    r.created_at            AS first_seen_at,
                    r.created_at            AS last_seen_at
                FROM dast_scan_results r
                JOIN secops_scans s ON s.scan_id = r.scan_id
                WHERE r.scan_run_id = %s AND r.tenant_id = %s
                  AND r.severity IN ('critical', 'high', 'medium', 'low')
            """, (scan_run_id, tenant_id))
            dast_rows = cur.fetchall()
            dast_cols = [d[0] for d in cur.description]

    findings = []
    for row in sast_rows:
        d = dict(zip(sast_cols, row))
        findings.append({
            "source_engine":     "secops",
            "source_finding_id": f"sast-{d['source_finding_id']}",
            "tenant_id":         tenant_id,
            "scan_run_id":       scan_run_id,
            "account_id":        d.get("account_id", ""),
            "provider":          d.get("provider", ""),
            "region":            None,
            "resource_uid":      d.get("resource_uid", ""),
            "resource_type":     "code_repository",
            "rule_id":           d.get("rule_id", ""),
            "severity":          d.get("severity", "medium"),
            "status":            "open",
            "title":             d.get("title", ""),
            "description":       d.get("description"),
            "remediation":       d.get("remediation"),
            "posture_category":  "code_security",
            "details":           {"scan_type": "sast", "file_path": d.get("file_path"), "language": d.get("language")},
            "first_seen_at":     d.get("first_seen_at"),
            "last_seen_at":      d.get("last_seen_at"),
        })

    for row in dast_rows:
        d = dict(zip(dast_cols, row))
        findings.append({
            "source_engine":     "secops",
            "source_finding_id": f"dast-{d['source_finding_id']}",
            "tenant_id":         tenant_id,
            "scan_run_id":       scan_run_id,
            "account_id":        d.get("account_id", ""),
            "provider":          d.get("provider", ""),
            "region":            None,
            "resource_uid":      d.get("resource_uid", ""),
            "resource_type":     "api_endpoint",
            "rule_id":           d.get("rule_id", ""),
            "severity":          d.get("severity", "medium"),
            "status":            "open",
            "title":             d.get("title", ""),
            "description":       d.get("description"),
            "remediation":       d.get("remediation"),
            "posture_category":  "code_security",
            "details":           {"scan_type": "dast"},
            "first_seen_at":     d.get("first_seen_at"),
            "last_seen_at":      d.get("last_seen_at"),
        })

    if not findings:
        return

    with get_inventory_conn() as iconn:
        upsert_findings(iconn, findings)
```

### 2. Verify secops scan table column names

Before writing the query, verify actual column names:
```bash
kubectl exec -n threat-engine-engines deployment/engine-secops -- python3 -c "
from engine_common.db_connections import get_secops_conn
with get_secops_conn() as c:
    with c.cursor() as cur:
        cur.execute(\"SELECT column_name FROM information_schema.columns WHERE table_name='sast_scan_results'\")
        print([r[0] for r in cur.fetchall()])
"
```
Adjust column names in the query to match actual schema.

### 3. Add `"secops"` to risk ETL `_wired_engines`

Same pattern as WRITER-01 — prevent double-counting in risk scoring.

## Acceptance Criteria

### AC-01 — SAST/DAST findings written after scan
After a SecOps scan completes, `security_findings` contains `source_engine = 'secops'` rows with `posture_category = 'code_security'`.

### AC-02 — Multi-tenant isolation
SecOps findings for tenant-A are not visible in tenant-B's query.

### AC-03 — Deduplication
Re-running the same repo scan does not duplicate findings. ON CONFLICT updates `last_seen_at` only.

### AC-04 — Empty scan does not crash
Zero SAST/DAST rows → early return, no error.

### AC-05 — `source_finding_id` unique per type
SAST rows prefixed `sast-{id}`, DAST rows prefixed `dast-{id}` to prevent conflicts in the UNIQUE constraint.

## Technical Notes

- `get_secops_conn()` must exist in `engine_common.db_connections` — verify; if not, use environment variable `SECOPS_DB_HOST`
- Column names in `sast_scan_results` / `dast_scan_results` must be verified from live schema before writing query
- SCA (dependency CVEs) deliberately excluded from this writer — they map to vuln engine findings instead
- The `source_engine` value `"secops"` must be in the CHECK constraint on `security_findings.source_engine` — verify in `025_security_findings.sql`

## Definition of Done

- [ ] `_emit_secops_findings()` added and called on scan completion
- [ ] SAST prefix `sast-` and DAST prefix `dast-` applied to source_finding_id
- [ ] `"secops"` added to risk ETL `_wired_engines`
- [ ] AC-01 through AC-05 verified
- [ ] New image: `yadavanup84/secops-scanner:v-secops-sf1`