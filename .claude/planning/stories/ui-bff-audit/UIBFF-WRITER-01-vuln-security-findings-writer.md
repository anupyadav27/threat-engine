# Story UIBFF-WRITER-01: Vulnerability Engine → security_findings Writer

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-WRITER — Fill Missing Engine Writers
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 5
- **Priority**: P1 (vulnerability data absent from unified findings layer)
- **Depends on**: `deferred_vuln_segregation` migration (see memory) — `scan_vulnerabilities` table must have `tenant_id`, `account_id`, `resource_uid`, `scan_run_id` columns before this story
- **Blocks**: UIBFF-ARCH (vulnerability BFF migration)

## User Story

As a security engineer, I want vulnerability CVE findings to appear in the unified `security_findings` table so that asset detail pages, risk ETL, and future BFF queries can include vulnerability severity counts alongside check/IAM/network findings.

## Context

The `security_findings` table in `threat_engine_inventory` DB was built in sprint SF (migration `025_security_findings.sql`). Seven engines already write to it:
`check`, `iam`, `network`, `datasec`, `cdr`, `container`, (api-security via ETL).

**Vulnerability engine is missing.** Root cause (from memory): `scan_vulnerabilities` table is missing `tenant_id`, `account_id`, `resource_uid`, `scan_run_id` columns — the write path cannot scope findings without them.

The deferred migration (`deferred_vuln_segregation` in memory) has SQL written but not yet applied. This story assumes that migration has been applied first.

## What to Build

### 1. Apply deferred migration (pre-condition check)

Verify columns exist before writing any code:
```sql
SELECT column_name FROM information_schema.columns
WHERE table_name = 'scan_vulnerabilities'
  AND column_name IN ('tenant_id', 'account_id', 'resource_uid', 'scan_run_id');
```
If < 4 rows returned, this story is blocked — apply `deferred_vuln_segregation` migrations first.

### 2. Add `write_to_security_findings()` in vulnerability engine `run_scan.py`

File: `engines/vulnerability/run_scan.py` (after scan loop completes).

```python
from engine_common.security_findings_writer import upsert_findings

def _emit_vuln_findings(scan_run_id: str, tenant_id: str) -> None:
    """Read completed scan_vulnerabilities rows and upsert into security_findings."""
    from engine_common.db_connections import get_vulnerability_conn, get_inventory_conn

    with get_vulnerability_conn() as vconn:
        with vconn.cursor() as cur:
            cur.execute("""
                SELECT
                    v.vuln_id::text         AS source_finding_id,
                    v.resource_uid,
                    v.resource_type,
                    v.account_id,
                    v.region,
                    v.provider,
                    v.cve_id               AS rule_id,
                    v.severity,
                    'open'                  AS status,
                    v.package_name         AS title,
                    v.description,
                    v.remediation,
                    v.first_seen_at,
                    v.last_seen_at,
                    jsonb_build_object(
                        'cve_id', v.cve_id,
                        'cvss_score', v.cvss_score,
                        'epss_score', v.epss_score,
                        'is_kev', v.is_kev,
                        'package_name', v.package_name,
                        'package_version', v.package_version,
                        'fix_version', v.fix_version
                    )                      AS details
                FROM scan_vulnerabilities v
                WHERE v.scan_run_id = %s
                  AND v.tenant_id   = %s
                  AND v.severity IN ('critical', 'high', 'medium', 'low')
            """, (scan_run_id, tenant_id))
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]

    if not rows:
        return

    findings = []
    for row in rows:
        d = dict(zip(cols, row))
        findings.append({
            "source_engine":     "vuln",
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
            "status":            "open",
            "title":             d.get("title", ""),
            "description":       d.get("description"),
            "remediation":       d.get("remediation"),
            "posture_category":  "vulnerability",
            "details":           d.get("details") or {},
            "first_seen_at":     d.get("first_seen_at"),
            "last_seen_at":      d.get("last_seen_at"),
        })

    with get_inventory_conn() as iconn:
        upsert_findings(iconn, findings)
```

Call at end of `run_scan()` after all CVE processing is complete:
```python
_emit_vuln_findings(scan_run_id, tenant_id)
logger.info(f"Emitted {len(rows)} vuln findings to security_findings")
```

### 3. Add `vuln` to risk ETL `_wired_engines` set

File: `engines/risk/etl.py` (or `_collect_findings.py` — wherever `_wired_engines` is defined).

```python
_WIRED_ENGINES = {"check", "iam", "network", "datasec", "cdr", "container", "api_security", "vuln"}
```

This prevents the old legacy DB-direct vuln read from duplicating findings in risk scoring.

## Acceptance Criteria

### AC-01 — Vuln findings written after scan
After a vulnerability scan completes for a tenant, `security_findings` contains rows where `source_engine = 'vuln'` and `tenant_id = <that tenant>`.

### AC-02 — Multi-tenant isolation
`SELECT * FROM security_findings WHERE source_engine = 'vuln' AND tenant_id = 'tenant-A'` returns only tenant-A rows. Cross-tenant query returns 0.

### AC-03 — Deduplication on re-scan
Running a second scan for the same resource + CVE upserts (does not duplicate) the row. `first_seen_at` is preserved from the first write; `last_seen_at` updates.

### AC-04 — Empty scan does not crash
If `scan_vulnerabilities` returns 0 rows for a scan_run_id, `_emit_vuln_findings` returns early with no error.

### AC-05 — Severity values valid
All emitted rows have `severity` in `{'critical', 'high', 'medium', 'low'}`. No nulls or unexpected values.

### AC-06 — `posture_category` always `vulnerability`
All rows have `posture_category = 'vulnerability'` — the asset detail page uses this field to route to the Vulnerabilities tab.

## Technical Notes

- `engine_common.security_findings_writer.upsert_findings()` already exists (`shared/common/security_findings_writer.py`) — do not reimplement
- `upsert_findings()` batches in 500 rows and uses `ON CONFLICT (source_engine, source_finding_id, tenant_id) DO UPDATE` — first_seen_at is preserved
- JSONB `details` field: psycopg2 returns JSONB as dict — do not call `json.loads()` on it
- The `vuln` source_engine string must match exactly — check `shared/database/schemas/inventory_schema.sql` for the CHECK constraint
- Pre-condition: `scan_vulnerabilities.tenant_id` must exist — if migration not yet applied, this story cannot proceed

## Definition of Done

- [ ] `_emit_vuln_findings()` added to vulnerability `run_scan.py`
- [ ] Called after scan loop completes
- [ ] `"vuln"` added to `_WIRED_ENGINES` in risk ETL
- [ ] AC-01 through AC-06 verified
- [ ] New image built: `yadavanup84/engine-vulnerability:v-vuln-sf1`