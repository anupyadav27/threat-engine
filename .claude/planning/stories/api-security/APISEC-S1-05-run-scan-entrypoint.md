# Story APISEC-S1-05: run_scan.py — Entry Point + Tenant Validation + Report Pre-Create

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 4
- **Depends on**: APISEC-S1-03, APISEC-S1-04
- **Blocks**: APISEC-S1-08 (provider called from here)
- **Security Gate**: bmad-security-reviewer (tenant isolation in scan entry point is a P0 blocker)

## Implementation

**File**: `engines/api-security/run_scan.py`

```python
import argparse
import json
import logging
import signal
import sys
from datetime import datetime, timezone
from uuid import UUID

from engine_common.db_connections import (
    get_api_security_conn,
    get_discoveries_conn,
    get_check_conn,
    get_inventory_conn,
)
from api_security_engine.providers import get_provider
from api_security_engine.storage.db_writer import APISecWriter
from api_security_engine.storage.posture_signals import write_api_posture_signals
from api_security_engine.enricher.cdr_enricher import CDREnricher

logging.basicConfig(level=logging.INFO,
                    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s","engine":"api-security"}')
logger = logging.getLogger("api_security.run_scan")

_shutdown = False

def _handle_sigterm(signum, frame):
    global _shutdown
    logger.warning('{"msg":"SIGTERM received — marking scan failed","engine":"api-security"}')
    _shutdown = True

signal.signal(signal.SIGTERM, _handle_sigterm)


def _validate_scan_ownership(discoveries_conn, scan_run_id: str, tenant_id: str) -> dict:
    """Verify scan_run_id belongs to tenant. Returns orchestration metadata."""
    with discoveries_conn.cursor() as cur:
        cur.execute("""
            SELECT scan_run_id, tenant_id, account_id, provider,
                   credential_ref, credential_type, region
            FROM scan_orchestration
            WHERE scan_run_id = %s AND tenant_id = %s
        """, (scan_run_id, tenant_id))
        row = cur.fetchone()
    if not row:
        raise ValueError(
            f"scan_run_id {scan_run_id} not found for tenant {tenant_id} — "
            "possible cross-tenant injection attempt"
        )
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))


def _pre_create_report(apisec_conn, scan_run_id: str, tenant_id: str,
                        provider: str, account_id: str) -> None:
    """Upsert api_security_report row with status=running."""
    with apisec_conn.cursor() as cur:
        cur.execute("""
            INSERT INTO api_security_report
                (scan_run_id, tenant_id, provider, account_id, status, started_at)
            VALUES (%s, %s, %s, %s, 'running', NOW())
            ON CONFLICT (scan_run_id) DO UPDATE SET
                status = 'running',
                started_at = NOW()
        """, (scan_run_id, tenant_id, provider, account_id))
        # Upsert tenant anchor
        cur.execute(
            "INSERT INTO tenants (tenant_id) VALUES (%s) ON CONFLICT DO NOTHING",
            (tenant_id,)
        )
    apisec_conn.commit()


def _mark_report_complete(apisec_conn, scan_run_id: str, tenant_id: str,
                           counts: dict, status: str = "completed") -> None:
    with apisec_conn.cursor() as cur:
        cur.execute("""
            UPDATE api_security_report SET
                status          = %s,
                completed_at    = NOW(),
                critical_count  = %s,
                high_count      = %s,
                medium_count    = %s,
                low_count       = %s,
                total_findings  = %s,
                owasp_api1_count = %s,
                owasp_api2_count = %s,
                owasp_api4_count = %s,
                owasp_api7_count = %s,
                owasp_api8_count = %s,
                owasp_api9_count = %s,
                cdr_enriched_count = %s
            WHERE scan_run_id = %s AND tenant_id = %s
        """, (
            status,
            counts.get("critical", 0), counts.get("high", 0),
            counts.get("medium", 0), counts.get("low", 0),
            counts.get("total", 0),
            counts.get("API1", 0), counts.get("API2", 0),
            counts.get("API4", 0), counts.get("API7", 0),
            counts.get("API8", 0), counts.get("API9", 0),
            counts.get("cdr_enriched", 0),
            scan_run_id, tenant_id
        ))
    apisec_conn.commit()


def run(scan_run_id: str, tenant_id: str, account_id: str,
        provider: str, credential_ref: str, credential_type: str,
        region: str | None = None) -> None:

    logger.info(f"Starting API security scan scan_run_id={scan_run_id} "
                f"tenant={tenant_id} provider={provider}")

    with get_discoveries_conn() as disc_conn, \
         get_api_security_conn() as apisec_conn, \
         get_check_conn() as check_conn, \
         get_inventory_conn() as inv_conn:

        # P0: validate tenant ownership of scan_run_id before any work
        meta = _validate_scan_ownership(disc_conn, scan_run_id, tenant_id)
        _pre_create_report(apisec_conn, scan_run_id, tenant_id, provider, account_id)

        if _shutdown:
            _mark_report_complete(apisec_conn, scan_run_id, tenant_id, {}, "failed")
            sys.exit(1)

        # Run provider analysis
        prov = get_provider(provider)
        findings = prov.analyze(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            discoveries_conn=disc_conn,
            check_conn=check_conn,
        )

        if _shutdown:
            _mark_report_complete(apisec_conn, scan_run_id, tenant_id, {}, "failed")
            sys.exit(1)

        # Write findings
        writer = APISecWriter(apisec_conn)
        writer.write(findings, scan_run_id, tenant_id)

        # Write posture signals
        write_api_posture_signals(inv_conn, findings, scan_run_id, tenant_id)

        # Wire to security_findings (cross-engine unified table)
        from engine_common.security_findings_writer import upsert_findings
        upsert_findings(inv_conn, findings, source_engine="api_security",
                        finding_type="misconfig")

        # Compute report counts
        counts = _compute_counts(findings)
        _mark_report_complete(apisec_conn, scan_run_id, tenant_id, counts)

        logger.info(f"API security scan complete: {counts['total']} findings "
                    f"({counts['critical']} critical)")


def _compute_counts(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings),
              "API1": 0, "API2": 0, "API4": 0, "API7": 0, "API8": 0, "API9": 0,
              "cdr_enriched": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1
        cat = f.get("owasp_api_category", "")
        if cat in counts:
            counts[cat] += 1
        if f.get("finding_source") in ("behavioral", "correlated"):
            counts["cdr_enriched"] += 1
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-run-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--credential-ref", required=True)
    parser.add_argument("--credential-type", required=True)
    parser.add_argument("--region", default=None)
    args = parser.parse_args()

    try:
        run(
            scan_run_id=args.scan_run_id,
            tenant_id=args.tenant_id,
            account_id=args.account_id,
            provider=args.provider,
            credential_ref=args.credential_ref,
            credential_type=args.credential_type,
            region=args.region,
        )
    except Exception as e:
        logger.error(f"run_scan fatal error: {e}", exc_info=True)
        sys.exit(1)
```

## Acceptance Criteria

- [ ] AC-1: SIGTERM received mid-scan → report marked `status='failed'`, process exits 1 cleanly
- [ ] AC-2: `scan_run_id` belonging to a different tenant → `ValueError` raised, scan does not start, no findings written
- [ ] AC-3: `api_security_report` row has `status='running'` immediately after pre-create, before provider runs
- [ ] AC-4: After successful scan, report row has `status='completed'`, `completed_at` set, counts non-zero
- [ ] AC-5: All DB connections use context managers — no connection leak on exception
- [ ] AC-6: JSONB fields from psycopg2 are NOT passed through `json.loads()` — CSPM Constitution violation

## Definition of Done
- [ ] `run_scan.py` committed, all args wired
- [ ] Tenant ownership validation tested with a cross-tenant `scan_run_id` (should raise ValueError)
- [ ] SIGTERM test: `kill -SIGTERM <pid>` mid-scan → report shows `failed`
