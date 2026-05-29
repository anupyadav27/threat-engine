# DBSEC-FIX-01 — DBSec report write fails: tenant not provisioned in dbsec DB

## Status
`ready-for-dev`

## Problem
The `engine-dbsec` inline API path (`_run_scan_sync` → `_write_dbsec_report`) fails to write to
`dbsec_report` with:

```
dbsec_report write failed (non-fatal): insert or update on table "dbsec_report" violates
foreign key constraint "fk_dbsec_report_tenant"
DETAIL: Key (tenant_id)=(tenant-finance-001) is not present in table "tenants".
```

Root cause: `_write_dbsec_report` in `engines/dbsec/dbsec_engine/api_server.py` inserts directly
into `dbsec_report` without first ensuring the tenant row exists in the **dbsec DB's** `tenants`
table. The inventory DB tenant is provisioned correctly (line 284) but that is a different DB
connection (`_inv_conn`), not `dbsec_conn`.

The `run_scan.py` path and `storage/dbsec_db_writer.py` already have the upsert, so Job-based
scans work. Only the inline API path is broken.

## Affected File
`engines/dbsec/dbsec_engine/api_server.py` — `_write_dbsec_report()` function (~line 170)

## Fix

In `_write_dbsec_report`, add a tenant upsert using `dbsec_conn` before the `dbsec_report` INSERT:

```python
def _write_dbsec_report(
    dbsec_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    ...
) -> None:
    try:
        with dbsec_conn.cursor() as cur:
            # Ensure tenant row exists before FK-constrained INSERT
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT (tenant_id) DO NOTHING",
                (tenant_id, tenant_id),
            )
            cur.execute(
                "INSERT INTO dbsec_report ...",
                ...
            )
        dbsec_conn.commit()
    except Exception as exc:
        logger.warning("dbsec_report write failed (non-fatal): %s", exc)
```

## Acceptance Criteria
- [ ] Trigger a dbsec scan for a tenant that has never been scanned before
- [ ] `dbsec_report` row is written with `status=completed`
- [ ] No FK violation in dbsec engine logs
- [ ] `tenants` table in `threat_engine_dbsec` has the new tenant row after scan
- [ ] Existing scans (tenants already in tenants table) are unaffected

## Pipeline Impact
`database-security` step in the Argo pipeline fails for all tenants not yet in the dbsec `tenants`
table. Currently 100% failure rate for new tenants since the inline scan path is the only path
called by the pipeline.

## Deploy
After code fix:
```bash
docker build -t yadavanup84/engine-dbsec:v-dbsec-fix1 -f engines/dbsec/Dockerfile .
docker push yadavanup84/engine-dbsec:v-dbsec-fix1
kubectl set image deployment/engine-dbsec engine-dbsec=yadavanup84/engine-dbsec:v-dbsec-fix1 -n threat-engine-engines
```

## Notes
- Error is currently marked non-fatal in the code, so the scan completes but writes no report
- The Argo pipeline step fails because it polls `/api/v1/scan/{scan_run_id}/status` and the
  in-memory status transitions to `failed` when the report write fails
- No DB migration needed — `tenants` table already exists in `threat_engine_dbsec`