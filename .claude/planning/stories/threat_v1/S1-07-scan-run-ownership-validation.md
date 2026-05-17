# Story S1-07: scan_run_id Ownership Validation — Step 0 in run_scan.py (CP1-07)

## Status: ready

## Metadata
- **Sprint**: 1 — Foundation: Schema + GraphBuilder
- **Points**: 3
- **Priority**: P0 — Security gate, not a feature
- **Depends on**: S1-02 (threat_scan_runs_v1 table), S1-03 (main.py structure)
- **Blocks**: S1-08 (integration test must invoke run_scan.py which has this gate)
- **RACI**: R=DEV A=SA C=SR I=DL,PO
- **Security Gate**: SA is accountable. SR consulted. This story exists purely as a security gate.

## Context

Argo Workflows passes `scan_run_id`, `tenant_id`, `account_id` as template parameters to `run_scan.py`. An adversary who can tamper with Argo parameters (e.g. via workflow injection) could supply a `scan_run_id` belonging to another tenant — causing the GraphBuilder to read that tenant's data into a different tenant's graph.

Step 0 in `run_scan.py` prevents this: before any DB read, validate that the `scan_run_id` is owned by the claimed `tenant_id + account_id` in `scan_orchestration`. If not, abort.

The per-tenant advisory lock also uses `hashtext(tenant_id || '|' || account_id)` — not `tenant_id` alone — to prevent concurrent graph builds for the same tenant+account combination (W-01).

## Technical Notes

### Output file
`engines/threat_v1/threat_v1/run_scan.py`

### Step 0 — ownership validation

```python
def validate_ownership(conn, scan_run_id: str, tenant_id: str, account_id: str) -> None:
    """
    CP1-07: Verify scan_run_id belongs to tenant_id + account_id
    in scan_orchestration before any DB reads.
    Aborts with sys.exit(1) on failure.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM scan_orchestration "
        "WHERE scan_run_id = %s AND tenant_id = %s AND account_id = %s",
        (scan_run_id, tenant_id, account_id)
    )
    if cur.fetchone() is None:
        logger.error(
            "Ownership validation failed — scan_run_id not owned by tenant",
            extra={"scan_run_id": scan_run_id, "tenant_id": tenant_id}
            # account_id intentionally excluded from log to avoid account enumeration
        )
        sys.exit(1)
```

### Advisory lock (W-01)
```python
lock_key = hashlib.md5(f"{tenant_id}|{account_id}".encode()).hexdigest()
lock_int = int(lock_key[:8], 16)  # 32-bit int for pg_advisory_lock
cur.execute("SELECT pg_advisory_lock(%s)", (lock_int,))
```
Released in finally block. Uses `tenant_id || '|' || account_id` — not tenant_id alone — so different accounts for the same tenant can build in parallel.

### run_scan.py overall structure
```
Step 0: validate_ownership() — abort if fails
Step 1: acquire advisory lock
Step 2: ResourceResolver.resolve()
Step 3: MisconfigLoader.load()
Step 4: VulnLoader.load()
Step 5: CDRLoader.load()
Step 6: CrownJewelClassifier.classify()
Step 7: EdgeBuilder.build()
Step 8: update threat_scan_runs_v1 status=completed
Step 9: release advisory lock
```

## Acceptance Criteria

- [ ] AC-1: `validate_ownership()` is the FIRST operation in `run_scan.py` before any other DB reads
- [ ] AC-2: Script exits with code 1 when scan_run_id not found in scan_orchestration for the given tenant+account
- [ ] AC-3: Script exits with code 0 when ownership validates correctly
- [ ] AC-4: Structured error log includes `scan_run_id` and `tenant_id` but NOT `account_id` (enumeration protection)
- [ ] AC-5: Advisory lock uses `hashtext(tenant_id || '|' || account_id)`, not tenant_id alone (W-01)
- [ ] AC-6: Advisory lock released in `finally` block — never leaked on exception
- [ ] AC-7: Argo pipeline does NOT retry on exit code 1 (document in Argo template notes)

## Security Acceptance Criteria

- [ ] Ownership check runs BEFORE any `SELECT` on check_findings, cdr_findings, or scan_vulnerabilities
- [ ] No way to skip the ownership check via environment variable or CLI flag
- [ ] `account_id` not logged in the failure event (enumeration protection)
- [ ] Advisory lock key uses `tenant_id || '|' || account_id` (not just tenant_id — W-01 fix)
- [ ] SA sign-off that this implementation satisfies CP1-07

## Definition of Done

- [ ] `run_scan.py` committed with Step 0 as first operation
- [ ] Unit test: mock scan_orchestration returning no rows → assert sys.exit(1)
- [ ] Unit test: mock scan_orchestration returning 1 row → assert execution continues
- [ ] Unit test: advisory lock is released even when downstream raises exception
- [ ] SA sign-off documented in PR thread
- [ ] SR consulted and sign-off recorded

## Verification

```bash
# Verify Step 0 runs first — read run_scan.py and confirm validate_ownership()
# is called before any cursor.execute() on other tables
grep -n "validate_ownership\|check_findings\|cdr_findings\|scan_vulnerabilities" \
  engines/threat_v1/threat_v1/run_scan.py
# validate_ownership must appear on the LOWEST line number
```
