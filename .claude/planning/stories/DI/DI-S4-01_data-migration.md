# DI-S4-01 — Data Migration (discovery_findings + inventory_findings → asset_inventory)
**Sprint**: DI-S4 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Migrate existing data from `discovery_findings` (discoveries DB) and `inventory_findings` (inventory DB)
into `asset_inventory` (DI DB) so historical data is available immediately after cutover without
requiring a full re-scan. Only rows with canonical UIDs (starting with `arn:`, `ocid1.`, `/subscriptions/`,
`crn:`, etc.) are migrated; synthetic UIDs are dropped.

## Context
After cutover (DI-S4-03), downstream engines switch to `asset_inventory` as their sole data source.
Without migration, any resource not yet re-scanned by engine-di would appear missing. Migration
brings existing valid data forward; engine-di scans will refresh and enrich it going forward.

## Files to Create
- `shared/database/migrations/di_003_migrate_from_discoveries.py` — Python migration script
- `shared/database/migrations/di_003_migrate_from_inventory.py` — inventory migration script

## Migration Logic (di_003_migrate_from_discoveries.py)
```python
"""Migrate canonical rows from discovery_findings to asset_inventory.
   Drops synthetic UIDs (region:name format). Non-destructive: discovery_findings untouched.
"""
import psycopg2, os, logging, json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("di_migration")
BATCH_SIZE = 1000

CANONICAL_PREFIXES = ('arn:', 'ocid1.', '/subscriptions/', 'crn:', 'projects/')

def is_canonical(uid: str) -> bool:
    return any(uid.startswith(p) for p in CANONICAL_PREFIXES) if uid else False

def run():
    disc_conn = psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST"),
        port=int(os.getenv("DISCOVERIES_DB_PORT", "5432")),
        database=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", "postgres"),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", ""),
    )
    di_conn = psycopg2.connect(
        host=os.getenv("DI_DB_HOST"),
        port=int(os.getenv("DI_DB_PORT", "5432")),
        database=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.getenv("DI_DB_USER", "postgres"),
        password=os.getenv("DI_DB_PASSWORD", ""),
    )
    try:
        stats = {"migrated": 0, "skipped_synthetic": 0, "errors": 0}
        offset = 0
        while True:
            with disc_conn.cursor() as cur:
                cur.execute("""
                    SELECT scan_run_id, tenant_id, account_id, provider, region,
                           credential_ref, credential_type,
                           resource_uid, resource_type, resource_name, service, discovery_id,
                           emitted_fields, raw_response, status, first_seen_at, last_seen_at
                    FROM discovery_findings
                    ORDER BY id
                    LIMIT %s OFFSET %s
                """, (BATCH_SIZE, offset))
                rows = cur.fetchall()

            if not rows:
                break

            batch = []
            for row in rows:
                uid = row[7]  # resource_uid
                if not is_canonical(uid):
                    stats["skipped_synthetic"] += 1
                    continue
                batch.append(row)

            if batch:
                try:
                    from psycopg2.extras import execute_values
                    with di_conn.cursor() as cur:
                        execute_values(cur, """
                            INSERT INTO asset_inventory (
                                scan_run_id, tenant_id, account_id, provider, region,
                                credential_ref, credential_type,
                                resource_uid, resource_type, resource_name, service, discovery_id,
                                phase, emitted_fields, raw_response,
                                severity, status, first_seen_at, last_seen_at
                            ) VALUES %s
                            ON CONFLICT (resource_uid, scan_run_id, tenant_id) DO NOTHING
                        """, [(
                            r[0], r[1], r[2], r[3], r[4],
                            r[5], r[6],
                            r[7], r[8], r[9], r[10], r[11],
                            1,  # phase=1 (treated as enriched historical data)
                            json.dumps(r[12]) if isinstance(r[12], dict) else r[12],
                            json.dumps(r[13]) if isinstance(r[13], dict) else (r[13] or '{}'),
                            'informational', r[14] or 'active',
                            r[15], r[16],
                        ) for r in batch])
                    di_conn.commit()
                    stats["migrated"] += len(batch)
                except Exception as e:
                    di_conn.rollback()
                    logger.error("Batch insert failed at offset=%d: %s", offset, e)
                    stats["errors"] += len(batch)

            offset += BATCH_SIZE
            logger.info("Progress: migrated=%d skipped=%d errors=%d",
                        stats["migrated"], stats["skipped_synthetic"], stats["errors"])

        logger.info("MIGRATION COMPLETE: %s", stats)
    finally:
        disc_conn.close()
        di_conn.close()

if __name__ == "__main__":
    run()
```

## Apply Instructions
```bash
# Run migration via kubectl exec on a pod that has BOTH DB env vars
# (engine-di pod has DI_DB_* and we add DISCOVERIES_DB_* + INVENTORY_DB_* temporarily)
kubectl cp shared/database/migrations/di_003_migrate_from_discoveries.py \
  threat-engine-engines/<engine-di-pod>:/tmp/di_003_migrate_from_discoveries.py

kubectl exec -n threat-engine-engines <engine-di-pod> -- python3 /tmp/di_003_migrate_from_discoveries.py
# Expected output: MIGRATION COMPLETE: {migrated: N, skipped_synthetic: M, errors: 0}
```

## Acceptance Criteria

### Functional
- [ ] `asset_inventory` count after migration ≥ `discovery_findings` canonical rows count
- [ ] No synthetic UIDs in `asset_inventory` after migration (verified by SQL check below)
- [ ] `ON CONFLICT DO NOTHING`: running migration twice is idempotent; second run adds 0 rows
- [ ] Migrated rows have `phase=1` (treated as enriched historical data)
- [ ] Migration completes within 60 minutes for 500K rows
- [ ] Migration log ends with `MIGRATION COMPLETE: {migrated: N, skipped_synthetic: M, errors: 0}`

### SQL Verification Queries
```sql
-- After migration: no synthetic UIDs
SELECT count(*) FROM asset_inventory
WHERE provider = 'aws' AND resource_uid NOT LIKE 'arn:%';
-- Expected: 0

SELECT count(*) FROM asset_inventory
WHERE provider = 'oci' AND resource_uid NOT LIKE 'ocid1.%';
-- Expected: 0

-- Migration completeness
SELECT provider, count(*) FROM asset_inventory GROUP BY provider;
-- Compare to: SELECT provider, count(*) FROM discovery_findings GROUP BY provider;
-- DI count should be ≥ discovery_findings count × (canonical_fraction)
```

### Security
- [ ] Migration script does not log credential values
- [ ] `ON CONFLICT DO NOTHING` prevents data corruption on re-run
- [ ] Migration is non-destructive: `discovery_findings` and `inventory_findings` untouched

### Error Handling
- [ ] Batch insert failure: rollback batch + log ERROR + continue with next batch
- [ ] Skipped rows logged at INFO; script completes even if all rows are synthetic (not a fatal error)

## Testing Requirements

**Pre-migration snapshot**:
```sql
SELECT provider, count(*) FROM discovery_findings GROUP BY provider;
-- Record these counts for post-migration comparison
```

**Post-migration validation**:
```sql
SELECT provider, count(*) FROM asset_inventory GROUP BY provider;
-- Each CSP should have >= discovery_findings count × (1 - synthetic_fraction)
```

**Idempotency test**: Run migration twice; second run stats = `{migrated: 0, skipped_synthetic: X, errors: 0}`.

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge (data migration — non-destructive verified) |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] Migration script committed and code-reviewed
- [ ] Migration applied; SQL verification queries pass (0 synthetic UIDs)
- [ ] `asset_inventory` count ≥ expected migrated rows
- [ ] Second run produces 0 new rows (idempotent)
- [ ] Migration log ends with `MIGRATION COMPLETE`
- [ ] MEMORY.md updated: migration completed; asset_inventory row counts recorded

## Dependencies
- DI-S1-01 (`asset_inventory` table exists)
- DI-S3-* all adapter code changes merged (to confirm asset_inventory schema matches what adapters expect)
- All DI-S3 engines deployed with `DI_ENGINE_ENABLED=false` (so they're reading from old tables during migration)

## Rollback
Migration is non-destructive. `discovery_findings` and `inventory_findings` are not modified.
To remove migrated data:
```sql
TRUNCATE asset_inventory;  -- Only if no new engine-di scans have run
```