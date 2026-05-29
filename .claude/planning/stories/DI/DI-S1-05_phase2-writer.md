# DI-S1-05 — Phase 2 Writer (asset_inventory + asset_relationships)
**Sprint**: DI-S1 | **Points**: 5 | **Status**: Ready for Dev

## Goal
Build Phase 2 (Write). Consume the generator output from Phase 0+1 and upsert each row into
`asset_inventory` with ON CONFLICT (resource_uid, scan_run_id, tenant_id) DO UPDATE. Also build
`asset_relationships` from relationship-bearing enrichment fields (subnet CONTAINS instance, etc.).
No synthetic UIDs are written; rows are skipped at the generator level before reaching this writer.

## Files to Create / Modify
- `engines/di/di_engine/phase2/writer.py` — batch upsert to asset_inventory
- `engines/di/di_engine/phase2/relationship_writer.py` — build and write asset_relationships
- `engines/di/di_engine/phase2/__init__.py` — empty
- `engines/di/di_engine/phase2/sensitive_scrubber.py` — remove sensitive fields from raw_response

## Implementation

### writer.py
```python
"""Phase 2: Batch upsert enriched rows to asset_inventory."""
import hashlib
import json
import logging
from typing import Any, Dict, Generator, Iterator, List

logger = logging.getLogger('di.phase2')
BATCH_SIZE = 500


def run_phase2(
    rows: Iterator[Dict[str, Any]],
    di_conn,  # psycopg2 connection to threat_engine_di
    scan_run_id: str,
    tenant_id: str,
) -> Dict[str, int]:
    """Consume generator rows, upsert to asset_inventory in batches of 500.

    Returns summary dict: {inserted, updated, skipped, errors}
    No synthetic UIDs are written — rows with ResourceIdMissingError never reach this function.
    """
    from .sensitive_scrubber import scrub_sensitive_fields
    stats = {'inserted': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
    batch: List[Dict] = []

    for row in rows:
        if not row.get('resource_uid'):
            logger.error("Phase2: row without resource_uid — THIS SHOULD NOT HAPPEN. "
                         "service=%s tenant=%s", row.get('service'), tenant_id)
            stats['errors'] += 1
            continue

        # Compute drift
        raw = scrub_sensitive_fields(row.get('raw_response') or {})
        config_hash = hashlib.md5(
            json.dumps(raw, sort_keys=True, default=str).encode()
        ).hexdigest()
        row['raw_response'] = raw
        row['config_hash'] = config_hash

        batch.append(row)
        if len(batch) >= BATCH_SIZE:
            _flush_batch(batch, di_conn, stats)
            batch.clear()

    if batch:
        _flush_batch(batch, di_conn, stats)

    logger.info("Phase2 complete: %s", stats)
    return stats


def _flush_batch(batch: List[Dict], conn, stats: Dict) -> None:
    """Upsert a batch of rows to asset_inventory."""
    from psycopg2.extras import execute_values
    try:
        with conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO asset_inventory (
                    scan_run_id, tenant_id, account_id, provider, region,
                    credential_ref, credential_type,
                    resource_uid, resource_type, resource_name, service, discovery_id,
                    phase, emitted_fields, raw_response,
                    config_hash, previous_config_hash, drift_detected,
                    severity, status, first_seen_at, last_seen_at
                ) VALUES %s
                ON CONFLICT (resource_uid, scan_run_id, tenant_id) DO UPDATE SET
                    phase                = EXCLUDED.phase,
                    emitted_fields       = EXCLUDED.emitted_fields,
                    raw_response         = EXCLUDED.raw_response,
                    resource_name        = EXCLUDED.resource_name,
                    config_hash          = EXCLUDED.config_hash,
                    previous_config_hash = asset_inventory.config_hash,
                    drift_detected       = (asset_inventory.config_hash IS NOT NULL
                                           AND asset_inventory.config_hash != EXCLUDED.config_hash),
                    last_seen_at         = NOW()
                """,
                [(
                    r['scan_run_id'], r['tenant_id'], r['account_id'],
                    r['provider'], r['region'],
                    r.get('credential_ref'), r.get('credential_type'),
                    r['resource_uid'], r['resource_type'], r.get('resource_name'),
                    r['service'], r.get('discovery_id'),
                    r.get('phase', 0), json.dumps(r.get('emitted_fields', {})),
                    json.dumps(r.get('raw_response', {})),
                    r.get('config_hash'), r.get('previous_config_hash'),
                    r.get('drift_detected', False),
                    r.get('severity', 'informational'), r.get('status', 'active'),
                    r.get('first_seen_at'), r.get('last_seen_at'),
                ) for r in batch],
            )
        conn.commit()
        stats['inserted'] += len(batch)
    except Exception as exc:
        conn.rollback()
        logger.error("Phase2 batch flush failed: %s", exc)
        stats['errors'] += len(batch)
```

### sensitive_scrubber.py
```python
"""Remove sensitive fields from raw_response before writing to DB."""
_SENSITIVE_KEYS = frozenset({
    'MasterUserPassword', 'Password', 'AccessKeyId', 'SecretAccessKey',
    'SessionToken', 'AuthToken', 'ConnectionString', 'DatabasePassword',
    'SecretString', 'SecretBinary', 'KeyMaterial', 'PrivateKey',
    'CertificatePrivateKey', 'token', 'secret', 'password', 'key_material',
})

def scrub_sensitive_fields(obj: Any) -> Any:
    """Recursively remove known sensitive keys from a dict/list structure."""
    if isinstance(obj, dict):
        return {k: scrub_sensitive_fields(v) for k, v in obj.items()
                if k not in _SENSITIVE_KEYS}
    elif isinstance(obj, list):
        return [scrub_sensitive_fields(item) for item in obj]
    return obj
```

### relationship_writer.py
Key relationships to derive from `emitted_fields`:
```python
RELATIONSHIP_EXTRACTORS = {
    'ec2.instance': [
        ('SubnetId', 'ec2.subnet', 'PLACED_IN'),
        ('VpcId', 'ec2.vpc', 'PLACED_IN'),
        ('SecurityGroups[].GroupId', 'ec2.security_group', 'PROTECTED_BY'),
    ],
    'ec2.subnet': [
        ('VpcId', 'ec2.vpc', 'BELONGS_TO'),
        ('RouteTableAssociationId', 'ec2.route_table', 'ROUTES_VIA'),
    ],
    'rds.db_instance': [
        ('VpcId', 'ec2.vpc', 'PLACED_IN'),
        ('DBSubnetGroup.VpcId', 'ec2.vpc', 'PLACED_IN'),
        ('VpcSecurityGroups[].VpcSecurityGroupId', 'ec2.security_group', 'PROTECTED_BY'),
    ],
    # ... additional resource types
}
```

Build `asset_relationships` from these extractors during Phase 2, using the `resource_uid` of
the source row and deriving the `to_uid` from the related resource's ARN in the scan's `asset_inventory`.

## Acceptance Criteria

### Functional
- [ ] All Phase 0/1 rows written to `asset_inventory` via upsert
- [ ] ON CONFLICT updates `last_seen_at` and sets `drift_detected=TRUE` when `config_hash` changes
- [ ] `drift_detected=TRUE` rows queryable via the partial index `idx_ai_drift`
- [ ] Batch size 500 — no single transaction holds > 500 rows
- [ ] `asset_relationships` built for EC2 instance→subnet, instance→VPC, instance→SG, subnet→VPC
- [ ] No row with empty or NULL `resource_uid` written (guard + ERROR log + stats.errors counter)
- [ ] Phase 2 stats returned: `{inserted, updated, skipped, errors}`

### Security
- [ ] `raw_response` has no `MasterUserPassword`, `AccessKeyId`, `SecretAccessKey` keys (scrubber ran)
- [ ] Verified by SELECT on DB: no row has `raw_response ? 'MasterUserPassword'`
- [ ] `tenant_id` is NOT derived from user input in Phase 2 — comes from orchestration record only

### Error Handling
- [ ] Batch flush failure: `conn.rollback()` + stats.errors += batch_size + continue (no crash)
- [ ] Connections closed in `finally` block of calling run_scan.py
- [ ] Duplicate `resource_uid` in same batch: ON CONFLICT handles it cleanly

## Testing Requirements

**Unit** (`tests/engines/di/test_phase2_writer.py`):
- Valid row → `INSERT INTO asset_inventory` with correct columns
- Duplicate row → ON CONFLICT DO UPDATE — `last_seen_at` updated
- Row with changed `raw_response` → `drift_detected=TRUE` on second upsert
- Row without `resource_uid` → `stats.errors += 1`, no DB write
- `scrub_sensitive_fields({'MasterUserPassword': 'x', 'VpcId': 'vpc-1'})` → `{'VpcId': 'vpc-1'}`
- Coverage ≥ 80% on `writer.py` and `sensitive_scrubber.py`

**Integration**:
1. Run full Phase 0 + 1 + 2 for AWS test account
2. `SELECT count(*) FROM asset_inventory` > 0
3. `SELECT count(*) FROM asset_inventory WHERE resource_uid LIKE '%region:name%'` = 0 (no synthetic UIDs)
4. `SELECT count(*) FROM asset_relationships` > 0

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge (sensitive scrubbing is a BLOCKER per threat model) |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] `engines/di/di_engine/phase2/` created with all 3 modules
- [ ] `sensitive_scrubber.py` removes all keys in `_SENSITIVE_KEYS`
- [ ] DB verify: `SELECT count(*) FROM asset_inventory WHERE resource_uid NOT LIKE 'arn:%' AND resource_uid NOT LIKE 'ocid1.%' AND provider IN ('aws','oci')` = 0
- [ ] `asset_relationships` populated for EC2 → subnet/VPC/SG
- [ ] Unit tests ≥ 80% coverage
- [ ] bmad-security-reviewer approved sensitive-scrubbing implementation

## Dependencies
- DI-S1-03 (Phase 0), DI-S1-04 (Phase 1)
- DI-S1-01 (`asset_inventory` + `asset_relationships` tables exist)

## Rollback
```sql
DELETE FROM asset_inventory WHERE scan_run_id = '<bad_scan_run_id>';
DELETE FROM asset_relationships WHERE scan_run_id = '<bad_scan_run_id>';
```