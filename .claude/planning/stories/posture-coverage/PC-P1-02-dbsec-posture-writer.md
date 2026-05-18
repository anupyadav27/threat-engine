# Story PC-P1-02: DBSec Engine — Write Posture Signals to resource_security_posture

## Status: done

## Metadata
- **Phase**: P1 — Tier A (immediately implementable)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P1
- **Depends on**: AP-P0-01 (posture table exists), AP-P0-02 (posture_writer utility)
- **Blocks**: PC-P1-07 (composite flags), attack-path compute→DB edges
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer — new cross-DB write path from dbsec to inventory DB

## Gap Being Closed

**Current state:** `resource_security_posture` has 3 dbsec-owned columns (`connected_db_count`, `db_auth_type`, `connected_db_uids`) — all always at defaults (0/null). The attack-path engine cannot draw compute→database edges because `connected_db_uids` is always empty.

**Impact of gap:** Attack paths that traverse `EC2 instance → RDS database → S3 exfil` cannot be computed. The blast radius of a compromised instance is underestimated because the databases it connects to are invisible.

**Why Tier A:** `dbsec_findings` already has `resource_uid` (the DB resource) and `account_id`. The compute→DB linkage can be inferred from the `resource_inventory_identifier` table (inventory DB) which maps resource types to their parent compute resources.

## Data Sources

```
threat_engine_dbsec DB → dbsec_findings
  Fields: resource_uid (DB resource), resource_type, rule_id, status, finding_data
  finding_data JSONB: {db_endpoint, vpc_id, security_group_ids, auth_type}

threat_engine_inventory DB → resource_relationships
  Fields: source_uid, target_uid, relationship_type
  Use: find compute resources that CONNECTS_TO each DB resource_uid
```

## Signals to Write

| Column | Source Logic |
|--------|-------------|
| `connected_db_count` | Count of distinct DB resource_uids in dbsec_findings for this scan |
| `db_auth_type` | `finding_data->>'auth_type'` — `iam`, `password`, `cert`, or `mixed` |
| `connected_db_uids` | JSONB array of DB resource_uids; written to the COMPUTE resource row, not the DB row |

**Two write passes:**
1. **DB resource row:** Write `db_auth_type` to the DB resource's posture row (e.g. the RDS instance itself)
2. **Compute resource row (reverse linkage):** For each DB resource, look up which compute resources `CONNECTS_TO` it via `resource_relationships`. Write `connected_db_count` and `connected_db_uids` to those compute resource rows.

If `resource_relationships` is empty or the join yields nothing, write only the DB row (pass 1) and log INFO "no compute→DB relationships found".

## Implementation

**New file:** `engines/dbsec/dbsec_engine/posture_signals.py`

```python
def write_dbsec_posture_signals(scan_run_id, tenant_id, account_id, provider) -> int:
    # Pass 1: write db_auth_type to DB resource rows
    # Pass 2: join resource_relationships to find compute resources,
    #          write connected_db_count + connected_db_uids to compute rows
```

**Wire into scan:** End of `engines/dbsec/run_scan.py` after findings commit.

**DB connections:**
- Read from: `get_dbsec_conn()` (dbsec findings) + `get_inventory_conn()` (resource_relationships)
- Write to: `get_inventory_conn()` (posture table)

## Acceptance Criteria

- [ ] AC-1: After dbsec scan, DB resources (RDS, Aurora, DynamoDB) have `db_auth_type` populated in posture rows
- [ ] AC-2: `db_auth_type='iam'` for RDS instances with IAM authentication enabled (verify rule PASS pattern)
- [ ] AC-3: `connected_db_uids` on compute resources lists the DB ARNs they connect to (non-empty when resource_relationships has CONNECTS_TO edges)
- [ ] AC-4: If `resource_relationships` has no rows for this scan, writer completes without error and logs INFO
- [ ] AC-5: Writer does NOT overwrite any non-dbsec columns
- [ ] AC-6: Non-fatal — dbsec scan completes even if inventory DB is unreachable
- [ ] AC-7: New image: `yadavanup84/engine-dbsec:v-dbsec-posture1`

## Definition of Done
- [ ] `posture_signals.py` written (both passes)
- [ ] `run_scan.py` wired
- [ ] Post-deploy: `SELECT resource_uid, connected_db_count, connected_db_uids FROM resource_security_posture WHERE connected_db_count > 0 LIMIT 5` returns rows for a real scan