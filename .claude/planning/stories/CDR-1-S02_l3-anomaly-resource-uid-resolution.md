# CDR-1-S02: Fix L3 Baseline Anomaly resource_uid Resolution

## Sprint
CDR-1 — Correctness Sprint

## Priority
P1 — L3 anomaly findings (baseline deviation detections) write blank `resource_uid` to `resource_security_posture` when entity_type is `actor.principal`. These rows are non-joinable — attack-path, risk, and CNAPP engines cannot correlate them back to any asset.

## Story
As the platform, I need L3 CDR baseline anomaly findings to resolve a valid `resource_uid` before writing to `resource_security_posture` and `security_findings`, so that cross-engine correlation works correctly for behavioral anomalies.

## Background / Root Cause

In `engines/cdr/run_scan.py`, the posture signal and security_findings writes aggregate from `cdr_findings`. When `rule_source='baseline'` and `entity_type='actor.principal'`, the `resource_uid` column in `cdr_findings` is the actor ARN (e.g. `arn:aws:iam::123:user/alice`) rather than a cloud resource ARN.

When `posture_signals.py` upserts this into `resource_security_posture` with `resource_uid = actor_arn`, no matching row exists in `resource_security_posture` (which is keyed on cloud resource UIDs from DI discovery). The upsert creates a dangling row with `resource_uid = actor_arn` that no other engine ever reads.

**Fix**: Resolve `actor_principal` ARN → cloud resource UID via `di_resource_catalog` before writing posture signals. If no match, use the actor ARN as resource_uid (IAM user/role is itself a cloud resource — it will have a posture row from the IAM engine).

## Files to Read First

- `engines/cdr/run_scan.py` — find where L3 findings are fetched for posture write (look for rule_source filter or lack thereof)
- `engines/cdr/cdr_engine/posture_signals.py` — `write_cdr_posture_signals()` full function
- `shared/database/migrations/di_001_initial_schema.sql` — `di_resource_catalog` table schema (columns: `resource_uid_pattern`, `provider`, `service`, `resource_type`)

## Files to Modify

| File | Change |
|---|---|
| `engines/cdr/cdr_engine/posture_signals.py` | Add actor ARN → resource_uid resolution via `di_resource_catalog` before aggregating posture rows |
| `engines/cdr/run_scan.py` | Pass `di_conn` into `write_cdr_posture_signals()` if not already available |

## Exact Implementation

### In `posture_signals.py` — add resolution step

```python
def _resolve_actor_to_resource_uid(actor_arn: str, di_conn, tenant_id: str) -> str:
    """
    Look up actor ARN in di_resource_catalog to find its canonical resource_uid.
    Falls back to actor_arn itself (IAM identity = cloud resource).
    """
    if not actor_arn:
        return actor_arn
    with di_conn.cursor() as cur:
        cur.execute("""
            SELECT resource_uid FROM asset_inventory
            WHERE tenant_id = %s AND resource_uid = %s
            LIMIT 1
        """, (tenant_id, actor_arn))
        row = cur.fetchone()
    return row["resource_uid"] if row else actor_arn
```

Then in `write_cdr_posture_signals()`, for rows where `entity_type = 'actor.principal'` and `resource_uid` is the actor ARN, call `_resolve_actor_to_resource_uid()` to obtain a joinable UID before building the upsert payload.

Batch the resolution: collect all unique `actor_principal` values first, then do a single `WHERE resource_uid = ANY(%s)` lookup rather than N individual queries.

```python
# Batch resolve all actor ARNs at once
actor_arns = list({f["actor_principal"] for f in l3_findings if f.get("actor_principal")})
if actor_arns:
    with di_conn.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT resource_uid FROM asset_inventory
            WHERE tenant_id = %s AND resource_uid = ANY(%s)
        """, (tenant_id, actor_arns))
        resolved = {row["resource_uid"] for row in cur.fetchall()}
else:
    resolved = set()

# Build resolution map: actor_arn → resolved_uid (or self if no match)
resolution_map = {arn: (arn if arn in resolved else arn) for arn in actor_arns}
```

Note: IAM users and roles ARE indexed in `asset_inventory` by the IAM engine (their ARN is the resource_uid). So the lookup will succeed for valid IAM principals and the fallback (actor_arn as resource_uid) is correct for unresolvable principals.

## Acceptance Criteria

- [ ] After CDR scan, `SELECT resource_uid FROM resource_security_posture WHERE has_active_cdr_actor=TRUE AND tenant_id=:t` returns only valid resource UIDs (ARNs of real cloud resources, not blank strings)
- [ ] L3 anomaly findings for `entity_type='actor.principal'` produce posture rows with `resource_uid = actor_arn` (IAM actor ARN is itself a valid resource_uid in asset_inventory)
- [ ] No posture rows with `resource_uid = ''` or `resource_uid IS NULL` are written by CDR
- [ ] Batch resolution uses a single `WHERE resource_uid = ANY(%s)` query, not N individual lookups
- [ ] Unresolvable actors fall back to actor_arn (do NOT skip writing the posture row)
- [ ] All DI DB queries scoped by `tenant_id`
- [ ] No `json.loads()` on JSONB

## Security Checklist

- [ ] `tenant_id` in all `asset_inventory` lookups comes from scan context, not cdr_findings rows
- [ ] No new endpoints added — internal scan path only
- [ ] Batch query uses parameterized `ANY(%s)` — no string interpolation

## Definition of Done

- [ ] `posture_signals.py` updated with batch resolution
- [ ] Manual verify: after CDR scan, zero rows in `resource_security_posture` with blank resource_uid and `has_active_cdr_actor=TRUE`
- [ ] Log line emitted: `"CDR: resolved %d/%d actor ARNs to asset_inventory entries"` so we can monitor match rate
- [ ] Image tag bumped in `deployment/aws/eks/engines/engine-cdr.yaml`