# AP-VAL-03 — Retire extra_edges: Pure Validated-Vector BFS

**Sprint:** VAL-02 (post-VAL-01 follow-on)
**Engine:** attack-path, iam, di
**Priority:** High — architectural correctness
**Depends on:** AP-VAL-01 complete (is_attack_edge column + 5 validators deployed as v-ap-val1)

---

## Problem

After VAL-01-D (pg_graph now filters `is_attack_edge=TRUE`), the BFS still has two
in-memory edge sources that bypass the validated-vector model:

### extra_edges source 1 — `_build_iam_permission_edges()` in `run_scan.py`
- Reads `iam_policy_statements WHERE effect='Allow'` directly
- Builds synthetic `role_arn → (crown_jewel_uid, "grants_access_to", ...)` edges
- Merged into adjacency list in-memory AFTER the DB query
- Bypasses `is_attack_edge=TRUE` filter; not written to `asset_relationships`

### extra_edges source 2 — `_build_eks_worker_node_edges()` in `run_scan.py`
- Reads `asset_inventory` for EC2 instances with EKS nodegroup instance profiles
- Matches EC2 to EKS cluster ARN via account+region
- Builds synthetic `ec2_uid → (eks_cluster_uid, "worker_node_of", ...)` edges
- Not in `asset_relationships` at all

**Why this matters:**
- The validated-vector architecture promise is broken: some attack traversal edges
  are DB-sourced + validated; others are in-memory + implicit
- Can't query `asset_relationships` for complete attack graph coverage
- `relationship-quality` BFF endpoint (ONTO-1-E) under-reports because these
  edges don't appear in `asset_relationships WHERE is_attack_edge=TRUE`
- `worker_node_of` edges are rebuilt from scratch every scan — expensive and fragile

---

## Solution

### Part A — IAM policy validator (new validator in engine-attack-path)

Create `engines/attack-path/attack_path_engine/validators/iam_policy.py`:

```
validate_iam_policy(di_conn, scan_run_id, tenant_id, account_id, provider)
  → reads iam_policy_statements WHERE effect='Allow' AND tenant_id=$1
  → reads resource_security_posture WHERE is_crown_jewel=TRUE AND tenant_id=$1
  → maps policy actions to crown jewel resource types (same SERVICE_TO_TYPE_HINTS map)
  → writes CAN_READ / CAN_DECRYPT / CAN_INVOKE edges to asset_relationships
     with is_attack_edge=TRUE, validation_rule_id='AWS-IAM-001..003'
  → returns count of edges written
```

Add to `runner.py` AFTER `data_access`:
```python
("iam_policy", validate_iam_policy),
```

### Part B — EKS worker-node edges written by DI engine

Update `engines/di/di_engine/phase2/catalog_relationship_writer.py`:
- When processing EC2 instances with `IamInstanceProfile.Arn` matching
  `instance-profile/eks-*`, resolve the cluster ARN and write:
  ```
  ec2_uid → WORKER_NODE_OF → eks_cluster_uid
  ```
  to `asset_relationships` via `upsert_asset_relationships()`

The `assume_role` validator already handles ASSUMES edges. Add WORKER_NODE_OF
to the catalog as `attack_edge_class='candidate'` with `validator_name='validate_assume_role'`
(or a dedicated small validator that marks it `is_attack_edge=TRUE`).

### Part C — Remove extra_edges from run_scan.py

After Part A and Part B are deployed and verified (non-zero attack paths confirmed):
- Delete `_build_iam_permission_edges()` function
- Delete `_build_eks_worker_node_edges()` function
- Remove `iam_extra_edges`, `eks_worker_edges` merge logic from Stage 2b-pre
- Remove `extra_edges=iam_extra_edges` from `run_pg_bfs()` call

---

## Files Changed

| File | Change |
|------|--------|
| `engines/attack-path/attack_path_engine/validators/iam_policy.py` | NEW — IAM policy validator |
| `engines/attack-path/attack_path_engine/validators/runner.py` | Add `iam_policy` to validator list |
| `engines/attack-path/attack_path_engine/run_scan.py` | Remove `_build_iam_permission_edges`, `_build_eks_worker_node_edges`, extra_edges merge |
| `engines/di/di_engine/phase2/catalog_relationship_writer.py` | Write WORKER_NODE_OF edges for EKS nodegroup EC2 instances |
| `shared/database/migrations/di_014_worker_node_catalog.sql` | Seed WORKER_NODE_OF in resource_relationship_catalog |
| `engines/attack-path/attack_path_engine/graph/pg_graph.py` | Remove `extra_edges` parameter from `run_pg_bfs()` signature |

---

## Acceptance Criteria

- [ ] `validate_iam_policy` writes `CAN_READ/CAN_DECRYPT/CAN_INVOKE` edges to `asset_relationships` with `is_attack_edge=TRUE`
- [ ] After scan, `SELECT COUNT(*) FROM asset_relationships WHERE validation_rule_id LIKE 'AWS-IAM-%' AND is_attack_edge=TRUE` > 0
- [ ] BFF `/api/v1/views/relationship-quality` shows `iam_policy` validator in `by_validator`
- [ ] DI phase-2 writes `WORKER_NODE_OF` edges to `asset_relationships` for EKS nodegroup EC2s
- [ ] `_build_iam_permission_edges()` and `_build_eks_worker_node_edges()` deleted from `run_scan.py`
- [ ] `run_pg_bfs()` no longer accepts `extra_edges` parameter
- [ ] Attack path count after scan is >= count before (no regression)
- [ ] `relationship-quality` endpoint shows all attack edge types (no hidden in-memory edges)

---

## Risk

**Medium.** The IAM policy validator replaces a working in-memory approach. Must verify
attack path counts don't drop before removing extra_edges (run in parallel: both paths
active for one scan cycle to compare counts before cutting over).

**Rollback:** extra_edges code can be restored from git. Validator is non-fatal.

---

## Migration Required

`di_014_worker_node_catalog.sql` — seeds `WORKER_NODE_OF` in `resource_relationship_catalog`
with `attack_edge_class='candidate'`, `validator_name='validate_assume_role'` (or new validator).
No new columns.