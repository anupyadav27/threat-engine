# Attack Path Validation Sprint — Handover Document
**Date:** 2026-05-29  
**Sprint:** VAL-01 (Attack Edge Validation Layer)  
**Status:** Phase 1 COMPLETE and deployed. Phase 2 deferred.

---

## What Was Built This Session

### The Problem Being Solved
Raw relationships in `asset_relationships` (routes_to, has_role, INTERNET_ACCESSIBLE, ASSUMES) are
structural facts — they don't mean a path is reachable and exploitable. The pg_graph BFS was
traversing all ~40 edge types equally, producing noisy/incorrect attack paths.

**Solution:** A validation layer that sits between relationship writers and the BFS graph.
It promotes valid structural edges into explicit attack edges (`is_attack_edge=TRUE`) and
composes multi-hop structural edges into single traversable attack edges.

---

## Architecture Decision (CONFIRMED, DO NOT REVISIT)

**Three distinct layers — no duplication:**

```
Layer 1: Source engines (IAM, Network, DI)
  → Real validation: parse trust policies, SG rules, emitted fields
  → Write structural edges to asset_relationships

Layer 2: Attack-path validators (NEW, this sprint)
  → Promote: mark is_attack_edge=TRUE on validated source edges
  → Compose: chain 2-hop structural edges into 1 attack edge
  → Normalize: ASSUMES → CAN_ASSUME, INTERNET_ACCESSIBLE → CAN_REACH (reversed direction)

Layer 3: pg_graph BFS (existing, to be updated in next sprint)
  → Reads is_attack_edge=TRUE rows only (VAL-01-D, deferred)
  → Builds attack paths
```

**Where IAM validation actually happens:**
- `iam_relationship_writer.py` `_assumes_edges()` — skips if `effect != "Allow"`
- `_grants_access_to_edges()` — parses resource policy JSON, skips Deny statements
- `_can_access_edges()` — only writes for `Resource:*` + `Effect=Allow` wildcards
- By the time ASSUMES/GRANTS_ACCESS_TO land in `asset_relationships`, policy is already evaluated
- Attack-path validators READ these pre-validated edges — they do NOT re-validate policy

**Where Network validation actually happens:**
- `network_relationship_writer.py` `_derive_sg_edges()` calls `compute_effective_exposure(sg, vpc, None)`
- Full SG + VPC topology evaluation happens there
- Attack-path validator just reverses the edge direction: `resource→internet` → `internet→resource`

---

## What's Deployed

| Component | Image Tag | Status |
|-----------|-----------|--------|
| engine-attack-path | `v-ap-val1` | Running, health checks passing |
| engine-di | `v-di-rel3` | Running |

**Pipeline ordering is already correct** (verified in `cspm-pipeline.yaml`):
- `iam` and `network-security` both run after `check`, in parallel with each other
- `mitre-enrich` waits for ALL domain engines (lines 447-455 of cspm-pipeline.yaml)
- `attack-path-scan` depends on `mitre-enrich`
- Guarantee: IAM and network-security ALWAYS finish before attack-path validators run

**No API gateway calls needed** — all engines write to `asset_relationships` in `threat_engine_di` DB.
Attack-path validators read from the same table via `di_conn`. Direct DB access, no HTTP.

---

## Database Migration Applied

**Migration:** `shared/database/migrations/di_013_attack_edge_validation.sql`  
**Applied to:** `threat_engine_di` DB on RDS  
**Status:** Applied and verified

### Columns added to `asset_relationships`:
```sql
is_attack_edge       BOOLEAN NOT NULL DEFAULT FALSE
attack_edge_type     VARCHAR(64)         -- CAN_REACH, CAN_ASSUME, CAN_USE_IDENTITY, etc.
validation_status    VARCHAR(32) NOT NULL DEFAULT 'unvalidated'
validation_rule_id   VARCHAR(64)         -- AWS-INET-001, AWS-ID-005, etc.
attack_evidence      JSONB               -- provenance trail
```

### Columns added to `resource_relationship_catalog`:
```sql
attack_edge_class        VARCHAR(32)   -- direct_capability | candidate | context | ignore
validation_required      BOOLEAN NOT NULL DEFAULT FALSE
derived_attack_edge_type VARCHAR(64)
validator_name           VARCHAR(64)
```

### Seeds applied (verified counts):
- `candidate`: 44 rules
- `context`: 22 rules
- `direct_capability`: 4 rules

### Indexes:
- `idx_ar_attack_edge` — partial WHERE `is_attack_edge=TRUE` (for BFS filter in VAL-01-D)
- `idx_ar_relation_type_lower` — LOWER(relation_type) for validator queries

---

## Validator Files (all in `engines/attack-path/attack_path_engine/validators/`)

### `base.py`
- `INTERNET_NODE = "pseudo:internet:global"`
- `_BATCH_SIZE = 500`
- `_upsert_attack_edges(conn, edges, scan_run_id, tenant_id, account_id, provider) -> int`
- ON CONFLICT upserts: sets `is_attack_edge=TRUE`, updates `attack_edge_type`, `validation_rule_id`, `attack_evidence`

### `internet_reachability.py` (Rule IDs: AWS-INET-001..005)
- Source 1: `resource_security_posture` WHERE `is_attack_entry_point=TRUE OR is_internet_exposed=TRUE`
- Source 2: `asset_relationships` WHERE `UPPER(relation_type)='INTERNET_ACCESSIBLE'`
- Output: `pseudo:internet:global → CAN_REACH → asset` (direction reversed for BFS)
- Does NOT re-validate SG rules — trusts network engine's INTERNET_ACCESSIBLE result

### `service_chain.py` (Rule IDs: AWS-SVC-001..005)
- Sources: `routes_to, invokes, has_integration, triggers, forwards_to, serves_traffic_for`
- Output: CAN_REACH (routing edges) or CAN_INVOKE (trigger edges)
- Direction: same as source (service routing = direct attack movement)

### `identity_usage.py` (Rule IDs: AWS-ID-001, AWS-ID-002)
Two paths — both write `CAN_USE_IDENTITY`:

**Path 1 — Direct (AWS-ID-002):**
`has_role / uses_identity / has_sa / has_identity` → CAN_USE_IDENTITY to role directly

**Path 2 — Chain (AWS-ID-001):**
```
EC2 →[HAS_PROFILE]→ instance_profile →[LINKED_TO]→ iam_role
    ↓ (collapsed by validator)
EC2 →[CAN_USE_IDENTITY]→ iam_role
```
Implementation: first builds `profile_uid → [role_uids]` dict from LINKED_TO edges,
then queries HAS_PROFILE edges and resolves through dict to actual role_uid.

**BUG FIXED THIS SESSION:** original version wrote `CAN_USE_IDENTITY` to `instance_profile`
(wrong target). Fixed to resolve through LINKED_TO to the actual `iam_role`.

### `assume_role.py` (Rule IDs: AWS-ID-005, AWS-XACC-001)
- Reads existing `assumes/can_assume` edges (IAM engine already validated trust policy)
- Step 1: UPDATE existing rows → `is_attack_edge=TRUE, attack_edge_type='CAN_ASSUME'`
- Step 2: INSERT normalised `CAN_ASSUME` derived edges
- Cross-account detection: if `account_id` not in `principal` ARN → `AWS-XACC-001`

### `data_access.py` (Rule IDs: AWS-DATA-001..005, AWS-SEC-001, AWS-KMS-001)
- Sources: `grants_access_to, reads_from, stores_data_in, encrypted_by`
- `_refine_rule()` maps `target_type` → specific rule ID:
  - secrets/ssm → AWS-SEC-001 + CAN_READ
  - kms → AWS-KMS-001 + CAN_DECRYPT
  - s3/bucket/blob → AWS-DATA-001 (read) or AWS-DATA-002 (write)
  - rds/database/dynamodb → AWS-DATA-004
  - efs/filesystem → AWS-DATA-005

### `runner.py`
- `run_all_validators(di_conn, scan_run_id, tenant_id, account_id, provider) -> Dict[str, int]`
- Runs all 5 in order: internet_reachability → service_chain → identity_usage → assume_role → data_access
- Non-fatal: each validator is wrapped; failure of one doesn't block others
- Returns `{validator_name: edges_written}` counts

### `run_scan.py` change
Stage 2a-pre2 added between internet_exposed_lookup and posture_lookup:
```python
from .validators import run_all_validators
val_results = run_all_validators(
    di_conn=di_conn, scan_run_id=scan_run_id,
    tenant_id=tenant_id, account_id=account_id, provider=provider,
)
```

---

## Deferred Work — Next Session Priorities

### Priority 1: VAL-01-D — pg_graph BFS filter (MOST IMPORTANT)
**File:** `engines/attack-path/attack_path_engine/graph/pg_graph.py`

**Current state:** pg_graph loads edges using a hardcoded `_ATTACK_RELEVANT_TYPES` set (~40 types).
All edges of those types are loaded regardless of whether they've been validated.

**What to change:** Replace the type-set filter with `WHERE is_attack_edge=TRUE`.
This means the graph only traverses edges that validators have explicitly promoted.

**Prerequisite to check first:** Do direct-capability edges (INVOKES, CAN_ASSUME written at
source engine time) get `is_attack_edge=TRUE` set? Two options:
  - Option A: Source engines set it at write time (network/IAM writers)
  - Option B: Validators mark them (assume_role.py already does UPDATE for ASSUMES rows)
  
Verify by querying: `SELECT relation_type, COUNT(*) FROM asset_relationships WHERE is_attack_edge=TRUE GROUP BY relation_type LIMIT 20` after a scan.

### Priority 2: ONTO-1-F — Network engine marks `is_attack_entry_point`
**File:** `engines/network-security/network_security_engine/storage/network_relationship_writer.py`

When writing INTERNET_ACCESSIBLE, also set `is_attack_entry_point=TRUE` and
`attack_entry_point_category='INTERNET_ENTRY'` on `resource_security_posture`.
This lets internet_reachability.py use a cleaner single source instead of two queries.

### Priority 3: ONTO-1-E — Relationship quality BFF endpoint
`GET /api/v1/views/relationship-quality` — returns validator edge counts per type per scan.
Shows ops team how many CAN_REACH, CAN_USE_IDENTITY, CAN_ASSUME edges were derived.

### Priority 4: ONTO-1-G — Drop deprecated columns (LAST, after ONTO-1-F)
Drop from `resource_security_posture`: `is_internet_exposed`, `is_crown_jewel`, `crown_jewel_type`

---

## How to Apply Migrations (CRITICAL GOTCHA)

**Never use psql or semicolon-split SQL files.** Inline SQL comments (`-- text`) break semicolon parsers.

**Correct pattern:**
```python
# Write migration as Python list of DDL strings, copy to pod, run
kubectl cp /tmp/apply_migration.py threat-engine-engines/<pod>:/tmp/apply_migration.py
kubectl exec -n threat-engine-engines <pod> -- python3 /tmp/apply_migration.py
```

Use a pod that has DB env vars (`engine-di` or `engine-attack-path` both have DI DB access).

---

## Uncommitted Changes on `dev` Branch

These files are modified but not committed:
- `catalog/discovery_generator_data/aws/` — YAML discovery updates
- `catalog/relationships/aws/infrastructure_attachment.yaml`
- `deployment/aws/eks/engines/engine-attack-path.yaml` — image tag (may be stale, use kubectl set image)
- `deployment/aws/eks/engines/engine-di.yaml` — image tag
- `engines/attack-path/attack_path_engine/` — validators + run_scan.py changes (THIS SPRINT)
- `engines/chat/` — chat engine fixes
- `engines/di/` — DI engine changes
- `shared/common/relationship_writer.py`

**Before next session:** consider committing the attack-path validator files.

---

## Key Files Reference

| Purpose | Path |
|---------|------|
| Argo pipeline DAG | `deployment/aws/eks/argo/cspm-pipeline.yaml` |
| Attack-path run_scan | `engines/attack-path/attack_path_engine/run_scan.py` |
| All validators | `engines/attack-path/attack_path_engine/validators/` |
| pg_graph (next sprint) | `engines/attack-path/attack_path_engine/graph/pg_graph.py` |
| IAM relationship writer | `engines/iam/iam_engine/storage/iam_relationship_writer.py` |
| Network relationship writer | `engines/network-security/network_security_engine/storage/network_relationship_writer.py` |
| Migration applied | `shared/database/migrations/di_013_attack_edge_validation.sql` |
| DI DB name | `threat_engine_di` on `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com` |