# AP-DEDUP-01 — Exposure-Key Deduplication

**Sprint:** VAL-02 (alongside AP-VAL-03)
**Engine:** attack-path
**Priority:** High — reduces alert fatigue; required for actionable CNAPP-grade output
**Depends on:** VAL-01-D complete (is_attack_edge=TRUE filter in pg_graph)

---

## Problem

The current Phase 3 deduplicator groups paths by `(crown_jewel_uid, tuple(node_types[-2:]))`.
This groups by TARGET + last two RESOURCE TYPES, which creates separate groups for paths
that are actually the same exposure:

```
Path A:  Internet → API GW → Lambda → AppRole → S3-CustomerData
Path B:  Internet → ALB    → EC2    → AppRole → S3-CustomerData
```

Current Phase 3 computes:
- Path A group key: (S3-CustomerData, ("iam_role", "s3_bucket"))
- Path B group key: (S3-CustomerData, ("iam_role", "s3_bucket"))

These happen to group together because the last two TYPES match. But this is fragile:

```
Path C:  Internet → Lambda → AppRole → AdminRole → S3-CustomerData
```

- Path C group key: (S3-CustomerData, ("iam_role", "s3_bucket"))  ← same group!

But Path C is a DIFFERENT exposure: AdminRole (not AppRole) can reach S3.
AdminRole has broader blast radius. These must NOT be grouped together.

**Root cause:** Grouping by resource TYPES, not resource UIDs. Two different roles that
are both "iam_role" type collapse into the same group even though they're different principals
with different permission scopes.

---

## What Is a Privilege Hop?

A **privilege hop** is a path edge that crosses a privilege boundary — it transfers
what identity/permissions the attacker controls:

| Edge type | Privilege hop? | Meaning |
|-----------|---------------|---------|
| `CAN_ASSUME` | YES | Attacker can now act as the assumed role |
| `CAN_USE_IDENTITY` | YES | Compute resource acts as the role (EC2 → IAM role) |
| `CAN_READ` | NO (final cap) | Role reads the target asset |
| `CAN_DECRYPT` | NO (final cap) | Role decrypts via KMS |
| `CAN_INVOKE` | NO (final cap) | Role invokes the target function |
| `CAN_REACH` | NO (traversal) | Network reachability — no privilege transfer |

The **effective_access_principal** is the last node to cross a privilege boundary before
reaching the crown jewel. It is the node that HOLDS the final access capability.

In practice for the current path model: `effective_access_principal = node_uids[-2]`
(penultimate node — the last node before the crown jewel). This is true because the
final edge is always a capability edge (CAN_READ / CAN_DECRYPT / CAN_INVOKE).

The **access_capability** is the final edge type: `edge_types[-1]`.

---

## Exposure Key Model

```
Exposure Key = hash(
    target_uid,                  # crown_jewel_uid
    effective_access_principal,  # node_uids[-2]
    access_capability,           # edge_types[-1]
)
```

### Example 1 — Same Exposure, Different Routes

```
Path A:  Internet → API GW → Lambda → AppRole → S3-CustomerData
  effective_access_principal = AppRole ARN
  access_capability          = CAN_READ
  Exposure Key: hash(S3-CustomerData | AppRole-ARN | CAN_READ)

Path B:  Internet → ALB → EC2 → AppRole → S3-CustomerData
  effective_access_principal = AppRole ARN
  access_capability          = CAN_READ
  Exposure Key: hash(S3-CustomerData | AppRole-ARN | CAN_READ)
```

→ SAME KEY → single exposure group. Two entry points. One alert.

### Example 2 — Different Exposure (Different Principal)

```
Path C:  Internet → Lambda → AppRole → AdminRole → S3-CustomerData
  effective_access_principal = AdminRole ARN        ← DIFFERENT
  access_capability          = CAN_READ
  Exposure Key: hash(S3-CustomerData | AdminRole-ARN | CAN_READ)
```

→ DIFFERENT KEY → separate exposure. AdminRole has broader blast radius than AppRole.

### What Ops Sees

Instead of "47 attack paths to S3-CustomerData", ops sees:

```
Exposure: AppRole can CAN_READ CustomerDataBucket
  Entry points:  API Gateway, ALB
  Paths:         2
  Severity:      HIGH

Exposure: AdminRole can CAN_READ CustomerDataBucket
  Entry points:  Lambda
  Paths:         1
  Severity:      CRITICAL
```

This is the "actionable exposure" model used by Wiz, Orca, and Prisma Cloud.

---

## Implementation

### New `_exposure_key()` function

```python
_PRIVILEGE_EDGE_TYPES = frozenset({
    "can_assume", "can_use_identity",
})

_CAPABILITY_EDGE_TYPES = frozenset({
    "can_read", "can_decrypt", "can_invoke",
    "can_write", "can_execute", "can_create", "can_delete",
})

def _exposure_key(path: Path) -> str:
    """Compute exposure key: hash(target_uid | effective_access_principal | access_capability)."""
    if not path.node_uids or len(path.node_uids) < 2:
        # depth-0 path (resource is directly exposed AND a crown jewel)
        key_str = f"{path.crown_jewel_uid}||DIRECT_EXPOSURE"
    else:
        effective_principal = path.node_uids[-2]
        access_cap = (path.edge_types[-1] if path.edge_types else "unknown").lower()
        key_str = f"{path.crown_jewel_uid}|{effective_principal}|{access_cap}"
    return hashlib.sha256(key_str.encode()).hexdigest()[:16]
```

### Replace Phase 3 in `deduplicator.py`

Current Phase 3 (convergence grouping):
```python
# OLD: groups by (crown_jewel_uid, tuple(node_types[-2:]))  ← fragile: uses types not UIDs
groups: Dict[str, List[int]] = {}
for idx, p in enumerate(paths):
    last_two = tuple((p.node_types or [])[-2:])
    key_hash = _group_key_hash(p.crown_jewel_uid, last_two)
```

Replace with:
```python
# NEW: groups by (target_uid, effective_access_principal, access_capability)
groups: Dict[str, List[int]] = {}
for idx, p in enumerate(paths):
    key_hash = _exposure_key(p)
```

The rest of Phase 3 (representative selection, group_size, choke_node_uid) stays the same.

### New field on Path model: `effective_access_principal`

Add to `Path` and `ScoredPath` in `models/attack_path.py`:
```python
effective_access_principal: Optional[str] = None  # node_uids[-2], the principal that holds final access
access_capability:          Optional[str] = None  # edge_types[-1], e.g. "can_read"
```

Populate in `deduplicator.py` during Phase 3 grouping (or earlier during conversion
from ScoredPath → Path). The deduplicator already iterates all paths.

### BFF / DB writer impact

`writer.py` should persist `effective_access_principal` and `access_capability` to the
`attack_paths` table so BFF can expose them. Add columns:

```sql
-- Migration: di_015_attack_paths_exposure_fields.sql
ALTER TABLE attack_paths
    ADD COLUMN IF NOT EXISTS effective_access_principal VARCHAR(512),
    ADD COLUMN IF NOT EXISTS access_capability          VARCHAR(64);
```

BFF `/api/v1/views/attack-paths` response should expose these fields so the UI can
display "AppRole can CAN_READ CustomerDataBucket" instead of a raw path list.

---

## Files Changed

| File | Change |
|------|--------|
| `engines/attack-path/attack_path_engine/core/deduplicator.py` | Replace Phase 3 convergence grouping with exposure-key grouping; add `_exposure_key()` |
| `engines/attack-path/attack_path_engine/models/attack_path.py` | Add `effective_access_principal`, `access_capability` to `Path` + `ScoredPath` |
| `engines/attack-path/attack_path_engine/db/writer.py` | Persist new fields to `attack_paths` table |
| `shared/database/migrations/di_015_attack_paths_exposure_fields.sql` | ADD COLUMN `effective_access_principal`, `access_capability` to `attack_paths` |
| `shared/api_gateway/bff/attack_paths.py` | Expose new fields in BFF response; add `exposure_label` computed field |

---

## Acceptance Criteria

- [ ] Two paths with same `(crown_jewel_uid, node_uids[-2], edge_types[-1])` are in the same group
- [ ] Two paths with different `node_uids[-2]` (different privilege principals) are in different groups even if resource types match
- [ ] `effective_access_principal` and `access_capability` are populated on all `Path` objects with depth >= 1
- [ ] Depth-0 paths (direct exposure — resource is crown jewel AND internet-exposed) get `access_capability = 'DIRECT_EXPOSURE'`
- [ ] `attack_paths` DB table has new columns and they are populated by `writer.py`
- [ ] BFF response includes `effective_access_principal` and `access_capability` in each path object
- [ ] Phase 1 (exact dedup) and Phase 2 (subpath absorption) are unchanged
- [ ] Final path count after scan is <= count before this change (dedup is more aggressive, not less)
- [ ] Regression: same crown jewel reached by two different roles → 2 separate exposures (not 1)

---

## Definition of "Privilege Hop" for Narrative Engine

When the attack-path narrative engine explains a path, a privilege hop should be
rendered as a distinct step:

```
1. Internet → API Gateway (internet entry)
2. API Gateway → Lambda (service invocation)
3. Lambda → AppRole  ← PRIVILEGE HOP: "Lambda assumes AppRole identity"
4. AppRole → S3-CustomerData  ← ACCESS: "AppRole reads CustomerDataBucket"
```

The `hop_categories` array in `RawPath` should distinguish privilege hops.
Tag the hop `privilege_escalation` when the edge type is `can_assume` or `can_use_identity`.
This is already partially done in `_categorise_hop()` via the "identity" category but
is not specifically tagged as a privilege boundary crossing.

---

## Risk

**Low.** This is a pure dedup change — no engine API changes, no new DB reads, no
pipeline ordering changes. Worst case: different group assignments → slightly different
`is_representative` paths shown in UI. Attack path DATA is unchanged.

**Rollback:** Revert `deduplicator.py`. No migration rollback needed for phase 1 deployment
(migration adds nullable columns — safe to leave if code reverts).