# Story AP-P2-05: Deduplicator

## Status: ready

## Metadata
- **Phase**: P2 — Attack Path Engine Core
- **Epic**: Attack Path Engine
- **Points**: 5
- **Priority**: P0
- **Depends on**: AP-P2-04 (scored paths needed as input), AP-P0-01 (posture table needed for subpath absorption exposure check)
- **Blocks**: AP-P2-06 (choke point detector receives deduplicated paths), AP-P2-07 (run_scan.py orchestrates dedup)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — deduplication incorrectly absorbing an independently-exposed entry point is a security defect (masks real attack paths).

## User Story

As the attack-path engine, I want a three-phase deduplicator that reduces thousands of raw BFS paths to fewer than 200 representative paths, so that the analyst-facing view is navigable and focuses on distinct exposures rather than combinatorial noise.

## Context

Without deduplication, the reverse BFS returns up to 500 raw paths per crown jewel, potentially thousands across all crown jewels for a large tenant. Many paths are:
- Exact duplicates (same nodes, different Neo4j traversal order)
- Subpaths of longer paths (EC2→S3 is a suffix of Internet→EC2→S3 and not independently exposed)
- Convergent paths to the same crown jewel via the same penultimate node

The three-phase algorithm from architecture doc section 6 handles each case. The implementation must match the algorithm exactly, including the independence check in Phase 2 (a subpath's entry node must NOT be independently internet-exposed to be absorbed — if it IS independently exposed, it remains a separate path).

Target: fewer than 200 representative paths per tenant after all three phases.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
ID.RA-3 (threats identified — dedup must not lose distinct threats)

**CSA CCM v4 Domain(s)**
- IVS-01 (Infrastructure Security), SEF-01 (Security Event Analysis)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | Phase 2 absorption | Subpath with independently-exposed entry node is absorbed → real entry point hidden from analyst | Independence check: `posture_lookup[entry_uid].is_internet_exposed` must be False for absorption to occur |
| Tampering | group_id assignment | sha256 of group_key is predictable — attacker might try to cause path collision | path_id is sha256 of node_uids (content-based), not sequential; collision is computationally infeasible |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1190 | Exploit Public-Facing Application | Phase 2 preserves independently internet-exposed entry points — they are NOT absorbed even if they appear as subpaths |

## Acceptance Criteria

### Functional
- [ ] AC-1: File `engines/attack-path/attack_path_engine/core/deduplicator.py` created
- [ ] AC-2: `deduplicate(raw_paths, posture_lookup) -> list[Path]` function implements all three phases from architecture doc section 6 exactly
- [ ] AC-3: Phase 1 (exact dedup): `sha256("|".join(node_uids).encode()).hexdigest()` used as dedup key; highest-scoring path wins on collision
- [ ] AC-4: Phase 2 (subpath absorption): short path absorbed into long path ONLY IF `is_suffix(short.node_uids, long.node_uids)` AND `posture_lookup[short.node_uids[0]].is_internet_exposed == False`
- [ ] AC-5: `is_suffix(short, long)` function: returns True if `long[-len(short):] == short` AND `len(short) < len(long)`
- [ ] AC-6: Absorbed path count stored in `absorbed_count` on the absorbing path
- [ ] AC-7: Phase 3 (convergence grouping): group key = `(crown_jewel_uid, tuple(node_types[-2:]))` — paths sharing same crown jewel and last-2-node-types share a `group_id`
- [ ] AC-8: `group_id` = first 12 chars of `sha256(str(group_key).encode()).hexdigest()`
- [ ] AC-9: `is_representative=True` for the highest-scoring path in each group
- [ ] AC-10: `choke_node_uid` = `node_uids[-2]` of the group (penultimate node in shared tail) for groups with > 1 path; None for single-path groups
- [ ] AC-11: `group_size` populated with count of paths in the group

### Unit Tests
- [ ] AC-12: `tests/attack_path/test_deduplicator.py` created with ALL of the following test cases:
  - Phase 1: two paths with identical node_uids — lower-scored one removed
  - Phase 2: subpath with non-internet-exposed entry absorbed into longer path (absorbed_count = 1)
  - Phase 2: subpath with internet-exposed entry NOT absorbed (both paths survive)
  - Phase 3: two paths with same (crown_jewel_uid, last-2-node-types) → same group_id
  - Phase 3: correct path marked is_representative=True (highest score in group)
  - Phase 3: choke_node_uid = penultimate node of group tail
  - End-to-end: 10 input paths → fewer than 10 output paths after all three phases

### Security (must pass bmad-security-reviewer)
- [ ] AC-13: Phase 2 independence check uses `posture_lookup` (DB-sourced) — NEVER trusts node metadata from Neo4j path alone
- [ ] AC-14: deduplicator does not accept raw DB connections — receives `posture_lookup` dict
- [ ] AC-15: sha256 used from Python standard library `hashlib` — no third-party crypto dependency

## Technical Notes

**File**: `engines/attack-path/attack_path_engine/core/deduplicator.py`

The `posture_lookup` dict maps `resource_uid → PostureRow` (same as scorer uses). The deduplicator needs only `is_internet_exposed` from the posture row for Phase 2.

**Phase order**: 1 → 2 → 3. Phases must run in this order (exact dedup first, then absorption of remaining paths, then convergence grouping of remaining paths).

**Phase 2 sorting**: Before Phase 2, sort paths by `len(node_uids)` descending (longest first) so outer loop iterates over potential absorbers.

**absorbed_count tracking**: When path j is absorbed into path i, increment `paths[i].absorbed_count += 1`. The UI shows "This path absorbs N shorter routes."

**Path dataclass** (or Pydantic model) needs these fields after dedup:
- All RawPath fields
- Plus: `group_id: str | None`, `group_size: int`, `is_representative: bool`, `choke_node_uid: str | None`, `absorbed_count: int`

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/core/deduplicator.py` (create new)
- `/Users/apple/Desktop/threat-engine/tests/attack_path/test_deduplicator.py` (create new)

## Definition of Done
- [ ] `deduplicator.py` committed with all three phases
- [ ] All 7 unit test cases pass: `pytest tests/attack_path/test_deduplicator.py -v`
- [ ] Phase 2 independence check verified: internet-exposed subpath entry survives (not absorbed)
- [ ] Phase 3 group_id, is_representative, choke_node_uid all correctly set
- [ ] End-to-end test: 10 input paths with known structure → correct output count
- [ ] bmad-security-reviewer: no BLOCKERS (critical: Phase 2 independence check correctness)