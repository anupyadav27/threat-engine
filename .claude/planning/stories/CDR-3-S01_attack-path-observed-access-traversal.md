# CDR-3-S01: Attack-Path Graph Traversal via OBSERVED_ACCESS Edges

## Sprint
CDR-3 — Attack-Path Enrichment Sprint

## Priority
P0 — After CDR-1-S01 writes `OBSERVED_ACCESS` edges to `asset_relationships`, the attack-path engine must be updated to include these behavioral edges in graph traversal. Currently `pg_graph.py` builds the graph from structural edges only. Without this story, CDR-1-S01's work has no effect on attack paths.

## Depends On
**CDR-1-S01 must be deployed first** — OBSERVED_ACCESS edges must exist in `asset_relationships` before this story adds value.

## Story
As the attack-path engine, I need to traverse `OBSERVED_ACCESS` behavioral edges alongside structural edges when building attack paths, so that CDR-detected runtime access patterns create additional path vectors that reflect actual attacker behavior rather than only theoretical reachability.

## Background

`engines/attack-path/attack_path_engine/graph/pg_graph.py` builds the in-memory attack graph by querying `asset_relationships`. It fetches edges by `relation_type` — the exact list of relation types it accepts determines which edges are traversable.

`OBSERVED_ACCESS` edges written by CDR (CDR-1-S01) will appear in `asset_relationships` with:
- `relation_type = 'OBSERVED_ACCESS'`
- `relationship_category = 'behavioral'`
- `is_attack_edge = TRUE` (for severity high/critical)
- `confidence = 'high'` or `'medium'`

The attack-path scorer (`core/scorer.py`) already applies a ×1.50 multiplier for hops where `has_active_cdr_actor=TRUE` (read from posture). After this story, the path itself can now traverse through the observed access, not just boost the score on static paths.

## Files to Read First

- `engines/attack-path/attack_path_engine/graph/pg_graph.py` — find the SQL query that fetches edges from `asset_relationships`; find the `relation_type` filter / include list
- `engines/attack-path/attack_path_engine/core/scorer.py` — path scoring; understand how edge type affects per-hop score
- `engines/attack-path/attack_path_engine/models/attack_path.py` — `AttackPath` and `PathHop` models; check if `relation_type` is stored per hop
- `engines/attack-path/attack_path_engine/run_scan.py` — where `pg_graph.py` is called

## Files to Modify

| File | Change |
|---|---|
| `engines/attack-path/attack_path_engine/graph/pg_graph.py` | Include `OBSERVED_ACCESS` in traversable edge types; add `relationship_category='behavioral'` edges to graph |
| `engines/attack-path/attack_path_engine/core/scorer.py` | Apply behavioral edge bonus: `OBSERVED_ACCESS` hop with `is_attack_edge=TRUE` → ×1.30 multiplier (on top of existing CDR posture ×1.50 if both present) |
| `engines/attack-path/attack_path_engine/models/attack_path.py` | Ensure `hop.edge_type` or `hop.relation_type` is stored so the UI can label behavioral hops differently |

## Exact Changes

### `pg_graph.py` — edge fetch query

Find the query that reads from `asset_relationships`. It will have a `WHERE relation_type IN (...)` or similar filter. Add `'OBSERVED_ACCESS'` to the included types.

Additionally, flag behavioral edges in the graph node metadata:
```python
# When building graph edge metadata, add:
if row["relationship_category"] == "behavioral":
    edge_attrs["is_behavioral"] = True
    edge_attrs["confidence"] = row["confidence"]
```

Include only `OBSERVED_ACCESS` edges where `confidence IN ('high', 'medium')` — skip `low` confidence behavioral edges to avoid path explosion.

```sql
-- Add to the relation_type filter or as an additional OR clause:
OR (relation_type = 'OBSERVED_ACCESS' AND confidence IN ('high', 'medium'))
```

### `scorer.py` — behavioral edge multiplier

In the per-hop scoring loop, add:
```python
if hop.get("is_behavioral") and hop.get("relation_type") == "OBSERVED_ACCESS":
    hop_score *= 1.30  # confirmed observed access = higher confidence in path validity
```

This stacks with the existing ×1.50 for `has_active_cdr_actor` — a hop that is both an OBSERVED_ACCESS edge AND has active CDR posture gets ×1.30 × ×1.50 = ×1.95 total multiplier. Cap total multiplier at ×2.0 to avoid score runaway.

### `attack_path.py` — PathHop model

Ensure `relation_type` and `is_behavioral` are stored in the hop object so the BFF/UI can render behavioral edges differently (dashed line vs. solid line in graph viz).

## Acceptance Criteria

- [ ] After CDR-1-S01 deployed and a CDR scan runs, attack-path engine traverses `OBSERVED_ACCESS` edges in path-finding
- [ ] New paths found via OBSERVED_ACCESS edges appear in `attack_paths` table with `path_edges` containing the behavioral hop
- [ ] Paths through OBSERVED_ACCESS hops have higher score than equivalent paths through only structural edges (×1.30 multiplier applied)
- [ ] Total per-hop multiplier capped at ×2.0 (no runaway scoring)
- [ ] Structural paths (non-CDR) are unaffected — no regression in existing path scores
- [ ] `OBSERVED_ACCESS` edges with `confidence='low'` are NOT included in traversal
- [ ] `pg_graph.py` edge query still scoped by `tenant_id` and `scan_run_id`
- [ ] `PathHop` model stores `relation_type` and `is_behavioral=True` for behavioral hops
- [ ] Attack-path engine scan completes without error when no OBSERVED_ACCESS edges exist (backwards compat)

## Security Checklist

- [ ] Graph query scoped by `tenant_id` from AuthContext — no cross-tenant edge traversal
- [ ] `scan_run_id` scoping unchanged — only edges from current scan are traversed
- [ ] Multiplier cap prevents a tenant from artificially inflating scores via many CDR events

## MITRE ATT&CK Coverage
- TA0008 Lateral Movement — OBSERVED_ACCESS edges represent confirmed inter-resource traversal
- TA0010 Exfiltration — OBSERVED_ACCESS to storage resources creates exfil paths

## Definition of Done

- [ ] `pg_graph.py` includes OBSERVED_ACCESS in traversable edges
- [ ] `scorer.py` applies ×1.30 multiplier for behavioral hops, capped at ×2.0
- [ ] `attack_path.py` stores `relation_type` per hop
- [ ] Manual verify: test-tenant-002 — after CDR scan + attack-path re-run, query `attack_paths` for paths containing OBSERVED_ACCESS hops
- [ ] Regression check: existing test-tenant-002 paths still present (count should increase, not decrease)
- [ ] Image tag bumped in `deployment/aws/eks/engines/engine-attack-path.yaml`
- [ ] ⚠ Use `kubectl set image` after `kubectl apply` — VSCode linter silently reverts engine-attack-path.yaml tags