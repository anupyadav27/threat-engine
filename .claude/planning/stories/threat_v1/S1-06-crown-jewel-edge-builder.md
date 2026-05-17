# Story S1-06: CrownJewelClassifier + EdgeBuilder

## Status: ready

## Metadata
- **Sprint**: 1 — Foundation: Schema + GraphBuilder
- **Points**: 5
- **Priority**: P0
- **Depends on**: S1-04, S1-05 (Resource nodes must exist in graph before edges are added)
- **Blocks**: S1-08, Sprint 2 (PatternExecutor needs crown jewel flags and CONNECTED_TO edges)
- **RACI**: R=DEV A=DL C=ARCH,SA I=PO,QA
- **Security Gate**: ARCH consulted for edge type mapping from inventory_relationships. CP1-03 — crown jewel property set ONLY by this classifier, never by API callers.

## Context

`CrownJewelClassifier` reads `resource_inventory_identifier` + `inventory_findings` to determine which assets are crown jewels, then sets `is_crown_jewel=true` on those Resource nodes in Neo4j.

`EdgeBuilder` reads `inventory_relationships` to create `CONNECTED_TO` (network) and `CONTAINS` (parent/child) edges between Resource nodes already in the graph.

Together these complete the graph: nodes from S1-04/S1-05 + crown jewel flags + relationship edges = full security graph ready for PatternExecutor.

## Technical Notes

### Module locations
- `engines/threat_v1/threat_v1/graph/crown_jewel_classifier.py`
- `engines/threat_v1/threat_v1/graph/edge_builder.py`

### CrownJewelClassifier logic (from REQUIREMENTS §6.3)
Crown jewel = resource meeting ≥ 2 of:
1. `asset_category IN ('data-store', 'secret-store', 'identity-provider')`
2. `access_pattern = 'internet-facing'`
3. `criticality IN ('critical', 'high')`
4. `environment = 'production'`
5. `risk_score >= 80`
6. `tags JSONB @> '[{"key":"crown-jewel","value":"true"}]'`

Query joins `inventory_findings` → `resource_inventory_identifier` for the tenant.

Sets Neo4j property:
```cypher
MATCH (r:Resource {resource_uid: $uid, tenant_id: $tid})
SET r.is_crown_jewel = true, r.crown_jewel_reason = $reason
```

CP1-03: this is the ONLY place `is_crown_jewel` is set to true from automated logic. Manual overrides go through `POST /api/v1/crown-jewels` endpoint which writes to `threat_crown_jewels` table, then this classifier reads that table as a 7th criterion.

### EdgeBuilder
Reads `inventory_relationships` table (inventory engine DB):
```sql
SELECT source_resource_uid, target_resource_uid, relationship_type, attack_path_category
FROM inventory_relationships
WHERE tenant_id = %s
```

Maps `relationship_type` to Neo4j edge type:
- `NETWORK` → `CONNECTED_TO`
- `PARENT_CHILD` / `CONTAINS` / `vpc_subnet` / `cluster_pod` → `CONTAINS`
- Others → `CONNECTED_TO` (default, log unknown type as WARNING)

Only creates edges where BOTH source and target Resource nodes already exist in Neo4j (MERGE pattern — no dangling edges).

```cypher
MATCH (src:Resource {resource_uid: $src, tenant_id: $tid})
MATCH (tgt:Resource {resource_uid: $tgt, tenant_id: $tid})
MERGE (src)-[:CONNECTED_TO {attack_path_category: $apc}]->(tgt)
```

## Acceptance Criteria

- [ ] AC-1: `CrownJewelClassifier.classify(tenant_id, account_id)` sets `is_crown_jewel=true` on qualifying Resource nodes
- [ ] AC-2: Crown jewel classification uses ≥ 2 of the 6 criteria from REQUIREMENTS §6.3
- [ ] AC-3: Manual overrides from `threat_crown_jewels` table are respected as 7th criterion
- [ ] AC-4: `EdgeBuilder` creates `CONNECTED_TO` edges from inventory_relationships
- [ ] AC-5: `CONTAINS` edges created for parent/child relationships
- [ ] AC-6: No edges created for Resource UIDs not in the graph (MATCH not MERGE for endpoint nodes)
- [ ] AC-7: All Neo4j writes parameterized — no f-string Cypher (CP1-01)
- [ ] AC-8: Unknown relationship_type logged as WARNING, not crash

## Security Acceptance Criteria

- [ ] `is_crown_jewel` can only be set to `true` by CrownJewelClassifier (CP1-03) — no other code path sets this
- [ ] API crown jewel endpoint writes to `threat_crown_jewels` table, reads by this classifier — not direct graph write
- [ ] Tenant_id filter on all inventory_relationships queries — no cross-tenant edges
- [ ] ARCH sign-off on edge type mapping from inventory_relationships

## Definition of Done

- [ ] `crown_jewel_classifier.py` committed with unit tests
- [ ] `edge_builder.py` committed with unit tests
- [ ] Integration test: verify `is_crown_jewel=true` set on data-store + production resource
- [ ] ARCH consulted and sign-off documented
- [ ] Grep: no other file sets `is_crown_jewel` property in Neo4j (CP1-03)

## Verification

```bash
# In Neo4j Browser (USE threat_v1):
MATCH (r:Resource {is_crown_jewel: true, tenant_id: '<tid>'})
RETURN r.resource_uid, r.resource_type, r.crown_jewel_reason LIMIT 10

MATCH ()-[e:CONNECTED_TO]->() RETURN count(e) AS network_edges
MATCH ()-[e:CONTAINS]->() RETURN count(e) AS containment_edges
```
