---
story_id: AZ-15
title: Fix Neo4j Label Function for Multi-CSP + Add Provider Property
status: done
sprint: azure-track-wave-7
depends_on: [AZ-06]
blocks: [AZ-16]
sme: Backend/Neo4j engineer
estimate: 0.5 days
---

# Story: Fix Neo4j _neo4j_label() for Multi-CSP + Add Provider Property

## Context
`graph_builder.py` converts `resource_type` to a Neo4j node label via `_neo4j_label()`. AWS types use dot-notation (`ec2.instance` → `EC2Instance`). Azure/GCP/K8s types are already PascalCase (`VirtualMachine`, `GCEInstance`, `Pod`). The current fallback for non-dot types returns `"CloudResource"` — this must return the type as-is instead.

Also: all Resource nodes need a `provider` property added to their MERGE/SET so Cypher queries can filter by CSP.

## Files to Modify

- `engines/threat/threat_engine/graph/graph_builder.py`
  - Fix `_neo4j_label()` function
  - Add `provider` to Resource node MERGE/SET

## Implementation Notes

**Fix `_neo4j_label()`:**
```python
def _neo4j_label(resource_type: str) -> str:
    """Convert resource_type string to Neo4j node label.
    
    AWS format:    'ec2.instance'    → 'EC2Instance'
    Azure format:  'VirtualMachine'  → 'VirtualMachine' (unchanged)
    GCP format:    'GCEInstance'     → 'GCEInstance'    (unchanged)
    K8s format:    'Pod'             → 'Pod'             (unchanged)
    """
    if not resource_type:
        return "Resource"
    if "." in resource_type:
        # AWS dot-notation: "ec2.instance" → "EC2Instance"
        parts = resource_type.split(".")
        return "".join(p.title() for p in parts)
    # Azure/GCP/K8s: already PascalCase — use as-is
    return resource_type
```

**Add `provider` to Resource node (find the MERGE statement in graph_builder.py):**
```cypher
-- Current (approximate):
MERGE (r:Resource {uid: $uid})
SET r.name = $name, r.resource_type = $resource_type, r.tenant_id = $tenant_id

-- Add provider:
SET r.name = $name, r.resource_type = $resource_type, 
    r.tenant_id = $tenant_id, r.provider = $provider
```

Find the exact MERGE/SET in `graph_builder.py` — search for `r.resource_type` to locate it.

## Acceptance Criteria
- [ ] `_neo4j_label("ec2.instance")` returns `"EC2Instance"` (unchanged — regression check)
- [ ] `_neo4j_label("VirtualMachine")` returns `"VirtualMachine"` (NOT "CloudResource")
- [ ] `_neo4j_label("GCEInstance")` returns `"GCEInstance"`
- [ ] `_neo4j_label("Pod")` returns `"Pod"`
- [ ] `_neo4j_label("")` returns `"Resource"` (unchanged)
- [ ] After Azure scan imported to Neo4j: `MATCH (r:Resource {provider: 'azure'}) RETURN count(r)` > 0
- [ ] After Azure scan: `MATCH (r:VirtualMachine) RETURN count(r)` > 0 (label used, not "CloudResource")

## Definition of Done
- [ ] `_neo4j_label()` updated + unit-tested (all 5 test cases above)
- [ ] `provider` property added to Resource node MERGE/SET
- [ ] Verified with live Azure scan data in Neo4j (AZ-13 must be done first)
- [ ] Existing AWS nodes still have correct labels (regression check on AWS scan)