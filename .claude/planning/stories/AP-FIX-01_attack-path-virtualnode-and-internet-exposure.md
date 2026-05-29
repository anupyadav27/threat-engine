# AP-FIX-01 — Attack Path: VirtualNode Filter + Internet Exposure Write

## Status
`done`

## Blocked By
**RID-01** — `RID-01_resource-id-standardisation.md`
After RID-01 ships, `resource_uid` values in all tables will be canonical ARNs/K8s paths.
The attack-path BFS will then correctly join Neo4j node UIDs → posture → findings.
The VirtualNode scaffolding nodes will have no matching posture rows and will be naturally excluded.

## Problem Summary
Two bugs make the Attack Path canvas useless in production:

1. **VirtualNode on canvas** — K8s topology hierarchy nodes (`account:vulnerability-eks-cluster`,
   `region:cluster`) appear as regular resource cards in the attack path canvas. These are Neo4j
   graph scaffolding nodes, not real cloud resources. They have `node_type = 'VirtualNode'` in
   `attack_path_nodes`.

2. **Only K8s paths found** — `resource_security_posture.is_internet_exposed` has ZERO rows,
   so the BFS finds no real AWS entry points. Only VirtualNode paths (K8s EKS → K8s Secret)
   are returned. No EC2 → IAM → S3, no Lambda → IAM → KMS, etc.

## Root Cause

### VirtualNode
Neo4j graph build script (`load_neo4j_graph.py` in threat_v1) creates topology scaffolding
nodes with label `VirtualNode` and UIDs like `account:vulnerability-eks-cluster`. The BFS
Cypher includes `OR origin:VirtualNode` making them valid entry points. The `write_path_nodes`
writer stores them in `attack_path_nodes` with `node_type = 'VirtualNode'`. The API returns
them raw in `steps[]`.

### is_internet_exposed = 0
The attack-path engine reads `resource_security_posture.is_internet_exposed = true` at Stage 2a
(`_fetch_internet_exposed_uids`). No engine currently writes this column. Network engine
computes internet reachability but does not write to posture. Discovery engine has
`PublicIpAddress`, `PubliclyAccessible`, `Scheme` fields in `emitted_fields` but these are
never aggregated into `is_internet_exposed`.

## Acceptance Criteria

### Fix 1 — VirtualNode filtered from API response
- [ ] `GET /api/v1/attack-paths/{path_id}` never returns a step with `node_type = 'VirtualNode'`
- [ ] Canvas shows only real cloud resource hops
- [ ] If ALL hops in a path are VirtualNode (degenerate path), the path is excluded from the list

### Fix 2 — Internet exposure write path
- [ ] After attack-path engine Stage 2a-pre runs, `resource_security_posture.is_internet_exposed`
      is `true` for EC2 instances with public IPs, RDS with `PubliclyAccessible=true`,
      ALBs with `Scheme=internet-facing`, Lambda with public URLs
- [ ] BFS finds paths: EC2 (internet-exposed) → IAM Role → S3 crown jewel
- [ ] At least one AWS attack path appears in the canvas alongside K8s paths

### Fix 3 — Canvas defensive guard (frontend)
- [ ] `AttackPathCanvas.jsx` skips rendering any step where `node_type === 'VirtualNode'`
- [ ] No blank/broken cards on canvas if VirtualNode slips through

## Technical Notes

### Fix 1 — routes.py (engine side)
File: `engines/attack-path/attack_path_engine/api/routes.py`
In `get_attack_path_detail()` after fetching steps, add:
```python
steps = [s for s in steps if s.get("node_type") != "VirtualNode"]
```
Also in `_fetch_attack_paths()`, exclude paths where ALL node_types are VirtualNode:
```python
AND NOT (node_types <@ ARRAY['VirtualNode']::text[])
```

### Fix 2 — run_scan.py (engine side)
File: `engines/attack-path/attack_path_engine/run_scan.py`

Add Stage 2a-pre: `_mark_internet_exposed_from_discoveries()` that:
1. Connects to discoveries DB via `get_discoveries_conn()`
2. Queries `discovery_findings.emitted_fields` for:
   - `PublicIpAddress IS NOT NULL` → EC2 instances, ENIs
   - `PubliclyAccessible = 'true'` → RDS, ElastiCache, Redshift
   - `Scheme = 'internet-facing'` → ALB, NLB, Classic ELB
   - `FunctionUrl IS NOT NULL` → Lambda
   - resource_type IN ('apigateway.restapi', 'apigateway.httpapi') → always public
3. Bulk-upserts `is_internet_exposed = true` into `resource_security_posture`
   using ON CONFLICT (resource_uid, tenant_id) DO UPDATE

Run this BEFORE `_fetch_internet_exposed_uids()` so the BFS gets populated entry points.

Key: do NOT set `is_internet_exposed = false` for anything here — only assert true.
The network engine owns the authoritative false value.

### Fix 3 — AttackPathCanvas.jsx (frontend)
File: `frontend/src/app/attack-paths/AttackPathCanvas.jsx`
In `stepsToGraph()`, skip VirtualNode steps:
```js
const visibleSteps = steps.filter(s => s.node_type !== 'VirtualNode');
```

## Files to Change
- `engines/attack-path/attack_path_engine/api/routes.py` — filter VirtualNode from steps[]
- `engines/attack-path/attack_path_engine/run_scan.py` — add Stage 2a-pre internet exposure write
- `frontend/src/app/attack-paths/AttackPathCanvas.jsx` — skip VirtualNode in canvas render

## DB Impact
- `resource_security_posture.is_internet_exposed` — upsert only (existing column, no migration)
- `attack_path_nodes` — read only (filter happens at API layer, no schema change)

## Images to Build After Fix
- `engine-attack-path` — routes.py + run_scan.py changed
- `frontend` — AttackPathCanvas.jsx changed

## Test Verification
1. Port-forward attack-path engine: `kubectl port-forward svc/engine-attack-path 8025:80 -n threat-engine-engines`
2. Trigger scan: `POST /api/v1/internal/scan` with valid scan_run_id + tenant_id
3. Fetch path detail: `GET /api/v1/attack-paths/{path_id}` — confirm no `node_type=VirtualNode` in steps
4. Check posture: query `SELECT resource_uid, is_internet_exposed FROM resource_security_posture WHERE is_internet_exposed = true LIMIT 20` — should return EC2/RDS/ALB rows
5. Canvas: open `/attack-paths` — VirtualNode should not appear; AWS resource paths should appear alongside K8s paths