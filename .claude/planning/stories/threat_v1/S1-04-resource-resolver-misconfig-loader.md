# Story S1-04: ResourceResolver + MisconfigLoader (Reads Check DB)

## Status: ready

## Metadata
- **Sprint**: 1 — Foundation: Schema + GraphBuilder
- **Points**: 5
- **Priority**: P0
- **Depends on**: S1-01 (Neo4j schema), S1-02 (DB DDL), S1-03 (project structure), CP-1 gate signed off by SA
- **Blocks**: S1-06, S1-07, S1-08
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: CP-1 gate MUST be signed off before this story begins. SR consulted for cross-DB read pattern.

## Context

`ResourceResolver` determines the best `scan_run_id` to use for each engine DB when building the graph. `MisconfigLoader` reads `check_findings` joined with `rule_metadata` for the resolved scan_run_id and loads `(:Resource)-[:FAILED_CHECK]->(:MisconfigFinding)` nodes and edges into Neo4j.

This is the first story that touches the check engine DB from outside the check engine — it implements the cross-engine DB read pattern approved in ADR-006 (SECURITY_ARCHITECT_REVIEW.md).

## Security Framework Tags

**CP1-07**: scan_run_id ownership validated in S1-07 (Step 0 in run_scan.py) — must be in place before this loader can safely be invoked
**CP1-01**: No Cypher string interpolation in Neo4j writes — all properties passed as dict parameters
**STRIDE**: Spoofing (cross-tenant data read), Tampering (writing wrong tenant's findings into graph)

## Technical Notes

### Module locations
- `engines/threat_v1/threat_v1/graph/resource_resolver.py`
- `engines/threat_v1/threat_v1/graph/misconfig_loader.py`

### ResourceResolver logic
```python
def resolve(tenant_id: str, account_id: str) -> dict[str, str | None]:
    """
    For each engine DB, find the scan_run_id with the most findings
    for this tenant+account. Returns dict keyed by engine name.
    """
    # Query check DB:
    # SELECT scan_run_id, COUNT(*) FROM check_findings
    # WHERE tenant_id = %s AND account_id = %s
    # GROUP BY scan_run_id ORDER BY COUNT(*) DESC LIMIT 1
```

Returns `{"check": scan_run_id, "vuln": ..., "cdr": ..., "inventory": ...}`. None if no data for that engine.

### MisconfigLoader
Reads `check_findings` JOIN `rule_metadata` ON `rule_id`:
- `check_findings`: resource_uid, rule_id, status, severity, scan_run_id, tenant_id, account_id
- `rule_metadata`: title, mitre_techniques (JSONB dict — never call json.loads()), mitre_tactics, threat_category

JSONB note: psycopg2 auto-deserializes JSONB to Python dict — NEVER call `json.loads()` on these columns.

Writes to Neo4j using parameterized Cypher only:
```cypher
MERGE (r:Resource {resource_uid: $uid, tenant_id: $tid})
MERGE (f:MisconfigFinding {finding_id: $fid, tenant_id: $tid})
SET r += $r_props, f += $f_props
MERGE (r)-[:FAILED_CHECK]->(f)
```
All values passed as `$parameters` dict — never f-string or string concatenation in Cypher (CP1-01).

### Tenant scoping
Every query MUST include `WHERE tenant_id = %s AND account_id = %s`. No cross-tenant data may be loaded into the graph.

## Acceptance Criteria

- [ ] AC-1: `ResourceResolver.resolve(tenant_id, account_id)` returns correct scan_run_id per engine
- [ ] AC-2: `MisconfigLoader` creates `(:Resource)` and `(:MisconfigFinding)` nodes in Neo4j named db `threat_v1`
- [ ] AC-3: `FAILED_CHECK` edges created between Resource and MisconfigFinding
- [ ] AC-4: `mitre_techniques` from rule_metadata appears as list property on MisconfigFinding nodes
- [ ] AC-5: All check_findings queries scoped by `tenant_id + account_id` — no cross-tenant data
- [ ] AC-6: No `json.loads()` calls anywhere in misconfig_loader.py (JSONB is already a dict)
- [ ] AC-7: All Neo4j MERGE/SET uses parameter dict, never f-string Cypher (CP1-01)
- [ ] AC-8: CP-1 gate signed off before this story was started (documented in PR)

## Security Acceptance Criteria

- [ ] Cross-engine DB read uses read-only credentials — no write access to check DB
- [ ] Neo4j writes scoped to `threat_v1` named database only
- [ ] `tenant_id` present on every Resource and MisconfigFinding node written
- [ ] No `actor_principal` data touched in this loader (CDR-only PII concern, but verify)
- [ ] SR sign-off on cross-DB read pattern (ADR-006 consulted)

## Definition of Done

- [ ] `resource_resolver.py` committed with unit tests
- [ ] `misconfig_loader.py` committed with unit tests
- [ ] Integration test: run against real check DB, assert nodes in Neo4j
- [ ] CP-1 sign-off documented in PR thread
- [ ] SR consulted and sign-off recorded
- [ ] No json.loads() calls (grep verified)
- [ ] No f-string Cypher (grep verified)

## Verification

```bash
# After running MisconfigLoader against a known tenant:
# In Neo4j Browser (USE threat_v1):
MATCH (r:Resource {tenant_id: '<your-tenant-id>'}) RETURN count(r) AS resource_count
MATCH (f:MisconfigFinding {tenant_id: '<your-tenant-id>'}) RETURN count(f)
MATCH ()-[e:FAILED_CHECK]->() RETURN count(e) AS edge_count

# Verify no cross-tenant contamination:
MATCH (n) WHERE n.tenant_id <> '<your-tenant-id>' RETURN count(n) AS foreign_nodes
# Expected: 0
```
