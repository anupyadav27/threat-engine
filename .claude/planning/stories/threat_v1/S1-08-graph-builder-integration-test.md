# Story S1-08: GraphBuilder Integration Test

## Status: ready

## Metadata
- **Sprint**: 1 — Foundation: Schema + GraphBuilder
- **Points**: 3
- **Priority**: P0
- **Depends on**: S1-04, S1-05, S1-06, S1-07 (all loaders + ownership gate complete)
- **Blocks**: Sprint 2 start (PatternExecutor needs a verified graph)
- **RACI**: R=QA,DEV A=QA C=ARCH I=DL,PO
- **Security Gate**: Must use real DB with real scan_run_id — NO mocks. QA owns this story.

## Context

Verifies the complete GraphBuilder pipeline end-to-end using real databases. Confirms: node counts are non-zero, edges are present, tenant_id is set on all nodes, and no cross-tenant data appears in the graph. This is the Sprint 1 completion gate.

Must use real data — a known scan_run_id from a tenant that has actual check_findings and cdr_findings in the live DBs. No mocking of DB connections.

## Technical Notes

### Output file
`engines/threat_v1/tests/integration/test_graph_builder.py`

### Test fixture
Use the existing tenant and scan_run_id with known data. Get current scan_run_id from:
```bash
kubectl exec -n threat-engine-engines deployment/engine-check-aws -- python3 -c "
import psycopg2, os
conn = psycopg2.connect(host=os.environ['DB_HOST'], ...)
cur = conn.cursor()
cur.execute('SELECT scan_run_id, COUNT(*) FROM check_findings WHERE tenant_id=%s GROUP BY 1 ORDER BY 2 DESC LIMIT 1', ('my-tenant',))
print(cur.fetchone())
"
```

### Assertions required

```python
def test_resource_nodes_created(neo4j_session, tenant_id):
    result = neo4j_session.run(
        "MATCH (r:Resource {tenant_id: $tid}) RETURN count(r) AS n",
        tid=tenant_id
    )
    assert result.single()["n"] >= 1

def test_misconfig_finding_nodes(neo4j_session, tenant_id):
    result = neo4j_session.run(
        "MATCH (f:MisconfigFinding {tenant_id: $tid}) RETURN count(f) AS n",
        tid=tenant_id
    )
    assert result.single()["n"] >= 1

def test_failed_check_edges_present(neo4j_session, tenant_id):
    result = neo4j_session.run(
        "MATCH (:Resource {tenant_id: $tid})-[e:FAILED_CHECK]->(:MisconfigFinding) RETURN count(e) AS n",
        tid=tenant_id
    )
    assert result.single()["n"] >= 1

def test_all_resource_nodes_have_tenant_id(neo4j_session, tenant_id):
    # No Resource node should lack tenant_id
    result = neo4j_session.run(
        "MATCH (r:Resource) WHERE r.tenant_id IS NULL RETURN count(r) AS n"
    )
    assert result.single()["n"] == 0

def test_no_cross_tenant_contamination(neo4j_session, tenant_id, other_tenant_id):
    # Nodes for other tenant should not appear when querying by this tenant
    result = neo4j_session.run(
        "MATCH (n {tenant_id: $tid}) WHERE n.tenant_id <> $tid RETURN count(n) AS n",
        tid=tenant_id
    )
    assert result.single()["n"] == 0

def test_neo4j_named_db_is_threat_v1(neo4j_driver):
    # Verify we are connected to threat_v1, not default
    with neo4j_driver.session(database="threat_v1") as s:
        result = s.run("CALL db.info() YIELD name RETURN name")
        assert result.single()["name"] == "threat_v1"

def test_actor_principal_not_stored(neo4j_session):
    # CDRActor nodes must not have actor_principal property (CP1-02)
    result = neo4j_session.run(
        "MATCH (a:CDRActor) WHERE a.actor_principal IS NOT NULL RETURN count(a) AS n"
    )
    assert result.single()["n"] == 0
```

### Neo4j connection fixture
```python
@pytest.fixture(scope="session")
def neo4j_driver():
    return GraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=(os.environ["NEO4J_USERNAME"], os.environ["NEO4J_PASSWORD"])
    )

@pytest.fixture(scope="session")
def neo4j_session(neo4j_driver):
    with neo4j_driver.session(database="threat_v1") as session:
        yield session
```

## Acceptance Criteria

- [ ] AC-1: `test_resource_nodes_created` passes — at least 1 Resource node for test tenant
- [ ] AC-2: `test_misconfig_finding_nodes` passes — at least 1 MisconfigFinding node
- [ ] AC-3: `test_failed_check_edges_present` passes — at least 1 FAILED_CHECK edge
- [ ] AC-4: `test_all_resource_nodes_have_tenant_id` passes — no nodes with NULL tenant_id
- [ ] AC-5: `test_no_cross_tenant_contamination` passes — no foreign tenant nodes
- [ ] AC-6: `test_neo4j_named_db_is_threat_v1` passes — connected to correct named DB
- [ ] AC-7: `test_actor_principal_not_stored` passes — PII not in graph (CP1-02)
- [ ] AC-8: All tests use real DBs — no unittest.mock or MagicMock for DB connections

## Security Acceptance Criteria

- [ ] Test uses `database="threat_v1"` explicitly in session — cannot accidentally run against default DB
- [ ] Test credentials from env vars only — not hardcoded
- [ ] `test_actor_principal_not_stored` is mandatory — not optional
- [ ] Cross-tenant isolation test covers at least 2 different tenant IDs

## Definition of Done

- [ ] `tests/integration/test_graph_builder.py` committed
- [ ] All 7 tests pass against real DBs
- [ ] Test output captured and attached to Sprint 1 PR
- [ ] QA sign-off: "S1-08 PASSED — Sprint 2 UNBLOCKED"
- [ ] ARCH peer review complete

## Verification SQL (pre-test check)
```sql
-- Verify real data exists before running the test:
-- Against check DB:
SELECT COUNT(*) FROM check_findings WHERE tenant_id = '<your-tenant-id>';
-- Expected: > 0

-- Against threat DB (after S1-02 migration):
SELECT COUNT(*) FROM threat_incidents WHERE tenant_id = '<your-tenant-id>';
-- Will be 0 until PatternExecutor runs in Sprint 2 — that is expected
```
