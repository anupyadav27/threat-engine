# Story AP-P2-03: Reverse BFS Cypher Query

## Status: ready

## Metadata
- **Phase**: P2 — Attack Path Engine Core
- **Epic**: Attack Path Engine
- **Points**: 5
- **Priority**: P0
- **Depends on**: AP-P2-02 (engine scaffold), AP-P1-01 (crown jewels classified in Neo4j), AP-P0-03 (posture signals available)
- **Blocks**: AP-P2-04 (scorer reads raw paths from BFS), AP-P2-05 (deduplicator receives BFS output), AP-P2-07 (run_scan.py orchestrates BFS)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory (Neo4j query + tenant isolation). bmad-security-architect reviews Cypher query for injection risk.

## User Story

As the attack-path engine, I want a Neo4j client with a `reverse_bfs()` method that traverses PATH edges backward from crown jewels to external entry points, so that I can discover all structural attack paths for a tenant within 30 seconds and within a 500-path result limit.

## Context

The BFS algorithm is the heart of the attack-path engine. It starts from crown jewel nodes (classified in AP-P1-01), traverses PATH edges in reverse (toward the origin), and stops when reaching an internet-exposed, OnPrem, VPN, or PeerAccount virtual node.

The Cypher query is defined in full in architecture doc section 4.2. It must be implemented exactly as specified — the evidence collection phase (OPTIONAL MATCH for CVE/finding/threat nodes) is part of the same query so that evidence arrives with each path.

Query timeout: 30 seconds enforced at the neo4j driver level. If a timeout occurs, log a WARNING and return the partial results collected before timeout (do not raise an exception that breaks the scan).

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
ID.RA-3 (threats identified), DE.CM-1 (network monitored via path detection)

**CSA CCM v4 Domain(s)**
- IVS-01 (Infrastructure Security), SEF-01 (Security Event Analysis)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | Neo4j query | Cross-tenant path leakage — query returns nodes from wrong tenant | All MATCH clauses include `{tenant_id: $tid}` property filter; parameterized query (no string interpolation of tenant_id) |
| DoS | reverse_bfs | Large tenant triggers traversal of 100k nodes, exhausting Neo4j memory | LIMIT 500 in Cypher; 30-second timeout at driver level; Argo step retry=0 |
| Spoofing | Neo4j driver | Attacker replaces Neo4j URI env var to redirect queries to attacker-controlled graph | NEO4J_URI from secret (threat-engine-db-passwords); not from request input |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | BFS traverses ASSUMES edges — paths via IAM role assumptions are discovered |
| T1530 | Data from Cloud Storage Object | BFS terminates at crown jewel data stores — paths to PII storage found |
| T1190 | Exploit Public-Facing Application | Entry point filter: internet-exposed resources detected as path origins |

## Acceptance Criteria

### Functional
- [ ] AC-1: File `engines/attack-path/attack_path_engine/graph/neo4j_client.py` created
- [ ] AC-2: `Neo4jClient` class wraps the neo4j Python driver with connection lifecycle management
- [ ] AC-3: `reverse_bfs(tenant_id, scan_run_id, max_hops=7)` method implemented
- [ ] AC-4: Cypher query matches architecture doc section 4.2 exactly — no structural modifications without architecture review
- [ ] AC-5: Query uses `$tid` parameter for tenant_id — no string interpolation of tenant_id into Cypher
- [ ] AC-6: Query includes both phases: Phase 1 (backward PATH traversal) and Phase 2 (evidence collection via OPTIONAL MATCH for CVE/Finding/ThreatDetection nodes)
- [ ] AC-7: Query enforces `LIMIT 500` at Cypher level
- [ ] AC-8: 30-second timeout enforced at neo4j driver level (`timeout=30.0` on session or transaction)
- [ ] AC-9: On timeout, method logs `WARNING: Neo4j BFS timeout after 30s, returning partial results` and returns whatever was collected before timeout
- [ ] AC-10: Return type is `list[RawPath]` where `RawPath` is a Pydantic model with fields: `crown_jewel_uid`, `entry_point_uid`, `node_uids`, `node_types`, `edge_types`, `hop_categories`, `depth`, `max_epss`, `misconfig_count`, `threat_count`, `top_cves` — matching the Cypher RETURN clause
- [ ] AC-11: `models/attack_path.py` contains the `RawPath` Pydantic model
- [ ] AC-12: Method validated manually against live Neo4j Aura instance with at least 3 known paths found

### Security (must pass bmad-security-reviewer)
- [ ] AC-13: ALL Cypher MATCH clauses that touch resource nodes include `tenant_id: $tid` — verified by code review
- [ ] AC-14: NEO4J_URI read from environment variable (not hardcoded)
- [ ] AC-15: neo4j driver credentials (NEO4J_USER, NEO4J_PASSWORD) read from environment — not from request input
- [ ] AC-16: No Cypher string injection — all variable values passed as query parameters
- [ ] AC-17: Neo4j connection uses encrypted transport (URI scheme `neo4j+s://` for Aura)

## Technical Notes

**File**: `engines/attack-path/attack_path_engine/graph/neo4j_client.py`

**Cypher** is defined verbatim in architecture doc section 4.2. Key structural notes:
- Phase 1 traversal: `MATCH path = (origin:Resource)-[rels*1..7]->(crown)` (backward — origin → crown)
- Entry point filter uses OR across 5 virtual node types (Internet, OnPrem, VPN, PeerAccount, peer_account)
- Phase 2 evidence: UNWIND nodes(path) AS hop_node with 3 OPTIONAL MATCH clauses
- RETURN includes aggregate functions: `max(c.epss_score) AS max_epss`, `count(DISTINCT f) AS misconfig_count`

**Driver pattern** (neo4j Python driver):
```python
from neo4j import GraphDatabase

class Neo4jClient:
    def __init__(self):
        self.driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI"),
            auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD"))
        )

    def reverse_bfs(self, tenant_id: str, scan_run_id: str, max_hops: int = 7) -> list:
        with self.driver.session(database="neo4j") as session:
            result = session.run(
                REVERSE_BFS_CYPHER,
                tid=tenant_id,
                scan_run_id=scan_run_id,
                timeout=30.0
            )
            return [RawPath(**dict(record)) for record in result]
```

**Dependency note**: The engine scaffold (AP-P2-02) must exist before this file can be added to the engine directory. This story adds the graph/ sub-module to the existing engine directory.

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/graph/neo4j_client.py` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/models/attack_path.py` (create/extend)

## Definition of Done
- [ ] `neo4j_client.py` committed with full Cypher query and `reverse_bfs()` method
- [ ] `RawPath` Pydantic model defined in `models/attack_path.py`
- [ ] Manual validation: `reverse_bfs("my-tenant", "<scan_run_id>")` returns at least 1 path against live Neo4j Aura
- [ ] Timeout handling verified: no exception raised on 30s timeout, WARNING logged
- [ ] LIMIT 500 verified: query returns at most 500 raw paths
- [ ] All Cypher MATCH clauses reviewed for tenant_id filter — confirmed by dev + bmad-security-reviewer
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-security-architect: Cypher injection risk sign-off recorded