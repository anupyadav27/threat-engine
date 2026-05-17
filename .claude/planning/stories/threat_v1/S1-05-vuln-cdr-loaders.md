# Story S1-05: VulnLoader + CDRLoader (Reads Vuln DB + CDR DB)

## Status: ready

## Metadata
- **Sprint**: 1 — Foundation: Schema + GraphBuilder
- **Points**: 5
- **Priority**: P0
- **Depends on**: S1-04 (ResourceResolver pattern established), CP-1 gate
- **Blocks**: S1-06, S1-08
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: SR consulted — actor_principal is PII (CDR). CP1-02 enforced in CDRLoader.

## Context

`VulnLoader` reads `scan_vulnerabilities` joined with `cve_attack_mappings` to get MITRE techniques per CVE, then creates `(:Resource)-[:HAS_CVE]->(:VulnFinding)` in Neo4j.

`CDRLoader` reads `cdr_findings` for the tenant and creates `(:Resource)-[:TRIGGERED]->(:CDREvent)-[:PERFORMED_BY]->(:CDRActor)`. The critical security requirement: `actor_principal` is PII and must NEVER be stored in Neo4j or logged. Only `actor_hash = sha256(actor_principal)` and `actor_principal_type` are written to graph nodes.

Note: CDR is tenant-wide, not per-account (no account_id filter on cdr_findings — documented as intentional per W-04 in the architecture doc).

## Security Framework Tags

**CP1-02**: actor_principal PII — hash before writing to Neo4j, never log raw value
**STRIDE**: Info Disclosure (actor_principal exposure in logs or graph)
**PASTA**: Threat actor re-identification via actor_hash correlation (acceptable — hash is one-way)

## Technical Notes

### Module locations
- `engines/threat_v1/threat_v1/graph/vuln_loader.py`
- `engines/threat_v1/threat_v1/graph/cdr_loader.py`

### VulnLoader join
```sql
SELECT sv.resource_uid, sv.cve_id, sv.package_name, sv.severity, sv.score,
       cam.technique_id, mt.tactic
FROM scan_vulnerabilities sv
LEFT JOIN cve_attack_mappings cam ON sv.cve_id = cam.cve_id
LEFT JOIN mitre_techniques mt ON cam.technique_id = mt.technique_id
WHERE sv.tenant_id = %s AND sv.scan_run_id = %s
```
Groups technique_ids into a list per cve_id for the VulnFinding node.

Note: `scan_vulnerabilities` will gain tenant_id + scan_run_id after the S0-04b migration. Until then, VulnLoader may return no data — handle gracefully (log INFO, return empty list, don't crash).

### CDRLoader PII rule (CP1-02 — non-negotiable)
```python
import hashlib

# CORRECT — hash before use
actor_hash = hashlib.sha256(actor_principal.encode()).hexdigest()

# FORBIDDEN — never log or write raw value
logger.info(f"actor: {actor_principal}")  # FORBIDDEN
neo4j_session.run("... SET a.actor = $ap", {"ap": actor_principal})  # FORBIDDEN
```

CDRActor dedup: MERGE on `(actor_hash, tenant_id)` — same actor across multiple events maps to one CDRActor node.

CDR query:
```sql
SELECT finding_id, resource_uid, rule_id, severity, actor_principal,
       actor_principal_type, mitre_techniques, event_time, tenant_id
FROM cdr_findings
WHERE tenant_id = %s
  AND event_time >= NOW() - INTERVAL '90 days'
```
No account_id filter — CDR is tenant-wide (W-04). Document this as intentional in code comment.

### Cypher writes (CP1-01)
All MERGE/SET must use parameter dict. No f-string Cypher.

```cypher
MERGE (a:CDRActor {actor_hash: $ahash, tenant_id: $tid})
SET a += {actor_principal_type: $atype, last_seen: $last_seen}
```

## Acceptance Criteria

- [ ] AC-1: VulnLoader creates `(:VulnFinding)` nodes with `mitre_techniques` list from cve_attack_mappings
- [ ] AC-2: `HAS_CVE` edges created between Resource and VulnFinding
- [ ] AC-3: CDRLoader creates `(:CDREvent)` nodes with `actor_principal_type` (NOT `actor_principal`)
- [ ] AC-4: `(:CDRActor)` nodes created with `actor_hash` (sha256) — raw `actor_principal` never stored
- [ ] AC-5: `PERFORMED_BY` edges between CDREvent and CDRActor
- [ ] AC-6: VulnLoader handles missing `tenant_id`/`scan_run_id` on scan_vulnerabilities gracefully (logs INFO, continues)
- [ ] AC-7: CDR query has no account_id filter — code comment explains W-04 intentional design
- [ ] AC-8: No `actor_principal` in any log statement at any level in cdr_loader.py

## Security Acceptance Criteria

- [ ] Grep `actor_principal` in cdr_loader.py — only appears in the sha256 call, nowhere else
- [ ] `actor_principal` not present as a property on any CDREvent or CDRActor node in Neo4j
- [ ] SR sign-off that PII handling is correct
- [ ] All Neo4j writes parameterized (no f-string Cypher)
- [ ] VulnLoader DB connection uses read-only credentials on vuln DB

## Definition of Done

- [ ] `vuln_loader.py` committed
- [ ] `cdr_loader.py` committed
- [ ] Unit test: mock cdr_findings row, assert actor_hash written, assert actor_principal NOT written
- [ ] SR sign-off on PII handling documented
- [ ] Integration test: run against real CDR DB, assert CDRActor nodes have actor_hash not actor_principal
- [ ] grep check: `grep -r "actor_principal" engines/threat_v1/` shows only sha256 call

## Verification

```bash
# In Neo4j Browser (USE threat_v1):
# Verify no PII stored on CDRActor:
MATCH (a:CDRActor) RETURN keys(a) LIMIT 1
# Expected keys: [actor_hash, tenant_id, actor_principal_type, first_seen, last_seen, event_count]
# actor_principal must NOT appear

# Verify VulnFinding has technique IDs:
MATCH (f:VulnFinding) RETURN f.cve_id, f.mitre_techniques LIMIT 5
```
