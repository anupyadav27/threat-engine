# Story S1-01: Neo4j Graph Schema (Node Labels, Edge Types, Property Contracts, Indexes)

## Status: ready

## Metadata
- **Sprint**: 1 — Foundation: Schema + GraphBuilder
- **Points**: 3
- **Priority**: P0
- **Depends on**: S0-05 (coverage gate passed)
- **Blocks**: S1-04 (CP-1 gate: SA reviews this schema before S1-04 starts), S1-06, S1-07, S1-08
- **RACI**: R=DEV,ARCH A=ARCH C=SA I=DL,PO
- **Security Gate**: CP-1 — SA must review and sign off on this schema before S1-04 begins

## Context

The threat_v1 GraphBuilder reads from 6 engine databases and materializes a security graph in Neo4j Aura. This story defines the complete schema contract: node labels, relationship types, property names and types, uniqueness constraints, and indexes. Everything downstream (GraphBuilder loaders, PatternExecutor Cypher queries, BFF views) depends on this schema being correct and stable.

The schema runs against the `threat_v1` named database on the existing Neo4j Aura instance (`neo4j+s://17ec5cbb.databases.neo4j.io`). It must NOT be applied to the default database (used by the existing threat engine).

## Security Framework Tags

**OWASP SAMM**: Design — Data classification (PII masking), security architecture
**NIST CSF 2.0**: ID.AM (asset management), PR.DS (data security — PII in CDRActor)
**STRIDE**: Tampering (cross-tenant node creation), Info Disclosure (actor_principal exposure)
**CP-1 gates**: CP1-02 (actor PII), tenant_id on every node label

## MITRE ATT&CK Techniques This Schema Enables Detection Of

- T1190 (Initial Access — internet-exposed resource nodes)
- T1548.005 (Privilege Escalation — IAM role assumption edges)
- T1552.005 (Credential Access — IMDSv1 via FAILED_CHECK edges)
- T1530 (Collection — S3 data access via HAS_CVE + crown jewel edges)
- T1486 (Impact — ransomware pattern via crown jewel targeting)

## Technical Notes

### Output file
`engines/threat_v1/scripts/neo4j_schema.cypher`

### Named database
```cypher
// USE threat_v1
// Apply with: neo4j-admin or via driver session("threat_v1")
// NEVER apply to default database — production graph lives there
```

### Node labels and required properties

| Label | Primary key | tenant_id? | PII risk |
|-------|-------------|------------|----------|
| Resource | resource_uid + tenant_id | YES | None |
| MisconfigFinding | finding_id + tenant_id | YES | None |
| VulnFinding | finding_id + tenant_id | YES | None |
| CDREvent | finding_id + tenant_id | YES | None (actor_principal NOT stored) |
| CDRActor | actor_hash + tenant_id | YES | actor_hash = sha256(actor_principal) — raw PII never stored |
| ThreatIncident | incident_id | YES | None |

### PII rule (CP1-02 — mandatory)
`actor_principal` from `cdr_findings` is PII. It must NEVER appear as a Neo4j node property.
- CDRActor stores only `actor_hash = sha256(actor_principal)` and `actor_principal_type`
- CDREvent stores only `actor_principal_type`, not the raw value
- The raw `actor_principal` stays in PostgreSQL `cdr_findings` only — accessible via `cdr:sensitive` permission

### Relationship types

| Relationship | From | To | Source |
|---|---|---|---|
| FAILED_CHECK | Resource | MisconfigFinding | check_findings |
| HAS_CVE | Resource | VulnFinding | scan_vulnerabilities |
| TRIGGERED | Resource | CDREvent | cdr_findings |
| PERFORMED_BY | CDREvent | CDRActor | cdr_findings.actor_principal (hashed) |
| CONNECTED_TO | Resource | Resource | inventory_relationships (network) |
| CONTAINS | Resource | Resource | inventory_relationships (parent/child) |
| INVOLVES | ThreatIncident | Resource | threat_incidents.entry_resource_uid |
| MATCHED | ThreatIncident | MisconfigFinding | threat_incidents.misconfig_finding_ids |

### Index strategy
- Every node label must have a `tenant_id` index (tenant isolation)
- `resource_uid` on Resource: primary lookup for graph traversal
- `is_crown_jewel` on Resource: Tier 1 pattern flag check
- `on_attack_path` on Resource: attack path visualization
- `dedup_key` on ThreatIncident: incident deduplication

## Acceptance Criteria

- [ ] AC-1: File `engines/threat_v1/scripts/neo4j_schema.cypher` exists and is valid Cypher
- [ ] AC-2: All 6 node labels defined with CREATE CONSTRAINT (uniqueness) and CREATE INDEX
- [ ] AC-3: All 8 relationship types defined with comments explaining source table
- [ ] AC-4: `actor_principal` does NOT appear anywhere in the schema file — only `actor_hash` and `actor_principal_type`
- [ ] AC-5: Every node label has a `tenant_id` index
- [ ] AC-6: `// USE threat_v1` comment at top of file with warning not to apply to default DB
- [ ] AC-7: Schema can be applied to a fresh `threat_v1` named database without errors
- [ ] AC-8: SA reviews and signs off on this schema (CP-1 gate)

## Security Acceptance Criteria

- [ ] `actor_principal` (raw PII) not present in any node property definition or comment example
- [ ] `actor_hash` comment explicitly states: sha256(actor_principal) — not reversible
- [ ] Every CREATE CONSTRAINT includes `tenant_id` in the uniqueness tuple (not just entity ID alone)
- [ ] File includes a comment block explaining the named database isolation requirement
- [ ] No `CALL apoc.*` or `CALL db.index.*` with dynamic string parameters — static schema only

## Definition of Done

- [ ] Cypher file committed to `engines/threat_v1/scripts/neo4j_schema.cypher`
- [ ] Applied to `threat_v1` named database on Aura (verified with `SHOW INDEXES` and `SHOW CONSTRAINTS`)
- [ ] SA CP-1 sign-off documented before S1-04 is started
- [ ] Peer reviewed by ARCH
- [ ] No APOC or dynamic Cypher in schema file
