---
story_id: AZ-16
title: Seed Azure Toxic Combination Patterns into Neo4j Hunt Queries
status: done
sprint: azure-track-wave-8
depends_on: [AZ-15, AZ-13]
blocks: [AZ-18]
sme: Threat analyst + Backend
estimate: 1 day
---

# Story: Seed Azure Toxic Combination Patterns

## Context
Toxic combinations detect multi-condition security failures that together create high attack risk (e.g., public storage + no encryption + sensitive data). Currently 11 AWS patterns exist in `threat_hunt_queries`. Need 5 Azure-specific + 2 cross-CSP patterns.

**CRITICAL:** Filter query must use `tags @> to_jsonb(ARRAY['azure']::text[])` — NOT `metadata->>'provider'` (that column does not exist).

## Files to Create

- `engines/threat/scripts/seed_azure_hunt_queries.py`

## Implementation Notes

**Seed script pattern:**
```python
"""Seed Azure toxic combination patterns into threat_hunt_queries."""
import psycopg2
import json

AZURE_PATTERNS = [
    {
        "query_name": "azure_public_storage_no_encryption_sensitive",
        "description": "Public StorageAccount + no CMK + sensitive data classification. Maps: T1530",
        "hunt_type": "toxic_combination",
        "query_language": "cypher",
        "severity": "critical",
        "mitre_tactics": ["Collection"],
        "mitre_techniques": ["T1530"],
        "tags": ["azure", "storage", "encryption", "public_access"],
        "query_text": """...""",  # full Cypher from 22_NEO4J_GRAPH_MULTICSP.md Pattern 1
    },
    # ... 4 more Azure patterns
    # ... 2 cross-CSP patterns
]

def seed():
    conn = psycopg2.connect(...)
    cur = conn.cursor()
    for p in AZURE_PATTERNS:
        cur.execute("""
            INSERT INTO threat_hunt_queries
              (query_name, description, hunt_type, query_language, severity,
               mitre_tactics, mitre_techniques, tags, query_text)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (query_name) DO UPDATE SET
              query_text       = EXCLUDED.query_text,
              severity         = EXCLUDED.severity,
              mitre_techniques = EXCLUDED.mitre_techniques,
              tags             = EXCLUDED.tags,
              updated_at       = NOW()
        """, (
            p["query_name"], p["description"], p["hunt_type"],
            p["query_language"], p["severity"],
            json.dumps(p["mitre_tactics"]), json.dumps(p["mitre_techniques"]),
            json.dumps(p["tags"]), p["query_text"]
        ))
    conn.commit()
```

**The 7 patterns to seed** (full Cypher in `.claude/planning/multi-csp/22_NEO4J_GRAPH_MULTICSP.md`):
1. Azure: Public Storage + No Encryption + Sensitive Data (T1530)
2. Azure: Overprivileged SP + Admin Role (T1098.001)
3. Azure: VM + Public IP + Admin ManagedIdentity + No Disk Encryption (T1078.004)
4. Azure: SQL Server + Public Firewall + No Auditing + No TDE (T1190, T1530)
5. Azure: AKS Public API + No AAD + Privileged Pods (T1190, T1610, T1611)
6. Cross-CSP: AWS→Azure Lateral Movement (federated identity abuse)
7. Cross-CSP: K8s Pod → Cloud Metadata → Cloud Account Takeover (T1552)

**Provider filter fix in graph_queries.py:**
```python
# In _load_hunt_queries() — find this function and add provider filter
if provider:
    sql += " AND tags @> to_jsonb(ARRAY[%s]::text[])"
    params.append(provider)
```

## Reference Files
- Cypher patterns: `.claude/planning/multi-csp/22_NEO4J_GRAPH_MULTICSP.md`
- Existing hunt queries: `engines/threat/scripts/seed_hunt_queries.py`
- graph_queries.py: `engines/threat/threat_engine/graph/graph_queries.py` (find `_load_hunt_queries`)

## Acceptance Criteria
- [ ] `SELECT COUNT(*) FROM threat_hunt_queries WHERE hunt_type='toxic_combination' AND tags @> to_jsonb(ARRAY['azure']::text[])` = 7
- [ ] Seed script is idempotent (ON CONFLICT DO UPDATE)
- [ ] `_load_hunt_queries(tenant_id, provider='azure')` only returns azure-tagged queries (add unit test)
- [ ] `_load_hunt_queries(tenant_id, provider='aws')` still returns AWS queries (regression check)
- [ ] `metadata->>'provider'` does NOT appear in the codebase (grep check)

## Definition of Done
- [ ] Seed script created + run against staging DB
- [ ] graph_queries.py updated with provider filter using `tags @>`
- [ ] 7 patterns verified in DB
- [ ] Unit tests for provider filter