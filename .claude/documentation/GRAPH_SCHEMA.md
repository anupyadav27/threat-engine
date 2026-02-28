# Neo4j Security Graph Schema

> Node types, relationships, Cypher query examples, and visualization guide for the security graph.

---

## Overview

The security graph provides attack path analysis, blast radius computation, and threat hunting capabilities. It's built by `engine_threat` from PostgreSQL data and stored in Neo4j (Aura SaaS).

```
Connection: neo4j+s://17ec5cbb.databases.neo4j.io
Builder:    POST /api/v1/graph/build
Queries:    GET /api/v1/graph/attack-paths, /blast-radius, /toxic-combinations
Hunting:    POST /api/v1/hunt/execute
```

---

## Node Types

### Virtual Nodes (Infrastructure anchors)

| Label | Properties | Count (typical) | Description |
|-------|-----------|-----------------|-------------|
| `Internet` | name | 1 | Represents external internet access |
| `Account` | uid, name, tenant_id | 1 per account | AWS account |
| `Region` | uid, name, tenant_id | 1 per region | AWS region |

### Resource Nodes

| Label | Properties | AWS Service | Count |
|-------|-----------|-------------|-------|
| `Resource` | uid, name, resource_type, tenant_id, account_id, region, risk_score | All | 280 |
| `S3Bucket` | (inherits Resource) | s3.resource | 21 |
| `IAMRole` | (inherits Resource) | iam.role | 140 |
| `IAMPolicy` | (inherits Resource) | iam.policy | 54 |
| `SecurityGroup` | (inherits Resource) | ec2.security-group | 31 |
| `EC2Instance` | (inherits Resource) | ec2.instance | varies |
| `RDSInstance` | (inherits Resource) | rds.instance | varies |
| `LambdaFunction` | (inherits Resource) | lambda.function | varies |
| `KMSKey` | (inherits Resource) | kms.key | varies |
| `ELBLoadBalancer` | (inherits Resource) | elbv2.loadbalancer | varies |

Each resource node has dual labels: `Resource` + specific type (e.g., `Resource:S3Bucket`).

### Threat Nodes

| Label | Properties | Count |
|-------|-----------|-------|
| `ThreatDetection` | detection_id, severity, confidence, threat_category, mitre_techniques, mitre_tactics, resource_arn, tenant_id | 21 |

### Finding Nodes

| Label | Properties | Count |
|-------|-----------|-------|
| `Finding` | finding_id, rule_id, severity, status, resource_uid, tenant_id | 1,528 |

---

## Relationship Types

| Relationship | From | To | Description | Count |
|-------------|------|-----|-------------|-------|
| `CONTAINS` | Account | Resource | Account owns resource | 280 |
| `HOSTS` | Region | Resource | Resource is in region | 280 |
| `HAS_FINDING` | Resource | Finding | Resource has check finding | 1,528 |
| `HAS_THREAT` | Resource | ThreatDetection | Resource has threat | 21 |
| `EXPOSES` | Internet | Resource | Resource is internet-exposed | 21 |
| `RELATES_TO` | Resource | Resource | Inventory relationship | varies |
| `REFERENCES` | Resource | Resource | IAM/policy reference | varies |
| `ATTACK_PATH` | Resource | Resource | Inferred attack path | varies |

### Relationship Properties

| Relationship | Properties |
|-------------|-----------|
| `RELATES_TO` | relationship_type, source |
| `REFERENCES` | reference_type |
| `EXPOSES` | exposure_type (inferred from SG rules) |

---

## Graph Structure Diagram

```
                    ┌──────────┐
                    │ Internet │
                    └────┬─────┘
                         │ EXPOSES
                    ┌────▼─────┐
         ┌─────────┤ S3Bucket ├─────────┐
         │         └────┬─────┘         │
    HAS_THREAT     HAS_FINDING     RELATES_TO
         │              │              │
    ┌────▼──────┐  ┌────▼────┐   ┌────▼─────┐
    │  Threat   │  │ Finding │   │ IAMRole  │
    │ Detection │  │ (check) │   │          │
    └───────────┘  └─────────┘   └────┬─────┘
                                      │ REFERENCES
                                 ┌────▼─────┐
                                 │IAMPolicy │
                                 └──────────┘

         ┌──────────┐          ┌──────────┐
         │ Account  │──CONTAINS──►│ Resource │
         └──────────┘          └──────────┘
         ┌──────────┐          ┌──────────┐
         │  Region  │───HOSTS────►│ Resource │
         └──────────┘          └──────────┘
```

---

## Cypher Query Examples

### Basic Queries

**Count all nodes and relationships:**
```cypher
CALL db.labels() YIELD label
CALL apoc.cypher.run('MATCH (n:`' + label + '`) RETURN count(n) AS count', {}) YIELD value
RETURN label, value.count AS count
ORDER BY value.count DESC
```

**View all node types:**
```cypher
MATCH (n)
RETURN DISTINCT labels(n) AS labels, count(*) AS count
ORDER BY count DESC
```

**View all relationship types:**
```cypher
MATCH ()-[r]->()
RETURN DISTINCT type(r) AS type, count(*) AS count
ORDER BY count DESC
```

### Attack Path Queries

**Find all internet-exposed resources:**
```cypher
MATCH (i:Internet)-[e:EXPOSES]->(r:Resource)
RETURN r.uid AS resource, r.resource_type AS type, r.risk_score AS risk
ORDER BY r.risk_score DESC
```

**Find internet → resource → threat paths:**
```cypher
MATCH path = (i:Internet)-[:EXPOSES]->(r:Resource)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN r.uid AS resource,
       r.resource_type AS type,
       t.severity AS threat_severity,
       t.mitre_techniques AS techniques,
       length(path) AS hops
ORDER BY t.severity DESC
```

**Multi-hop attack paths (up to 5 hops):**
```cypher
MATCH path = (i:Internet)-[:EXPOSES|RELATES_TO|REFERENCES*1..5]->(target:Resource)-[:HAS_THREAT]->(t:ThreatDetection)
WHERE t.severity = 'high'
RETURN [n IN nodes(path) | n.uid] AS path_nodes,
       [r IN relationships(path) | type(r)] AS path_rels,
       length(path) AS hops,
       target.uid AS target_resource
ORDER BY hops ASC
LIMIT 50
```

### Blast Radius Queries

**Compute blast radius from a resource (3 hops):**
```cypher
MATCH (source:Resource {uid: $resource_uid})
CALL apoc.path.subgraphNodes(source, {
  maxLevel: 3,
  relationshipFilter: 'RELATES_TO|REFERENCES|CONTAINS'
}) YIELD node
WHERE node:Resource
RETURN node.uid AS reachable_resource,
       node.resource_type AS type,
       size([(node)-[:HAS_THREAT]->(t) | t]) AS threat_count
```

**Simple blast radius (no APOC):**
```cypher
MATCH (source:Resource {uid: $resource_uid})-[:RELATES_TO|REFERENCES*1..3]-(target:Resource)
WHERE target <> source
RETURN DISTINCT target.uid AS resource,
       target.resource_type AS type,
       min(length((source)-[*]-(target))) AS hops
ORDER BY hops ASC
```

### Toxic Combination Queries

**Resources with multiple threats:**
```cypher
MATCH (r:Resource)-[:HAS_THREAT]->(t:ThreatDetection)
WITH r, collect(t) AS threats, count(t) AS threat_count
WHERE threat_count >= 2
RETURN r.uid AS resource,
       r.resource_type AS type,
       threat_count,
       [t IN threats | t.severity] AS severities,
       [t IN threats | t.mitre_techniques] AS techniques
ORDER BY threat_count DESC
```

**Internet-exposed resources with high-severity threats:**
```cypher
MATCH (i:Internet)-[:EXPOSES]->(r:Resource)-[:HAS_THREAT]->(t:ThreatDetection)
WHERE t.severity = 'high'
RETURN r.uid AS resource,
       r.resource_type AS type,
       collect(DISTINCT t.detection_id) AS threat_ids,
       size(collect(DISTINCT t)) AS threat_count
ORDER BY threat_count DESC
```

### Threat Hunting Queries

**Find IAM lateral movement paths:**
```cypher
MATCH (role:IAMRole)-[:REFERENCES]->(policy:IAMPolicy)-[:REFERENCES]->(target:Resource)
WHERE target:S3Bucket OR target:RDSInstance
RETURN role.uid AS iam_role,
       policy.uid AS via_policy,
       target.uid AS target_resource,
       target.resource_type AS target_type
```

**Public S3 buckets with active threats:**
```cypher
MATCH (i:Internet)-[:EXPOSES]->(b:S3Bucket)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN b.uid AS bucket,
       b.name AS bucket_name,
       t.severity AS threat_severity,
       t.mitre_techniques AS techniques
ORDER BY t.severity DESC
```

**Resources with findings but no threats (potential gaps):**
```cypher
MATCH (r:Resource)-[:HAS_FINDING]->(f:Finding)
WHERE NOT (r)-[:HAS_THREAT]->()
  AND f.severity = 'high'
WITH r, count(f) AS finding_count
WHERE finding_count >= 5
RETURN r.uid AS resource,
       r.resource_type AS type,
       finding_count
ORDER BY finding_count DESC
```

**Critical resources without encryption:**
```cypher
MATCH (r:Resource)-[:HAS_FINDING]->(f:Finding)
WHERE f.rule_id CONTAINS 'encryption'
  AND f.status = 'FAIL'
RETURN r.uid AS resource,
       r.resource_type AS type,
       collect(f.rule_id) AS failed_encryption_rules
```

---

## Graph Build Process

The graph is built by `SecurityGraphBuilder.build_graph(tenant_id)`:

```
1. Clear existing graph (MATCH (n) DETACH DELETE n)
2. Create virtual nodes (Internet, Account, Region)
3. Load resources from inventory_findings → create Resource nodes
4. Load inventory_relationships → create RELATES_TO/REFERENCES edges
5. Create hierarchy edges (Account→CONTAINS→Resource, Region→HOSTS→Resource)
6. Load threat_detections → create ThreatDetection nodes + HAS_THREAT edges
7. Load check_findings → create Finding nodes + HAS_FINDING edges
8. Infer internet exposure from security groups (0.0.0.0/0) → create EXPOSES edges
```

**Trigger:** `POST /api/v1/graph/build` with `{"tenant_id": "..."}`

**Duration:** ~3-5 minutes for full rebuild

---

## Neo4j Console Access

**Aura Console:** https://console.neo4j.io

To visualize in Neo4j Browser:
1. Log into Neo4j Aura console
2. Open the Query tab
3. Run: `MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100`
4. Switch to graph view

**Resource type colors (recommended):**
- S3Bucket: Green
- IAMRole: Blue
- IAMPolicy: Light Blue
- SecurityGroup: Orange
- ThreatDetection: Red
- Finding: Yellow
- Internet: Purple
- Account/Region: Gray
