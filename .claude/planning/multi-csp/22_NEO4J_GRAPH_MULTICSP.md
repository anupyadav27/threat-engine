# Neo4j Graph — Blast Radius, Attack Paths, Toxic Combinations (Multi-CSP)

## Two Separate Implementations — Clear Split

There are TWO implementations of blast radius and attack paths. They serve different purposes.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  INVENTORY ENGINE (PostgreSQL recursive CTE)                                │
│  engines/inventory/inventory_engine/api/                                    │
│                                                                             │
│  Purpose: Asset-level graph for the UI "Assets" tab                        │
│  Data:    inventory_relationships table (from_uid → to_uid)                 │
│  Input:   resource_uid from user clicking an asset in the UI                │
│  Output:  "if THIS asset is compromised, these N assets are affected"       │
│                                                                             │
│  API:  GET /api/v1/inventory/assets/{uid}/blast-radius                      │
│        GET /api/v1/inventory/attack-paths                                   │
│                                                                             │
│  How:  WITH RECURSIVE reachable AS (...)                                    │
│        walks inventory_relationships JOIN resource_security_relationship_   │
│        rules WHERE attack_path_category IS NOT NULL                         │
│        max_depth=3 (UI-facing, fast)                                        │
│                                                                             │
│  Multi-CSP: ALREADY WORKS — inventory_relationships has provider column,   │
│  resource_security_relationship_rules has provider column.                  │
│  Only missing: seed data for Azure/GCP/K8s relationships (07_INVENTORY.md) │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  THREAT ENGINE (Neo4j Cypher)                                               │
│  engines/threat/threat_engine/graph/                                        │
│                                                                             │
│  Purpose: Deep security graph for threat detection and hunting              │
│  Data:    Neo4j nodes (Resource, Finding, ThreatDetection, Internet)        │
│  Input:   Full scan — all resources + findings + threats loaded into graph  │
│  Output:  Attack chains, blast radius with risk scores, toxic combinations  │
│                                                                             │
│  Files:   graph_builder.py   ← WRITES: resources+findings → Neo4j          │
│           graph_queries.py   ← READS: Cypher queries → results             │
│                                                                             │
│  Three query types:                                                         │
│    1. blast_radius(resource_uid)  → graph traversal, attack edges only     │
│    2. attack_paths(tenant_id)     → Internet → threatened resources chains  │
│    3. toxic_combinations()        → runs Cypher from threat_hunt_queries DB │
│                                                                             │
│  Multi-CSP: PARTIAL — graph_builder already uses resource_type as label,   │
│  so Azure/GCP/K8s nodes will have correct labels. BUT toxic combination     │
│  Cypher patterns are ALL AWS-specific node types.                           │
│  Fix: Add CSP-tagged patterns to threat_hunt_queries per CSP.               │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Neo4j Graph Schema (Current — AWS)

```
Nodes:
  (:Internet)                          ← synthetic — represents public internet
  (:Resource {uid, name, resource_type, tenant_id, provider, region,
              account_id, risk_score, severity})
  (:Finding {rule_id, severity, status, resource_type})
  (:ThreatDetection {detection_id, severity, threat_category, risk_score,
                     mitre_tactics, mitre_techniques})

Relationships:
  (:Internet)-[:EXPOSES]→(:Resource)           ← public-facing resources
  (:Resource)-[:HAS_FINDING]→(:Finding)        ← check findings on resource
  (:Resource)-[:HAS_THREAT]→(:ThreatDetection) ← threat detections
  (:Resource)-[attack_edge {attack_path_category}]→(:Resource)
    ← CONTAINS, ROUTES_TO, ACCESSES, PROTECTED_BY, AUTHENTICATES_VIA, EXPOSES
    ← attack_path_category set from resource_security_relationship_rules
```

## Multi-CSP Node Labeling (graph_builder.py)

`graph_builder.py` calls `_neo4j_label(resource_type)` to convert resource_type → Neo4j label.

Current AWS examples:
- `ec2.instance` → `EC2Instance`
- `rds.db-instance` → `RDSInstance`
- `s3.bucket` → `S3Bucket`

For multi-CSP — `resource_type` from scanner determines label. No code change needed IF
scanner writes the correct normalized resource_type:
- Azure `VirtualMachine` → Neo4j label `:VirtualMachine`
- GCP `GCEInstance` → Neo4j label `:GCEInstance`
- K8s `Pod` → Neo4j label `:Pod`

**The `_neo4j_label()` function needs a small update** to handle Azure/GCP/K8s types
that don't follow the AWS `service.type` dot-notation pattern:

```python
def _neo4j_label(resource_type: str) -> str:
    if not resource_type:
        return "Resource"
    # AWS format: "ec2.instance" → "EC2Instance"
    if "." in resource_type:
        parts = resource_type.split(".")
        return "".join(p.title() for p in parts)
    # Azure/GCP/K8s: already normalized short names → use as-is
    # "VirtualMachine", "GCEInstance", "Pod" → unchanged
    return resource_type
```

---

## Toxic Combination Patterns — Multi-CSP

Toxic combinations live in `threat_hunt_queries` table (`query_language='cypher'`, `hunt_type='toxic_combination'`).
Currently 11+ AWS patterns. Need parallel patterns per CSP.

### How to add: `seed_hunt_queries.py` equivalent per CSP, or SQL INSERT.

---

### Azure Toxic Combination Patterns

```cypher
-- Pattern 1: Public Storage + No Encryption + Sensitive Data
-- StorageAccount with public access + no CMK + datasec finding
-- Maps: T1530 (Data from Cloud Storage Object)
MATCH (i:Internet)-[:EXPOSES]->(sa:StorageAccount {tenant_id: $tid})
MATCH (sa)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'public_access' OR f1.rule_id CONTAINS 'blob_public'
WITH sa, collect(f1.rule_id) AS access_rules
MATCH (sa)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'encrypt' OR f2.rule_id CONTAINS 'cmk'
OPTIONAL MATCH (sa)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN sa.uid AS resource_uid, sa.name AS resource_name,
       sa.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       access_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 2: Overprivileged Service Principal + Admin Role
-- SP with Owner/Contributor role at subscription scope — lateral movement
-- Maps: T1098.001 (Account Manipulation)
MATCH (sp:ServicePrincipal {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
WHERE f.rule_id CONTAINS 'owner_role' OR f.rule_id CONTAINS 'contributor'
     OR f.rule_id CONTAINS 'subscription_scope'
WITH sp, collect(f.rule_id) AS iam_rules
MATCH (sp)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'credential_expiry' OR f2.rule_id CONTAINS 'no_mfa'
OPTIONAL MATCH (sp)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN sp.uid AS resource_uid, sp.name AS resource_name,
       sp.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       iam_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 3: VM + Public IP + Admin ManagedIdentity + No Disk Encryption
-- Internet → VM → sensitive workload via identity chain
-- Maps: T1078.004 (Valid Accounts: Cloud Accounts)
MATCH (i:Internet)-[:EXPOSES]->(vm:VirtualMachine {tenant_id: $tid})
WITH DISTINCT vm
MATCH (vm)-[:AUTHENTICATES_VIA]->(mi:ManagedIdentity)
MATCH (mi)-[:HAS_FINDING]->(f_iam:Finding)
WHERE f_iam.rule_id CONTAINS 'admin' OR f_iam.rule_id CONTAINS 'owner'
WITH vm, mi, collect(f_iam.rule_id) AS iam_rules
MATCH (vm)-[:HAS_FINDING]->(f_disk:Finding)
WHERE f_disk.rule_id CONTAINS 'disk_encrypt' OR f_disk.rule_id CONTAINS 'cmk'
OPTIONAL MATCH (vm)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN vm.uid AS resource_uid, vm.name AS resource_name,
       vm.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       iam_rules + collect(f_disk.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 4: SQL Server + Public Firewall + No Auditing + No TDE
-- Database fully exposed and unmonitored
-- Maps: T1190 (Exploit Public-Facing Application), T1530
MATCH (i:Internet)-[:EXPOSES]->(sql:SQLServer {tenant_id: $tid})
WITH DISTINCT sql
MATCH (sql)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'firewall' OR f1.rule_id CONTAINS 'public_access'
WITH sql, collect(f1.rule_id) AS net_rules
MATCH (sql)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'audit' OR f2.rule_id CONTAINS 'tde'
    OR f2.rule_id CONTAINS 'encrypt'
OPTIONAL MATCH (sql)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN sql.uid AS resource_uid, sql.name AS resource_name,
       sql.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       net_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 5: AKS Cluster + Public API + No AAD + Privileged Pods
-- Maps: T1190, T1610, T1611
MATCH (i:Internet)-[:EXPOSES]->(aks:AKSCluster {tenant_id: $tid})
WITH DISTINCT aks
MATCH (aks)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'aad' OR f1.rule_id CONTAINS 'rbac'
WITH aks, collect(f1.rule_id) AS auth_rules
MATCH (aks)-[:CONTAINS]->(pod:Pod)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'privileged' OR f2.rule_id CONTAINS 'host_pid'
    OR f2.rule_id CONTAINS 'host_network'
OPTIONAL MATCH (aks)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN aks.uid AS resource_uid, aks.name AS resource_name,
       aks.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       auth_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
```

---

### GCP Toxic Combination Patterns

```cypher
-- Pattern 1: GCE + Default SA + Full API Scope + Public IP
-- Metadata API → SA token → project-wide access
-- Maps: T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)
MATCH (i:Internet)-[:EXPOSES]->(vm:GCEInstance {tenant_id: $tid})
WITH DISTINCT vm
MATCH (vm)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'default_service_account'
    OR f1.rule_id CONTAINS 'full_api_access'
    OR f1.rule_id CONTAINS 'api_scope'
WITH vm, collect(f1.rule_id) AS sa_rules
OPTIONAL MATCH (vm)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'imds' OR f2.rule_id CONTAINS 'metadata'
OPTIONAL MATCH (vm)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN vm.uid AS resource_uid, vm.name AS resource_name,
       vm.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       sa_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 2: Public GCS Bucket + No Versioning + Sensitive Data Classification
-- Maps: T1530 (Data from Cloud Storage Object)
MATCH (i:Internet)-[:EXPOSES]->(bucket:GCSBucket {tenant_id: $tid})
WITH DISTINCT bucket
MATCH (bucket)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'public_access' OR f1.rule_id CONTAINS 'allUsers'
WITH bucket, collect(f1.rule_id) AS access_rules
MATCH (bucket)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'versioning' OR f2.rule_id CONTAINS 'encrypt'
    OR f2.rule_id CONTAINS 'logging'
OPTIONAL MATCH (bucket)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN bucket.uid AS resource_uid, bucket.name AS resource_name,
       bucket.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       access_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 3: ServiceAccount with Owner Role + Long-lived Key + Key Age > 90d
-- Maps: T1078.004 (Valid Accounts: Cloud Accounts)
MATCH (sa:ServiceAccount {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'owner' OR f1.rule_id CONTAINS 'primitive_role'
    OR f1.rule_id CONTAINS 'editor'
WITH sa, collect(f1.rule_id) AS role_rules
MATCH (sa)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'key_age' OR f2.rule_id CONTAINS 'key_rotation'
    OR f2.rule_id CONTAINS '90_days'
OPTIONAL MATCH (sa)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN sa.uid AS resource_uid, sa.name AS resource_name,
       sa.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       role_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 4: Public Cloud SQL + No SSL + No Private IP + Weak Auth
-- Maps: T1190 (Exploit Public-Facing Application)
MATCH (i:Internet)-[:EXPOSES]->(db:CloudSQLInstance {tenant_id: $tid})
WITH DISTINCT db
MATCH (db)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'ssl' OR f1.rule_id CONTAINS 'public_ip'
    OR f1.rule_id CONTAINS 'authorized_networks'
WITH db, collect(f1.rule_id) AS net_rules
MATCH (db)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'backup' OR f2.rule_id CONTAINS 'encrypt'
OPTIONAL MATCH (db)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN db.uid AS resource_uid, db.name AS resource_name,
       db.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       net_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 5: GKE Public API + No Workload Identity + Privileged Pods
-- Maps: T1190, T1610 (Deploy Container), T1613 (Container and Resource Discovery)
MATCH (i:Internet)-[:EXPOSES]->(gke:GKECluster {tenant_id: $tid})
WITH DISTINCT gke
MATCH (gke)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'workload_identity' OR f1.rule_id CONTAINS 'master_auth'
    OR f1.rule_id CONTAINS 'private_cluster'
WITH gke, collect(f1.rule_id) AS auth_rules
MATCH (gke)-[:CONTAINS]->(np:NodePool)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'service_account' OR f2.rule_id CONTAINS 'oauth_scope'
OPTIONAL MATCH (gke)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN gke.uid AS resource_uid, gke.name AS resource_name,
       gke.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       auth_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
```

---

### Kubernetes Toxic Combination Patterns

```cypher
-- Pattern 1: Privileged Pod + hostPID + hostNetwork + Default ServiceAccount
-- Complete host escape + cluster visibility
-- Maps: T1611 (Escape to Host), T1046 (Network Service Discovery)
MATCH (pod:Pod {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'privileged'
WITH pod, collect(f1.rule_id) AS priv_rules
MATCH (pod)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'host_pid' OR f2.rule_id CONTAINS 'host_network'
    OR f2.rule_id CONTAINS 'host_ipc'
WITH pod, priv_rules, collect(f2.rule_id) AS host_rules
MATCH (pod)-[:AUTHENTICATES_VIA]->(sa:ServiceAccount)-[:HAS_FINDING]->(f3:Finding)
WHERE f3.rule_id CONTAINS 'default_sa' OR f3.rule_id CONTAINS 'automount'
OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN pod.uid AS resource_uid, pod.name AS resource_name,
       pod.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       priv_rules + host_rules + collect(f3.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 2: Wildcard ClusterRole + Bound to Default SA + Across All Namespaces
-- Full cluster compromise via RBAC misconfig
-- Maps: T1098 (Account Manipulation), T1613 (Container and Resource Discovery)
MATCH (crb:ClusterRoleBinding {tenant_id: $tid})-[:ACCESSES]->(cr:ClusterRole)
MATCH (cr)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'wildcard' OR f1.rule_id CONTAINS 'cluster_admin'
    OR f1.rule_id CONTAINS 'all_verbs'
WITH crb, cr, collect(f1.rule_id) AS rbac_rules
MATCH (crb)-[:GRANTS]->(sa:ServiceAccount)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'default_sa' OR f2.rule_id CONTAINS 'automount'
OPTIONAL MATCH (crb)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN crb.uid AS resource_uid, crb.name AS resource_name,
       crb.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       rbac_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 3: Internet-Exposed Service + No NetworkPolicy + Privileged Pod Behind It
-- Exposed workload with no network segmentation
-- Maps: T1190 (Exploit Public-Facing Application), T1610 (Deploy Container)
MATCH (i:Internet)-[:EXPOSES]->(svc:Service {tenant_id: $tid})
WITH DISTINCT svc
MATCH (svc)-[:ROUTES_TO]->(pod:Pod)-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'privileged' OR f1.rule_id CONTAINS 'capabilities'
    OR f1.rule_id CONTAINS 'root'
WITH svc, pod, collect(f1.rule_id) AS pod_rules
MATCH (ns:Namespace {tenant_id: $tid, name: pod.namespace})-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'no_network_policy' OR f2.rule_id CONTAINS 'default_deny'
OPTIONAL MATCH (svc)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN svc.uid AS resource_uid, svc.name AS resource_name,
       svc.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       pod_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details

-- Pattern 4: Secret Mounted as Env Var + Pod with hostPath + No Resource Limits
-- Credential exposure + host access + resource exhaustion
-- Maps: T1552.007 (Container API), T1611 (Escape to Host)
MATCH (pod:Pod {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'secret_env' OR f1.rule_id CONTAINS 'env_secret'
WITH pod, collect(f1.rule_id) AS secret_rules
MATCH (pod)-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'host_path' OR f2.rule_id CONTAINS 'hostpath'
WITH pod, secret_rules, collect(f2.rule_id) AS path_rules
MATCH (pod)-[:HAS_FINDING]->(f3:Finding)
WHERE f3.rule_id CONTAINS 'no_limit' OR f3.rule_id CONTAINS 'resource_limit'
OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN pod.uid AS resource_uid, pod.name AS resource_name,
       pod.resource_type AS resource_type,
       count(DISTINCT t) AS threat_count,
       secret_rules + path_rules + collect(f3.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
```

---

### Cross-CSP Toxic Patterns (Multi-Cloud Attack Chains)

These detect attack chains that cross CSP boundaries — high value for multi-cloud tenants.

```cypher
-- Pattern: AWS→Azure Lateral Movement (federated identity abuse)
-- AWS resource with cross-cloud trust → Azure SP → Azure resources
MATCH (r:Resource {tenant_id: $tid, provider: 'aws'})-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'cross_account' OR f1.rule_id CONTAINS 'federation'
WITH r, collect(f1.rule_id) AS aws_rules
MATCH (sp:ServicePrincipal {tenant_id: $tid, provider: 'azure'})-[:HAS_FINDING]->(f2:Finding)
WHERE f2.rule_id CONTAINS 'owner' OR f2.rule_id CONTAINS 'privileged'
OPTIONAL MATCH (r)-[:HAS_THREAT]->(t:ThreatDetection)
RETURN r.uid AS resource_uid, r.name AS resource_name,
       r.resource_type AS resource_type,
       'cross_csp_lateral_movement' AS combo_type,
       count(DISTINCT t) AS threat_count,
       aws_rules + collect(f2.rule_id) AS matched_rules,
       collect(DISTINCT {severity: t.severity}) AS threat_details

-- Pattern: K8s Pod → Cloud Metadata → Cloud Account Takeover
-- K8s pod in cloud → metadata API → cloud SA/role → cloud resources
MATCH (pod:Pod {tenant_id: $tid})-[:HAS_FINDING]->(f1:Finding)
WHERE f1.rule_id CONTAINS 'metadata' OR f1.rule_id CONTAINS 'imds'
    OR f1.rule_id CONTAINS 'automount'
WITH pod, collect(f1.rule_id) AS pod_rules
OPTIONAL MATCH (pod)-[:HAS_THREAT]->(t:ThreatDetection)
WHERE t.mitre_techniques CONTAINS 'T1552'
RETURN pod.uid AS resource_uid, pod.name AS resource_name,
       pod.resource_type AS resource_type,
       'k8s_to_cloud_escalation' AS combo_type,
       count(DISTINCT t) AS threat_count,
       pod_rules AS matched_rules,
       collect(DISTINCT {severity: t.severity, threat_category: t.threat_category}) AS threat_details
```

---

## Blast Radius — Multi-CSP Cypher

The blast radius Cypher in `graph_queries.py:308` is already CSP-agnostic — it traverses
`attack_path_category`-tagged edges regardless of node label. No code change needed.

**Only prerequisite:** `resource_security_relationship_rules` must have rows for Azure/GCP/K8s
with `attack_path_category` set. Once `seed_attack_path_categories.py` runs against
the new rows, Neo4j edges will carry the `attack_path_category` property and blast radius
traversal works automatically for the new CSP.

Example Azure blast radius:
```cypher
-- Starting from a compromised KeyVault — what's reachable?
MATCH path = (start:KeyVault)-[rels*1..5]->(target:Resource)
WHERE start.uid STARTS WITH $uid AND target.tenant_id = $tid
  AND start <> target
  AND ALL(r IN rels WHERE r.attack_path_category IS NOT NULL AND r.attack_path_category <> '')
-- Returns: AppService (uses vault secrets), VirtualMachine (disk encrypted by vault key),
--          ManagedDisk (encrypted), SQLServer (TDE key in vault)
```

---

## Implementation Tasks

### 1. Fix `_neo4j_label()` for non-AWS resource types
File: `engines/threat/threat_engine/graph/graph_builder.py:241`
Change: handle already-normalized names (no dot → use as-is)

### 2. Add `provider` property to Neo4j nodes
File: `engines/threat/threat_engine/graph/graph_builder.py`
Add: `provider` field to MERGE/SET for each Resource node
Enables: filtering blast radius / attack paths by CSP in UI

### 3. Seed Azure/GCP/K8s toxic patterns into `threat_hunt_queries`
Script: extend `engines/threat/scripts/seed_hunt_queries.py`
Add: all patterns from this file with correct `provider` tag in metadata JSONB
Pattern rows need: `query_name`, `description`, `hunt_type='toxic_combination'`,
`query_language='cypher'`, `severity`, `mitre_techniques`, `tags` (include provider)

### 4. Run `seed_attack_path_categories.py` after seeding relationships
After inserting Azure/GCP/K8s rows into `resource_security_relationship_rules`,
run the seed script to stamp `attack_path_category` onto those rows.
The graph_builder will then carry the category to Neo4j edge properties.

### 5. `_load_hunt_queries` filter by provider (optional enhancement)
File: `engines/threat/threat_engine/graph/graph_queries.py:41`
Add: optional `provider` filter so GCP scan only runs GCP patterns (not AWS patterns)
Currently: loads all patterns for tenant — running AWS Cypher on GCP scan returns 0 results (harmless but wasteful)

```python
def _load_hunt_queries(tenant_id, hunt_type="toxic_combination", provider=None):
    sql = """
        SELECT hunt_id, query_name, description, hunt_type,
               query_text, tags, mitre_tactics, mitre_techniques
        FROM   threat_hunt_queries
        WHERE  hunt_type = %s
          AND  (tenant_id = %s OR tenant_id IS NULL)
    """
    params = [hunt_type, tenant_id]
    if provider:
        sql += " AND (metadata->>'provider' = %s OR metadata->>'provider' IS NULL)"
        params.append(provider)
    ...
```

---

## Summary: What's needed per CSP for full Neo4j coverage

| Task | AWS | Azure | GCP | K8s |
|------|-----|-------|-----|-----|
| Resource nodes in graph | ✓ | auto (scanner writes resource_type) | auto | auto |
| `_neo4j_label()` handles type | ✓ | needs fix | needs fix | needs fix |
| `provider` property on nodes | ✓ check | add | add | add |
| Relationship edges in graph | ✓ | needs seed (07_INVENTORY.md) | needs seed | needs seed |
| `attack_path_category` on edges | ✓ | run seed script after | run after | run after |
| Blast radius Cypher works | ✓ | auto after above | auto | auto |
| Attack paths Cypher works | ✓ | auto after above | auto | auto |
| Toxic combination patterns | ✓ (11 AWS) | 5 patterns (this file) | 5 patterns | 4 patterns |
| Cross-CSP patterns | — | 2 patterns (this file) | — | — |