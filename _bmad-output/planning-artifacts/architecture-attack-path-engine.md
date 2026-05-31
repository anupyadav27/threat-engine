---
title: "Architecture — Attack Path Engine"
type: architecture
status: approved
version: "1.0"
date: "2026-05-15"
author: "Anup Yadave"
stepsCompleted:
  - step-01-init
  - step-02-project-analysis
  - step-03-system-design
  - step-04-core-decisions
  - step-05-data-model
  - step-06-api-design
  - step-07-security
  - step-08-deployment
  - step-09-adrs
inputDocuments:
  - "Design sessions: attack path architecture discussions (2026-05-15)"
  - ".claude/documentation/CSPM_CONSTITUTION.md"
  - ".claude/documentation/RBAC.md"
  - "Competitor research: Wiz, Orca, Prisma Cloud, CrowdStrike attack path approaches"
---

# Architecture: Attack Path Engine (`engine-attack-path`)

## 1. Purpose & Scope

The Attack Path Engine is a new standalone microservice that discovers, scores, deduplicates, and persists attack paths from external entry points to crown jewel assets in the CSPM platform's multi-cloud graph.

**What it replaces:** Attack path logic currently scattered across `engine-threat` (graph queries) and the threat BFF is extracted into a dedicated engine with its own DB, API, Argo pipeline step, and lifecycle.

**What it is NOT:**
- Not a threat detection engine (that stays in `engine-threat`)
- Not a risk scoring engine (that stays in `engine-risk`)
- Not a BFF or UI layer

**Competitive parity targets:** Orca's reverse graph algorithm + choke point detection; Wiz's Security Graph toxic combinations; CrowdStrike's ExPRT.AI path prioritization.

---

## 2. System Context

```
┌──────────────────────────────────────────────────────────────────────┐
│                    ARGO PIPELINE (scan_run_id)                        │
│                                                                        │
│  Discovery(1) → Inventory(2) → Check(3) → Threat(4)                  │
│      → [IAM / Network / DataSec / CDR / Vuln](5, parallel)           │
│      → Graph-Build(6)                                                 │
│      → Attack-Path(6.5)   ← NEW ENGINE                               │
│      → Risk(7)                                                        │
│      → Narrative(8)                                                   │
└──────────────────────────────────────────────────────────────────────┘

External dependencies consumed by engine-attack-path:
  ┌─────────────────┐    ┌─────────────────────────────────────┐
  │   Neo4j Aura    │    │  PostgreSQL (RDS)                    │
  │                 │    │  ├── threat_engine_inventory DB       │
  │  Resource nodes │    │  │    └── resource_security_posture  │
  │  PATH edges     │    │  └── threat_engine_attack_path DB    │
  │  VirtualNodes   │    │       ├── attack_paths               │
  │  Crown jewels   │    │       ├── attack_path_nodes          │
  └─────────────────┘    │       ├── attack_path_history        │
                         │       └── crown_jewel_overrides      │
                         └─────────────────────────────────────┘
```

**Upstream producers** (write to `resource_security_posture` before this engine runs):
- `engine-iam` → IAM dimension columns
- `engine-network-security` → network dimension columns
- `engine-datasec` → data classification columns
- `engine-cdr` → CDR actor columns
- `graph-build` (threat engine) → encryption/cert columns from Neo4j

**Downstream consumers** (read from this engine's output):
- `engine-risk` → reads `resource_security_posture` (is_on_attack_path, blast_radius_count, is_choke_point)
- `shared/api_gateway/bff/attack_paths.py` → BFF view handler
- `frontend/src/app/threats/attack-paths/` → UI page

---

## 3. Component Design

```
engines/attack-path/
├── Dockerfile
├── requirements.txt
├── attack_path_engine/
│   ├── main.py                    # FastAPI app factory
│   ├── api/
│   │   └── routes.py              # All endpoints
│   ├── core/
│   │   ├── crown_jewel_classifier.py   # Auto-classify + manual override
│   │   ├── reverse_bfs.py              # Neo4j reverse traversal
│   │   ├── scorer.py                   # P×I scoring formula
│   │   ├── deduplicator.py             # Hash + subpath + grouping
│   │   └── choke_point_detector.py     # Nodes in most paths
│   ├── db/
│   │   ├── connection.py          # psycopg2 pool
│   │   ├── writer.py              # INSERT attack_paths, attack_path_nodes
│   │   └── posture_updater.py     # UPDATE resource_security_posture
│   ├── graph/
│   │   └── neo4j_client.py        # Neo4j driver wrapper + queries
│   ├── models/
│   │   ├── attack_path.py         # Pydantic models
│   │   └── crown_jewel.py
│   └── run_scan.py                # Argo entry point (triggered by pipeline)
```

### 3.1 Data Flow Inside Engine

```
run_scan.py (Argo trigger)
    │
    ▼
crown_jewel_classifier.py
    Reads: resource_security_posture + crown_jewel_overrides + Neo4j node labels
    Writes: is_crown_jewel=true on matching nodes (Neo4j property + posture table)
    │
    ▼
reverse_bfs.py
    Reads: Neo4j — traverses PATH edges BACKWARD from each crown jewel
    Stops: when reaching Internet/OnPrem/VPN/PeerAccount VirtualNode
    Returns: raw path list [(node_uids[], edge_types[], hop_evidence[])]
    │
    ▼
scorer.py
    Reads: resource_security_posture per node (CVEs, misconfigs, CDR signals)
    Computes: probability_score × impact_score → path_score (0–100)
    Assigns: severity bucket (critical/high/medium/low)
    │
    ▼
deduplicator.py
    Phase 1: sha256 hash dedup (exact duplicates)
    Phase 2: subpath absorption (suffix match + independent exposure check)
    Phase 3: convergence grouping (shared tail → group_id + choke_node_uid)
    │
    ▼
choke_point_detector.py
    Counts: how many distinct groups each node appears in as choke_node
    Marks: top nodes as is_choke_point=true + choke_point_path_count
    │
    ▼
writer.py
    Writes: attack_paths, attack_path_nodes, attack_path_history tables
    │
    ▼
posture_updater.py
    Updates: resource_security_posture (is_on_attack_path, is_choke_point,
             attack_path_count, blast_radius_count, crown_jewel_count)
```

---

## 4. Core Algorithm: Reverse BFS

### 4.1 Why Reverse (Not Forward)

| Approach | Search Space | Completeness | Noise |
|---|---|---|---|
| Forward (Internet → any resource) | Exponential — explores entire reachable graph | Incomplete — misses paths >5 hops | High — returns paths to non-critical assets |
| **Reverse (Crown Jewel ← origin)** | **Bounded — starts from small crown jewel set** | **Complete — finds ALL paths to critical assets** | **Low — every path terminates at a crown jewel** |

### 4.2 The Cypher Query (Reverse Traversal)

```cypher
// Phase 1: Start from crown jewels, traverse PATH edges backward
MATCH (crown:Resource {tenant_id: $tid, is_crown_jewel: true})

MATCH path = (origin:Resource)-[rels*1..7]->(crown)
WHERE ALL(r IN rels WHERE r.edge_kind = 'path')
  AND NOT ALL(n IN nodes(path) WHERE n:IAMRole OR n:VirtualNode)

// Origin must be reachable from an external entry point
AND (
  origin.is_internet_exposed = true
  OR EXISTS { MATCH (i:Internet)-[:EXPOSES]->(origin) }
  OR EXISTS { MATCH (o:OnPrem)-[:CONNECTED_VIA]->(origin) }
  OR EXISTS { MATCH (v:VPN)-[:CONNECTED_VIA]->(origin) }
  OR EXISTS { MATCH (p:PeerAccount)-[:PEERED_WITH]->(origin) }
)

WITH crown, origin, path,
     [r IN relationships(path) | r.attack_path_category] AS hop_categories,
     [n IN nodes(path) | n.uid]                          AS node_uids,
     [n IN nodes(path) | n.resource_type]                AS node_types,
     [n IN nodes(path) | coalesce(n.risk_score, 0)]      AS node_risks,
     [r IN relationships(path) | type(r)]                AS edge_types,
     length(path)                                        AS depth

// Phase 2: Collect evidence per node (misconfigs, CVEs, CDR)
UNWIND nodes(path) AS hop_node
OPTIONAL MATCH (hop_node)-[:HAS_CVE]->(c:CVE)
OPTIONAL MATCH (hop_node)-[:HAS_FINDING]->(f:Finding) WHERE f.severity IN ['critical','high']
OPTIONAL MATCH (hop_node)-[:HAS_THREAT]->(t:ThreatDetection)

RETURN
  crown.uid              AS crown_jewel_uid,
  crown.crown_jewel_type AS crown_jewel_type,
  crown.data_classification AS data_classification,
  origin.uid             AS entry_point_uid,
  origin.resource_type   AS entry_point_type,
  node_uids, node_types, node_risks, edge_types, hop_categories, depth,
  max(c.epss_score)      AS max_epss,
  count(DISTINCT f)      AS misconfig_count,
  count(DISTINCT t)      AS threat_count,
  collect(DISTINCT c.cve_id)[..5] AS top_cves

ORDER BY max_epss DESC NULLS LAST, misconfig_count DESC
LIMIT 500
```

### 4.3 Crown Jewel Classification

Auto-classification criteria (any matching = is_crown_jewel: true):

| Resource Type | Auto-Classify Condition |
|---|---|
| s3.bucket, blob.container, gcs.bucket, oci.object_storage | data_classification IN (pii, financial, credentials) |
| rds.instance, aurora.cluster, cloud_sql.instance, oci.autonomous_db | always crown jewel |
| secretsmanager.secret, ssm.parameter (SecureString) | always crown jewel |
| iam.role, iam.user | is_admin_role=true OR has_wildcard_policy=true |
| eks.cluster, aks.cluster, gke.cluster | always crown jewel (infra control) |
| ecr.repository, acr.registry, gcr.repository | always crown jewel (code supply chain) |
| sagemaker.endpoint, bedrock.model | always crown jewel (AI/ML) |
| cloudformation.stack | has admin IAM role permissions |
| redshift.cluster, elasticsearch.domain | always crown jewel |
| kms.key, key_vault.key | always crown jewel (encryption control) |

Manual override: `PATCH /api/v1/crown-jewels/{uid}` stores in `crown_jewel_overrides` table. Overrides always win.

---

## 5. Scoring: Probability × Impact

### 5.1 Formula

```
path_score = round(min(100, P(path) × I(path) × 100))

Severity:
  Critical: score ≥ 80
  High:     60–79
  Medium:   40–59
  Low:      < 40
```

### 5.2 Probability Score P(path)

```python
def probability_score(path, posture_lookup) -> float:
    # Start with entry point base probability
    entry = posture_lookup[path.node_uids[0]]
    if entry.entry_point_type == "internet":
        p = 0.90
    elif entry.entry_point_type in ("vpn", "onprem"):
        p = 0.60
    elif entry.entry_point_type == "peer_account":
        p = 0.40
    else:
        p = 0.30

    # Multiply per-hop factors
    for node_uid in path.node_uids:
        posture = posture_lookup[node_uid]

        # Exploitability boosters
        if posture.max_epss and posture.max_epss > 0.7:
            p *= 0.95   # nearly certain if KEV + high EPSS
        elif posture.max_epss and posture.max_epss > 0.3:
            p *= 0.80

        if posture.critical_misconfig_count > 0:
            p *= 0.85
        elif posture.high_misconfig_count > 0:
            p *= 0.75

        # Mitigating control discounts
        if posture.waf_protected:
            p *= 0.80
        if posture.mfa_required:
            p *= 0.50
        if posture.has_permission_boundary:
            p *= 0.70

    # CDR elevation — active threat actor observed on path
    if any(posture_lookup[uid].has_active_cdr_actor for uid in path.node_uids):
        p = min(1.0, p * 1.40)

    return round(min(1.0, p), 4)
```

### 5.3 Impact Score I(path)

```python
def impact_score(path, posture_lookup) -> float:
    crown = posture_lookup[path.crown_jewel_uid]

    # Base from crown jewel type
    base = {
        "data":          1.00,
        "secrets":       0.95,
        "identity":      0.90,
        "infra_control": 0.85,
        "ai_model":      0.85,
        "code":          0.80,
    }.get(crown.crown_jewel_type, 0.60)

    # Data classification multiplier
    if crown.data_classification == "pii":
        base *= 1.20
    elif crown.data_classification in ("financial", "credentials"):
        base *= 1.15

    # Blast radius multiplier
    if crown.blast_radius_count > 50:
        base *= 1.30
    elif crown.blast_radius_count > 10:
        base *= 1.15

    # Encryption gap — data at rest not KMS-protected
    if crown.encryption_type in ("none", "sse"):
        base *= 1.10

    return round(min(1.0, base), 4)
```

---

## 6. Deduplication Algorithm

### 6.1 Three-Phase Dedup

```python
def deduplicate(raw_paths: list[RawPath], posture_lookup: dict) -> list[Path]:

    # Phase 1: Exact dedup by node_uid hash
    seen = {}
    for p in raw_paths:
        h = sha256("|".join(p.node_uids).encode()).hexdigest()
        if h not in seen or p.score > seen[h].score:
            seen[h] = p
    paths = list(seen.values())

    # Phase 2: Subpath absorption
    # Longer paths absorb shorter ones IF the shorter path's entry
    # node is NOT independently internet-exposed
    paths.sort(key=lambda p: len(p.node_uids), reverse=True)
    absorbed = set()
    for i, long_path in enumerate(paths):
        for j, short_path in enumerate(paths):
            if i == j or j in absorbed:
                continue
            if is_suffix(short_path.node_uids, long_path.node_uids):
                entry = posture_lookup[short_path.node_uids[0]]
                if not entry.is_internet_exposed:
                    absorbed.add(j)
    paths = [p for i, p in enumerate(paths) if i not in absorbed]

    # Phase 3: Convergence grouping
    # Paths sharing the same (crown_jewel, last-2-node-types) are grouped
    groups: dict[tuple, list] = {}
    for path in paths:
        tail = tuple(path.node_types[-2:])
        key = (path.crown_jewel_uid, tail)
        groups.setdefault(key, []).append(path)

    for group_key, group_paths in groups.items():
        gid = sha256(str(group_key).encode()).hexdigest()[:12]
        choke = group_paths[0].node_uids[-2] if len(group_paths) > 1 else None
        for p in group_paths:
            p.group_id    = gid
            p.group_size  = len(group_paths)
            p.choke_node_uid = choke
            p.is_representative = (p == max(group_paths, key=lambda x: x.score))

    return paths


def is_suffix(short: list, long: list) -> bool:
    if len(short) >= len(long):
        return False
    return long[-len(short):] == short
```

### 6.2 Absorbed Count

Each surviving path stores `absorbed_count` — how many subpaths were folded into it. This is shown in the UI: "This path absorbs 3 shorter routes."

---

## 7. Data Model

### 7.1 `resource_security_posture` (threat_engine_inventory DB)

The central merge table. Every engine writes its columns after completing its scan step.

```sql
CREATE TABLE resource_security_posture (
    posture_id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    resource_uid            VARCHAR(512)  NOT NULL,
    scan_run_id             UUID          NOT NULL,
    tenant_id               VARCHAR(255)  NOT NULL,
    account_id              VARCHAR(512),
    provider                VARCHAR(50),
    resource_type           VARCHAR(255),

    -- Network (written by engine-network-security)
    is_internet_exposed     BOOLEAN DEFAULT FALSE,
    is_onprem_reachable     BOOLEAN DEFAULT FALSE,
    entry_point_type        VARCHAR(50),
    waf_protected           BOOLEAN DEFAULT FALSE,
    network_detail          JSONB,

    -- IAM (written by engine-iam)
    attached_role_arn       VARCHAR(512),
    is_admin_role           BOOLEAN DEFAULT FALSE,
    has_wildcard_policy     BOOLEAN DEFAULT FALSE,
    has_permission_boundary BOOLEAN DEFAULT FALSE,
    mfa_required            BOOLEAN DEFAULT FALSE,
    iam_reachable_count     INTEGER DEFAULT 0,
    iam_detail              JSONB,

    -- Encryption (written by graph-build step)
    volume_encrypted        BOOLEAN,
    kms_key_uid             VARCHAR(512),
    encryption_type         VARCHAR(50),
    cert_uid                VARCHAR(512),
    cert_expiry_date        TIMESTAMPTZ,
    cert_days_remaining     INTEGER,
    in_transit_tls          BOOLEAN,

    -- Data (written by engine-datasec)
    data_classification     VARCHAR(50),
    can_access_pii          BOOLEAN DEFAULT FALSE,
    can_write_data          BOOLEAN DEFAULT FALSE,
    exfil_path_exists       BOOLEAN DEFAULT FALSE,

    -- Database (written by engine-network-security via relationships)
    connected_db_uids       JSONB,
    db_auth_type            VARCHAR(50),
    db_same_vpc             BOOLEAN,

    -- CDR (written by engine-cdr cron)
    has_active_cdr_actor    BOOLEAN DEFAULT FALSE,
    cdr_actor_last_seen     TIMESTAMPTZ,
    cdr_actor_uid           VARCHAR(255),
    cdr_risk_score          INTEGER DEFAULT 0,

    -- Attack path signals (written by engine-attack-path)
    is_crown_jewel          BOOLEAN DEFAULT FALSE,
    crown_jewel_type        VARCHAR(50),
    is_on_attack_path       BOOLEAN DEFAULT FALSE,
    attack_path_count       INTEGER DEFAULT 0,
    is_choke_point          BOOLEAN DEFAULT FALSE,
    choke_point_path_count  INTEGER DEFAULT 0,
    blast_radius_count      INTEGER DEFAULT 0,
    crown_jewel_count       INTEGER DEFAULT 0,

    -- Scoring helpers (written by engine-attack-path)
    max_epss                FLOAT,
    critical_misconfig_count INTEGER DEFAULT 0,
    high_misconfig_count    INTEGER DEFAULT 0,

    -- Computed posture (written last)
    posture_score           INTEGER DEFAULT 0,

    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (resource_uid, scan_run_id, tenant_id)
);

CREATE INDEX idx_rsp_tenant_scan    ON resource_security_posture(tenant_id, scan_run_id);
CREATE INDEX idx_rsp_crown_jewel    ON resource_security_posture(tenant_id, is_crown_jewel) WHERE is_crown_jewel = TRUE;
CREATE INDEX idx_rsp_attack_path    ON resource_security_posture(tenant_id, is_on_attack_path) WHERE is_on_attack_path = TRUE;
CREATE INDEX idx_rsp_choke_point    ON resource_security_posture(tenant_id, is_choke_point) WHERE is_choke_point = TRUE;
CREATE INDEX idx_rsp_resource_uid   ON resource_security_posture(resource_uid, tenant_id);
```

### 7.2 `attack_paths` (threat_engine_attack_path DB)

```sql
CREATE TABLE attack_paths (
    path_id             VARCHAR(64)   PRIMARY KEY,  -- sha256 of node_uids
    scan_run_id         UUID          NOT NULL,
    tenant_id           VARCHAR(255)  NOT NULL,
    account_id          VARCHAR(512),
    provider            VARCHAR(50),

    -- Path topology
    entry_point_uid     VARCHAR(512)  NOT NULL,
    entry_point_type    VARCHAR(50)   NOT NULL,  -- internet|onprem|vpn|peer_account|vendor
    crown_jewel_uid     VARCHAR(512)  NOT NULL,
    crown_jewel_type    VARCHAR(50)   NOT NULL,
    chain_type          VARCHAR(100)  NOT NULL,  -- internet_to_data|internet_to_secrets|etc
    depth               INTEGER       NOT NULL,
    node_uids           JSONB         NOT NULL,  -- ordered list
    node_types          JSONB         NOT NULL,
    edge_types          JSONB         NOT NULL,
    hop_categories      JSONB         NOT NULL,

    -- Scoring
    path_score          INTEGER       NOT NULL,
    severity            VARCHAR(20)   NOT NULL,
    probability_score   FLOAT,
    impact_score        FLOAT,

    -- Dedup / grouping
    group_id            VARCHAR(12),
    group_size          INTEGER DEFAULT 1,
    is_representative   BOOLEAN DEFAULT TRUE,
    choke_node_uid      VARCHAR(512),
    absorbed_count      INTEGER DEFAULT 0,

    -- Evidence summary
    max_epss            FLOAT,
    misconfig_count     INTEGER DEFAULT 0,
    threat_count        INTEGER DEFAULT 0,
    has_active_cdr_actor BOOLEAN DEFAULT FALSE,
    data_classification VARCHAR(50),

    -- Lifecycle
    first_seen_at       TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ DEFAULT NOW(),
    status              VARCHAR(20) DEFAULT 'active',  -- active|resolved|suppressed

    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ap_tenant_scan     ON attack_paths(tenant_id, scan_run_id);
CREATE INDEX idx_ap_severity        ON attack_paths(tenant_id, severity);
CREATE INDEX idx_ap_crown_jewel     ON attack_paths(tenant_id, crown_jewel_uid);
CREATE INDEX idx_ap_choke_node      ON attack_paths(tenant_id, choke_node_uid) WHERE choke_node_uid IS NOT NULL;
CREATE INDEX idx_ap_representative  ON attack_paths(tenant_id, is_representative) WHERE is_representative = TRUE;
```

### 7.3 `attack_path_nodes` (threat_engine_attack_path DB)

Per-hop evidence for the path story UI.

```sql
CREATE TABLE attack_path_nodes (
    id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    path_id         VARCHAR(64)  NOT NULL REFERENCES attack_paths(path_id),
    tenant_id       VARCHAR(255) NOT NULL,
    hop_index       INTEGER      NOT NULL,  -- 0 = entry, N = crown jewel
    node_uid        VARCHAR(512) NOT NULL,
    node_name       VARCHAR(512),
    node_type       VARCHAR(255),
    edge_to_next    VARCHAR(100),  -- edge type to next hop
    edge_category   VARCHAR(50),   -- attack_path_category

    -- WHY this hop is traversable
    traversal_reason TEXT,         -- human-readable: "EC2 has IamInstanceProfile attached"
    policy_statement JSONB,        -- for IAM edges: {actions, resource, effect}
    sg_rule         JSONB,         -- for network edges: {port, protocol, cidr}

    -- Evidence on this node
    misconfigs      JSONB,         -- [{rule_id, severity, title, remediation}]
    cves            JSONB,         -- [{cve_id, epss, cvss, in_kev}]
    threat_detections JSONB,       -- [{detection_type, technique, severity}]
    cdr_actor_active BOOLEAN DEFAULT FALSE,
    cdr_actor_uid   VARCHAR(255),

    -- Node posture
    risk_score      INTEGER,
    is_crown_jewel  BOOLEAN DEFAULT FALSE,
    data_classification VARCHAR(50),
    encrypted_by    VARCHAR(512),  -- KMS key UID if applicable
    cert_expiry     TIMESTAMPTZ
);

CREATE INDEX idx_apn_path_id ON attack_path_nodes(path_id);
CREATE INDEX idx_apn_node_uid ON attack_path_nodes(tenant_id, node_uid);
```

### 7.4 `attack_path_history` (threat_engine_attack_path DB)

Tracks path evolution across scans for the Trends feature.

```sql
CREATE TABLE attack_path_history (
    id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    path_id         VARCHAR(64)  NOT NULL,
    tenant_id       VARCHAR(255) NOT NULL,
    scan_run_id     UUID         NOT NULL,
    score           INTEGER      NOT NULL,
    severity        VARCHAR(20)  NOT NULL,
    node_uids       JSONB        NOT NULL,  -- detect node changes
    node_count      INTEGER,
    recorded_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aph_path_trend ON attack_path_history(path_id, recorded_at DESC);
CREATE INDEX idx_aph_tenant     ON attack_path_history(tenant_id, recorded_at DESC);
```

### 7.5 `crown_jewel_overrides` (threat_engine_attack_path DB)

Manual analyst tagging. Always takes precedence over auto-classification.

```sql
CREATE TABLE crown_jewel_overrides (
    id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    resource_uid    VARCHAR(512) NOT NULL,
    tenant_id       VARCHAR(255) NOT NULL,
    is_crown_jewel  BOOLEAN      NOT NULL,
    crown_jewel_type VARCHAR(50),
    reason          TEXT,
    set_by          VARCHAR(255) NOT NULL,  -- user email
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(resource_uid, tenant_id)
);
```

---

## 8. API Design

All endpoints require `Authorization: Bearer <token>` + `X-Auth-Context` header set by gateway.

### 8.1 Endpoints

```
GET  /api/v1/health/live
GET  /api/v1/health/ready

GET  /api/v1/attack-paths
     Query: tenant_id, scan_run_id, severity, chain_type, entry_point_type,
            crown_jewel_type, representative_only=true, page, page_size
     Returns: { paths[], total, kpis{critical, high, choke_points, longest_open_days} }
     Permission: attack_path:read

GET  /api/v1/attack-paths/{path_id}
     Returns: full path with attack_path_nodes[] (per-hop story)
     Permission: attack_path:read

GET  /api/v1/crown-jewels
     Query: tenant_id, scan_run_id, type, page, page_size
     Returns: { crown_jewels[], total }
     Permission: attack_path:read

PATCH /api/v1/crown-jewels/{resource_uid}
     Body: { is_crown_jewel: bool, crown_jewel_type: str, reason: str }
     Returns: updated crown jewel record
     Permission: attack_path:write (org_admin, platform_admin, tenant_admin)

GET  /api/v1/choke-points
     Query: tenant_id, scan_run_id, limit=10
     Returns: [{ node_uid, node_name, node_type, paths_blocked, avg_path_score }]
     Permission: attack_path:read

GET  /api/v1/attack-paths/trends
     Query: tenant_id, days=30, path_id (optional — single path trend)
     Returns: { score_history[], new_paths, resolved_paths, longest_open_days }
     Permission: attack_path:read

POST /api/v1/internal/scan
     Body: { scan_run_id, tenant_id, account_id }
     Auth: X-Internal-Secret header (bypasses AuthMiddleware, internal Argo use only)
     Returns: { job_id, status: "queued" }
```

### 8.2 Response Shape: attack_paths list

```json
{
  "paths": [
    {
      "path_id": "a3f9c2...",
      "severity": "critical",
      "path_score": 87,
      "chain_type": "internet_to_data",
      "entry_point_type": "internet",
      "depth": 3,
      "title": "Internet → EC2 → IAMRole → S3 (PII)",
      "crown_jewel_uid": "arn:aws:s3:::prod-customer-data",
      "crown_jewel_type": "data",
      "data_classification": "pii",
      "group_id": "c4f912",
      "group_size": 3,
      "is_representative": true,
      "choke_node_uid": "arn:aws:iam::588...role/web-prod-role",
      "has_active_cdr_actor": true,
      "max_epss": 0.94,
      "misconfig_count": 4,
      "first_seen_at": "2026-04-28T10:00:00Z",
      "last_seen_at": "2026-05-15T14:00:00Z",
      "open_days": 17
    }
  ],
  "total": 142,
  "kpis": {
    "critical": 12,
    "high": 38,
    "choke_points": 5,
    "longest_open_days": 47,
    "paths_with_active_cdr": 3
  }
}
```

### 8.3 Response Shape: attack-paths/{id} (path story)

```json
{
  "path_id": "a3f9c2...",
  "path_score": 87,
  "severity": "critical",
  "probability_score": 0.72,
  "impact_score": 0.95,
  "steps": [
    {
      "hop_index": 0,
      "node_uid": "arn:aws:ec2:ap-south-1:588...:instance/i-0abc",
      "node_name": "web-server-prod",
      "node_type": "ec2.instance",
      "edge_to_next": "ASSUMES",
      "edge_category": "privilege_escalation",
      "traversal_reason": "EC2 has IamInstanceProfile with role web-prod-role",
      "misconfigs": [
        {"rule_id": "aws-ec2-imds-v1", "severity": "high", "title": "IMDSv1 enabled — token hijack risk"},
        {"rule_id": "aws-sg-ssh-open", "severity": "critical", "title": "SSH open to 0.0.0.0/0"}
      ],
      "cves": [{"cve_id": "CVE-2023-44487", "epss": 0.94, "cvss": 7.5, "in_kev": true}],
      "cdr_actor_active": true,
      "cdr_actor_uid": "i-0abc/root"
    },
    {
      "hop_index": 1,
      "node_uid": "arn:aws:iam::588...:role/web-prod-role",
      "node_name": "web-prod-role",
      "node_type": "iam.role",
      "edge_to_next": "CAN_ACCESS",
      "edge_category": "data_access",
      "traversal_reason": "Policy allows s3:GetObject on Resource:*",
      "policy_statement": {"actions": ["s3:GetObject","s3:ListBucket"], "resource": "*", "effect": "Allow"},
      "misconfigs": [
        {"rule_id": "aws-iam-no-boundary", "severity": "critical", "title": "No permission boundary"}
      ]
    },
    {
      "hop_index": 2,
      "node_uid": "arn:aws:s3:::prod-customer-data",
      "node_name": "prod-customer-data",
      "node_type": "s3.bucket",
      "is_crown_jewel": true,
      "crown_jewel_type": "data",
      "data_classification": "pii",
      "encrypted_by": null,
      "encryption_gap": "SSE-S3 (not KMS — key not customer-managed)"
    }
  ]
}
```

---

## 9. Security Architecture

### 9.1 STRIDE Threat Model

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Fake AuthContext header bypassing gateway | `require_permission()` validates token independently; no trust of raw headers |
| **Tampering** | Attacker modifies attack_paths table to suppress findings | All writes scoped by scan_run_id + tenant_id; read-only DB user for BFF |
| **Repudiation** | Analyst tags crown jewel override without audit trail | `crown_jewel_overrides.set_by` captures user email; immutable audit log |
| **Info Disclosure** | Cross-tenant path leakage via path_id guessing | path_id is sha256 hash; all queries WHERE tenant_id = $tid |
| **DoS** | Large tenant triggers 10,000 paths, exhausting Neo4j | LIMIT 500 in Cypher; engine has 30s query timeout; Argo retry=0 for scan step |
| **Elevation** | Internal scan endpoint exploited from external | POST /internal/scan requires X-Internal-Secret; not exposed via gateway PUBLIC_PREFIXES |

### 9.2 RBAC Matrix

| Role | GET /attack-paths | GET /attack-paths/{id} | GET /crown-jewels | PATCH /crown-jewels | GET /choke-points |
|---|---|---|---|---|---|
| platform_admin | ✓ | ✓ | ✓ | ✓ | ✓ |
| org_admin | ✓ | ✓ | ✓ | ✓ | ✓ |
| tenant_admin | ✓ | ✓ | ✓ | ✓ | ✓ |
| analyst | ✓ | ✓ | ✓ | ✗ | ✓ |
| viewer | ✓ (summary only) | ✗ | ✓ | ✗ | ✗ |

New permissions to seed in Django migration:
- `attack_path:read` — all roles except viewer gets summary only
- `attack_path:write` — platform_admin, org_admin, tenant_admin

### 9.3 Multi-Tenancy

- Every DB query: `WHERE tenant_id = $tid` from `AuthContext.engine_tenant_id`
- Neo4j queries: all node matches include `tenant_id: $tid` property filter
- No cross-tenant path leakage possible by construction
- `resource_security_posture` UNIQUE constraint on `(resource_uid, scan_run_id, tenant_id)`

### 9.4 PASTA Analysis Summary

**Assets at risk:** Crown jewel resource classifications (PII data, secrets, admin roles)
**Entry points:** Internet-exposed resources, on-prem connected resources
**Attack scenarios modeled:** All paths in `attack_paths` table represent real adversary scenarios
**Defensive coverage:** Path score deduction for WAF, MFA, permission boundaries; ENCRYPTED_BY edges surface key-compromise risk

---

## 10. Deployment

### 10.1 K8s Manifest (`deployment/aws/eks/engines/engine-attack-path.yaml`)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-attack-path
  namespace: threat-engine-engines
spec:
  replicas: 1
  selector:
    matchLabels:
      app: engine-attack-path
  template:
    metadata:
      labels:
        app: engine-attack-path
    spec:
      containers:
        - name: engine-attack-path
          image: yadavanup84/engine-attack-path:v-attack-path1
          ports:
            - containerPort: 8025
          envFrom:
            - secretRef:
                name: threat-engine-db-passwords
            - secretRef:
                name: threat-engine-secrets
          env:
            - name: ATTACK_PATH_DB_HOST
              valueFrom:
                configMapKeyRef:
                  name: threat-engine-db-config
                  key: ATTACK_PATH_DB_HOST
            - name: NEO4J_URI
              valueFrom:
                secretKeyRef:
                  name: threat-engine-db-passwords
                  key: NEO4J_URI
          livenessProbe:
            httpGet:
              path: /api/v1/health/live
              port: 8025
          readinessProbe:
            httpGet:
              path: /api/v1/health/ready
              port: 8025
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: engine-attack-path
  namespace: threat-engine-engines
spec:
  selector:
    app: engine-attack-path
  ports:
    - port: 80
      targetPort: 8025
```

### 10.2 Argo Pipeline Step

Added to `deployment/aws/eks/argo/cspm-pipeline.yaml` between graph-build and risk:

```yaml
- name: attack-path-scan
  dependencies: [graph-build]
  template: attack-path-scan-template
  arguments:
    parameters:
      - name: scan-run-id
        value: "{{inputs.parameters.scan-run-id}}"

- name: risk-scan
  dependencies: [attack-path-scan]   # was: [graph-build]
  template: risk-scan-template
```

### 10.3 Gateway Route

Add to `shared/api_gateway/main.py` SERVICE_ROUTES:
```python
"attack-path": "http://engine-attack-path.threat-engine-engines.svc.cluster.local:80",
```

Add to `frontend/src/lib/constants.js` ENGINE_ENDPOINTS:
```js
ATTACK_PATH: '/api/v1/attack-paths',
CROWN_JEWELS: '/api/v1/crown-jewels',
CHOKE_POINTS: '/api/v1/choke-points',
```

---

## 11. Architecture Decision Records (ADRs)

### ADR-001: Separate Engine vs. Part of Threat Engine

**Status:** Accepted

**Context:** Attack path discovery logic was initially part of `engine-threat`. The threat engine already has graph queries, blast radius, and attack path endpoints.

**Decision:** Extract into `engine-attack-path` (port 8025).

**Rationale:**
- Threat engine = behavioral detection (MITRE T1/T2 incidents). Attack path engine = structural topology analysis. Different responsibilities, different Argo lifecycle.
- Separate scaling: attack-path scan is memory-intensive (Neo4j traversal + dedup); threat detection is CPU-intensive (pattern matching). Different resource profiles.
- Independent deployment: attack path algorithm improvements don't require redeploying threat detection.
- Cleaner BFF: `/views/attack-paths` calls one engine, not two.

**Consequences:** One more K8s deployment. One more DB. Offset by cleaner separation of concerns.

---

### ADR-002: Reverse BFS vs. Forward Traversal

**Status:** Accepted

**Context:** Current graph queries traverse forward: `Internet → resource → resource` hoping to reach a crown jewel within 5 hops. This produces noise (paths to non-critical resources) and misses deep paths.

**Decision:** Reverse BFS starting from crown jewels.

**Rationale:**
- Search space: crown jewels are ~100–200 nodes per tenant. Internet-exposed resources may be thousands. Starting from the smaller set is always more efficient.
- Completeness: every path found TERMINATES at a crown jewel by construction. Forward traversal required filtering after the fact.
- Industry alignment: Orca's published algorithm is reverse BFS. This matches the competitive baseline.

**Consequences:** Requires crown jewels to be correctly classified first. Crown jewel classification quality directly affects path completeness.

---

### ADR-003: resource_security_posture as Shared Merge Table

**Status:** Accepted

**Context:** The risk engine and attack-path engine both need IAM posture, network exposure, data classification, and CDR signals per resource. Currently each engine queries 5+ other engines at runtime.

**Decision:** Introduce `resource_security_posture` in the inventory DB as a pre-computed merge table written by each engine after its scan step.

**Rationale:**
- Eliminates N×M cross-engine API calls at query time
- Risk engine reads ONE table instead of calling IAM + Network + DataSec + CDR engines
- Reduces latency: BFF asset detail panel reads from one table (5 parallel API calls → 1 DB query)
- Write-once-read-many: each engine writes its columns once per scan, many consumers read

**Consequences:** Requires coordinated migration. Each engine must be updated to write its columns. Stale data risk if an engine fails mid-scan (mitigated by `updated_at` timestamp check).

---

### ADR-004: P×I Scoring vs. Additive Score

**Status:** Accepted

**Context:** Current scoring is additive: `30 (internet) + 15 (priv_esc) + 25 (data_store) = 70`. This produces identical scores for very different paths.

**Decision:** Probability × Impact multiplicative formula.

**Rationale:**
- Probability is compositional: P(attacker traverses hop 1) × P(traverses hop 2 | already at hop 1). Multiplicative is the correct model.
- Impact is independent of traversal probability: a path to PII data with low probability is different from a path to monitoring logs with high probability.
- Enables meaningful "mitigating control" discounts: WAF reduces P by ×0.80, not by subtracting a fixed number from a 100-point additive score.
- Separating P and I allows operators to filter: "show me all paths with high impact regardless of probability" (find latent risk).

**Consequences:** Score is less intuitive (0.72 × 0.95 × 100 = 68) until normalized. P and I stored separately so UI can surface both.

---

### ADR-005: Dedup Before Persistence vs. At Query Time

**Status:** Accepted

**Context:** Option A: store all raw paths, dedup in BFF. Option B: dedup in engine before writing to DB.

**Decision:** Dedup in engine (Option B), store deduplicated paths with group_id linkage.

**Rationale:**
- Raw paths for a large tenant could be 50,000+. Storing all then deduping in BFF adds latency and storage cost.
- Dedup logic (subpath absorption requires checking posture table for independent exposure) is a DB operation, not suitable for BFF.
- group_id and choke_node_uid must be pre-computed for UI to render "N similar paths" collapsed view.

**Consequences:** If dedup logic changes, historical paths are stored with old groupings. Mitigated by storing `absorbed_count` and `group_size` so changes are auditable. Re-running the scan produces fresh dedup results.

---

## 12. Open Questions / Future Work

| Item | Priority | Notes |
|---|---|---|
| Cross-cloud paths (AWS→Azure hop) | P1 | Requires PeerAccount VirtualNode + cross-cloud IAM trust detection |
| ENCRYPTED_BY edges in graph-build | P0 | Needed before cert_expiry and encryption_gap scoring work correctly |
| SECURED_BY edges (ACM→ALB) | P1 | Cert expiry scoring requires these edges to exist |
| On-prem VirtualNode sourcing | P1 | Need DirectConnect/ExpressRoute/FastConnect discovery to feed OnPrem node |
| Path suppression | P2 | Analyst suppresses a known-acceptable path; stored in separate suppression table |
| Remediation actions per path | P2 | Per-hop: "fix this misconfig → reduces path score by X" — needs remediation engine integration |
| Path diff alerts | P2 | Notify when a new critical path appears since last scan |
